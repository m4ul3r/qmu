"""Debugger↔VM coherence: warn loudly when qmu mutates VM reality under a debugger.

Software breakpoints are int3 (0xCC) bytes patched into guest memory; hardware
watchpoints and breakpoints live in the QEMU gdbstub's own bookkeeping. Several
qmu operations mutate VM reality out from under an attached debugger without the
gdbstub protocol telling the client anything changed, so the debugger keeps
reporting a world that no longer exists — stale registers, breakpoints listed
``[enabled]`` that never fire again, or int3 trap bytes frozen into a restored
image. Every one of those is a *silent* divergence: no error, wrong answer.

qmu owns all of those lifecycle events and knows whether a VM has a GDB stub
(``gdb_port`` is set), so it is the right place to enforce the contract the
gdbstub protocol does not:

  Whenever qmu mutates VM reality (reset, loadvm, savevm) while a debug session
  is attached — or a debug session attaches under conditions where its effects
  won't work — either re-sync automatically, or invalidate loudly. Never
  silently diverge.

This module implements the "invalidate loudly" half: it does not drive pry
(auto re-sync/re-arm is a pry-side capability), so it emits actionable warnings
naming exactly what diverged and how to recover. The warnings are worded so they
are correct whether or not a client is currently attached, and the attach probe
below only *suppresses* them when qmu can positively determine no client is
connected — on any uncertainty it warns, because a missed divergence is the
failure this subsystem exists to prevent.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .instance import instance_json_path, is_pid_alive, proc_pid_start, save_instance

# TCP states from include/net/tcp_states.h as they appear (hex, upper-case) in
# field 4 of /proc/net/tcp{,6}. An attached gdb client shows up as the gdbstub
# server's ESTABLISHED socket whose *local* port is the gdb port; an unattached
# stub is only LISTEN (0A) on that port.
_TCP_ESTABLISHED = "01"

_PROC_NET_TCP = ("/proc/net/tcp", "/proc/net/tcp6")

# Loopback local addresses as /proc/net/tcp{,6} render them (host-byte-order
# hex). qmu binds the gdb stub to 127.0.0.1 (`vm.py` -gdb tcp:127.0.0.1:PORT),
# so a genuine attach is always loopback. Filtering on this means an unrelated
# ESTABLISHED socket on another interface that merely reuses the port *number*
# cannot masquerade as an attached debugger.
_LOOPBACK_LOCAL_HEX = frozenset({
    "0100007F",                          # IPv4 127.0.0.1
    "00000000000000000000000001000000",  # IPv6 ::1
})


def established_local_ports(proc_net_tcp_text: str) -> set[int]:
    """ESTABLISHED **loopback** local ports parsed from /proc/net/tcp{,6} text.

    Pure so it can be unit-tested without a live socket. The local address is
    ``HEXIP:HEXPORT`` (port big-endian hex); only loopback local IPs are kept
    (the gdb stub binds 127.0.0.1). Malformed lines are skipped rather than
    raised on — this feeds a best-effort probe.
    """
    ports: set[int] = set()
    for line in proc_net_tcp_text.splitlines()[1:]:  # skip the header row
        fields = line.split()
        if len(fields) < 4:
            continue
        local, state = fields[1], fields[3]
        if state != _TCP_ESTABLISHED or ":" not in local:
            continue
        ip_hex, _, port_hex = local.rpartition(":")
        if ip_hex not in _LOOPBACK_LOCAL_HEX:
            continue
        try:
            ports.add(int(port_hex, 16))
        except ValueError:
            continue
    return ports


def gdb_client_attached(inst: Any) -> bool | None:
    """Best-effort: is a client connected to this VM's gdb stub?

    Returns True (an ESTABLISHED connection on the gdb port exists), False (the
    proc tables were readable and none exists), or None (no gdb port, or the
    proc tables could not be read — e.g. non-Linux). None means "cannot tell",
    which callers treat as "assume attached" so a real divergence is never
    silently skipped.
    """
    port = getattr(inst, "gdb_port", None)
    if port is None:
        return None
    read_any = False
    for name in _PROC_NET_TCP:
        try:
            text = Path(name).read_text()
        except OSError:
            continue
        read_any = True
        if port in established_local_ports(text):
            return True
    return False if read_any else None


def debug_stub_present(inst: Any) -> bool:
    """Whether the VM has a GDB stub at all (`--gdb` was passed at launch).

    This is the correct gate for divergences whose damage **outlives an attached
    client** — chiefly baked-in software-breakpoint int3s (#45): a bridge can arm
    breakpoints, then die uncleanly (the #40 stranded-bridge case) leaving the
    trap bytes resident while no client is connected. Requiring a live client
    there would suppress exactly the warning that is needed. qmu cannot query pry
    for whether breakpoints are armed, so "a stub ever existed" is the safe
    predicate.
    """
    return getattr(inst, "gdb_port", None) is not None


def debug_session_present(inst: Any) -> bool:
    """Whether a debugger's *live view* can diverge for `inst`.

    True when the VM has a GDB stub AND qmu cannot positively rule out an
    attached client. This is the gate for divergences that only matter while a
    client is watching — stale registers after loadvm (#44), dropped breakpoints
    after a reset (#46). A VM launched without ``--gdb`` (no ``gdb_port``) can
    never diverge this way, so it is always False and no warning fires. For the
    image-persistent int3 case use :func:`debug_stub_present` instead.
    """
    if getattr(inst, "gdb_port", None) is None:
        return False
    return gdb_client_attached(inst) is not False


# --- pry bridge ownership (#40) ---------------------------------------------
#
# `qmu gdb` spawns a headless pry bridge and records its pid + /proc start-time
# on the instance. That record is what lets `kill` reap the bridge instead of
# stranding it against a dead stub, and lets a second `qmu gdb` name the
# existing bridge instead of leaking another one.


def bridge_alive(inst: Any) -> bool:
    """Whether the recorded pry bridge is still the process it was at spawn.

    Same discipline as `instance_alive`: a pid alone can be recycled, so when
    a start-time was recorded it must match.
    """
    pid = getattr(inst, "gdb_bridge_pid", None)
    if not isinstance(pid, int) or pid <= 0 or not is_pid_alive(pid):
        return False
    recorded = getattr(inst, "gdb_bridge_pid_start", None)
    if recorded is None:
        return True
    return proc_pid_start(pid) == recorded


def _exited(pid: int) -> bool:
    """Gone, or a zombie (exited but not yet reaped by its parent)."""
    if not is_pid_alive(pid):
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    rest = stat.rsplit(")", 1)[1].split()
    return bool(rest) and rest[0] == "Z"


def _wait_exit(pid: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not _exited(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def reap_bridge(inst: Any) -> bool:
    """Terminate the pry bridge `qmu gdb` recorded for `inst`, if it is alive.

    Prefers `pry kill --instance <pid>` (a clean gdb detach, which also lets
    QEMU resume the vCPU) and falls back to SIGTERM. Clears the record on the
    instance in place and rewrites its JSON when that still exists. Returns
    True only when a live, identity-verified bridge was terminated; never
    raises — this runs on the `kill` path, where a reaping failure must not
    mask the VM teardown.
    """
    if not bridge_alive(inst):
        return False
    pid = inst.gdb_bridge_pid
    killed = False
    pry = shutil.which("pry")
    if pry:
        try:
            result = subprocess.run(
                [pry, "kill", "--instance", str(pid)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            killed = result.returncode == 0 and _wait_exit(pid, 5.0)
        except (subprocess.TimeoutExpired, OSError):
            killed = False
    if not killed and bridge_alive(inst):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        killed = _wait_exit(pid, 5.0)
    inst.gdb_bridge_pid = None
    inst.gdb_bridge_pid_start = None
    try:
        if instance_json_path(inst.vm_id).exists():
            save_instance(inst)
    except (OSError, TypeError, ValueError):
        pass
    return killed


# --- Warning builders ------------------------------------------------------
#
# Each names the divergence event, what silently diverges, and the recovery
# action, so an agent reading stderr knows the state is suspect without having
# already learned this contract.


def loadvm_stale_session_warning(vm_id: str) -> str:
    """#44 — `snapshot load` rewound the guest but the debugger did not."""
    return (
        f"[qmu] WARNING: VM '{vm_id}' has a GDB stub and was just rewound by "
        "snapshot load. An attached debugger does NOT re-sync: it keeps its "
        "pre-load vCPU state (stale $rip and stop reason) and stale "
        "breakpoint/memory bookkeeping, presenting them as current. Tear the "
        "stale pry bridge down first (its connection survived the rewind, so a "
        f"fresh `qmu gdb --vm {vm_id}` would spawn a SECOND one — see #40), then "
        "reconnect and re-arm breakpoints before trusting any register or "
        "memory read."
    )


def savevm_breakpoint_warning(vm_id: str) -> str:
    """#45 — a snapshot taken with SW breakpoints armed bakes in their int3s."""
    return (
        f"[qmu] WARNING: VM '{vm_id}' has a GDB stub. If a debugger has "
        "software breakpoints armed, this snapshot captured their int3 (0xCC) "
        "trap bytes. After `qmu snapshot load`, execution reaching one of those "
        "addresses raises a trap with no live breakpoint behind it — a guest "
        "Oops/panic (e.g. `int3` at the breakpointed function) that looks "
        "exactly like your PoC crashing the kernel. Clear breakpoints before "
        "saving a clean image, or treat a post-load int3 crash as a debugger "
        "artifact rather than an exploit result."
    )


def reset_dropped_breakpoints_warning(vm_id: str) -> str:
    """#46 — a VM reset drops the gdbstub breakpoint set without telling anyone.

    Re-arming by symbol is not enough on its own: KASLR re-slides the kernel on
    every boot, so the symbol file pry loaded against the old base now resolves
    to addresses nothing executes, and the re-armed breakpoint sits at a stale
    address with hits=0 and no error (debug audit R25–R26). The recovery must
    re-derive the base first.
    """
    return (
        f"[qmu] WARNING: VM '{vm_id}' has a GDB stub and was just reset. A "
        "machine reset drops the gdbstub's breakpoint/watchpoint set without "
        "notifying the client: an attached debugger will still list them as "
        "[enabled] but they will not fire (hits stay 0). KASLR also re-slides "
        "the kernel on reboot, so symbols loaded against the old base now "
        "resolve to stale addresses and a breakpoint re-set by symbol lands "
        "where nothing runs. After the guest comes back up: re-derive the base "
        f"with `eval \"$(qmu kbase --vm {vm_id} --symbols <vmlinux>)\"`, reload "
        "symbols with `pry load <vmlinux> --base $KBASE`, THEN re-set (re-arm) "
        "all breakpoints; a canary breakpoint you can prove is hit confirms "
        "trapping is live again."
    )


def kvm_watchpoint_warning(vm_id: str) -> str:
    """#39 — hardware-watchpoint "silent miss" caveats on a KVM VM.

    Reworded after live testing (PR #50): on qemu 8.2.2 + KVM a hw write-
    watchpoint on `jiffies` fired reliably, so the original "watchpoints never
    deliver under KVM" framing was wrong. The reproducible cause of a "silent
    miss" is the virtual-address one below; a KVM guest-debug limitation is a
    secondary possibility that `--no-kvm` isolates.
    """
    return (
        "WARNING: a hardware watchpoint (e.g. `pry watch set`) fires only on "
        "writes through the WATCHED virtual address. A kernel write to the same "
        "bytes via a different mapping — a heap/physmap alias, common in LPEs "
        "that corrupt e.g. modprobe_path — will NOT trip a watchpoint set on the "
        "symbol's VA; that looks like a silent miss but is not KVM's fault. "
        "Separately, some QEMU/KVM builds can drop gdbstub watchpoints entirely. "
        "If a watchpoint does not fire on a write you can prove happened, suspect "
        f"the alias first, then retest under `qmu launch --no-kvm ...` (TCG) to "
        "rule out a KVM guest-debug limitation."
    )
