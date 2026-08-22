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

from pathlib import Path
from typing import Any

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
    """#46 — a VM reset drops the gdbstub breakpoint set without telling anyone."""
    return (
        f"[qmu] WARNING: VM '{vm_id}' has a GDB stub and was just reset. A "
        "machine reset drops the gdbstub's breakpoint/watchpoint set without "
        "notifying the client: an attached debugger will still list them as "
        "[enabled] but they will not fire (hits stay 0). Re-set (re-arm) all "
        "breakpoints after the guest comes back up; a canary breakpoint you can "
        "prove is hit confirms trapping is live again."
    )


def kvm_watchpoint_warning(vm_id: str) -> str:
    """#39 — hardware watchpoints can silently no-op under KVM + gdbstub."""
    return (
        "WARNING: this VM runs under KVM acceleration. Hardware watchpoints set "
        "through the QEMU gdbstub (e.g. `pry watch set`) may be accepted and "
        "reported [enabled] yet never deliver a hit under KVM — a silent miss. "
        "Breakpoints are unaffected. If a watchpoint does not fire on a write "
        f"you can prove happened, relaunch with `qmu launch --no-kvm ...` (TCG "
        "emulation) to debug it."
    )
