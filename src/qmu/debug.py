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
(auto re-sync/re-arm is a pry-side capability; the most it does is read
`pry status` from the bridge `qmu gdb` spawned, on an already-paused VM), so
it emits actionable warnings naming exactly what diverged and how to recover.
The warnings are worded so they are correct whether or not a client is
currently attached, and the attach probe below only *suppresses* them when qmu
can positively determine no client is connected — on any uncertainty it warns,
because a missed divergence is the failure this subsystem exists to prevent.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from typing import Any

from .instance import (
    instance_json_path,
    is_pid_alive,
    load_instance,
    proc_pid_start,
    save_instance,
)
from .serial import count_boot_banners, last_boot_offset, serial_log_offset

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


def established_client_inodes(proc_net_tcp_text: str, port: int) -> set[int]:
    """Socket inodes of the CLIENT ends of ESTABLISHED loopback connections
    to `port` (remote port == `port`), parsed from /proc/net/tcp{,6} text.

    The server end lives in QEMU; the client end in whichever process
    attached — what tells qmu's bridge from a hand-started one (#186).
    """
    inodes: set[int] = set()
    for line in proc_net_tcp_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != _TCP_ESTABLISHED or ":" not in fields[2]:
            continue
        ip_hex, _, port_hex = fields[2].rpartition(":")
        if ip_hex not in _LOOPBACK_LOCAL_HEX:
            continue
        try:
            if int(port_hex, 16) == port:
                inodes.add(int(fields[9]))
        except ValueError:
            continue
    return inodes


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


def reap_bridge_on_exit(vm_id: str) -> bool:
    """Reap the bridge recorded for `vm_id` once its QEMU is observed gone.

    The daemon's per-VM supervisor calls this on SHUTDOWN/POWERDOWN/QMP EOF:
    the stub died with QEMU, so a bridge parked on it can only strand the
    next `pry` command (#78). The record is re-read here, not passed in,
    because the supervisor's copy may predate a `qmu gdb` that recorded the
    bridge after the watch began. False when there is no record or no bridge.
    """
    inst = load_instance(vm_id)
    if inst is None or inst.gdb_bridge_pid is None:
        return False
    return reap_bridge(inst)


def bridge_instance_id(vm_id: str) -> str:
    """Stable pry `--instance-id` of the bridge `qmu gdb` spawns for `vm_id`.

    Lets `pry --instance qmu-<vm>` select the bridge without knowing its pid,
    and makes pry itself refuse a second bridge under the same name — a second
    line of defence behind `qmu gdb`'s attach gate.
    """
    return f"qmu-{vm_id}"


def bridge_holds_stub(inst: Any) -> bool | None:
    """Whether the client attached to the stub is the bridge `qmu gdb` recorded.

    True when that bridge's process owns the client end of the connection;
    False when it is dead, or alive without it (a hand-started client holds
    the stub, or nobody does); None when /proc cannot tell. A live recorded
    bridge alone proves nothing: it may have disconnected while another
    client took the stub (#186).
    """
    if not bridge_alive(inst):
        return False
    port = getattr(inst, "gdb_port", None)
    if port is None:
        return False
    inodes: set[int] = set()
    read_any = False
    for name in _PROC_NET_TCP:
        try:
            text = Path(name).read_text()
        except OSError:
            continue
        read_any = True
        inodes |= established_client_inodes(text, port)
    if not read_any:
        return None
    if not inodes:
        return False
    fd_dir = Path(f"/proc/{inst.gdb_bridge_pid}/fd")
    try:
        fds = list(fd_dir.iterdir())
    except OSError:
        return None
    for fd in fds:
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            try:
                if int(target[8:-1]) in inodes:
                    return True
            except ValueError:
                continue
    return False


def qmu_bridge_attached(inst: Any) -> bool:
    """The recorded bridge is the client (or /proc cannot say otherwise)."""
    holds = bridge_holds_stub(inst)
    return holds is True or (holds is None and bridge_alive(inst))


def _bridge_ref(inst: Any) -> tuple[str, str]:
    """How a recovery addresses this VM's debugger: `(instance, gloss)`.

    Only the bridge qmu recorded, and only while it is the attached client,
    answers to `qmu-<vm>`; naming it for a hand-started client sends the
    reader to `No running GDB bridge instance named …` or to a bridge that
    is not connected (#186), so anything else gets a placeholder and where
    to find it.
    """
    if qmu_bridge_attached(inst):
        return bridge_instance_id(inst.vm_id), ""
    return "<id>", " (<id>: your bridge's pid or --instance-id, from `pry doctor`)"


_PRY_STATUS_TIMEOUT = 5.0


def bridge_stopped(inst: Any) -> bool | None:
    """Whether the bridge `qmu gdb` recorded, as the attached client, is at a stop.

    Asks `pry status`; None when that bridge is not the attached client or
    did not answer. Only ask while QEMU is already paused: a pry command that
    touches a target GDB believes stopped halts a running VM (the gdbstub
    stops on any packet), so on a running guest this read is not free.
    """
    if not qmu_bridge_attached(inst):
        return None
    pry = shutil.which("pry")
    if not pry:
        return None
    try:
        result = subprocess.run(
            [pry, "--instance", str(inst.gdb_bridge_pid), "status", "--format", "json"],
            capture_output=True, text=True, timeout=_PRY_STATUS_TIMEOUT,
        )
        payload = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
    if result.returncode != 0 or not isinstance(payload, dict):
        return None
    state = payload.get("state")
    return state == "stopped" if isinstance(state, str) else None


# --- Breakpoint bytes in a saved image (#45, #188) ---------------------------
#
# Under KVM a gdbstub software breakpoint is an int3 QEMU writes into guest
# RAM; GDB (`breakpoint always-inserted off`) inserts its breakpoints when it
# resumes the target and lifts them when it stops. So what a `savevm` captures
# depends on whether GDB was at a stop when the save began. QEMU's run state
# answers that for a breakpoint/step stop (`debug`). `paused` is what an
# interrupt, a fresh attach and a QMP `stop` all leave (QEMU reports the
# latter to the client as SIGINT, so an attached GDB lifts its breakpoints
# then too), but whether a GDB actually took that stop is known only to the
# client: qmu asks the bridge it spawned, and cannot ask a hand-started one or
# a client that detached uncleanly and left its bytes behind. The state is
# read on both sides of the save: savevm resumes a running guest before it
# returns, so a breakpoint hit right after it shows `debug` for an image
# taken while the guest ran (measured, through to an int3 panic on load).
# Under TCG breakpoints live in QEMU's translator and never touch guest RAM
# (measured: 0x53 at an inserted breakpoint, and the image loaded and ran it
# clean).

INT3_NEVER = "never"
INT3_LIFTED = "lifted"
INT3_POSSIBLE = "possible"


def savevm_breakpoint_state(
    inst: Any, before: str | None, after: str | None
) -> str | None:
    """What a save holds of debugger breakpoints; None without a stub.

    `before`/`after` are QEMU's run state read right before and right after
    the save. `never` (TCG), `lifted` (a debugger stop held across the whole
    save) or `possible`.
    """
    if not debug_stub_present(inst):
        return None
    if getattr(inst, "kvm", None) is False:
        return INT3_NEVER
    if before != after:
        return INT3_POSSIBLE
    if before == "debug":
        return INT3_LIFTED
    if before == "paused" and bridge_stopped(inst) is True:
        return INT3_LIFTED
    return INT3_POSSIBLE


# --- Guest generations the debugger was not told about (#184) ----------------
#
# A reboot the guest starts itself (panic=N, a watchdog, a triple fault, sysrq)
# drops the gdbstub's breakpoints and re-slides KASLR exactly like a qmu
# `system_reset`, but no qmu command issued it. Its kernel boot banner is in
# the serial log either way, so every command that resolves a running VM
# compares the banners past the recorded debugger epoch with the ones already
# accounted for, warns once through the dispatch (`coherence_warnings`), and
# moves the epoch so the next command stays quiet.

_coherence_warnings: ContextVar[tuple[str, ...]] = ContextVar(
    "qmu_coherence_warnings", default=()
)


def reset_coherence_warnings() -> None:
    """Clear the per-dispatch list; `cli._parse` calls it before each command."""
    _coherence_warnings.set(())


def coherence_warnings() -> tuple[str, ...]:
    """Warnings recorded while the VM was resolved, for the dispatch's Result."""
    return _coherence_warnings.get()


def mark_debugger_epoch(inst: Any, offset: int, *, banners: int = 0) -> Any:
    """Record the generation a debugger on `inst` is now up to date with.

    `offset` is where it starts in the serial log; `banners` is how many boot
    banners at or past it belong to it (1 for a reset whose boot has yet to
    print). The record is re-read first so a concurrent writer (the daemon's
    epoch) is not clobbered. Returns `inst` with the fields set.
    """
    current = load_instance(inst.vm_id) or inst
    saved = replace(current, debugger_epoch_offset=offset, debugger_epoch_banners=banners)
    try:
        save_instance(saved)
    except OSError:
        pass
    return replace(inst, debugger_epoch_offset=offset, debugger_epoch_banners=banners)


def mark_debugger_attached(inst: Any) -> Any:
    """`qmu gdb` attached: the debugger's view is the guest as it is now.

    A guest still in firmware has not printed its banner; that boot is the
    attached one, so it is allowed for.
    """
    log = inst.serial_log
    pending = count_boot_banners(log) == 0
    return mark_debugger_epoch(inst, serial_log_offset(log), banners=1 if pending else 0)


def unwarned_reboot_offset(inst: Any) -> int | None:
    """Offset of a boot banner past the debugger epoch nobody warned about."""
    if getattr(inst, "gdb_port", None) is None:
        return None
    start = getattr(inst, "debugger_epoch_offset", None)
    if start is None:
        # Nothing recorded (a hand-started bridge on a VM qmu never attached):
        # the first boot is the one any debugger saw first.
        start, allowed = 0, 1
    else:
        allowed = getattr(inst, "debugger_epoch_banners", 0)
    if count_boot_banners(inst.serial_log, start_offset=start) <= allowed:
        return None
    return last_boot_offset(inst.serial_log, start_offset=start)


def check_unwarned_reboot(inst: Any) -> Any:
    """Warn once about a guest reboot the VM's debugger was never told about.

    Records the reset warning for the dispatch when a client may be attached
    (`debug_session_present`) and moves the debugger epoch past the reboot
    either way — a debugger that attaches later sees the new boot. Returns
    the (possibly updated) instance.
    """
    banner = unwarned_reboot_offset(inst)
    if banner is None:
        return inst
    inst = mark_debugger_epoch(inst, banner, banners=1)
    if debug_session_present(inst):
        warning = reset_dropped_breakpoints_warning(inst, guest_initiated=True) + "\n"
        if warning not in _coherence_warnings.get():
            _coherence_warnings.set(_coherence_warnings.get() + (warning,))
    return inst


# --- Warning builders ------------------------------------------------------
#
# Each names the divergence event, what silently diverges, and the recovery
# action, so an agent reading stderr knows the state is suspect without having
# already learned this contract. Every recovery below was run as written
# against a live pry bridge (#183, #188), under KVM and under TCG, because the
# two differ: under KVM a breakpoint is an int3 QEMU writes into guest RAM,
# so a rewind or reset takes it out of RAM while QEMU and GDB still count it
# inserted, and GDB's lift-at-stop / insert-on-resume cycle (`pry interrupt` →
# `pry continue --background`) puts it back. Under TCG breakpoints live in
# QEMU's translator, keyed by virtual address: a load or reset leaves them in
# force (measured: the canary fired with no re-arm after both), and only a
# KASLR re-slide moves the code out from under them.


def _kaslr_off(inst: Any) -> bool:
    return "nokaslr" in (getattr(inst, "cmdline", "") or "").split()


def _tcg(inst: Any) -> bool:
    """Positively TCG; None (a pre-#39 record) is treated as KVM."""
    return getattr(inst, "kvm", None) is False


def loadvm_stale_session_warning(inst: Any) -> str:
    """#44 — `snapshot load` rewound the guest but the debugger did not."""
    ref, gloss = _bridge_ref(inst)
    lead = (
        f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and was just rewound "
        "by snapshot load. An attached debugger does NOT re-sync: if it was at "
        "a stop, its stop reason still names that pre-load stop (frame and "
        "registers are re-read and current)"
    )
    if _tcg(inst):
        return lead + (
            ". Its breakpoints are unaffected: under TCG they live in QEMU, not "
            "in guest RAM, and a load moves no address, so they still fire with "
            "no re-arm. Trust the frame, not the reason, until the next stop."
        )
    return lead + (
        ", and the breakpoints it had inserted while the guest ran are no "
        "longer in guest RAM — still listed [enabled], they never fire. "
        f"Addresses did not move, so re-arm in place: `pry --instance {ref} "
        "interrupt` (`not interrupted` at a stop is fine), then `pry --instance "
        f"{ref} continue --background` (GDB re-inserts every breakpoint when it "
        f"resumes){gloss}; prove one fires with a canary before trusting a stop. "
        "An image whose save said `breakpoints_in_image: possible` brings its "
        "int3 bytes back, and nothing tracks those (they survive `pry "
        "interrupt`): load a `lifted` image or reboot instead."
    )


def savevm_breakpoint_warning(inst: Any, qemu_status: str | None) -> str:
    """#45/#188 — a save taken outside a debugger stop can hold int3 bytes."""
    ref, gloss = _bridge_ref(inst)
    state = qemu_status or "unknown"
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and was saved while "
        f"QEMU reported '{state}', not a debugger stop qmu could confirm. A "
        "software breakpoint is an int3 (0xCC) byte in guest RAM whenever the "
        "debugger has the target running, so this image may carry some: after "
        "`qmu snapshot load`, reaching one raises a trap with no live "
        "breakpoint behind it — an Oops/panic at the breakpointed function that "
        "looks exactly like your PoC crashing the kernel. For a clean image, "
        f"save at a stop: `pry --instance {ref} interrupt`, `qmu snapshot save "
        f"--vm {inst.vm_id} <tag>`, then `pry --instance {ref} continue "
        f"--background`{gloss}. Deleting a breakpoint while the guest runs does "
        "not remove its byte (m4ul3r/pry#56)."
    )


def savevm_lifted_note(inst: Any, qemu_status: str | None) -> str:
    """#188 — a save taken at a debugger stop: GDB had lifted its breakpoints."""
    return (
        f"[qmu] Note: VM '{inst.vm_id}' was saved at a debugger stop "
        f"('{qemu_status}'), where GDB has lifted its breakpoints, so this image "
        "holds no int3 for a breakpoint the debugger lists. The exceptions are "
        "int3 bytes nothing tracks — one deleted while the guest ran "
        "(m4ul3r/pry#56), or one a `possible` image brought back on load: they "
        "stay in RAM and in the image."
    )


def reset_dropped_breakpoints_warning(
    inst: Any, *, guest_initiated: bool = False, qemu_status: str | None = None
) -> str:
    """#46/#184 — a reset leaves the debugger's breakpoints dead, silently.

    Under KVM the reset takes them out of guest RAM while GDB still lists them
    inserted; under TCG QEMU keeps them, at their old virtual addresses. Either
    way KASLR re-slides the kernel on every boot, so the symbol file pry loaded
    against the old base resolves to addresses nothing executes (debug audit
    R25–R26). The recovery re-derives the base while the guest runs, THEN
    stops the debugger to reload: `pry load` on a running target leaves every
    breakpoint <PENDING> (m4ul3r/pry#57).

    `qemu_status` is QEMU's run state right after the reset, when known. A
    reset that lands while the debugger is at a stop leaves the vCPU halted at
    the reset vector (`prelaunch`), and `pry continue` does not start it
    (measured under KVM and TCG: still `EIP=0000fff0`, no console output).
    `qmu cont` boots it; the debugger, still believing it is stopped, then
    re-arms through the usual recovery.
    """
    vm_id = inst.vm_id
    ref, gloss = _bridge_ref(inst)
    tcg = _tcg(inst)
    kaslr_off = _kaslr_off(inst)
    halted = qemu_status is not None and qemu_status != "running"
    event = (
        "its guest rebooted by itself (a new kernel boot banner is in the "
        "serial log)"
        if guest_initiated
        else "was just reset"
    )
    lead = f"[qmu] WARNING: VM '{vm_id}' has a GDB stub and {event}. "
    if not tcg:
        lead += (
            "A machine reset drops the gdbstub's breakpoint/watchpoint set "
            "without notifying the client: an attached debugger still lists "
            "them as [enabled] but they do not fire (hits stay 0). "
        )
    elif kaslr_off and halted:
        lead += (
            "Under TCG a reset does not drop breakpoints (they live in QEMU, "
            "not in guest RAM) and nokaslr keeps their addresses, but the "
            "debugger lifted them at its stop and re-inserts them only when it "
            "resumes. "
        )
    elif kaslr_off:
        lead += (
            "Under TCG the gdbstub keeps its breakpoints across a reset (they "
            "live in QEMU, not in guest RAM), and this kernel booted with "
            "nokaslr, so they still fire where they were set. "
        )
    else:
        lead += (
            "Under TCG a reset does not drop the debugger's breakpoints (they "
            "live in QEMU, not in guest RAM), but they stay at their old "
            "addresses: KASLR re-slid the kernel, so they sit where nothing "
            "runs — still listed [enabled], they do not fire. "
        )
    if halted:
        lead += (
            f"The guest is still halted (QEMU '{qemu_status}'): the reset "
            "landed at a debugger stop, and `pry continue` does not start it "
            f"(the vCPU stays at the reset vector). Boot it with `qmu cont --vm "
            f"{vm_id}` first. "
        )
    if kaslr_off:
        if tcg and not halted:
            return lead + "Nothing to re-arm; prove one fires with a canary."
        return lead + (
            ("Addresses did not move: " if tcg else
             "This kernel booted with nokaslr, so addresses did not move: ")
            + f"`pry --instance {ref} interrupt`, then `pry --instance {ref} "
            f"continue --background` re-inserts every breakpoint{gloss}; prove "
            "one fires with a canary."
        )
    return lead + (
        ("" if tcg else
         "KASLR also re-slid the kernel, so symbols loaded against the old base "
         "resolve to addresses nothing runs. ")
        + "Once the guest serves SSH again: "
        f"`eval \"$(qmu kbase --vm {vm_id} --symbols <vmlinux>)\"` (guest "
        f"running), `pry --instance {ref} interrupt`, `pry --instance {ref} load "
        f"<vmlinux> --base $KBASE`, `pry --instance {ref} continue --background`"
        f"{gloss}. The breakpoints already set re-resolve to the new base (no "
        "re-set needed); `pry load` before the interrupt leaves them <PENDING> "
        "(m4ul3r/pry#57). Prove one fires with a canary."
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
