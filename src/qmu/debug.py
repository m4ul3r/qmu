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

This module implements both halves. For the bridge qmu itself spawned (`qmu
gdb` records its pid) and that holds the stub, after a snapshot load or a reset
qmu issued, it re-syncs that bridge with pry's `pry resync`, or tears it down
and says why when no re-sync can make the bridge's view true (#187). Anything
else it does not drive (the most it does is read `pry status` from qmu's
bridge on an already-paused VM): it emits actionable warnings naming exactly
what diverged and how to recover. The warnings are worded so they are correct
whether or not a client is currently attached, and the attach probe below only
*suppresses* them when qmu can positively determine no client is connected —
on any uncertainty it warns, because a missed divergence is the failure this
subsystem exists to prevent.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .instance import (
    instance_alive,
    instance_json_path,
    is_pid_alive,
    load_instance,
    proc_pid_start,
    save_instance,
)
from .serial import (
    count_boot_banners,
    init_lines_hidden,
    kernel_init_done,
    last_boot_offset,
    serial_log_offset,
)

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


def debugger_holding(inst: Any, qemu_status: str | None) -> tuple[str, str] | None:
    """`(instance, gloss)` of the debugger holding a halted guest's stop, the
    way a `pry --instance` recovery addresses it; None when no debugger can be
    holding it.

    `debug` is a gdbstub stop (breakpoint, watchpoint, step) and nothing
    else; `paused` under the bridge `qmu gdb` spawned is its attach or its
    interrupt.
    """
    if qemu_status == "debug" and debug_session_present(inst):
        return _bridge_ref(inst)
    if qemu_status == "paused" and qmu_bridge_attached(inst):
        return bridge_instance_id(inst.vm_id), ""
    return None


def debugger_resume(inst: Any, qemu_status: str | None) -> tuple[str, str] | None:
    """`(command, gloss)` resuming a halted guest a debugger holds (#225).

    GDB lifts its breakpoints at a stop and puts them back only when it
    resumes, so a QMP `cont` (`qmu cont`) there runs the guest with every
    breakpoint lifted, behind GDB's back: GDB still believes the target
    stopped, and its next command (`pry status` included) halts the guest
    again. None when no debugger can be holding this stop
    (`debugger_holding`): `qmu cont` is the resume then, unless the stop is
    an orphaned breakpoint (`orphaned_breakpoint_stop`).
    """
    held = debugger_holding(inst, qemu_status)
    if held is None:
        return None
    ref, gloss = held
    return f"pry --instance {ref} continue --background", gloss


def orphaned_breakpoint_stop(inst: Any, qemu_status: str | None) -> bool:
    """#237 — QEMU at a gdbstub stop (`debug`) with positively no client on
    the stub.

    A debugger that died without detaching (a GDB abort, a `kill -9`) leaves
    its int3s in guest RAM, and QEMU's gdbstub keeps them in its breakpoint
    list: the first guest call into such a function halts the vCPU in
    `debug`, and a QMP `cont` re-runs the int3, so the vCPU is back in
    `debug` at once. A new client clears them: QEMU drops a gone client's
    breakpoints, writing the original bytes back, when the next one
    connects. Claimed only on a positive "no client" — `gdb_client_attached`
    None (cannot tell) never is one.
    """
    return (
        qemu_status == "debug"
        and getattr(inst, "gdb_port", None) is not None
        and gdb_client_attached(inst) is False
    )


ORPHANED_STOP = (
    "halted at a breakpoint no debugger owns (a debugger died without removing it)"
)


def orphaned_stop_recovery(inst: Any) -> str:
    """What clears an orphaned breakpoint stop (`orphaned_breakpoint_stop`)."""
    return (
        f"attach a debugger to clear it: qmu gdb --vm {inst.vm_id} --symbols "
        "<vmlinux> (QEMU drops a gone debugger's breakpoints when a new one "
        f"connects), then pry --instance {bridge_instance_id(inst.vm_id)} "
        "continue --background"
    )


def orphaned_cont_warning(inst: Any) -> str:
    """#237 — `qmu cont` ran a guest out of an orphaned breakpoint stop (a
    watchpoint's, which does not re-trap at once): QEMU still holds that
    debugger's breakpoints, so the next hit halts it again."""
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}' was {ORPHANED_STOP}. `qmu cont` "
        "resumed it, but QEMU still holds that debugger's breakpoints and "
        "watchpoints, so the next hit halts the guest again; "
        f"{orphaned_stop_recovery(inst)}.\n"
    )


CONT_BEHIND_DEBUGGER = (
    "`qmu cont` resumes the guest behind the debugger's back: every breakpoint "
    "stays lifted, and GDB, still believing the target stopped, halts it again "
    "on its next command (`pry status` included)"
)


def cont_behind_debugger_warning(inst: Any, before: str | None) -> str | None:
    """#225 — `qmu cont` resumed a stop a debugger holds (`debugger_resume`).

    Running with no breakpoint in RAM is sometimes the point (reading the
    kernel base over SSH before a rebase, `_left_stopped_unrebased`), so the
    warning names the debugger's resume for the guest that should run under
    it, and what to expect either way.
    """
    resume = debugger_resume(inst, before)
    if resume is None:
        return None
    command, gloss = resume
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}' was at a debugger stop (QEMU "
        f"'{before}'); {CONT_BEHIND_DEBUGGER}. To run it under the debugger, "
        f"resume through it instead, which also works now: `{command}`{gloss} "
        "(GDB re-inserts its breakpoints when it resumes). If you meant it to "
        "run with no breakpoint armed (e.g. to read the kernel base over SSH "
        "first), expect the debugger's next command to halt it.\n"
    )


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


# --- Driving the bridge qmu owns (#187, #200, #201, #226) ---------------------
#
# The bridge `qmu gdb` spawned, while it is the attached client
# (`qmu_bridge_attached`), is qmu's: after a snapshot load or a reset qmu itself
# issued, it runs `pry resync` (pry #59/#61) on it, at a stop qmu holds, and
# puts pry's report in the envelope, or tears the bridge down and says why when
# a re-sync cannot make its view true. On a KASLR guest `pry kbase` (pry #66)
# first finds the running kernel's base without SSH, validated against the
# loaded vmlinux, and rebases the symbols to it: a reset re-slides the kernel,
# and a load restores the base of whichever boot the image was saved in.
# Around a savevm under KVM it stops the bridge so GDB lifts its breakpoints
# from guest RAM, and resumes it after. Whether qmu resumes a stop is decided
# by QEMU's run state around qmu's interrupt, never by pry's belief alone
# (`BridgeStop`). Any other client is never driven; it gets the warnings below.

# pry's own transport budget for one `pry resync`, and the headroom over it
# for the CLI start and the stop/resume around the op. The resync reads and
# decodes every code section of the loaded vmlinux for stray traps, so its
# cost grows with the image and with host load: a 7.0 KASAN vmlinux (52.8 MiB
# of text) took 19–23 s on a loaded host, and the 20 s budget this used to be
# cost the operator a healthy bridge (#233). 120 s is pry's own op limit.
PRY_RESYNC_TIMEOUT = 120
_PRY_CALL_SLACK = 15.0
# `pry kbase` takes no --timeout; pry's default transport budget is 30 s.
_PRY_KBASE_TIMEOUT = 30 + _PRY_CALL_SLACK
# `pry interrupt` / `pry continue --background` around a save or a rebase.
_PRY_STOP_TIMEOUT = 15.0
# How long a reset waits for the new boot to finish kernel init (the end of
# its boot-time text patching, or a getty's `login:` prompt when the cmdline
# hides the kernel's end-of-init lines) before it re-syncs; past it, qmu does
# not re-sync at all. Measured on KVM: init done ≈1.3 s after the reset; TCG
# boots several times slower.
RESET_KERNEL_WAIT_SECONDS = 30.0
# QEMU closes its sockets (the gdbstub's, QMP's) before its pid goes away,
# and tearing a large KVM guest down takes a while: a 2 GiB KASAN guest
# SIGKILLed while qmu drove its bridge still had its /proc entry when pry
# reported the stub gone (measured, #236). How long a drive step that failed
# waits for a QEMU whose QMP no longer answers to finish exiting.
_QEMU_EXIT_GRACE = 3.0


def _qemu_gone(inst: Any, run_state: Callable[[], str | None] | None = None) -> bool:
    """QEMU exited under the drive (#236): the recorded process identity is
    gone, once a dying process has had `_QEMU_EXIT_GRACE` to finish. A QEMU
    whose QMP still answers (`run_state`) is alive, with no wait."""
    if run_state is not None and run_state() is not None:
        return False
    deadline = time.monotonic() + _QEMU_EXIT_GRACE
    while instance_alive(inst):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


# pry's resync statuses that leave a location unable to fire (`not_armed`).
_NOT_ARMED = frozenset({"pending", "unreadable", "insert-failed", "not-resident"})


@dataclass(frozen=True)
class BridgeDrive:
    """What qmu did to the bridge it owns: the envelope's `debugger` object,
    the text-mode receipt (stderr notes), and warnings for every mode."""

    data: dict[str, Any]
    notes: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def _pry_error(proc: subprocess.CompletedProcess) -> str:
    """pry's own message: `--format json` errors are `{"ok": false, "error"}`
    on stderr."""
    for stream in (proc.stderr, proc.stdout):
        for line in reversed((stream or "").strip().splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                return payload["error"]
    text = (proc.stderr or "").strip() or (proc.stdout or "").strip()
    return text or f"exit {proc.returncode} with no diagnostic"


def _pry_json(argv: list[str], *, timeout: float) -> tuple[Any, str | None]:
    """Run `pry ARGV` (which must ask for `--format json`); (payload, error)."""
    pry = shutil.which("pry")
    if pry is None:
        return None, "pry is not on PATH"
    try:
        proc = subprocess.run(
            [pry, *argv], capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, f"`pry {argv[0]}` did not answer within {timeout:.0f} s"
    except OSError as exc:
        return None, f"could not run pry: {exc}"
    if proc.returncode != 0:
        return None, _pry_error(proc)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, f"`pry {argv[0]}` printed no JSON: {_pry_error(proc)}"
    # A result past pry's token limit is spilled: stdout is then a pointer
    # envelope and the result itself is the file it names.
    if isinstance(payload, dict) and isinstance(payload.get("artifact_path"), str):
        try:
            payload = json.loads(Path(payload["artifact_path"]).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"could not read pry's spilled result: {exc}"
    return payload, None


def _pry_resync(inst: Any) -> tuple[dict[str, Any] | None, str | None, bool]:
    """`pry resync` on the owned bridge: `(report, error, timed_out)`.

    `timed_out` when it failed only after using the whole budget qmu gave
    it — pry's own op timeout, or the CLI not answering at all (#233). That
    says the job is big or the host loaded, nothing about the bridge, and
    is read off the clock rather than pry's wording, which has changed.
    """
    started = time.monotonic()
    report, error = _pry_json(
        [
            "resync", "--instance", str(inst.gdb_bridge_pid), "--format", "json",
            "--timeout", str(PRY_RESYNC_TIMEOUT),
        ],
        timeout=PRY_RESYNC_TIMEOUT + _PRY_CALL_SLACK,
    )
    if error is None and not (isinstance(report, dict) and report.get("resynced") is True):
        return None, "`pry resync` answered without a resync report", False
    timed_out = error is not None and time.monotonic() - started >= PRY_RESYNC_TIMEOUT
    return report, error, timed_out


def _pry_kbase(inst: Any) -> tuple[dict[str, Any] | None, str | None]:
    """`pry kbase` on the owned bridge: the running kernel's validated `_text`,
    with the loaded vmlinux rebased to it (pry #66). Run it only at a stop:
    on a running target pry stops it and resumes it, success or not, and
    that resume re-inserts every breakpoint where the bridge has it."""
    report, error = _pry_json(
        ["kbase", "--instance", str(inst.gdb_bridge_pid), "--format", "json"],
        timeout=_PRY_KBASE_TIMEOUT,
    )
    if error is not None:
        return None, error
    if not (isinstance(report, dict) and isinstance(report.get("base"), str)):
        return None, "`pry kbase` answered without a base"
    apply = report.get("apply")
    if isinstance(apply, dict) and apply.get("applied") is False and apply.get("command"):
        # The base validated against a file GDB does not have loaded: the
        # breakpoints still resolve against whatever it does have.
        return None, (
            f"`pry kbase` found _text at {report['base']} but did not rebase the "
            f"bridge's symbols ({apply.get('reason', 'not applied')})"
        )
    return report, None


def _kbase_note(ident: str, kbase: dict[str, Any]) -> str:
    apply = kbase.get("apply") if isinstance(kbase.get("apply"), dict) else {}
    if apply.get("applied"):
        moved = (
            f"rebased the bridge's symbols to it (slide {apply.get('previous_slide', '?')} "
            f"→ {kbase.get('slide', '?')})"
        )
    else:
        moved = "the bridge's symbols were already there"
    return (
        f"[qmu] `pry kbase` on {ident} validated the running kernel's _text at "
        f"{kbase['base']} and {moved}."
    )


def _rebase_slides(kbase: dict[str, Any] | None) -> tuple[int, int] | None:
    """`(previous_slide, slide)` when the `pry kbase` qmu ran moved the
    bridge's symbols, else None (nothing moved, or pry did not say from where)."""
    if kbase is None or not isinstance(kbase.get("apply"), dict):
        return None
    apply = kbase["apply"]
    try:
        previous, slide = int(apply["previous_slide"], 16), int(kbase["slide"], 16)
    except (KeyError, TypeError, ValueError):
        return None
    if not apply.get("applied") or previous == slide:
        return None
    return previous, slide


# A code breakpoint at a literal address, the way GDB's `*ADDR` takes one
# (hex, octal, decimal). A `*EXPR` naming a symbol (`*func+4`) is re-evaluated
# when the symbols move, so it is not raw (pry #112 draws the same line).
_RAW_ADDRESS = re.compile(r"^\*\s*(?:0[xX]([0-9a-fA-F]+)|(0[0-7]*)|([1-9][0-9]*))\s*$")
_ADDR_MASK = (1 << 64) - 1


def _raw_address(location: Any) -> int | None:
    match = _RAW_ADDRESS.match(str(location or ""))
    if match is None:
        return None
    hex_digits, octal, decimal = match.groups()
    if hex_digits is not None:
        return int(hex_digits, 16)
    if octal is not None:
        return int(octal, 8)
    return int(decimal)


def _raw_breakpoints(inst: Any) -> dict[int, dict[str, Any]]:
    """The owned bridge's breakpoints set at a raw address, by number, read
    with `pry break list` (a resync entry names its location `N.M`, not the
    expression it was set with). Empty when the bridge did not answer."""
    listed, _ = _pry_json(
        ["break", "list", "--instance", str(inst.gdb_bridge_pid), "--format", "json"],
        timeout=15.0,
    )
    if not isinstance(listed, list):
        return {}
    return {
        bp["number"]: bp for bp in listed
        if isinstance(bp, dict) and isinstance(bp.get("number"), int)
        and bp.get("kind") in ("breakpoint", "hw-breakpoint")
        and _raw_address(bp.get("location")) is not None
    }


def _raw_moved_warning(
    inst: Any, event: str, slides: tuple[int, int],
    moved: list[tuple[dict[str, Any], dict[str, Any]]],
) -> str:
    """#238: a breakpoint set at a raw address stays at that address when
    `pry kbase` rebases the symbols, so after a KASLR move it sits where the
    kernel no longer runs that code, and no `pry resync` can move it. Name
    the address the same instruction has now and the commands that put the
    breakpoint there: pry's `rebased_address` when it confirmed the slide
    the address was set at (pry #112), else old − previous slide + slide."""
    ident = bridge_instance_id(inst.vm_id)
    previous, slide = slides
    items = []
    for entry, bp in moved:
        old = _raw_address(bp.get("location"))
        number = bp["number"]
        confirmed = isinstance(entry.get("rebased_address"), str)
        new = (
            int(entry["rebased_address"], 16) if confirmed
            else (old - previous + slide) & _ADDR_MASK
        )
        status = entry.get("status")
        where = {
            "unreadable": "nothing is mapped at its address now",
            "armed": "still armed at its address, where the moved kernel has other code",
        }.get(status, f"{status} at its address")
        flags = " --hardware" if bp.get("kind") == "hw-breakpoint" else ""
        if bp.get("temporary"):
            flags += " --temporary"
        if bp.get("condition"):
            flags += f" --condition {shlex.quote(str(bp['condition']))}"
        lead = "" if confirmed else f"if it was set while the symbols sat at slide {previous:#x}, "
        items.append(
            f"#{number} `{bp.get('location')}` ({where}): {lead}the same instruction "
            f"is now at {new:#x}: `pry --instance {ident} break delete {number}`, then "
            f"`pry --instance {ident} break set '*{new:#x}'{flags}`"
        )
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}': `pry kbase` moved the pry bridge {ident}'s "
        f"symbols (slide {previous:#x} → {slide:#x}) after {event}; breakpoints set by "
        "symbol or file:line moved with them, but a breakpoint set at a raw address "
        "does not follow a rebase, and no `pry resync` moves it: "
        + "; ".join(items) + ".\n"
    )


def _entries(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in report.get("breakpoints") or [] if isinstance(e, dict)]


def _entry_line(entry: dict[str, Any]) -> str:
    """One resync entry the way `pry resync` prints it in text."""
    parts = [f"#{entry.get('location') or entry.get('number', '?')}", str(entry.get("status", "?"))]
    if entry.get("address"):
        parts.append(f"@ {entry['address']}")
    what = entry.get("function") or entry.get("expression")
    if what:
        parts.append(str(what))
    line = " ".join(parts)
    if entry.get("detail"):
        line += f": {entry['detail']}"
    return line


def _owned_ref(inst: Any) -> dict[str, Any]:
    return {
        "bridge_pid": inst.gdb_bridge_pid,
        "bridge_instance_id": bridge_instance_id(inst.vm_id),
    }


def _pry_interrupt(inst: Any) -> tuple[dict[str, Any] | None, str | None]:
    """`pry interrupt` on the owned bridge; `interrupted` in the report is
    False when GDB believed the target stopped already (`BridgeStop` reads
    what that belief is worth)."""
    report, error = _pry_json(
        ["interrupt", "--instance", str(inst.gdb_bridge_pid), "--format", "json"],
        timeout=_PRY_STOP_TIMEOUT,
    )
    if error is not None:
        return None, error
    if not (isinstance(report, dict) and report.get("stopped") is True):
        return None, "`pry interrupt` did not report a stop"
    return report, None


def _pry_continue(inst: Any) -> str | None:
    """`pry continue --background` on the owned bridge; the error, if any."""
    _, error = _pry_json(
        ["continue", "--background", "--instance", str(inst.gdb_bridge_pid),
         "--format", "json"],
        timeout=_PRY_STOP_TIMEOUT,
    )
    return error


@dataclass(frozen=True)
class BridgeStop:
    """The owned bridge at the stop qmu went to take with `pry interrupt`.

    `before`/`after` are QEMU's run state right before and right after the
    interrupt. pry's `interrupted` is only GDB's belief, and GDB can believe
    the target stopped while QEMU runs it: a QMP `cont` (`qmu cont`) resumes
    the vCPU behind GDB's back, and the next packet the bridge sends halts
    it again (the gdbstub stops a running VM, as `paused`, on any byte it
    receives). pry then answers `interrupted: false` for a stop qmu's own
    touch made, and trusting that left a running guest halted after a save,
    a load or a KASLR reset (#226). So the stop is qmu's (`taken`) when pry
    interrupted the target, or when QEMU said `running` before and is not
    at a gdbstub stop (`debug`: a breakpoint, watchpoint or step hit in
    between, the operator's stop) after (`stale`).
    """

    inst: Any
    report: dict[str, Any]
    before: str | None
    after: str | None = None

    @property
    def stale(self) -> bool:
        """The bridge believed the target stopped while QEMU ran it."""
        return (
            self.report.get("interrupted") is not True
            and self.before == "running"
            and self.after != "debug"
        )

    @property
    def taken(self) -> bool:
        """qmu made this stop, so qmu resumes it."""
        return self.report.get("interrupted") is True or self.stale

    def at(self, after: str | None) -> BridgeStop:
        """This stop, with QEMU's run state right after the interrupt."""
        return replace(self, after=after)


def _stop(inst: Any, before: str | None) -> tuple[BridgeStop | None, str | None]:
    """`pry interrupt` the owned bridge, QEMU's run state being `before`."""
    report, error = _pry_interrupt(inst)
    if error is not None:
        return None, error
    return BridgeStop(inst, report, before), None


def _stale_note(stop: BridgeStop, event: str) -> str:
    """The receipt for a stop qmu made on a bridge whose view was stale."""
    ident = bridge_instance_id(stop.inst.vm_id)
    return (
        f"[qmu] The pry bridge {ident} (pid {stop.inst.gdb_bridge_pid}) believed "
        "the target stopped while QEMU ran it (it was resumed behind GDB's back, "
        f"e.g. by `qmu cont`), so qmu's stop for {event} halted a running guest; "
        "qmu resumed it through the bridge (`pry continue --background`), which "
        "also re-inserted GDB's breakpoints: they fire from now on."
    )


def _waiters_note(stop: BridgeStop, event: str, resumed: bool) -> str | None:
    """#228: qmu's stop is the public `pry interrupt`, which ends whatever the
    operator has in flight on the same bridge with a stop of its own; say so,
    or an agent takes that stop for a real one. Only a stop pry actually made
    (`interrupted`) ends a waiter: on a target GDB believed stopped none can
    be waiting."""
    if stop.report.get("interrupted") is not True:
        return None
    ident = bridge_instance_id(stop.inst.vm_id)
    after = (
        "which qmu then resumed: that stop was qmu's, not a hit, so wait again"
        if resumed
        else "and the target is still at that stop"
    )
    return (
        f"[qmu] qmu's `pry interrupt` for {event} ended any `pry wait` or "
        f"foreground `pry continue` running on {ident} with a `reason: signal "
        f"SIGINT` stop, {after}."
    )


def _stray_line(trap: dict[str, Any]) -> str:
    """One `stray_traps` entry of a `pry resync` report: where, the bytes
    pry found and the symbol file's, and what pry did."""
    where = str(trap.get("address", "?"))
    if trap.get("function"):
        where += f" ({trap['function']})"
    if not trap.get("trap_in_memory"):
        return f"{where}: a breakpoint the stub recorded for nobody, no trap in memory; dropped"
    found = f"guest {trap.get('guest_bytes', '?')}"
    if trap.get("elf_bytes"):
        found += f" → ELF {trap['elf_bytes']}"
    return f"{where}: {found}, " + (
        "repaired" if trap.get("repaired") else "NOT repaired (it still traps)"
    )


def _stray_warning(inst: Any, event: str, strays: list[dict[str, Any]]) -> str:
    """#230: `pry resync` (pry #83) writes the symbol file's bytes over every
    trap in mapped code that no breakpoint owns. That is kernel text qmu had
    rewritten, and pry has taken patched code for a trap before (pry #88), so
    the receipt names every address it touched, in every mode."""
    ident = bridge_instance_id(inst.vm_id)
    repaired = sum(bool(t.get("repaired")) for t in strays)
    if event == "system_reset":
        origin = (
            "A reboot loads the kernel afresh, so none is expected after it: "
            "pry may have taken code the kernel patched for a trap (pry #88)."
        )
    else:
        origin = (
            "They are most likely int3 bytes baked into the image by a save "
            "that reported `breakpoints_in_image: \"possible\"`."
        )
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}': the `pry resync` qmu ran on {ident} "
        f"after {event} found {len(strays)} trap(s) in kernel code that no "
        f"breakpoint owned and wrote the symbol file's bytes over {repaired}: "
        + "; ".join(_stray_line(t) for t in strays)
        + f". {origin} An unexpected crash in one of these functions after "
        f"{event} is a debugger artifact (a trap left in the code, or a byte pry "
        "wrote over code the kernel patched), not your PoC's.\n"
    )


def _strays(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in report.get("stray_traps") or [] if isinstance(t, dict)]


def _resynced(
    inst: Any, event: str, report: dict[str, Any], *,
    kbase: dict[str, Any] | None = None, stop: BridgeStop | None = None,
    resume_error: str | None = None, raw: dict[int, dict[str, Any]] | None = None,
    **extra: Any,
) -> BridgeDrive:
    """The owned bridge re-synced at `stop`. Its symbols are known to be the
    running kernel's: a nokaslr kernel cannot move, and on a KASLR one
    `kbase` is the base `pry kbase` validated just before. When qmu made the
    stop (`stop.taken`) it resumed the target after the re-sync
    (`resume_error` when that failed). `raw` is the bridge's raw-address
    breakpoints (`_raw_breakpoints`), read when `kbase` moved the symbols:
    those stayed where they were (#238)."""
    ident = bridge_instance_id(inst.vm_id)
    summary = report.get("summary") or {}
    taken = stop is not None and stop.taken
    resumed = taken and resume_error is None
    state = "running (qmu resumed it)" if resumed else report.get("state", "unknown")
    entries = _entries(report)
    strays = _strays(report)
    stray_count = (
        f"{len(strays)} stray trap(s), {sum(bool(t.get('repaired')) for t in strays)} "
        "repaired; "
        if strays else ""
    )
    notes = [_kbase_note(ident, kbase)] if kbase is not None else []
    notes += [
        f"[qmu] Re-synced the pry bridge {ident} (pid {inst.gdb_bridge_pid}) "
        f"after {event}: {summary.get('armed', 0)} armed, "
        f"{summary.get('not_armed', 0)} not armed; {stray_count}target {state}.",
        *(f"  {_entry_line(e)}" for e in entries),
        *(f"  stray trap {_stray_line(t)}" for t in strays),
    ]
    warnings: list[str] = []
    if resume_error is not None:
        warnings.append(
            f"[qmu] WARNING: VM '{inst.vm_id}': qmu stopped the pry bridge {ident} "
            f"to re-sync it after {event} and could not resume it ({resume_error}); "
            "the guest is halted in the debugger: `pry --instance "
            f"{ident} continue --background`.\n"
        )
    elif state == "stopped" and stop is not None and stop.before == "running":
        # QEMU ran the guest when qmu went to stop it and was at a gdbstub
        # stop right after: a breakpoint hit in between. The operator's stop,
        # but a guest the command found running is now halted.
        warnings.append(
            f"[qmu] WARNING: VM '{inst.vm_id}': the target stopped by itself "
            f"({_stop_reason(stop.report)}) right after {event}, as qmu went to "
            f"re-sync the pry bridge {ident}; it is left at that stop, halted: "
            f"`pry --instance {ident} continue --background` resumes it.\n"
        )
    elif state == "stopped":
        notes.append(
            f"[qmu] The target is stopped in the debugger: resume it with "
            f"`pry --instance {ident} continue --background`."
        )
    if resumed and stop.stale:
        notes.append(_stale_note(stop, event))
    if taken:
        waiters = _waiters_note(stop, event, resumed)
        if waiters is not None:
            notes.append(waiters)
    if strays:
        warnings.append(_stray_warning(inst, event, strays))
    slides = _rebase_slides(kbase)
    moved: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if slides is not None and raw:
        for e in entries:
            number = e.get("number")
            if (
                number in raw and number not in {bp["number"] for _, bp in moved}
                and e.get("status") not in ("disabled", "pending")
            ):
                moved.append((e, raw[number]))
    stayed = {id(e) for e, _ in moved}
    not_armed = [e for e in entries if e.get("status") in _NOT_ARMED and id(e) not in stayed]
    mismatch = [
        e for e in entries
        if e.get("elf_match") is False and e.get("status") not in _NOT_ARMED
        and id(e) not in stayed
    ]
    if mismatch:
        # The symbols sit at the kernel's base, so memory that differs from
        # the ELF is the kernel's own boot-time patching (alternatives,
        # return thunks, static keys), and the breakpoint is where it was set.
        where = (
            f"the symbols sit at the base `pry kbase` validated ({kbase['base']})"
            if kbase is not None
            else "this nokaslr kernel did not move"
        )
        notes.append(
            f"[qmu] {len(mismatch)} armed location(s) hold code the kernel "
            "patched at boot (`elf_match: false`; alternatives, return thunks, "
            f"static keys) — {where}, so they trap where they were set"
            + (", unless the symbol file is not this kernel's." if kbase is None else ".")
        )
    if moved:
        warnings.append(_raw_moved_warning(inst, event, slides, moved))
    if not_armed:
        warnings.append(
            f"[qmu] WARNING: VM '{inst.vm_id}': the pry bridge {ident} re-synced "
            f"after {event}, but its breakpoints are not all live. "
            f"{len(not_armed)} location(s) are not armed and will not fire: "
            + "; ".join(_entry_line(e) for e in not_armed)
            + f". Re-run `pry --instance {ident} resync` once that code is mapped.\n"
        )
    data: dict[str, Any] = {"action": "resynced", "event": event, **_owned_ref(inst), **extra}
    if taken:
        data["interrupted"] = True
        data["resumed"] = resumed
        if stop.stale:
            data["stale_stop"] = True
        if resume_error is not None:
            data["resume_error"] = resume_error
    if kbase is not None:
        data["kbase"] = kbase
    data["resync"] = report
    return BridgeDrive(data=data, notes=tuple(notes), warnings=tuple(warnings))


def _read_and_reap(inst: Any) -> tuple[list[Any] | None, bool, bool, str]:
    """Read the owned bridge's breakpoint list, then reap it:
    `(dropped, was_alive, reaped, lost)`.

    The list is read first so the envelope names what went away (`None` when
    the bridge could not even answer that); `lost` says it in prose.
    """
    dropped, _ = _pry_json(
        ["break", "list", "--instance", str(inst.gdb_bridge_pid), "--format", "json"],
        timeout=15.0,
    )
    if not isinstance(dropped, list):
        dropped = None
    was_alive = bridge_alive(inst)
    reaped = reap_bridge(inst)
    if dropped:
        lost = "; ".join(
            f"#{b.get('number', '?')} {b.get('location') or b.get('expression') or '?'}"
            + ("" if b.get("enabled", True) else " (disabled)")
            for b in dropped if isinstance(b, dict)
        )
        lost = f"Its breakpoints are gone: {lost}."
    elif dropped == []:
        lost = "It had no breakpoints."
    else:
        lost = "Its breakpoint list could not be read before the teardown."
    return dropped, was_alive, reaped, lost


def _torn_down(
    inst: Any, event: str, happened: str, reason: str, *, first: str = ""
) -> BridgeDrive:
    """Reap the owned bridge and say what was lost and how to get it back."""
    ref = _owned_ref(inst)
    ident = ref["bridge_instance_id"]
    dropped, _, reaped, lost = _read_and_reap(inst)
    fate = (
        "qmu tore that bridge down"
        if reaped
        else "qmu tried to tear that bridge down and could not confirm it exited "
        "(check `pry doctor`)"
    )
    warning = (
        f"[qmu] WARNING: VM '{inst.vm_id}' was {happened} under the pry bridge "
        f"`qmu gdb` spawned ({ident}, pid {ref['bridge_pid']}); {fate} because "
        f"{reason}. {lost} {first}Reattach once the guest is up: `qmu gdb --vm "
        f"{inst.vm_id} --symbols <vmlinux>` (it leaves the guest halted), on a "
        f"KASLR guest `pry --instance {ident} kbase` (rebases the loaded vmlinux "
        "to the running kernel, no SSH needed), set the breakpoints again, then "
        f"`pry --instance {ident} continue --background` (GDB arms breakpoints "
        "only when it resumes) and prove one with a canary hit.\n"
    )
    data = {
        "action": "torn_down", "event": event, **ref, "reason": reason,
        "bridge_reaped": reaped, "breakpoints_dropped": dropped,
    }
    return BridgeDrive(data=data, warnings=(warning,))


def _qemu_exited(inst: Any, event: str, failed: str) -> BridgeDrive:
    """QEMU went away while qmu drove its bridge (#236): a SIGKILL, a crash,
    a concurrent `qmu kill`. The step that failed (`failed`) says nothing
    about the bridge; the VM is stopped, its stub gone with it, so the
    bridge is reaped and the warning sends the reader to what happened to
    the VM — never to a reattach, which needs a running VM.
    """
    ref = _owned_ref(inst)
    ident = ref["bridge_instance_id"]
    dropped, was_alive, reaped, lost = _read_and_reap(inst)
    if reaped:
        fate = "qmu reaped that bridge, whose stub went with QEMU"
    elif not was_alive:
        fate = "that bridge has exited too"
    else:
        fate = (
            "qmu tried to reap that bridge and could not confirm it exited "
            "(check `pry doctor`)"
        )
    reason = f"QEMU exited during the re-sync after {event}; the VM is stopped ({failed})"
    vm = inst.vm_id
    warning = (
        f"[qmu] WARNING: VM '{vm}': QEMU exited while qmu was re-syncing the pry "
        f"bridge `qmu gdb` spawned ({ident}, pid {ref['bridge_pid']}) after {event}, "
        f"so the VM is stopped ({failed}); {fate}. {lost} "
        f"There is no guest to reattach to: see what happened with `qmu status "
        f"--vm {vm}`, `qmu crash --vm {vm}` and `qmu log --vm {vm} --tail 50`.\n"
    )
    data = {
        "action": "torn_down", "event": event, **ref, "reason": reason,
        "qemu_exited": True, "bridge_reaped": reaped, "breakpoints_dropped": dropped,
    }
    return BridgeDrive(data=data, warnings=(warning,))


def _resync_timed_out(
    inst: Any, event: str, *, stop: BridgeStop, kbase: dict[str, Any] | None,
    resume_error: str | None, **extra: Any,
) -> BridgeDrive:
    """`pry resync` ran out of the budget qmu gave it (#233).

    A slow resync is a big image on a loaded host, not a bridge whose view
    nobody can correct: the bridge is left as it is, its symbols at the
    kernel's base (nokaslr, or the base `pry kbase` validated just before),
    and a stop qmu made is resumed as after a re-sync, so GDB re-inserts its
    breakpoints. What is missing is pry's verification and its stray-trap
    repair; the warning names the `pry resync` that does both.
    """
    ref = _owned_ref(inst)
    ident = ref["bridge_instance_id"]
    resumed = stop.taken and resume_error is None
    reason = (
        f"`pry resync` ran out of time: it did not finish within the "
        f"{PRY_RESYNC_TIMEOUT} s qmu gives it"
    )
    if resumed:
        target = (
            "qmu resumed the target it had stopped for the re-sync, so GDB "
            "re-inserted its breakpoints"
        )
    elif stop.taken:
        target = (
            f"qmu could not resume the target it had stopped for the re-sync "
            f"({resume_error}): the guest is halted in the debugger, `pry "
            f"--instance {ident} continue --background` resumes it"
        )
    else:
        target = (
            "the target is left at the debugger stop it was at: `pry --instance "
            f"{ident} continue --background` resumes it"
        )
    rebased = (
        f", its symbols at the base `pry kbase` validated ({kbase['base']})"
        if kbase is not None else ""
    )
    notes = [_kbase_note(ident, kbase)] if kbase is not None else []
    notes.append(
        f"[qmu] `pry resync` on {ident} (pid {ref['bridge_pid']}) after {event} ran "
        f"out of time ({PRY_RESYNC_TIMEOUT} s): no re-sync report; target "
        + ("running (qmu resumed it)." if resumed else "stopped.")
    )
    warning = (
        f"[qmu] WARNING: VM '{inst.vm_id}': the `pry resync` qmu ran on the pry "
        f"bridge `qmu gdb` spawned ({ident}, pid {ref['bridge_pid']}) after {event} "
        f"ran out of time: it did not finish within the {PRY_RESYNC_TIMEOUT} s qmu "
        "gives it (it reads and decodes every code section of the loaded vmlinux "
        "for stray traps, which takes longer for a large image on a loaded host). "
        f"Nothing is wrong with the bridge, so qmu left it as it is{rebased}; "
        f"{target}. None of its breakpoints is verified, and any stray trap is "
        f"still in place: `pry --instance {ident} resync --timeout 600` re-arms and "
        "checks every one (`summary.not_armed`) and repairs stray traps (it stops "
        "a running target and resumes it).\n"
    )
    data: dict[str, Any] = {
        "action": "not_resynced", "event": event, **ref, "reason": reason,
        "timed_out": True, "interrupted": stop.taken, "resumed": resumed, **extra,
    }
    if stop.stale:
        data["stale_stop"] = True
    if resume_error is not None:
        data["resume_error"] = resume_error
    if kbase is not None:
        data["kbase"] = kbase
    return BridgeDrive(data=data, notes=tuple(notes), warnings=(warning,))


def _not_resynced(inst: Any, event: str, reason: str, recovery: str) -> BridgeDrive:
    """Leave the owned bridge as it is and say why, with the manual recovery.

    For when qmu could not re-sync for reasons that say nothing about the
    bridge (pry missing from qmu's PATH, a boot whose end of init never
    showed): tearing a healthy bridge down there would lose its breakpoints
    for nothing.
    """
    ref = _owned_ref(inst)
    lead = (
        f"[qmu] WARNING: VM '{inst.vm_id}': qmu did not re-sync the pry bridge "
        f"`qmu gdb` spawned ({ref['bridge_instance_id']}, pid "
        f"{ref['bridge_pid']}) after {event} because {reason}; the bridge is "
        "left as it is.\n"
    )
    data = {"action": "not_resynced", "event": event, **ref, "reason": reason}
    return BridgeDrive(data=data, warnings=(lead, recovery))


def _pry_missing() -> bool:
    return shutil.which("pry") is None


_NO_PRY = "`pry` is not on qmu's PATH"


# What a bridge whose base `pry kbase` could not validate has at stake, per
# event, and the first step back.
_LOAD_BASE = (
    "which is right only if the image was saved in this boot: if nothing reset "
    "or rebooted the guest since the save, `pry --instance {ident} continue "
    "--background` re-arms them in place. Otherwise rebase first:"
)
_RESET_BASE = "which the reset re-slid, so they are stale. Rebase first:"


def _left_stopped_unrebased(
    inst: Any, event: str, error: str, stop: BridgeStop, at_stake: str
) -> BridgeDrive:
    """`pry kbase` failed at the stop qmu took: keep that stop.

    At a stop GDB holds none of its breakpoints in guest RAM; resuming puts
    every one back at the address the bridge has, which is the stale base
    if the kernel moved. So the target is left stopped and the warning says
    how to rebase before resuming it.
    """
    ref = _owned_ref(inst)
    ident = ref["bridge_instance_id"]
    held = (
        "left at the stop qmu took for the rebase"
        if stop.taken
        else "left at the debugger stop it was already at"
    )
    reason = f"`pry kbase` could not validate the kernel's base: {error}"
    warning = (
        f"[qmu] WARNING: VM '{inst.vm_id}': qmu did not re-sync the pry bridge "
        f"`qmu gdb` spawned ({ident}, pid {ref['bridge_pid']}) after {event}: "
        f"{reason}. The target is {held}, with none of its breakpoints in "
        "guest RAM, rather than resume it: resuming re-inserts every breakpoint "
        "at the address the bridge has now, "
        + at_stake.format(ident=ident)
        + f" `pry --instance {ident} load <vmlinux>` if `pry kbase` found no "
        f"kernel symbol file, then `pry --instance {ident} kbase` and `pry "
        f"--instance {ident} resync`; or, over SSH, `qmu cont --vm {inst.vm_id}` "
        "(the guest runs with no breakpoint in RAM), `eval \"$(qmu kbase --vm "
        f"{inst.vm_id} --symbols <vmlinux>)\"`, then `pry --instance {ident} "
        "resync --base $KBASE --symbols <vmlinux>` (it stops the guest again). "
        f"Then `pry --instance {ident} continue --background`. A breakpoint set "
        "at a raw address (`*0x…`) does not follow a rebase: delete it and set "
        "it again.\n"
    )
    data = {
        "action": "not_resynced", "event": event, **ref, "reason": reason,
        "interrupted": stop.taken, "resumed": False,
    }
    if stop.stale:
        data["stale_stop"] = True
    return BridgeDrive(data=data, warnings=(warning,))


def _resync_at_stop(
    inst: Any, event: str, *, run_state: Callable[[], str | None], happened: str,
    recovery: str, at_stake: str | None = None, **extra: Any,
) -> BridgeDrive:
    """Re-sync the owned bridge at a stop qmu holds, rebasing it first on a
    KASLR guest (`at_stake`: what a base `pry kbase` cannot validate leaves
    at risk; None on a nokaslr guest, whose base cannot move).

    `pry kbase` and `pry resync` each stop a running target and resume it,
    and under KVM that resume re-inserts every breakpoint where the bridge
    has it now: at the stale base when the kernel moved, even after a `pry
    kbase` that failed. And a bridge whose view is stale (GDB believes the
    target stopped while QEMU runs it, #226) resumes nothing: its first
    packet halts the guest, and pry reports the stop it believed in. So qmu
    takes the stop itself (`pry interrupt`), reading QEMU's run state on both
    sides of it (`run_state`), both run at that stop, and qmu resumes the
    target only when the stop is its own (`BridgeStop.taken`) and the
    symbols sit at a validated base. A target the operator had stopped is
    left there. When `pry kbase` cannot validate a base, the stop is kept
    (`_left_stopped_unrebased`). A step that fails because QEMU exited
    meanwhile is reported as that (`_qemu_exited`, #236); a `pry resync`
    that only ran out of time leaves the bridge (`_resync_timed_out`, #233).
    After a rebase the bridge's raw-address breakpoints are read at the stop
    (`_raw_breakpoints`): they did not move with the symbols (#238).
    """
    stop, error = _stop(inst, run_state())
    if error is not None:
        if _qemu_gone(inst, run_state):
            return _qemu_exited(inst, event, f"`pry interrupt` failed: {error}")
        return _not_resynced(
            inst, event, f"qmu could not stop the bridge to re-sync it ({error})",
            recovery,
        )
    stop = stop.at(run_state())
    kbase = None
    if at_stake is not None:
        kbase, error = _pry_kbase(inst)
        if error is not None:
            if _qemu_gone(inst, run_state):
                return _qemu_exited(inst, event, f"`pry kbase` failed: {error}")
            return _left_stopped_unrebased(inst, event, error, stop, at_stake)
    report, error, timed_out = _pry_resync(inst)
    if error is not None:
        if _qemu_gone(inst, run_state):
            return _qemu_exited(inst, event, f"`pry resync` failed: {error}")
        if timed_out:
            resume_error = _pry_continue(inst) if stop.taken else None
            return _resync_timed_out(
                inst, event, stop=stop, kbase=kbase, resume_error=resume_error, **extra,
            )
        return _torn_down(inst, event, happened, f"`pry resync` failed: {error}")
    raw = _raw_breakpoints(inst) if _rebase_slides(kbase) is not None else None
    resume_error = _pry_continue(inst) if stop.taken else None
    if resume_error is not None and _qemu_gone(inst, run_state):
        return _qemu_exited(inst, event, f"`pry continue` failed: {resume_error}")
    return _resynced(
        inst, event, report, kbase=kbase, stop=stop, resume_error=resume_error,
        raw=raw, **extra,
    )


def drive_bridge_after_loadvm(
    inst: Any, event: str, *, run_state: Callable[[], str | None]
) -> BridgeDrive:
    """Re-sync the owned bridge after a successful `loadvm` (`event` names it).

    The restored image is the boot it was saved from, mapped and ready, so
    one `pry resync` re-reads the stop state and re-arms every breakpoint at
    once. On a KASLR guest that boot need not be the current one (the guest
    was reset or rebooted since the save, #200), so `pry kbase` first rebases
    the symbols to the restored kernel. Both at a stop qmu holds
    (`_resync_at_stop`; `run_state` reads QEMU's run state). A re-sync that
    fails leaves a view nobody can correct: tear down — unless it only ran
    out of time (#233), or QEMU exited under it (#236).
    """
    recovery = loadvm_stale_session_warning(inst) + "\n"
    if _pry_missing():
        return _not_resynced(inst, event, _NO_PRY, recovery)
    return _resync_at_stop(
        inst, event, run_state=run_state, happened=f"rewound by {event}",
        recovery=recovery, at_stake=None if _kaslr_off(inst) else _LOAD_BASE,
    )


def drive_bridge_after_reset(
    inst: Any, *, epoch: int | None, qemu_status: str | None,
    run_state: Callable[[], str | None],
) -> BridgeDrive:
    """Re-sync the owned bridge after a qmu-issued `system_reset`, or tear it down.

    A reset reboots the kernel, and the new kernel patches its own text at
    boot (alternatives, return thunks, static keys): a breakpoint armed before
    that is overwritten, or trips the patcher into a WARNING (`missing return
    thunk` from `apply_returns`) that reads as a guest crash. So on a running
    guest qmu waits until the new boot's console shows the end of kernel init
    or, later still, a getty's `login:` prompt (`serial.kernel_init_done`,
    bounded by `RESET_KERNEL_WAIT_SECONDS`; a `quiet` cmdline hides the
    former, #205), then re-syncs at a stop qmu holds (`_resync_at_stop`),
    rebasing first with `pry kbase` on a KASLR guest. If neither shows (no
    getty on a quiet console, a slow boot, QEMU gone) qmu does not re-sync
    and says so; if `pry kbase` cannot validate a base, the target is left
    stopped with no breakpoint in guest RAM. `qemu_status` is QEMU's run
    state right after the reset. A guest halted when it was reset cannot be
    made true and is torn down instead: it stays at the reset vector, where
    no kernel address is readable, and GDB cannot resume it past breakpoints
    it cannot insert (measured: `pry continue` → `Command aborted`).
    """
    event = "system_reset"
    if qemu_status != "running":
        if _qemu_gone(inst, run_state):
            return _qemu_exited(
                inst, event, "QEMU's run state could not be read after the reset"
            )
        why = (
            f"the guest was halted when it was reset (QEMU '{qemu_status}')"
            if qemu_status is not None
            else "QEMU's run state could not be read after the reset"
        )
        return _torn_down(
            inst, event, "reset",
            f"{why}: a halted reset guest sits at the reset vector, where no "
            "kernel address is readable, so no breakpoint can be re-armed and "
            "GDB cannot resume it past breakpoints it cannot insert",
            first=(
                "A clean detach lets QEMU boot it; if `qmu status --vm "
                f"{inst.vm_id}` still says `paused`, boot it with `qmu cont --vm "
                f"{inst.vm_id}` first. "
            ),
        )
    recovery = reset_dropped_breakpoints_warning(inst, qemu_status=qemu_status) + "\n"
    if _pry_missing():
        return _not_resynced(inst, event, _NO_PRY, recovery)
    if epoch is None:
        # Without the pre-reset log size, the previous boot's end-of-init
        # lines would satisfy the wait at once.
        return _not_resynced(
            inst, event,
            "the serial log size before the reset is unknown, so the new boot's "
            "end of kernel init cannot be told from the previous one's",
            recovery,
        )
    started = time.monotonic()
    deadline = started + RESET_KERNEL_WAIT_SECONDS
    while not kernel_init_done(inst.serial_log, start_offset=epoch):
        if not instance_alive(inst):
            return _qemu_exited(
                inst, event, "the new boot had not finished kernel init"
            )
        if time.monotonic() >= deadline:
            return _not_resynced(
                inst, event, _boot_not_done(inst, time.monotonic() - started), recovery,
            )
        time.sleep(0.1)
    return _resync_at_stop(
        inst, event, run_state=run_state, happened="reset", recovery=recovery,
        at_stake=None if _kaslr_off(inst) else _RESET_BASE,
        waited_seconds=round(time.monotonic() - started, 2),
    )


def _boot_not_done(inst: Any, waited: float) -> str:
    """Why a reset's wait for the end of the new boot ran out."""
    hidden = init_lines_hidden(getattr(inst, "cmdline", "") or "")
    if hidden is not None:
        why = (
            "neither the end of kernel init nor a `login:` prompt showed on the "
            f"console within {waited:.0f} s (the recorded cmdline's `{hidden}` "
            "hides the kernel's end-of-init lines, so only a getty's prompt on "
            "the console can show the boot is done)"
        )
    else:
        why = (
            "the new kernel did not show the end of its init (or a `login:` "
            f"prompt) on the console within {waited:.0f} s (the boot is slow or "
            "stuck)"
        )
    return (
        f"{why}, and arming a breakpoint before the kernel has patched its own "
        "text can trip that patching"
    )


# --- A save under the bridge qmu owns (#201, #226) ---------------------------
#
# Under KVM GDB's breakpoints are int3 bytes in guest RAM whenever it has the
# target running, and a savevm freezes them into the image. At a debugger stop
# GDB has lifted them, so with its own bridge attached and the guest running
# qmu stops the bridge, saves, and resumes it: the image is clean without the
# operator's interrupt / save / continue. The caller reads QEMU's run state
# right after the interrupt (`BridgeStop.at`), which decides whether the stop
# was qmu's to resume.


def stop_bridge_for_save(
    inst: Any, qemu_status: str | None
) -> tuple[BridgeStop | None, str | None]:
    """`pry interrupt` the owned bridge before a savevm; `(stop, error)`.

    `(None, None)` where it does not apply: TCG (breakpoints never reach
    guest RAM), QEMU not `running` (a debugger stop is already clean, and a
    pause is classified by `savevm_breakpoint_state`), a client qmu did not
    spawn, no `pry`. `(None, error)` when the interrupt failed: the save
    goes ahead and reports what it can.
    """
    if (
        qemu_status != "running" or _tcg(inst) or _pry_missing()
        or not qmu_bridge_attached(inst)
    ):
        return None, None
    return _stop(inst, qemu_status)


def _stop_reason(report: dict[str, Any]) -> str:
    """pry's stop reason the way `pry status` prints it."""
    reason = report.get("reason")
    if not isinstance(reason, dict):
        return "reason unknown"
    if reason.get("kind") == "breakpoint-hit":
        return f"breakpoint #{reason.get('number', '?')} hit"
    if reason.get("kind") == "signal":
        return f"signal {reason.get('signal', '?')}"
    return str(reason.get("kind", "reason unknown"))


def resume_bridge_after_save(stop: BridgeStop, event: str) -> BridgeDrive:
    """Resume the bridge `stop_bridge_for_save` stopped, once the save returned.

    Only a stop qmu made (`stop.taken`) is resumed: the target running when
    qmu went to stop it and not at a gdbstub stop right after, whatever pry
    believed (#226). A breakpoint hit in between is the operator's stop; the
    guest the save found running is then halted, which a warning says in
    every mode.
    """
    inst = stop.inst
    ref = _owned_ref(inst)
    ident = ref["bridge_instance_id"]
    data: dict[str, Any] = {
        "action": "stopped_for_save", "event": event, **ref,
        "interrupted": stop.taken,
    }
    if stop.stale:
        data["stale_stop"] = True
    if not stop.taken:
        data["resumed"] = False
        return BridgeDrive(data=data, warnings=(
            f"[qmu] WARNING: VM '{inst.vm_id}': the target stopped by itself "
            f"({_stop_reason(stop.report)}; QEMU '{stop.after}') as qmu went to "
            f"stop the pry bridge {ident} for {event}; the image was saved at that "
            "stop, and the guest is left halted there: `pry --instance "
            f"{ident} continue --background` resumes it.\n",
        ))
    error = _pry_continue(inst)
    data["resumed"] = error is None
    waiters = _waiters_note(stop, event, error is None)
    ended = (waiters,) if waiters is not None else ()
    if error is None:
        if stop.stale:
            return BridgeDrive(data=data, notes=(_stale_note(stop, event),))
        return BridgeDrive(data=data, notes=(
            f"[qmu] Stopped the pry bridge {ident} (pid {ref['bridge_pid']}) for "
            f"{event}, so GDB had lifted its breakpoints from guest RAM while QEMU "
            "saved, then resumed it (`pry continue --background`).",
            *ended,
        ))
    data["resume_error"] = error
    return BridgeDrive(data=data, notes=ended, warnings=(
        f"[qmu] WARNING: VM '{inst.vm_id}': qmu stopped the pry bridge {ident} "
        f"for {event} and could not resume it ({error}); the guest is halted in "
        f"the debugger: `pry --instance {ident} continue --background`.\n",
    ))


def save_left_stopped_warning(stop: BridgeStop, event: str) -> str:
    """The save outran its budget with the owned bridge stopped for it by qmu."""
    ident = bridge_instance_id(stop.inst.vm_id)
    return (
        f"[qmu] WARNING: VM '{stop.inst.vm_id}': qmu stopped the pry bridge "
        f"{ident} for {event}, and left it stopped because the save had not "
        "returned: resuming then would put its breakpoints back into RAM that "
        "may still be being saved. Once `qmu snapshot list` shows the tag, "
        f"resume it: `pry --instance {ident} continue --background`.\n"
    )


def save_stop_failed_warning(inst: Any, error: str) -> str:
    """`pry interrupt` on the owned bridge failed before a save."""
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}': qmu could not stop the pry bridge "
        f"{bridge_instance_id(inst.vm_id)} for the save ({error}), so it saved "
        "with the guest running.\n"
    )


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
# overwrites the software breakpoints' int3s and re-slides KASLR exactly like a
# qmu `system_reset`, but no qmu command issued it. Its kernel boot banner is in
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


def note_coherence_warnings(*warnings: str) -> None:
    """Record warnings that must reach the dispatch's Result or error envelope."""
    current = _coherence_warnings.get()
    _coherence_warnings.set(current + tuple(w for w in warnings if w not in current))


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
# against a live pry bridge (#183, #188, #200), under KVM and under TCG,
# because the two differ: under KVM a breakpoint is an int3 QEMU writes into
# guest RAM, so a rewind or reset takes it out of RAM while QEMU and GDB still
# count it inserted, and GDB's lift-at-stop / insert-on-resume cycle (`pry
# interrupt` → `pry continue --background`) puts it back. Under TCG
# breakpoints live in QEMU's translator, keyed by virtual address: a load or
# reset leaves them in force (measured: the canary fired with no re-arm after
# both), and only a KASLR move takes the code out from under them — a reboot
# re-slides the kernel, and a load restores the base of the boot the image
# was saved in. `pry kbase` (pry #66) finds the running kernel's base with no
# SSH; `pry resync` (pry #61) re-arms and says what is armed.


def _kaslr_off(inst: Any) -> bool:
    return "nokaslr" in (getattr(inst, "cmdline", "") or "").split()


def _tcg(inst: Any) -> bool:
    """Positively TCG; None (a pre-#39 record) is treated as KVM."""
    return getattr(inst, "kvm", None) is False


def _rebase_recovery(vm_id: str, ref: str, gloss: str) -> str:
    """Re-derive the kernel base and re-arm at it, with or without SSH.

    Breakpoints set by symbol or file:line follow the rebase; one set at a
    raw address does not (#238), and saying "no re-set needed" for it sent
    the reader to a `pry resync` that can never arm it.
    """
    return (
        f"`pry --instance {ref} kbase` (finds the running kernel's _text with no "
        "SSH, validates it against the loaded vmlinux and rebases that file; it "
        f"exits 1 rather than guess), then `pry --instance {ref} resync` "
        f"(re-arms every breakpoint and reports `summary.not_armed`){gloss}; or "
        f"`eval \"$(qmu kbase --vm {vm_id} --symbols <vmlinux>)\"` once SSH "
        f"serves, then `pry --instance {ref} resync --base $KBASE`. Both work "
        "on a running target, and breakpoints set by symbol or file:line "
        "re-resolve to the new base (no re-set needed). One set at a raw address "
        "(`*0x…`) stays at that address: delete it and set it again at the "
        "address minus the old slide plus the new one (`pry resync` names it "
        "as `rebased_address` when pry knows the slide it was set at)."
    )


def loadvm_stale_session_warning(inst: Any) -> str:
    """#44/#200 — `snapshot load` rewound the guest but the debugger did not.

    The image restores the kernel at the base of the boot it was saved in.
    On a KASLR guest that is the current boot's only if nothing reset or
    rebooted it since the save, which qmu does not track, so the recovery
    re-derives the base instead of assuming it did not move.
    """
    ref, gloss = _bridge_ref(inst)
    lead = (
        f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and was just rewound "
        "by snapshot load. An attached debugger does NOT re-sync: if it was at "
        "a stop, its stop reason still names that pre-load stop (frame and "
        "registers are re-read and current)"
    )
    moved = (
        " The image also restores the kernel at the KASLR base of the boot it "
        "was saved in: if the guest was reset or rebooted since that save, the "
        "debugger's symbols and breakpoints use another base and sit where "
        "nothing runs (qmu does not record which boot a tag came from). Rebase "
        "and re-arm: " + _rebase_recovery(inst.vm_id, ref, gloss)
        + " Prove one fires with a canary before trusting a stop."
    )
    if _tcg(inst):
        if _kaslr_off(inst):
            return lead + (
                ". Its breakpoints are unaffected: under TCG they live in QEMU, "
                "not in guest RAM, and this kernel booted with nokaslr, so a load "
                "moves no address and they still fire with no re-arm. Trust the "
                "frame, not the reason, until the next stop."
            )
        return lead + (
            ". Under TCG its breakpoints live in QEMU, not in guest RAM, so the "
            "load leaves them in force at the addresses they were set at." + moved
        )
    lead += (
        ", and the breakpoints it had inserted while the guest ran are no "
        "longer in guest RAM — still listed [enabled], they never fire."
    )
    baked = (
        " An image whose save said `breakpoints_in_image: possible` can bring "
        "int3 bytes back, also at a site whose breakpoint was deleted before the "
        f"load: `pry --instance {ref} resync` (pry #83) writes the symbol file's "
        "bytes back over every trap no breakpoint owns in the code it can map "
        "and lists each one under `stray_traps`; only a trap in code no loaded "
        "symbol file maps needs a `lifted` image or a reboot instead."
    )
    if _kaslr_off(inst):
        return lead + (
            " This kernel booted with nokaslr, so addresses did not move: re-arm "
            f"in place with `pry --instance {ref} interrupt` (`not interrupted` "
            f"at a stop is fine), then `pry --instance {ref} continue "
            "--background` (GDB re-inserts every breakpoint when it resumes)"
            f"{gloss}; prove one fires with a canary before trusting a stop."
        ) + baked
    return lead + moved + baked


def loadvm_failed_restore_warning(inst: Any) -> str:
    """#44 x #87 — a load that failed mid-restore under an attached debugger.

    The machine is inconsistent and left paused on purpose. Every way of
    re-arming, re-syncing or dropping the debugger can resume it — `pry
    continue`, a resync of a target pry believes running, a detach that lets
    QEMU continue — so qmu drives no bridge here, its own included.
    """
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and its snapshot load "
        "failed after the restore began, so an attached debugger's view is "
        "stale. Do NOT re-sync, continue or detach (`pry kill`) it now: each "
        "can resume the half-restored machine. Load a known-good snapshot "
        "first (qmu then re-syncs the bridge `qmu gdb` spawned and warns about "
        f"any other client), or `qmu kill --vm {inst.vm_id}`, which reaps qmu's "
        "bridge."
    )


def savevm_breakpoint_warning(
    inst: Any, qemu_status: str | None, after: str | None = None
) -> str:
    """#45/#188 — a save taken outside a debugger stop can hold int3 bytes.

    `qemu_status`/`after` are QEMU's run state right before and right after
    the save. `paused` held across the whole save is a stop qmu could not
    attribute (#229): a debugger that took it had lifted its breakpoints, but
    qmu can ask only the bridge it spawned. Repeating the save-at-a-stop
    recovery there sent the reader round in a loop, since that save is this
    one; it says what the stop means instead, and what repairs a baked trap.
    """
    ref, gloss = _bridge_ref(inst)
    state = qemu_status or "unknown"
    trap = (
        "after `qmu snapshot load`, reaching one raises a trap with no live "
        "breakpoint behind it — an Oops/panic at the breakpointed function that "
        "looks exactly like your PoC crashing the kernel."
    )
    if qemu_status == "paused" and after == "paused":
        who = (
            "the bridge `qmu gdb` spawned did not report a stop when asked (`pry "
            "status`)"
            if not gloss
            else "qmu can ask only the bridge `qmu gdb` spawned, not the client "
            "attached now"
        )
        return (
            f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and was saved while "
            f"QEMU reported 'paused' before and after the save, a stop qmu could "
            f"not attribute to a debugger ({who}), so it says `possible`. If your "
            "debugger took this stop (its interrupt, or a QMP `stop`, which GDB "
            "sees as SIGINT), GDB had lifted its breakpoints and the image holds "
            "none of them. If it did not, or a debugger that detached uncleanly "
            "left int3 (0xCC) bytes in guest RAM, the image may carry some: "
            + trap
            + f" After a load, `pry --instance {ref} resync`{gloss} writes the "
            "symbol file's bytes back over any trap no breakpoint owns in the code "
            "it can map, and lists each one under `stray_traps`."
        )
    foreign = (
        " (qmu cannot confirm a stop of a client it did not spawn, so that save "
        "says `possible` too, with a warning saying what a stop you took means)"
        if gloss else ""
    )
    return (
        f"[qmu] WARNING: VM '{inst.vm_id}' has a GDB stub and was saved while "
        f"QEMU reported '{state}', not a debugger stop qmu could confirm. A "
        "software breakpoint is an int3 (0xCC) byte in guest RAM whenever the "
        "debugger has the target running, so this image may carry some: "
        + trap
        + " For a clean image, save at a stop: "
        f"`pry --instance {ref} interrupt`, `qmu snapshot save --vm {inst.vm_id} "
        f"<tag>`, then `pry --instance {ref} continue --background`{gloss}"
        f"{foreign}."
    )


def savevm_lifted_note(inst: Any, qemu_status: str | None) -> str:
    """#188 — a save taken at a debugger stop: GDB had lifted its breakpoints."""
    return (
        f"[qmu] Note: VM '{inst.vm_id}' was saved at a debugger stop "
        f"('{qemu_status}'), where GDB has lifted its breakpoints, so this image "
        "holds no int3 for a breakpoint the debugger lists. The exception is an "
        "int3 nothing tracks: one a `possible` image brought back on load that "
        "no `pry resync` has repaired since (pry #83 repairs one in the code it "
        "can map, listed under `stray_traps`) is still in RAM, so in this image."
    )


def reset_dropped_breakpoints_warning(
    inst: Any, *, guest_initiated: bool = False, qemu_status: str | None = None
) -> str:
    """#46/#184/#231 — a reset leaves the debugger's software breakpoints dead, silently.

    Under KVM a software breakpoint is an int3 in guest RAM, and the new boot
    loads the kernel over it while GDB still lists it inserted; hardware
    breakpoints and watchpoints live in the vCPU's debug registers, not in
    RAM, and keep firing at their addresses (measured: a hardware breakpoint
    hit after a `sysrq b` reboot with no re-arm, and a watchpoint trapped on
    the boot's own `sethostname` after a nokaslr reset). Under TCG QEMU keeps
    them all, at their old virtual addresses. Either way KASLR re-slides the
    kernel on every boot, so the symbol file pry loaded against the old base
    resolves to addresses nothing executes (debug audit R25–R26). The
    recovery re-derives the base once the new kernel is up — `pry kbase` with
    no SSH (pry #66) or `qmu kbase` over it — and re-arms with `pry resync`,
    which stops a running target itself (pry #61). Under KVM a nokaslr kernel
    keeps its addresses, but a breakpoint re-inserted before the new boot is
    done is overwritten by it, so that re-arm waits for the boot too (#204).

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
    if not tcg and halted:
        lead += (
            "The debugger had lifted its breakpoints at its stop and re-inserts "
            "them only when it resumes: still listed [enabled], none is in force "
            "(hits stay 0). "
        )
    elif not tcg:
        lead += (
            "The new boot loads the kernel over the int3 bytes of the debugger's "
            "software breakpoints without notifying the client: still listed "
            "[enabled], they do not fire (hits stay 0). Hardware breakpoints and "
            "watchpoints are not in guest RAM and stay armed at their addresses"
            + (
                ": with nokaslr they keep firing. "
                if kaslr_off
                else ", which the re-slid kernel no longer runs as those functions. "
            )
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
    booted = (
        f"Once the new kernel has booted (`qmu wait --vm {vm_id} --pattern "
        "'login:'`, or the end of kernel init on the console): "
    )
    if kaslr_off:
        if tcg and not halted:
            return lead + "Nothing to re-arm; prove one fires with a canary."
        if tcg:
            return lead + (
                f"Addresses did not move: `pry --instance {ref} interrupt`, then "
                f"`pry --instance {ref} continue --background` re-inserts every "
                f"breakpoint{gloss}; prove one fires with a canary."
            )
        return lead + (
            "This kernel booted with nokaslr, so addresses did not move, but a "
            "breakpoint re-inserted before the new boot is done is overwritten "
            "by it (the kernel is loaded again and patches its own text) and "
            "stays dead. "
            + booted
            + f"`pry --instance {ref} resync` (re-inserts every breakpoint and "
            f"reports `summary.not_armed`){gloss}."
            + (
                " The debugger still believes the guest stopped, so it halts it "
                f"again: resume with `pry --instance {ref} continue --background`."
                if halted else ""
            )
            + " Prove one fires with a canary."
        )
    return lead + (
        ("" if tcg else
         "KASLR also re-slid the kernel, so symbols loaded against the old base "
         "resolve to addresses nothing runs. ")
        + booted
        + _rebase_recovery(vm_id, ref, gloss)
        + (
            f" The debugger still believes the guest stopped, so these halt it "
            f"again: resume with `pry --instance {ref} continue --background`."
            if halted else ""
        )
        + " Prove one fires with a canary."
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
