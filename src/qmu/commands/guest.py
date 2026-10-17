"""Guest-facing commands: exec, compile, dmesg, crash, log, push, pull.

Everything here talks to the guest over SSH (exec/compile/dmesg/push/pull) or
reads the serial log (crash/log). Shared helpers come from :mod:`.._cliutil`.

The patchable collaborators (``choose_instance``, ``_make_ssh``,
``_preflight_ssh_guest``, ``_require_ssh``, ``extract_crash``, and
``serial_log_offset``) are imported
directly into this module's namespace, and
``_add_exec`` binds the module-global ``_handle_exec``. The test suite drives the
production seams with ``monkeypatch.setattr(guest, ...)`` (e.g.
``guest.choose_instance`` / ``guest._make_ssh`` / ``guest._handle_exec``); the
patches take effect because the handlers read these names from this module at
call time.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..hostcc import host_compile, resolve_host_cc
from ..instance import (
    QMUError,
    VMInstance,
    choose_instance,
    find_instance,
)
from ..serial import (
    current_boot_offset,
    extract_crash,
    has_terminal_panic,
    read_log,
    serial_log_offset,
    tail_log,
)
from ..ssh import SSHClient, SSHError, guest_bytes, guest_lossy, is_transport_failure
from .._cliutil import (
    _add_common_opts,
    _emit,
    _emit_bytes,
    _make_ssh,
    _preflight_ssh_guest,
    _qmp_stopped_status,
    _require_ssh,
    _stopped_guest_payload,
)


def _require_running_vm(vm_id: str | None, command: str) -> None:
    """Reject a non-running VM with a description, never with "not found".

    Imported lazily: lifecycle sits beside this module in the command layer, so
    a module-level import would make the two mutually dependent. The shared
    describer is what keeps `exec` from contradicting `list` about whether a VM
    exists — the invariant that six rounds of dogfooding kept catching.
    """
    if not vm_id:
        return
    from .lifecycle import describe_non_running

    explanation = describe_non_running(vm_id, command=command)
    if explanation is not None:
        raise QMUError(explanation)


# ---------------------------------------------------------------------------
# push / pull
# ---------------------------------------------------------------------------


def _emit_transfer_transport_lost(
    args: argparse.Namespace,
    *,
    operation: str,
    local: str,
    remote: str,
    inst: VMInstance,
    start_offset: int,
    stem: str | None = None,
) -> int:
    """Emit the scp-transport-lost envelope; exit 3 only with a fresh crash.

    The same split :func:`_ssh_lost_payload` applies to `exec`: an scp failure
    (rc=255 + transport marker) is a weak guest-death signal on its own — it
    can be a host-side ssh control-master hiccup (issue #10's own repro is a
    mux "read from master failed: Broken pipe") — so a guest crash is never
    claimed on the transfer's word alone. A fresh command-scoped serial crash
    corroborates it → exit 3 (CLAUDE.md "transport-loss"); otherwise it stays
    exit 4 (infra). The fresh-crash presence is the discriminator between the
    contract's transport-loss (3) and SSH-failure (4) buckets.
    """
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    if crash is not None:
        hint = (
            "SCP transport lost. Kernel may have crashed. "
            "See crash field or run: qmu crash"
        )
        detail = f"Crash from serial log:\n{crash}"
        status = 3
    else:
        hint = (
            "SCP transport lost; VM may be unreachable. "
            "No fresh crash report in serial log. Check: qmu log --tail 100"
        )
        detail = "No fresh crash detected. Check: qmu log --tail 100"
        status = 4
    direction = (
        f"{local} -> guest:{remote}"
        if operation == "push"
        else f"guest:{remote} -> {local}"
    )
    result = {
        "ok": False,
        "vm_id": inst.vm_id,
        "ssh_error": True,
        "crash_detected": crash is not None,
        "operation": operation,
        "local": local,
        "remote": remote,
        "crash": crash,
        "hint": hint,
    }
    _emit(
        args,
        data=result,
        text=[f"SCP transport lost during {operation}: {direction}", detail],
        stem=stem or operation,
    )
    return status


def _emit_transfer_halted(
    args: argparse.Namespace,
    inst: VMInstance,
    start_offset: int,
    *,
    operation: str,
    stem: str,
) -> int | None:
    """Emit the paused envelope when a lost transfer is explained by a halted
    vCPU (the watcher aborted it, or ssh gave up on a stopped guest). Returns
    the exit status (1), or None when the vCPU runs and the transport
    classification applies.
    """
    qemu_status = _halted_not_panicked(inst, start_offset=start_offset)
    if qemu_status is None:
        return None
    data, text = _stopped_guest_payload(inst, qemu_status)
    data["operation"] = operation
    _emit(
        args,
        data=data,
        text=[f"SSH connection lost during {operation}.", *text],
        stem=stem,
    )
    return 1


class _DeliveryTransportLost(SSHError):
    """A confirmed transport loss while delivering a host-built binary.

    A distinct type, not a bare SSHError: the delivery handler must not treat
    *every* untyped SSH failure as a dropped guest. `push`/`pull` re-raise an
    SSHError with no returncode and no fresh panic (an scp subprocess timeout
    on a live guest) rather than calling it transport loss, and the host path
    has to make the same distinction or it reclassifies ordinary infra
    failures as crashes.
    """


def _classify_transfer_failure(
    args: argparse.Namespace,
    exc: SSHError,
    *,
    inst: VMInstance,
    start_offset: int,
    operation: str,
    local: str,
    remote: str,
    stem: str,
) -> int:
    """Emit the envelope for a transfer `exc` ended and return the exit status;
    re-raises `exc` when nothing qmu holds explains it (plain infra, exit 4).

    One decision for push, pull and host-build delivery, in the order
    :func:`_explain_lost_transport` uses for `exec`:

    - a halted vCPU (QMP) is the paused envelope (1);
    - a terminal panic appended since the transfer started is the outcome of
      the transfer: exit 3 with the report. This covers the exception the
      watcher raises (:class:`~qmu.ssh.SSHAborted`, no returncode): a sysrq
      panic during a 2 GiB push aborted scp within a second, and the handler
      then re-raised it as a bare `SSHAborted` (4, no report) while the
      concurrent `exec` and the next `qmu crash` both returned the panic. An
      scp timeout that coincides with the panic is the same guest outcome
      (the drain loop checks the deadline before the watcher, so which of the
      two fires is a race);
    - otherwise only a confirmed transport loss (rc 255 plus a transport
      marker, or the probed :class:`_DeliveryTransportLost`) reaches the
      crash-vs-unreachable split; an ordinary scp timeout or protocol failure
      with no panic stays infra.
    """
    halted = _emit_transfer_halted(
        args, inst, start_offset, operation=operation, stem=stem
    )
    if halted is not None:
        return halted
    if isinstance(exc, _DeliveryTransportLost):
        pass
    elif exc.returncode is None:
        if not has_terminal_panic(inst.serial_log, start_offset=start_offset):
            raise exc
    elif not is_transport_failure(exc.returncode, exc.stderr):
        raise exc
    return _emit_transfer_transport_lost(
        args,
        operation=operation,
        local=local,
        remote=remote,
        inst=inst,
        start_offset=start_offset,
        stem=stem,
    )


def _add_push(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "push",
        help="Copy a file to the guest",
        description=(
            "Copy ONE regular file into the guest over scp. Directories are "
            "not transferred (archive them first, e.g. tar); a missing local "
            "file, a directory, or an scp refusal (missing remote directory, "
            "permission denied) is exit 1, not the transport class (4)."
        ),
    )
    p.add_argument("local", help="Local file path (a single regular file; archive directories first)")
    p.add_argument("remote", nargs="?", default="/root/",
                   help="Remote path (default: /root/); a trailing / means 'into that directory', "
                        "otherwise it is the destination file name")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_push)


def _handle_push(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="push")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    start_offset = serial_log_offset(inst.serial_log)
    try:
        ssh.push(
            args.local,
            args.remote,
            abort_when=_guest_abort_watcher(inst, start_offset=start_offset),
        )
    except SSHError as exc:
        return _classify_transfer_failure(
            args, exc, inst=inst, start_offset=start_offset, operation="push",
            local=args.local, remote=args.remote, stem="push",
        )
    _emit(
        args,
        data={"ok": True, "vm_id": inst.vm_id, "local": args.local, "remote": args.remote},
        text=f"Pushed {args.local} -> guest:{args.remote}",
        stem="push",
    )
    return 0


def _add_pull(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("pull", help="Copy file from guest")
    p.add_argument("remote", help="Remote file path")
    p.add_argument("local", nargs="?", default=".", help="Local path (default: .)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_pull)


def _handle_pull(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="pull")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    start_offset = serial_log_offset(inst.serial_log)
    try:
        ssh.pull(
            args.remote,
            args.local,
            abort_when=_guest_abort_watcher(inst, start_offset=start_offset),
        )
    except SSHError as exc:
        return _classify_transfer_failure(
            args, exc, inst=inst, start_offset=start_offset, operation="pull",
            local=args.local, remote=args.remote, stem="pull",
        )
    _emit(
        args,
        data={"ok": True, "vm_id": inst.vm_id, "local": args.local, "remote": args.remote},
        text=f"Pulled guest:{args.remote} -> {args.local}",
        stem="pull",
    )
    return 0


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


GUEST_COMMAND_HELP = (
    "Command to run in the guest. ONE argument is handed to the guest shell "
    "verbatim (quote it to use pipes/redirects: 'cat /proc/slabinfo | grep "
    "kmalloc'); SEVERAL arguments are shell-quoted and joined, so `echo hi` "
    "runs `echo hi`. qmu flags may appear anywhere (`qmu exec \"./exploit\" "
    "--timeout 120`). Unquoted dash-words belong to qmu unless they follow "
    "a bare -- (`qmu exec -- uname -a`)."
)


def _add_exec(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "exec",
        help="Run command in guest",
        description=(
            "Run a command in the guest over SSH. qmu flags may appear before "
            "or after COMMAND (`qmu exec \"./exploit\" --timeout 120`); quote "
            "the guest command, or put -- before it, when it has its own "
            "dash-words (`qmu exec -- uname -a`). Text mode prints the guest's "
            "stdout on stdout, byte for byte, and the guest's stderr on stderr "
            "followed by `[exit code: N]` when N is non-zero, so "
            "`qmu exec ... > out.txt` and `qmu exec ... | grep` see guest "
            "stdout only. A kernel panic while the command runs is reported "
            "(exit 3) as soon as the serial log shows it, without waiting for "
            "the SSH keepalive to notice."
        ),
    )
    p.add_argument("command", nargs="+", help=GUEST_COMMAND_HELP)
    p.add_argument("--timeout", type=float, default=30.0,
                   help="Guest command timeout in seconds (default: 30); on expiry the "
                        "output produced so far is still reported (exit 124)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_exec)


def _transport_lost(ssh: SSHClient) -> bool:
    """True only if SSH is unreachable after probing twice (CORR-5).

    rc==255 from `ssh.run` is ambiguous: it is both a legal guest exit code and
    the code ssh returns when the transport drops (e.g. a kernel panic). Before
    declaring a crash we confirm with a liveness probe — and retry once, since a
    single slow probe against a busy live guest can spuriously fail and produce a
    false-positive "kernel crashed". Only when BOTH probes fail do we treat the
    transport as lost.
    """
    if ssh.is_ready(timeout=3):
        return False
    # Retry once after a short backoff: a busy guest may have missed the first
    # short probe, and an immediate re-probe would just fail the same way.
    time.sleep(0.5)
    if ssh.is_ready(timeout=3):
        return False
    return True


def _ssh_lost_hint(crash: str | None) -> str:
    """The SSH-lost hint text, in one place.

    `exec`/`dmesg`/`compile --run` (via :func:`_ssh_lost_payload`) and the
    transfers report the same condition, so the follow-up command a caller is
    told to run must not differ between them: `compile --run` used to name no
    follow-up at all, so an agent whose exploit panicked the guest was never
    pointed at `qmu crash`.
    """
    if crash is not None:
        return (
            "SSH connection lost. Kernel may have crashed. "
            "See crash field or run: qmu crash"
        )
    return (
        "SSH connection lost; VM may be unreachable. "
        "No fresh crash report in serial log. Check: qmu log --tail 100"
    )


def _ssh_lost_payload(
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
) -> tuple[int, dict[str, Any], list[str]]:
    """Build the SSH-lost (status, data, text) triple; status 3 only on a crash.

    Used for both an SSH timeout (TimeoutExpired -> SSHError) and a transport
    disconnect (rc=255 + ssh transport marker). A dropped connection alone does
    NOT prove a panic: a guest with no sshd produces one on every exec, and
    returning 3 there reports a missing daemon in the kernel-crash class —
    against the contract that a tooling fault is never mistaken for a panic.
    Status 3 requires a corroborating fresh serial crash; otherwise the guest is
    merely unreachable and this is transport-layer (4). This matches the
    discrimination `_emit_transfer_transport_lost` already applied to scp, so
    the two siblings no longer disagree about the same condition.

    A (status, data, text) triple rather than an emitter so ``qmu exec``,
    ``qmu run``, ``dmesg`` and ``compile --run`` reach the identical
    classification without re-deriving it: a second copy of this decision is
    exactly how ``exec`` and ``push``/``pull`` came to disagree about what a
    dropped connection means.
    """
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    # CORR-5: only assert a kernel crash when a crash report was actually
    # extracted; otherwise the connection merely dropped (VM unreachable) and we
    # must not send the agent chasing a phantom panic.
    hint = _ssh_lost_hint(crash)
    if crash is not None:
        text_msg = f"\nCrash from serial log:\n{crash}"
    else:
        text_msg = "\nNo fresh crash detected in serial log. Check: qmu log --tail 100"
    # `exit_code`/`vm_id` are present on every exec envelope: the guest's exit
    # code is unknown here (ssh's own 255 is not the guest's), so it is null
    # rather than absent — a caller reads one key set on every path.
    result: dict[str, Any] = {
        "ok": False,
        "vm_id": inst.vm_id,
        "exit_code": None,
        "ssh_error": True,
        "crash_detected": crash is not None,
        "command": command,
        "crash": crash,
        "hint": hint,
    }
    # 3 only with a corroborating fresh crash; a bare dropped connection
    # (no sshd, guest wedged) is transport-layer, i.e. 4.
    status = 3 if crash is not None else 4
    return status, result, [f"SSH connection lost while running: {command}", text_msg]


def _explain_lost_transport(
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
    halted_status: Callable[[], str | None] | None = None,
) -> tuple[int, dict[str, Any], list[str]] | None:
    """Explain a dropped/expired SSH session from evidence qmu already holds.

    Consulted BEFORE the liveness re-probe, which is slow (two 3 s probes) and
    can be fooled: a `panic=N` guest reboots inside the probe window and
    answers the probe, so the panic was reported as the guest "returning 255"
    with `crash_detected: false`. The serial log is authoritative — a terminal
    panic appended after the command started IS the outcome of the command,
    whatever the probe says afterwards (exit 3 with the report). Likewise a
    vCPU QMP says is halted (a breakpoint fired mid-command) explains the loss
    exactly; probing SSH against a stopped CPU only adds 7 s before a wrong
    "VM may be unreachable" in the transport class. Returns None when neither
    explains it, leaving the probe to decide.

    `halted_status` is how QMP is asked; a command that was watched passes
    its :class:`_GuestWatcher`'s bounded probe so a socket held by another
    client does not add the 2 s greeting budget to a `--timeout` that has
    already expired. The default is the synchronous query.
    """
    if has_terminal_panic(inst.serial_log, start_offset=start_offset):
        return _ssh_lost_payload(command, inst, start_offset=start_offset)
    qemu_status = (
        halted_status() if halted_status is not None else _qmp_stopped_status(inst)
    )
    if qemu_status is not None:
        data, text = _stopped_guest_payload(inst, qemu_status)
        data["exit_code"] = None
        data["command"] = command
        return 1, data, [f"SSH connection lost while running: {command}", *text]
    return None


# How long a watcher poll may wait for a QMP answer. Bounds the drain loop's
# stall: the deadline is enforced within this plus the loop's own poll
# interval, whatever state the QMP socket is in.
_QMP_PROBE_BUDGET = 0.2


class _GuestWatcher:
    """The `abort_when` predicate for a guest command: panic OR halted vCPU.

    Every poll reads the serial log for a terminal panic appended since
    `start_offset` (cheap, ~100 ms behind reality). About once per
    `qmp_interval` it also asks QMP `query-status`: a breakpoint that fires
    mid-command halts the vCPU without a byte of serial output, and ssh only
    notices after its keepalive window plus the liveness re-probes (measured
    20 s for `exec uname -r` against an armed `__x64_sys_newuname`). QMP is
    best-effort — a busy or missing socket is treated as "still running" so
    the watcher can never turn a working guest command into an outage — and
    the stop it detects is re-read by :func:`_explain_lost_transport`, which
    renders the same paused envelope the preflight uses.

    The QMP query runs on a daemon thread. The predicate is called from the
    single-threaded drain loop in :func:`~qmu.ssh._watch_child`, and a
    socket held by another client made a synchronous query sit out the 2 s
    greeting budget on every cadence — during which nothing drained and the
    deadline was not enforced, so `exec --timeout 2 'sleep 2.5; printf
    done'` returned 0 after 3.1 s with a sibling holding QMP. A poll now
    waits at most `_QMP_PROBE_BUDGET` for the answer and otherwise reads the
    last published one. One query is in flight at a time: a tick that finds
    the previous one still blocked does not queue another connection behind
    it, and a thread still waiting on a held socket when the command ends
    must not keep the process alive (hence daemon).
    """

    def __init__(
        self, inst: VMInstance, *, start_offset: int, qmp_interval: float = 1.0
    ) -> None:
        self._inst = inst
        self._start_offset = start_offset
        self._qmp_interval = qmp_interval
        self._next_qmp = time.monotonic() + qmp_interval
        self._thread: threading.Thread | None = None
        self._status: str | None = None

    def _query(self) -> None:
        self._status = _qmp_stopped_status(self._inst)

    def halted_status(self) -> str | None:
        """QEMU's status if it positively says the vCPUs are stopped, waiting
        at most `_QMP_PROBE_BUDGET` for a fresh answer; None otherwise. A
        query still blocked from the previous call is not waited on again —
        the socket is held, and the last published answer is all there is."""
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._query, name="qmu-qmp-probe", daemon=True
            )
            self._thread.start()
            self._thread.join(_QMP_PROBE_BUDGET)
        return self._status

    def __call__(self) -> bool:
        if has_terminal_panic(self._inst.serial_log, start_offset=self._start_offset):
            return True
        now = time.monotonic()
        if now < self._next_qmp:
            return False
        self._next_qmp = now + self._qmp_interval
        return self.halted_status() is not None


def _guest_abort_watcher(
    inst: VMInstance, *, start_offset: int, qmp_interval: float = 1.0
) -> _GuestWatcher:
    """See :class:`_GuestWatcher`."""
    return _GuestWatcher(inst, start_offset=start_offset, qmp_interval=qmp_interval)


def _halted_not_panicked(inst: VMInstance, *, start_offset: int) -> str | None:
    """QEMU's status when a lost command is explained by a halted vCPU.

    None when the serial log holds a terminal panic since `start_offset`
    (QEMU reports a panicked guest as running, and the panic is the better
    explanation when both show) or when QMP says the guest runs.
    """
    if has_terminal_panic(inst.serial_log, start_offset=start_offset):
        return None
    return _qmp_stopped_status(inst)


def _command_timeout_payload(
    command: str,
    inst: VMInstance,
    timeout: float,
) -> tuple[int, dict[str, Any], list[str]]:
    """The guest is alive and answering; the command just outlived --timeout.

    Exit 124 is the contract's wait-timeout code, and it is what this is: no
    crash, no transport loss, nothing to reap. Keeping the L1 booleans present
    and false is what lets a caller branch on `crash_detected` without first
    checking which envelope shape it received.
    """
    return (
        124,
        {
            "ok": False,
            "vm_id": inst.vm_id,
            "exit_code": None,
            "ssh_error": False,
            "crash_detected": False,
            "timed_out": True,
            "command": command,
            "timeout": timeout,
            "hint": f"Guest command exceeded --timeout ({timeout:g}s) but the "
                    "guest is still answering SSH. Raise --timeout, or check "
                    "what the command is waiting on.",
        },
        [
            f"Guest command timed out after {timeout:g}s (guest still reachable): "
            f"{command}",
            "No crash detected. Raise --timeout if the command needs longer.",
        ],
    )


def _join_exec_command(command: list[str]) -> str:
    """Build the guest command string from `qmu exec` positionals.

    A single argument is passed to the guest login shell verbatim, so the
    documented shell forms work: `qmu exec "uname -a"` and
    `qmu exec "cat /proc/slabinfo | grep kmalloc-192"` (pipes/redirects rely on
    the guest shell). Multiple args (`qmu exec echo hi`, `qmu exec -- ls -la`)
    keep the token-per-arg model via shlex.join: `qmu exec grep "two words" f`
    runs `grep 'two words' f`, not `grep two words f`.
    """
    return command[0] if len(command) == 1 else shlex.join(command)


def _stream_fields(stdout: str, stderr: str) -> dict[str, Any]:
    """The envelope's view of the guest's streams.

    JSON carries the lossy decode (a JSON string cannot hold a bare 0xff);
    `stdout_lossy`/`stderr_lossy: true` appear only when U+FFFD replaced
    something, so a consumer knows the string is not the output and can
    `pull` the artifact or read text mode instead.
    """
    fields: dict[str, Any] = {"stdout": stdout, "stderr": stderr}
    if guest_lossy(stdout):
        fields["stdout_lossy"] = True
    if guest_lossy(stderr):
        fields["stderr_lossy"] = True
    return fields


def _with_guest_output(
    outcome: tuple[int, dict[str, Any], list[str]],
    stdout: str,
    stderr: str,
) -> tuple[int, dict[str, Any], str, list[str], list[str | bytes]]:
    """Attach what the guest printed to a lost/expired/halted outcome.

    The stopped child's output is still the guest's output: a long-running
    exploit that prints progress and then panics (or outlives `--timeout`)
    has told the caller where it got to, and dropping that with the
    classification made every such run look silent. Guest stdout leads on
    stdout (it is stdout) with the classification's text after it; guest
    stderr goes to the stderr notes, verbatim.
    """
    status, data, text = outcome
    data.update(_stream_fields(stdout, stderr))
    return status, data, stdout, text, [guest_bytes(stderr)] if stderr else []


def _run_guest_command(
    ssh: SSHClient,
    command: str,
    inst: VMInstance,
    *,
    timeout: float,
) -> tuple[int, dict[str, Any], str, list[str], list[str | bytes]]:
    """Run `command` in the guest and classify the outcome.

    Returns (exit status, JSON data, guest stdout, trailing stdout text,
    stderr notes) rather than emitting, so ``qmu exec``, ``qmu run`` and
    ``compile --run`` render the same classification under their own
    ``stem`` instead of maintaining copies of the crash-vs-transport-loss
    discrimination. In text mode the guest stdout goes to stdout byte for
    byte, followed by the text lines when the command was lost (the crash
    report); the notes belong on stderr (guest stderr bytes verbatim, the
    `[exit code: N]` trailer, a survived kernel report) — see
    :func:`_emit_guest_result`.

    The ssh child is watched by :func:`_guest_abort_watcher`: a terminal
    panic appended after the command started, or a vCPU QMP reports halted,
    kills it immediately instead of waiting the keepalive window (15 s) plus
    the liveness re-probes for ssh to report the loss itself (measured 20–50 s
    for a sysrq crash the serial log showed within 100 ms).
    """
    command_start_offset = serial_log_offset(inst.serial_log)
    watcher = _guest_abort_watcher(inst, start_offset=command_start_offset)

    try:
        rc, stdout, stderr = ssh.run(command, timeout=timeout, abort_when=watcher)
    except SSHError as exc:
        # qmu stopped the child: the watcher saw a panic, or --timeout expired.
        # The latter is NOT by itself a crash: a guest that still answers SSH
        # merely ran longer than --timeout, and reporting exit 3 there told the
        # caller a healthy kernel had died (reproduced live with
        # `qmu run --timeout 1 -- 'sleep 10'`). The serial log and QMP are
        # consulted first (instant, and authoritative); only then probe, and
        # only an unreachable guest takes the crash/transport-loss path.
        explained = _explain_lost_transport(
            command, inst, start_offset=command_start_offset,
            halted_status=watcher.halted_status,
        )
        if explained is None:
            if not _transport_lost(ssh):
                explained = _command_timeout_payload(command, inst, timeout)
            else:
                explained = _ssh_lost_payload(
                    command, inst, start_offset=command_start_offset
                )
        return _with_guest_output(explained, exc.stdout, exc.stderr)

    # A kernel panic during the command drops the connection and ssh exits 255 —
    # often with EMPTY stderr (LogLevel=ERROR suppresses the keepalive message),
    # so a stderr-marker test is unreliable. rc=255 is also a legal guest exit
    # code, so disambiguate: the serial log / QMP first (a panic appended after
    # the command started, or a halted vCPU, settle it), then an authoritative
    # liveness probe (retried once to avoid a false positive on a busy live
    # guest): if SSH is still unreachable the guest vanished (crash); if it
    # answers, the guest genuinely returned 255 and we take the normal path.
    if rc == 255:
        explained = _explain_lost_transport(
            command, inst, start_offset=command_start_offset
        )
        if explained is None and _transport_lost(ssh):
            explained = _ssh_lost_payload(
                command, inst, start_offset=command_start_offset
            )
        if explained is not None:
            return _with_guest_output(explained, stdout, stderr)

    kernel_warning = extract_crash(
        inst.serial_log, start_offset=command_start_offset
    )
    notes: list[str | bytes] = []
    if stderr:
        notes.append(guest_bytes(stderr))
    if rc != 0:
        notes.append(f"[exit code: {rc}]")
    if kernel_warning is not None:
        notes.append(
            "Kernel warning from command serial output:\n"
            + kernel_warning.rstrip()
        )
    # L1: always include ssh_error/crash_detected so consumers have a stable,
    # explicit contract (not an implicit "key omitted on success").
    data: dict[str, Any] = {
        "ok": rc == 0,
        "vm_id": inst.vm_id,
        "exit_code": rc,
        **_stream_fields(stdout, stderr),
        "ssh_error": False,
        "crash_detected": False,
        "kernel_warning_detected": kernel_warning is not None,
        "kernel_warning": kernel_warning,
    }
    return (0 if rc == 0 else 1), data, stdout, [], notes


def _emit_guest_result(
    args: argparse.Namespace,
    *,
    data: dict[str, Any],
    stdout: str = "",
    text: list[str] = (),
    notes: list[str | bytes] = (),
    stem: str,
) -> None:
    """Emit a guest command result; text mode keeps stdout for guest stdout.

    Text mode writes the guest's `stdout` bytes to stdout exactly as the
    guest wrote them — no decode, no added newline — through
    :func:`_emit_bytes` (spill/--out apply). `text` (the crash report or
    timeout notice when the command was lost) follows on its own lines. An
    empty payload prints nothing rather than a blank line, so `qmu exec ...
    > out.txt` is byte-exact for a silent command too. `notes` go to stderr:
    `bytes` entries are guest stderr, verbatim; `str` entries (`[exit code:
    N]`, kernel warnings, follow-up hints) are qmu's lines and start on a
    fresh line. `exec` used to print all of it on stdout as `[stderr] ...` /
    `[exit code: N]` lines, so a pipeline or a redirect collected the
    decorations as if the guest had printed them; then it rendered the
    stdout as text, so `printf x` arrived as `x\\n` and a 0xff byte as
    U+FFFD. JSON modes: `data` is the envelope.
    """
    if getattr(args, "format", "text") != "text":
        _emit(args, data=data, text="", stem=stem)
        return
    raw = guest_bytes(stdout)
    if text:
        if raw and not raw.endswith(b"\n"):
            raw += b"\n"
        raw += "\n".join(text).encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
    if raw or getattr(args, "out", None):
        exit_code = data.get("exit_code")
        _emit_bytes(
            args,
            raw,
            stem=stem,
            source_ok=bool(data.get("ok", False)),
            exit_code=exit_code if isinstance(exit_code, int) else None,
        )
    if not notes:
        return
    sys.stdout.flush()
    sys.stderr.flush()
    err = sys.stderr.buffer
    at_line_start = True
    for note in notes:
        if isinstance(note, bytes):
            if note:
                err.write(note)
                at_line_start = note.endswith(b"\n")
            continue
        if not at_line_start:
            err.write(b"\n")
        err.write(note.encode("utf-8"))
        if not note.endswith("\n"):
            err.write(b"\n")
        at_line_start = True
    err.flush()


def _handle_exec(args: argparse.Namespace) -> int:
    _require_running_vm(args.vm, "exec")
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="exec")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    command = _join_exec_command(args.command)
    status, data, stdout, text, notes = _run_guest_command(
        ssh, command, inst, timeout=args.timeout
    )
    _emit_guest_result(
        args, data=data, stdout=stdout, text=text, notes=notes, stem="exec"
    )
    return status


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------


def _add_compile(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("compile", help="Compile C file in guest (or on the host with --host)")
    p.add_argument("source", help="Local C source file")
    p.add_argument("--run", action="store_true", help="Run after compiling")
    p.add_argument("--cflags", default="-static -lpthread", help="Compiler flags")
    p.add_argument("--timeout", type=float, default=60.0, help="Execution timeout")
    p.add_argument(
        "--host",
        action="store_true",
        dest="host_build",
        help="Compile on the HOST with a toolchain for the guest arch, then push "
             "the binary (guest needs no gcc; much faster for emulated guests)",
    )
    p.add_argument(
        "--cc",
        default=None,
        help="Compiler command to use (default: gcc in the guest; with --host, "
             "overrides the arch-based host toolchain selection, e.g. "
             "'clang --target=aarch64-linux-gnu')",
    )
    _add_common_opts(p)
    p.set_defaults(handler=_handle_compile)


def _compile_on_host(
    args: argparse.Namespace,
    inst: VMInstance,
    ssh: SSHClient,
    source: Path,
    remote_bin: str,
) -> tuple[int, dict[str, Any]]:
    """Build `source` on the host for the guest arch and push it to `remote_bin`.

    Returns (compile rc, partial result dict) using the SAME key names as the
    in-guest path, so a JSON consumer does not have to branch on where the build
    happened; ``compiled_on`` records which path ran.
    """
    cc = resolve_host_cc(inst.arch, args.cc)
    # Delivery is watched like every other guest session (panic or halted vCPU).
    watcher = _guest_abort_watcher(inst, start_offset=serial_log_offset(inst.serial_log))
    with tempfile.TemporaryDirectory(prefix="qmu-compile-") as tmpdir:
        local_bin = Path(tmpdir) / source.stem
        rc, stdout, stderr, argv = host_compile(
            source, local_bin, args.cflags, cc
        )
        result: dict[str, Any] = {
            "source": str(source),
            # shlex.join, not " ".join: a quoted flag that shlex.split correctly
            # kept as ONE argv entry would otherwise be rendered back as two,
            # so the reported command was not a runnable representation of what
            # actually executed.
            "compile_cmd": shlex.join(argv),
            "compile_exit": rc,
            "compile_stdout": stdout,
            "compile_stderr": stderr,
            "compiled_on": "host",
            "compiler": shlex.join(cc),
            "guest_arch": inst.arch,
            "ssh_error": False,
            "crash_detected": False,
        }
        if rc != 0:
            return rc, result

        ssh.push(str(local_bin), remote_bin, abort_when=watcher)

    # scp does not preserve the mode (no -p in SSHClient._scp_base), so the
    # pushed binary lands non-executable and --run would fail with a bare
    # "Permission denied" that reads like a guest problem. chmod is part of
    # delivering a *runnable* artifact, so its failure is a compile failure.
    chmod_rc, _, chmod_err = ssh.run(
        f"chmod +x {shlex.quote(remote_bin)}", timeout=15, abort_when=watcher
    )
    # ...unless the guest vanished under it. rc=255 is both a legal exit code and
    # what ssh returns when a panic drops the transport, so confirm with the same
    # liveness probe exec uses and hand the caller the transport-loss path:
    # reporting a kernel panic as "compilation failed" would bury it.
    if chmod_rc == 255 and _transport_lost(ssh):
        raise _DeliveryTransportLost(
            "SSH transport lost (rc=255) while delivering the host-built "
            "binary — guest likely crashed"
        )
    if chmod_rc != 0:
        result["compile_exit"] = chmod_rc
        result["compile_stderr"] = (
            f"pushed {remote_bin} but could not make it executable: {chmod_err.strip()}"
        )
        return chmod_rc, result
    return 0, result


def _handle_compile(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="compile")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    source = Path(args.source)

    if not source.exists():
        raise QMUError(f"Source file not found: {source}")

    name = source.stem
    remote_src = f"/root/{source.name}"
    remote_bin = f"/root/{name}"

    if args.host_build:
        delivery_offset = serial_log_offset(inst.serial_log)
        try:
            rc, result = _compile_on_host(args, inst, ssh, source, remote_bin)
        except SSHError as exc:
            # Delivering the host-built binary lost the transport (or the
            # watcher stopped it): classified exactly as push/pull. The
            # transferred file is the host-built binary, not the source, and
            # the loss may have happened in the chmod that follows it.
            return _classify_transfer_failure(
                args, exc, inst=inst, start_offset=delivery_offset, operation="push",
                local=f"{source.name} (host-built binary)", remote=remote_bin,
                stem="compile",
            )
    else:
        # Push source, watched like every transfer: a halted vCPU under scp
        # is the paused envelope, a panic appended under it the crash class.
        push_offset = serial_log_offset(inst.serial_log)
        try:
            ssh.push(
                str(source),
                remote_src,
                abort_when=_guest_abort_watcher(inst, start_offset=push_offset),
            )
        except SSHError as exc:
            return _classify_transfer_failure(
                args, exc, inst=inst, start_offset=push_offset, operation="push",
                local=str(source), remote=remote_src, stem="compile",
            )

        # Compile. The remote paths are quoted (a source name with a space or shell
        # metacharacter must not detonate the root shell); --cflags and --cc are
        # intentionally left unquoted — they are shell command words.
        compile_cmd = (
            f"{args.cc or 'gcc'} {args.cflags} -o {shlex.quote(remote_bin)} "
            f"{shlex.quote(remote_src)}"
        )
        # Watched like the run: a breakpoint armed on a syscall the login shell
        # makes (`uname`) halts the vCPU under gcc, and an unwatched 30 s
        # budget then expired into a bare infra error.
        compile_start_offset = serial_log_offset(inst.serial_log)
        watcher = _guest_abort_watcher(inst, start_offset=compile_start_offset)
        try:
            rc, stdout, stderr = ssh.run(
                compile_cmd, timeout=30, abort_when=watcher
            )
        except SSHError as exc:
            # A halted vCPU (breakpoint under gcc) is the paused envelope, a
            # terminal panic appended under it the crash class with the
            # report; a gcc that merely outran its budget stays infra.
            explained = _explain_lost_transport(
                compile_cmd, inst, start_offset=compile_start_offset,
                halted_status=watcher.halted_status,
            )
            if explained is None:
                raise
            status, data, stdout, text, notes = _with_guest_output(
                explained, exc.stdout, exc.stderr
            )
            _emit_guest_result(
                args, data=data, stdout=stdout, text=text, notes=notes, stem="compile"
            )
            return status

        result = {
            "source": str(source),
            "compile_cmd": compile_cmd,
            "compile_exit": rc,
            "compile_stdout": stdout,
            "compile_stderr": stderr,
            "compiled_on": "guest",
            # L1: always-present booleans for a stable JSON contract. Updated below
            # if the run path detects a crash/transport loss.
            "ssh_error": False,
            "crash_detected": False,
        }

    # Every guest-command envelope names its VM, on every path.
    result["vm_id"] = inst.vm_id

    if rc != 0:
        result["ok"] = False
        where = "on the host" if args.host_build else "in the guest"
        _emit(
            args,
            data=result,
            text=f"Compilation failed {where}:\n{str(result['compile_stderr']).strip()}",
            stem="compile",
        )
        return 1

    result["compiled"] = True

    if not args.run:
        result["ok"] = True
        built_by = (
            f" (host {result['compiler']})" if args.host_build else ""
        )
        # Text mode: the banner is a note (stderr), never stdout — stdout is
        # reserved for program output on every compile path, so a redirect
        # of `compile` with or without --run collects the same thing.
        _emit_guest_result(
            args,
            data=result,
            notes=[f"Compiled {source.name} -> {remote_bin}{built_by}"],
            stem="compile",
        )
        return 0

    # Run (quoted: the binary path is interpolated into a root shell command).
    if getattr(args, "format", "text") == "text":
        # The banner precedes the program's output on a terminal, and lives on
        # stderr so `compile --run ... > out.txt` holds only what the program
        # printed. It used to be a trailing stderr note, so it landed AFTER
        # the output and read as a footer of the wrong stream.
        sys.stderr.write(f"Compiled and ran {source.name}:\n")
        sys.stderr.flush()

    # The run is `exec`'s classification under the compile envelope: watched
    # for a panic / halted vCPU, rc 255 disambiguated by serial log, QMP and
    # the liveness probe, and a `--timeout` overrun on a guest that still
    # answers reported as 124 with the partial output. `compile --run` kept
    # its own copy of the lost-transport branch, which treated every SSHError
    # as transport loss: a program that printed and then slept past
    # `--timeout 1` came back as 4 `ssh_error` ("VM unreachable") against a
    # serving guest, while the same program under `exec` was 124.
    status, data, stdout, text, notes = _run_guest_command(
        ssh, shlex.quote(remote_bin), inst, timeout=args.timeout
    )
    data = {**result, **_as_run_fields(data)}
    _emit_guest_result(
        args, data=data, stdout=stdout, text=text, notes=notes, stem="compile"
    )
    return status


def _as_run_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Rename exec's stream/exit keys to the compile envelope's `run_*` ones.

    `command` is dropped: the envelope already names what ran
    (`compile_cmd`, and the binary is `/root/<stem>`).
    """
    renamed = dict(data)
    renamed.pop("command", None)
    renamed["run_exit"] = renamed.pop("exit_code")
    for key in ("stdout", "stderr", "stdout_lossy", "stderr_lossy"):
        if key in renamed:
            renamed[f"run_{key}"] = renamed.pop(key)
    return renamed


# ---------------------------------------------------------------------------
# dmesg
# ---------------------------------------------------------------------------


def _add_dmesg(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("dmesg", help="Get kernel log from guest")
    p.add_argument("--tail", type=int, default=None, help="Last N lines")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_dmesg)


def _handle_dmesg(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="dmesg")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    cmd = "dmesg"
    if args.tail is not None:
        # `is not None` so --tail 0 is honored rather than silently dropped.
        # Clamp negatives to 0: like `tail -n 0`, both emit nothing (a negative
        # count would otherwise be misparsed as a tail option).
        cmd = f"dmesg | tail -n {max(args.tail, 0)}"
    command_start_offset = serial_log_offset(inst.serial_log)
    watcher = _guest_abort_watcher(inst, start_offset=command_start_offset)

    try:
        rc, stdout, stderr = ssh.run(cmd, timeout=15, abort_when=watcher)
    except SSHError as exc:
        # qmu stopped the child: the serial watcher saw a panic, or the 15 s
        # budget expired. The serial log / QMP explain it first (a panic
        # appended during the read, a halted vCPU); otherwise a guest that
        # still answers merely ran dmesg slowly, which stays an infra error
        # (the re-raise -> 4), and an unreachable one takes the shared
        # crash-vs-transport-loss path.
        explained = _explain_lost_transport(
            cmd, inst, start_offset=command_start_offset,
            halted_status=watcher.halted_status,
        )
        if explained is None:
            if not _transport_lost(ssh):
                raise
            explained = _ssh_lost_payload(
                cmd, inst, start_offset=command_start_offset
            )
        status, data, out, text, notes = _with_guest_output(
            explained, exc.stdout, exc.stderr
        )
        _emit_guest_result(
            args, data=data, stdout=out, text=text, notes=notes, stem="dmesg"
        )
        return status

    # A panic during the read drops the connection and ssh exits 255, often
    # with only a banner-exchange timeout on stderr. rc=255 is also a legal
    # guest exit code, so disambiguate exactly as exec does: serial log / QMP
    # first, then the probed liveness check. Without this, `qmu dmesg` on a
    # dead guest returned exit 1 — the "guest command non-zero" class —
    # reading as "dmesg failed inside the guest" while the kernel was gone.
    if rc == 255:
        explained = _explain_lost_transport(
            cmd, inst, start_offset=command_start_offset
        )
        if explained is None and _transport_lost(ssh):
            explained = _ssh_lost_payload(
                cmd, inst, start_offset=command_start_offset
            )
        if explained is not None:
            status, data, out, text, notes = _with_guest_output(
                explained, stdout, stderr
            )
            _emit_guest_result(
                args, data=data, stdout=out, text=text, notes=notes, stem="dmesg"
            )
            return status

    # L3: honor the guest exit code; do not silently render stderr as if it were
    # the kernel log. The kernel log is stdout (byte for byte, so `qmu dmesg |
    # grep` sees only log lines); stderr and a failure trailer are stderr notes.
    notes: list[str | bytes] = []
    if rc == 0:
        if not stdout.strip():
            notes.append("(empty dmesg)")
    else:
        err = stderr.rstrip()
        notes.append(f"[dmesg failed, exit {rc}]" + (f" {err}" if err else ""))
    data: dict[str, Any] = {
        "ok": rc == 0,
        "vm_id": inst.vm_id,
        "exit_code": rc,
        "text": stdout,
        "stderr": stderr,
    }
    if guest_lossy(stdout):
        data["text_lossy"] = True
    if guest_lossy(stderr):
        data["stderr_lossy"] = True
    _emit_guest_result(args, data=data, stdout=stdout, notes=notes, stem="dmesg")
    return 0 if rc == 0 else 1


# ---------------------------------------------------------------------------
# crash
# ---------------------------------------------------------------------------


def _add_crash(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("crash", help="Extract crash from serial log")
    p.add_argument(
        "--full-history",
        action="store_true",
        help=(
            "Search the entire retained serial log, including previous guest epochs"
        ),
    )
    _add_common_opts(p)
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.set_defaults(handler=_handle_crash)


def _handle_crash(args: argparse.Namespace) -> int:
    # Already gated: cli.main validates the project/explicit config for every
    # non-exempt verb before dispatching (#37).
    inst = find_instance(args.vm)
    history = args.full_history
    scope = "history" if history else "current"
    # The current scope is the current BOOT — the later of the recorded epoch
    # and the newest boot banner — the same primitive `status`/`list` and the
    # SSH preflight use. On the raw epoch alone, a `panic=N` guest that
    # rebooted on its own reported its pre-reboot panic as "current" while
    # `status` called the guest serving. `--full-history` keeps scanning
    # everything.
    start_offset = (
        0
        if history
        else current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    )
    crash = extract_crash(inst.serial_log, start_offset=start_offset)

    log_exists = Path(inst.serial_log).exists()
    scope_reason = "retained serial history" if history else "current guest epoch"
    scope_text = (
        "retained serial history (forensics; may predate current guest epoch)"
        if history
        else "current guest epoch"
    )
    detected = crash is not None
    if detected:
        reason = f"crash report extracted from {scope_reason}"
        text = f"Crash detected in {scope_text}:\n{crash}"
    elif not log_exists:
        reason = "serial log not found"
        text = f"No crash detected in {scope_text}: {reason}."
    else:
        reason = f"no crash markers found in {scope_reason}"
        text = f"No crash detected in {scope_text}: {reason}."

    crash_data = {
        "ok": detected,
        "vm": inst.vm_id,
        "crash_detected": detected,
        "scope": scope,
        "reason": reason,
        "serial_log": inst.serial_log,
        "crash": crash,
    }
    _emit(args, data=crash_data, text=text, stem="crash")
    return 0 if detected else 1


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------


def _add_log(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("log", help="View serial console log")
    p.add_argument("--tail", type=int, default=None,
                   help="Last N lines (default: 50, or the whole log when --grep is used)")
    p.add_argument("--full", action="store_true",
                   help="Emit the whole serial log (ignores --tail); pair with --out to "
                        "save it as evidence")
    p.add_argument("--grep", default=None,
                   help="Keep only lines matching this regex. Searches the WHOLE log "
                        "unless you also pass an explicit --tail")
    p.add_argument("--context", "-C", type=int, default=0, dest="context",
                   help="With --grep: also keep N lines around each match")
    _add_common_opts(p)
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.set_defaults(handler=_handle_log)


def _grep_lines(text: str, pattern: str, context: int) -> tuple[str, int]:
    """Return (rendered, match_count) for lines matching `pattern`.

    Non-adjacent hit windows are separated by a `--` marker, matching grep's
    convention so the output stays readable when context is requested.
    """
    try:
        matcher = re.compile(pattern)
    except re.error as exc:
        raise QMUError(f"Invalid --grep regex {pattern!r}: {exc}") from exc

    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if matcher.search(line)]
    if not hits:
        return "", 0

    keep: set[int] = set()
    for i in hits:
        keep.update(range(max(0, i - context), min(len(lines), i + context + 1)))

    rendered: list[str] = []
    previous: int | None = None
    for i in sorted(keep):
        if previous is not None and i > previous + 1:
            rendered.append("--")
        rendered.append(lines[i])
        previous = i
    return "\n".join(rendered) + "\n", len(hits)


def _handle_log(args: argparse.Namespace) -> int:
    # Already gated: cli.main validates the project/explicit config for every
    # non-exempt verb before dispatching (#37).
    inst = find_instance(args.vm)

    # A filtered read defaults to the WHOLE log. Applying the 50-line tail
    # first would silently scope the search to the end of the boot and report
    # "no lines matched" for a pattern that is present — a confident false
    # negative, and exactly wrong for crash triage. An explicit --tail still
    # wins, so the window is narrowable on purpose but never by accident.
    # `--full` is unbounded: the spill path in _emit turns an oversized log
    # into an artifact pointer, so this stays agent-safe.
    whole_log = args.full or (args.grep is not None and args.tail is None)
    tail_lines = 50 if args.tail is None else args.tail

    log = read_log(inst.serial_log) if whole_log else tail_log(inst.serial_log, lines=tail_lines)
    value = log or ""

    matches: int | None = None
    if args.grep is not None and value:
        value, matches = _grep_lines(value, args.grep, max(0, args.context))

    available = bool(value)
    data = {
        "ok": True,
        "vm": inst.vm_id,
        "log": value,
        "available": available,
        "empty": not available,
    }
    if args.grep is not None:
        data["grep"] = args.grep
        data["matches"] = matches or 0
        # State the scope that was actually searched, so a zero-match result is
        # never mistaken for a statement about the whole log.
        data["scope"] = "full" if whole_log else f"last {tail_lines} lines"

    if value:
        text = value
    elif args.grep is not None:
        scope = "the serial log" if whole_log else f"the last {tail_lines} lines"
        text = f"No lines in {scope} matched /{args.grep}/."
    else:
        text = "Serial log is empty or missing."

    _emit(args, data=data, text=text, stem="log")
    return 0
