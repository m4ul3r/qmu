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
import json
import re
import shlex
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..debug import check_unwarned_reboot
from ..hostcc import host_compile, resolve_host_cc
from ..instance import (
    QMUError,
    VMInstance,
    choose_instance,
    find_instance,
    instance_alive,
    load_instance,
)
from ..serial import (
    current_boot_offset,
    extract_crash,
    has_terminal_panic,
    read_log,
    serial_log_offset,
    tail_log,
)
from ..output import (
    DEFAULT_SPILL_TOKEN_LIMIT,
    _CHARS_PER_TOKEN,
    _artifact_payload,
    _estimate_tokens,
    _spill_path,
    release_closed_streams,
    text_out_pointer,
)
from ..runtime import invalidate_owned_spill_marker, mark_spill_artifact
from ..ssh import (
    SCPFileError,
    SSHAuthError,
    SSHClient,
    SSHError,
    client_log,
    guest_bytes,
    guest_lossy,
    is_auth_failure,
    is_transport_failure,
    never_connected,
    probe_refused_auth,
)
from .._cliutil import (
    Result,
    _add_common_opts,
    _auth_refused_error,
    _auth_refused_hint,
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
    from .lifecycle import _require_running

    _require_running(vm_id, command)


def _choose_running(vm_id: str | None, command: str) -> VMInstance:
    """`choose_instance`, with a listed-but-not-running name described.

    The running-only lookup answers "not found" for a stopped or orphaned
    VM that `qmu list` displays; on that miss the shared describer answers
    instead (the same words and `vm_id` `exec` gives), and only a name no
    command knows keeps the "not found" listing. Paid on the failure path
    only, so a running VM costs no extra classification. A guest reboot the
    VM's debugger was not told about is announced here (#184).
    """
    try:
        inst = choose_instance(vm_id)
    except QMUError:
        _require_running_vm(vm_id, command)
        raise
    return check_unwarned_reboot(inst)


# ---------------------------------------------------------------------------
# push / pull
# ---------------------------------------------------------------------------


def _scp_file_hint(
    exc: SCPFileError, *, inst: VMInstance, operation: str, remote: str
) -> str:
    """A recovery hint for a transfer the guest filesystem refused.

    scp's non-255 exit means the connection was fine and the path was not,
    so the generic "check the VM" advice sends the reader to the wrong place.
    Name the guest path to inspect (`qmu exec … ls -ld`) and, for a missing
    push destination, how to create it.
    """
    reason = f"{exc.stderr} {exc}"
    vm = inst.vm_id
    if remote.endswith("/"):
        remote_dir = remote.rstrip("/") or "/"
    else:
        remote_dir = remote.rsplit("/", 1)[0] or "/"
    if operation == "push":
        if "No such file or directory" in reason:
            return (
                f"The guest directory must exist: qmu exec --vm {vm} "
                f"'ls -ld {remote_dir}'; create it first with qmu exec "
                f"--vm {vm} 'mkdir -p {remote_dir}'"
            )
        if "Permission denied" in reason:
            return (
                f"Check ownership/mode on the guest path: qmu exec --vm {vm} "
                f"'ls -ld {remote_dir}'"
            )
        return f"Inspect the guest destination: qmu exec --vm {vm} 'ls -ld {remote_dir}'"
    if "No such file or directory" in reason:
        return (
            f"Check the guest file exists: qmu exec --vm {vm} 'ls -l {remote}'; "
            f"and that the local destination directory exists"
        )
    if "Permission denied" in reason:
        return (
            f"Check ownership/mode on the guest path: qmu exec --vm {vm} "
            f"'ls -l {remote}'; and that the local destination is writable"
        )
    return f"Inspect the guest file: qmu exec --vm {vm} 'ls -l {remote}'"


def _rethrow_scp_file_error(
    exc: SCPFileError, *, inst: VMInstance, operation: str, remote: str
) -> None:
    """Attach a path-specific hint and the VM to a filesystem refusal; re-raise.

    The exit-1 / `error_type: SCPFileError` contract is untouched; only the
    `hint` gains the guest path and the command that inspects it. A hint the
    raiser already set (a missing local file) is kept. `vm_id` rides in the
    envelope as it does on the success path and every other guest-command
    failure (#159).
    """
    if exc.hint is None:
        exc.hint = _scp_file_hint(exc, inst=inst, operation=operation, remote=remote)
    exc.vm_id = inst.vm_id
    raise exc



def _transfer_transport_lost(
    *,
    operation: str,
    local: str,
    remote: str,
    inst: VMInstance,
    start_offset: int,
    stem: str | None = None,
) -> Result:
    """The scp-transport-lost envelope; exit 3 only with a fresh crash.

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
    vm = inst.vm_id
    if crash is not None:
        hint = (
            "SCP transport lost. Kernel may have crashed. "
            f"See crash field or run: qmu crash --vm {vm}"
        )
        detail = f"Crash from serial log:\n{crash}"
        status = 3
    else:
        hint = (
            "SCP transport lost; VM may be unreachable. "
            f"No fresh crash report in serial log. Check: qmu log --vm {vm} --tail 100"
        )
        detail = f"No fresh crash detected. Check: qmu log --vm {vm} --tail 100"
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
    return Result(
        data=result,
        text=[f"SCP transport lost during {operation}: {direction}", detail],
        stem=stem or operation,
        exit_code=status,
    )


def _transfer_halted(
    inst: VMInstance,
    start_offset: int,
    *,
    operation: str,
    stem: str,
) -> Result | None:
    """The paused envelope when a lost transfer is explained by a halted
    vCPU (the watcher aborted it, or ssh gave up on a stopped guest). Returns
    the exit-1 Result, or None when the vCPU runs and the transport
    classification applies.
    """
    qemu_status = _halted_not_panicked(inst, start_offset=start_offset)
    if qemu_status is None:
        return None
    data, text = _stopped_guest_payload(inst, qemu_status)
    data["operation"] = operation
    return Result(
        data=data,
        text=[f"SSH connection lost during {operation}.", *text],
        stem=stem,
        exit_code=1,
    )


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
    exc: SSHError,
    *,
    inst: VMInstance,
    start_offset: int,
    operation: str,
    local: str,
    remote: str,
    stem: str,
) -> Result:
    """The envelope for a transfer `exc` ended, with its exit status;
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
    if isinstance(exc, SSHAuthError):
        # sshd answered and refused the login: not a transfer outcome, and
        # not a lost transport — the recorded user/key is wrong (#158).
        if exc.hint is None:
            exc.hint = _auth_refused_hint(inst)
        exc.vm_id = inst.vm_id
        raise exc
    halted = _transfer_halted(
        inst, start_offset, operation=operation, stem=stem
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
    return _transfer_transport_lost(
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


def _handle_push(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "push")
    _require_ssh(inst)
    if (refused := _preflight_ssh_guest(inst, stem="push")) is not None:
        return refused
    ssh = _make_ssh(inst)
    start_offset = serial_log_offset(inst.serial_log)
    try:
        ssh.push(
            args.local,
            args.remote,
            abort_when=_guest_abort_watcher(inst, start_offset=start_offset),
        )
    except SCPFileError as exc:
        _rethrow_scp_file_error(exc, inst=inst, operation="push", remote=args.remote)
    except SSHError as exc:
        return _classify_transfer_failure(
            exc, inst=inst, start_offset=start_offset, operation="push",
            local=args.local, remote=args.remote, stem="push",
        )
    return Result(
        data={"ok": True, "vm_id": inst.vm_id, "local": args.local, "remote": args.remote},
        text=f"Pushed {args.local} -> guest:{args.remote}",
        stem="push",
    )


def _add_pull(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("pull", help="Copy file from guest")
    p.add_argument("remote", help="Remote file path")
    p.add_argument("local", nargs="?", default=".", help="Local path (default: .)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_pull)


def _handle_pull(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "pull")
    _require_ssh(inst)
    if (refused := _preflight_ssh_guest(inst, stem="pull")) is not None:
        return refused
    ssh = _make_ssh(inst)
    start_offset = serial_log_offset(inst.serial_log)
    try:
        ssh.pull(
            args.remote,
            args.local,
            abort_when=_guest_abort_watcher(inst, start_offset=start_offset),
        )
    except SCPFileError as exc:
        _rethrow_scp_file_error(exc, inst=inst, operation="pull", remote=args.remote)
    except SSHError as exc:
        return _classify_transfer_failure(
            exc, inst=inst, start_offset=start_offset, operation="pull",
            local=args.local, remote=args.remote, stem="pull",
        )
    return Result(
        data={"ok": True, "vm_id": inst.vm_id, "local": args.local, "remote": args.remote},
        text=f"Pulled guest:{args.remote} -> {args.local}",
        stem="pull",
    )


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


def _add_user_opt(parser: argparse.ArgumentParser, *, what: str = "the guest command") -> None:
    """Register `--user NAME` (#150), shared by exec, compile --run and run."""
    parser.add_argument(
        "--user", default=None, metavar="NAME",
        help=f"Run {what} as guest account NAME instead of the VM's SSH user "
             "(an unprivileged PoC run): qmu logs in as usual and drops to NAME "
             "with `runuser -u NAME --` (BusyBox: `su`), in NAME's home "
             "directory; the exit status is the command's. Needs the SSH user to "
             "be root. JSON `run_as` names the account.",
    )


def _as_user(command: str, user: str) -> str:
    """The guest shell line that runs `command` as `user` (#150).

    `runuser -u` (util-linux) is the non-PAM privilege drop for root and
    forwards the child's exit status; a BusyBox guest has `su` instead, which
    does the same for root without a password. Both set HOME to the target's,
    so the command starts in NAME's home — the SSH user's home (/root) is
    normally unreadable to NAME — or in / when it has none. The command is
    one `sh -c` argument, so the caller's quoting reaches the guest unchanged.
    """
    inner = shlex.quote(f'cd "$HOME" 2>/dev/null || cd /; {command}')
    name = shlex.quote(user)
    return (
        f"if command -v runuser >/dev/null 2>&1; then exec runuser -u {name} -- "
        f"sh -c {inner}; else exec su -s /bin/sh {name} -c {inner}; fi"
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
    _add_user_opt(p)
    _add_common_opts(p)
    p.set_defaults(handler=_handle_exec)


def _transport_lost(ssh: SSHClient, inst: VMInstance) -> bool:
    """True only if SSH is unreachable after probing twice (CORR-5).

    rc==255 from `ssh.run` is ambiguous: it is both a legal guest exit code and
    the code ssh returns when the transport drops (e.g. a kernel panic). Before
    declaring a crash we confirm with a liveness probe — and retry once, since a
    single slow probe against a busy live guest can spuriously fail and produce a
    false-positive "kernel crashed". Only when BOTH probes fail do we treat the
    transport as lost.

    A probe that sshd answers by refusing the login is neither: the 255 was
    ssh's own "Permission denied" for the VM's recorded user/key, so this
    raises :class:`SSHAuthError` (exit 4, naming the user) instead of calling
    a serving guest unreachable (#158).
    """
    for attempt in range(2):
        if attempt:
            # Retry once after a short backoff: a busy guest may have missed
            # the first short probe, and an immediate re-probe would just fail
            # the same way.
            time.sleep(0.5)
        if ssh.is_ready(timeout=3):
            return False
        if probe_refused_auth(ssh):
            raise _auth_refused_error(inst, ssh)
    return True


def _never_started(ssh: SSHClient, inst: VMInstance) -> bool:
    """True when qmu's own ssh client proves an rc-255 session never reached
    the guest, so the command did not run.

    Only the client's log (:func:`~qmu.ssh.client_log`) is evidence: the
    guest's stderr carries whatever the command printed, and a command
    whose last step is a failing inner `ssh` prints ssh's pre-session lines
    there and exits 255 itself (#199). The same log saying the login was
    refused raises :class:`SSHAuthError` at once (#158) — no probe needed.
    No log (a test double) proves nothing: the caller probes.
    """
    log = client_log(ssh)
    if log is None:
        return False
    if is_auth_failure(255, log):
        raise _auth_refused_error(inst, ssh, log)
    return never_connected(255, log)


def _ssh_lost_hint(crash: str | None, vm: str, *, connected: bool = True) -> str:
    """The SSH-lost hint text, in one place.

    `exec`/`dmesg`/`compile --run` (via :func:`_ssh_lost_payload`) and the
    transfers report the same condition, so the follow-up command a caller is
    told to run must not differ between them: `compile --run` used to name no
    follow-up at all, so an agent whose exploit panicked the guest was never
    pointed at `qmu crash`. Every follow-up names the VM: a bare `qmu log`
    fails under `QMU_REQUIRE_VM=1` or with several VMs running (#180).
    """
    if crash is not None:
        return (
            "SSH connection lost. Kernel may have crashed. "
            f"See crash field or run: qmu crash --vm {vm}"
        )
    if not connected:
        return (
            "SSH could not connect, so the command never started (safe to "
            "re-run once the guest answers). No fresh crash report in serial "
            f"log. Check: qmu status --vm {vm}; qmu log --vm {vm} --tail 100"
        )
    return (
        "SSH connection lost; VM may be unreachable. "
        f"No fresh crash report in serial log. Check: qmu log --vm {vm} --tail 100"
    )


def _ssh_lost_payload(
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
    connected: bool = True,
) -> tuple[int, dict[str, Any], list[str]]:
    """Build the SSH-lost (status, data, text) triple; status 3 only on a crash.

    Used for a transport disconnect (rc=255 + no answer to the re-probe), a
    terminal panic under the command, and `dmesg`'s own expired budget on an
    unreachable guest (`exec`'s `--timeout` is :func:`_command_timeout_payload`).
    A dropped connection alone does NOT prove a panic: a guest with no sshd
    produces one on every exec, and returning 3 there reports a missing daemon
    in the kernel-crash class — against the contract that a tooling fault is
    never mistaken for a panic.
    Status 3 requires a corroborating fresh serial crash; otherwise the guest is
    merely unreachable and this is transport-layer (4). This matches the
    discrimination `_transfer_transport_lost` already applied to scp, so
    the two siblings no longer disagree about the same condition.

    A (status, data, text) triple rather than an emitter so ``qmu exec``,
    ``qmu run``, ``dmesg`` and ``compile --run`` reach the identical
    classification without re-deriving it: a second copy of this decision is
    exactly how ``exec`` and ``push``/``pull`` came to disagree about what a
    dropped connection means.

    `connected=False` is a 255 that :func:`~qmu.ssh.never_connected` proves
    was ssh's own connect/banner failure (#177): the same class (4, or 3 with
    a fresh crash), but the command is not described as having run — it
    never started — whatever a later probe says, because sshd coming up
    during the probe window made the old path report the guest command as
    having exited 255.
    """
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    vm = inst.vm_id
    # CORR-5: only assert a kernel crash when a crash report was actually
    # extracted; otherwise the connection merely dropped (VM unreachable) and we
    # must not send the agent chasing a phantom panic.
    hint = _ssh_lost_hint(crash, vm, connected=connected)
    if crash is not None:
        text_msg = f"\nCrash from serial log:\n{crash}"
    else:
        text_msg = f"\nNo fresh crash detected in serial log. Check: qmu log --vm {vm} --tail 100"
    headline = (
        f"SSH connection lost while running: {command}"
        if connected
        else f"SSH could not connect; the command was not started: {command}"
    )
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
    return status, result, [headline, text_msg]


# Who cut an in-flight guest command's SSH session (#221), as a reader
# recognises it, what that certainly did, and the recovery — worded to hold
# for every outcome of the cut: a load that QEMU then refuses rewinds
# nothing, and its command's process runs on.
_LOAD_RECOVERY = (
    "If the load succeeded, the guest was rewound and the command's process "
    "with it: re-run it on the restored guest. If it was refused "
    "(`restore_state: \"none\"`), nothing was rewound and the process may "
    "still be running in the guest: check before re-running it."
)
_SAVE_RECOVERY = (
    "The guest kept running; the command dies on its next stdout/stderr "
    "write. Re-run it after the save, or start a command that must outlive "
    "a save detached: setsid nohup CMD > /root/out.log 2>&1 < /dev/null &"
)
_REBOOT_RECOVERY = (
    "Check the guest once it serves (qmu status --vm {vm}) and re-run the "
    "command if it still needs to run."
)
_SEVER_SOURCES: dict[str, tuple[str, str, str]] = {
    "snapshot load": (
        "qmu snapshot load",
        "it closes the VM's SSH ControlMaster right before `loadvm`",
        _LOAD_RECOVERY,
    ),
    "loadvm": (
        "a raw qmu monitor/qmp `loadvm`",
        "it closes the VM's SSH ControlMaster right before `loadvm`",
        _LOAD_RECOVERY,
    ),
    "snapshot save": (
        "qmu snapshot save",
        "it closes the VM's SSH ControlMaster before saving",
        _SAVE_RECOVERY,
    ),
    "savevm": (
        "a raw qmu monitor/qmp `savevm`",
        "it closes the VM's SSH ControlMaster before saving",
        _SAVE_RECOVERY,
    ),
    "system_reset": (
        "a raw qmu qmp/monitor `system_reset`",
        "it closes the VM's SSH ControlMaster and resets the guest",
        _REBOOT_RECOVERY,
    ),
    "guest reboot": (
        "a guest reboot",
        "the guest kernel booted again while it ran",
        _REBOOT_RECOVERY,
    ),
}


def _severed_by(inst: VMInstance, *, started_at: float) -> str | None:
    """What cut a guest command's session after it started, if anything.

    The one signal is the record's `ssh_severed_at`/`ssh_severed_by` stamp
    at or after `started_at`, written just before the cut by whoever made
    it: the qmu command that tears the ControlMaster down for a load, save
    or reset (`qmp_cmds._sever_sessions`), or the daemon when QEMU reports
    a guest-requested RESET (`"guest reboot"`). A session cut either way
    used to be reported as the guest command exiting 255 (#221). Nothing
    the guest can write decides it: a boot banner in the serial log is not
    a reboot — `dmesg > /dev/console` reprints it verbatim with the session
    intact and the guest command really exiting 255 (review of #221). With
    the daemon off nothing stamps a guest reboot; :func:`_booted_since`
    answers that case from the guest kernel's own clock.
    """
    record = load_instance(inst.vm_id)
    stamped = getattr(record, "ssh_severed_at", None)
    if isinstance(stamped, (int, float)) and stamped >= started_at:
        return record.ssh_severed_by or "snapshot load"
    return None


def _booted_since(ssh: SSHClient, *, started: float) -> bool:
    """Whether the guest kernel booted after `started` (`time.monotonic()`
    when the command began), read from `/proc/uptime` once sshd answers.

    The guest's CLOCK_BOOTTIME cannot be set by anything in the guest (a
    console replay, a `date -s`, a command's output), so an uptime shorter
    than the time since the command started means a new boot ran under it:
    a guest reboot with no daemon to witness QEMU's RESET (review of #221).
    Without a reboot the uptime is the guest's uptime at the command's start
    plus the time since, which is never shorter. A snapshot load also rewinds
    it, but qmu stamps its own loads first. Any failure to read it proves
    nothing: False.
    """
    try:
        rc, out, _ = ssh.run("cat /proc/uptime", timeout=5)
    except SSHError:
        return False
    elapsed = time.monotonic() - started
    if rc != 0:
        return False
    try:
        uptime = float(str(out).split()[0])
    except (IndexError, ValueError):
        return False
    return uptime < elapsed


def _severed_payload(
    command: str, inst: VMInstance, cause: str, *, start_offset: int
) -> tuple[int, dict[str, Any], list[str]]:
    """The (status, data, text) triple for a session qmu or a reboot cut.

    A dropped transport with no crash report is 4 under the contract, and
    here the drop is explained: `ssh_error: true`, `exit_code: null` (ssh's
    255 is not the guest's) and `severed_by` naming the cause. A report the
    command provoked stays attributed (`crash_detected`/`crash`); only a
    reboot after one keeps the crash class (3), as a dropped transport
    with a fresh report does — qmu's own teardown is never a kernel crash.
    """
    vm = inst.vm_id
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    who, effect, recovery = _SEVER_SOURCES.get(
        cause, (cause, "the session was closed", _REBOOT_RECOVERY)
    )
    head = (
        f"The command's SSH session was cut by {who} ({effect}), so its exit "
        "status is unknown."
    )
    if crash is not None:
        hint = (
            f"{head} The kernel printed a crash report while it ran; read it "
            f"with: qmu crash --vm {vm}"
        )
    else:
        hint = f"{head} {recovery.format(vm=vm)}"
    status = 3 if crash is not None and cause == "guest reboot" else 4
    result: dict[str, Any] = {
        "ok": False,
        "vm_id": vm,
        "exit_code": None,
        "ssh_error": True,
        "severed_by": cause,
        "crash_detected": crash is not None,
        "command": command,
        "crash": crash,
        "hint": hint,
    }
    text = [f"SSH session cut by {who} while running: {command}"]
    text.append(f"\nCrash from serial log:\n{crash}" if crash is not None else hint)
    return status, result, text


def _ssh_255_payload(
    ssh: SSHClient,
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
    started_at: float,
    started_mono: float,
) -> tuple[int, dict[str, Any], list[str]] | None:
    """The SSH-lost triple for an rc-255 session the serial log and QMP did
    not explain, or None when the guest command itself returned 255.

    ssh's own pre-session failure (`Connection timed out during banner
    exchange`, :func:`_never_started`) settles it without a probe: the
    command never ran, so a sshd that comes up during the probe window must
    not turn it into "the guest command exited 255" (#177). A session qmu
    itself cut (a snapshot load/save, a raw reset) or the daemon saw a guest
    reboot cut (:func:`_severed_by`) is next: the restored or rebooted guest
    answers the probe, which then called the cut the guest program exiting
    255 (#221). A guest that answers the probe but whose kernel booted after
    the command started (:func:`_booted_since`) was rebooted under it too —
    the daemon-off form of the same cut. Anything else is ambiguous and
    :func:`_transport_lost` probes. The guest's stdout/stderr and console
    decide nothing here: a guest command can print ssh's words itself
    (#199), and replay the boot banner.
    """
    if _never_started(ssh, inst):
        return _ssh_lost_payload(
            command, inst, start_offset=start_offset, connected=False
        )
    cause = _severed_by(inst, started_at=started_at)
    if cause is None:
        lost = _transport_lost(ssh, inst)
        # The stamp may land while the probe runs (the daemon writes a
        # guest reboot's from its own thread): read it once more.
        cause = _severed_by(inst, started_at=started_at)
        if cause is None:
            if lost:
                return _ssh_lost_payload(command, inst, start_offset=start_offset)
            if not _booted_since(ssh, started=started_mono):
                return None
            cause = "guest reboot"
    return _severed_payload(command, inst, cause, start_offset=start_offset)


def _explain_lost_transport(
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
    halted_status: Callable[[], str | None] | None = None,
    session_note: bool = False,
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
        if session_note:
            # #143: the session is gone (not detached), so the guest process
            # dies of SIGPIPE on its next write once the vCPU runs again.
            data["hint"] += " " + _HALT_KILLS_SESSION
            text = [*text, _HALT_KILLS_SESSION]
        return 1, data, [f"SSH connection lost while running: {command}", *text]
    return None


_HALT_KILLS_SESSION = (
    "The command's SSH session is closed: once the vCPU runs again it dies on "
    "its next stdout/stderr write (SIGPIPE). Start a trigger that must outlive "
    "a debugger stop detached: setsid nohup CMD > /root/out.log 2>&1 < /dev/null &"
)


def _detached_halt_payload(
    command: str, inst: VMInstance, qemu_status: str, output: Path
) -> tuple[int, dict[str, Any], list[str]]:
    """A debugger stop mid-command, with the command left running (#143).

    The paused envelope the preflight uses (exit 1), plus `detached_output`:
    qmu did not close the command's SSH session, so the trigger continues
    when the vCPU resumes and its further output lands in that file
    (measured: a 120 s halt, the command finished after `qmu cont`). What
    still ends it is its SSH connection going away — `snapshot load`,
    `system_reset` and `kill` tear the ControlMaster down — so the hint names
    the fully detached form for a trigger that must survive those.
    """
    data, text = _stopped_guest_payload(inst, qemu_status)
    data["exit_code"] = None
    data["command"] = command
    data["detached_output"] = str(output)
    note = (
        "The command is still running in the guest: qmu left its SSH session "
        f"open, so it continues when the vCPU resumes; its further output is "
        f"appended to {output}. A snapshot load, reset or kill drops that "
        "session; a trigger that must survive those runs detached: setsid "
        "nohup CMD > /root/out.log 2>&1 < /dev/null &"
    )
    data["hint"] += " " + note
    return 1, data, [f"vCPU halted while running (command left running): {command}", *text, note]


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
        # The QEMU status that made the predicate fire on a halted vCPU;
        # None for a panic, or while it has not fired.
        self.halt: str | None = None

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
        self.halt = self.halted_status()
        return self.halt is not None


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
    *,
    start_offset: int,
    answering: bool,
) -> tuple[int, dict[str, Any], list[str]]:
    """qmu's own `--timeout` ended the command, and nothing explains it sooner.

    Exit 124 is the contract's timeout code, and it is what this is whatever
    the guest looks like afterwards: qmu cut the session at the deadline, so
    no transport was "lost". A terminal panic or a halted vCPU since the
    command began is already reported by :func:`_explain_lost_transport`
    before this is reached. It used to probe SSH twice (≈7 s past the
    deadline) and take the crash/transport-loss path when the guest did not
    answer, so a guest wedged printing a `kasan_multi_shot` report flood
    returned exit 3 — the "kernel crashed" class — 7.7 s after `--timeout
    120`, without `timed_out` and with no panic in the log (#142).

    `answering` is ONE readiness probe, the one `status` runs (≤2.25 s): it
    decides `ssh_error` and the hint, never the exit code. A report the
    kernel printed while the command ran is `crash_detected`/`crash` here as
    on every other path (the newest event, not the flood). Keeping the L1
    booleans present is what lets a caller branch on `crash_detected` without
    first checking which envelope shape it received.
    """
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    vm = inst.vm_id
    if answering:
        reach = "guest still reachable"
        hint = (
            f"Guest command exceeded --timeout ({timeout:g}s) but the guest is "
            "still answering SSH. "
        )
    else:
        reach = "guest no longer answers SSH"
        hint = (
            f"Guest command exceeded --timeout ({timeout:g}s) and the guest no "
            "longer answers SSH (it did not panic). "
        )
    if crash is not None:
        hint += (
            "The kernel printed a crash report while the command ran (crash); "
            f"read it with: qmu crash --vm {vm}"
        )
        detail = f"\nCrash from serial log (no panic):\n{crash}"
    elif answering:
        hint += "Raise --timeout, or check what the command is waiting on."
        detail = "No crash detected. Raise --timeout if the command needs longer."
    else:
        hint += (
            f"No fresh crash report in the serial log. Check: qmu status --vm {vm}; "
            f"qmu log --vm {vm} --tail 100"
        )
        detail = f"No fresh crash detected in serial log. Check: qmu log --vm {vm} --tail 100"
    return (
        124,
        {
            "ok": False,
            "vm_id": vm,
            "exit_code": None,
            "ssh_error": not answering,
            "crash_detected": crash is not None,
            "crash": crash,
            "timed_out": True,
            "command": command,
            "timeout": timeout,
            "hint": hint,
        },
        [
            f"Guest command timed out after {timeout:g}s ({reach}): {command}",
            detail,
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
    *,
    note_stderr: bool = True,
) -> tuple[int, dict[str, Any], str, list[str], list[str | bytes]]:
    """Attach what the guest printed to a lost/expired/halted outcome.

    The stopped child's output is still the guest's output: a long-running
    exploit that prints progress and then panics (or outlives `--timeout`)
    has told the caller where it got to, and dropping that with the
    classification made every such run look silent. Guest stdout goes to
    stdout (it is stdout); the classification's text and guest stderr go to
    stderr — the text as a note after the guest's own stderr, which is in
    the notes verbatim unless a stream sink already relayed it live
    (`note_stderr=False`).
    """
    status, data, text = outcome
    data.update(_stream_fields(stdout, stderr))
    notes: list[str | bytes] = [guest_bytes(stderr)] if stderr and note_stderr else []
    return status, data, stdout, text, notes


# Bytes of guest stdout a streamed text-mode command may put on stdout before
# the rest is diverted to a spill file: the same budget `write_bytes_result`
# applies to a buffered payload, measured in bytes because the stream cannot
# be decoded before it is written.
STREAM_SPILL_BYTES = DEFAULT_SPILL_TOKEN_LIMIT * _CHARS_PER_TOKEN


def _relay(stream: Any, data: bytes | str) -> None:
    """Write and flush one relayed chunk on `stream` (`sys.stdout`/`stderr`).

    A reader that closed the stream (`qmu exec … | head -5`, #208) drops
    the rest of it: the guest command still runs to its own end and qmu
    exits with that command's code, as the buffered rendering does.
    """
    try:
        stream.flush()
        target = stream.buffer if isinstance(data, bytes) else stream
        target.write(data)
        target.flush()
    except BrokenPipeError:
        if not release_closed_streams():
            raise


class _TextStreamSink:
    """Relay guest output to the terminal as it arrives (text mode).

    stdout chunks go to `sys.stdout.buffer` and stderr chunks to
    `sys.stderr.buffer`, flushed after every write, so a long-running
    exploit's progress is visible before it exits or `--timeout` fires. The
    bytes are copied verbatim — `qmu exec ... | sha256sum` matches the
    buffered rendering byte for byte.

    The spill/`--out` contract of `Result.raw` is kept, with the one
    difference a live stream forces: `--out FILE` streams into the file and
    the pointer envelope follows at the end; without `--out`, output within
    the budget (:data:`STREAM_SPILL_BYTES`) stays on stdout, and the first
    chunk crossing it diverts the remainder into a spill file that then holds
    the *whole* output (the prefix already shown included), announced by the
    usual pointer + preview trailer once the command ends. The file (like
    stdout) holds guest stdout only: the outcome text (a crash report, the
    timeout or debugger-stop notice) is a stderr note, rendered after the
    stream (#172).

    `finish` writes whatever the final output holds beyond what was
    relayed: nothing for the real client, everything for a test double that
    returns output without ever calling `on_chunk`.
    """

    streams_stderr = True

    def __init__(self, *, out_path: Path | None, stem: str) -> None:
        self._stem = stem
        self._explicit_out = out_path
        self._file = None
        self._path: Path | None = None
        self._spilled = False
        self._shown = 0  # bytes on stdout
        self._prefix = bytearray()  # stdout bytes shown, kept until diverted
        self._out_received = 0
        self._err_received = 0
        self.err_at_line_start = True
        if out_path is not None:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            invalidate_owned_spill_marker(out_path)
            self._open(out_path)

    def _open(self, path: Path) -> None:
        self._path = path
        self._file = path.open("wb")

    @property
    def wrote_to_file(self) -> bool:
        """True when stdout ended with a pointer line (`--out` or a spill),
        not with the guest's last byte."""
        return self._path is not None

    def on_chunk(self, stream: str, data: bytes) -> None:
        if stream == "stderr":
            self._err_received += len(data)
            if data:
                _relay(sys.stderr, data)
                self.err_at_line_start = data.endswith(b"\n")
            return
        self._out_received += len(data)
        self._write_out(data)

    def _write_out(self, data: bytes) -> None:
        if not data:
            return
        if self._file is None:
            room = STREAM_SPILL_BYTES - self._shown
            if len(data) <= room:
                self._emit(data)
                self._prefix += data
                return
            # Budget crossed: show what still fits, then divert everything
            # (the shown prefix included) to a spill file.
            self._emit(data[:room])
            self._prefix += data[:room]
            self._spilled = True
            self._open(_spill_path(self._stem, ".txt"))
            self._file.write(bytes(self._prefix))
            self._prefix = bytearray()
            data = data[room:]
        self._file.write(data)
        self._file.flush()

    def _emit(self, data: bytes) -> None:
        _relay(sys.stdout, data)
        self._shown += len(data)

    def finish(
        self,
        stdout: str,
        stderr: str,
        *,
        source_ok: bool,
        exit_code: int | None,
    ) -> None:
        """Flush the un-relayed remainder, and the pointer when the stream
        went to a file."""
        out_raw, err_raw = guest_bytes(stdout), guest_bytes(stderr)
        self.on_chunk("stdout", out_raw[self._out_received:])
        self.on_chunk("stderr", err_raw[self._err_received:])
        if self._file is None:
            return
        self._file.close()
        full = out_raw
        if self._spilled:
            mark_spill_artifact(self._path)
        artifact = _artifact_payload(
            artifact_path=self._path,
            fmt="text",
            encoded=full,
            token_estimate=_estimate_tokens(full.decode("utf-8", errors="replace")),
            value={"kind": "bytes", "bytes": len(full)},
            source_ok=source_ok,
        )
        if exit_code is not None:
            artifact["exit_code"] = exit_code
        if self._spilled:
            # The preview already went by live; say where the rest is.
            rendered = (
                f"[qmu] Output spilled to {self._path} "
                f"(~{artifact['token_estimate']} tokens)\n"
                f"[qmu] Preview: first {self._shown} of {len(full)} bytes "
                f"({len(full) - self._shown} omitted) streamed above\n"
            )
        else:
            rendered = text_out_pointer(artifact)
        _relay(sys.stdout, rendered.encode("utf-8"))
        if self._spilled:
            _relay(sys.stderr, f"[qmu] Output spilled to {self._path}\n")


class _NdjsonStreamSink:
    """Relay guest output as `{"event": "chunk", ...}` lines (ndjson mode).

    Each drained read becomes one line on stdout, `stream` being `stdout` or
    `stderr` and `data` the bytes decoded as UTF-8 with `surrogateescape`
    (JSON-escaped, so undecodable bytes round-trip as lone surrogates and a
    chunk boundary may split a multibyte character). The normal final
    envelope — the one line carrying `ok` — follows as the last line and
    still holds the complete `stdout`/`stderr`, so a reader may ignore the
    chunk events entirely. Nothing is relayed at `finish`: the envelope has
    the whole output, only live data is worth an event.
    """

    streams_stderr = False
    err_at_line_start = True

    def on_chunk(self, stream: str, data: bytes) -> None:
        line = json.dumps(
            {
                "event": "chunk",
                "stream": stream,
                "data": data.decode("utf-8", errors="surrogateescape"),
            },
            sort_keys=True,
        )
        _relay(sys.stdout, line + "\n")

    def finish(self, *args: Any, **kwargs: Any) -> None:
        return None


def _stream_sink(
    args: argparse.Namespace, *, stem: str
) -> _TextStreamSink | _NdjsonStreamSink | None:
    """The live relay for a guest command under this `--format`, or None for
    `json` (buffered envelope, unchanged)."""
    fmt = getattr(args, "format", "text")
    if fmt == "text":
        out = getattr(args, "out", None)
        return _TextStreamSink(out_path=Path(out) if out else None, stem=stem)
    if fmt == "ndjson":
        return _NdjsonStreamSink()
    return None


def _run_guest_command(
    ssh: SSHClient,
    command: str,
    inst: VMInstance,
    *,
    timeout: float,
    sink: _TextStreamSink | _NdjsonStreamSink | None = None,
    user: str | None = None,
) -> tuple[int, dict[str, Any], str, list[str], list[str | bytes]]:
    """Run `command` in the guest — as `user` when given (#150) — and
    classify the outcome (see :func:`_classify_guest_command`).

    The privilege drop is :func:`_as_user` around the command on the wire
    only: every envelope's `command` is the command as the caller gave it,
    and `run_as` names the account it ran as, on every path.
    """
    run_as = user or inst.ssh_user
    wire = _as_user(command, user) if user and user != inst.ssh_user else command
    status, data, stdout, text, notes = _classify_guest_command(
        ssh, command, inst, timeout=timeout, sink=sink, wire=wire
    )
    data["run_as"] = run_as
    return status, data, stdout, text, notes


def _classify_guest_command(
    ssh: SSHClient,
    command: str,
    inst: VMInstance,
    *,
    timeout: float,
    sink: _TextStreamSink | _NdjsonStreamSink | None,
    wire: str,
) -> tuple[int, dict[str, Any], str, list[str], list[str | bytes]]:
    """Run `wire` (`command`, or its privilege-dropped form) in the guest and
    classify the outcome; envelopes and messages name `command`.

    Returns (exit status, JSON data, guest stdout, trailing stdout text,
    stderr notes) rather than emitting, so ``qmu exec``, ``qmu run`` and
    ``compile --run`` render the same classification under their own
    ``stem`` instead of maintaining copies of the crash-vs-transport-loss
    discrimination. In text mode stdout is the guest's stdout, byte for
    byte; the text lines (the crash report, the timeout or halt notice when
    the command was lost) and the notes belong on stderr (guest stderr bytes
    verbatim, the `[exit code: N]` trailer, a survived kernel report) — see
    :func:`_guest_result`.

    The ssh child is watched by :func:`_guest_abort_watcher`: a terminal
    panic appended after the command started, or a vCPU QMP reports halted,
    kills it immediately — ssh's keepalive never gives up on a silent guest
    (#182), and before that it took the keepalive window plus the liveness
    re-probes (measured 20–50 s for a sysrq crash the serial log showed
    within 100 ms).

    `sink` (from :func:`_stream_sink`) receives the output live; a text sink
    relays guest stderr itself, so the stderr bytes then stay out of `notes`.
    """
    command_start_offset = serial_log_offset(inst.serial_log)
    started_at, started_mono = time.time(), time.monotonic()
    watcher = _guest_abort_watcher(inst, start_offset=command_start_offset)

    def detach_to() -> Path | None:
        # A debugger stop is not the command's end (#143): leave its session
        # open so the trigger is still there after `pry continue`. A panic
        # ends the guest, so that abort kills the child as before.
        return _spill_path("exec-detached", ".txt") if watcher.halt is not None else None

    note_stderr = sink is None or not sink.streams_stderr
    try:
        rc, stdout, stderr = ssh.run(
            wire,
            timeout=timeout,
            abort_when=watcher,
            on_chunk=sink.on_chunk if sink is not None else None,
            detach_to=detach_to,
        )
    except SSHError as exc:
        # qmu stopped waiting: the watcher saw a panic or a halted vCPU, or
        # --timeout expired. A halt left the command running (detached); the
        # serial log and QMP explain the rest (instant, and authoritative);
        # what is left is qmu's own deadline,
        # which is a timeout (124) whether or not the guest still answers —
        # one readiness probe only says which, for the hint (#142). Probing
        # first and taking the crash/transport-loss path on no answer told the
        # caller a healthy kernel had died for a slow command (reproduced live
        # with `qmu run --timeout 1 -- 'sleep 10'`), and a guest wedged by a
        # report flood "crashed" 7 s after the deadline.
        detached = getattr(exc, "detached_output", None)
        if detached is not None:
            explained = _detached_halt_payload(command, inst, watcher.halt or "paused", detached)
        else:
            explained = _explain_lost_transport(
                command, inst, start_offset=command_start_offset,
                halted_status=watcher.halted_status, session_note=True,
            )
        if explained is None:
            explained = _command_timeout_payload(
                command, inst, timeout,
                start_offset=command_start_offset, answering=ssh.is_ready(),
            )
        return _with_guest_output(
            explained, exc.stdout, exc.stderr, note_stderr=note_stderr
        )

    # A kernel panic during the command drops the connection and ssh exits 255 —
    # often with EMPTY stderr (LogLevel=ERROR suppresses the keepalive message),
    # so a stderr-marker test is unreliable. rc=255 is also a legal guest exit
    # code, so disambiguate: the serial log / QMP first (a panic appended after
    # the command started, or a halted vCPU, settle it), then ssh's own
    # never-connected lines (#177), then an authoritative
    # liveness probe (retried once to avoid a false positive on a busy live
    # guest): if SSH is still unreachable the guest vanished (crash); if it
    # answers, the guest genuinely returned 255 and we take the normal path.
    if rc == 255:
        explained = _explain_lost_transport(
            command, inst, start_offset=command_start_offset, session_note=True
        ) or _ssh_255_payload(
            ssh, command, inst, start_offset=command_start_offset,
            started_at=started_at, started_mono=started_mono,
        )
        if explained is not None:
            return _with_guest_output(explained, stdout, stderr, note_stderr=note_stderr)

    # A report the kernel printed while the command ran is a crash the guest
    # survived (under `exploit-dev` an Oops kills only the faulting task), and
    # `crash_detected` is the key every reader gates on: it used to be filed
    # under `kernel_warning` with `crash_detected: false`, while the `status`
    # right after called the same event `crashed` and `qmu crash` returned it
    # (#136). The exit code stays the guest command's: the session completed.
    crash = extract_crash(inst.serial_log, start_offset=command_start_offset)
    notes: list[str | bytes] = []
    if stderr and note_stderr:
        notes.append(guest_bytes(stderr))
    if rc != 0:
        notes.append(f"[exit code: {rc}]")
    if crash is not None:
        notes.append(
            "Kernel crash report from command serial output (the guest kept "
            "running):\n" + crash.rstrip()
        )
    # L1: always include ssh_error/crash_detected so consumers have a stable,
    # explicit contract (not an implicit "key omitted on success").
    # `kernel_warning`/`kernel_warning_detected` are the keys this report used
    # to be filed under; they stay, carrying the same report, so a consumer
    # written against them keeps working.
    data: dict[str, Any] = {
        "ok": rc == 0,
        "vm_id": inst.vm_id,
        "exit_code": rc,
        **_stream_fields(stdout, stderr),
        "ssh_error": False,
        "crash_detected": crash is not None,
        "crash": crash,
        "kernel_warning_detected": crash is not None,
        "kernel_warning": crash,
    }
    if rc != 0:
        data["hint"] = _guest_exit_hint(inst, rc, crash is not None)
    return (0 if rc == 0 else 1), data, stdout, [], notes


def _guest_exit_hint(inst: VMInstance, rc: int, kernel_report: bool) -> str:
    """The recovery for a guest command that ran to completion and failed.

    The guest already said why on stderr, so the hint points there first and
    never at `qmu doctor` (a host check that cannot see a guest exit code).
    A kernel report captured during the command is the more likely cause and
    leads when present.
    """
    if kernel_report:
        return (
            f"The guest command exited {rc} and the kernel printed a crash "
            f"report during it (crash); read it in full with: qmu crash --vm "
            f"{inst.vm_id}, or qmu log --vm {inst.vm_id} --tail 100"
        )
    return (
        f"The guest command exited {rc} — see stderr; if a kernel message is "
        f"expected: qmu exec --vm {inst.vm_id} 'dmesg | tail -n 30'"
    )


def _stdout_is_terminal() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _guest_result(
    *,
    data: dict[str, Any],
    stdout: str = "",
    stderr: str = "",
    text: list[str] = (),
    notes: list[str | bytes] = (),
    followups: list[str] = (),
    stem: str,
    exit_code: int,
    sink: _TextStreamSink | _NdjsonStreamSink | None = None,
) -> Result:
    """A guest command Result; text mode keeps stdout for guest stdout.

    Text mode writes the guest's `stdout` bytes to stdout exactly as the
    guest wrote them — no decode, no added newline — as `Result.raw`
    (spill/--out apply), and nothing else: an empty payload prints nothing
    rather than a blank line, so `qmu exec ... > out.txt` is byte-exact for
    a silent command too. `notes` go to stderr: `bytes` entries are guest
    stderr, verbatim; `str` entries (`[exit code: N]`, kernel warnings,
    follow-up hints) are qmu's lines and start on a fresh line. `text` (the
    crash report, timeout or debugger-stop notice when the command was lost)
    follows them, then `followups` (`run`'s preserved-VM hints: the cause
    reads before the cleanup advice). When guest stdout on a terminal ended
    mid-line, the text starts on a fresh terminal line. `exec` used to
    print all of it on stdout as
    `[stderr] ...` / `[exit code: N]` lines, so a pipeline or a redirect
    collected the decorations as if the guest had printed them; then it
    rendered the stdout as text, so `printf x` arrived as `x\\n` and a 0xff
    byte as U+FFFD; the `text` trailer stayed on stdout until #172. JSON
    modes: `data` is the envelope.

    With a text `sink` the stdout bytes (and guest stderr) were relayed as
    they arrived; `sink.finish` writes any remainder, and the Result is
    `streamed` so render adds nothing to stdout. The notes still follow on
    stderr, on a fresh line after streamed stderr that ended without one.
    An ndjson sink has nothing left to do: the envelope renders as usual.
    """
    raw = guest_bytes(stdout)
    if text:
        if (raw and not raw.endswith(b"\n") and _stdout_is_terminal()
                and not (isinstance(sink, _TextStreamSink) and sink.wrote_to_file)):
            # The old stdout trailer started on a fresh line; on a shared
            # terminal the stderr text must too, without touching stdout.
            notes = [*notes, b"\n"]
        notes = [*notes, "\n".join(text)]
    notes = [*notes, *followups]
    if isinstance(sink, _TextStreamSink):
        exit_rc = data.get("exit_code")
        sink.finish(
            stdout,
            stderr,
            source_ok=bool(data.get("ok", False)),
            exit_code=exit_rc if isinstance(exit_rc, int) else None,
        )
        if not sink.err_at_line_start and any(isinstance(n, str) for n in notes):
            notes = [b"\n", *notes]
        return Result(
            data=data, stem=stem, exit_code=exit_code, notes=tuple(notes),
            streamed=True,
        )
    return Result(
        data=data,
        stem=stem,
        exit_code=exit_code,
        raw=raw,
        suffix=".txt",
        notes=tuple(notes),
    )


def _handle_exec(args: argparse.Namespace) -> Result:
    _require_running_vm(args.vm, "exec")
    inst = check_unwarned_reboot(choose_instance(args.vm))
    _require_ssh(inst)
    if (refused := _preflight_ssh_guest(inst, stem="exec")) is not None:
        return refused
    ssh = _make_ssh(inst)
    command = _join_exec_command(args.command)
    sink = _stream_sink(args, stem="exec")
    status, data, stdout, text, notes = _run_guest_command(
        ssh, command, inst, timeout=args.timeout, sink=sink, user=args.user
    )
    return _guest_result(
        data=data, stdout=stdout, stderr=data.get("stderr", ""), text=text,
        notes=notes, stem="exec", exit_code=status, sink=sink,
    )


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------


_COMPILE_DEFAULT_CFLAGS = "-static -lpthread"
_COMPILE_DEFAULT_TIMEOUT = 60.0


def _add_compile(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("compile", help="Compile C file in guest (or on the host with --host)")
    p.add_argument("source", help="Local C source file")
    p.add_argument(
        "program_args", nargs="*", metavar="ARG",
        help="With --run: argv for the program, each ARG one argument "
             "(shell-quoted); put -- before them when one starts with a dash "
             "(`qmu compile poc.c --run -- /tmp/target 1 DATA`).",
    )
    p.add_argument("--run", action="store_true", help="Run after compiling")
    p.add_argument("--cflags", default=_COMPILE_DEFAULT_CFLAGS, help="Compiler flags")
    p.add_argument("--timeout", type=float, default=_COMPILE_DEFAULT_TIMEOUT, help="Execution timeout")
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
    _add_user_opt(p, what="the compiled binary (with --run)")
    _add_common_opts(p)
    # `trailing_positionals`: ARGs after `--run`/`--` land in program_args on
    # every supported Python (`cli._absorb_trailing_positionals`).
    p.set_defaults(handler=_handle_compile, trailing_positionals="program_args")


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
    chmod_rc, chmod_out, chmod_err = ssh.run(
        f"chmod +x {shlex.quote(remote_bin)}", timeout=15, abort_when=watcher
    )
    # ...unless the guest vanished under it. rc=255 is both a legal exit code and
    # what ssh returns when a panic drops the transport, so confirm with the same
    # liveness probe exec uses and hand the caller the transport-loss path:
    # reporting a kernel panic as "compilation failed" would bury it. ssh's own
    # never-connected failure, read from its own log, needs no probe: chmod
    # never ran (#177).
    if chmod_rc == 255 and (
        _never_started(ssh, inst) or _transport_lost(ssh, inst)
    ):
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


def _handle_compile(args: argparse.Namespace) -> Result:
    # Arguments for a program that is never run would be dropped silently;
    # refuse before anything is compiled.
    if getattr(args, "program_args", None) and not args.run:
        # The corrected command is the caller's own, plus --run: dropping
        # --host/--cflags/--cc/--timeout/--user would rebuild something else.
        retry = ["qmu", "compile", args.source]
        if args.vm:
            retry += ["--vm", args.vm]
        if args.host_build:
            retry.append("--host")
        if args.cc is not None:
            retry += ["--cc", args.cc]
        if args.cflags != _COMPILE_DEFAULT_CFLAGS:
            retry += ["--cflags", args.cflags]
        if args.timeout != _COMPILE_DEFAULT_TIMEOUT:
            retry += ["--timeout", f"{args.timeout:g}"]
        if args.user:
            retry += ["--user", args.user]
        retry += ["--run", "--", *args.program_args]
        raise QMUError(
            "compile got program arguments without --run: "
            + shlex.join(args.program_args),
            hint=shlex.join(retry),
        )
    if args.user and not args.run:
        # A mode-scoped flag must not parse and do nothing.
        raise QMUError(
            "--user applies to --run (it names who runs the binary); "
            "nothing runs without --run.",
            hint="add --run, or drop --user",
        )
    inst = _choose_running(args.vm, "compile")
    _require_ssh(inst)
    if (refused := _preflight_ssh_guest(inst, stem="compile")) is not None:
        return refused
    ssh = _make_ssh(inst)
    source = Path(args.source)

    if not source.exists():
        raise QMUError(f"Source file not found: {source}")

    name = source.stem
    # The SSH user's home (/root) is unreadable to another account, so a
    # binary that runs as --user is built into /tmp (#150).
    remote_dir = "/tmp" if args.user and args.user != inst.ssh_user else "/root"
    remote_src = f"{remote_dir}/{source.name}"
    remote_bin = f"{remote_dir}/{name}"

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
                exc, inst=inst, start_offset=delivery_offset, operation="push",
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
                exc, inst=inst, start_offset=push_offset, operation="push",
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
            return _guest_result(
                data=data, stdout=stdout, text=text, notes=notes, stem="compile",
                exit_code=status,
            )

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
        result["hint"] = (
            f"The compiler exited {rc} {where} — fix the errors in "
            "compile_stderr; pass --cflags/--cc to change the build line"
            + (
                ""
                if args.host_build
                else f", or --host-build to compile on the host and push the binary"
            )
        )
        return Result(
            data=result,
            text=f"Compilation failed {where}:\n{str(result['compile_stderr']).strip()}",
            stem="compile",
            exit_code=1,
        )

    result["compiled"] = True

    if not args.run:
        result["ok"] = True
        built_by = (
            f" (host {result['compiler']})" if args.host_build else ""
        )
        # Text mode: the banner is a note (stderr), never stdout — stdout is
        # reserved for program output on every compile path, so a redirect
        # of `compile` with or without --run collects the same thing.
        return _guest_result(
            data=result,
            notes=[f"Compiled {source.name} -> {remote_bin}{built_by}"],
            stem="compile",
            exit_code=0,
        )

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
    sink = _stream_sink(args, stem="compile")
    run_args = list(getattr(args, "program_args", None) or [])
    run_cmd = shlex.join([remote_bin, *run_args])
    status, data, stdout, text, notes = _run_guest_command(
        ssh, run_cmd, inst, timeout=args.timeout, sink=sink,
        user=args.user,
    )
    run_stderr = data.get("stderr", "")
    data = {**result, **_as_run_fields(data), "run_args": run_args}
    return _guest_result(
        data=data, stdout=stdout, stderr=run_stderr, text=text, notes=notes,
        stem="compile", exit_code=status, sink=sink,
    )


def _as_run_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Rename exec's stream/exit keys to the compile envelope's `run_*` ones.

    `command` is dropped: the envelope already names what ran
    (`compile_cmd`, and the binary is `/root/<stem>`, or `/tmp/<stem>` under
    `--user`); `run_as` stays as is.
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


def _handle_dmesg(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "dmesg")
    _require_ssh(inst)
    if (refused := _preflight_ssh_guest(inst, stem="dmesg")) is not None:
        return refused
    ssh = _make_ssh(inst)
    cmd = "dmesg"
    if args.tail is not None:
        # `is not None` so --tail 0 is honored rather than silently dropped.
        # Clamp negatives to 0: like `tail -n 0`, both emit nothing (a negative
        # count would otherwise be misparsed as a tail option).
        cmd = f"dmesg | tail -n {max(args.tail, 0)}"
    command_start_offset = serial_log_offset(inst.serial_log)
    started_at, started_mono = time.time(), time.monotonic()
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
            if not _transport_lost(ssh, inst):
                raise
            explained = _ssh_lost_payload(
                cmd, inst, start_offset=command_start_offset
            )
        status, data, out, text, notes = _with_guest_output(
            explained, exc.stdout, exc.stderr
        )
        return _guest_result(
            data=data, stdout=out, text=text, notes=notes, stem="dmesg",
            exit_code=status,
        )

    # A panic during the read drops the connection and ssh exits 255, often
    # with only a banner-exchange timeout on stderr. rc=255 is also a legal
    # guest exit code, so disambiguate exactly as exec does: serial log / QMP
    # first, then ssh's own never-connected lines, then the probed liveness
    # check. Without this, `qmu dmesg` on a
    # dead guest returned exit 1 — the "guest command non-zero" class —
    # reading as "dmesg failed inside the guest" while the kernel was gone.
    if rc == 255:
        explained = _explain_lost_transport(
            cmd, inst, start_offset=command_start_offset
        ) or _ssh_255_payload(
            ssh, cmd, inst, start_offset=command_start_offset,
            started_at=started_at, started_mono=started_mono,
        )
        if explained is not None:
            status, data, out, text, notes = _with_guest_output(
                explained, stdout, stderr
            )
            return _guest_result(
                data=data, stdout=out, text=text, notes=notes, stem="dmesg",
                exit_code=status,
            )

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
    if rc != 0:
        data["hint"] = (
            f"dmesg exited {rc} in the guest — see stderr (a non-root SSH user "
            "needs kernel.dmesg_restrict=0); the serial console has the same "
            f"kernel log: qmu log --vm {inst.vm_id} --tail 100"
        )
    if guest_lossy(stdout):
        data["text_lossy"] = True
    if guest_lossy(stderr):
        data["stderr_lossy"] = True
    return _guest_result(
        data=data, stdout=stdout, notes=notes, stem="dmesg",
        exit_code=0 if rc == 0 else 1,
    )


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


def _handle_crash(args: argparse.Namespace) -> Result:
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
    hint: str | None = None
    if detected:
        reason = f"crash report extracted from {scope_reason}"
        text = f"Crash detected in {scope_text}:\n{crash}"
    elif not log_exists:
        reason = "serial log not found"
        text = f"No crash detected in {scope_text}: {reason}."
        if instance_alive(inst):
            # `kill --no-clean` keeps a log when a VM stops; this one went
            # while the VM still runs, so that advice answers nothing (#216).
            hint = (
                f"The serial log {inst.serial_log} is gone although VM "
                f"'{inst.vm_id}' is still running (removed outside qmu); qmu "
                f"status --vm {inst.vm_id} shows what qmu still knows."
            )
        else:
            hint = (
                f"The serial log {inst.serial_log} is gone (pruned, or the cache "
                f"dir changed); qmu status --vm {inst.vm_id} shows what qmu still "
                "knows. Next time keep it with: qmu kill --no-clean"
            )
    else:
        reason = f"no crash markers found in {scope_reason}"
        text = f"No crash detected in {scope_text}: {reason}."
        if history:
            hint = (
                "No Oops/BUG/panic anywhere in the retained log; see what the "
                f"guest did print: qmu log --vm {inst.vm_id} --tail 200"
            )
        else:
            hint = (
                "No report since the current boot. Read the console: qmu log "
                f"--vm {inst.vm_id} --tail 200; a report from an earlier boot "
                f"is still retrievable with: qmu crash --vm {inst.vm_id} "
                "--full-history"
            )

    crash_data = {
        "ok": detected,
        "vm_id": inst.vm_id,
        "crash_detected": detected,
        "scope": scope,
        "reason": reason,
        "serial_log": inst.serial_log,
        "crash": crash,
    }
    if hint is not None:
        crash_data["hint"] = hint
    return Result(
        data=crash_data, text=text, stem="crash", exit_code=0 if detected else 1
    )


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


def _handle_log(args: argparse.Namespace) -> Result:
    # Already gated: cli.main validates the project/explicit config for every
    # non-exempt verb before dispatching (#37).
    inst = find_instance(args.vm)

    # A filtered read defaults to the WHOLE log. Applying the 50-line tail
    # first would silently scope the search to the end of the boot and report
    # "no lines matched" for a pattern that is present — a confident false
    # negative, and exactly wrong for crash triage. An explicit --tail still
    # wins, so the window is narrowable on purpose but never by accident.
    # `--full` is unbounded: the spill path in `render` turns an oversized log
    # into an artifact pointer, so this stays agent-safe.
    whole_log = args.full or (args.grep is not None and args.tail is None)
    tail_lines = 50 if args.tail is None else args.tail

    log = read_log(inst.serial_log) if whole_log else tail_log(inst.serial_log, lines=tail_lines)
    # `available`/`empty` describe the log FILE, never this filtered response:
    # a populated log that `--grep` matched nothing in (or `--tail 0`) said
    # `available: false, empty: true`, and a missing log under `--grep` read
    # as an ordinary no-match (#215). `available` — the file exists and was
    # read; `empty` — it holds no bytes (or is not there to hold any).
    available = log is not None
    empty = not available or (not log and serial_log_offset(inst.serial_log) == 0)
    value = log or ""

    matches: int | None = None
    if args.grep is not None and value:
        value, matches = _grep_lines(value, args.grep, max(0, args.context))

    data = {
        "ok": True,
        "vm_id": inst.vm_id,
        "log": value,
        "available": available,
        "empty": empty,
    }
    if args.grep is not None:
        data["grep"] = args.grep
        data["matches"] = matches or 0
        # State the scope that was actually searched, so a zero-match result is
        # never mistaken for a statement about the whole log.
        data["scope"] = "full" if whole_log else f"last {tail_lines} lines"

    if value:
        text = value
    elif not available:
        text = f"Serial log is missing or unreadable: {inst.serial_log}"
    elif empty:
        text = "Serial log is empty."
    elif args.grep is not None:
        scope = "the serial log" if whole_log else f"the last {tail_lines} lines"
        text = f"No lines in {scope} matched /{args.grep}/."
    else:
        text = f"--tail {tail_lines} selected no lines of the serial log."

    return Result(data=data, text=text, stem="log")
