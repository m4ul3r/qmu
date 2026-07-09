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
import shlex
import time
from pathlib import Path
from typing import Any

from ..instance import QMUError, VMInstance, choose_instance, find_instance
from ..serial import extract_crash, serial_log_offset, tail_log
from ..ssh import SSHClient, SSHError
from .._cliutil import (
    _add_common_opts,
    _emit,
    _make_ssh,
    _preflight_ssh_guest,
    _require_ssh,
)


# ---------------------------------------------------------------------------
# push / pull
# ---------------------------------------------------------------------------


def _add_push(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("push", help="Copy file to guest")
    p.add_argument("local", help="Local file path")
    p.add_argument("remote", nargs="?", default="/root/", help="Remote path (default: /root/)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_push)


def _handle_push(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="push")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    ssh.push(args.local, args.remote)
    _emit(
        args,
        data={"ok": True, "local": args.local, "remote": args.remote},
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
    ssh.pull(args.remote, args.local)
    _emit(
        args,
        data={"ok": True, "local": args.local, "remote": args.remote},
        text=f"Pulled guest:{args.remote} -> {args.local}",
        stem="pull",
    )
    return 0


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


def _add_exec(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("exec", help="Run command in guest")
    p.add_argument("command", nargs="+", help="Command to run")
    p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds")
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


def _emit_ssh_lost(
    args: argparse.Namespace,
    command: str,
    inst: VMInstance,
    *,
    start_offset: int,
) -> int:
    """Emit the SSH-lost / probable-crash envelope and return exit 3.

    Used for both an SSH timeout (TimeoutExpired -> SSHError) and a transport
    disconnect (rc=255 + ssh transport marker), which both mean the guest very
    likely panicked and dropped the connection. Exit 3 distinguishes a
    crash/transport-loss from an ordinary non-zero guest command (exit 1).
    """
    crash = extract_crash(inst.serial_log, start_offset=start_offset)
    # CORR-5: only assert a kernel crash when a crash report was actually
    # extracted; otherwise the connection merely dropped (VM unreachable) and we
    # must not send the agent chasing a phantom panic.
    if crash is not None:
        hint = (
            "SSH connection lost. Kernel may have crashed. "
            "See crash field or run: qmu crash"
        )
        text_msg = f"\nCrash from serial log:\n{crash}"
    else:
        hint = (
            "SSH connection lost; VM may be unreachable. "
            "No crash report in serial log. Check: qmu log --tail 100"
        )
        text_msg = "\nNo crash detected in serial log. Check: qmu log --tail 100"
    result = {
        "ok": False,
        "ssh_error": True,
        "crash_detected": crash is not None,
        "command": command,
        "crash": crash,
        "hint": hint,
    }
    _emit(
        args,
        data=result,
        text=[f"SSH connection lost while running: {command}", text_msg],
        stem="exec",
    )
    return 3


def _join_exec_command(command: list[str]) -> str:
    """Build the guest command string from `qmu exec` positionals.

    A single argument is passed to the guest login shell verbatim, so the
    documented shell forms work: `qmu exec "uname -a"` and
    `qmu exec "cat /proc/slabinfo | grep kmalloc-192"` (pipes/redirects rely on
    the guest shell). Multiple args keep the token-per-arg model via shlex.join:
    `qmu exec grep "two words" f` runs `grep 'two words' f`, not `grep two words f`.
    """
    return command[0] if len(command) == 1 else shlex.join(command)


def _handle_exec(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    if (preflight_rc := _preflight_ssh_guest(args, inst, stem="exec")) is not None:
        return preflight_rc
    ssh = _make_ssh(inst)
    command = _join_exec_command(args.command)

    command_start_offset = serial_log_offset(inst.serial_log)
    try:
        rc, stdout, stderr = ssh.run(command, timeout=args.timeout)
    except SSHError:
        # SSH command exceeded qmu's own timeout — likely a hung/crashed guest.
        return _emit_ssh_lost(
            args, command, inst, start_offset=command_start_offset
        )

    # A kernel panic during the command drops the connection and ssh exits 255 —
    # often with EMPTY stderr (LogLevel=ERROR suppresses the keepalive message),
    # so a stderr-marker test is unreliable. rc=255 is also a legal guest exit
    # code, so disambiguate with an authoritative liveness probe (retried once to
    # avoid a false positive on a busy live guest): if SSH is still unreachable
    # the guest vanished (crash); if it answers, the guest genuinely returned 255
    # and we take the normal path.
    if rc == 255 and _transport_lost(ssh):
        return _emit_ssh_lost(
            args, command, inst, start_offset=command_start_offset
        )

    output_parts = []
    if stdout.strip():
        output_parts.append(stdout.rstrip())
    if stderr.strip():
        output_parts.append(f"[stderr] {stderr.rstrip()}")
    if rc != 0:
        output_parts.append(f"[exit code: {rc}]")
    text = "\n".join(output_parts) if output_parts else f"[exit code: {rc}]"
    # L1: always include ssh_error/crash_detected so consumers have a stable,
    # explicit contract (not an implicit "key omitted on success").
    _emit(
        args,
        data={
            "ok": rc == 0,
            "exit_code": rc,
            "stdout": stdout,
            "stderr": stderr,
            "ssh_error": False,
            "crash_detected": False,
        },
        text=text,
        stem="exec",
    )
    return 0 if rc == 0 else 1


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------


def _add_compile(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("compile", help="Compile C file in guest")
    p.add_argument("source", help="Local C source file")
    p.add_argument("--run", action="store_true", help="Run after compiling")
    p.add_argument("--cflags", default="-static -lpthread", help="Compiler flags")
    p.add_argument("--timeout", type=float, default=60.0, help="Execution timeout")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_compile)


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

    # Push source
    ssh.push(str(source), remote_src)

    # Compile. The remote paths are quoted (a source name with a space or shell
    # metacharacter must not detonate the root shell); --cflags is intentionally
    # left unquoted — it is a list of shell flags.
    compile_cmd = (
        f"gcc {args.cflags} -o {shlex.quote(remote_bin)} {shlex.quote(remote_src)}"
    )
    rc, stdout, stderr = ssh.run(compile_cmd, timeout=30)

    result: dict[str, Any] = {
        "source": str(source),
        "compile_cmd": compile_cmd,
        "compile_exit": rc,
        "compile_stdout": stdout,
        "compile_stderr": stderr,
        # L1: always-present booleans for a stable JSON contract. Updated below
        # if the run path detects a crash/transport loss.
        "ssh_error": False,
        "crash_detected": False,
    }

    if rc != 0:
        result["ok"] = False
        _emit(
            args,
            data=result,
            text=f"Compilation failed:\n{stderr.strip()}",
            stem="compile",
        )
        return 1

    result["compiled"] = True

    if not args.run:
        result["ok"] = True
        _emit(
            args,
            data=result,
            text=f"Compiled {source.name} -> {remote_bin}",
            stem="compile",
        )
        return 0

    # Run (quoted: the binary path is interpolated into a root shell command)
    run_start_offset = serial_log_offset(inst.serial_log)
    try:
        rc, stdout, stderr = ssh.run(shlex.quote(remote_bin), timeout=args.timeout)
        # A kernel panic during the run drops the connection and ssh exits 255
        # (often with empty stderr). rc=255 is also a legal guest exit code, so
        # confirm with a liveness probe (retried once to avoid a false positive
        # on a busy live guest): if SSH still does not answer the guest vanished
        # — raise SSHError so the crash-extraction except-block below handles it
        # uniformly with the timeout case.
        if rc == 255 and _transport_lost(ssh):
            raise SSHError("SSH transport lost (rc=255) — guest likely crashed")
        result.update({
            "ok": rc == 0,
            "run_exit": rc,
            "run_stdout": stdout,
            "run_stderr": stderr,
        })
        lines = [f"Compiled and ran {source.name}:"]
        if stdout.strip():
            lines.append(stdout.rstrip())
        if stderr.strip():
            lines.append(f"[stderr] {stderr.rstrip()}")
        lines.append(f"[exit code: {rc}]")
        _emit(args, data=result, text=lines, stem="compile")
        return 0 if rc == 0 else 1

    except SSHError:
        crash = extract_crash(inst.serial_log, start_offset=run_start_offset)
        result.update({
            "ok": False,
            "ssh_error": True,
            "crash_detected": crash is not None,
            "crash": crash,
        })
        lines = [f"SSH connection lost while running {name}."]
        # CORR-5: only the strong "Kernel may have crashed" wording when a
        # crash report was actually extracted; otherwise report unreachable.
        if crash:
            lines.append(f"\nKernel may have crashed. Crash from serial log:\n{crash}")
        else:
            lines.append(
                "\nSSH connection lost; VM may be unreachable. "
                "No crash report in serial log. Check: qmu log --tail 100"
            )
        _emit(args, data=result, text=lines, stem="compile")
        # Exit 3 = crash/transport-loss (distinct from exit 1 for an ordinary
        # non-zero guest command), consistent with _emit_ssh_lost in exec.
        return 3


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
    rc, stdout, stderr = ssh.run(cmd, timeout=15)

    # L3: honor the guest exit code; do not silently render stderr as if it were
    # the kernel log. The kernel log is stdout; stderr is labelled distinctly.
    if rc == 0:
        text = stdout if stdout.strip() else "(empty dmesg)"
    else:
        text = stdout.rstrip()
        err = stderr.rstrip()
        if err:
            text = (text + "\n" if text else "") + f"[dmesg failed, exit {rc}] {err}"
        elif not text:
            text = f"[dmesg failed, exit {rc}]"
    _emit(
        args,
        data={"ok": rc == 0, "exit_code": rc, "text": stdout, "stderr": stderr},
        text=text,
        stem="dmesg",
    )
    return 0 if rc == 0 else 1


# ---------------------------------------------------------------------------
# crash
# ---------------------------------------------------------------------------


def _add_crash(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("crash", help="Extract crash from serial log")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_crash)


def _handle_crash(args: argparse.Namespace) -> int:
    inst = find_instance(args.vm)
    crash = extract_crash(inst.serial_log)

    # L2: distinguish "serial log missing" from "log present but no crash match"
    # so an agent can tell a dead/never-booted VM apart from a clean run.
    log_exists = Path(inst.serial_log).exists()
    if crash is not None:
        detected = True
        reason = "crash report extracted from serial log"
    elif not log_exists:
        detected = False
        reason = "serial log not found"
    else:
        detected = False
        reason = "no crash markers found in serial log"

    text = crash if crash is not None else f"No crash detected: {reason}."
    _emit(
        args,
        data={
            "ok": detected,
            "detected": detected,
            "reason": reason,
            "serial_log": inst.serial_log,
            "crash": crash,
        },
        text=text,
        stem="crash",
    )

    # L2: non-zero when no crash was found (either missing log or no match).
    return 0 if detected else 1


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------


def _add_log(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("log", help="View serial console log")
    p.add_argument("--tail", type=int, default=50, help="Last N lines (default: 50)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_log)


def _handle_log(args: argparse.Namespace) -> int:
    inst = find_instance(args.vm)
    text = tail_log(inst.serial_log, lines=args.tail)
    _emit(
        args,
        data={"ok": text is not None, "text": text or ""},
        text=text if text else "Serial log is empty or missing.",
        stem="log",
    )
    return 0
