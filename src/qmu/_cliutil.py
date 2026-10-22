"""Shared CLI helpers used by every command module.

This module is the bottom of the CLI dependency DAG:

    cli -> commands.* -> _cliutil -> (config, instance, qmp, output, ssh, ...)

It imports only the qmu domain modules; it never imports ``cli`` or any
``commands.*`` module, so it cannot participate in an import cycle. The command
modules import their shared helpers from here verbatim.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .config import (
    FORWARD_SPEC_HINT,
    QMUConfig,
    global_config_warnings,
    parse_forward_spec,
    resolve_config,
)
from .instance import (
    QMUError,
    VMInstance,
    autoselected_vm,
    is_pid_alive,
    remove_instance,
)
from .output import release_closed_streams, write_bytes_result, write_output_result
from .qmp import QMPBusyError, QMPClient, QMPError
from . import daemon_client
from .debug import (
    CONT_BEHIND_DEBUGGER,
    ORPHANED_STOP,
    coherence_warnings,
    debugger_resume,
    orphaned_breakpoint_stop,
    orphaned_stop_recovery,
)
from .serial import current_boot_offset, has_terminal_panic
from .ssh import SSHAuthError, SSHClient


def dispatch_warnings() -> tuple[str, ...]:
    """Warnings recorded this dispatch outside any handler's Result.

    The broken-global-config notice (config gate) and a guest reboot the
    VM's debugger was not told about (found while resolving the VM, #184).
    `cli._dispatch` attaches them to the Result; `_emit_error` to the
    failure envelope, so neither is lost to an error path.
    """
    return global_config_warnings() + coherence_warnings()


def _make_ssh(inst: VMInstance) -> SSHClient:
    # `kvm` is the accel recorded at launch; None (a pre-#39 record) is
    # unknown and keeps the KVM-sized probe.
    return SSHClient(
        port=inst.ssh_port, key_path=inst.ssh_key, user=inst.ssh_user,
        emulated=getattr(inst, "kvm", None) is False,
    )


def _ssh_user(inst: Any) -> str | None:
    """The account SSH commands log in as (`[ssh] user`, recorded at launch),
    or None for a VM with no SSH endpoint (harness, --no-net)."""
    if getattr(inst, "harness", False) or getattr(inst, "ssh_port", None) is None:
        return None
    return getattr(inst, "ssh_user", "root")


def forward_label(forward: dict[str, Any]) -> str:
    """`127.0.0.1:12345 -> guest:2345`, one recorded `--forward`."""
    return f"{forward['host']}:{forward['host_port']} -> guest:{forward['guest_port']}"


def _auth_refused_hint(inst: VMInstance) -> str:
    """Recovery for sshd refusing the VM's recorded user/key (#158).

    The account is fixed at launch from `[ssh] user`, so the fix is a
    relaunch; a longer wait or `qmu log` cannot help. A non-root user is
    usually an attempt to run a PoC unprivileged, which `--user` does over
    the root login.
    """
    user = inst.ssh_user
    hint = (
        f"The guest booted and sshd answers, but refuses user '{user}' with "
        f"key {inst.ssh_key}. The user is recorded at launch from [ssh] user: "
        f"qmu kill --vm {inst.vm_id}, fix [ssh] user/key in qmu.toml to an "
        "account the image accepts (root for qmu-built rootfs), then relaunch."
    )
    if user != "root":
        hint += (
            f" To run a command as '{user}', keep root and pass "
            f"--user {user} to qmu exec / compile --run / run."
        )
    return hint


def _auth_refused_error(
    inst: VMInstance, ssh: Any, stderr: str | None = None
) -> SSHAuthError:
    """The SSHAuthError (exit 4) for `inst`, with the relaunch hint and the
    VM's `vm_id` (#196)."""
    exc = ssh.auth_error(stderr)
    exc.hint = _auth_refused_hint(inst)
    exc.vm_id = inst.vm_id
    return exc


def _require_ssh(inst: VMInstance) -> None:
    """Raise QMUError if `inst` has no SSH (harness mode, --no-net, unconfigured)."""
    serial_only = (
        f"qmu log --vm {inst.vm_id} --tail 50; qmu wait --vm {inst.vm_id}; "
        f"qmu crash --vm {inst.vm_id}"
    )
    if inst.harness:
        raise QMUError(
            f"VM '{inst.vm_id}' is harness-mode (no SSH). "
            f"Use 'qmu log', 'qmu crash', 'qmu qmp', or 'qmu wait' instead.",
            hint=serial_only,
        )
    if inst.ssh_port is None:
        # A non-harness VM with no port was launched with --no-net and no
        # --ssh-port: qmu never bound a port, so there is no SSH endpoint.
        raise QMUError(
            f"VM '{inst.vm_id}' was launched with --no-net and no --ssh-port; "
            "it has no SSH endpoint. Relaunch with --ssh-port N and a matching "
            "hostfwd, or without --no-net.",
            hint=f"{serial_only}; or relaunch with --ssh-port N",
        )
    if inst.ssh_key is None:
        raise QMUError(
            f"VM '{inst.vm_id}' has no SSH key recorded (no SSH). "
            f"Use 'qmu log', 'qmu crash', 'qmu qmp', or 'qmu wait' instead.",
            hint=f"{serial_only}; or relaunch with --ssh-key <key>",
        )


def _qmp_ctx(inst: VMInstance) -> Any:
    """The QMP client every handler opens with `with _qmp_ctx(inst) as qmp:`.

    With the daemon layer enabled (`QMU_DAEMON` not `off`) this is a
    :class:`daemon_client.DaemonQMP`: on connect it proxies through the
    daemon's single per-VM connection when the daemon watches the VM, and is
    a plain :class:`QMPClient` on the VM's socket otherwise — same `execute`/
    `execute_hmp`/`greeting_timeout` surface either way, so handlers and the
    tests that patch this name never see the difference. With the layer off
    it is the plain direct client (`daemon_client.StandaloneQMP`), whose busy
    error names a live daemon this process bypasses (#207).
    """
    if not daemon_client.enabled():
        return daemon_client.StandaloneQMP(inst.qmp_socket)
    return daemon_client.DaemonQMP(inst, QMPClient)


def _resolve_config_from_args(args: argparse.Namespace) -> QMUConfig:
    """Build a QMUConfig from CLI args, layered over config files."""
    cli_overrides: dict[str, Any] = {}

    # Map CLI flag names to QMUConfig field names. The [boot] fields are here
    # so a flag and a config key resolve through the same layering — a launch
    # flag beats qmu.toml, and qmu.toml beats the built-in default.
    flag_map = {
        "kernel": "kernel",
        "initrd": "initrd",
        "cmdline": "cmdline",
        "profile": "profile",
        "rootfs": "rootfs",
        "ssh_key": "ssh_key",
        "memory": "memory",
        "cpus": "cpus",
        "cpu_model": "cpu_model",
        "arch": "arch",
        "nic_model": "nic_model",
        # Repeatable: the flag's list replaces [machine] forwards entirely.
        "forwards": "forwards",
    }
    for flag, cfg_field in flag_map.items():
        val = getattr(args, flag, None)
        if val is not None:
            cli_overrides[cfg_field] = val

    # --no-kvm is a boolean launch flag, not a value flag, so it cannot go
    # through flag_map (which copies non-None values). Translate it into the
    # same `accel` config field a `[machine] accel` key sets, so flag-beats-
    # config layering stays uniform: --no-kvm on the CLI overrides accel from
    # qmu.toml, exactly as every other launch flag overrides its config key.
    if getattr(args, "no_kvm", False):
        cli_overrides["accel"] = "tcg"
    # --no-reboot / --reboot likewise: store_true flags whose False default
    # must not shadow `[machine] no_reboot` in qmu.toml, so only a set flag
    # becomes an override — `--reboot` the one that clears a project's
    # `no_reboot = true` for this launch (#151).
    if getattr(args, "no_reboot", False):
        cli_overrides["no_reboot"] = True
    elif getattr(args, "reboot", False):
        cli_overrides["no_reboot"] = False

    config_path = getattr(args, "config", None)
    return resolve_config(
        cli_overrides=cli_overrides or None,
        config_path_override=Path(config_path) if config_path else None,
    )


@dataclass(frozen=True)
class Result:
    """What a handler returns; :func:`render` writes it and yields the exit code.

    `data` is the JSON-mode payload (a dict carrying `ok`, usually). In text
    mode one of three things is written to stdout:

    - `text` — a string, or a list rendered one item per line (strings as-is,
      anything else as compact single-line JSON so a QMP list-of-dicts never
      raises);
    - `raw` — a byte payload written verbatim (no decode, no trailing
      newline), the byte-for-byte promise `exec`/`run`/`dmesg`/`rootfs cat`
      make. Spill/`--out` files are named `<stem>-…<suffix>` and described by
      the usual pointer/envelope whose `ok`/`exit_code` come from `data`;
    - a refusal (`refusal=True`) — `text` lines go to stderr as `[qmu] Error:
      …`, nothing to stdout, so `eval "$(qmu kbase ...)"` never executes prose.

    `notes` follow on stderr in text mode only: `bytes` entries are guest
    stderr, verbatim; `str` entries are qmu's own lines and start on a fresh
    line. `warnings` are stderr text written verbatim after everything else
    in every mode — the follow-up hints and debugger-coherence warnings that
    trail a command's output (so a terminal shows them after the result they
    qualify, and a JSON envelope is never interleaved with them). In json/
    ndjson mode the same lines also ride in the envelope as `warnings: [str]`
    (#74), one list merged with any `warnings` the handler already put in
    `data` (launch's), prefix-stripped and deduplicated. A `silent` Result
    renders nothing in any mode: the handler already wrote what it had
    to (a group's help, an interactive shell, the print-as-you-go skill
    install) and only the exit code remains. A `streamed` Result's text-mode
    stdout payload was already written by the handler as the guest produced
    it (`exec`/`run`/`compile --run` relay output live); render then skips
    stdout and still writes `notes`/`warnings`. Handlers never write stdout
    themselves otherwise: `cli.invoke` returns the Result unrendered (the seam
    for in-process callers) and `cli.main` renders.
    """

    data: Any
    text: str | list[Any] | None = None
    stem: str = "qmu"
    exit_code: int = 0
    raw: bytes | None = None
    suffix: str = ".bin"
    notes: tuple[str | bytes, ...] = ()
    warnings: tuple[str, ...] = ()
    refusal: bool = False
    silent: bool = False
    streamed: bool = False

    @classmethod
    def silent_exit(cls, exit_code: int) -> Result:
        return cls(data=None, exit_code=exit_code, silent=True)

    def warn(self, *lines: str) -> Result:
        """This Result with `lines` appended to its trailing stderr text."""
        return replace(self, warnings=self.warnings + lines)


def _output(
    value: Any,
    args: argparse.Namespace,
    stem: str = "qmu",
    *,
    source_ok: bool | None = None,
) -> None:
    """Render output with optional spilling.

    A dict payload emitted after an auto-selection carries `autoselected:
    true`, so the JSON reader learns which VM the command acted on without
    every handler plumbing the fact (the stderr note covers text mode).
    """
    if isinstance(value, dict) and autoselected_vm() is not None:
        value = {**value, "autoselected": True}
    fmt = getattr(args, "format", "text")
    out = getattr(args, "out", None)
    out_path = Path(out) if out else None
    result = write_output_result(
        value,
        fmt=fmt,
        out_path=out_path,
        stem=stem,
        source_ok=source_ok,
    )
    sys.stdout.write(result.rendered)
    if result.spilled:
        sys.stderr.write(f"[qmu] Output spilled to {result.artifact['artifact_path']}\n")


def _write_bytes(args: argparse.Namespace, result: Result) -> None:
    """Text-mode delivery of `result.raw` on stdout, verbatim.

    Inline output goes to `sys.stdout.buffer` untouched; a payload over the
    spill budget, or `--out`, is written to the file exactly and described by
    the usual pointer/envelope, so the artifact is checksum-comparable with
    what the guest wrote. The envelope's `ok` is the outcome of the operation
    that produced the bytes (`data["ok"]`), never "the file got written" —
    with `data["exit_code"]` alongside when known, so a failed guest command
    looks failed in text `--out`/spill exactly as it does in JSON `--out`.
    """
    raw = result.raw
    data = result.data if isinstance(result.data, dict) else {}
    exit_code = data.get("exit_code")
    out = getattr(args, "out", None)
    written = write_bytes_result(
        raw,
        out_path=Path(out) if out else None,
        stem=result.stem,
        suffix=result.suffix,
        source_ok=bool(data.get("ok", False)),
        exit_code=exit_code if isinstance(exit_code, int) else None,
    )
    if written.artifact is None:
        sys.stdout.flush()
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return
    sys.stdout.write(written.rendered)
    if written.spilled:
        sys.stderr.write(f"[qmu] Output spilled to {written.artifact['artifact_path']}\n")


def _write_notes(notes: tuple[str | bytes, ...]) -> None:
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


_WARNING_PREFIXES = ("[qmu] WARNING: ", "[qmu] Warning: ", "[qmu] ")


def envelope_warning(line: str) -> str:
    """A stderr warning line as it appears in the envelope's `warnings[]`.

    The `[qmu] Warning:` dressing is for a terminal; the envelope entry is
    the message itself, which is what launch already recorded in its own
    `data["warnings"]` before this list existed.
    """
    text = line.rstrip("\n")
    for prefix in _WARNING_PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def _with_envelope_warnings(data: Any, warnings: tuple[str, ...]) -> Any:
    """`data` with `warnings[]` merged: the handler's own list, then the
    Result's stderr lines, in order, without duplicates."""
    if not isinstance(data, dict):
        return data
    existing = data.get("warnings")
    merged: list[str] = list(existing) if isinstance(existing, list) else []
    for line in warnings:
        entry = envelope_warning(line)
        if entry not in merged:
            merged.append(entry)
    if not merged and existing is None:
        return data
    return {**data, "warnings": merged}


def render(args: argparse.Namespace, result: Result) -> int:
    """Write a handler's :class:`Result` through the one ``--format`` fork.

    In text mode the ``text`` payload (or ``raw`` bytes, or a refusal to
    stderr) is rendered; otherwise the ``data`` payload is rendered. Both paths
    funnel into :func:`_output`, so spilling / file-out behavior is uniform.
    ``format`` is read defensively so leaf commands that use
    ``_add_format_opts`` (which may leave the attribute unset before defaults)
    behave as ``getattr(args, "format", "text")``. Returns the exit code.

    A reader that closed stdout or stderr (`qmu … | head -1`) drops the rest
    of that stream and the exit code stays the operation's (#208): it used
    to escape as `[qmu] Error: [Errno 32] Broken pipe`, exit 4, after the
    command had succeeded.
    """
    try:
        if not result.silent:
            _write_result(args, result)
        for line in result.warnings:
            sys.stderr.write(line)
        sys.stdout.flush()
        sys.stderr.flush()
    except BrokenPipeError:
        if not release_closed_streams():
            raise
    return result.exit_code


# Every `{"ok": false}` envelope carries a `hint` (#74, #120). Handlers set a
# result-specific one in `data` at the producer; this is the backstop for a
# producer that did not, so a reader is never left with no recovery at all.
# It is deliberately neutral (no `qmu doctor`: most failed Results are guest/
# caller conditions doctor does not check) and a test pins that the known
# producers do NOT rely on it.
_BACKSTOP_HINT = "qmu status --vm {vm}; qmu log --vm {vm} --tail 50"


def _with_backstop_hint(data: Any, args: argparse.Namespace) -> Any:
    if (
        isinstance(data, dict)
        and data.get("ok") is False
        and not data.get("hint")
    ):
        return {**data, "hint": _BACKSTOP_HINT.format(vm=_vm_for_hint(args))}
    return data


def _write_result(args: argparse.Namespace, result: Result) -> None:
    data = result.data
    source_ok = (
        data["ok"]
        if isinstance(data, dict) and isinstance(data.get("ok"), bool)
        else None
    )
    if getattr(args, "format", "text") != "text":
        data = _with_backstop_hint(
            _with_envelope_warnings(data, result.warnings), args
        )
        _output(data, args, stem=result.stem, source_ok=source_ok)
        return
    if result.refusal:
        first, *rest = result.text
        sys.stderr.write(f"[qmu] Error: {first}\n")
        for line in rest:
            sys.stderr.write(f"[qmu] {line}\n")
    elif result.streamed:
        pass  # stdout already written as the guest produced it
    else:
        try:
            if result.raw is not None:
                _write_bytes(args, result)
            else:
                _write_text(args, result, source_ok)
            sys.stdout.flush()
        except BrokenPipeError:
            # stdout's reader left; the stderr notes (`[exit code: N]`, the
            # crash narrative) still belong to a reader that is there.
            if not release_closed_streams():
                raise
    _write_notes(result.notes)


def _write_text(args: argparse.Namespace, result: Result, source_ok: bool | None) -> None:
    text = result.text
    rendered = (
        "\n".join(
            item
            if isinstance(item, str)
            else json.dumps(item, separators=(",", ":"))
            for item in text
        )
        if isinstance(text, list)
        else text
    )
    _output(rendered, args, stem=result.stem, source_ok=source_ok)


def _refusal(*, data: dict[str, Any], text: list[str], stem: str) -> Result:
    """An operational refusal: JSON envelope on stdout, text on stderr.

    A refusal is prose about why nothing ran, not a result. In text mode it
    must not land on stdout: `eval "$(qmu kbase ...)"` executed the refusal
    as shell commands (`VM: command not found`), destroying the message and
    leaving `KBASE` unset. The skill's text contract — errors print
    `[qmu] Error: ...` to stderr — applies to every refusal path, so the
    stdout of a text-mode command stays eval-/pipe-safe. Exit 1.
    """
    return Result(data=data, text=text, stem=stem, exit_code=1, refusal=True)


def _qmp_stopped_status(inst: VMInstance) -> str | None:
    """QEMU's status string when QMP positively says the vCPUs are not running.

    Keyed on `running: false`, not on a list of status names: `paused` and
    `debug` are the common ones, but a failed `loadvm` leaves `restore-vm`,
    and `prelaunch`/`inmigrate`/`postmigrate` are just as unreachable over
    SSH. Every one of them is what `qmu status` calls `paused`, and a gate
    that recognised two of them sent the rest down a 15–30 s SSH failure in
    the transport class. Returns None when QMP cannot be asked or says the
    guest runs — introspection is best-effort and must never become a new
    outage for a working guest.
    """
    try:
        with _qmp_ctx(inst) as qmp:
            status_result = qmp.execute("query-status")
    except (QMPError, OSError):
        return None
    if not isinstance(status_result, dict):
        return None
    running = status_result.get("running")
    qemu_status = status_result.get("status")
    if running is True:
        return None
    if running is False:
        return qemu_status if isinstance(qemu_status, str) else "paused"
    # No `running` boolean: fall back to the status name. QEMU's only running
    # RunState is "running"; every other name is a stopped vCPU.
    if isinstance(qemu_status, str) and qemu_status != "running":
        return qemu_status
    return None


def _stopped_guest_payload(
    inst: VMInstance, qemu_status: str
) -> tuple[dict[str, Any], list[str]]:
    """The (data, text) pair for a vCPU-halted guest, shared by every reporter.

    Used before an SSH command starts (preflight) and after one lost its
    transport mid-flight (a breakpoint fired while `exec` was running), so
    both tell the same story and name the same recovery.

    `restore-vm` is the one halt `qmu cont` must NOT be the answer to: QEMU
    is left in it by a `snapshot load` that failed mid-restore (#87), with
    the disk rewound and the devices not, and continuing that machine is
    the inconsistent resume the failed load refused to perform. The recovery
    is another load of a known-good snapshot, or kill and relaunch.

    A stop a debugger holds (`debug.debugger_resume`: a gdbstub stop, or the
    `qmu gdb` bridge's attach/interrupt) leads with the debugger's resume:
    `qmu cont` there runs the guest with every breakpoint lifted and leaves
    GDB believing it stopped, so its next command halts the guest again (#225).
    A gdbstub stop with no client on the stub is an orphaned breakpoint
    (`debug.orphaned_breakpoint_stop`): `qmu cont` re-runs its trap and the
    vCPU halts again at once, and attaching a debugger is what clears it (#237).
    """
    resume = debugger_resume(inst, qemu_status)
    if qemu_status == "restore-vm":
        recovery = (
            f"qmu snapshot load <known-good> --vm {inst.vm_id}, or "
            f"qmu kill --vm {inst.vm_id} and relaunch"
        )
        hint = (
            f"VM '{inst.vm_id}' is restore-vm: the last snapshot load failed "
            "mid-restore, so the machine state is inconsistent. Do not resume it. "
            f"Recover with: {recovery}."
        )
        text = [
            f"VM '{inst.vm_id}' is restore-vm (vCPU halted): the last snapshot "
            "load failed mid-restore; the machine state is inconsistent.",
            f"Recover with: {recovery}",
            "Do not: qmu cont (resumes a rewound disk under un-restored devices)",
        ]
    elif resume is not None:
        command, gloss = resume
        hint = (
            f"VM '{inst.vm_id}' is {qemu_status}: a debugger holds this stop. "
            f"Resume with: {command}{gloss}. Not qmu cont --vm {inst.vm_id}: "
            f"{CONT_BEHIND_DEBUGGER}."
        )
        text = [
            f"VM '{inst.vm_id}' is {qemu_status} (vCPU halted by a debugger).",
            f"Resume with: {command}{gloss}",
            f"Do not: qmu cont --vm {inst.vm_id} "
            f"({CONT_BEHIND_DEBUGGER.removeprefix('`qmu cont` ')})",
        ]
    elif orphaned_breakpoint_stop(inst, qemu_status):
        recovery = orphaned_stop_recovery(inst)
        hint = (
            f"VM '{inst.vm_id}' is {qemu_status}: {ORPHANED_STOP}, and no "
            f"debugger is attached to its stub. Not qmu cont --vm {inst.vm_id}: "
            "it re-runs the trap and the vCPU halts again at once. "
            f"{recovery[0].upper()}{recovery[1:]}."
        )
        text = [
            f"VM '{inst.vm_id}' is {qemu_status} (vCPU {ORPHANED_STOP}; no "
            "debugger attached).",
            f"Clear it: {recovery.removeprefix('attach a debugger to clear it: ')}",
            f"Do not: qmu cont --vm {inst.vm_id} (it re-runs the trap; the vCPU "
            "halts again at once)",
        ]
    else:
        hint = (
            f"VM '{inst.vm_id}' is {qemu_status}. "
            f"Resume with: qmu cont --vm {inst.vm_id}. "
            "If a debugger halted the vCPU, use: pry continue."
        )
        text = [
            f"VM '{inst.vm_id}' is {qemu_status} (vCPU halted).",
            f"Resume with: qmu cont --vm {inst.vm_id}",
            "Debugger alternative: pry continue",
        ]
    data: dict[str, Any] = {
        "ok": False,
        "vm_id": inst.vm_id,
        "guest_state": "paused",
        "qemu_status": qemu_status,
        "ssh_error": False,
        "crash_detected": False,
        "hint": hint,
    }
    return data, text


def _panicked_guest_payload(inst: VMInstance) -> tuple[dict[str, Any], list[str]]:
    """The (data, text) pair for a guest whose current boot took a terminal panic."""
    hint = (
        f"VM '{inst.vm_id}' guest is PANICKED: a terminal kernel panic predates "
        f"this command, so nothing can run until relaunch. "
        f"Read it with: qmu crash --vm {inst.vm_id}; then reap with: "
        f"qmu kill --vm {inst.vm_id}"
    )
    data: dict[str, Any] = {
        "ok": False,
        "vm_id": inst.vm_id,
        "guest_state": "panicked",
        "ssh_error": False,
        "crash_detected": False,
        "hint": hint,
    }
    text = [
        f"VM '{inst.vm_id}' guest is PANICKED (terminal kernel panic before "
        "this command); SSH operation was not started.",
        f"Read the report: qmu crash --vm {inst.vm_id}",
        f"Then reap it:    qmu kill --vm {inst.vm_id}",
    ]
    return data, text


def _preflight_ssh_guest(
    inst: VMInstance,
    *,
    stem: str,
) -> Result | None:
    """Fail fast when the guest demonstrably cannot answer SSH.

    Two positive signals, checked in the order `_guest_state` uses:

    - a terminal panic in the current boot scope (the serial log is the
      ground truth; a reboot banner after the panic means a new guest, which
      is NOT refused). Exit 1, not 3: the panic is not fresh for this command,
      and the guest is known gone rather than merely unreachable (4). Without
      this, `exec` on a VM `status` already called PANICKED spent 15–45 s in
      ssh keepalive and reported "no fresh crash" — contradicting `status`.
    - QMP reports the vCPUs are not running (`qmu gdb` halt, a failed
      `loadvm`, a breakpoint): exit 1 with the resume hint.

    QMP introspection is best-effort. An unavailable QMP socket must not turn an
    otherwise working guest command into a new outage, so transport failures
    preserve the existing SSH path. Returns the refusal (exit 1) when it
    refused, else None.
    """
    boot_start = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    if has_terminal_panic(inst.serial_log, start_offset=boot_start):
        data, text = _panicked_guest_payload(inst)
        return _refusal(data=data, text=text, stem=stem)

    qemu_status = _qmp_stopped_status(inst)
    if qemu_status is None:
        return None
    data, text = _stopped_guest_payload(inst, qemu_status)
    return _refusal(data=data, text=text, stem=stem)


# Per-`error_type` recovery hints for `{"ok": false}` envelopes whose exception
# carries no specific `hint` (#74). Keyed on the class name as it appears in
# `error_type`; subclasses fall back through their MRO, and anything else gets
# the catch-all. `{vm}` is the VM the command addressed. The catch-all must
# not promise that `qmu doctor` resolves an operational error — doctor checks
# the host environment, not the guest path or VM state most QMUErrors are
# about — so it names both and says which is which.
_DEFAULT_HINTS: dict[str, str] = {
    "SSHError": (
        "Check the guest: qmu status --vm {vm}; qmu log --vm {vm} --tail 50"
    ),
    "QMPBusyError": (
        "Another client holds QMP (a running `qmu wait`, `qmu gdb` or snapshot "
        "op); retry when it finishes, or check with qmu status --vm {vm}"
    ),
    "QMPTimeoutError": (
        "QEMU did not answer within the budget; check qmu status --vm {vm}, "
        "then retry with a larger --timeout"
    ),
    "QMPError": (
        "Check that the VM is running: qmu status --vm {vm}; if its QMP socket "
        "is gone, qmu prune --vm {vm}"
    ),
    "ConfigError": (
        "qmu config show names the file and key; qmu doctor checks the "
        "resolved config"
    ),
}
_CATCH_ALL_HINT = (
    "qmu status --vm {vm} for VM state; qmu doctor for the host environment"
)


def _vm_for_hint(args: argparse.Namespace) -> str:
    return getattr(args, "vm", None) or autoselected_vm() or "<vm_id>"


def default_hint(error_type: type, args: argparse.Namespace) -> str:
    """The type-default recovery hint for exception class `error_type`."""
    template = next(
        (
            _DEFAULT_HINTS[klass.__name__]
            for klass in error_type.__mro__
            if klass.__name__ in _DEFAULT_HINTS
        ),
        _CATCH_ALL_HINT,
    )
    return template.format(vm=_vm_for_hint(args))


def _emit_error(args: argparse.Namespace, exc: BaseException, text_prefix: str) -> None:
    """Emit an error honoring --format (ERG-1).

    Text mode keeps the existing "[qmu] <prefix> ..." line on stderr, followed
    by `[qmu] Hint: …` only when the exception carries a *specific* hint (and
    the message does not already contain it), so text output stays quiet. When
    the format is not "text", emit the universal error envelope
    {"ok": false, "error": ..., "error_type": ..., "hint": ...} as JSON to
    stdout — `hint` is the exception's own or the `error_type` default, never
    absent. Warnings collected before the failure (`dispatch_warnings`: a
    broken global config, an unannounced guest reboot) trail on stderr in
    every mode and ride in the envelope as `warnings[]`, exactly as they do
    on a successful Result. ``args`` may be partially populated (e.g. if
    argparse failed before defaults were applied), so the format is read
    defensively with getattr().

    The error is real, so the caller's exit code stands when the reader has
    closed the stream it would go to (#208); nothing else is written.
    """
    try:
        _write_error(args, exc, text_prefix)
        sys.stdout.flush()
        sys.stderr.flush()
    except BrokenPipeError:
        if not release_closed_streams():
            raise


def _write_error(args: argparse.Namespace, exc: BaseException, text_prefix: str) -> None:
    fmt = getattr(args, "format", "text") or "text"
    specific = getattr(exc, "hint", None)
    warnings = dispatch_warnings()
    if fmt == "text":
        sys.stderr.write(f"{text_prefix} {exc}\n")
        if specific and specific not in str(exc):
            sys.stderr.write(f"[qmu] Hint: {specific}\n")
        for line in warnings:
            sys.stderr.write(line)
        return
    # Route the error envelope through _output so ndjson renders as one object
    # (output.py), spill/--out handling applies, and source_ok=False stamps the
    # authoritative ok:false — superseding the earlier direct json.dumps path.
    payload: dict[str, Any] = {
        "ok": False,
        "error": str(exc),
        "error_type": exc.__class__.__name__,
    }
    # An exception that carries structured detail (ConfigError: source/key/
    # hint/errors[]) merges it into the envelope; every other error is the
    # three-key shape above.
    payload.update(getattr(exc, "envelope_fields", dict)())
    if payload.get("hint") is None:
        payload["hint"] = specific or default_hint(type(exc), args)
    payload = _with_envelope_warnings(payload, warnings)
    _output(payload, args, stem="error", source_ok=False)
    for line in warnings:
        sys.stderr.write(line)


def _wait_pid_exit(pid: int, timeout: float) -> bool:
    """Poll until `pid` exits or `timeout` elapses. Returns True if it exited.

    Returns immediately when the process is already dead, so callers never
    sleep for a process that has already gone away. A QEMU launched by THIS
    process (`qmu run`) is its child, and a child that has exited stays a
    zombie — `kill(pid, 0)` keeps succeeding — until it is reaped; without the
    `waitpid` every escalation step burned its full budget on a VM that had
    already quit (2 s per `run`). `waitpid` on a pid that is not our child
    raises `ChildProcessError`, which is the common case and ignored.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        if not is_pid_alive(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


# A `quit` that cannot be delivered because another client holds QMP must
# not pay the full greeting timeout: the graceful path is unavailable, and a
# SIGTERM one second from now is strictly better than one three seconds from
# now. Measured before the fix: `kill` during a `wait` took 14 s.
_KILL_GREETING_TIMEOUT = 1.0


def _kill_vm(inst: VMInstance, force: bool = False, clean: bool = True) -> None:
    """Kill a VM instance: QMP quit → SIGTERM → SIGKILL → optional cleanup.

    With clean=False, the process is terminated but instance files are left
    in place so the caller can still read .serial.log post-mortem.

    Each escalation step only waits while the process is actually still
    alive (poll-with-timeout), so killing an already-dead VM is instant. A QMP
    socket held by another client (`QMPBusyError`) skips straight to the
    signal: there is no graceful `quit` to wait for.
    """
    if not force:
        quit_sent = False
        qmp = _qmp_ctx(inst)
        qmp.greeting_timeout = _KILL_GREETING_TIMEOUT
        try:
            with qmp:
                qmp.execute("quit", timeout=5)
                quit_sent = True
        except QMPBusyError:
            pass
        except (QMPError, OSError):
            # `quit` closes the socket from QEMU's side, so a transport error
            # here can still mean the command landed; give it its grace.
            quit_sent = True
        if quit_sent:
            _wait_pid_exit(inst.pid, 1.0)

    if is_pid_alive(inst.pid):
        sig = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.kill(inst.pid, sig)
        except OSError:
            pass  # Died between the liveness check and the signal
        else:
            if not _wait_pid_exit(inst.pid, 1.0):
                try:
                    os.kill(inst.pid, signal.SIGKILL)
                except OSError:
                    pass  # Already dead

    if clean:
        remove_instance(inst.vm_id)


def _make_group_help_handler(group_parser: argparse.ArgumentParser):
    """Return a handler that prints THIS group's own help and exits 2 (ERG-5).

    Group commands (snapshot/config/rootfs/skill) require a sub-action. When
    invoked bare (e.g. `qmu snapshot`) argparse leaves no leaf handler, so
    without this the dispatcher would fall back to TOP-LEVEL help. This handler
    prints the group's help instead and returns the usage exit code (2).
    """

    def _handler(args: argparse.Namespace) -> Result:
        group_parser.print_help(sys.stderr)
        return Result.silent_exit(2)

    return _handler


def _add_top_level_common_opts(parser: argparse.ArgumentParser) -> None:
    """Register --vm/--format/--out on the TOP-LEVEL parser with real defaults.

    These defaults are the ones that actually populate the namespace, so the
    attributes always exist (e.g. for ``qmu --vm X exec``). The subparser copies
    use argparse.SUPPRESS (see _add_common_opts) so they do not clobber a value
    supplied here before the subcommand.
    """
    parser.add_argument("--vm", default=None, help="VM instance ID (auto-selects if only one)")
    parser.add_argument("--format", choices=["text", "json", "ndjson"], default="text")
    parser.add_argument("--out", default=None, help="Write output to file instead of stdout")


def _add_format_opts(parser: argparse.ArgumentParser) -> None:
    """Register --format/--out on a leaf command where --vm is not meaningful
    (version, config init/path). SUPPRESS defaults so a value parsed by the
    top-level parser before the subcommand is preserved (ERG-6)."""
    parser.add_argument(
        "--format", choices=["text", "json", "ndjson"], default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--out", default=argparse.SUPPRESS,
        help="Write output to file instead of stdout",
    )


def _forward_spec_arg(value: str) -> str:
    """argparse `type` for `--forward`: a malformed spec is a usage error
    (exit 2) at parse time; the string is kept so it layers over
    `[machine] forwards` exactly as written."""
    try:
        parse_forward_spec(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{exc}; {FORWARD_SPEC_HINT}") from None
    return value


def _add_launch_opts(parser: argparse.ArgumentParser, *, run_mode: bool = False) -> None:
    """Register the boot-describing flags shared by ``launch`` and ``run``.

    ``run`` boots a VM with exactly the same knobs ``launch`` does, so the two
    parsers are built from one registrar: a flag added to only one of them is the
    "subcommand vs subcommand" divergence the state-agreement matrix exists to
    catch, and it would surface as a boot that silently differs from the launch
    the agent verified by hand.

    ``run_mode`` drops the three flags whose meaning does not survive the
    boot-run-reap composition:

    - ``--harness`` / ``--no-wait-ssh`` — ``run`` executes a guest command over
      SSH, so a mode that guarantees no SSH cannot run one. ``run`` registers
      them itself with a rejecting action, so the attempt is still an argparse
      usage error (exit 2) but one that points at ``launch --harness`` +
      ``wait`` + ``crash``, not a boot that comes up and then reports a
      confusing SSH failure.
    - ``extra`` (trailing QEMU passthrough) — ``run`` spends its positional on
      the guest command instead; two greedy positionals cannot be disambiguated.
      The passthrough returns as the repeatable ``--qemu-arg`` flag, because an
      aarch64/arm guest does not boot without ``-M virt``.
    """
    parser.add_argument("--kernel", default=None,
                        help="Path to bzImage (overrides [boot] kernel in qmu.toml)")
    parser.add_argument("--config", default=None, help="Path to qmu.toml config file")
    parser.add_argument("--rootfs", default=None, help="Path to rootfs image (overrides config)")
    parser.add_argument("--ssh-key", default=None, dest="ssh_key", help="SSH private key (overrides config)")
    parser.add_argument("--arch", default=None, help="Architecture (overrides config, e.g. x86_64, aarch64)")
    parser.add_argument("--memory", default=None, help="VM memory (overrides config)")
    parser.add_argument("--cpus", type=int, default=None, help="VM CPU count (overrides config)")
    parser.add_argument("--cpu", default=None, dest="cpu_model",
                        help="QEMU -cpu model, e.g. 'host', 'max', 'qemu64' (overrides config)")
    parser.add_argument("--profile", default=None,
                        help="Boot profile (default: exploit-dev, or [boot] profile in qmu.toml)")
    parser.add_argument("--cmdline", default=None,
                        help="REPLACE the profile's kernel command line (see --append to extend it)")
    parser.add_argument("--append", default=None,
                        help="Append params to the resolved cmdline instead of replacing it, "
                             "e.g. --append 'slub_debug=- nokaslr'")
    parser.add_argument("--gdb", action="store_true", help="Enable GDB stub")
    parser.add_argument(
        "--no-kvm", dest="no_kvm", action="store_true",
        help="Disable KVM acceleration (force TCG emulation; sets [machine] "
             "accel=tcg). A retest lever for a suspected KVM guest-debug "
             "limitation: if a gdbstub hardware watchpoint does not fire on a "
             "write you can prove happened, suspect a VA alias first, then "
             "retest under TCG. (Measured: a jiffies watchpoint fires under KVM.)",
    )
    parser.add_argument("--name", default=None, help="VM instance name")
    parser.add_argument("--inject", action="append", dest="injects", default=None,
                        help="Copy LOCAL:/guest/dir into the rootfs image before boot "
                             "(repeatable; needs libguestfs)")
    parser.add_argument("--partition", type=int, default=1,
                        help="With --inject: rootfs partition (default 1; use 0 for a "
                             "whole-disk/partitionless image)")
    parser.add_argument("--mkdir", action="store_true",
                        help="With --inject: create the guest directory if missing "
                             "(default: a missing directory is an error, so a typo'd "
                             "path cannot report success)")
    parser.add_argument("--no-replace", action="store_true",
                        help="Don't kill existing VM with same name (default: replace)")
    parser.add_argument("--ssh-port", type=int, default=None, help="SSH port (auto-allocated)")
    parser.add_argument("--gdb-port", type=int, default=None, help="GDB port (auto-allocated)")
    parser.add_argument(
        "--forward", action="append", dest="forwards", default=None,
        type=_forward_spec_arg,
        metavar="[HOST:]HPORT:GPORT",
        help="Forward a host TCP port to a guest port on qmu's own NIC, repeatable "
             "(gdbserver, a service under test). HOST defaults to 127.0.0.1; a bare "
             "GPORT auto-allocates the host port. Recorded on the VM and reported "
             "as `forwards` by launch/status/list. Replaces [machine] forwards.",
    )
    if run_mode:
        ssh_timeout_help = (
            "Seconds to wait for the guest to answer SSH (default: 60). On "
            "expiry `run` reaps the VM and exits 124 (the timeout class); a "
            "guest that panicked first exits 3; an sshd that refuses the "
            "[ssh] user/key exits 4 (SSHAuthError) without waiting it out."
        )
    else:
        ssh_timeout_help = (
            "Seconds to wait for the guest to answer SSH (default: 60). On "
            "expiry `launch` exits 124 (TimeoutError, timed_out: true, "
            "ssh_status 'timeout') and RETAINS the VM for inspection — `qmu "
            "status`/`qmu log --vm <id>` — the same code `run` returns, "
            "which does not retain it. A serial log still empty after ~10 s "
            "of running vCPUs fails "
            "earlier with ssh_status 'no-console-output' (wrong console= or "
            "machine type for this arch); an sshd that refuses the "
            "[ssh] user/key fails with ssh_status 'auth-failed' (exit 4)."
        )
    parser.add_argument("--ssh-timeout", type=int, default=60, help=ssh_timeout_help)
    reboot = parser.add_mutually_exclusive_group()
    reboot.add_argument(
        "--no-reboot", dest="no_reboot", action="store_true",
        help="Pass -no-reboot to QEMU: a kernel panic under `panic=N` exits "
             "QEMU instead of rebooting into a fresh boot that buries the "
             "crash report (boot-and-die harnesses rely on this). Without the "
             "flag the bare word would have to follow `--` as a raw QEMU arg.",
    )
    reboot.add_argument(
        "--reboot", dest="reboot", action="store_true",
        help="Omit -no-reboot even when qmu.toml sets [machine] no_reboot = "
             "true, so a `panic=N` kernel reboots (reboot-behaviour tests).",
    )
    if not run_mode:
        parser.add_argument("--no-wait-ssh", action="store_true", help="Don't wait for SSH to be ready")
    parser.add_argument("--initrd", default=None, help="Path to initramfs/initrd image")
    parser.add_argument("--drive", action="append", dest="drives", default=None,
                        help="QEMU -drive spec, repeatable (suppresses implicit rootfs drive)")
    parser.add_argument("--nic-model", default=None, dest="nic_model",
                        help="NIC model (default: virtio-net-pci)")
    # --no-net stays available on `run`, unlike --harness/--no-wait-ssh. It is
    # not an SSH-less mode: it suppresses qmu's own NIC so a manually supplied
    # one can take over, which is the documented arm32/MMIO topology
    # (--no-net + --qemu-arg=-netdev ...hostfwd + virtio-net-device + a matching
    # --ssh-port). Rejecting it would make that valid configuration unreachable
    # from `run`.
    parser.add_argument("--no-net", action="store_true",
                        help="Disable qmu's own NIC (-nic none). On `run`, supply a "
                             "replacement via --qemu-arg and a matching --ssh-port, "
                             "or the guest will be unreachable.")
    parser.add_argument("--net-backend", default=None, dest="net_backend",
                        choices=["user", "passt"],
                        help="Network backend: 'user' (slirp, default) or 'passt' "
                             "(migration-compatible when the selected QEMU advertises native passt). "
                             "Overrides config.")
    if run_mode:
        # `run` spends its positional on the guest command, so QEMU passthrough
        # has to be flag-carried. It is not optional decoration: an aarch64 or
        # arm guest does not boot without `-M virt`, so without this `run` would
        # be unusable for exactly the cross-arch case it is most useful for.
        # Use the `=` form for values that start with a dash (argparse would
        # otherwise read them as options): --qemu-arg=-M --qemu-arg=virt
        parser.add_argument(
            "--qemu-arg", action="append", dest="extra", default=None, metavar="ARG",
            help="Extra QEMU argument, repeatable. Use the '=' form for values "
                 "starting with a dash: --qemu-arg=-M --qemu-arg=virt",
        )
    else:
        parser.add_argument("--harness", action="store_true",
                            help="Harness/judge VM mode: implies --no-wait-ssh + --no-net; "
                                 "skips rootfs/ssh-key requirement")
        parser.add_argument("extra", nargs="*", help="Extra QEMU arguments")


def _add_common_opts(parser: argparse.ArgumentParser) -> None:
    """Register --vm/--format/--out on a SUBPARSER so the flags also work AFTER
    the subcommand (e.g. ``qmu exec --vm X``).

    Defaults are argparse.SUPPRESS: when these flags are omitted after the
    subcommand, argparse leaves the namespace attribute untouched, preserving
    any value parsed by the top-level parser before the subcommand. The
    top-level defaults (None/"text") guarantee the attributes always exist.
    """
    parser.add_argument(
        "--vm", default=argparse.SUPPRESS,
        help="VM instance ID (auto-selects if only one)",
    )
    parser.add_argument(
        "--format", choices=["text", "json", "ndjson"], default=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--out", default=argparse.SUPPRESS,
        help="Write output to file instead of stdout",
    )
