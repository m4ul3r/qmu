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
from pathlib import Path
from typing import Any

from .config import QMUConfig, resolve_config
from .instance import (
    QMUError,
    VMInstance,
    autoselected_vm,
    is_pid_alive,
    remove_instance,
)
from .output import write_bytes_result, write_output_result
from .qmp import QMPBusyError, QMPClient, QMPError
from .serial import current_boot_offset, has_terminal_panic
from .ssh import SSHClient


def _make_ssh(inst: VMInstance) -> SSHClient:
    return SSHClient(port=inst.ssh_port, key_path=inst.ssh_key, user=inst.ssh_user)


def _require_ssh(inst: VMInstance) -> None:
    """Raise QMUError if `inst` has no SSH (harness mode, --no-net, unconfigured)."""
    if inst.harness:
        raise QMUError(
            f"VM '{inst.vm_id}' is harness-mode (no SSH). "
            f"Use 'qmu log', 'qmu crash', 'qmu qmp', or 'qmu wait' instead."
        )
    if inst.ssh_port is None:
        # A non-harness VM with no port was launched with --no-net and no
        # --ssh-port: qmu never bound a port, so there is no SSH endpoint.
        raise QMUError(
            f"VM '{inst.vm_id}' was launched with --no-net and no --ssh-port; "
            "it has no SSH endpoint. Relaunch with --ssh-port N and a matching "
            "hostfwd, or without --no-net."
        )
    if inst.ssh_key is None:
        raise QMUError(
            f"VM '{inst.vm_id}' has no SSH key recorded (no SSH). "
            f"Use 'qmu log', 'qmu crash', 'qmu qmp', or 'qmu wait' instead."
        )


def _qmp_ctx(inst: VMInstance) -> QMPClient:
    return QMPClient(inst.qmp_socket)


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

    config_path = getattr(args, "config", None)
    return resolve_config(
        cli_overrides=cli_overrides or None,
        config_path_override=Path(config_path) if config_path else None,
    )


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


def _emit(
    args: argparse.Namespace,
    *,
    data: Any,
    text: str | list[str],
    stem: str,
) -> None:
    """Dispatch a handler result through the one ``--format`` fork.

    In text mode the ``text`` payload is rendered (a list is joined with "\n");
    otherwise the ``data`` payload (typically a dict) is rendered. Both paths
    funnel into the existing :func:`_output`, so spilling / file-out behavior is
    unchanged. This collapses the per-handler ``if args.format == "text"`` fork
    into a single place. ``format`` is read defensively so leaf commands that use
    ``_add_format_opts`` (which may leave the attribute unset before defaults)
    behave exactly as the prior ``getattr(args, "format", "text")`` checks.
    """
    source_ok = (
        data["ok"]
        if isinstance(data, dict) and isinstance(data.get("ok"), bool)
        else None
    )
    if getattr(args, "format", "text") == "text":
        # QMP results can be lists of non-strings (e.g. a list of dicts from
        # introspection commands). Render one line per item: strings as-is,
        # anything else (dicts, scalars) as compact single-line JSON so text
        # mode never raises on a list-of-* payload. JSON mode still receives
        # `data` untouched below, so its output is byte-identical.
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
        _output(rendered, args, stem=stem, source_ok=source_ok)
    else:
        _output(data, args, stem=stem, source_ok=source_ok)


def _emit_bytes(args: argparse.Namespace, raw: bytes, *, stem: str) -> None:
    """Text-mode delivery of a byte payload on stdout, verbatim.

    `_emit` renders through `render_value`, which decodes and appends a
    newline, so guest stdout came out as `x\\n` for `printf x` and as U+FFFD
    for a 0xff byte — against the byte-for-byte promise `exec`/`run` make.
    Inline output goes to `sys.stdout.buffer` untouched; a payload over the
    spill budget, or `--out`, is written to the file exactly and described by
    the usual pointer/envelope, so the artifact is checksum-comparable with
    what the guest wrote.
    """
    out = getattr(args, "out", None)
    result = write_bytes_result(
        raw, out_path=Path(out) if out else None, stem=stem, suffix=".txt"
    )
    if result.artifact is None:
        sys.stdout.flush()
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return
    sys.stdout.write(result.rendered)
    if result.spilled:
        sys.stderr.write(f"[qmu] Output spilled to {result.artifact['artifact_path']}\n")


def _emit_refusal(
    args: argparse.Namespace,
    *,
    data: dict[str, Any],
    text: list[str],
    stem: str,
) -> None:
    """Emit an operational refusal: JSON envelope on stdout, text on stderr.

    A refusal is prose about why nothing ran, not a result. In text mode it
    must not land on stdout: `eval "$(qmu kbase ...)"` executed the refusal
    as shell commands (`VM: command not found`), destroying the message and
    leaving `KBASE` unset. The skill's text contract — errors print
    `[qmu] Error: ...` to stderr — applies to every refusal path, so the
    stdout of a text-mode command stays eval-/pipe-safe.
    """
    if getattr(args, "format", "text") == "text":
        first, *rest = text
        sys.stderr.write(f"[qmu] Error: {first}\n")
        for line in rest:
            sys.stderr.write(f"[qmu] {line}\n")
        return
    _emit(args, data=data, text=text, stem=stem)


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
    """
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
    args: argparse.Namespace,
    inst: VMInstance,
    *,
    stem: str,
) -> int | None:
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
    preserve the existing SSH path. Returns the exit status when it refused,
    else None.
    """
    boot_start = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    if has_terminal_panic(inst.serial_log, start_offset=boot_start):
        data, text = _panicked_guest_payload(inst)
        _emit_refusal(args, data=data, text=text, stem=stem)
        return 1

    qemu_status = _qmp_stopped_status(inst)
    if qemu_status is None:
        return None
    data, text = _stopped_guest_payload(inst, qemu_status)
    _emit_refusal(args, data=data, text=text, stem=stem)
    return 1


def _emit_error(args: argparse.Namespace, exc: BaseException, text_prefix: str) -> None:
    """Emit an error honoring --format (ERG-1).

    Text mode keeps the existing "[qmu] <prefix> ..." line on stderr. When the
    format is not "text", emit the universal error envelope
    {"ok": false, "error": ..., "error_type": ...} as JSON to stdout. ``args``
    may be partially populated (e.g. if argparse failed before defaults were
    applied), so the format is read defensively with getattr().
    """
    fmt = getattr(args, "format", "text") or "text"
    if fmt == "text":
        sys.stderr.write(f"{text_prefix} {exc}\n")
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
    _output(payload, args, stem="error", source_ok=False)


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

    def _handler(args: argparse.Namespace) -> int:
        group_parser.print_help(sys.stderr)
        return 2

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
    if run_mode:
        ssh_timeout_help = (
            "Seconds to wait for the guest to answer SSH (default: 60). On "
            "expiry `run` reaps the VM and exits 124 (the timeout class); a "
            "guest that panicked first exits 3."
        )
    else:
        ssh_timeout_help = (
            "Seconds to wait for the guest to answer SSH (default: 60). On "
            "expiry `launch` exits 4 (SSHError) and RETAINS the VM for "
            "inspection — `qmu status`/`qmu log --vm <id>` — unlike `run`, "
            "which exits 124. A serial log still empty after ~10 s fails "
            "earlier with ssh_status 'no-console-output' (wrong console= or "
            "machine type for this arch)."
        )
    parser.add_argument("--ssh-timeout", type=int, default=60, help=ssh_timeout_help)
    parser.add_argument(
        "--no-reboot", dest="no_reboot", action="store_true",
        help="Pass -no-reboot to QEMU: a kernel panic under `panic=N` exits "
             "QEMU instead of rebooting into a fresh boot that buries the "
             "crash report (boot-and-die harnesses rely on this). Without the "
             "flag the bare word would have to follow `--` as a raw QEMU arg.",
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
