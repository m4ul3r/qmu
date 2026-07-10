"""Shared CLI helpers used by every command module.

This module is the bottom of the CLI dependency DAG:

    cli -> commands.* -> _cliutil -> (config, instance, qmp, output, ssh, ...)

It imports only the qmu domain modules; it never imports ``cli`` or any
``commands.*`` module, so it cannot participate in an import cycle. The command
modules import their shared helpers from here verbatim.
"""

from __future__ import annotations

import argparse
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
    is_pid_alive,
    remove_instance,
)
from .output import write_output_result
from .qmp import QMPClient, QMPError
from .ssh import SSHClient


def _make_ssh(inst: VMInstance) -> SSHClient:
    return SSHClient(port=inst.ssh_port, key_path=inst.ssh_key, user=inst.ssh_user)


def _require_ssh(inst: VMInstance) -> None:
    """Raise QMUError if `inst` has no SSH (harness mode or unconfigured)."""
    if inst.harness or inst.ssh_port is None or inst.ssh_key is None:
        raise QMUError(
            f"VM '{inst.vm_id}' is harness-mode (no SSH). "
            f"Use 'qmu log', 'qmu crash', 'qmu qmp', or 'qmu wait' instead."
        )


def _qmp_ctx(inst: VMInstance) -> QMPClient:
    return QMPClient(inst.qmp_socket)


def _resolve_config_from_args(args: argparse.Namespace) -> QMUConfig:
    """Build a QMUConfig from CLI args, layered over config files."""
    cli_overrides: dict[str, Any] = {}

    # Map CLI flag names to QMUConfig field names
    flag_map = {
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
    """Render output with optional spilling."""
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
        rendered = "\n".join(text) if isinstance(text, list) else text
        _output(rendered, args, stem=stem, source_ok=source_ok)
    else:
        _output(data, args, stem=stem, source_ok=source_ok)


_SSH_BLOCKED_QEMU_STATUSES = frozenset({"paused", "debug"})


def _preflight_ssh_guest(
    args: argparse.Namespace,
    inst: VMInstance,
    *,
    stem: str,
) -> int | None:
    """Fail fast when QMP positively identifies a manual/debugger stop.

    QMP introspection is best-effort. An unavailable QMP socket must not turn an
    otherwise working guest command into a new outage, so transport failures
    return None and preserve the existing SSH path.
    """
    try:
        with _qmp_ctx(inst) as qmp:
            status_result = qmp.execute("query-status")
    except (QMPError, OSError):
        return None

    if not isinstance(status_result, dict):
        return None
    qemu_status = status_result.get("status")
    if not isinstance(qemu_status, str):
        return None
    if qemu_status not in _SSH_BLOCKED_QEMU_STATUSES:
        return None

    hint = (
        f"VM '{inst.vm_id}' is {qemu_status}. "
        f"Resume with: qmu cont --vm {inst.vm_id}. "
        "If a debugger halted the vCPU, use: pry continue."
    )
    _emit(
        args,
        data={
            "ok": False,
            "vm_id": inst.vm_id,
            "qemu_status": qemu_status,
            "ssh_error": False,
            "crash_detected": False,
            "hint": hint,
        },
        text=[
            f"VM '{inst.vm_id}' is {qemu_status}; SSH operation was not started.",
            f"Resume with: qmu cont --vm {inst.vm_id}",
            "Debugger alternative: pry continue",
        ],
        stem=stem,
    )
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
    payload = {
        "ok": False,
        "error": str(exc),
        "error_type": exc.__class__.__name__,
    }
    _output(payload, args, stem="error", source_ok=False)


def _wait_pid_exit(pid: int, timeout: float) -> bool:
    """Poll until `pid` exits or `timeout` elapses. Returns True if it exited.

    Returns immediately when the process is already dead, so callers never
    sleep for a process that has already gone away.
    """
    deadline = time.monotonic() + timeout
    while True:
        if not is_pid_alive(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _kill_vm(inst: VMInstance, force: bool = False, clean: bool = True) -> None:
    """Kill a VM instance: QMP quit → SIGTERM → SIGKILL → optional cleanup.

    With clean=False, the process is terminated but instance files are left
    in place so the caller can still read .serial.log post-mortem.

    Each escalation step only waits while the process is actually still
    alive (poll-with-timeout), so killing an already-dead VM is instant.
    """
    if not force:
        try:
            with _qmp_ctx(inst) as qmp:
                qmp.execute("quit", timeout=5)
        except (QMPError, OSError):
            pass
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
