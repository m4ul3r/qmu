from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .config import QMUConfig, find_project_config, render_starter_config, resolve_config
from .instance import (
    QMUError,
    VMInstance,
    choose_instance,
    find_instance,
    instance_alive,
    is_pid_alive,
    list_instances,
    list_stopped_instances,
    load_instance,
    remove_instance,
)
from .output import write_output_result
from .paths import (
    all_skill_source_dirs,
    claude_skills_dir,
    codex_home,
    codex_skills_dir,
    global_config_path,
)
from .qmp import QMPClient, QMPError
from . import rootfs as rootfs_mod
from .serial import extract_crash, tail_log
from .snapshot import (
    delete_snapshot,
    list_snapshots,
    load_snapshot,
    save_snapshot,
)
from .ssh import SSHClient, SSHError
from .version import VERSION
from .vm import launch_vm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _output(value: Any, args: argparse.Namespace, stem: str = "qmu") -> None:
    """Render output with optional spilling."""
    fmt = getattr(args, "format", "text")
    out = getattr(args, "out", None)
    out_path = Path(out) if out else None
    result = write_output_result(value, fmt=fmt, out_path=out_path, stem=stem)
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
    if getattr(args, "format", "text") == "text":
        rendered = "\n".join(text) if isinstance(text, list) else text
        _output(rendered, args, stem=stem)
    else:
        _output(data, args, stem=stem)


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
    else:
        sys.stdout.write(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "error_type": exc.__class__.__name__,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )


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


# ---------------------------------------------------------------------------
# launch
# ---------------------------------------------------------------------------


def _add_launch(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("launch", help="Start a QEMU VM")
    p.add_argument("--kernel", required=True, help="Path to bzImage")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.add_argument("--rootfs", default=None, help="Path to rootfs image (overrides config)")
    p.add_argument("--ssh-key", default=None, dest="ssh_key", help="SSH private key (overrides config)")
    p.add_argument("--arch", default=None, help="Architecture (overrides config, e.g. x86_64, aarch64)")
    p.add_argument("--memory", default=None, help="VM memory (overrides config)")
    p.add_argument("--cpus", type=int, default=None, help="VM CPU count (overrides config)")
    p.add_argument("--cpu", default=None, dest="cpu_model",
                   help="QEMU -cpu model, e.g. 'host', 'max', 'qemu64' (overrides config)")
    p.add_argument("--profile", default="exploit-dev", help="Boot profile (default: exploit-dev)")
    p.add_argument("--cmdline", default=None, help="Override kernel command line")
    p.add_argument("--gdb", action="store_true", help="Enable GDB stub")
    p.add_argument("--name", default=None, help="VM instance name")
    p.add_argument("--no-replace", action="store_true",
                   help="Don't kill existing VM with same name (default: replace)")
    p.add_argument("--ssh-port", type=int, default=None, help="SSH port (auto-allocated)")
    p.add_argument("--gdb-port", type=int, default=None, help="GDB port (auto-allocated)")
    p.add_argument("--ssh-timeout", type=int, default=60, help="SSH wait timeout in seconds")
    p.add_argument("--no-wait-ssh", action="store_true", help="Don't wait for SSH to be ready")
    p.add_argument("--initrd", default=None, help="Path to initramfs/initrd image")
    p.add_argument("--drive", action="append", dest="drives", default=None,
                   help="QEMU -drive spec, repeatable (suppresses implicit rootfs drive)")
    p.add_argument("--nic-model", default=None, dest="nic_model",
                   help="NIC model (default: virtio-net-pci)")
    p.add_argument("--no-net", action="store_true",
                   help="Disable networking entirely (-nic none)")
    p.add_argument("--net-backend", default=None, dest="net_backend",
                   choices=["user", "passt"],
                   help="Network backend: 'user' (slirp, default) or 'passt' "
                        "(rootless + migratable, so snapshots work). Overrides config.")
    p.add_argument("--harness", action="store_true",
                   help="Harness/judge VM mode: implies --no-wait-ssh + --no-net; "
                        "skips rootfs/ssh-key requirement")
    p.add_argument("extra", nargs="*", help="Extra QEMU arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_launch)


def _handle_launch(args: argparse.Namespace) -> int:
    config = _resolve_config_from_args(args)

    # Harness mode bundles --no-wait-ssh + --no-net
    if args.harness:
        args.no_wait_ssh = True
        args.no_net = True

    # Replace existing VM with the same name (default behavior)
    if args.name and not args.no_replace:
        existing = load_instance(args.name)
        if existing is not None and instance_alive(existing):
            sys.stderr.write(f"[qmu] Replacing existing VM '{args.name}' (pid={existing.pid})\n")
            _kill_vm(existing)
        elif existing is not None:
            # Stale metadata from dead process — just clean up
            remove_instance(existing.vm_id)

    inst = launch_vm(
        config=config,
        kernel=args.kernel,
        profile=args.profile,
        cmdline=args.cmdline,
        gdb=args.gdb,
        name=args.name,
        ssh_port=args.ssh_port,
        gdb_port=args.gdb_port,
        extra_args=args.extra or None,
        ssh_timeout=args.ssh_timeout,
        initrd=args.initrd,
        drives=args.drives,
        no_net=args.no_net,
        nic_model=args.nic_model,
        net_backend=args.net_backend,
        harness=args.harness,
    )

    if inst.harness or inst.ssh_port is None:
        ssh_status = "n/a (harness)"
    elif not args.no_wait_ssh:
        ssh = _make_ssh(inst)
        sys.stderr.write(f"[qmu] VM launched (pid={inst.pid}). Waiting for SSH on port {inst.ssh_port}...\n")
        if ssh.wait_ready(timeout=args.ssh_timeout):
            ssh_status = "ready"
        else:
            ssh_status = "timeout (VM may still be booting)"
    else:
        ssh_status = "skipped"

    result = {
        "ok": True,
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "ssh_port": inst.ssh_port,
        "ssh_status": ssh_status,
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "profile": inst.profile,
        "serial_log": inst.serial_log,
        "arch": config.arch,
    }

    lines = [
        f"VM '{inst.vm_id}' launched (pid={inst.pid})",
        f"  Arch:    {config.arch}",
    ]
    if inst.harness:
        lines.append(f"  Mode:    harness (no SSH)")
    elif inst.ssh_port is not None:
        lines.append(f"  SSH:     port {inst.ssh_port} ({ssh_status})")
    else:
        lines.append(f"  SSH:     {ssh_status}")
    if inst.gdb_port:
        lines.append(f"  GDB:     port {inst.gdb_port}")
    lines.append(f"  Kernel:  {inst.kernel}")
    lines.append(f"  Profile: {inst.profile}")
    lines.append(f"  Serial:  {inst.serial_log}")
    _emit(args, data=result, text=lines, stem="launch")
    return 0


# ---------------------------------------------------------------------------
# kill
# ---------------------------------------------------------------------------


def _add_kill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("kill", help="Stop a running VM")
    p.add_argument("--force", action="store_true", help="Force kill (SIGKILL)")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata or serial log after kill")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_kill)


def _handle_kill(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _kill_vm(inst, force=args.force, clean=not args.no_clean)
    if args.no_clean:
        msg = f"VM '{inst.vm_id}' stopped. State preserved at {inst.serial_log}"
    else:
        msg = f"VM '{inst.vm_id}' stopped."
    _emit(
        args,
        data={
            "ok": True,
            "vm_id": inst.vm_id,
            "cleaned": not args.no_clean,
            "serial_log": inst.serial_log,
        },
        text=msg,
        stem="kill",
    )
    return 0


# ---------------------------------------------------------------------------
# prune
# ---------------------------------------------------------------------------


def _add_prune(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("prune", help="Remove state files for stopped VMs")
    g = p.add_mutually_exclusive_group()
    # SUPPRESS (like _add_common_opts) so a top-level `--vm X` given before the
    # subcommand is not clobbered by this subparser's own default.
    g.add_argument("--vm", default=argparse.SUPPRESS, help="Prune a specific stopped VM")
    g.add_argument("--all", dest="prune_all", action="store_true",
                   help="Prune every stopped VM")
    p.add_argument("--keep-logs", action="store_true",
                   help="Drop .json + .qmp.sock but preserve .serial.log")
    # _add_common_opts adds --vm too; we declared --vm above so add the rest manually.
    p.add_argument("--format", choices=["text", "json", "ndjson"], default="text")
    p.add_argument("--out", default=None, help="Write output to file instead of stdout")
    p.set_defaults(handler=_handle_prune)


def _handle_prune(args: argparse.Namespace) -> int:
    stopped = list_stopped_instances()
    running = list_instances()
    running_ids = {inst.vm_id for inst in running}

    # SUPPRESS default (fix #2) means the attribute may be absent when --vm is
    # not given after the subcommand; the top-level parser default of None
    # guarantees it otherwise exists.
    vm = getattr(args, "vm", None)
    if vm is not None:
        if vm in running_ids:
            raise QMUError(
                f"VM '{vm}' is running. Use 'qmu kill --vm {vm}' first."
            )
        target = next((inst for inst in stopped if inst.vm_id == vm), None)
        if target is None:
            raise QMUError(f"No stopped VM named '{vm}'.")
        targets = [target]
    elif args.prune_all:
        targets = stopped
    else:
        raise QMUError("Specify either --vm <name> or --all.")

    pruned: list[str] = []
    for inst in targets:
        remove_instance(inst.vm_id, keep_logs=args.keep_logs)
        pruned.append(inst.vm_id)

    if not pruned:
        text = "No stopped VMs to prune."
    else:
        verb = "kept logs for" if args.keep_logs else "removed"
        text = f"Pruned {len(pruned)} VM(s) ({verb}): {', '.join(pruned)}"
    _emit(
        args,
        data={"ok": True, "pruned": pruned, "keep_logs": args.keep_logs},
        text=text,
        stem="prune",
    )
    return 0


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


_STOP_EVENTS = {"STOP", "SHUTDOWN", "POWERDOWN", "RESET"}


def _add_wait(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("wait", help="Block until a VM stops (harness/judge mode)")
    p.add_argument("--timeout", type=float, default=None,
                   help="Max seconds to wait (default: no timeout)")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata after stop (harness VMs only)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_wait)


def _handle_wait(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)

    start = time.monotonic()
    # `is not None` so --timeout 0 means "check once, then time out immediately"
    # rather than being treated as "no timeout".
    deadline: float | None = (start + args.timeout) if args.timeout is not None else None
    reason = "unknown"
    qemu_status = "unknown"
    event_data: Any = None
    stopped = False

    try:
        with _qmp_ctx(inst) as qmp:
            # Short-circuit: query current state first.
            try:
                status = qmp.execute("query-status")
                if isinstance(status, dict):
                    qemu_status = status.get("status", "unknown")
                    if qemu_status in ("paused", "shutdown", "postmigrate", "guest-panicked"):
                        reason = qemu_status
                        stopped = True
            except (QMPError, OSError):
                pass

            # Loop in 1s ticks: wait for an event OR notice the PID died.
            while not stopped:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    tick = min(1.0, remaining)
                else:
                    tick = 1.0

                ev = qmp.wait_event(_STOP_EVENTS, timeout=tick)
                if ev is not None:
                    reason = ev.get("event", "stopped")
                    event_data = ev.get("data")
                    stopped = True
                    break

                if not is_pid_alive(inst.pid):
                    reason = "process_exited"
                    stopped = True
                    break
    except (QMPError, OSError) as exc:
        # If the QMP socket disappeared, the VM almost certainly stopped.
        if not is_pid_alive(inst.pid):
            stopped = True
            reason = "process_exited"
        else:
            raise QMUError(f"QMP error during wait: {exc}") from exc

    elapsed = time.monotonic() - start
    crash = extract_crash(inst.serial_log) if stopped else None

    result = {
        # ok mirrors success: True when the VM actually stopped, False on the
        # timeout result object (exit 124).
        "ok": stopped,
        "vm_id": inst.vm_id,
        "stopped": stopped,
        "reason": reason,
        "elapsed": round(elapsed, 3),
        "event_data": event_data,
        "crash": crash,
    }

    # Auto-clean harness VMs unless --no-clean.
    cleaned = False
    if stopped and inst.harness and not args.no_clean:
        try:
            _kill_vm(inst, force=False)
            cleaned = True
        except QMUError:
            pass
    result["cleaned"] = cleaned

    lines = [
        f"VM '{inst.vm_id}' {'stopped' if stopped else 'still running'} "
        f"({reason}, elapsed={elapsed:.2f}s)"
    ]
    if crash:
        lines.append("\nCrash from serial log:\n" + crash)
    if cleaned:
        lines.append("[qmu] Instance metadata cleaned up.")
    _emit(args, data=result, text=lines, stem="wait")

    if not stopped:
        return 124  # timeout
    return 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _add_list(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="List VMs (running and stopped)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_list)


def _handle_list(args: argparse.Namespace) -> int:
    running = list_instances()
    stopped = list_stopped_instances()
    if not running and not stopped:
        _emit(args, data={"ok": True, "vms": []}, text="No VMs.", stem="list")
        return 0

    if args.format != "text":
        data = []
        for inst in running:
            entry: dict[str, Any] = {
                "vm_id": inst.vm_id,
                "status": "running",
                "pid": inst.pid,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel,
                "profile": inst.profile,
            }
            if inst.harness or inst.ssh_port is None:
                entry["ssh_ready"] = None
            else:
                entry["ssh_ready"] = _make_ssh(inst).is_ready()
            data.append(entry)
        for inst in stopped:
            data.append({
                "vm_id": inst.vm_id,
                "status": "stopped",
                "pid": inst.pid or None,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel or None,
                "profile": inst.profile or None,
                "ssh_ready": None,
                "serial_log": inst.serial_log,
            })
        _output({"ok": True, "vms": data}, args, stem="list")
        return 0

    lines = []
    for inst in running:
        if inst.harness or inst.ssh_port is None:
            ssh_str = "harness"
        else:
            ssh_ok = _make_ssh(inst).is_ready()
            ssh_str = f"ssh={inst.ssh_port}({'ok' if ssh_ok else 'down'})"
        gdb_str = f" gdb={inst.gdb_port}" if inst.gdb_port else ""
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else ""
        lines.append(
            f"  {inst.vm_id}  pid={inst.pid}  {ssh_str}{gdb_str}  "
            f"profile={inst.profile}  {kernel_str}  [running]"
        )
    for inst in stopped:
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else "kernel=?"
        profile_str = f"profile={inst.profile}" if inst.profile else "profile=?"
        lines.append(f"  {inst.vm_id}  {profile_str}  {kernel_str}  [stopped]")
    _output("VMs:\n" + "\n".join(lines), args, stem="list")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _add_status(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("status", help="Detailed VM status")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_status)


def _handle_status(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)

    qmp_ok = False
    qemu_status = "unknown"
    try:
        with _qmp_ctx(inst) as qmp:
            status = qmp.execute("query-status")
            qmp_ok = True
            qemu_status = status.get("status", "unknown") if isinstance(status, dict) else str(status)
    except (QMPError, OSError):
        pass

    if inst.harness or inst.ssh_port is None:
        ssh_state = "n/a (harness)"
        ssh_ok = None
    else:
        ssh_ok = _make_ssh(inst).is_ready()
        ssh_state = "ready" if ssh_ok else "down"

    result = {
        "ok": True,
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "harness": inst.harness,
        "qmp": "connected" if qmp_ok else "unreachable",
        "qemu_status": qemu_status,
        "ssh_port": inst.ssh_port,
        "ssh": ssh_state,
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "rootfs": inst.rootfs,
        "memory": inst.memory,
        "cpus": inst.cpus,
        "profile": inst.profile,
        "cmdline": inst.cmdline,
        "serial_log": inst.serial_log,
        "started_at": inst.started_at,
    }

    lines = [
        f"VM '{inst.vm_id}'",
        f"  PID:       {inst.pid}",
        f"  QMP:       {'connected' if qmp_ok else 'unreachable'}",
        f"  QEMU:      {qemu_status}",
    ]
    if inst.harness or inst.ssh_port is None:
        lines.append(f"  Mode:      harness")
        lines.append(f"  SSH:       n/a")
    else:
        lines.append(f"  SSH:       port {inst.ssh_port} ({ssh_state})")
    if inst.gdb_port:
        lines.append(f"  GDB:       port {inst.gdb_port}")
    lines.extend([
        f"  Kernel:    {inst.kernel}",
        f"  Rootfs:    {inst.rootfs}",
        f"  Memory:    {inst.memory}",
        f"  CPUs:      {inst.cpus}",
        f"  Profile:   {inst.profile}",
        f"  Cmdline:   {inst.cmdline}",
        f"  Serial:    {inst.serial_log}",
        f"  Started:   {inst.started_at}",
    ])
    _emit(args, data=result, text=lines, stem="status")
    return 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def _add_doctor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="Health check")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_doctor)


def _handle_doctor(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )
    checks: list[dict[str, Any]] = []

    # Config sources — distinguish "loaded a file" from "defaults only"
    file_sources = [s for s in config._sources if s.startswith(("global:", "project:", "config:"))]
    if file_sources:
        checks.append({
            "check": "config",
            "status": "ok",
            "detail": " -> ".join(config._sources),
        })
    else:
        checks.append({
            "check": "config",
            "status": "warn",
            "detail": "No qmu.toml or ~/.config/qmu/config.toml found. Run: qmu config init",
        })

    # QEMU binary (arch-aware)
    binary = config.qemu_binary()
    qemu = shutil.which(binary)
    checks.append({
        "check": binary,
        "status": "ok" if qemu else "MISSING",
        "detail": qemu or "Not found in PATH",
    })

    # Rootfs
    if config.rootfs:
        rootfs_resolved = Path(config.rootfs).expanduser()
        rootfs_ok = rootfs_resolved.exists()
        checks.append({
            "check": "rootfs image",
            "status": "ok" if rootfs_ok else "MISSING",
            "detail": config.rootfs,
        })
    else:
        checks.append({
            "check": "rootfs image",
            "status": "not configured",
            "detail": "Set [drive] rootfs in qmu.toml or pass --rootfs (skip for --harness)",
        })

    # SSH key — split existence from permissions
    if config.ssh_key:
        key_path = Path(config.ssh_key).expanduser()
        key_ok = key_path.exists()
        checks.append({
            "check": "SSH key",
            "status": "ok" if key_ok else "MISSING",
            "detail": config.ssh_key,
        })
        if key_ok:
            mode = oct(key_path.stat().st_mode)[-3:]
            if mode in ("600", "400"):
                checks.append({
                    "check": "SSH key permissions",
                    "status": "ok",
                    "detail": f"mode={mode}",
                })
            else:
                checks.append({
                    "check": "SSH key permissions",
                    "status": "warn",
                    "detail": f"mode={mode} (should be 600 — `chmod 600 {config.ssh_key}`)",
                })
    else:
        checks.append({
            "check": "SSH key",
            "status": "not configured",
            "detail": "Set [ssh] key in qmu.toml or pass --ssh-key (skip for --harness)",
        })

    # KVM
    if config.use_kvm():
        checks.append({
            "check": "KVM",
            "status": "ok",
            "detail": "KVM acceleration available",
        })
    else:
        checks.append({
            "check": "KVM",
            "status": "info",
            "detail": f"Not available for arch={config.arch} (will use TCG)",
        })

    # pry (optional — only needed for `qmu gdb`)
    pry = shutil.which("pry")
    checks.append({
        "check": "pry (GDB integration)",
        "status": "ok" if pry else "info",
        "detail": pry or "Not found in PATH — required only for `qmu gdb`. "
                         "Install pry and ensure it is on PATH.",
    })

    # passt (required only when net_backend = "passt"; enables snapshots)
    passt = shutil.which("passt")
    passt_required = config.net_backend == "passt"
    checks.append({
        "check": "passt (net_backend=passt)",
        "status": ("ok" if passt else "MISSING") if passt_required else "info",
        "detail": passt or (
            "Not found in PATH — REQUIRED because net_backend=passt. "
            "Install passt (e.g. 'pacman -S passt' / 'apt install passt')."
            if passt_required else
            "Not found — only needed if you set net_backend=passt "
            "(rootless backend that makes snapshots work)."
        ),
    })

    # Running instances
    instances = list_instances()
    checks.append({
        "check": "running VMs",
        "status": "ok",
        "detail": f"{len(instances)} instance(s)",
    })

    # Skills installed — check all skills in each install root
    skill_names = [d.name for d in all_skill_source_dirs()]
    if not skill_names:
        skill_names = ["qmu"]
    roots = [claude_skills_dir()]
    if codex_home().is_dir():
        roots.append(codex_skills_dir())
    installed: list[Path] = []
    missing: list[Path] = []
    for name in skill_names:
        for root in roots:
            p = root / name
            (installed if p.exists() else missing).append(p)
    if not missing:
        checks.append({
            "check": "skills",
            "status": "ok",
            "detail": ", ".join(str(p) for p in installed),
        })
    elif installed:
        checks.append({
            "check": "skills",
            "status": "warn",
            "detail": f"partial: {len(installed)} installed, {len(missing)} missing (run: qmu skill install)",
        })
    else:
        checks.append({
            "check": "skills",
            "status": "not installed",
            "detail": "Run: qmu skill install",
        })

    healthy = ("ok", "info")
    all_ok = all(c["status"] in healthy for c in checks)
    lines = ["qmu doctor:"]
    for c in checks:
        if c["status"] in healthy:
            mark = "+"
        elif c["status"] == "warn":
            mark = "~"
        else:
            mark = "!"
        lines.append(f"  [{mark}] {c['check']}: {c['detail']}")
    if not file_sources and config.rootfs is None and config.ssh_key is None:
        lines.append("")
        lines.append("Tip: run `qmu config init` to create a starter qmu.toml in this directory.")
    _emit(args, data={"ok": all_ok, "checks": checks}, text=lines, stem="doctor")

    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _add_config(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("config", help="Manage qmu configuration")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="config_cmd")

    s = sp.add_parser("show", help="Show resolved configuration")
    s.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_config_show)

    s = sp.add_parser("init", help="Create a starter qmu.toml in current directory")
    _add_format_opts(s)
    s.set_defaults(handler=_handle_config_init)

    s = sp.add_parser("path", help="Show config file search paths")
    _add_format_opts(s)
    s.set_defaults(handler=_handle_config_path)


def _handle_config_show(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )

    data = {
        "ok": True,
        "sources": config._sources,
        "machine": {
            "arch": config.arch,
            "memory": config.memory,
            "cpus": config.cpus,
            "cpu_model": config.cpu_model,
            "qemu_binary": config.qemu_binary(),
            "kvm": config.use_kvm(),
            "extra_args": config.extra_args,
        },
        "drive": {
            "rootfs": config.rootfs,
            "format": config.drive_format,
        },
        "ssh": {
            "key": config.ssh_key,
            "user": config.ssh_user,
            "port_start": config.ssh_port_start,
        },
        "gdb": {
            "port_start": config.gdb_port_start,
        },
        "profiles": config.profiles,
    }

    lines = ["Resolved qmu config:"]
    lines.append(f"  Sources: {' -> '.join(config._sources)}")
    lines.append(f"  Arch:        {config.arch} ({config.qemu_binary()})")
    lines.append(f"  KVM:         {config.use_kvm()}")
    lines.append(f"  Memory:      {config.memory}")
    lines.append(f"  CPUs:        {config.cpus}")
    lines.append(f"  CPU model:   {config.cpu_model or '(qemu default)'}")
    lines.append(f"  Rootfs:      {config.rootfs or '(not set)'}")
    lines.append(f"  Drive fmt:   {config.drive_format}")
    lines.append(f"  SSH key:     {config.ssh_key or '(not set)'}")
    lines.append(f"  SSH user:    {config.ssh_user}")
    lines.append(f"  SSH port:    {config.ssh_port_start}+")
    lines.append(f"  GDB port:    {config.gdb_port_start}+")
    if config.extra_args:
        lines.append(f"  Extra args:  {' '.join(config.extra_args)}")
    lines.append(f"  Profiles:    {', '.join(config.profiles.keys())}")
    _emit(args, data=data, text=lines, stem="config-show")
    return 0


def _handle_config_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / "qmu.toml"
    # ERG-7: `config init` is idempotent — an existing file is a benign no-op
    # (exit 0), not a failure. The file is never overwritten.
    if target.exists():
        msg = f"{target} already exists, not overwritten"
        _emit(
            args,
            data={"ok": True, "path": str(target), "created": False, "message": msg},
            text=msg,
            stem="config-init",
        )
        return 0
    target.write_text(render_starter_config())
    _emit(
        args,
        data={"ok": True, "path": str(target), "created": True},
        text=f"Created {target}",
        stem="config-init",
    )
    return 0


def _handle_config_path(args: argparse.Namespace) -> int:
    gpath = global_config_path()
    ppath = find_project_config()
    lines = [
        f"Global config:  {gpath} ({'exists' if gpath.is_file() else 'not found'})",
        f"Project config: {ppath or '(none found — searched up from CWD)'}",
    ]
    _emit(
        args,
        data={
            "ok": True,
            "global_config": str(gpath),
            "global_config_exists": gpath.is_file(),
            "project_config": str(ppath) if ppath else None,
        },
        text=lines,
        stem="config-path",
    )
    return 0


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def _add_snapshot(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("snapshot", help="VM snapshot management")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="snapshot_cmd")

    s = sp.add_parser("save", help="Save a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_save)

    s = sp.add_parser("load", help="Load a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_load)

    s = sp.add_parser("list", help="List snapshots")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_list)

    s = sp.add_parser("delete", help="Delete a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_delete)


# HMP error markers that indicate a snapshot operation actually failed.
# Deliberately specific so benign savevm slirp *warnings* (e.g. "warning: Slirp:
# Save of field ... failed") are NOT treated as hard failures — those lines
# begin with "warning:" and contain none of the markers below, so save still
# exits 0.
_SNAPSHOT_ERROR_MARKERS = (
    "Error:",
    "Missing section footer",
    "Section footer error",
    "does not support",
    "Could not open",
    "No block device",
)


def _snapshot_failed(msg: str) -> bool:
    return any(m in msg for m in _SNAPSHOT_ERROR_MARKERS)


def _handle_snapshot_save(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = save_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-save",
    )
    if failed:
        # savevm stores *internal* snapshots, which QEMU can only write into a
        # writable qcow2 disk. The default implicit rootfs drive is
        # format=raw,snapshot=on (see vm.py): raw images cannot hold internal
        # snapshots, and the snapshot=on overlay is a throwaway that savevm
        # refuses too. Give the actionable requirement rather than the raw HMP
        # error (mirrors the load handler's hint).
        sys.stderr.write(
            f"[qmu] snapshot save failed: {msg}\n"
            "[qmu] `savevm` requires a writable qcow2 rootfs disk to store "
            "internal snapshots; the default format=raw image (and any "
            "snapshot=on overlay) cannot hold them. Rebuild/convert the rootfs "
            "to qcow2 (e.g. `qemu-img convert -O qcow2 rootfs.img rootfs.qcow2`), "
            "set [drive] format = \"qcow2\", and launch with net_backend=passt "
            "(not the default slirp) so the saved state round-trips.\n"
        )
        return 1
    return 0


def _handle_snapshot_load(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = load_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-load",
    )
    if failed:
        sys.stderr.write(
            f"[qmu] snapshot load failed: {msg}\n"
            "[qmu] The VM was NOT restored. With the default -net user (slirp) "
            "networking, savevm/loadvm cannot serialize NIC state; relaunch the "
            "VM instead of relying on snapshot restore.\n"
        )
        return 1
    return 0


def _handle_snapshot_list(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        snaps = list_snapshots(qmp)
    if not snaps:
        text: str | list[str] = "No snapshots."
    else:
        lines = ["Snapshots:"]
        for s in snaps:
            lines.append(f"  {s['id']}  {s['tag']}  size={s['vm_size']}  {s['date']} {s['time']}")
        text = lines
    _emit(args, data={"ok": True, "snapshots": snaps}, text=text, stem="snapshot-list")
    return 0


def _handle_snapshot_delete(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = delete_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-delete",
    )
    if failed:
        sys.stderr.write(f"[qmu] snapshot delete failed: {msg}\n")
        return 1
    return 0


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


def _emit_ssh_lost(args: argparse.Namespace, command: str, inst: VMInstance) -> int:
    """Emit the SSH-lost / probable-crash envelope and return exit 3.

    Used for both an SSH timeout (TimeoutExpired -> SSHError) and a transport
    disconnect (rc=255 + ssh transport marker), which both mean the guest very
    likely panicked and dropped the connection. Exit 3 distinguishes a
    crash/transport-loss from an ordinary non-zero guest command (exit 1).
    """
    crash = extract_crash(inst.serial_log)
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
    ssh = _make_ssh(inst)
    command = _join_exec_command(args.command)

    try:
        rc, stdout, stderr = ssh.run(command, timeout=args.timeout)
    except SSHError:
        # SSH command exceeded qmu's own timeout — likely a hung/crashed guest.
        return _emit_ssh_lost(args, command, inst)

    # A kernel panic during the command drops the connection and ssh exits 255 —
    # often with EMPTY stderr (LogLevel=ERROR suppresses the keepalive message),
    # so a stderr-marker test is unreliable. rc=255 is also a legal guest exit
    # code, so disambiguate with an authoritative liveness probe (retried once to
    # avoid a false positive on a busy live guest): if SSH is still unreachable
    # the guest vanished (crash); if it answers, the guest genuinely returned 255
    # and we take the normal path.
    if rc == 255 and _transport_lost(ssh):
        return _emit_ssh_lost(args, command, inst)

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
        crash = extract_crash(inst.serial_log)
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


# ---------------------------------------------------------------------------
# gdb
# ---------------------------------------------------------------------------


def _add_gdb(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "gdb",
        help="Connect pry (headless GDB bridge) to the VM's GDB stub; "
             "non-interactive, does not open a debugger session",
    )
    p.add_argument("--symbols", default=None, help="Path to vmlinux with debug symbols")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_gdb)


def _handle_gdb(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    if inst.gdb_port is None:
        raise QMUError(
            "VM was launched without --gdb. Relaunch with: qmu launch --gdb --kernel ..."
        )

    pry = shutil.which("pry")
    if not pry:
        raise QMUError("pry not found in PATH. Install pry and ensure it is on PATH.")

    cmd = ["pry", "launch", "--connect", f"localhost:{inst.gdb_port}"]
    if args.symbols:
        cmd.extend(["--symbols", str(Path(args.symbols).expanduser().resolve())])

    # `pry launch` is non-interactive: it spins up a headless GDB + bridge in the
    # background, connects to the stub, and returns — it does NOT hand back an
    # interactive debugger session. So capturing output and capping at 15s (pry's
    # own bridge-start wait defaults to 10s) is correct; the agent drives the
    # halted session afterwards via the `pry` CLI.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if result.returncode == 0:
        # H4: attaching to the gdb stub HALTS the vCPU. If the agent does not
        # resume it, every subsequent exec/push/pull/compile will hang and fail
        # with an ambiguous transport timeout. Warn loudly and tell them how to
        # resume.
        warning = (
            "WARNING: the vCPU is now HALTED by the debugger. SSH (exec/push/"
            "pull/compile) will hang until you resume it. Resume with `pry "
            "continue` (in the debugger) or `qmu cont`."
        )
        _emit(
            args,
            data={
                "ok": True,
                "vm_id": inst.vm_id,
                "gdb_port": inst.gdb_port,
                "cpu_state": "halted",
                "warning": warning,
            },
            text=f"pry connected to VM '{inst.vm_id}' GDB stub on port "
            f"{inst.gdb_port}\n{warning}",
            stem="gdb",
        )
    else:
        output = result.stderr.strip() or result.stdout.strip()
        _emit(
            args,
            data={"ok": False, "error": output},
            text=f"pry launch failed: {output}",
            stem="gdb",
        )
        return 1
    return 0


# ---------------------------------------------------------------------------
# cont (resume a halted vCPU)
# ---------------------------------------------------------------------------


def _add_cont(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "cont",
        help="Resume a vCPU halted by the debugger (issues QMP cont)",
    )
    _add_common_opts(p)
    p.set_defaults(handler=_handle_cont)


def _handle_cont(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        # Resume the guest. QMP "cont" returns {} on success; if the VM is
        # already running QEMU raises an error, which surfaces as QMPError.
        qmp.execute("cont")
        status = qmp.execute("query-status")
    run_state = (
        status.get("status", "unknown") if isinstance(status, dict) else str(status)
    )
    _emit(
        args,
        data={"ok": True, "vm_id": inst.vm_id, "status": run_state},
        text=f"VM '{inst.vm_id}' resumed (status: {run_state})",
        stem="cont",
    )
    return 0


# ---------------------------------------------------------------------------
# qmp (raw)
# ---------------------------------------------------------------------------


def _add_qmp(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("qmp", help="Send raw QMP command")
    p.add_argument("command", help="QMP command name")
    p.add_argument("--args", default=None, help="JSON arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_qmp)


def _handle_qmp(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    # M3: pre-validate --args JSON with a friendly QMUError instead of letting a
    # raw JSONDecodeError escape as a traceback.
    if args.args:
        try:
            qmp_args = json.loads(args.args)
        except json.JSONDecodeError as exc:
            raise QMUError(f"Invalid --args JSON: {exc}") from exc
    else:
        qmp_args = None
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute(args.command, qmp_args)
    # Text mode passes the raw QMP return (any JSON type) straight to _output;
    # json mode wraps it so the universal {"ok": ...} contract holds, with the
    # original payload under "result".
    _emit(args, data={"ok": True, "result": result}, text=result, stem="qmp")
    return 0


# ---------------------------------------------------------------------------
# monitor (HMP)
# ---------------------------------------------------------------------------


def _add_monitor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("monitor", help="Send HMP monitor command")
    p.add_argument("command", nargs="+", help="HMP command")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_monitor)


def _handle_monitor(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    command = " ".join(args.command)
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute_hmp(command)
    _emit(
        args,
        data={"ok": True, "output": result},
        text=result if result.strip() else "(no output)",
        stem="monitor",
    )
    return 0


# ---------------------------------------------------------------------------
# rootfs (libguestfs)
# ---------------------------------------------------------------------------


def _add_rootfs(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("rootfs", help="Manipulate rootfs images via libguestfs")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="rootfs_cmd")

    s = sp.add_parser("inject", help="Copy local files into a rootfs image")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("mappings", nargs="+", metavar="LOCAL:GUEST",
                   help="One or more LOCAL:GUEST pairs (GUEST is a directory)")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number (default: 1; use 0 for whole-disk image)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_inject)

    s = sp.add_parser("shell", help="Drop into a guestfish interactive shell")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("--partition", type=int, default=1)
    s.set_defaults(handler=_handle_rootfs_shell)


def _handle_rootfs_inject(args: argparse.Namespace) -> int:
    parsed = [rootfs_mod.parse_mapping(m) for m in args.mappings]
    rootfs_mod.inject(args.image, parsed, partition=args.partition)

    summary = {
        "ok": True,
        "image": args.image,
        "partition": args.partition,
        "injected": [{"local": l, "guest": g} for l, g in parsed],
    }
    lines = [f"Injected into {args.image} (partition {args.partition}):"]
    for local, guest in parsed:
        lines.append(f"  {local} -> {guest}")
    _emit(args, data=summary, text=lines, stem="rootfs-inject")
    return 0


def _handle_rootfs_shell(args: argparse.Namespace) -> int:
    return rootfs_mod.shell(args.image, partition=args.partition)


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------


def _add_skill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("skill", help="Manage Claude Code / Codex skill")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="skill_cmd")
    s = sp.add_parser("install", help="Install skill into ~/.claude (and ~/.codex if present)")
    s.set_defaults(handler=_handle_skill_install)


def _skill_install_roots() -> list[Path]:
    """Return the destination dirs for `qmu skill install`.

    Always installs into ~/.claude/skills/. Additionally installs into
    ~/.codex/skills/ when ~/.codex/ exists.
    """
    roots = [claude_skills_dir()]
    if codex_home().is_dir():
        roots.append(codex_skills_dir())
    return roots


def _handle_skill_install(args: argparse.Namespace) -> int:
    skill_dirs = all_skill_source_dirs()
    if not skill_dirs:
        raise QMUError("No skill sources found under skills/")

    for src in skill_dirs:
        name = src.name
        for root in _skill_install_roots():
            dst = root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.is_symlink() or dst.exists():
                if dst.is_symlink():
                    dst.unlink()
                else:
                    shutil.rmtree(dst)
            dst.symlink_to(src)
            print(f"Skill installed: {dst} -> {src}")
    return 0


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


def _add_version(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("version", help="Print version")
    _add_format_opts(p)
    p.set_defaults(handler=_handle_version)


def _handle_version(args: argparse.Namespace) -> int:
    _emit(args, data={"ok": True, "version": VERSION}, text=f"qmu {VERSION}", stem="version")
    return 0


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qmu",
        description="Agent-friendly QEMU VM management CLI for kernel research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0    success\n"
            "  1    operation failed (guest command non-zero, doctor unhealthy,\n"
            "       snapshot op failed, no crash found, qmu operational errors\n"
            "       such as 'no running VM' or 'kernel not found')\n"
            "  2    usage / argparse error (bad flags or arguments) — ONLY\n"
            "  3    guest kernel crash or SSH transport-loss\n"
            "  4    infrastructure / internal error (QMP or SSH layer failures,\n"
            "       unexpected qmu errors, infra-subprocess failures such as a\n"
            "       pry/gdb hang)\n"
            "  124  wait timeout\n"
            "\n"
            "json contract:\n"
            "  With --format json|ndjson every result is a JSON object carrying\n"
            "  \"ok\": <bool>. Every error path emits\n"
            "  {\"ok\": false, \"error\": ..., \"error_type\": ...} to stdout."
        ),
    )
    # Register --vm/--format/--out on the top-level parser so they may be given
    # BEFORE the subcommand (e.g. `qmu --vm X exec "uname -r"`); the same flags
    # are also added to each subparser (after the subcommand) via
    # _add_common_opts with SUPPRESS defaults so neither order clobbers the other.
    _add_top_level_common_opts(parser)
    sub = parser.add_subparsers(dest="subcommand")

    _add_launch(sub)
    _add_kill(sub)
    _add_prune(sub)
    _add_wait(sub)
    _add_list(sub)
    _add_status(sub)
    _add_doctor(sub)
    _add_config(sub)
    _add_snapshot(sub)
    _add_push(sub)
    _add_pull(sub)
    _add_exec(sub)
    _add_compile(sub)
    _add_dmesg(sub)
    _add_crash(sub)
    _add_log(sub)
    _add_gdb(sub)
    _add_cont(sub)
    _add_qmp(sub)
    _add_monitor(sub)
    _add_rootfs(sub)
    _add_skill(sub)
    _add_version(sub)

    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 2

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2

    try:
        return handler(args)
    except QMUError as exc:
        # Exit-code contract: 2 is reserved for argparse usage errors (argparse
        # itself calls sys.exit(2)). Library errors get distinct codes so an
        # agent can tell a typo from an operational/infra failure:
        #   QMUError (operational, e.g. "no running VM", "kernel not found") -> 1
        #   QMPError/SSHError (infrastructure transport failures)            -> 4
        _emit_error(args, exc, "[qmu] Error:")
        return 1
    except QMPError as exc:
        _emit_error(args, exc, "[qmu] QMP error:")
        return 4
    except SSHError as exc:
        _emit_error(args, exc, "[qmu] SSH error:")
        return 4
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 — agent-facing catch-all
        # CORR-3: never surface a raw Python traceback to the agent. Any
        # unexpected internal error (the main() catch-all, plus infra-subprocess
        # failures such as a pry/gdb/scp hang) becomes a machine-actionable
        # message + JSON envelope with exit code 4 (internal/unexpected qmu
        # error) so it is NOT confused with a guest kernel crash / SSH
        # transport-loss (exit 3) or an ordinary non-zero guest command (exit 1).
        _emit_error(args, exc, "[qmu] Error:")
        return 4
