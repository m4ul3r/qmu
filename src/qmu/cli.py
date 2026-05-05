from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .config import QMUConfig, STARTER_CONFIG, find_project_config, resolve_config
from .instance import QMUError, VMInstance, choose_instance, is_pid_alive, list_instances, load_instance, remove_instance
from .output import render_value, write_output_result
from .paths import global_config_path, skill_install_dir, skill_source_dir
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
    return SSHClient(port=inst.ssh_port, key_path=inst.ssh_key)


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


def _kill_vm(inst: VMInstance, force: bool = False) -> None:
    """Kill a VM instance: QMP quit → SIGTERM → SIGKILL → cleanup."""
    if not force:
        try:
            with _qmp_ctx(inst) as qmp:
                qmp.execute("quit", timeout=5)
        except (QMPError, OSError):
            pass
        time.sleep(1)

    try:
        os.kill(inst.pid, 0)
        sig = signal.SIGKILL if force else signal.SIGTERM
        os.kill(inst.pid, sig)
        time.sleep(1)
        try:
            os.kill(inst.pid, 0)
            os.kill(inst.pid, signal.SIGKILL)
        except OSError:
            pass
    except OSError:
        pass  # Already dead

    remove_instance(inst.vm_id)


def _add_common_opts(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vm", default=None, help="VM instance ID (auto-selects if only one)")
    parser.add_argument("--format", choices=["text", "json", "ndjson"], default="text")
    parser.add_argument("--out", default=None, help="Write output to file instead of stdout")


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
    p.add_argument("--cpus", type=int, default=None, help="VM CPUs (overrides config)")
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
        if existing is not None and is_pid_alive(existing.pid):
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

    if args.format == "text":
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
        lines.append(f"  Log:     {inst.serial_log}")
        _output("\n".join(lines), args, stem="launch")
    else:
        _output(result, args, stem="launch")
    return 0


# ---------------------------------------------------------------------------
# kill
# ---------------------------------------------------------------------------


def _add_kill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("kill", help="Stop a running VM")
    p.add_argument("--force", action="store_true", help="Force kill (SIGKILL)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_kill)


def _handle_kill(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _kill_vm(inst, force=args.force)
    _output(f"VM '{inst.vm_id}' stopped.", args, stem="kill")
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
    deadline: float | None = (start + args.timeout) if args.timeout else None
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

    if args.format == "text":
        lines = [
            f"VM '{inst.vm_id}' {'stopped' if stopped else 'still running'} "
            f"({reason}, elapsed={elapsed:.2f}s)"
        ]
        if crash:
            lines.append("\nCrash from serial log:\n" + crash)
        if cleaned:
            lines.append("[qmu] Instance metadata cleaned up.")
        _output("\n".join(lines), args, stem="wait")
    else:
        _output(result, args, stem="wait")

    if not stopped:
        return 124  # timeout
    return 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _add_list(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="List running VMs")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_list)


def _handle_list(args: argparse.Namespace) -> int:
    instances = list_instances()
    if not instances:
        _output("No running VMs.", args, stem="list")
        return 0

    if args.format != "text":
        data = []
        for inst in instances:
            entry: dict[str, Any] = {
                "vm_id": inst.vm_id,
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
        _output(data, args, stem="list")
        return 0

    lines = []
    for inst in instances:
        if inst.harness or inst.ssh_port is None:
            ssh_str = "harness"
        else:
            ssh_ok = _make_ssh(inst).is_ready()
            ssh_str = f"ssh={inst.ssh_port}({'ok' if ssh_ok else 'down'})"
        gdb_str = f" gdb={inst.gdb_port}" if inst.gdb_port else ""
        lines.append(
            f"  {inst.vm_id}  pid={inst.pid}  {ssh_str}{gdb_str}  "
            f"profile={inst.profile}  kernel={Path(inst.kernel).name}"
        )
    _output("Running VMs:\n" + "\n".join(lines), args, stem="list")
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

    if args.format == "text":
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
        _output("\n".join(lines), args, stem="status")
    else:
        _output(result, args, stem="status")
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

    # Config sources
    checks.append({
        "check": "config",
        "status": "ok",
        "detail": " -> ".join(config._sources),
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
        rootfs_ok = Path(config.rootfs).exists()
        checks.append({
            "check": "rootfs image",
            "status": "ok" if rootfs_ok else "MISSING",
            "detail": config.rootfs,
        })
    else:
        checks.append({
            "check": "rootfs image",
            "status": "not configured",
            "detail": "Set [drive] rootfs in qmu.toml or pass --rootfs",
        })

    # SSH key
    if config.ssh_key:
        key_path = Path(config.ssh_key)
        key_ok = key_path.exists()
        key_perms = ""
        if key_ok:
            mode = oct(key_path.stat().st_mode)[-3:]
            key_perms = f" (mode={mode})"
            if mode not in ("600", "400"):
                key_perms += " WARNING: should be 600"
        checks.append({
            "check": "SSH key",
            "status": "ok" if key_ok else "MISSING",
            "detail": f"{config.ssh_key}{key_perms}",
        })
    else:
        checks.append({
            "check": "SSH key",
            "status": "not configured",
            "detail": "Set [ssh] key in qmu.toml or pass --ssh-key",
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

    # Running instances
    instances = list_instances()
    checks.append({
        "check": "running VMs",
        "status": "ok",
        "detail": f"{len(instances)} instance(s)",
    })

    # Skill installed
    skill_ok = skill_install_dir().exists()
    checks.append({
        "check": "Claude skill",
        "status": "ok" if skill_ok else "not installed",
        "detail": str(skill_install_dir()) if skill_ok else "Run: qmu skill install",
    })

    if args.format == "text":
        lines = ["qmu doctor:"]
        for c in checks:
            mark = "+" if c["status"] in ("ok", "info") else "!"
            lines.append(f"  [{mark}] {c['check']}: {c['detail']}")
        _output("\n".join(lines), args, stem="doctor")
    else:
        _output(checks, args, stem="doctor")

    all_ok = all(c["status"] in ("ok", "info") for c in checks)
    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _add_config(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("config", help="Manage qmu configuration")
    sp = p.add_subparsers(dest="config_cmd")

    s = sp.add_parser("show", help="Show resolved configuration")
    s.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_config_show)

    s = sp.add_parser("init", help="Create a starter qmu.toml in current directory")
    s.set_defaults(handler=_handle_config_init)

    s = sp.add_parser("path", help="Show config file search paths")
    s.set_defaults(handler=_handle_config_path)


def _handle_config_show(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )

    data = {
        "sources": config._sources,
        "machine": {
            "arch": config.arch,
            "memory": config.memory,
            "cpus": config.cpus,
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

    if args.format == "text":
        lines = ["Resolved qmu config:"]
        lines.append(f"  Sources: {' -> '.join(config._sources)}")
        lines.append(f"  Arch:        {config.arch} ({config.qemu_binary()})")
        lines.append(f"  KVM:         {config.use_kvm()}")
        lines.append(f"  Memory:      {config.memory}")
        lines.append(f"  CPUs:        {config.cpus}")
        lines.append(f"  Rootfs:      {config.rootfs or '(not set)'}")
        lines.append(f"  Drive fmt:   {config.drive_format}")
        lines.append(f"  SSH key:     {config.ssh_key or '(not set)'}")
        lines.append(f"  SSH user:    {config.ssh_user}")
        lines.append(f"  SSH port:    {config.ssh_port_start}+")
        lines.append(f"  GDB port:    {config.gdb_port_start}+")
        if config.extra_args:
            lines.append(f"  Extra args:  {' '.join(config.extra_args)}")
        lines.append(f"  Profiles:    {', '.join(config.profiles.keys())}")
        _output("\n".join(lines), args, stem="config-show")
    else:
        _output(data, args, stem="config-show")
    return 0


def _handle_config_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / "qmu.toml"
    if target.exists():
        sys.stderr.write(f"[qmu] {target} already exists\n")
        return 1
    target.write_text(STARTER_CONFIG)
    print(f"Created {target}")
    return 0


def _handle_config_path(args: argparse.Namespace) -> int:
    gpath = global_config_path()
    ppath = find_project_config()
    lines = [
        f"Global config:  {gpath} ({'exists' if gpath.is_file() else 'not found'})",
        f"Project config: {ppath or '(none found — searched up from CWD)'}",
    ]
    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def _add_snapshot(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("snapshot", help="VM snapshot management")
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


def _handle_snapshot_save(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = save_snapshot(qmp, args.name)
    _output(msg, args, stem="snapshot-save")
    return 0


def _handle_snapshot_load(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = load_snapshot(qmp, args.name)
    _output(msg, args, stem="snapshot-load")
    return 0


def _handle_snapshot_list(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        snaps = list_snapshots(qmp)
    if not snaps:
        _output("No snapshots.", args, stem="snapshot-list")
    elif args.format == "text":
        lines = ["Snapshots:"]
        for s in snaps:
            lines.append(f"  {s['id']}  {s['tag']}  size={s['vm_size']}  {s['date']} {s['time']}")
        _output("\n".join(lines), args, stem="snapshot-list")
    else:
        _output(snaps, args, stem="snapshot-list")
    return 0


def _handle_snapshot_delete(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = delete_snapshot(qmp, args.name)
    _output(msg, args, stem="snapshot-delete")
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
    _output(f"Pushed {args.local} -> guest:{args.remote}", args, stem="push")
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
    _output(f"Pulled guest:{args.remote} -> {args.local}", args, stem="pull")
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


def _handle_exec(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)
    ssh = _make_ssh(inst)
    command = " ".join(args.command)

    try:
        rc, stdout, stderr = ssh.run(command, timeout=args.timeout)
    except SSHError:
        # SSH died — likely kernel crash. Try to get crash info.
        crash = extract_crash(inst.serial_log)
        result = {
            "ssh_error": True,
            "command": command,
            "crash": crash,
            "hint": "SSH connection lost. Kernel may have crashed. See crash field or run: qmu crash",
        }
        if args.format == "text":
            lines = [f"SSH connection lost while running: {command}"]
            if crash:
                lines.append(f"\nCrash from serial log:\n{crash}")
            else:
                lines.append("\nNo crash detected in serial log. Check: qmu log --tail 100")
            _output("\n".join(lines), args, stem="exec")
        else:
            _output(result, args, stem="exec")
        return 1

    if args.format == "text":
        output_parts = []
        if stdout.strip():
            output_parts.append(stdout.rstrip())
        if stderr.strip():
            output_parts.append(f"[stderr] {stderr.rstrip()}")
        if rc != 0:
            output_parts.append(f"[exit code: {rc}]")
        text = "\n".join(output_parts) if output_parts else f"[exit code: {rc}]"
        _output(text, args, stem="exec")
    else:
        _output({"exit_code": rc, "stdout": stdout, "stderr": stderr}, args, stem="exec")
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

    # Compile
    compile_cmd = f"gcc {args.cflags} -o {remote_bin} {remote_src}"
    rc, stdout, stderr = ssh.run(compile_cmd, timeout=30)

    result: dict[str, Any] = {
        "source": str(source),
        "compile_cmd": compile_cmd,
        "compile_exit": rc,
        "compile_stdout": stdout,
        "compile_stderr": stderr,
    }

    if rc != 0:
        if args.format == "text":
            _output(f"Compilation failed:\n{stderr.strip()}", args, stem="compile")
        else:
            _output(result, args, stem="compile")
        return 1

    result["compiled"] = True

    if not args.run:
        if args.format == "text":
            _output(f"Compiled {source.name} -> {remote_bin}", args, stem="compile")
        else:
            _output(result, args, stem="compile")
        return 0

    # Run
    try:
        rc, stdout, stderr = ssh.run(remote_bin, timeout=args.timeout)
        result.update({
            "run_exit": rc,
            "run_stdout": stdout,
            "run_stderr": stderr,
        })
        if args.format == "text":
            lines = [f"Compiled and ran {source.name}:"]
            if stdout.strip():
                lines.append(stdout.rstrip())
            if stderr.strip():
                lines.append(f"[stderr] {stderr.rstrip()}")
            lines.append(f"[exit code: {rc}]")
            _output("\n".join(lines), args, stem="compile")
        else:
            _output(result, args, stem="compile")
        return 0 if rc == 0 else 1

    except SSHError:
        crash = extract_crash(inst.serial_log)
        result.update({
            "ssh_error": True,
            "crash": crash,
        })
        if args.format == "text":
            lines = [f"SSH connection lost while running {name}."]
            if crash:
                lines.append(f"\nCrash from serial log:\n{crash}")
            else:
                lines.append("\nNo crash detected in serial log. Check: qmu log --tail 100")
            _output("\n".join(lines), args, stem="compile")
        else:
            _output(result, args, stem="compile")
        return 1


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
    if args.tail:
        cmd = f"dmesg | tail -{args.tail}"
    rc, stdout, stderr = ssh.run(cmd, timeout=15)
    _output(stdout if stdout else stderr, args, stem="dmesg")
    return 0


# ---------------------------------------------------------------------------
# crash
# ---------------------------------------------------------------------------


def _add_crash(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("crash", help="Extract crash from serial log")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_crash)


def _handle_crash(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    crash = extract_crash(inst.serial_log)
    if crash:
        _output(crash, args, stem="crash")
    else:
        _output("No crash detected in serial log.", args, stem="crash")
    return 0


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------


def _add_log(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("log", help="View serial console log")
    p.add_argument("--tail", type=int, default=50, help="Last N lines (default: 50)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_log)


def _handle_log(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    text = tail_log(inst.serial_log, lines=args.tail)
    if text:
        _output(text, args, stem="log")
    else:
        _output("Serial log is empty or missing.", args, stem="log")
    return 0


# ---------------------------------------------------------------------------
# gdb
# ---------------------------------------------------------------------------


def _add_gdb(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("gdb", help="Launch pry connected to VM's GDB stub")
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
        raise QMUError("pry not found in PATH. Install it from /opt/pry")

    cmd = ["pry", "launch", "--connect", f"localhost:{inst.gdb_port}"]
    if args.symbols:
        cmd.extend(["--symbols", str(Path(args.symbols).expanduser().resolve())])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if result.returncode == 0:
        _output(
            f"pry connected to VM '{inst.vm_id}' GDB stub on port {inst.gdb_port}",
            args,
            stem="gdb",
        )
    else:
        output = result.stderr.strip() or result.stdout.strip()
        _output(f"pry launch failed: {output}", args, stem="gdb")
        return 1
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
    qmp_args = json.loads(args.args) if args.args else None
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute(args.command, qmp_args)
    _output(result, args, stem="qmp")
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
    _output(result if result.strip() else "(no output)", args, stem="monitor")
    return 0


# ---------------------------------------------------------------------------
# rootfs (libguestfs)
# ---------------------------------------------------------------------------


def _add_rootfs(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("rootfs", help="Manipulate rootfs images via libguestfs")
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
        "image": args.image,
        "partition": args.partition,
        "injected": [{"local": l, "guest": g} for l, g in parsed],
    }
    if args.format == "text":
        lines = [f"Injected into {args.image} (partition {args.partition}):"]
        for local, guest in parsed:
            lines.append(f"  {local} -> {guest}")
        _output("\n".join(lines), args, stem="rootfs-inject")
    else:
        _output(summary, args, stem="rootfs-inject")
    return 0


def _handle_rootfs_shell(args: argparse.Namespace) -> int:
    return rootfs_mod.shell(args.image, partition=args.partition)


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------


def _add_skill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("skill", help="Manage Claude Code skill")
    sp = p.add_subparsers(dest="skill_cmd")
    s = sp.add_parser("install", help="Install Claude Code skill")
    s.set_defaults(handler=_handle_skill_install)


def _handle_skill_install(args: argparse.Namespace) -> int:
    src = skill_source_dir()
    dst = skill_install_dir()

    if not src.exists():
        raise QMUError(f"Skill source not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    # Remove existing (symlink or dir)
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
    p.set_defaults(handler=_handle_version)


def _handle_version(args: argparse.Namespace) -> int:
    print(f"qmu {VERSION}")
    return 0


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qmu",
        description="Agent-friendly QEMU VM management CLI for kernel research",
    )
    sub = parser.add_subparsers(dest="subcommand")

    _add_launch(sub)
    _add_kill(sub)
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
        sys.stderr.write(f"[qmu] Error: {exc}\n")
        return 2
    except QMPError as exc:
        sys.stderr.write(f"[qmu] QMP error: {exc}\n")
        return 2
    except SSHError as exc:
        sys.stderr.write(f"[qmu] SSH error: {exc}\n")
        return 2
    except KeyboardInterrupt:
        return 130
