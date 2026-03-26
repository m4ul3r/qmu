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

from .instance import QMUError, VMInstance, choose_instance, list_instances, remove_instance
from .output import render_value, write_output_result
from .paths import skill_install_dir, skill_source_dir
from .qmp import QMPClient, QMPError
from .serial import extract_crash, tail_log
from .snapshot import (
    delete_snapshot,
    list_snapshots,
    load_snapshot,
    save_snapshot,
)
from .ssh import SSHClient, SSHError
from .version import VERSION
from .vm import (
    BOOT_PROFILES,
    DEFAULT_CPUS,
    DEFAULT_MEMORY,
    DEFAULT_ROOTFS,
    DEFAULT_SSH_KEY,
    launch_vm,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ssh(inst: VMInstance) -> SSHClient:
    return SSHClient(port=inst.ssh_port, key_path=inst.ssh_key)


def _qmp_ctx(inst: VMInstance) -> QMPClient:
    return QMPClient(inst.qmp_socket)


def _output(value: Any, args: argparse.Namespace, stem: str = "qmu") -> None:
    """Render output with optional spilling."""
    fmt = getattr(args, "format", "text")
    out = getattr(args, "out", None)
    out_path = Path(out) if out else None
    result = write_output_result(value, fmt=fmt, out_path=out_path, stem=stem)
    sys.stdout.write(result.rendered)
    if result.spilled:
        sys.stderr.write(f"[qmu] Output spilled to {result.artifact['artifact_path']}\n")


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
    p.add_argument("--rootfs", default=DEFAULT_ROOTFS, help="Path to rootfs image")
    p.add_argument("--ssh-key", default=DEFAULT_SSH_KEY, help="SSH private key for guest")
    p.add_argument("--memory", default=DEFAULT_MEMORY, help="VM memory (default: 4G)")
    p.add_argument("--cpus", type=int, default=DEFAULT_CPUS, help="VM CPUs (default: 2)")
    p.add_argument(
        "--profile",
        choices=list(BOOT_PROFILES.keys()),
        default="exploit-dev",
        help="Boot profile (default: exploit-dev)",
    )
    p.add_argument("--cmdline", default=None, help="Override kernel command line")
    p.add_argument("--gdb", action="store_true", help="Enable GDB stub")
    p.add_argument("--name", default=None, help="VM instance name")
    p.add_argument("--ssh-port", type=int, default=None, help="SSH port (auto-allocated)")
    p.add_argument("--gdb-port", type=int, default=None, help="GDB port (auto-allocated)")
    p.add_argument("--ssh-timeout", type=int, default=60, help="SSH wait timeout in seconds")
    p.add_argument("--no-wait-ssh", action="store_true", help="Don't wait for SSH to be ready")
    p.add_argument("extra", nargs="*", help="Extra QEMU arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_launch)


def _handle_launch(args: argparse.Namespace) -> int:
    inst = launch_vm(
        kernel=args.kernel,
        rootfs=args.rootfs,
        ssh_key=args.ssh_key,
        memory=args.memory,
        cpus=args.cpus,
        profile=args.profile,
        cmdline=args.cmdline,
        gdb=args.gdb,
        name=args.name,
        ssh_port=args.ssh_port,
        gdb_port=args.gdb_port,
        extra_args=args.extra or None,
        ssh_timeout=args.ssh_timeout,
    )

    ssh = _make_ssh(inst)
    ssh_status = "waiting..."

    if not args.no_wait_ssh:
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
    }

    if args.format == "text":
        lines = [
            f"VM '{inst.vm_id}' launched (pid={inst.pid})",
            f"  SSH:     port {inst.ssh_port} ({ssh_status})",
        ]
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

    # Try graceful QMP quit first
    if not args.force:
        try:
            with _qmp_ctx(inst) as qmp:
                qmp.execute("quit", timeout=5)
        except (QMPError, OSError):
            pass
        # Give it a moment
        time.sleep(1)

    # Check if still alive
    try:
        os.kill(inst.pid, 0)
        # Still alive — escalate
        sig = signal.SIGKILL if args.force else signal.SIGTERM
        os.kill(inst.pid, sig)
        time.sleep(1)
        # Final check
        try:
            os.kill(inst.pid, 0)
            os.kill(inst.pid, signal.SIGKILL)
        except OSError:
            pass
    except OSError:
        pass  # Already dead

    remove_instance(inst.vm_id)
    _output(f"VM '{inst.vm_id}' stopped.", args, stem="kill")
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
            ssh = _make_ssh(inst)
            data.append({
                "vm_id": inst.vm_id,
                "pid": inst.pid,
                "ssh_port": inst.ssh_port,
                "ssh_ready": ssh.is_ready(),
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel,
                "profile": inst.profile,
            })
        _output(data, args, stem="list")
        return 0

    lines = []
    for inst in instances:
        ssh = _make_ssh(inst)
        ssh_ok = ssh.is_ready()
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
    ssh = _make_ssh(inst)

    qmp_ok = False
    qemu_status = "unknown"
    try:
        with _qmp_ctx(inst) as qmp:
            status = qmp.execute("query-status")
            qmp_ok = True
            qemu_status = status.get("status", "unknown") if isinstance(status, dict) else str(status)
    except (QMPError, OSError):
        pass

    ssh_ok = ssh.is_ready()

    result = {
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "qmp": "connected" if qmp_ok else "unreachable",
        "qemu_status": qemu_status,
        "ssh_port": inst.ssh_port,
        "ssh": "ready" if ssh_ok else "down",
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
            f"  SSH:       port {inst.ssh_port} ({'ready' if ssh_ok else 'down'})",
        ]
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
    _add_common_opts(p)
    p.set_defaults(handler=_handle_doctor)


def _handle_doctor(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    # QEMU binary
    qemu = shutil.which("qemu-system-x86_64")
    checks.append({
        "check": "qemu-system-x86_64",
        "status": "ok" if qemu else "MISSING",
        "detail": qemu or "Not found in PATH",
    })

    # Default rootfs
    rootfs_ok = Path(DEFAULT_ROOTFS).exists()
    checks.append({
        "check": "rootfs image",
        "status": "ok" if rootfs_ok else "MISSING",
        "detail": DEFAULT_ROOTFS,
    })

    # SSH key
    key_path = Path(DEFAULT_SSH_KEY)
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
        "detail": f"{DEFAULT_SSH_KEY}{key_perms}",
    })

    # KVM
    kvm_ok = Path("/dev/kvm").exists()
    checks.append({
        "check": "/dev/kvm",
        "status": "ok" if kvm_ok else "MISSING",
        "detail": "KVM acceleration available" if kvm_ok else "No KVM — will be slow",
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
            mark = "+" if c["status"] == "ok" else "!"
            lines.append(f"  [{mark}] {c['check']}: {c['detail']}")
        _output("\n".join(lines), args, stem="doctor")
    else:
        _output(checks, args, stem="doctor")

    all_ok = all(c["status"] == "ok" for c in checks)
    return 0 if all_ok else 1


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
    _add_list(sub)
    _add_status(sub)
    _add_doctor(sub)
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
