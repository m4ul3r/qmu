from __future__ import annotations

import os
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .instance import QMUError, VMInstance, save_instance
from .paths import instances_dir, qmp_socket_path, serial_log_path
from .qmp import QMPClient


DEFAULT_ROOTFS = "/media/ssd/kernel_research/tools/qemu/trixie.img"
DEFAULT_SSH_KEY = "/media/ssd/kernel_research/tools/qemu/trixie.id_rsa"
DEFAULT_MEMORY = "4G"
DEFAULT_CPUS = 2
DEFAULT_SSH_PORT_START = 10021
DEFAULT_GDB_PORT_START = 1234

BOOT_PROFILES: dict[str, str] = {
    "exploit-dev": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 kasan.fault=panic"
    ),
    "trigger-test": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"
    ),
    "exploit-test": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 panic_on_oops=1 kasan.fault=panic"
    ),
}


def find_free_port(start: int, max_tries: int = 100) -> int:
    """Find a free TCP port starting from `start`."""
    for offset in range(max_tries):
        port = start + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise QMUError(f"No free port found in range {start}-{start + max_tries - 1}")


def build_qemu_command(
    *,
    kernel: str,
    rootfs: str,
    memory: str,
    cpus: int,
    ssh_port: int,
    gdb_port: int | None,
    qmp_socket: str,
    serial_log: str,
    cmdline: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the qemu-system-x86_64 command line."""
    cmd = [
        "qemu-system-x86_64",
        "-m", memory,
        "-smp", str(cpus),
        "-kernel", kernel,
        "-append", cmdline,
        "-drive", f"file={rootfs},format=raw,snapshot=on",
        "-net", f"user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
        "-net", "nic,model=e1000",
        "-enable-kvm",
        "-display", "none",
        "-serial", f"file:{serial_log}",
        "-monitor", "none",
        "-qmp", f"unix:{qmp_socket},server,wait=off",
    ]
    if gdb_port is not None:
        cmd.extend(["-gdb", f"tcp::{gdb_port}"])
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def launch_vm(
    *,
    kernel: str,
    rootfs: str = DEFAULT_ROOTFS,
    ssh_key: str = DEFAULT_SSH_KEY,
    memory: str = DEFAULT_MEMORY,
    cpus: int = DEFAULT_CPUS,
    profile: str = "exploit-dev",
    cmdline: str | None = None,
    gdb: bool = False,
    name: str | None = None,
    ssh_port: int | None = None,
    gdb_port: int | None = None,
    extra_args: list[str] | None = None,
    ssh_timeout: int = 60,
) -> VMInstance:
    """Launch a QEMU VM and return the instance."""
    # Validate files
    kernel_path = Path(kernel).resolve()
    if not kernel_path.exists():
        raise QMUError(f"Kernel not found: {kernel}")

    rootfs_path = Path(rootfs).resolve()
    if not rootfs_path.exists():
        raise QMUError(f"Rootfs image not found: {rootfs}")

    key_path = Path(ssh_key).resolve()
    if not key_path.exists():
        raise QMUError(f"SSH key not found: {ssh_key}")

    if profile not in BOOT_PROFILES:
        valid = ", ".join(BOOT_PROFILES.keys())
        raise QMUError(f"Unknown profile '{profile}'. Valid: {valid}")

    # Resolve command line
    if cmdline is None:
        cmdline = BOOT_PROFILES[profile]

    # Allocate ports
    if ssh_port is None:
        ssh_port = find_free_port(DEFAULT_SSH_PORT_START)
    if gdb and gdb_port is None:
        gdb_port = find_free_port(DEFAULT_GDB_PORT_START)

    # Generate VM ID
    vm_id = name or f"vm-{ssh_port}"

    # Prepare paths
    idir = instances_dir()
    idir.mkdir(parents=True, exist_ok=True)

    qmp_sock = str(qmp_socket_path(vm_id))
    serial_path = str(serial_log_path(vm_id))

    # Remove stale socket if present
    Path(qmp_sock).unlink(missing_ok=True)

    # Build command
    cmd = build_qemu_command(
        kernel=str(kernel_path),
        rootfs=str(rootfs_path),
        memory=memory,
        cpus=cpus,
        ssh_port=ssh_port,
        gdb_port=gdb_port,
        qmp_socket=qmp_sock,
        serial_log=serial_path,
        cmdline=cmdline,
        extra_args=extra_args,
    )

    # Spawn QEMU detached
    log_fd = open(idir / f"{vm_id}.qemu.log", "w")
    proc = subprocess.Popen(
        cmd,
        stdout=log_fd,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Wait for QMP socket to appear
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if Path(qmp_sock).exists():
            break
        if proc.poll() is not None:
            log_fd.close()
            qemu_log = (idir / f"{vm_id}.qemu.log").read_text(errors="replace")
            raise QMUError(
                f"QEMU exited immediately (code {proc.returncode}).\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output:\n{qemu_log[-2000:]}"
            )
        time.sleep(0.2)
    else:
        proc.terminate()
        log_fd.close()
        raise QMUError("Timed out waiting for QMP socket to appear")

    # Verify QMP connectivity
    try:
        with QMPClient(qmp_sock) as qmp:
            qmp.execute("query-status")
    except Exception as exc:
        proc.terminate()
        log_fd.close()
        raise QMUError(f"QMP connection failed after launch: {exc}") from exc

    # Build and save instance
    inst = VMInstance(
        vm_id=vm_id,
        pid=proc.pid,
        qmp_socket=qmp_sock,
        ssh_port=ssh_port,
        ssh_key=str(key_path),
        gdb_port=gdb_port,
        serial_log=serial_path,
        kernel=str(kernel_path),
        rootfs=str(rootfs_path),
        memory=memory,
        cpus=cpus,
        cmdline=cmdline,
        profile=profile,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    save_instance(inst)

    return inst
