from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import QMUConfig
from .instance import QMUError, VMInstance, proc_pid_start, save_instance
from .paths import instances_dir, qmp_socket_path, serial_log_path
from .qemu import native_passt_problem, probe_qemu_netdevs
from .qmp import QMPClient


def find_free_port(start: int, max_tries: int = 100) -> int:
    """Find a free TCP port starting from `start`.

    TOCTOU note: the probe socket is closed before QEMU binds, so under
    concurrent launches another process (or VM) can claim the returned port in
    the window between this check and QEMU's bind. QEMU will then fail to bind;
    callers should be prepared for a launch-time bind failure rather than
    treating a returned port as a hard reservation.
    """
    for offset in range(max_tries):
        port = start + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise QMUError(f"No free port found in range {start}-{start + max_tries - 1}")


def _preflight_native_passt(
    *,
    config: QMUConfig,
    net_backend: str | None,
    no_net: bool,
    harness: bool,
) -> str | None:
    effective_backend = net_backend or config.net_backend
    if no_net or harness or effective_backend != "passt":
        return None

    caps = probe_qemu_netdevs(config.qemu_binary())
    problem = native_passt_problem(caps)
    if problem is not None:
        raise QMUError(problem)

    if shutil.which("passt") is None:
        raise QMUError(
            "net_backend=passt requires the 'passt' binary on PATH "
            "(e.g. 'apt install passt' / 'pacman -S passt'). "
            "Use the default 'user' backend, or --no-net, if passt is unavailable."
        )

    assert caps.path is not None
    return caps.path


def build_qemu_command(
    *,
    config: QMUConfig,
    kernel: str,
    rootfs: str | None,
    ssh_port: int | None,
    gdb_port: int | None,
    qmp_socket: str,
    serial_log: str,
    cmdline: str,
    initrd: str | None = None,
    drives: list[str] | None = None,
    no_net: bool = False,
    nic_model: str | None = None,
    net_backend: str | None = None,
    qemu_binary: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build the qemu-system command line from config."""
    nic = nic_model or config.nic_model
    backend = net_backend or config.net_backend

    cmd = [
        qemu_binary or config.qemu_binary(),
        "-m", config.memory,
        "-smp", str(config.cpus),
        "-kernel", kernel,
        "-append", cmdline,
    ]

    if config.cpu_model:
        cmd.extend(["-cpu", config.cpu_model])

    if initrd:
        cmd.extend(["-initrd", initrd])

    # Drives: explicit --drive specs win and suppress the implicit rootfs drive.
    if drives:
        for spec in drives:
            cmd.extend(["-drive", spec])
    elif rootfs is not None:
        cmd.extend(["-drive", f"file={rootfs},format={config.drive_format},snapshot=on"])

    # Networking
    if no_net:
        cmd.extend(["-nic", "none"])
    elif ssh_port is None:
        # No SSH hostfwd, but still provide a NIC (rare: --no-wait-ssh without --no-net).
        cmd.extend(["-nic", f"user,model={nic}"])
    elif backend == "passt":
        # Native passt is migration-compatible when the selected QEMU advertises it.
        # Some user/slirp QEMU/build/device combinations restore successfully; others
        # report slirp section/footer errors on loadvm. Capability and external-binary
        # validation happens once in launch_vm before artifacts or process creation.
        cmd.extend([
            "-netdev",
            f"passt,id=net0,address=10.0.2.15,gateway=10.0.2.2,"
            f"tcp-ports=127.0.0.1/{ssh_port}:22,quiet=on",
            "-device", f"{nic},netdev=net0",
        ])
    else:
        cmd.extend([
            "-netdev", f"user,id=net0,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
            "-device", f"{nic},netdev=net0",
        ])

    cmd.extend([
        "-display", "none",
        "-serial", f"file:{serial_log}",
        "-monitor", "none",
        "-qmp", f"unix:{qmp_socket},server,wait=off",
    ])

    if config.use_kvm():
        cmd.append("-enable-kvm")

    if config.extra_args:
        cmd.extend(config.extra_args)

    if gdb_port is not None:
        # Bind the gdb stub to 127.0.0.1 to match the address find_free_port
        # probes; "tcp::{port}" would bind the wildcard and let the probe pass
        # even when 127.0.0.1:{port} is already taken.
        cmd.extend(["-gdb", f"tcp:127.0.0.1:{gdb_port}"])

    if extra_args:
        cmd.extend(extra_args)

    return cmd


def launch_vm(
    *,
    config: QMUConfig,
    kernel: str,
    profile: str = "exploit-dev",
    cmdline: str | None = None,
    gdb: bool = False,
    name: str | None = None,
    ssh_port: int | None = None,
    gdb_port: int | None = None,
    extra_args: list[str] | None = None,
    ssh_timeout: int = 60,
    initrd: str | None = None,
    drives: list[str] | None = None,
    no_net: bool = False,
    nic_model: str | None = None,
    net_backend: str | None = None,
    harness: bool = False,
) -> VMInstance:
    """Launch a QEMU VM and return the instance."""
    # Validate files
    kernel_path = Path(kernel).expanduser().resolve()
    if not kernel_path.exists():
        raise QMUError(f"Kernel not found: {kernel}")

    rootfs_path: Path | None = None
    if not harness and not drives:
        if config.rootfs is None:
            raise QMUError(
                "No rootfs configured. Set [drive] rootfs in qmu.toml or pass --rootfs"
            )
        rootfs_path = Path(config.rootfs).expanduser().resolve()
        if not rootfs_path.exists():
            raise QMUError(f"Rootfs image not found: {config.rootfs}")
    elif config.rootfs is not None:
        # rootfs is configured but suppressed by --drive or --harness; only resolve
        # so we can record the path on the instance for diagnostics.
        candidate = Path(config.rootfs).expanduser().resolve()
        if candidate.exists():
            rootfs_path = candidate

    key_path: Path | None = None
    if not harness:
        if config.ssh_key is None:
            raise QMUError(
                "No SSH key configured. Set [ssh] key in qmu.toml or pass --ssh-key"
            )
        key_path = Path(config.ssh_key).expanduser().resolve()
        if not key_path.exists():
            raise QMUError(f"SSH key not found: {config.ssh_key}")

    initrd_path: Path | None = None
    if initrd is not None:
        initrd_path = Path(initrd).expanduser().resolve()
        if not initrd_path.exists():
            raise QMUError(f"Initrd not found: {initrd}")

    if profile not in config.profiles:
        valid = ", ".join(config.profiles.keys())
        raise QMUError(f"Unknown profile '{profile}'. Valid: {valid}")

    # Resolve command line
    if cmdline is None:
        cmdline = config.profiles[profile]
    resolved_qemu = _preflight_native_passt(
        config=config,
        net_backend=net_backend,
        no_net=no_net,
        harness=harness,
    )

    idir = instances_dir()
    idir.mkdir(parents=True, exist_ok=True)

    # Resolved NIC recorded on the instance.
    resolved_nic = nic_model or config.nic_model

    # Harness VMs run boot-and-die with no SSH, so never allocate an SSH port.
    # Otherwise auto-allocate any port the caller did not pin. Auto-allocated
    # ports have a TOCTOU window (find_free_port closes its probe before QEMU
    # binds), so a concurrent launch can steal one; QEMU then exits with a bind
    # error and we retry with fresh ports. Pinned ports are never re-allocated.
    if harness:
        ssh_port = None
    auto_ssh = (not harness) and (ssh_port is None)
    auto_gdb = gdb and gdb_port is None
    bind_markers = ("Address already in use", "Could not set up host forwarding", "Failed to bind")

    proc = None
    vm_id = qmp_sock = serial_path = None
    for attempt in range(3):
        if auto_ssh:
            ssh_port = find_free_port(config.ssh_port_start)
        if auto_gdb:
            gdb_port = find_free_port(config.gdb_port_start)

        if name:
            vm_id = name
        elif ssh_port is not None:
            vm_id = f"vm-{ssh_port}"
        else:
            # uuid suffix: timestamp-based ids collide when two harness VMs
            # launch within the same second (parallel agent workflows).
            vm_id = f"vm-h{uuid.uuid4().hex[:8]}"
        qmp_sock = str(qmp_socket_path(vm_id))
        serial_path = str(serial_log_path(vm_id))
        Path(qmp_sock).unlink(missing_ok=True)  # remove stale socket if present

        cmd = build_qemu_command(
            config=config,
            kernel=str(kernel_path),
            rootfs=str(rootfs_path) if rootfs_path else None,
            ssh_port=ssh_port,
            gdb_port=gdb_port,
            qmp_socket=qmp_sock,
            serial_log=serial_path,
            cmdline=cmdline,
            initrd=str(initrd_path) if initrd_path else None,
            drives=drives,
            no_net=no_net,
            nic_model=nic_model,
            net_backend=net_backend,
            qemu_binary=resolved_qemu,
            extra_args=extra_args,
        )

        log_fd = open(idir / f"{vm_id}.qemu.log", "w")
        proc = subprocess.Popen(
            cmd,
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        # Record the kernel start-time of the child immediately so liveness
        # checks can detect PID recycling across host reboots. None on
        # platforms without /proc (pid-only fallback applies there).
        pid_start = proc_pid_start(proc.pid)

        # Wait for the QMP socket to appear (or QEMU to exit immediately).
        deadline = time.monotonic() + 10
        exited = False
        while time.monotonic() < deadline:
            if Path(qmp_sock).exists():
                break
            if proc.poll() is not None:
                exited = True
                break
            time.sleep(0.2)
        else:
            proc.terminate()
            log_fd.close()
            raise QMUError("Timed out waiting for QMP socket to appear")

        if exited:
            log_fd.close()
            qemu_log = (idir / f"{vm_id}.qemu.log").read_text(errors="replace")
            if any(m in qemu_log for m in bind_markers) and (auto_ssh or auto_gdb) and attempt < 2:
                continue  # lost a port race — retry with freshly allocated ports
            raise QMUError(
                f"QEMU exited immediately (code {proc.returncode}).\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output:\n{qemu_log[-2000:]}"
            )

        # QMP socket appeared — verify connectivity.
        try:
            with QMPClient(qmp_sock) as qmp:
                qmp.execute("query-status")
        except Exception as exc:
            proc.terminate()
            log_fd.close()
            raise QMUError(f"QMP connection failed after launch: {exc}") from exc
        break  # launched successfully

    # Build and save instance
    inst = VMInstance(
        vm_id=vm_id,
        pid=proc.pid,
        qmp_socket=qmp_sock,
        ssh_port=ssh_port,
        ssh_key=str(key_path) if key_path else None,
        ssh_user=config.ssh_user,
        gdb_port=gdb_port,
        serial_log=serial_path,
        kernel=str(kernel_path),
        rootfs=str(rootfs_path) if rootfs_path else None,
        memory=config.memory,
        cpus=config.cpus,
        cmdline=cmdline,
        profile=profile,
        started_at=datetime.now(timezone.utc).isoformat(),
        harness=harness,
        nic_model=resolved_nic,
        pid_start=pid_start,
    )
    save_instance(inst)

    return inst
