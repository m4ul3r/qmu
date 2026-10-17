from __future__ import annotations

import errno
import fcntl
import os
import shutil
import socket
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import get_close_matches
from pathlib import Path

from .config import QMUConfig
from .instance import QMUError, VMInstance, proc_pid_start, save_instance
from .paths import instances_dir, qmp_socket_path, qemu_log_path, serial_log_path
from .qemu import native_passt_problem, probe_qemu_netdevs
from .qmp import QMPClient, QMPError


def _resolve_boot_file(value: str, label: str, source: str = "") -> Path:
    """Resolve a kernel/initrd path, naming the absolute path on failure.

    `source` is the config provenance suffix (see
    `QMUConfig.describe_path_source`) so a value that came from a qmu.toml in
    a parent directory is reported as the file it resolved to and the file
    that set it, not as the bare relative string the user never typed here.
    """
    path = Path(value).expanduser()
    try:
        # Before 3.13, resolve() raises RuntimeError on a symlink loop even in
        # non-strict mode; from 3.13 the loop surfaces as ELOOP from stat().
        path = path.resolve()
        mode = path.stat().st_mode
    except (FileNotFoundError, NotADirectoryError):
        raise QMUError(
            f"{label} not found: {path}{source}",
            hint=f"ls -l {path}; qmu config show names the file that set it",
        ) from None
    except OSError as exc:
        raise QMUError(
            f"{label} not accessible: {path} ({exc.strerror}){source}",
            hint=f"ls -l {path}; check its permissions",
        ) from None
    except RuntimeError as exc:
        raise QMUError(f"{label} not accessible: {path} ({exc}){source}") from None
    if not stat.S_ISREG(mode):
        raise QMUError(
            f"{label} is not a regular file: {path}{source}",
            hint=f"ls -l {path}; point at the image file itself",
        )
    return path


def _terminate_and_reap(
    proc: subprocess.Popen,
    *,
    terminate_timeout: float = 1.0,
    kill_timeout: float = 1.0,
) -> None:
    if proc.poll() is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=terminate_timeout)
        return
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    proc.wait(timeout=kill_timeout)


def _remove_attempt_artifacts(*paths: Path) -> None:
    for path in paths:
        path.unlink(missing_ok=True)


def _validate_qmp(socket_path: Path) -> None:
    qmp = QMPClient(socket_path)
    try:
        qmp.connect()
        qmp.execute("query-status")
    finally:
        qmp.close()


# How long the first QMP connect to a live QEMU is retried before the launch
# is declared failed. QEMU creates the listener before it is ready to accept
# on it, so under host load a concurrent launch saw the very first connect
# reset by peer (ECONNRESET) and was reported as a failed launch — unlike the
# bind race, which already retried. 3 s is generous for a socket that QEMU
# normally serves within milliseconds.
QMP_CONNECT_RETRY_SECONDS = 3.0
_QMP_CONNECT_RETRY_INTERVAL = 0.25


def _transient_qmp_failure(exc: BaseException) -> bool:
    """A connect-time fault worth retrying while QEMU is still alive.

    Reset/refused/aborted/broken-pipe on the socket, or the client's own
    wrappers of those (`Cannot connect`, `closed unexpectedly`). A rejected
    greeting or a QEMU error reply is not transient and is reported at once.
    """
    if isinstance(exc, ConnectionError):
        return True
    if isinstance(exc.__cause__, ConnectionError):
        return True
    if isinstance(exc, QMPError):
        text = str(exc)
        return "Cannot connect" in text or "closed unexpectedly" in text
    return False


def _fault_name(exc: BaseException) -> str:
    """`ECONNRESET`-style name for a transient connect fault, for the note."""
    err: BaseException | None = exc
    if not isinstance(err, OSError) and isinstance(exc.__cause__, OSError):
        err = exc.__cause__
    if isinstance(err, OSError) and err.errno is not None:
        return errno.errorcode.get(err.errno, f"errno {err.errno}")
    return type(exc).__name__


def _validate_qmp_with_retry(
    socket_path: Path, proc: subprocess.Popen
) -> tuple[bool, Exception | None, str | None]:
    """Connect to a freshly launched QEMU's QMP socket.

    Returns ``(exited, error, note)``: ``exited`` when QEMU died meanwhile
    (its log carries the reason, so no QMP error is reported), else ``error``
    is the final non-transient or budget-exhausting failure, or None on
    success. ``note`` names how many retries a successful connect needed
    (`QMP connect retried 2× (ECONNRESET)`) so the retry is observable in
    the launch's `warnings[]` instead of silently absorbed (#76).
    """
    deadline = time.monotonic() + QMP_CONNECT_RETRY_SECONDS
    retries = 0
    last_fault: BaseException | None = None
    while True:
        try:
            _validate_qmp(socket_path)
            note = None
            if retries and last_fault is not None:
                note = f"QMP connect retried {retries}× ({_fault_name(last_fault)})"
            return False, None, note
        except Exception as exc:  # noqa: BLE001 — classified below
            # QEMU creates the QMP listener before it applies -netdev hostfwd
            # rules or opens -drive files, so a failure there (port already
            # taken, a stray word from an unquoted --cmdline parsed as a disk
            # image) leaves the socket on disk and the connect refused. That
            # is a dead QEMU whose reason is in its log, not a QMP problem.
            if proc.poll() is not None:
                return True, None, None
            if _transient_qmp_failure(exc) and time.monotonic() < deadline:
                # Each retry interval is also the grace an exiting QEMU gets:
                # the poll above catches it on the next pass.
                retries += 1
                last_fault = exc
                time.sleep(_QMP_CONNECT_RETRY_INTERVAL)
                continue
            # Give the exit a moment to land before deciding which it was.
            if _exits_within(proc, 1.0):
                return True, None, None
            return False, exc, None


def _exits_within(proc: subprocess.Popen, grace: float) -> bool:
    """True once `proc` has exited, polling for at most `grace` seconds.

    Polls rather than `wait(timeout=)` so a child that is genuinely still
    running is left alone (nothing is reaped or signalled here).
    """
    deadline = time.monotonic() + grace
    while True:
        if proc.poll() is not None:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


@dataclass
class _LaunchAttempt:
    proc: subprocess.Popen
    vm_id: str
    qmp_socket: Path
    serial_log: Path
    qemu_log: Path
    committed: bool = False
    _primary_error: BaseException | None = field(default=None, repr=False)

    def rollback(self, *, capture_output: bool = False) -> str:
        if self.committed:
            return ""
        output = ""
        cleanup_error: BaseException | None = None
        try:
            _terminate_and_reap(self.proc)
        except BaseException as exc:
            cleanup_error = exc
        finally:
            if capture_output:
                try:
                    with self.qemu_log.open("rb") as log:
                        log.seek(0, os.SEEK_END)
                        log.seek(max(0, log.tell() - 2000))
                        output = log.read().decode(errors="replace")
                except OSError:
                    pass
            try:
                _remove_attempt_artifacts(
                    self.qmp_socket, self.serial_log, self.qemu_log
                )
            except BaseException as unlink_exc:
                if cleanup_error is None:
                    cleanup_error = unlink_exc
        if cleanup_error is not None:
            pid = getattr(self.proc, "pid", "?")
            message = f"Launch cleanup failed for pid {pid}: could not reap child"
            if output:
                message += f"\nQEMU output:\n{output}"
            raise QMUError(message) from cleanup_error
        return output

    def commit(self) -> None:
        self.committed = True


PORT_LOCK_NAME = "ports.lock"
# Below this the lock wait is normal contention; above it, name it so an
# agent timing 8 parallel launches sees where the seconds went.
PORT_LOCK_WAIT_NOTE_SECONDS = 1.0


class PortAllocationLock:
    """`flock` serialising the probe→bind window of concurrent launches (#113).

    `find_free_port` closes its probe socket before QEMU binds, so N launchers
    probing from the same `ssh_port_start` all pick the same first free port
    and N-1 of them lose the bind race (`Could not set up host forwarding
    rule`). The retry loop re-runs the same deterministic search and loses
    again. Holding this lock from allocation until QEMU has bound — the first
    QMP connect succeeding proves it, QEMU sets up hostfwd before it serves
    QMP — makes the next launcher's probe see the port as taken. Only the
    ~1 s allocation window is serialised; flock releases on process death, so a
    launcher killed mid-window cannot wedge its siblings.
    """

    def __init__(self, home: Path) -> None:
        self.path = home / PORT_LOCK_NAME
        self._fd: int | None = None
        self.waited: float = 0.0

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        if self._fd is not None:
            return
        # Same mode as the instance records (mkstemp → 0600).
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        started = time.monotonic()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(fd)
            raise
        self.waited += time.monotonic() - started
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def find_free_port(start: int, max_tries: int = 100) -> int:
    """Find a free TCP port starting from `start`.

    The probe socket is closed before QEMU binds, so the returned port is not
    a reservation: a foreign listener can still take it in between. Against
    *concurrent qmu launches* that window is closed by `PortAllocationLock`,
    which `launch_vm` holds from this probe until QEMU has bound; callers
    outside the lock must be prepared for a launch-time bind failure.
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
            "Use the default 'user' backend, or --no-net, if passt is unavailable.",
            hint="apt install passt; or set [machine] net_backend = \"user\"",
        )

    assert caps.path is not None
    return caps.path


# Stable id linking the implicit rootfs -drive to its -device on machines
# (arm 'virt') where a bare if=virtio does not auto-instantiate a blk device.
_IMPLICIT_ROOTFS_DRIVE_ID = "rootfs"


def _implicit_rootfs_drive_args(rootfs: str, config: QMUConfig) -> list[str]:
    """QEMU args for the synthesized rootfs drive, made arch-aware.

    On QEMU 'virt' machines the guest only sees /dev/vda through a virtio-blk
    topology; a plain -drive yields no block device and boot panics with
    "VFS: Unable to mount root fs on unknown-block(0,0)".

    - x86 (x86_64/i386): unchanged plain drive — the suite pins this argv.
    - aarch64: if=virtio is enough on qemu-system-aarch64 (per issue #26).
    - arm (arm32 virt): if=virtio alone does NOT create the disk on
      qemu-system-arm; split into an if=none backend drive plus an explicit
      virtio-blk-device (per issue #28).
    """
    fmt = config.drive_format
    if config.arch == "aarch64":
        return ["-drive", f"file={rootfs},if=virtio,format={fmt},snapshot=on"]
    if config.arch == "arm":
        return [
            "-drive",
            f"file={rootfs},if=none,format={fmt},"
            f"id={_IMPLICIT_ROOTFS_DRIVE_ID},snapshot=on",
            "-device",
            f"virtio-blk-device,drive={_IMPLICIT_ROOTFS_DRIVE_ID}",
        ]
    return ["-drive", f"file={rootfs},format={fmt},snapshot=on"]


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
        # Configured raw or qcow2 rootfs images sit behind this temporary overlay:
        # in-session checkpoints disappear with QEMU. A durable internal snapshot
        # needs an explicit writable qcow2 drive above, without snapshot=on. The
        # topology is arch-aware so 'virt' machines boot to /dev/vda unassisted.
        cmd.extend(_implicit_rootfs_drive_args(rootfs, config))

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

    # A panicking guest under `panic=N` otherwise reboots into a fresh boot
    # that overwrites the state every post-mortem command reads; boot-and-die
    # harnesses (kernelCTF, syzkaller) rely on QEMU exiting instead. Read
    # from config: `--no-reboot` and `[machine] no_reboot` meet there (#76).
    if config.no_reboot:
        cmd.append("-no-reboot")

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


# Dotted boot params qmu itself ships, or that show up constantly in kernel
# exploit-dev cmdlines. A dotted param NEVER appears in the kernel's "Unknown
# kernel command line parameters" line — the kernel routes `foo.bar=x` to the
# module-param path instead — so `kasan.faul=panic` is silently ignored at boot
# and invisible afterwards. This table exists only to catch near-misses of
# names qmu knows about; unrelated dotted params are left alone.
# Harvested from the kernel tree rather than hand-listed:
#   grep -rhoE 'early_param\("[a-z0-9_.]+"' mm/ kernel/ arch/ drivers/
# The kasan.* family matters most: all three built-in profiles enable KASAN, so
# a typo of any of these is both silently ignored at boot and invisible in the
# log. Shipping only kasan.fault left eight of its nine siblings unguarded.
_KNOWN_DOTTED_PARAMS = frozenset({
    # mm/kasan/{report,hw_tags,tags}.c
    "kasan.fault",
    "kasan.mode",
    "kasan.vmalloc",
    "kasan.write_only",
    "kasan.stacktrace",
    "kasan.stack_ring_size",
    "kasan.page_alloc.sample",
    "kasan.page_alloc.sample.order",
    # mm/kfence
    "kfence.fault",
    "kfence.sample_interval",
    # kernel/
    "cpuhp.parallel",
    # frequently used in exploit-dev cmdlines.
    # Undotted names (slub_debug, init_on_alloc, init_on_free) do NOT belong
    # here: suspect_dotted_params only considers tokens containing a dot, so
    # they could never be matched as known — and as get_close_matches
    # candidates they could only ever produce a WRONG suggestion, proposing an
    # undotted name for a dotted param. The kernel's own unknown-parameter line
    # already reports them, which is the mechanism this table exists to cover
    # for precisely because it cannot see dotted params.
    "net.ifnames",
    "rcupdate.rcu_expedited",
    "rcupdate.rcu_cpu_stall_suppress",
    "vsyscall.emulate",
    "kvm.nx_huge_pages",
    "page_alloc.shuffle",
    # drivers/ and arch/ early_params seen in embedded and arm64 work
    "iommu.passthrough",
    "iommu.strict",
    "iommu.forcedac",
    "iommu.debug_pagealloc",
    "irqchip.gicv3_pseudo_nmi",
    "irqchip.gicv2_force_probe",
    "irqchip.gicv3_nolpi",
    "fw_devlink.strict",
    "fw_devlink.sync_state",
    "random.trust_cpu",
    "random.trust_bootloader",
    "clocksource.arm_arch_timer.evtstrm",
})


def suspect_dotted_params(cmdline: str) -> list[tuple[str, str]]:
    """Return (typo, suggestion) for dotted params that near-miss a known name.

    The cutoff is high on purpose: a legitimate dotted param qmu has never
    heard of (say `nvme.io_queue_depth=4`) is nowhere near any known name and
    is correctly left alone.
    """
    suspects: list[tuple[str, str]] = []
    for token in cmdline.split():
        name = token.split("=", 1)[0]
        if "." not in name or name in _KNOWN_DOTTED_PARAMS:
            continue
        close = get_close_matches(name, _KNOWN_DOTTED_PARAMS, n=1, cutoff=0.85)
        if close:
            suspects.append((name, close[0]))
    return suspects


def resolve_cmdline(
    config: QMUConfig,
    *,
    profile: str = "exploit-dev",
    cmdline: str | None = None,
    append: str | None = None,
) -> str:
    """Resolve the kernel command line from profile, override, and extension.

    `cmdline` replaces the profile wholesale; `append` extends whichever of the
    two won. The distinction matters because every built-in profile carries
    `root=`, so a caller who only wants to add one boot parameter must not be
    forced through `--cmdline` — restating the whole line is how `root=` gets
    dropped by accident.
    """
    if profile not in config.profiles:
        valid = ", ".join(config.profiles.keys())
        raise QMUError(
            f"Unknown profile '{profile}'. Valid: {valid}",
            hint=f"pass one of --profile {valid}, or define [profiles] in qmu.toml",
        )

    resolved = config.profiles[profile] if cmdline is None else cmdline
    if append:
        resolved = f"{resolved} {append}".strip()
    return resolved


def launch_vm(
    *,
    config: QMUConfig,
    kernel: str,
    profile: str = "exploit-dev",
    cmdline: str | None = None,
    append: str | None = None,
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
    notes: list[str] | None = None,
) -> VMInstance:
    """Launch a QEMU VM and return the instance.

    `notes`, when given, collects what a successful launch wants the caller
    to report alongside the instance (the first-QMP-connect retry note); the
    CLI mirrors it into `warnings[]`.
    """
    # Validate files. Provenance only applies when the value is the one the
    # config layer resolved; a caller passing its own string gets no suffix.
    kernel_path = _resolve_boot_file(
        kernel,
        "Kernel",
        config.describe_path_source("kernel") if kernel == config.kernel else "",
    )

    # Only the disk QEMU is actually handed is recorded on the instance:
    # `rootfs inject` holder detection and `status.rootfs` both read it, and a
    # --drive launch that recorded the configured image it never attached was
    # reported as holding an image it did not use (and not holding the one it
    # did). Explicit --drive specs replace the implicit rootfs drive entirely;
    # a harness launch WITHOUT --drive attaches the configured rootfs if it
    # exists (the caller may rely on it for `root=`), so it stays recorded.
    rootfs_path: Path | None = None
    if drives:
        pass
    elif not harness:
        if config.rootfs is None:
            raise QMUError(
                "No rootfs configured. Set [drive] rootfs in qmu.toml or pass --rootfs. "
                "For a boot-and-die kernel (initramfs-only, kernelCTF, syzkaller repro) "
                "pass --harness instead: it needs no rootfs or SSH key and implies "
                "--no-wait-ssh + --no-net.",
                hint="pass --rootfs <image> (or --harness for initramfs-only kernels); "
                     "tools/mkrootfs.sh builds one",
            )
        rootfs_path = Path(config.rootfs).expanduser().resolve()
        if not rootfs_path.exists():
            raise QMUError(
                f"Rootfs image not found: {rootfs_path}"
                f"{config.describe_path_source('rootfs')}",
                hint=f"ls -l {rootfs_path}; qmu config show names the file that set it",
            )
    elif config.rootfs is not None:
        candidate = Path(config.rootfs).expanduser().resolve()
        if candidate.exists():
            rootfs_path = candidate

    key_path: Path | None = None
    if not harness:
        if config.ssh_key is None:
            raise QMUError(
                "No SSH key configured. Set [ssh] key in qmu.toml or pass --ssh-key",
                hint="qmu config init (writes a starter [ssh] key); or pass --ssh-key <key>",
            )
        key_path = Path(config.ssh_key).expanduser().resolve()
        if not key_path.exists():
            raise QMUError(
                f"SSH key not found: {key_path}{config.describe_path_source('ssh_key')}",
                hint=f"ls -l {key_path}; qmu config show names the file that set it",
            )

    initrd_path: Path | None = None
    if initrd is not None:
        initrd_path = _resolve_boot_file(
            initrd,
            "Initrd",
            config.describe_path_source("initrd") if initrd == config.initrd else "",
        )

    cmdline_override = cmdline is not None
    cmdline = resolve_cmdline(config, profile=profile, cmdline=cmdline, append=append)
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
    # --no-net emits `-nic none`, so qmu binds nothing either: an auto-allocated
    # port would be recorded but never owned by this QEMU, and whichever VM was
    # later handed that port would answer `qmu exec --vm <this>` as if it were
    # this guest (the readiness probe is a bare TCP connect). Only a port the
    # caller pinned (to match their own hostfwd in the extra QEMU args) is kept.
    # Otherwise auto-allocate any port the caller did not pin. find_free_port
    # closes its probe before QEMU binds, so `port_lock` is held from the probe
    # until QEMU has bound (first QMP connect) to keep concurrent launches from
    # picking the same port (#113). The retry below stays as a backstop for a
    # foreign listener taking the port. Pinned ports are never re-allocated.
    if harness:
        ssh_port = None
    auto_ssh = (not harness) and (not no_net) and (ssh_port is None)
    auto_gdb = gdb and gdb_port is None
    bind_markers = ("Address already in use", "Could not set up host forwarding", "Failed to bind")

    attempt: _LaunchAttempt | None = None
    pid_start: str | None = None
    cmd: list[str] = []
    port_lock = PortAllocationLock(idir)
    for attempt_idx in range(3):
        try:
            if auto_ssh or auto_gdb:
                port_lock.acquire()
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
                # 'h' = harness, 'n' = --no-net without a pinned SSH port.
                vm_id = f"vm-{'h' if harness else 'n'}{uuid.uuid4().hex[:8]}"
            qmp_path = qmp_socket_path(vm_id)
            serial_path = serial_log_path(vm_id)
            qemu_log = qemu_log_path(vm_id)
            qmp_path.unlink(missing_ok=True)  # remove stale socket if present

            cmd = build_qemu_command(
                config=config,
                kernel=str(kernel_path),
                rootfs=str(rootfs_path) if rootfs_path else None,
                ssh_port=ssh_port,
                gdb_port=gdb_port,
                qmp_socket=str(qmp_path),
                serial_log=str(serial_path),
                cmdline=cmdline,
                initrd=str(initrd_path) if initrd_path else None,
                drives=drives,
                no_net=no_net,
                nic_model=nic_model,
                net_backend=net_backend,
                qemu_binary=resolved_qemu,
                extra_args=extra_args,
            )

            try:
                with qemu_log.open("w") as log_fd:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=log_fd,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        start_new_session=True,
                    )
            except BaseException:
                qemu_log.unlink(missing_ok=True)
                raise

            attempt = _LaunchAttempt(
                proc=proc,
                vm_id=vm_id,
                qmp_socket=qmp_path,
                serial_log=serial_path,
                qemu_log=qemu_log,
            )
            # Record the kernel start-time of the child immediately so liveness
            # checks can detect PID recycling across host reboots. None on
            # platforms without /proc (pid-only fallback applies there).
            pid_start = proc_pid_start(proc.pid)

            # Wait for the QMP socket to appear (or QEMU to exit immediately).
            deadline = time.monotonic() + 10
            exited = False
            while time.monotonic() < deadline:
                if qmp_path.exists():
                    break
                if proc.poll() is not None:
                    exited = True
                    break
                time.sleep(0.2)
            else:
                primary = QMUError("Timed out waiting for QMP socket to appear")
                try:
                    log_text = attempt.rollback(capture_output=True)
                except QMUError as cleanup_exc:
                    raise cleanup_exc from primary
                if log_text:
                    primary = QMUError(
                        f"{primary}\nCommand: {' '.join(cmd)}\nQEMU output:\n{log_text}"
                    )
                raise primary

            qmp_error: Exception | None = None
            if not exited:
                # QMP socket appeared — verify connectivity. A transient reset or
                # refusal on this first connect is retried while QEMU lives; a
                # QEMU that dies meanwhile is reported from its own log.
                exited, qmp_error, qmp_note = _validate_qmp_with_retry(qmp_path, proc)
                if qmp_note is not None and notes is not None:
                    notes.append(qmp_note)
        finally:
            # QEMU has bound its ports (QMP answered) or is gone: either way a
            # sibling's probe now sees the truth, so stop serialising it.
            port_lock.release()
        if port_lock.waited >= PORT_LOCK_WAIT_NOTE_SECONDS and notes is not None:
            notes.append(
                f"Waited {port_lock.waited:.1f}s for the port-allocation lock "
                f"({port_lock.path}) held by a concurrent launch"
            )
            port_lock.waited = 0.0

        if exited:
            # Reap before reading diagnostics so the log is fully flushed.
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                pass
            log_text = ""
            try:
                log_text = qemu_log.read_text(errors="replace")
            except OSError:
                log_text = ""
            bind_failed = any(m in log_text for m in bind_markers)
            retryable = bind_failed and (auto_ssh or auto_gdb) and attempt_idx < 2
            if retryable:
                attempt.rollback()
                attempt = None
                continue  # lost a port race — retry with freshly allocated ports
            lock_note = ""
            if bind_failed and (auto_ssh or auto_gdb):
                # Three allocations under the lock all lost: concurrent qmu
                # launches are excluded, so something outside qmu owns the port.
                lock_note = (
                    f"\nPort bind failed on all 3 attempts while holding "
                    f"{port_lock.path}; concurrent qmu launches are serialised by "
                    "that lock, so a foreign listener (not qmu) holds the port. "
                    "Check `ss -ltnp` or pass --ssh-port/--gdb-port."
                )
            primary = QMUError(
                f"QEMU exited immediately (code {proc.returncode})."
                f"{lock_note}\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output:\n{log_text[-2000:]}"
            )
            try:
                attempt.rollback()
            except QMUError as cleanup_exc:
                raise cleanup_exc from primary
            raise primary

        if qmp_error is not None:
            primary = QMUError(f"QMP connection failed after launch: {qmp_error}")
            primary.__cause__ = qmp_error
            try:
                log_text = attempt.rollback(capture_output=True)
            except QMUError as cleanup_exc:
                raise cleanup_exc from primary
            if log_text:
                primary = QMUError(
                    f"{primary}\nCommand: {' '.join(cmd)}\nQEMU output:\n{log_text}"
                )
            raise primary from qmp_error

        # Build and save instance under the attempt transaction.
        inst = VMInstance(
            vm_id=vm_id,
            pid=proc.pid,
            qmp_socket=str(qmp_path),
            ssh_port=ssh_port,
            ssh_key=str(key_path) if key_path else None,
            ssh_user=config.ssh_user,
            gdb_port=gdb_port,
            serial_log=str(serial_path),
            kernel=str(kernel_path),
            arch=config.arch,
            rootfs=str(rootfs_path) if rootfs_path else None,
            memory=config.memory,
            cpus=config.cpus,
            cmdline=cmdline,
            profile=profile,
            cmdline_override=cmdline_override,
            started_at=datetime.now(timezone.utc).isoformat(),
            harness=harness,
            nic_model=resolved_nic,
            pid_start=pid_start,
            # Record the effective acceleration so `qmu gdb` can surface the
            # hardware-watchpoint caveats that apply under KVM (#39) without
            # re-deriving host state that may have changed since launch. This is
            # the same predicate build_qemu_command used to decide -enable-kvm.
            kvm=config.use_kvm(),
        )
        try:
            save_instance(inst)
        except BaseException as primary:
            try:
                attempt.rollback()
            except QMUError as cleanup_exc:
                raise cleanup_exc from primary
            raise
        attempt.commit()
        return inst

    # Unreachable: the loop always returns or raises. Keep mypy happy.
    raise QMUError("VM launch failed after retries")
