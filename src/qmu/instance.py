from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .paths import instance_json_path, instances_dir, qemu_log_path, serial_log_path
from .runtime import probe_unix_socket

_KNOWN_INSTANCE_SUFFIXES = (".serial.log", ".qemu.log", ".qmp.sock", ".json")


class QMUError(RuntimeError):
    pass


@dataclass(kw_only=True)
class VMInstance:
    vm_id: str
    pid: int
    qmp_socket: str
    ssh_port: int | None
    ssh_key: str | None
    # Defaulted so instance JSON written before ssh_user existed still loads
    # (_instance_from_dict omits the absent key and VMInstance supplies "root").
    ssh_user: str = "root"
    gdb_port: int | None
    serial_log: str
    kernel: str
    rootfs: str | None
    memory: str
    cpus: int
    cmdline: str
    profile: str
    started_at: str
    harness: bool = False
    nic_model: str | None = None
    # Kernel start-time of the QEMU process (jiffies since boot, from
    # /proc/<pid>/stat field 22). Used to detect PID recycling across reboots.
    # Defaulted so instance JSON written before this field existed still loads.
    pid_start: str | None = None


def _instance_from_dict(data: dict) -> VMInstance:
    """Tolerant constructor: ignore unknown keys (forward compat for old JSON)."""
    known = {f.name for f in fields(VMInstance)}
    return VMInstance(**{k: v for k, v in data.items() if k in known})


def save_instance(inst: VMInstance) -> Path:
    path = instance_json_path(inst.vm_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file in the SAME dir and os.replace() onto the target so a
    # crash mid-write can never leave a truncated .json that makes a live VM
    # vanish from `qmu list`. os.replace is atomic when src/dst share a fs.
    payload = json.dumps(asdict(inst), indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp, path)
    except BaseException:
        # Don't litter the instances dir with partial temp files on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def load_instance(vm_id: str) -> VMInstance | None:
    path = instance_json_path(vm_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return _instance_from_dict(data)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        # pid 0 signals our own process group; negatives signal a group by id.
        # Neither identifies a single VM process — treat as not alive.
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def proc_pid_start(pid: int) -> str | None:
    """Return the kernel start-time of `pid` (field 22 of /proc/<pid>/stat).

    The comm field (2) is in parentheses and may itself contain spaces or
    parens, so we split on the LAST ')' before tokenizing. Returns None if
    /proc is unavailable (non-Linux) or the process is gone/unreadable.
    """
    if pid <= 0:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    try:
        rest = stat.rsplit(")", 1)[1].split()
        # rest[0] is field 3 (state); field 22 (starttime) is rest[19].
        return rest[19]
    except IndexError:
        return None


def instance_alive(inst: VMInstance) -> bool:
    """Liveness check that guards against PID recycling.

    A recorded pid can be reused by an unrelated process after a reboot (the
    instance JSON outlives the kernel's pid namespace). When the instance has
    a recorded pid_start, require the current /proc start-time to match; if
    /proc is unavailable (non-Linux) or pid_start was never recorded (old
    JSON), fall back to pid-only liveness.
    """
    if inst.pid <= 0:
        return False
    if not is_pid_alive(inst.pid):
        return False
    if inst.pid_start is None:
        return True
    current = proc_pid_start(inst.pid)
    if current is None:
        if not os.path.isdir("/proc"):
            # Non-Linux: /proc not available, cannot verify identity.
            # Fall back to pid-only liveness (already confirmed above).
            return True
        # /proc exists but the stat entry is gone/unreadable: the process
        # most likely exited between the kill(0) probe and this read.
        return False
    return current == inst.pid_start


def _iter_instance_records() -> list[VMInstance]:
    """Read every parseable .json record under instances_dir(). Pure: no filesystem mutation."""
    idir = instances_dir()
    if not idir.exists():
        return []
    out: list[VMInstance] = []
    for p in sorted(idir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            out.append(_instance_from_dict(data))
        except (json.JSONDecodeError, TypeError, KeyError):
            continue
    return out


def list_instances() -> list[VMInstance]:
    """Return VMInstance records whose process is still alive."""
    return [inst for inst in _iter_instance_records() if instance_alive(inst)]


def list_stopped_instances() -> list[VMInstance]:
    """Return VMInstance records whose process has exited.

    Also surfaces orphan serial logs (no .json) by synthesizing a minimal record,
    so users can still recover forensics from a stale .serial.log.
    """
    records = _iter_instance_records()
    stopped = [inst for inst in records if not instance_alive(inst)]
    known_ids = {inst.vm_id for inst in records}

    idir = instances_dir()
    if idir.exists():
        for p in sorted(idir.glob("*.serial.log")):
            vm_id = p.name[: -len(".serial.log")]
            if vm_id in known_ids:
                continue
            stopped.append(_synthesize_orphan(vm_id, p))
    return stopped


def _synthesize_orphan(vm_id: str, log_path: Path) -> VMInstance:
    """Build a minimal VMInstance for a serial log that lost its .json."""
    return VMInstance(
        vm_id=vm_id,
        pid=0,
        qmp_socket="",
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=str(log_path),
        kernel="",
        rootfs=None,
        memory="",
        cpus=0,
        cmdline="",
        profile="",
        started_at="",
        harness=False,
        nic_model=None,
    )


@dataclass(frozen=True, kw_only=True)
class InstanceArtifacts:
    vm_id: str
    instance: VMInstance | None
    invalid_json: bool
    json_path: Path | None
    qmp_socket: Path | None
    serial_log: Path | None
    qemu_log: Path | None


def _match_known_suffix(name: str) -> tuple[str, str] | None:
    """Return (vm_id, suffix) for the longest known exact suffix, else None."""
    for suffix in _KNOWN_INSTANCE_SUFFIXES:
        if name.endswith(suffix):
            vm_id = name[: -len(suffix)]
            if vm_id:
                return vm_id, suffix
    return None


def _is_discoverable_instance_node(mode: int, suffix: str) -> bool:
    """Accept regular files; also accept Unix sockets for the QMP suffix."""
    if stat.S_ISLNK(mode) or stat.S_ISDIR(mode):
        return False
    if stat.S_ISREG(mode):
        return True
    return suffix == ".qmp.sock" and stat.S_ISSOCK(mode)


def discover_instance_artifacts() -> list[InstanceArtifacts]:
    """Group exact known instance suffixes under instances_dir() by VM id.

    Scans only direct children. Directories, symlinks, nested files, and
    unknown suffixes are ignored. JSON is parsed with the tolerant constructor;
    ``invalid_json`` is True only when a ``.json`` path exists but cannot
    produce a ``VMInstance``.
    """
    idir = instances_dir()
    if not idir.exists():
        return []

    grouped: dict[str, dict[str, Path]] = {}
    try:
        children = sorted(idir.iterdir())
    except OSError:
        return []

    for path in children:
        try:
            st = path.lstat()
        except OSError:
            continue
        matched = _match_known_suffix(path.name)
        if matched is None:
            continue
        vm_id, suffix = matched
        if not _is_discoverable_instance_node(st.st_mode, suffix):
            continue
        grouped.setdefault(vm_id, {})[suffix] = path

    bundles: list[InstanceArtifacts] = []
    for vm_id in sorted(grouped):
        paths = grouped[vm_id]
        json_path = paths.get(".json")
        instance: VMInstance | None = None
        invalid_json = False
        if json_path is not None:
            try:
                data = json.loads(json_path.read_text())
                instance = _instance_from_dict(data)
            except (json.JSONDecodeError, TypeError, KeyError, OSError, UnicodeError):
                invalid_json = True
                instance = None
        bundles.append(
            InstanceArtifacts(
                vm_id=vm_id,
                instance=instance,
                invalid_json=invalid_json,
                json_path=json_path,
                qmp_socket=paths.get(".qmp.sock"),
                serial_log=paths.get(".serial.log"),
                qemu_log=paths.get(".qemu.log"),
            )
        )
    return bundles


def _path_mtime(path: Path | None) -> float | None:
    if path is None:
        return None
    try:
        return path.lstat().st_mtime
    except OSError:
        return None


def _bundle_is_age_eligible(
    bundle: InstanceArtifacts, *, cutoff: float
) -> bool:
    """True when every present known artifact is at or older than cutoff."""
    for path in (
        bundle.json_path,
        bundle.qmp_socket,
        bundle.serial_log,
        bundle.qemu_log,
    ):
        mtime = _path_mtime(path)
        if mtime is None:
            # Path listed but unstatable: treat as ineligible.
            if path is not None:
                return False
            continue
        if mtime > cutoff:
            return False
    return True


def _qmp_safe_to_prune(qmp_socket: Path | None) -> bool:
    if qmp_socket is None:
        return True
    try:
        st = qmp_socket.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISSOCK(st.st_mode):
        # Non-socket leftover at the QMP path cannot be a live QMP channel.
        return True
    state = probe_unix_socket(qmp_socket)
    return state in ("stale", "gone")


def list_prunable_instance_ids(
    *, older_than_seconds: float, now: float | None = None
) -> list[str]:
    """Return VM ids whose exact known artifacts are safe to prune.

    Parseable stopped records and serial-only orphans remain immediately
    eligible (no age gate). QEMU-log/QMP-only remnants require every present
    known artifact to be at or older than the cutoff, and any QMP socket must
    probe stale/gone. Live parseable instances and malformed JSON without a
    serial-log recovery path are never returned.
    """
    if not math.isfinite(older_than_seconds) or older_than_seconds < 0:
        raise ValueError("older_than_seconds must be finite and non-negative")
    current_time = time.time() if now is None else now
    if not math.isfinite(current_time):
        raise ValueError("now must be finite")
    cutoff = current_time - older_than_seconds

    eligible: list[str] = []
    for bundle in discover_instance_artifacts():
        if bundle.instance is not None:
            if instance_alive(bundle.instance):
                continue
            # Parseable stopped records prune immediately for compatibility.
            if not _qmp_safe_to_prune(bundle.qmp_socket):
                continue
            eligible.append(bundle.vm_id)
            continue

        if bundle.invalid_json:
            # Unknown identity: only serial-log recovery path is eligible.
            if bundle.serial_log is None:
                continue
            if not _qmp_safe_to_prune(bundle.qmp_socket):
                continue
            eligible.append(bundle.vm_id)
            continue

        # Metadata-free remnant: serial-only stays immediate; qemu/QMP age-gated.
        if (
            bundle.serial_log is not None
            and bundle.qmp_socket is None
            and bundle.qemu_log is None
        ):
            eligible.append(bundle.vm_id)
            continue

        if not _bundle_is_age_eligible(bundle, cutoff=cutoff):
            continue
        if not _qmp_safe_to_prune(bundle.qmp_socket):
            continue
        eligible.append(bundle.vm_id)

    return eligible


def remove_instance(vm_id: str, *, keep_logs: bool = False) -> None:
    """Remove instance state files. With keep_logs=True, preserve the logs.

    Both the guest serial log (.serial.log) and QEMU's own stdout/stderr log
    (.qemu.log, written by launch_vm) are treated as logs: dropped by default,
    kept together under keep_logs so post-mortem forensics stay intact.
    """
    instance_json_path(vm_id).unlink(missing_ok=True)
    (instances_dir() / f"{vm_id}.qmp.sock").unlink(missing_ok=True)
    if not keep_logs:
        serial_log_path(vm_id).unlink(missing_ok=True)
        qemu_log_path(vm_id).unlink(missing_ok=True)


def choose_instance(vm_id: str | None = None) -> VMInstance:
    instances = list_instances()
    if not instances:
        raise QMUError("No running VMs. Start one with: qmu launch --kernel <bzImage>")

    if vm_id is not None:
        for inst in instances:
            if inst.vm_id == vm_id:
                return inst
        names = ", ".join(i.vm_id for i in instances)
        raise QMUError(f"VM '{vm_id}' not found. Running: {names}")

    if len(instances) == 1:
        return instances[0]

    lines = [f"Multiple VMs running. Specify one with --vm <id>:"]
    for inst in instances:
        if inst.harness or inst.ssh_port is None:
            lines.append(f"  {inst.vm_id}  (pid={inst.pid}, harness)")
        else:
            lines.append(f"  {inst.vm_id}  (pid={inst.pid}, ssh={inst.ssh_port})")
    raise QMUError("\n".join(lines))


def find_instance(vm_id: str | None = None) -> VMInstance:
    """Locate a VM whether it's running or stopped. Used by read-only commands."""
    running = list_instances()
    stopped = list_stopped_instances()

    if vm_id is not None:
        for inst in running + stopped:
            if inst.vm_id == vm_id:
                return inst
        raise QMUError(
            f"VM '{vm_id}' not found. "
            f"Running: {', '.join(i.vm_id for i in running) or 'none'}; "
            f"Stopped: {', '.join(i.vm_id for i in stopped) or 'none'}."
        )

    candidates = running + stopped
    if not candidates:
        raise QMUError("No VMs found. Start one with: qmu launch --kernel <bzImage>")
    if len(candidates) == 1:
        return candidates[0]

    lines = ["Multiple VMs found. Specify one with --vm <id>:"]
    for inst in running:
        lines.append(f"  {inst.vm_id}  (pid={inst.pid}, running)")
    for inst in stopped:
        lines.append(f"  {inst.vm_id}  (stopped)")
    raise QMUError("\n".join(lines))
