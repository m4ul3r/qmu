from __future__ import annotations

import json
import os
import signal
import tempfile
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

from .paths import instance_json_path, instances_dir, serial_log_path


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
    # Byte offset at which the currently restored guest generation begins.
    # Zero preserves old instance JSON and includes all bytes from a new launch.
    guest_epoch_serial_offset: int = 0


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

def save_guest_epoch_serial_offset(inst: VMInstance, offset: int) -> VMInstance:
    """Atomically persist an explicitly captured guest-generation boundary."""
    updated = replace(inst, guest_epoch_serial_offset=offset)
    save_instance(updated)
    return updated


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


def remove_instance(vm_id: str, *, keep_logs: bool = False) -> None:
    """Remove instance state files. With keep_logs=True, preserve the logs.

    Both the guest serial log (.serial.log) and QEMU's own stdout/stderr log
    (.qemu.log, written by launch_vm) are treated as logs: dropped by default,
    kept together under keep_logs so post-mortem forensics stay intact.
    """
    idir = instances_dir()
    suffixes = [".json", ".qmp.sock"]
    if not keep_logs:
        suffixes.extend([".serial.log", ".qemu.log"])
    for suffix in suffixes:
        (idir / f"{vm_id}{suffix}").unlink(missing_ok=True)


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
