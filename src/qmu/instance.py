from __future__ import annotations

import json
import os
import signal
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .paths import instance_json_path, instances_dir, serial_log_path


class QMUError(RuntimeError):
    pass


@dataclass
class VMInstance:
    vm_id: str
    pid: int
    qmp_socket: str
    ssh_port: int | None
    ssh_key: str | None
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


def _instance_from_dict(data: dict) -> VMInstance:
    """Tolerant constructor: ignore unknown keys (forward compat for old JSON)."""
    known = {f.name for f in fields(VMInstance)}
    return VMInstance(**{k: v for k, v in data.items() if k in known})


def save_instance(inst: VMInstance) -> Path:
    path = instance_json_path(inst.vm_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(inst), indent=2) + "\n")
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
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


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
    return [inst for inst in _iter_instance_records() if is_pid_alive(inst.pid)]


def list_stopped_instances() -> list[VMInstance]:
    """Return VMInstance records whose process has exited.

    Also surfaces orphan serial logs (no .json) by synthesizing a minimal record,
    so users can still recover forensics from a stale .serial.log.
    """
    records = _iter_instance_records()
    stopped = [inst for inst in records if not is_pid_alive(inst.pid)]
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
    """Remove instance state files. With keep_logs=True, preserve .serial.log."""
    idir = instances_dir()
    suffixes = [".json", ".qmp.sock"]
    if not keep_logs:
        suffixes.append(".serial.log")
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
