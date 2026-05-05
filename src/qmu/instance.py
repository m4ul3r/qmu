from __future__ import annotations

import json
import os
import signal
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from .paths import instance_json_path, instances_dir


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


def list_instances() -> list[VMInstance]:
    idir = instances_dir()
    if not idir.exists():
        return []
    live: list[VMInstance] = []
    for p in sorted(idir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            inst = _instance_from_dict(data)
        except (json.JSONDecodeError, TypeError, KeyError):
            p.unlink(missing_ok=True)
            continue
        if is_pid_alive(inst.pid):
            live.append(inst)
        else:
            # Stale — clean up
            p.unlink(missing_ok=True)
            for suffix in (".qmp.sock", ".serial.log"):
                stale = idir / f"{inst.vm_id}{suffix}"
                stale.unlink(missing_ok=True)
    return live


def remove_instance(vm_id: str) -> None:
    idir = instances_dir()
    for suffix in (".json", ".qmp.sock", ".serial.log"):
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
