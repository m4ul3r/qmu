from __future__ import annotations

import re
from typing import Any

from .qmp import QMPClient


def save_snapshot(qmp: QMPClient, name: str, timeout: float = 60.0) -> str:
    """Save a VM snapshot. Returns status message."""
    result = qmp.execute_hmp(f"savevm {name}", timeout=timeout)
    if result.strip():
        return result.strip()
    return f"Snapshot '{name}' saved."


def load_snapshot(qmp: QMPClient, name: str, timeout: float = 60.0) -> str:
    """Load a VM snapshot. Returns status message."""
    result = qmp.execute_hmp(f"loadvm {name}", timeout=timeout)
    if result.strip():
        return result.strip()
    return f"Snapshot '{name}' loaded."


def delete_snapshot(qmp: QMPClient, name: str, timeout: float = 30.0) -> str:
    """Delete a VM snapshot. Returns status message."""
    result = qmp.execute_hmp(f"delvm {name}", timeout=timeout)
    if result.strip():
        return result.strip()
    return f"Snapshot '{name}' deleted."


def list_snapshots(qmp: QMPClient) -> list[dict[str, Any]]:
    """List VM snapshots. Returns parsed list."""
    raw = qmp.execute_hmp("info snapshots")
    return parse_snapshot_list(raw)


def parse_snapshot_list(raw: str) -> list[dict[str, Any]]:
    """Parse 'info snapshots' HMP output into structured data.

    Example HMP output:
        List of snapshots present on all disks:
        ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
        --        clean             913 MiB 2026-03-25 23:42:16 00:00:28.552
    """
    # Regex: ID  TAG  SIZE UNIT  DATE  TIME  VM_CLOCK  [ICOUNT]
    snap_re = re.compile(
        r"^\s*(\S+)\s+(\S+)\s+(\d+\s*\S+)\s+"  # id, tag, vm_size (e.g. "913 MiB")
        r"(\d{4}-\d{2}-\d{2})\s+"                # date
        r"(\d{2}:\d{2}:\d{2})\s+"                # time
        r"(\S+)"                                   # vm_clock
    )
    snapshots: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("List of") or line.startswith("ID"):
            continue
        m = snap_re.match(line)
        if m:
            snapshots.append({
                "id": m.group(1),
                "tag": m.group(2),
                "vm_size": m.group(3).strip(),
                "date": m.group(4),
                "time": m.group(5),
                "vm_clock": m.group(6),
            })
    return snapshots
