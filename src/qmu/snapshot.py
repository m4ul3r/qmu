from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .qmp import QMPClient, QMPError, hmp_failed


@dataclass(frozen=True)
class SnapshotResult:
    """Outcome of one HMP snapshot operation.

    `message` is the HMP text verbatim when QEMU printed any, else a
    synthesized success line. The two run-state flags only ever apply to a
    FAILED load: QEMU's `hmp_loadvm` stops the guest (`restore-vm`) before it
    looks for the tag and only restarts it on success, so a typo'd name leaves
    a previously running guest paused with no error saying so. qmu owns the
    operation and the pre-load state, so it resumes the guest (`resumed`) or,
    if that failed too, says the guest is paused (`guest_paused`) instead of
    letting every later SSH command time out against a stopped vCPU.
    """

    ok: bool
    message: str
    resumed: bool = False
    guest_paused: bool = False


def guest_running(qmp: QMPClient) -> bool | None:
    """QMP `query-status` `running` flag; None when it cannot be read."""
    try:
        status = qmp.execute("query-status")
    except QMPError:
        return None
    if not isinstance(status, dict):
        return None
    running = status.get("running")
    return running if isinstance(running, bool) else None


def resume_guest(qmp: QMPClient) -> bool:
    """Issue QMP `cont`; True when the guest is positively running afterwards."""
    try:
        qmp.execute("cont")
    except QMPError:
        return False
    return guest_running(qmp) is True


def snapshot_tags(qmp: QMPClient) -> set[str]:
    return {snap["tag"] for snap in list_snapshots(qmp)}


def save_snapshot(qmp: QMPClient, name: str, timeout: float = 60.0) -> SnapshotResult:
    """Save a VM snapshot and confirm it is listed afterwards.

    HMP parse errors (`savevm: extraneous characters at the end of line` for
    a name with whitespace) come back as result text with no snapshot written,
    so the result is cross-checked against `info snapshots` rather than
    trusting a reply that merely arrived.
    """
    result = qmp.execute_hmp(f"savevm {name}", timeout=timeout).strip()
    if hmp_failed(result):
        return SnapshotResult(False, result)
    if name not in snapshot_tags(qmp):
        return SnapshotResult(
            False,
            result or f"Snapshot '{name}' is not listed by 'info snapshots' after savevm",
        )
    return SnapshotResult(True, result or f"Snapshot '{name}' saved.")


def load_snapshot(qmp: QMPClient, name: str, timeout: float = 60.0) -> SnapshotResult:
    """Load a VM snapshot, restoring the pre-load run state if loadvm fails."""
    was_running = guest_running(qmp)
    result = qmp.execute_hmp(f"loadvm {name}", timeout=timeout).strip()
    if not hmp_failed(result):
        return SnapshotResult(True, result or f"Snapshot '{name}' loaded.")
    resumed = guest_paused = False
    if was_running and guest_running(qmp) is False:
        resumed = resume_guest(qmp)
        guest_paused = not resumed
    return SnapshotResult(False, result, resumed=resumed, guest_paused=guest_paused)


def delete_snapshot(qmp: QMPClient, name: str, timeout: float = 30.0) -> SnapshotResult:
    """Delete a VM snapshot. HMP `delvm` is silent for a missing tag, so the
    tag is checked against `info snapshots` first."""
    if name not in snapshot_tags(qmp):
        return SnapshotResult(False, f"Snapshot '{name}' does not exist")
    result = qmp.execute_hmp(f"delvm {name}", timeout=timeout).strip()
    if hmp_failed(result):
        return SnapshotResult(False, result)
    return SnapshotResult(True, result or f"Snapshot '{name}' deleted.")


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
