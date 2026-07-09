from __future__ import annotations

from dataclasses import dataclass

import json
import math
import os
import socket
import stat
import tempfile
import time
from pathlib import Path
from typing import Literal

from .paths import spill_root, ssh_control_dir


SPILL_MARKER_SUFFIX = ".qmu-owned.json"
_SPILL_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
_SPILL_MARKER_FIELDS = frozenset(
    {"schema", "kind", "artifact", "created_at", *_SPILL_IDENTITY_FIELDS}
)


def spill_marker_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + SPILL_MARKER_SUFFIX)

def _same_file_node(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _load_regular_marker(
    marker: Path, marker_stat: os.stat_result
) -> tuple[dict[str, object], os.stat_result] | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(marker, flags), encoding="utf-8") as marker_file:
            opened_stat = os.fstat(marker_file.fileno())
            if not _same_file_node(marker_stat, opened_stat):
                return None
            payload = json.load(marker_file)
            opened_stat = os.fstat(marker_file.fileno())
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None

    try:
        current_stat = marker.lstat()
    except OSError:
        return None
    if not _same_file_node(opened_stat, current_stat):
        return None
    return (payload, current_stat) if isinstance(payload, dict) else None


def invalidate_owned_spill_marker(artifact: Path) -> bool:
    artifact_name = artifact.name
    if not artifact_name or artifact_name in {".", ".."}:
        return False

    marker = spill_marker_path(artifact)
    try:
        marker_stat = marker.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(marker_stat.st_mode):
        return False

    try:
        root = spill_root().resolve()
        if not artifact.parent.resolve().is_relative_to(root):
            return False
    except OSError:
        return False

    loaded_marker = _load_regular_marker(marker, marker_stat)
    if loaded_marker is None:
        return False
    payload, expected_marker_stat = loaded_marker
    if set(payload) != _SPILL_MARKER_FIELDS:
        return False
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        return False
    if payload["kind"] != "spill" or payload["artifact"] != artifact_name:
        return False
    if type(payload["created_at"]) is not float or not math.isfinite(
        payload["created_at"]
    ):
        return False

    try:
        artifact_stat = artifact.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(artifact_stat.st_mode):
        return False
    if not all(
        type(payload[field]) is int
        and payload[field] == getattr(artifact_stat, field)
        for field in _SPILL_IDENTITY_FIELDS
    ):
        return False

    try:
        current_artifact_stat = artifact.lstat()
        current_marker_stat = marker.lstat()
    except OSError:
        return False
    if not _same_file_node(artifact_stat, current_artifact_stat):
        return False
    if not _same_file_node(expected_marker_stat, current_marker_stat):
        return False
    try:
        marker.unlink()
    except OSError:
        return False
    return True


def mark_spill_artifact(
    artifact: Path, *, created_at: float | None = None
) -> Path:
    artifact_name = artifact.name
    if not artifact_name or artifact_name in {".", ".."}:
        raise ValueError("spill artifact must have a basename")

    root = spill_root().resolve()
    if not artifact.parent.resolve().is_relative_to(root):
        raise ValueError(f"spill artifact must be under {root}")

    artifact_stat = artifact.lstat()
    if not stat.S_ISREG(artifact_stat.st_mode):
        raise ValueError("spill artifact must be a regular file")
    timestamp = time.time() if created_at is None else float(created_at)
    if not math.isfinite(timestamp):
        raise ValueError("spill marker timestamp must be finite")
    marker = spill_marker_path(artifact)
    payload = {
        "schema": 1,
        "kind": "spill",
        "artifact": artifact_name,
        "created_at": timestamp,
        "st_dev": artifact_stat.st_dev,
        "st_ino": artifact_stat.st_ino,
        "st_size": artifact_stat.st_size,
        "st_mtime_ns": artifact_stat.st_mtime_ns,
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=marker.parent,
            prefix=f".{marker.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary = Path(temporary_file.name)
        temporary.write_text(json.dumps(payload), encoding="utf-8")
        temporary.replace(marker)
    except BaseException:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)
        raise
    return marker


SocketState = Literal["live", "stale", "gone", "indeterminate"]
RuntimeArtifactKind = Literal["spill", "ssh-control"]


@dataclass(frozen=True)
class RuntimeArtifact:
    kind: RuntimeArtifactKind
    path: Path
    created_at: float
    marker_path: Path | None = None


@dataclass(frozen=True)
class RuntimePruneResult:
    removed: tuple[RuntimeArtifact, ...]
    skipped_live: tuple[RuntimeArtifact, ...]
    skipped_indeterminate: tuple[RuntimeArtifact, ...]


def probe_unix_socket(path: Path, *, timeout: float = 0.1) -> SocketState:
    try:
        path_stat = path.lstat()
    except FileNotFoundError:
        return "gone"
    except OSError:
        return "indeterminate"
    if not stat.S_ISSOCK(path_stat.st_mode):
        return "indeterminate"
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        return "indeterminate"

    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(path))
    except ConnectionRefusedError:
        return "stale"
    except FileNotFoundError:
        return "gone"
    except OSError:
        return "indeterminate"
    return "live"


def _valid_spill_marker(
    marker: Path,
    root: Path,
) -> tuple[RuntimeArtifact, dict[str, object], os.stat_result] | None:
    try:
        marker_stat = marker.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(marker_stat.st_mode):
        return None

    loaded_marker = _load_regular_marker(marker, marker_stat)
    if loaded_marker is None:
        return None
    payload, expected_marker_stat = loaded_marker
    if set(payload) != _SPILL_MARKER_FIELDS:
        return None
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        return None
    if payload["kind"] != "spill":
        return None

    artifact_name = payload["artifact"]
    expected_name = marker.name[:-len(SPILL_MARKER_SUFFIX)]
    if (
        not isinstance(artifact_name, str)
        or artifact_name != Path(artifact_name).name
        or artifact_name != expected_name
    ):
        return None
    created_at = payload["created_at"]
    if type(created_at) is not float or not math.isfinite(created_at):
        return None
    if not all(type(payload[field]) is int for field in _SPILL_IDENTITY_FIELDS):
        return None

    artifact = marker.with_name(artifact_name)
    try:
        resolved_root = root.resolve()
        if not artifact.parent.resolve().is_relative_to(resolved_root):
            return None
    except OSError:
        return None
    return (
        RuntimeArtifact("spill", artifact, created_at, marker),
        payload,
        expected_marker_stat,
    )


def _marker_is_unchanged(marker: Path, expected: os.stat_result) -> bool:
    try:
        return _same_file_node(expected, marker.lstat())
    except OSError:
        return False


def _artifact_matches_marker(
    artifact_stat: os.stat_result,
    marker_payload: dict[str, object],
) -> bool:
    return stat.S_ISREG(artifact_stat.st_mode) and all(
        marker_payload[field] == getattr(artifact_stat, field)
        for field in _SPILL_IDENTITY_FIELDS
    )


def _remove_empty_owned_date_directory(parent: Path, root: Path) -> None:
    if parent.parent != root or len(parent.name) != 8 or not parent.name.isdigit():
        return
    try:
        parent.rmdir()
    except OSError:
        pass


def _prune_spills(
    root: Path,
    cutoff: float,
    removed: list[RuntimeArtifact],
) -> None:
    markers = sorted(root.rglob(f"*{SPILL_MARKER_SUFFIX}"))
    for marker in markers:
        validated = _valid_spill_marker(marker, root)
        if validated is None:
            continue
        record, marker_payload, expected_marker_stat = validated
        if record.created_at > cutoff:
            continue

        artifact = record.path
        try:
            artifact_stat = artifact.lstat()
        except FileNotFoundError:
            if not _marker_is_unchanged(marker, expected_marker_stat):
                continue
            try:
                marker.unlink()
            except OSError:
                continue
            removed.append(record)
            _remove_empty_owned_date_directory(artifact.parent, root)
            continue
        except OSError:
            continue

        if not _artifact_matches_marker(artifact_stat, marker_payload):
            continue
        if not _marker_is_unchanged(marker, expected_marker_stat):
            continue
        try:
            current_artifact_stat = artifact.lstat()
        except OSError:
            continue
        if not _artifact_matches_marker(current_artifact_stat, marker_payload):
            continue

        try:
            artifact.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            continue
        if not _marker_is_unchanged(marker, expected_marker_stat):
            continue
        try:
            marker.unlink()
        except OSError:
            continue
        removed.append(record)
        _remove_empty_owned_date_directory(artifact.parent, root)


def _control_node_is_unchanged(
    expected: os.stat_result,
    current: os.stat_result,
) -> bool:
    return all(
        getattr(expected, field) == getattr(current, field)
        for field in ("st_dev", "st_ino", "st_mode")
    )


def _prune_ssh_controls(
    root: Path,
    cutoff: float,
    removed: list[RuntimeArtifact],
    skipped_live: list[RuntimeArtifact],
    skipped_indeterminate: list[RuntimeArtifact],
) -> None:
    try:
        candidates = sorted(root.iterdir())
    except OSError:
        return
    for path in candidates:
        if not path.name.startswith("cm-"):
            continue
        try:
            path_stat = path.lstat()
        except OSError:
            continue
        if not stat.S_ISSOCK(path_stat.st_mode) or path_stat.st_mtime > cutoff:
            continue

        record = RuntimeArtifact("ssh-control", path, path_stat.st_mtime)
        state = probe_unix_socket(path)
        if state == "live":
            skipped_live.append(record)
            continue
        if state == "indeterminate":
            skipped_indeterminate.append(record)
            continue
        if state == "gone":
            continue

        # A bound socket may begin listening without changing its inode. Probe
        # again immediately before the identity check so a newly live master is
        # preserved rather than unlinked based on an earlier refusal.
        state = probe_unix_socket(path)
        if state == "live":
            skipped_live.append(record)
            continue
        if state == "indeterminate":
            skipped_indeterminate.append(record)
            continue
        if state == "gone":
            continue

        try:
            current_stat = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            skipped_indeterminate.append(record)
            continue
        if not _control_node_is_unchanged(path_stat, current_stat):
            skipped_indeterminate.append(record)
            continue
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            skipped_indeterminate.append(record)
            continue
        removed.append(record)


def prune_runtime_artifacts(
    *,
    older_than_seconds: float,
    now: float | None = None,
) -> RuntimePruneResult:
    if not math.isfinite(older_than_seconds) or older_than_seconds < 0:
        raise ValueError("older_than_seconds must be finite and non-negative")
    current_time = time.time() if now is None else now
    if not math.isfinite(current_time):
        raise ValueError("now must be finite")
    cutoff = current_time - older_than_seconds
    removed: list[RuntimeArtifact] = []
    skipped_live: list[RuntimeArtifact] = []
    skipped_indeterminate: list[RuntimeArtifact] = []

    _prune_spills(spill_root(), cutoff, removed)
    _prune_ssh_controls(
        ssh_control_dir(),
        cutoff,
        removed,
        skipped_live,
        skipped_indeterminate,
    )
    return RuntimePruneResult(
        tuple(removed),
        tuple(skipped_live),
        tuple(skipped_indeterminate),
    )
