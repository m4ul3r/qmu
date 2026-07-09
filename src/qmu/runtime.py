from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import time
from pathlib import Path

from .paths import spill_root


SPILL_MARKER_SUFFIX = ".qmu-owned.json"
_SPILL_IDENTITY_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
_SPILL_MARKER_FIELDS = frozenset(
    {"schema", "kind", "artifact", "created_at", *_SPILL_IDENTITY_FIELDS}
)


def spill_marker_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + SPILL_MARKER_SUFFIX)

def _same_marker_node(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    )


def _load_regular_marker(
    marker: Path, marker_stat: os.stat_result
) -> dict[str, object] | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(marker, flags), encoding="utf-8") as marker_file:
            opened_stat = os.fstat(marker_file.fileno())
            if not _same_marker_node(marker_stat, opened_stat):
                return None
            payload = json.load(marker_file)
            opened_stat = os.fstat(marker_file.fileno())
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None

    try:
        current_stat = marker.lstat()
    except OSError:
        return None
    if not _same_marker_node(opened_stat, current_stat):
        return None
    return payload if isinstance(payload, dict) else None


def is_owned_spill_artifact(artifact: Path) -> bool:
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

    payload = _load_regular_marker(marker, marker_stat)
    if payload is None or set(payload) != _SPILL_MARKER_FIELDS:
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
    return all(
        type(payload[field]) is int
        and payload[field] == getattr(artifact_stat, field)
        for field in _SPILL_IDENTITY_FIELDS
    )


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
