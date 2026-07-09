from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from .paths import spill_root


SPILL_MARKER_SUFFIX = ".qmu-owned.json"


def spill_marker_path(artifact: Path) -> Path:
    return artifact.with_name(artifact.name + SPILL_MARKER_SUFFIX)


def mark_spill_artifact(
    artifact: Path, *, created_at: float | None = None
) -> Path:
    artifact_name = artifact.name
    if not artifact_name or artifact_name in {".", ".."}:
        raise ValueError("spill artifact must have a basename")

    root = spill_root().resolve()
    if not artifact.parent.resolve().is_relative_to(root):
        raise ValueError(f"spill artifact must be under {root}")

    artifact_stat = artifact.stat()
    marker = spill_marker_path(artifact)
    payload = {
        "schema": 1,
        "kind": "spill",
        "artifact": artifact_name,
        "created_at": time.time() if created_at is None else float(created_at),
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
