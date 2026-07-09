from __future__ import annotations

import json
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

    marker = spill_marker_path(artifact)
    payload = {
        "schema": 1,
        "kind": "spill",
        "artifact": artifact_name,
        "created_at": time.time() if created_at is None else float(created_at),
    }
    marker.write_text(json.dumps(payload), encoding="utf-8")
    return marker
