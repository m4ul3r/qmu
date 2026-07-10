from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .paths import spill_root
from .runtime import invalidate_owned_spill_marker, mark_spill_artifact


DEFAULT_SPILL_TOKEN_LIMIT = 10_000
# Tokenizer-agnostic estimate: a conservative chars-per-token heuristic that
# does not depend on any model-specific (and network/first-use) tokenizer.
TOKEN_ESTIMATOR = "chars/4"
_CHARS_PER_TOKEN = 4


@dataclass(frozen=True)
class OutputWriteResult:
    rendered: str
    artifact: dict[str, Any] | None = None
    spilled: bool = False


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    return repr(value)


def render_value(value: Any, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(value, indent=2, sort_keys=True, default=_json_default) + "\n"

    if fmt == "ndjson":
        if isinstance(value, list):
            lines = [
                json.dumps(item, sort_keys=True, default=_json_default) for item in value
            ]
            return "\n".join(lines) + ("\n" if lines else "")
        return json.dumps(value, sort_keys=True, default=_json_default) + "\n"

    if isinstance(value, str):
        return value if value.endswith("\n") else value + "\n"
    return json.dumps(value, indent=2, sort_keys=True, default=_json_default) + "\n"


def _summary(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"kind": "object", "keys": sorted(value.keys())[:10], "count": len(value)}
    if isinstance(value, list):
        return {"kind": "array", "count": len(value)}
    if isinstance(value, str):
        return {"kind": "string", "chars": len(value)}
    return {"kind": type(value).__name__}


def _spill_path(stem: str, suffix: str) -> Path:
    now = datetime.now(timezone.utc)
    directory = spill_root() / now.strftime("%Y%m%d")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{stem}-{now.strftime('%H%M%S')}{suffix}"


def _estimate_tokens(rendered: str) -> int:
    return math.ceil(len(rendered) / _CHARS_PER_TOKEN)


def _artifact_payload(
    *,
    artifact_path: Path,
    fmt: str,
    encoded: bytes,
    token_estimate: int,
    value: Any,
) -> dict[str, Any]:
    return {
        "ok": True,
        "artifact_path": str(artifact_path),
        "format": fmt,
        "bytes": len(encoded),
        "token_estimate": token_estimate,
        "estimator": TOKEN_ESTIMATOR,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "summary": _summary(value),
    }


def _artifact_envelope(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_output_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_token_limit: int = DEFAULT_SPILL_TOKEN_LIMIT,
) -> OutputWriteResult:
    rendered = render_value(value, fmt)
    encoded = rendered.encode("utf-8")
    token_estimate = _estimate_tokens(rendered)

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        invalidate_owned_spill_marker(out_path)
        out_path.write_bytes(encoded)
        artifact = _artifact_payload(
            artifact_path=out_path,
            fmt=fmt,
            encoded=encoded,
            token_estimate=token_estimate,
            value=value,
        )
        return OutputWriteResult(
            rendered=_artifact_envelope(artifact),
            artifact=artifact,
            spilled=False,
        )

    if token_estimate <= spill_token_limit:
        return OutputWriteResult(rendered=rendered)

    suffix = ".ndjson" if fmt == "ndjson" else ".txt" if fmt == "text" else ".json"
    spill_path = _spill_path(stem, suffix)
    try:
        spill_path.write_bytes(encoded)
        mark_spill_artifact(spill_path)
    except BaseException:
        spill_path.unlink(missing_ok=True)
        raise
    artifact = _artifact_payload(
        artifact_path=spill_path,
        fmt=fmt,
        encoded=encoded,
        token_estimate=token_estimate,
        value=value,
    )
    return OutputWriteResult(
        rendered=_artifact_envelope(artifact),
        artifact=artifact,
        spilled=True,
    )
