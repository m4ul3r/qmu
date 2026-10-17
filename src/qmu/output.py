from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
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
    """Create a unique, empty spill file and return its path.

    The name is `<stem>-<HHMMSS>-<random><suffix>` created with O_EXCL via
    mkstemp, so two spills in the same second (two large `exec` results back
    to back) never share a file: the second used to overwrite the first while
    the first envelope still advertised that path and a sha256 that no longer
    matched it.
    """
    now = datetime.now(timezone.utc)
    directory = spill_root() / now.strftime("%Y%m%d")
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        dir=directory, prefix=f"{stem}-{now.strftime('%H%M%S')}-", suffix=suffix
    )
    os.close(fd)
    return Path(name)


def _estimate_tokens(rendered: str) -> int:
    return math.ceil(len(rendered) / _CHARS_PER_TOKEN)


def _source_ok(value: Any, explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    if isinstance(value, dict) and isinstance(value.get("ok"), bool):
        return value["ok"]
    return True


def _artifact_payload(
    *,
    artifact_path: Path,
    fmt: str,
    encoded: bytes,
    token_estimate: int,
    value: Any,
    source_ok: bool,
) -> dict[str, Any]:
    return {
        "ok": source_ok,
        "artifact_path": str(artifact_path),
        "format": fmt,
        "bytes": len(encoded),
        "token_estimate": token_estimate,
        "estimator": TOKEN_ESTIMATOR,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "summary": _summary(value),
    }


def _artifact_envelope(payload: dict[str, Any], fmt: str) -> str:
    return render_value(payload, "ndjson" if fmt == "ndjson" else "json")


# How much of a spilled text result still reaches stdout, so a human or a
# `| head` pipeline sees what the output looked like without opening the file.
# Both bounds apply: a 200 000-character single line (`printf %0200000d`, a
# leak dump with no newlines) is one "line", and a 40-line preview of it put
# the whole output on stdout after the pointer claiming it had been spilled.
TEXT_SPILL_HEAD_LINES = 40
TEXT_SPILL_HEAD_BYTES = 4096


def _text_spill_pointer(payload: dict[str, Any], rendered: str) -> str:
    """Text-mode stand-in for a spilled result: a one-line pointer, a bounded
    head of the output, and a trailer saying how much was left out.

    `--format text` promises text on stdout; the JSON pointer envelope that
    used to appear here broke `qmu exec ... | grep` and read as an error to a
    caller who never asked for JSON. json/ndjson keep their envelopes.
    """
    lines = rendered.splitlines()
    head = "\n".join(lines[:TEXT_SPILL_HEAD_LINES])
    encoded = head.encode("utf-8")
    if len(encoded) > TEXT_SPILL_HEAD_BYTES:
        # Cut on a character boundary: a multibyte sequence split by the byte
        # cap is dropped rather than decoded into U+FFFD.
        head = encoded[:TEXT_SPILL_HEAD_BYTES].decode("utf-8", errors="ignore")
        encoded = head.encode("utf-8")
    shown_lines = head.count("\n") + 1 if head else 0
    total = payload["bytes"]
    pointer = (
        f"[qmu] Output spilled to {payload['artifact_path']} "
        f"(~{payload['token_estimate']} tokens)"
    )
    trailer = (
        f"[qmu] Preview: first {len(encoded)} of {total} bytes "
        f"({total - len(encoded)} omitted; {shown_lines} of {len(lines)} lines)"
    )
    return "\n".join([pointer, head, trailer]) + "\n"


def write_output_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    source_ok: bool | None = None,
    spill_token_limit: int = DEFAULT_SPILL_TOKEN_LIMIT,
) -> OutputWriteResult:
    rendered = render_value(value, fmt)
    encoded = rendered.encode("utf-8")
    token_estimate = _estimate_tokens(rendered)
    artifact_ok = _source_ok(value, source_ok)

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
            source_ok=artifact_ok,
        )
        return OutputWriteResult(
            rendered=_artifact_envelope(artifact, fmt),
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
        source_ok=artifact_ok,
    )
    return OutputWriteResult(
        rendered=(
            _text_spill_pointer(artifact, rendered)
            if fmt == "text"
            else _artifact_envelope(artifact, fmt)
        ),
        artifact=artifact,
        spilled=True,
    )


def write_bytes_result(
    raw: bytes,
    *,
    out_path: Path | None,
    stem: str,
    spill_token_limit: int = DEFAULT_SPILL_TOKEN_LIMIT,
    suffix: str = ".bin",
    source_ok: bool = True,
    exit_code: int | None = None,
) -> OutputWriteResult:
    """Text-mode delivery of a byte payload with NO rendering applied.

    `render_value` appends a newline to a string and the spill/`--out` paths
    write that rendered form, so a file read back through them was never
    checksum-comparable with its source. This variant writes `raw` verbatim:
    inline when it fits the spill budget, otherwise to `out_path`/a spill file
    (named `<stem>-...<suffix>`) exactly, with the usual artifact envelope
    describing the file. The inline `rendered` is a lossy decode for callers
    that can only take text; byte-exact callers write `raw` themselves when
    `artifact` is None. The envelope carries the *source operation's*
    `source_ok` (and its `exit_code` when the caller knows one): writing the
    artifact succeeding says nothing about whether the guest command did.
    """
    rendered = raw.decode("utf-8", errors="replace")
    token_estimate = _estimate_tokens(rendered)
    summary = {"kind": "bytes", "bytes": len(raw)}

    if out_path is None and token_estimate <= spill_token_limit:
        return OutputWriteResult(rendered=rendered)

    spilled = out_path is None
    if out_path is None:
        out_path = _spill_path(stem, suffix)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        invalidate_owned_spill_marker(out_path)
    try:
        out_path.write_bytes(raw)
        if spilled:
            mark_spill_artifact(out_path)
    except BaseException:
        if spilled:
            out_path.unlink(missing_ok=True)
        raise
    artifact = _artifact_payload(
        artifact_path=out_path,
        fmt="text",
        encoded=raw,
        token_estimate=token_estimate,
        value=summary,
        source_ok=source_ok,
    )
    if exit_code is not None:
        artifact["exit_code"] = exit_code
    return OutputWriteResult(
        rendered=(
            _text_spill_pointer(artifact, rendered)
            if spilled
            else _artifact_envelope(artifact, "text")
        ),
        artifact=artifact,
        spilled=spilled,
    )
