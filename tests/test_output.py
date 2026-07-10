"""Tests for qmu.output.write_output_result — spill threshold + artifact envelope.

These tests require NO VM. They use a small explicit spill_token_limit so they
are fast and deterministic. The estimator is tokenizer-AGNOSTIC: a char-based
heuristic (output._estimate_tokens == ceil(len(rendered) / _CHARS_PER_TOKEN),
labelled TOKEN_ESTIMATOR == "chars/4"). No tiktoken / GPT tokenizer is used, and
no network/first-use download is required.

Isolation: QMU_TEMP_DIR is pointed at a tmp dir so spill_root()
(<QMU_TEMP_DIR>/spills) never touches any shared location.

These tests pin:
  * the char-based estimate (ceil(chars/4)) and the `<=` spill boundary
    (output.py:124) against off-by-one regressions,
  * the artifact-envelope schema (output.py:80-89) the agent parses — including
    the new {token_estimate, estimator} fields (NOT the old GPT tokens/tokenizer),
  * sha256/bytes correctness, and that artifact_path resolves under $TMPDIR.

Findings exercised: TC-6 / TC-7 / OUT-1 / M5 / M4.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qmu.output import (
    TOKEN_ESTIMATOR,
    OutputWriteResult,
    write_output_result,
    render_value,
    _estimate_tokens,
    _CHARS_PER_TOKEN,
)
from qmu.paths import spill_root
from qmu.runtime import SPILL_MARKER_SUFFIX, spill_marker_path


@pytest.fixture(autouse=True)
def isolate_spill_runtime(tmp_path, monkeypatch):
    """Keep automatic spills under a per-test QMU_TEMP_DIR."""
    runtime_base = tmp_path / "runtime"
    monkeypatch.setenv("QMU_TEMP_DIR", str(runtime_base))
    return runtime_base


def _text_with_estimate(n: int) -> str:
    """Build a text-format value (str) whose RENDERED estimate is exactly n.

    estimator = ceil(len(rendered) / _CHARS_PER_TOKEN). render_value(str, 'text')
    appends a trailing '\\n' when absent. A body of (n*_CHARS_PER_TOKEN - 1) 'x'
    chars renders to exactly n*_CHARS_PER_TOKEN chars -> estimate exactly n.
    """
    assert n >= 1
    body = "x" * (n * _CHARS_PER_TOKEN - 1)
    rendered = render_value(body, "text")
    assert len(rendered) == n * _CHARS_PER_TOKEN
    assert _estimate_tokens(rendered) == n, (_estimate_tokens(rendered), n)
    return body  # write_output_result re-renders and re-adds the trailing newline


def test_estimator_is_char_based():
    """The estimator is the tokenizer-agnostic chars/N heuristic, not a GPT/Claude
    tokenizer; ceil rounding is used so any non-empty rendered output is >= 1."""
    assert TOKEN_ESTIMATOR == "chars/4"
    assert _CHARS_PER_TOKEN == 4
    assert _estimate_tokens("") == 0
    assert _estimate_tokens("x") == 1            # ceil(1/4)
    assert _estimate_tokens("x" * 4) == 1        # ceil(4/4)
    assert _estimate_tokens("x" * 5) == 2        # ceil(5/4)


def test_at_limit_is_inline(tmp_path):
    """token_estimate == limit -> inline (the boundary is <=, output.py:124)."""
    limit = 50
    value = _text_with_estimate(limit)
    res = write_output_result(
        value, fmt="text", out_path=None, stem="exec", spill_token_limit=limit
    )
    assert isinstance(res, OutputWriteResult)
    assert res.spilled is False
    assert res.artifact is None
    assert res.rendered == (value + "\n")


def test_below_limit_is_inline(tmp_path):
    limit = 50
    value = _text_with_estimate(limit - 5)
    res = write_output_result(
        value, fmt="text", out_path=None, stem="exec", spill_token_limit=limit
    )
    assert res.spilled is False
    assert res.artifact is None


def test_above_limit_spills(isolate_spill_runtime):
    """token_estimate == limit+1 spills under <QMU_TEMP_DIR>/spills."""
    limit = 50
    value = _text_with_estimate(limit + 1)
    res = write_output_result(
        value, fmt="text", out_path=None, stem="exec", spill_token_limit=limit
    )
    assert res.spilled is True
    assert res.artifact is not None
    # rendered output is the JSON envelope, not the raw value
    envelope = json.loads(res.rendered)
    assert envelope == res.artifact
    # the spill file actually exists under the isolated runtime root
    artifact_path = Path(res.artifact["artifact_path"])
    assert artifact_path.is_relative_to(isolate_spill_runtime / "spills")


def test_auto_spill_writes_valid_ownership_marker():
    value = _text_with_estimate(51)
    result = write_output_result(
        value, fmt="text", out_path=None, stem="exec", spill_token_limit=50
    )
    artifact = Path(result.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    payload = json.loads(marker.read_text())
    assert artifact.is_relative_to(spill_root())
    assert marker.name == artifact.name + SPILL_MARKER_SUFFIX
    assert payload["schema"] == 1
    assert payload["kind"] == "spill"
    assert payload["artifact"] == artifact.name
    assert isinstance(payload["created_at"], float)


def test_marker_binds_identity_and_preserves_replacement_mismatch():
    result = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(result.artifact["artifact_path"])
    payload = json.loads(spill_marker_path(artifact).read_text())
    recorded_identity = {
        field: payload[field]
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    }
    artifact_stat = artifact.stat()
    artifact_identity = {
        field: getattr(artifact_stat, field)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    }
    assert recorded_identity == artifact_identity

    artifact.unlink()
    artifact.write_bytes(b"explicit user replacement")
    replacement_stat = artifact.stat()
    replacement_identity = {
        field: getattr(replacement_stat, field)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    }

    assert recorded_identity != replacement_identity


def test_explicit_out_inside_spill_tree_is_not_marked():
    out = spill_root() / "manual.json"
    result = write_output_result(
        {"large": "x" * 1000},
        fmt="json",
        out_path=out,
        stem="exec",
        spill_token_limit=1,
    )
    assert result.spilled is False
    assert out.exists()
    assert not spill_marker_path(out).exists()


def test_explicit_out_invalidates_only_valid_identity_bound_ownership_marker():
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    payload = json.loads(marker.read_text())
    artifact_stat = artifact.stat()
    assert payload["schema"] == 1
    assert payload["kind"] == "spill"
    assert payload["artifact"] == artifact.name
    assert {
        field: payload[field]
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    } == {
        field: getattr(artifact_stat, field)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    }

    user_value = {"source": "explicit --out"}
    explicit = write_output_result(
        user_value,
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert explicit.spilled is False
    assert artifact.read_bytes() == render_value(user_value, "json").encode("utf-8")
    assert not marker.exists()


def test_explicit_out_preserves_malformed_adjacent_marker():
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    malformed_marker = b'{"schema":'
    marker.write_bytes(malformed_marker)

    explicit_value = {"source": "explicit --out"}
    result = write_output_result(
        explicit_value,
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert result.spilled is False
    assert artifact.read_bytes() == render_value(explicit_value, "json").encode("utf-8")
    assert marker.read_bytes() == malformed_marker


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        pytest.param("schema", 2, id="wrong-schema"),
        pytest.param("kind", "user-output", id="wrong-kind"),
        pytest.param("artifact", "someone-elses-file", id="wrong-artifact"),
    ],
)
def test_explicit_out_preserves_marker_with_invalid_ownership_field(
    field, invalid_value
):
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    payload = json.loads(marker.read_text())
    payload[field] = invalid_value
    invalid_marker = json.dumps(payload, sort_keys=True).encode("utf-8")
    marker.write_bytes(invalid_marker)

    explicit_value = {"source": "explicit --out"}
    result = write_output_result(
        explicit_value,
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert result.spilled is False
    assert marker.read_bytes() == invalid_marker


def test_explicit_out_preserves_identity_mismatched_marker():
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    original_marker = marker.read_bytes()
    artifact.write_bytes(b"user replacement before explicit overwrite")

    explicit_value = {"source": "explicit --out"}
    result = write_output_result(
        explicit_value,
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert result.spilled is False
    assert marker.read_bytes() == original_marker


def test_explicit_out_preserves_symlink_sidecar(tmp_path):
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    marker.unlink()
    user_sidecar = tmp_path / "user-sidecar.json"
    user_sidecar.write_text("user-owned sidecar")
    marker.symlink_to(user_sidecar)

    result = write_output_result(
        {"source": "explicit --out"},
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert result.spilled is False
    assert marker.is_symlink()
    assert marker.read_text() == "user-owned sidecar"


def test_explicit_out_preserves_marker_replaced_after_validation(monkeypatch):
    automatic = write_output_result(
        _text_with_estimate(51),
        fmt="text",
        out_path=None,
        stem="exec",
        spill_token_limit=50,
    )
    artifact = Path(automatic.artifact["artifact_path"])
    marker = spill_marker_path(artifact)
    replacement_marker = b"user replacement after marker validation"
    real_lstat = Path.lstat
    marker_lstats = 0

    def replace_marker_after_validation(path):
        nonlocal marker_lstats
        observed = real_lstat(path)
        if path == marker:
            marker_lstats += 1
            if marker_lstats == 2:
                marker.unlink()
                marker.write_bytes(replacement_marker)
        return observed

    monkeypatch.setattr(Path, "lstat", replace_marker_after_validation)
    explicit_value = {"source": "explicit --out"}
    result = write_output_result(
        explicit_value,
        fmt="json",
        out_path=artifact,
        stem="exec",
        spill_token_limit=1,
    )

    assert result.spilled is False
    assert artifact.read_bytes() == render_value(explicit_value, "json").encode("utf-8")
    assert marker.read_bytes() == replacement_marker


def test_marker_failure_removes_partial_auto_spill_transaction(monkeypatch):

    def write_partial_then_raise(path, *_args, **_kwargs):
        path.write_bytes(b'{"schema":')
        raise OSError("marker full")

    monkeypatch.setattr(Path, "write_text", write_partial_then_raise)
    with pytest.raises(OSError, match="marker full"):
        write_output_result(
            _text_with_estimate(51),
            fmt="text",
            out_path=None,
            stem="exec",
            spill_token_limit=50,
        )

    remaining_files = [
        path.relative_to(spill_root())
        for path in spill_root().rglob("*")
        if path.is_file()
    ]
    assert remaining_files == []


def test_artifact_envelope_fields_and_integrity():
    """The artifact envelope schema is the agent-facing contract: exact keys,
    ok True, the char-based estimator label, and a sha256/bytes that match the
    bytes actually written to disk."""
    limit = 20
    value = _text_with_estimate(limit + 50)
    res = write_output_result(
        value, fmt="text", out_path=None, stem="exec", spill_token_limit=limit
    )
    art = res.artifact
    assert art is not None
    assert set(art.keys()) == {
        "ok",
        "artifact_path",
        "format",
        "bytes",
        "token_estimate",
        "estimator",
        "sha256",
        "summary",
    }
    # the old GPT tokenizer fields must be gone
    assert "tokens" not in art
    assert "tokenizer" not in art
    assert art["ok"] is True
    assert art["format"] == "text"
    assert art["estimator"] == TOKEN_ESTIMATOR == "chars/4"
    assert isinstance(art["token_estimate"], int)

    on_disk = open(art["artifact_path"], "rb").read()
    assert art["bytes"] == len(on_disk)
    assert art["token_estimate"] == _estimate_tokens(on_disk.decode("utf-8"))
    assert art["sha256"] == hashlib.sha256(on_disk).hexdigest()
    assert art["summary"] == {"kind": "string", "chars": len(value)}


def test_out_path_writes_file_and_returns_envelope(tmp_path):
    """When out_path is given, the value is written verbatim and an envelope is
    returned with spilled=False (output.py:108-122)."""
    out = tmp_path / "nested" / "dump.json"
    value = {"exit_code": 0, "stdout": "6.6.75\n", "stderr": ""}
    res = write_output_result(value, fmt="json", out_path=out, stem="exec")
    assert res.spilled is False
    assert res.artifact is not None
    assert out.exists()
    # the file holds the exact rendered json bytes
    assert out.read_bytes() == render_value(value, "json").encode("utf-8")
    assert res.artifact["artifact_path"] == str(out)
    assert res.artifact["format"] == "json"
    assert res.artifact["summary"]["kind"] == "object"


def test_ndjson_spill_uses_ndjson_suffix():
    """A spilled ndjson list is written with a .ndjson suffix (output.py:127)."""
    limit = 5
    value = [{"i": i} for i in range(200)]  # well over 5*4 chars once rendered
    res = write_output_result(
        value, fmt="ndjson", out_path=None, stem="list", spill_token_limit=limit
    )
    assert res.spilled is True
    assert res.artifact["artifact_path"].endswith(".ndjson")
    assert res.artifact["summary"] == {"kind": "array", "count": 200}


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_forced_out_preserves_false_source_ok(tmp_path, fmt):
    out = tmp_path / f"failed.{fmt}"
    value = {"ok": False, "error": "guest command failed"}

    result = write_output_result(value, fmt=fmt, out_path=out, stem="exec")

    envelope = json.loads(result.rendered)
    assert envelope["ok"] is False
    assert json.loads(out.read_text()) == value
    if fmt == "ndjson":
        assert len(result.rendered.splitlines()) == 1


def test_text_forced_out_uses_explicit_false_source_ok(tmp_path):
    out = tmp_path / "failed.txt"

    result = write_output_result(
        "[exit code: 7]",
        fmt="text",
        out_path=out,
        stem="exec",
        source_ok=False,
    )

    assert json.loads(result.rendered)["ok"] is False
    assert out.read_text() == "[exit code: 7]\n"


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_spill_preserves_false_source_ok(isolate_spill_runtime, fmt):
    value = {"ok": False, "error": "x" * 512}

    result = write_output_result(
        value,
        fmt=fmt,
        out_path=None,
        stem="error",
        spill_token_limit=5,
    )

    envelope = json.loads(result.rendered)
    assert result.spilled is True
    assert envelope["ok"] is False
    assert json.loads(Path(envelope["artifact_path"]).read_text()) == value
    if fmt == "ndjson":
        assert len(result.rendered.splitlines()) == 1
