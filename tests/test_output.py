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


def test_marker_failure_removes_incomplete_auto_spill(monkeypatch):
    def fail_marker(_artifact):
        raise OSError("marker full")

    monkeypatch.setattr("qmu.output.mark_spill_artifact", fail_marker)
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
