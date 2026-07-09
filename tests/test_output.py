"""Tests for qmu.output.write_output_result — spill threshold + artifact envelope.

These tests require NO VM. They use a small explicit spill_token_limit so they
are fast and deterministic. The estimator is tokenizer-AGNOSTIC: a char-based
heuristic (output._estimate_tokens == ceil(len(rendered) / _CHARS_PER_TOKEN),
labelled TOKEN_ESTIMATOR == "chars/4"). No tiktoken / GPT tokenizer is used, and
no network/first-use download is required.

Isolation: TMPDIR is pointed at a tmp dir so the spill_root() ($TMPDIR/qmu-spills)
never touches /tmp/qmu-spills or any shared location.

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


@pytest.fixture(autouse=True)
def isolate_spill_tmpdir(tmp_path, monkeypatch):
    """spill_root() = tempfile.gettempdir()/qmu-spills, which honors $TMPDIR."""
    spill_base = tmp_path / "tmp"
    spill_base.mkdir()
    monkeypatch.setenv("TMPDIR", str(spill_base))
    # tempfile caches the resolved tempdir; clear it so the new TMPDIR applies.
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", None)
    return spill_base


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


def test_above_limit_spills(isolate_spill_tmpdir):
    """token_estimate == limit+1 -> spills to a file under $TMPDIR/qmu-spills."""
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
    # the spill file actually exists, under the isolated TMPDIR
    artifact_path = res.artifact["artifact_path"]
    assert str(isolate_spill_tmpdir) in artifact_path
    assert str(isolate_spill_tmpdir / "qmu-spills") in artifact_path


def test_artifact_envelope_fields_and_integrity(isolate_spill_tmpdir):
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


def test_ndjson_spill_uses_ndjson_suffix(isolate_spill_tmpdir):
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
def test_spill_preserves_false_source_ok(isolate_spill_tmpdir, fmt):
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
