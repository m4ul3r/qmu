"""The universal JSON result contract (task contract).

When --format != text, EVERY command's result is a JSON OBJECT containing
"ok": <bool>:

  * success  -> {"ok": true, ...}
  * error    -> {"ok": false, "error": "<message>", "error_type": "<ExcClass>"}
               emitted to STDOUT, with the exit code from the one-true map.

Text mode is unchanged: errors stay on STDERR as "[qmu] Error: ...".

These tests are deliberately VM-free. The error-envelope tests trigger a real
QMUError on the common path (`qmu status` with no running VM -> choose_instance
raises QMUError); the autouse isolate_qmu_env fixture (conftest.py) guarantees
there are no instances. The universal-ok test parametrizes representative
commands that produce a JSON SUCCESS result without a VM.

Findings exercised: H3 (JSON error contract) / universal-ok / M2.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import QMUError


# --- error envelope: QMUError under --format json --------------------------

def test_qmu_error_json_emits_ok_false_envelope_on_stdout(capsys):
    """`qmu status --format json` with no VM -> QMUError -> a parseable JSON
    object on STDOUT with ok:false/error/error_type, exit 1.

    (Per the map, an operation failure such as 'no VM' is exit 1. The point of
    this test is the JSON ENVELOPE shape on the common error path, which the old
    code emitted as plain text + exit 2 even under --format json.)"""
    rc = cli.main(["--format", "json", "status"])
    captured = capsys.readouterr()
    # stdout must be a JSON object, not the plain "[qmu] Error" text.
    payload = json.loads(captured.out)
    assert payload["ok"] is False
    assert payload["error_type"] == "QMUError"
    assert payload["error"]  # non-empty message
    assert "No running VMs" in payload["error"]
    # the JSON envelope goes to stdout; stderr is not the carrier under json mode
    assert "{" not in captured.err
    assert rc != 0


def test_qmu_error_text_mode_goes_to_stderr(capsys):
    """Text mode keeps the existing behavior: '[qmu] Error: ...' on STDERR, and
    stdout is NOT a JSON envelope."""
    rc = cli.main(["status"])
    captured = capsys.readouterr()
    assert "[qmu] Error:" in captured.err
    assert "No running VMs" in captured.err
    # no JSON envelope on stdout in text mode
    assert captured.out.strip() == "" or "ok" not in captured.out
    assert rc != 0


def test_qmp_error_json_carries_error_type(monkeypatch, capsys):
    """A QMPError escaping a handler under --format json -> ok:false envelope
    with error_type 'QMPError'."""
    from qmu.qmp import QMPError

    def boom(vm=None):
        raise QMPError("qmp socket vanished")

    monkeypatch.setattr(lifecycle, "choose_instance", boom)
    rc = cli.main(["--format", "json", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "QMPError"
    assert "qmp socket vanished" in payload["error"]
    assert rc != 0


def test_ssh_error_json_carries_error_type(monkeypatch, capsys):
    """An SSHError escaping a handler under --format json -> ok:false envelope
    with error_type 'SSHError'."""
    from qmu.ssh import SSHError

    def boom(vm=None):
        raise SSHError("ssh transport gone")

    monkeypatch.setattr(lifecycle, "choose_instance", boom)
    rc = cli.main(["--format", "json", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert "ssh transport gone" in payload["error"]
    assert rc != 0


# --- universal ok on the SUCCESS path --------------------------------------

# Representative commands that produce a JSON success result WITHOUT a VM. Each
# must emit a JSON object carrying "ok" (the single success predicate an agent
# can rely on across every command).
_UNIVERSAL_OK_CMDS = [
    pytest.param(["--format", "json", "list"], id="list-empty"),
    pytest.param(["--format", "json", "config", "show"], id="config-show"),
    pytest.param(["--format", "json", "config", "path"], id="config-path"),
    pytest.param(["--format", "json", "version"], id="version"),
    pytest.param(["--format", "json", "doctor"], id="doctor"),
]


@pytest.mark.parametrize("argv", _UNIVERSAL_OK_CMDS)
def test_success_json_results_carry_ok(argv, capsys):
    """Every representative --format json SUCCESS result is a JSON object with an
    'ok' key. These run with no VM so they are deterministic."""
    cli.main(argv)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert isinstance(payload, dict), f"{argv} did not emit a JSON object: {out!r}"
    assert "ok" in payload, f"{argv} result missing 'ok': {payload!r}"
    assert isinstance(payload["ok"], bool)
