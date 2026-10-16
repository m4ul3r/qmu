"""HMP's own error forms are failures on every route that wraps it.

HMP answers `human-monitor-command` with result TEXT, never a QMP error reply,
so `qmu monitor nonsense-cmd`, `qmu qmp human-monitor-command`, and the
snapshot handlers all used to report `ok:true` / exit 0 around an
"unknown command" or "extraneous characters" line (snapshot audit D3/D4/D8).
One classifier, `qmp.hmp_failed`, decides for all of them.
"""

from __future__ import annotations

import contextlib
import json

import pytest

from qmu import cli
from qmu.commands import qmp_cmds
from qmu.qmp import hmp_failed
from qmu.snapshot import SnapshotResult


@pytest.mark.parametrize(
    "output",
    [
        "unknown command: 'nonsense-cmd'\r\n",
        'savevm: extraneous characters at the end of line\r\nTry "help savevm" for more information',
        "Error: Snapshot 'nope' does not exist in one or more devices",
        "Device 'nosuch' not found",
        "Parameter 'id' is missing",
        "Invalid parameter 'x'",
        "Missing section footer for slirp\nError: Section footer error, section_id: 1",
    ],
)
def test_hmp_error_forms_are_failures(output):
    assert hmp_failed(output) is True


@pytest.mark.parametrize(
    "output",
    [
        "",
        "VM status: running\r\n",
        "warning: Slirp: Save of field slirp_bootpclient/macaddr failed",
        "There is no snapshot available.",
        # "Invalid"/"Parameter" are only error forms at a line start.
        "CPU#0\nRAX=0000000000000000 RBX=... flags Invalid=0\n",
    ],
)
def test_benign_hmp_output_is_not_a_failure(output):
    assert hmp_failed(output) is False


class _Inst:
    vm_id = "dev"
    qmp_socket = "/tmp/nonexistent.sock"
    serial_log = "/tmp/nonexistent.serial.log"
    guest_epoch_serial_offset = 0
    gdb_port = None
    ssh_port = None


class _HmpQMP:
    def __init__(self, result):
        self._result = result

    def execute(self, command, arguments=None, timeout=30.0):
        return self._result

    def execute_hmp(self, command_line, timeout=30.0):
        return self._result


def _install(monkeypatch, result):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _Inst())
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_HmpQMP(result))
    )


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_monitor_unknown_command_exits_1(monkeypatch, capsys, output_format):
    _install(monkeypatch, "unknown command: 'nonsense-cmd'\r\n")
    rc = cli.main(["--format", output_format, "monitor", "nonsense-cmd"])
    captured = capsys.readouterr()
    assert rc == 1
    if output_format == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "QMUError"
        assert "unknown command: 'nonsense-cmd'" in payload["error"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("[qmu] Error: HMP command 'nonsense-cmd' failed")


def test_monitor_benign_output_passes_through(monkeypatch, capsys):
    _install(monkeypatch, "VM status: running\r\n")
    assert cli.main(["--format", "json", "monitor", "info", "status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": True, "output": "VM status: running\r\n"}


def test_monitor_loadvm_failure_names_the_paused_guest(monkeypatch, capsys):
    """The raw route does not restore the run state the way `snapshot load`
    does, so it must at least say what loadvm did to the guest."""
    _install(monkeypatch, "Error: Snapshot 'nope' does not exist in one or more devices")
    assert cli.main(["monitor", "loadvm", "nope"]) == 1
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert "qmu cont" in err


def test_qmp_human_monitor_command_error_text_exits_1(monkeypatch, capsys):
    _install(monkeypatch, "unknown command: 'nonsense-cmd'\r\n")
    rc = cli.main([
        "--format", "json", "qmp", "human-monitor-command",
        "--args", '{"command-line": "nonsense-cmd"}',
    ])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert "unknown command" in payload["error"]


# --- snapshot handlers: failure envelope shape ------------------------------


def _snapshot_seams(monkeypatch, op, result):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _Inst())
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(None))
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, f"{op}_snapshot", lambda qmp, name: result)


@pytest.mark.parametrize("op", ["save", "load", "delete"])
def test_snapshot_failure_envelope_carries_error_and_error_type(monkeypatch, capsys, op):
    _snapshot_seams(monkeypatch, op, SnapshotResult(False, "Error: boom"))
    rc = cli.main(["--format", "json", "snapshot", op, "x", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["error"] == f"snapshot {op} failed: Error: boom"
    assert payload["error_type"] == "SnapshotError"
    assert payload["name"] == "x"
    assert "message" not in payload


@pytest.mark.parametrize("op", ["save", "load", "delete"])
def test_snapshot_failure_text_goes_to_stderr_with_the_error_prefix(monkeypatch, capsys, op):
    _snapshot_seams(monkeypatch, op, SnapshotResult(False, "Error: boom"))
    rc = cli.main(["snapshot", op, "x", "--vm", "dev"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert f"[qmu] Error: snapshot {op} failed: Error: boom" in captured.err


def test_snapshot_load_failure_reports_the_resume(monkeypatch, capsys):
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    _snapshot_seams(monkeypatch, "load", SnapshotResult(False, err, resumed=True))
    rc = cli.main(["--format", "json", "snapshot", "load", "nope", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["resumed"] is True
    assert payload["guest_paused"] is False
    assert "hint" not in payload

    rc = cli.main(["snapshot", "load", "nope", "--vm", "dev"])
    assert rc == 1
    assert "qmu resumed it" in capsys.readouterr().err


def test_snapshot_load_failure_reports_a_stuck_pause_with_the_cont_hint(monkeypatch, capsys):
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    _snapshot_seams(monkeypatch, "load", SnapshotResult(False, err, guest_paused=True))
    rc = cli.main(["--format", "json", "snapshot", "load", "nope", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["resumed"] is False
    assert payload["guest_paused"] is True
    assert "qmu cont --vm dev" in payload["hint"]

    rc = cli.main(["snapshot", "load", "nope", "--vm", "dev"])
    assert rc == 1
    assert "qmu cont --vm dev" in capsys.readouterr().err


def test_snapshot_success_envelope_is_unchanged(monkeypatch, capsys):
    _snapshot_seams(monkeypatch, "delete", SnapshotResult(True, "Snapshot 'x' deleted."))
    rc = cli.main(["--format", "json", "snapshot", "delete", "x", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload == {"ok": True, "name": "x", "message": "Snapshot 'x' deleted."}
