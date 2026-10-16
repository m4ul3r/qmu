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


# Result DATA that carries error words: a snapshot tagged `Error:checkpoint`
# (receipt 089/099 verbatim), tags spelled like error forms, and a table
# cell that says "not found". None of these is a QEMU diagnostic, and the
# unanchored substring classifier made `qmu monitor 'info snapshots'` exit 1
# on the first one while `qmu snapshot list` on the same VM exited 0 (#86).
ERROR_TAG_TABLE = (
    "List of snapshots present on all disks:\r\n"
    "ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT\r\n"
    "--        Error:checkpoint  819 MiB 2026-10-16 16:51:32 00:00:06.409           \r\n"
    "--        large            1.36 GiB 2026-10-16 16:51:42 00:00:15.084"
)


@pytest.mark.parametrize(
    "output",
    [
        "",
        "VM status: running\r\n",
        "warning: Slirp: Save of field slirp_bootpclient/macaddr failed",
        "There is no snapshot available.",
        # "Invalid"/"Parameter" are only error forms at a line start.
        "CPU#0\nRAX=0000000000000000 RBX=... flags Invalid=0\n",
        ERROR_TAG_TABLE,
        "List of snapshots present on all disks:\r\n"
        "ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT\r\n"
        "--        does-not-exist    819 MiB 2026-10-16 16:51:32 00:00:06.409\r\n"
        "--        invalid-state     819 MiB 2026-10-16 16:51:33 00:00:07.409\r\n"
        "--        unknown-command   819 MiB 2026-10-16 16:51:34 00:00:08.409",
        "ide0-hd0 (#block123): /tmp/not found/disk.qcow2 (qcow2)\n"
        "    Cache mode:       writeback\n",
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


def test_monitor_loadvm_pre_restore_failure_names_the_paused_guest(monkeypatch, capsys):
    """The raw route does not restore the run state the way `snapshot load`
    does, so it must at least say what loadvm did to the guest -- and for a
    refusal QEMU made before restoring anything, `qmu cont` is the fix."""
    _install(monkeypatch, "Error: Snapshot 'nope' does not exist in one or more devices")
    assert cli.main(["monitor", "loadvm", "nope"]) == 1
    err = capsys.readouterr().err
    assert "does not exist" in err
    assert "qmu cont" in err


def test_monitor_loadvm_partial_failure_does_not_offer_cont(monkeypatch, capsys):
    """#87 on the raw route: past the tag check loadvm has reverted the disks,
    so `qmu cont` would run an inconsistent machine; the hint must name the
    recovery (another snapshot / kill) and not the resume."""
    _install(monkeypatch, "Error: Error -22 while loading VM state")
    assert cli.main(["--format", "json", "monitor", "loadvm", "clean"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "Error -22 while loading VM state" in payload["error"]
    assert "resume with `qmu cont`" not in payload["error"]
    assert "qmu kill" in payload["error"]


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_every_hmp_route_agrees_error_words_in_data_are_not_a_failure(
    monkeypatch, capsys, output_format
):
    """#86: `snapshot list`, `monitor 'info snapshots'` and `qmp
    human-monitor-command` read the SAME table; one exiting 0 and the others
    1 on a tag named `Error:checkpoint` is sibling disagreement, and the
    table is data either way."""
    _install(monkeypatch, ERROR_TAG_TABLE)
    argvs = {
        "snapshot list": ["snapshot", "list"],
        "monitor": ["monitor", "info", "snapshots"],
        "qmp human-monitor-command": [
            "qmp", "human-monitor-command",
            "--args", '{"command-line": "info snapshots"}',
        ],
    }
    for command, argv in argvs.items():
        rc = cli.main(["--format", output_format, *argv])
        captured = capsys.readouterr()
        assert rc == 0, f"`qmu {command}` exit {rc}: {captured.out}{captured.err}"
        if output_format == "json":
            payload = json.loads(captured.out)
            assert payload["ok"] is True, command
            if command == "snapshot list":
                assert [s["tag"] for s in payload["snapshots"]] == ["Error:checkpoint", "large"]
            else:
                assert payload.get("output", payload.get("result")) == ERROR_TAG_TABLE
        else:
            assert "Error:checkpoint" in captured.out, command
            assert captured.err == "", command


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
    _snapshot_seams(
        monkeypatch, "load", SnapshotResult(False, err, resumed=True, reason="missing")
    )
    rc = cli.main(["--format", "json", "snapshot", "load", "nope", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["resumed"] is True
    assert payload["guest_paused"] is False
    # Every SnapshotError carries the fix; the resume is a note, not the hint.
    assert "qmu snapshot list --vm dev" in payload["hint"]

    rc = cli.main(["snapshot", "load", "nope", "--vm", "dev"])
    assert rc == 1
    assert "qmu resumed it" in capsys.readouterr().err


def test_snapshot_load_failure_reports_a_stuck_pause_with_the_cont_hint(monkeypatch, capsys):
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    _snapshot_seams(
        monkeypatch, "load",
        SnapshotResult(False, err, guest_paused=True, reason="missing", restore_state="none"),
    )
    rc = cli.main(["--format", "json", "snapshot", "load", "nope", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["resumed"] is False
    assert payload["guest_paused"] is True
    assert payload["restore_state"] == "none"
    assert payload["hint"].startswith("loadvm left the guest paused")
    assert "qmu cont --vm dev" in payload["hint"]

    rc = cli.main(["snapshot", "load", "nope", "--vm", "dev"])
    assert rc == 1
    assert "qmu cont --vm dev" in capsys.readouterr().err


@pytest.mark.parametrize("restore_state", ["partial", "unknown"])
def test_snapshot_load_failure_after_restoration_began_never_offers_cont(
    monkeypatch, capsys, restore_state
):
    """#87: the envelope says the guest is paused AND why `cont` is wrong;
    the recovery it names is another snapshot or a relaunch."""
    err = "Error: Error -22 while loading VM state"
    _snapshot_seams(
        monkeypatch, "load",
        SnapshotResult(
            False, err, guest_paused=True, reason="hmp", restore_state=restore_state
        ),
    )
    rc = cli.main(["--format", "json", "snapshot", "load", "clean", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["error_type"] == "SnapshotError"
    assert payload["resumed"] is False
    assert payload["guest_paused"] is True
    assert payload["restore_state"] == restore_state
    assert "Resume with" not in payload["hint"]
    assert "qmu snapshot load <tag> --vm dev" in payload["hint"]
    assert "qmu kill --vm dev" in payload["hint"]

    rc = cli.main(["snapshot", "load", "clean", "--vm", "dev"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    assert "qmu kill --vm dev" in captured.err
    assert "Resume with" not in captured.err


@pytest.mark.parametrize("op", ["load", "delete"])
def test_snapshot_missing_tag_hint_points_at_snapshot_list(monkeypatch, capsys, op):
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    _snapshot_seams(monkeypatch, op, SnapshotResult(False, err, reason="missing"))
    rc = cli.main(["--format", "json", "snapshot", op, "nope", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["error_type"] == "SnapshotError"
    assert "qmu snapshot list --vm dev" in payload["hint"]

    rc = cli.main(["snapshot", op, "nope", "--vm", "dev"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == ""
    error_line, hint_line = [
        line for line in captured.err.splitlines() if line.startswith("[qmu]")
    ][:2]
    assert error_line.startswith(f"[qmu] Error: snapshot {op} failed:")
    assert "qmu snapshot list --vm dev" in hint_line


def test_snapshot_save_bad_name_hint_names_the_one_token_rule(monkeypatch, capsys):
    err = "savevm: extraneous characters at the end of line"
    _snapshot_seams(monkeypatch, "save", SnapshotResult(False, err, reason="bad_name"))
    rc = cli.main(["--format", "json", "snapshot", "save", "has space", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert "cannot contain whitespace" in payload["hint"]
    assert "'has-space'" in payload["hint"]


@pytest.mark.parametrize("op", ["save", "load", "delete"])
def test_snapshot_other_hmp_failure_hint_points_at_info_snapshots(monkeypatch, capsys, op):
    _snapshot_seams(monkeypatch, op, SnapshotResult(False, "Error: boom", reason="hmp"))
    rc = cli.main(["--format", "json", "snapshot", op, "x", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["hint"] == (
        "Inspect the image's snapshot table with: qmu monitor 'info snapshots' --vm dev"
    )


def test_snapshot_success_envelope_is_unchanged(monkeypatch, capsys):
    _snapshot_seams(monkeypatch, "delete", SnapshotResult(True, "Snapshot 'x' deleted."))
    rc = cli.main(["--format", "json", "snapshot", "delete", "x", "--vm", "dev"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload == {"ok": True, "name": "x", "message": "Snapshot 'x' deleted."}
