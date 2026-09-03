"""`qmu qmp` accepts both call forms an agent types (#36, 2026-08-22 comment).

QEMU's own documentation shows QMP commands as envelopes
(`{"execute": "query-status"}`), so an agent copies that shape onto the command
line. Before the normalization added here the whole string was sent as the
*method name*: QEMU answered CommandNotFound, the QMPError mapped to exit 4, and
the caller read an infra-failure code for what was a caller-input mistake.

These run offline: choose_instance and _qmp_ctx are stubbed the same way
tests/test_snapshot_exit.py stubs them, and FakeQMP records the (method,
arguments) pair actually handed to the socket layer.
"""

from __future__ import annotations

import contextlib

import pytest

from qmu import cli
from qmu.commands import qmp_cmds


class _FakeInst:
    vm_id = "dev"
    qmp_socket = "/tmp/nonexistent.sock"
    serial_log = "/tmp/nonexistent.serial.log"
    guest_epoch_serial_offset = 0
    gdb_port = 1234


class FakeQMP:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def execute(self, command, args=None):
        self.calls.append((command, args))
        return {"status": "running"}


@pytest.fixture()
def qmp(monkeypatch):
    """Stub the socket layer; the fixture value is the call recorder."""
    fake = FakeQMP()
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _FakeInst())
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(fake)
    )
    # Default: no debugger attached, so the #46 warning stays out of the way.
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    return fake


def test_bare_method_name_is_passed_through(qmp):
    assert cli.main(["qmp", "query-status"]) == 0
    assert qmp.calls == [("query-status", None)]


def test_braceless_envelope_is_normalized(qmp):
    """The exact shape reported on #36: a JSON envelope minus its braces."""
    assert cli.main(["qmp", '"execute":"query-status"']) == 0
    assert qmp.calls == [("query-status", None)]


def test_envelope_arguments_are_taken_from_the_envelope(qmp):
    argv = [
        "qmp",
        '{"execute":"human-monitor-command",'
        '"arguments":{"command-line":"info status"}}',
    ]
    assert cli.main(argv) == 0
    assert qmp.calls == [
        ("human-monitor-command", {"command-line": "info status"})
    ]


def test_arguments_given_twice_is_refused_before_connecting(qmp, capsys):
    argv = [
        "qmp",
        '{"execute":"human-monitor-command","arguments":{"command-line":"x"}}',
        "--args",
        '{"x":1}',
    ]
    assert cli.main(argv) == 1
    err = capsys.readouterr().err
    assert "arguments given twice" in err
    assert qmp.calls == []


@pytest.mark.parametrize("command", ["not json", '{"foo":1}', '{"execute":42}'])
def test_unparseable_command_form_is_a_caller_error(qmp, capsys, command):
    """Exit 1 (caller input), not the exit-4 infra class QEMU's CommandNotFound
    produced when the envelope was sent verbatim as a method name."""
    assert cli.main(["qmp", command]) == 1
    err = capsys.readouterr().err
    assert "pass the bare method name" in err
    assert qmp.calls == []


def test_non_object_envelope_arguments_are_refused(qmp, capsys):
    assert cli.main(["qmp", '{"execute":"cont","arguments":[1,2]}']) == 1
    assert "'arguments' must be a JSON object" in capsys.readouterr().err
    assert qmp.calls == []


def test_reset_warning_follows_the_normalized_method(qmp, monkeypatch, capsys):
    """#46's breakpoint warning was keyed on the raw argv string, so the
    envelope form of system_reset silently skipped it."""
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)
    assert cli.main(["qmp", '{"execute":"system_reset"}']) == 0
    assert qmp.calls == [("system_reset", None)]
    err = capsys.readouterr().err
    assert "breakpoint" in err.lower()


def test_malformed_flag_args_keep_the_friendly_message(qmp, capsys):
    assert cli.main(["qmp", "query-status", "--args", "{oops"]) == 1
    assert "Invalid --args JSON" in capsys.readouterr().err
    assert qmp.calls == []
