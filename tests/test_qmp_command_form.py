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
import json

import pytest

from qmu import cli
from qmu.commands import qmp_cmds
from qmu.qmp import QMPClient, QMPCommandError, QMPError


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


@pytest.mark.parametrize(
    "command",
    [
        "not json",
        '{"foo":1}',
        '{"execute":42}',
        # The `fullmatch` clause on envelope["execute"]: the envelope's method
        # is never stripped, so `match` (which stops at the regex's `$` before
        # a trailing newline) let a raw newline ride into the method name on
        # the wire -> CommandNotFound, the exact caller-input-as-infra failure
        # #36 exists to prevent.
        '{"execute": "query-status\\n"}',
        '{"execute": "\\nquery-status"}',
        '{"execute": " query-status"}',
        '{"execute": "query status"}',
        '"execute":"query-status\\n"',
    ],
)
def test_unparseable_command_form_is_a_caller_error(qmp, capsys, command):
    """Exit 1 (caller input), not the exit-4 infra class QEMU's CommandNotFound
    produced when the envelope was sent verbatim as a method name."""
    assert cli.main(["qmp", command]) == 1
    err = capsys.readouterr().err
    assert "pass the bare method name" in err
    assert qmp.calls == []


def test_non_object_envelope_arguments_are_refused(qmp, capsys):
    assert cli.main(["qmp", '{"execute":"cont","arguments":[1,2]}']) == 1
    assert "envelope 'arguments' must be a JSON object" in capsys.readouterr().err
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


def test_trailing_newline_is_stripped_not_matched_as_part_of_the_method(qmp):
    """A trailing newline must not ride along into the QMP method name on the
    wire (that produced CommandNotFound / exit 4, the exact failure #36 exists
    to prevent) -- match() let '$' match before it; fullmatch() on the
    stripped candidate does not."""
    assert cli.main(["qmp", "query-status\n"]) == 0
    assert qmp.calls == [("query-status", None)]


def test_leading_and_trailing_space_is_stripped(qmp):
    """Padded whitespace must not misroute a bare method name into the
    envelope branch, where it would be rejected with advice already followed."""
    assert cli.main(["qmp", "  query-status  "]) == 0
    assert qmp.calls == [("query-status", None)]


def test_envelope_typo_key_is_rejected_not_silently_dropped(qmp, capsys):
    """'argument' (missing the trailing s) must not silently execute with the
    caller's arguments discarded and exit 0 -- that is a wrong answer with
    nothing on stderr.

    The assertion names the actual clause: `"argument" in err` was vacuous
    because _QMP_FORM_HINT itself ends with "arguments go in --args '{...}'",
    so it held for every error this function raises, including the generic
    invalid-form one."""
    argv = ["qmp", '{"execute":"qom-list-types","argument":{"implements":"device"}}']
    assert cli.main(argv) == 1
    err = capsys.readouterr().err
    assert "unknown envelope key(s) argument;" in err
    assert "pass the bare method name" in err
    assert qmp.calls == []


def test_envelope_id_is_rejected_with_a_reason(qmp, capsys):
    """`id` is a real QMP protocol member, so silence is the trap: qmu sends
    one command and returns that reply's payload, so a forwarded id could never
    reach the caller (QMPClient.execute has no id parameter and _recv_response
    unwraps to `return`). Dropping it is the same silent-discard that made a
    mistyped `argument` execute-and-exit-0, so it is refused, and the refusal
    -- not a docstring -- is where the contract is stated."""
    assert cli.main(["qmp", '{"execute":"query-status","id":"req-1"}']) == 1
    err = capsys.readouterr().err
    assert "unknown envelope key(s) id" in err
    assert "nothing to correlate an id against" in err
    assert qmp.calls == []


def test_envelope_contract_is_stated_in_the_help_surface(capsys):
    """An agent reads `qmu qmp --help`, never a Python docstring: the envelope
    form and the id refusal must be visible there."""
    with pytest.raises(SystemExit):
        cli.main(["qmp", "--help"])
    out = capsys.readouterr().out
    assert '{"execute": "query-status"}' in out
    assert "'id' member is REJECTED" in out


def test_non_object_flag_args_name_the_flag_not_the_envelope(qmp, capsys):
    """The array form on the wire made QEMU answer 'arguments must be an
    object', which mapped to exit 4 (QMPError) -- identical to the envelope
    mistake but only that one was caught. Reject both, alike, before
    connecting -- and name the input the caller actually typed: "QMP
    'arguments' must be a JSON object" pointed at an envelope member they never
    supplied, while the sibling error for the same flag says "--args"."""
    assert cli.main(["qmp", "cont", "--args", "[1,2]"]) == 1
    err = capsys.readouterr().err
    assert "Invalid --args JSON: must be a JSON object, got list" in err
    assert "--args '{\"command-line\": \"info status\"}'" in err
    assert "envelope" not in err
    assert qmp.calls == []


# --- QEMU error REPLIES: caller input is exit 1, VM/host state stays 4 ------
#
# `qmu qmp query-staus` used to exit 4 with error_type QMPError (dogfood F1):
# every QEMU error reply collapsed into the transport class, so an agent read
# "infrastructure failure, retry or escalate" for a typo it could have fixed.
# This is the command-NAME/shape half of #36, left open when the command-FORM
# half landed.


class _ErrorQMP:
    """QMP double that answers with a QEMU error reply."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.calls: list[tuple[str, dict | None]] = []

    def execute(self, command, args=None):
        self.calls.append((command, args))
        raise self.exc


@pytest.fixture()
def erroring(monkeypatch):
    """Install a QMP double whose execute() raises the given exception."""

    def install(exc: Exception) -> _ErrorQMP:
        fake = _ErrorQMP(exc)
        monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _FakeInst())
        monkeypatch.setattr(
            qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(fake)
        )
        monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
        return fake

    return install


def test_recv_response_carries_the_qemu_error_class_and_no_inner_prefix(
    monkeypatch,
):
    """Two things at once, both observed live:

    - the reply's `class` must survive out of the socket layer, or the handler
      has nothing to discriminate a typo from a transport fault with;
    - the message must NOT start with "QMP error: ". cli.main renders a
      QMPError under its own "[qmu] QMP error:" heading, so the inner prefix
      produced `[qmu] QMP error: QMP error: The command ... has not been
      found` -- the string an agent regex-matches and pastes into a report.
    """
    client = QMPClient("/tmp/nonexistent.sock")
    monkeypatch.setattr(
        client,
        "_recv_json",
        lambda: {
            "error": {
                "class": "CommandNotFound",
                "desc": "The command query-staus has not been found",
            }
        },
    )
    with pytest.raises(QMPCommandError) as excinfo:
        client._recv_response()
    exc = excinfo.value
    assert exc.qmp_class == "CommandNotFound"
    assert exc.desc == "The command query-staus has not been found"
    assert str(exc) == "The command query-staus has not been found"
    # Every existing `except QMPError` site (liveness probes, kill's
    # best-effort quit) must keep catching this.
    assert isinstance(exc, QMPError)


def test_command_not_found_is_a_caller_error_with_a_correction(erroring, capsys):
    fake = erroring(
        QMPCommandError(
            "The command query-staus has not been found", "CommandNotFound"
        )
    )
    assert cli.main(["qmp", "query-staus"]) == 1
    err = capsys.readouterr().err
    assert "[qmu] Error:" in err
    assert "Unknown QMP command 'query-staus'" in err
    assert "qmu qmp query-commands" in err
    assert fake.calls == [("query-staus", None)]


@pytest.mark.parametrize(
    "desc",
    [
        # Measured from QEMU 8.2.2 -- every shape its QAPI input visitor emits.
        "Parameter 'foo' is unexpected",
        "Parameter 'path' is missing",
        "Parameter 'max-bandwidth' expects uint64",
        "Parameter 'driver' does not accept value 'nope'",
        "Invalid parameter type for 'cpu-index', expected: integer",
        "Invalid parameter 'nope'",
        "QMP input member 'arguments' must be an object",
    ],
)
def test_argument_shape_errors_are_caller_errors(erroring, capsys, desc):
    """Arguments QEMU's schema rejects were decided before it touched VM
    state, so they are the caller's text, not an infra fault."""
    erroring(QMPCommandError(desc, "GenericError"))
    assert cli.main(["qmp", "qom-list"]) == 1
    err = capsys.readouterr().err
    assert "Invalid arguments for QMP command 'qom-list'" in err
    assert desc in err
    assert "QAPI" in err


@pytest.mark.parametrize(
    "qmp_class,desc",
    [
        # Operational GenericErrors: these describe host/VM state, not the
        # command text, so re-classifying them would tell the caller they
        # typo'd something they got right.
        ("GenericError", "failed to open file '/nope/x.ppm': No such file or directory"),
        ("GenericError", "Property 'pc-i440fx-machine.nope' not found"),
        ("GenericError", "File descriptor named 'y' has not been found"),
        ("DeviceNotFound", "Device 'nope' not found"),
        ("KVMMissingCap", "kvm does not support guest debugging"),
    ],
)
def test_state_errors_stay_on_the_infra_exit_code(erroring, capsys, qmp_class, desc):
    erroring(QMPCommandError(desc, qmp_class))
    assert cli.main(["qmp", "screendump"]) == 4
    err = capsys.readouterr().err
    # Exactly one prefix, owned by the CLI.
    assert err.strip() == f"[qmu] QMP error: {desc}"


def test_transport_failure_is_still_exit_4(erroring, capsys):
    """The narrow point of the re-classification: a closed socket must not be
    dragged into the caller-error class along with the typos."""
    erroring(QMPError("QMP connection closed unexpectedly"))
    assert cli.main(["qmp", "query-status"]) == 4
    assert "[qmu] QMP error: QMP connection closed unexpectedly" in (
        capsys.readouterr().err
    )


def test_state_error_json_envelope_names_the_reply_class(erroring, capsys):
    """Same key, same exit code, strictly more specific value: a QEMU error
    REPLY is not a transport fault, and the envelope now says which it was."""
    erroring(QMPCommandError("Device 'nope' not found", "DeviceNotFound"))
    assert cli.main(["--format", "json", "qmp", "device_del"]) == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "QMPCommandError"
    assert payload["error"] == "Device 'nope' not found"


def test_command_not_found_json_envelope_is_the_caller_error_class(
    erroring, capsys
):
    erroring(QMPCommandError("The command x has not been found", "CommandNotFound"))
    assert cli.main(["--format", "json", "qmp", "x"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "QMUError"


def test_hmp_reset_via_human_monitor_command_warns(qmp, monkeypatch, capsys):
    """End-to-end through cli.main: `qmp human-monitor-command` is the third
    route to a machine reset and was the only silent one (dogfood F4)."""
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)
    argv = [
        "qmp",
        '{"execute":"human-monitor-command",'
        '"arguments":{"command-line":"system_reset"}}',
    ]
    assert cli.main(argv) == 0
    assert qmp.calls == [
        ("human-monitor-command", {"command-line": "system_reset"})
    ]
    assert "breakpoint" in capsys.readouterr().err.lower()


def test_malformed_command_is_rejected_before_choosing_the_instance(
    monkeypatch, capsys
):
    """Nothing pinned parse-before-connect: every other test stubs
    choose_instance to succeed. Here it raises, so a malformed command must
    still be an exit-1 caller error, never reach choose_instance/QMP at all."""

    def _boom(vm):
        raise QMPError("dead socket")

    monkeypatch.setattr(qmp_cmds, "choose_instance", _boom)
    assert cli.main(["qmp", "not json"]) == 1
    assert "pass the bare method name" in capsys.readouterr().err
