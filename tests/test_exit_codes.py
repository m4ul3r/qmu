"""The one true exit-code map (task contract).

EXIT CODES:
  0   success
  1   operation failed (guest command non-zero, doctor unhealthy, snapshot fail)
  2   usage / argparse error
  3   guest kernel crash OR SSH transport-loss
  4   internal / unexpected qmu error (the main() catch-all AND infra-subprocess
      failures like a pry/gdb hang)
  124 wait timeout

This module pins the boundaries that the task asks to be split/clarified — most
importantly that the main() CATCH-ALL now yields 4 (internal), distinct from 3
(crash). It also re-pins the already-correct 2 (usage) and 124 (wait timeout) so
a regression that renumbers them is caught here.

The catch-all test monkeypatches a handler-internal call (cli.choose_instance)
to raise a *generic* Exception (RuntimeError) that is neither QMUError/QMPError/
SSHError nor KeyboardInterrupt, so it falls through to the bare `except
Exception` in main().

Findings exercised: H2 / exit-code-map.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli


# --- 4: the main() catch-all (internal / unexpected) ------------------------

def test_catch_all_generic_exception_is_exit_4_text(monkeypatch, capsys):
    """A generic (non-QMU/QMP/SSH) exception escaping a handler -> exit 4, NOT 3.

    Exit 3 is reserved for a real kernel crash / SSH transport-loss; an internal
    qmu bug or an infra-subprocess hang must be distinguishable."""
    def boom(vm=None):
        raise RuntimeError("unexpected internal failure")

    monkeypatch.setattr(cli, "choose_instance", boom)
    rc = cli.main(["status"])
    assert rc == 4
    # text mode: error on stderr, not stdout
    err = capsys.readouterr().err
    assert "unexpected internal failure" in err


def test_catch_all_generic_exception_is_exit_4_json(monkeypatch, capsys):
    """Same catch-all under --format json -> exit 4 with the universal error
    envelope on stdout (ok:false / error / error_type)."""
    def boom(vm=None):
        raise RuntimeError("unexpected internal failure")

    monkeypatch.setattr(cli, "choose_instance", boom)
    rc = cli.main(["--format", "json", "status"])
    assert rc == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "RuntimeError"
    assert "unexpected internal failure" in payload["error"]


# --- 2: usage / argparse error ---------------------------------------------

def test_no_subcommand_is_exit_2(capsys):
    rc = cli.main([])
    assert rc == 2


def test_argparse_error_is_exit_2():
    """A genuinely invalid argument exits 2 (argparse raises SystemExit(2))."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["exec", "--format", "not-a-format", "uname"])
    assert exc.value.code == 2


# --- 124: wait timeout ------------------------------------------------------

def test_wait_timeout_is_exit_124(monkeypatch, tmp_path, capsys):
    """`qmu wait --timeout` that never sees a stop -> exit 124.

    Driven without a VM: choose_instance returns a fake still-alive instance, the
    QMP context is stubbed so query-status reports 'running' and wait_event never
    fires, and is_pid_alive stays True so the loop runs to the deadline."""
    from qmu.instance import VMInstance

    inst = VMInstance(
        vm_id="wait-vm",
        pid=4243,
        qmp_socket=str(tmp_path / "wait-vm.qmp.sock"),
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=str(tmp_path / "wait-vm.serial.log"),
        kernel="/boot/bzImage",
        rootfs=None,
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-29T00:00:00Z",
        harness=True,
    )

    class FakeQMP:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, cmd, args=None, timeout=10):
            if cmd == "query-status":
                return {"status": "running"}
            return {}

        def wait_event(self, events, timeout=1.0):
            return None  # never a stop event

    monkeypatch.setattr(cli, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(cli, "_qmp_ctx", lambda i: FakeQMP())
    monkeypatch.setattr(cli, "is_pid_alive", lambda pid: True)

    rc = cli.main(["wait", "--timeout", "0.05"])
    assert rc == 124
