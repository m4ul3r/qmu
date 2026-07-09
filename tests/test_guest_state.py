from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from qmu import _cliutil, cli
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.qmp import QMPError


CASES = ("push", "pull", "exec", "compile", "dmesg")


def _instance(tmp_path) -> VMInstance:
    return VMInstance(
        vm_id="state-vm",
        pid=4242,
        qmp_socket=str(tmp_path / "state-vm.qmp.sock"),
        ssh_port=10099,
        ssh_key=str(tmp_path / "state-vm.key"),
        gdb_port=1234,
        serial_log=str(tmp_path / "state-vm.serial.log"),
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        harness=False,
    )


def _case(case: str, tmp_path, fmt: str):
    source = tmp_path / "x.c"
    source.write_text("int main(void) { return 0; }\n")
    destination = tmp_path / "pulled"
    if case == "push":
        return (
            ["--format", fmt, "push", "--vm", "state-vm", str(source), "/root/x.c"],
            [("ssh", "push", str(source), "/root/x.c")],
        )
    if case == "pull":
        return (
            ["--format", fmt, "pull", "--vm", "state-vm", "/root/x", str(destination)],
            [("ssh", "pull", "/root/x", str(destination))],
        )
    if case == "exec":
        return (
            ["--format", fmt, "exec", "--vm", "state-vm", "true"],
            [("ssh", "run", "true", 30.0)],
        )
    if case == "compile":
        return (
            ["--format", fmt, "compile", "--vm", "state-vm", str(source)],
            [
                ("ssh", "push", str(source), "/root/x.c"),
                ("ssh", "run", "gcc -static -lpthread -o /root/x /root/x.c", 30),
            ],
        )
    if case == "dmesg":
        return (
            ["--format", fmt, "dmesg", "--vm", "state-vm"],
            [("ssh", "run", "dmesg", 15)],
        )
    raise AssertionError(f"unknown case: {case}")


class FakeQMP:
    def __init__(self, trace, *, status="running", enter_error=None, execute_error=None):
        self.trace = trace
        self.status = status
        self.enter_error = enter_error
        self.execute_error = execute_error

    def __enter__(self):
        self.trace.append(("qmp", "enter"))
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command):
        self.trace.append(("qmp", command))
        if self.execute_error is not None:
            raise self.execute_error
        assert command == "query-status"
        return {"running": self.status == "running", "status": self.status}


class FakeSSH:
    def __init__(self, trace):
        self.trace = trace

    def push(self, local, remote):
        self.trace.append(("ssh", "push", local, remote))

    def pull(self, remote, local):
        self.trace.append(("ssh", "pull", remote, local))

    def run(self, command, timeout=30.0, check=False):
        self.trace.append(("ssh", "run", command, timeout))
        return 0, "", ""

    def is_ready(self, timeout=2):
        self.trace.append(("ssh", "is_ready", timeout))
        return True


@pytest.mark.parametrize("fmt", ("json", "ndjson"))
@pytest.mark.parametrize("case", CASES)
def test_paused_guest_fails_before_ssh_for_every_handler(
    case, fmt, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, _ = _case(case, tmp_path, fmt)
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="paused"),
    )
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert trace == [("qmp", "enter"), ("qmp", "query-status")]
    make_ssh.assert_not_called()
    assert payload["ok"] is False
    assert payload["vm_id"] == "state-vm"
    assert payload["qemu_status"] == "paused"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert "crash" not in payload
    assert "qmu cont --vm state-vm" in payload["hint"]
    assert "pry continue" in payload["hint"]


@pytest.mark.parametrize("case", CASES)
def test_running_guest_preflight_dispatches_every_ssh_handler(
    case, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case(case, tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="running"),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace[:3] == [
        ("qmp", "enter"),
        ("qmp", "query-status"),
        ("ssh", "construct"),
    ]
    assert trace[3:] == expected_ssh


@pytest.mark.parametrize("case", CASES)
def test_qmp_unavailable_falls_back_to_every_ssh_handler(
    case, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case(case, tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(
            trace,
            enter_error=QMPError("QMP socket unavailable"),
        ),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace == [
        ("qmp", "enter"),
        ("ssh", "construct"),
        *expected_ssh,
    ]


def test_qmp_oserror_during_query_falls_back_to_ssh(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case("exec", tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(
            trace,
            execute_error=OSError("QMP disappeared"),
        ),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace == [
        ("qmp", "enter"),
        ("qmp", "query-status"),
        ("ssh", "construct"),
        *expected_ssh,
    ]


def test_debug_state_uses_same_operational_failure(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, _ = _case("exec", tmp_path, "json")
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="debug"),
    )
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    make_ssh.assert_not_called()
    assert payload["qemu_status"] == "debug"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert "crash" not in payload


def test_paused_guest_text_names_state_and_recovery_without_crash_wording(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="paused"),
    )
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(["exec", "--vm", "state-vm", "true"])
    captured = capsys.readouterr()

    assert rc == 1
    make_ssh.assert_not_called()
    assert "VM 'state-vm' is paused" in captured.out
    assert "qmu cont --vm state-vm" in captured.out
    assert "pry continue" in captured.out
    assert "SSH connection lost" not in captured.out
    assert "crash" not in captured.out.lower()
    assert captured.err == ""
