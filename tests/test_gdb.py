from __future__ import annotations

import json
import subprocess

import pytest

from qmu import cli
from qmu.commands import qmp_cmds
from qmu.instance import VMInstance


_SYMBOL_FIELDS = {
    "symbols",
    "symbols_rebased",
    "symbol_base",
    "kaslr_status",
    "symbol_warning",
}


@pytest.fixture
def gdb_vm(tmp_path):
    return VMInstance(
        vm_id="debug-vm",
        pid=4242,
        qmp_socket=str(tmp_path / "debug-vm.qmp.sock"),
        ssh_port=10022,
        ssh_key=str(tmp_path / "id_rsa"),
        gdb_port=1234,
        serial_log=str(tmp_path / "serial.log"),
        kernel=str(tmp_path / "bzImage"),
        rootfs=str(tmp_path / "rootfs.img"),
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00+00:00",
        harness=False,
        arch="x86_64",
    )


_BRIDGE_PID = 777001
_LAUNCH_JSON = json.dumps({"launched": True, "pid": _BRIDGE_PID, "instance_id": "qmu-debug-vm"})


def _install_gdb_seams(
    monkeypatch, gdb_vm, *, returncode=0, stdout=_LAUNCH_JSON, stderr="", attached=False
):
    calls = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: gdb_vm)
    monkeypatch.setattr(
        qmp_cmds.shutil,
        "which",
        lambda name: "/usr/bin/pry" if name == "pry" else None,
    )
    # The attach gate reads the real /proc/net/tcp; on a shared host another
    # VM's debugger may sit on port 1234, so the probe is pinned per test.
    monkeypatch.setattr(qmp_cmds, "gdb_client_attached", lambda inst: attached)
    # The bridge pid is recorded with its /proc start-time; the fake pid has none.
    monkeypatch.setattr(qmp_cmds, "proc_pid_start", lambda pid: "4242")

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(
            args=argv,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    monkeypatch.setattr(qmp_cmds.subprocess, "run", run)
    return calls


_LAUNCH_PREFIX = [
    "pry", "launch", "--format", "json", "--instance-id", "qmu-debug-vm",
    "--connect", "localhost:1234",
]


def _symbols_argv(symbols):
    return _LAUNCH_PREFIX + ["--symbols", str(symbols.resolve())]


def _assert_no_misleading_kaslr_claim(message: str) -> None:
    lowered = message.lower()
    assert "kaslr is enabled" not in lowered
    assert "kaslr is disabled" not in lowered
    assert "nonzero slide" not in lowered
    assert "zero slide" not in lowered


def test_gdb_symbols_text_warns_link_time_and_gives_manual_workflow(
    monkeypatch, tmp_path, gdb_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    calls = _install_gdb_seams(monkeypatch, gdb_vm)

    rc = cli.main([
        "gdb", "--vm", "debug-vm", "--symbols", str(symbols)
    ])
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.err == ""
    assert "pry connected to VM 'debug-vm' GDB stub on port 1234" in captured.out
    assert "vCPU is now HALTED" in captured.out
    assert "loaded at ELF link-time addresses" in captured.out
    assert "qmu gdb did not apply runtime rebasing" in captured.out
    assert "qmu kbase --vm debug-vm --symbols" in captured.out
    assert "pry load" in captured.out
    assert "--base <KBASE>" in captured.out
    _assert_no_misleading_kaslr_claim(captured.out)
    assert calls == [(
        _symbols_argv(symbols),
        {"capture_output": True, "text": True, "timeout": 15},
    )]
    assert "--base" not in calls[0][0]


def test_gdb_symbols_json_preserves_halt_warning_and_adds_symbol_warning(
    monkeypatch, tmp_path, gdb_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    calls = _install_gdb_seams(monkeypatch, gdb_vm)

    rc = cli.main([
        "--format", "json", "gdb", "--vm", "debug-vm",
        "--symbols", str(symbols),
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert captured.err == ""
    assert payload["ok"] is True
    assert payload["vm_id"] == "debug-vm"
    assert payload["gdb_port"] == 1234
    assert payload["cpu_state"] == "halted"
    assert "vCPU is now HALTED" in payload["warning"]
    assert payload["symbols"] == str(symbols.resolve())
    assert payload["symbols_rebased"] is False
    assert payload["symbol_base"] == "elf-link-time"
    assert payload["kaslr_status"] == "unknown"
    assert "loaded at ELF link-time addresses" in payload["symbol_warning"]
    assert "qmu kbase --vm debug-vm --symbols" in payload["symbol_warning"]
    assert "pry load" in payload["symbol_warning"]
    assert "--base <KBASE>" in payload["symbol_warning"]
    _assert_no_misleading_kaslr_claim(payload["symbol_warning"])
    assert calls[0][0] == _symbols_argv(symbols)
    assert "--base" not in calls[0][0]


def test_gdb_symbols_ndjson_is_one_object_with_symbol_warning(
    monkeypatch, tmp_path, gdb_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    calls = _install_gdb_seams(monkeypatch, gdb_vm)

    rc = cli.main([
        "--format", "ndjson", "gdb", "--vm", "debug-vm",
        "--symbols", str(symbols),
    ])
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    payload = json.loads(lines[0])

    assert rc == 0
    assert captured.err == ""
    assert len(lines) == 1
    assert payload["ok"] is True
    assert payload["cpu_state"] == "halted"
    assert "vCPU is now HALTED" in payload["warning"]
    assert payload["symbols"] == str(symbols.resolve())
    assert payload["symbols_rebased"] is False
    assert payload["symbol_base"] == "elf-link-time"
    assert payload["kaslr_status"] == "unknown"
    assert "loaded at ELF link-time addresses" in payload["symbol_warning"]
    assert "qmu kbase --vm debug-vm --symbols" in payload["symbol_warning"]
    assert "pry load" in payload["symbol_warning"]
    assert "--base <KBASE>" in payload["symbol_warning"]
    _assert_no_misleading_kaslr_claim(payload["symbol_warning"])
    assert calls[0][0] == _symbols_argv(symbols)
    assert "--base" not in calls[0][0]


def test_gdb_without_symbols_omits_symbol_warning_and_metadata(
    monkeypatch, gdb_vm, capsys
):
    calls = _install_gdb_seams(monkeypatch, gdb_vm)
    argv = _LAUNCH_PREFIX

    json_rc = cli.main([
        "--format", "json", "gdb", "--vm", "debug-vm"
    ])
    payload = json.loads(capsys.readouterr().out)
    text_rc = cli.main(["gdb", "--vm", "debug-vm"])
    text = capsys.readouterr().out

    assert json_rc == 0
    assert payload["ok"] is True
    assert payload["cpu_state"] == "halted"
    assert "vCPU is now HALTED" in payload["warning"]
    assert _SYMBOL_FIELDS.isdisjoint(payload)
    assert text_rc == 0
    assert "vCPU is now HALTED" in text
    assert "link-time" not in text
    assert "qmu kbase" not in text
    assert calls[0][0] == argv
    assert calls[1][0] == argv


def test_gdb_failed_pry_is_an_operational_error(
    monkeypatch, tmp_path, gdb_vm, capsys
):
    """A pry launch failure is the exit-1 class with `error` + `error_type`
    (pry's own JSON error text when it gives one), on stderr in text mode."""
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    calls = _install_gdb_seams(
        monkeypatch,
        gdb_vm,
        returncode=2,
        stdout=json.dumps({"ok": False, "error": "bridge startup failed"}),
        stderr="",
    )

    json_rc = cli.main([
        "--format", "json", "gdb", "--vm", "debug-vm",
        "--symbols", str(symbols),
    ])
    payload = json.loads(capsys.readouterr().out)
    text_rc = cli.main([
        "gdb", "--vm", "debug-vm", "--symbols", str(symbols)
    ])
    captured = capsys.readouterr()

    assert json_rc == 1
    assert payload == {
        "ok": False,
        "error": "pry launch failed: bridge startup failed",
        "error_type": "QMUError",
        "hint": (
            "pry doctor; qmu log --vm debug-vm --tail 50; then re-run "
            "qmu gdb --vm debug-vm"
        ),
    }
    assert text_rc == 1
    assert captured.out == ""
    assert captured.err == (
        "[qmu] Error: pry launch failed: bridge startup failed\n"
        "[qmu] Hint: pry doctor; qmu log --vm debug-vm --tail 50; then re-run "
        "qmu gdb --vm debug-vm\n"
    )
    assert calls[0][0] == _symbols_argv(symbols)
    assert calls[1][0] == _symbols_argv(symbols)


# --- bridge ownership (#40, debug audit D4/D5) ------------------------------


def test_gdb_records_the_bridge_pid_and_exposes_it(
    monkeypatch, gdb_vm, capsys
):
    from qmu.instance import load_instance

    _install_gdb_seams(monkeypatch, gdb_vm)
    rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["bridge_pid"] == _BRIDGE_PID
    assert payload["bridge_instance_id"] == "qmu-debug-vm"
    saved = load_instance("debug-vm")
    assert saved.gdb_bridge_pid == _BRIDGE_PID
    assert saved.gdb_bridge_pid_start == "4242"

    text_rc = cli.main(["gdb", "--vm", "debug-vm"])
    text = capsys.readouterr().out
    assert text_rc == 0
    assert f"pry bridge pid {_BRIDGE_PID}" in text
    assert "pry --instance" in text


def test_gdb_tolerates_a_launch_reply_without_a_pid(monkeypatch, gdb_vm, capsys):
    _install_gdb_seams(monkeypatch, gdb_vm, stdout="")
    rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["bridge_pid"] is None


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_gdb_refuses_when_a_client_is_already_attached(
    monkeypatch, gdb_vm, capsys, output_format
):
    """The stub serves one client: a second `pry launch` used to hang 15 s,
    exit 4 with a raw TimeoutExpired and leak a bridge per attempt."""
    gdb_vm.gdb_bridge_pid = _BRIDGE_PID
    gdb_vm.gdb_bridge_pid_start = "4242"
    calls = _install_gdb_seams(monkeypatch, gdb_vm, attached=True)
    monkeypatch.setattr(qmp_cmds, "bridge_alive", lambda inst: True)

    rc = cli.main(["--format", output_format, "gdb", "--vm", "debug-vm"])
    captured = capsys.readouterr()

    assert rc == 1
    assert calls == []  # nothing spawned
    if output_format == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "QMUError"
        message = payload["error"]
    else:
        assert captured.out == ""
        message = captured.err
    assert "already attached to port 1234" in message
    assert f"pry bridge pid {_BRIDGE_PID}" in message
    assert f"pry kill --instance {_BRIDGE_PID}" in message


def test_gdb_refusal_without_a_known_bridge_points_at_pry_doctor(
    monkeypatch, gdb_vm, capsys
):
    calls = _install_gdb_seams(monkeypatch, gdb_vm, attached=True)
    rc = cli.main(["gdb", "--vm", "debug-vm"])
    err = capsys.readouterr().err
    assert rc == 1
    assert calls == []
    assert "already attached to port 1234" in err
    assert "pry doctor" in err


def test_gdb_timeout_is_an_operational_error_and_reaps_the_attempt(
    monkeypatch, gdb_vm, capsys
):
    """`subprocess.TimeoutExpired` must never escape as a raw repr (exit 4);
    the attempt's bridge is killed by its instance id."""
    calls = _install_gdb_seams(monkeypatch, gdb_vm)

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[:2] == ["pry", "launch"]:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(qmp_cmds.subprocess, "run", run)
    rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["error_type"] == "QMUError"
    assert "TimeoutExpired" not in payload["error"]
    assert "did not connect" in payload["error"]
    assert "port 1234" in payload["error"]
    assert calls[1][0] == ["/usr/bin/pry", "kill", "--instance", "qmu-debug-vm"]


def test_gdb_reaps_a_stranded_bridge_before_spawning(monkeypatch, gdb_vm, capsys):
    """A recorded bridge alive with NO client attached is the #40 stranded
    case; it holds the VM's instance id, so it is reaped first."""
    gdb_vm.gdb_bridge_pid = 555
    gdb_vm.gdb_bridge_pid_start = "1"
    calls = _install_gdb_seams(monkeypatch, gdb_vm, attached=False)
    monkeypatch.setattr(qmp_cmds, "bridge_alive", lambda inst: True)
    reaped = []
    monkeypatch.setattr(qmp_cmds, "reap_bridge", lambda inst: reaped.append(inst.vm_id) or True)

    rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert reaped == ["debug-vm"]
    assert payload["bridge_pid"] == _BRIDGE_PID
    assert calls[0][0] == _LAUNCH_PREFIX
