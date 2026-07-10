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


def _install_gdb_seams(monkeypatch, gdb_vm, *, returncode=0, stdout="", stderr=""):
    calls = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: gdb_vm)
    monkeypatch.setattr(
        qmp_cmds.shutil,
        "which",
        lambda name: "/usr/bin/pry" if name == "pry" else None,
    )

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


def _symbols_argv(symbols):
    return [
        "pry",
        "launch",
        "--connect",
        "localhost:1234",
        "--symbols",
        str(symbols.resolve()),
    ]


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
    argv = ["pry", "launch", "--connect", "localhost:1234"]

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


def test_gdb_failed_pry_omits_success_warnings(
    monkeypatch, tmp_path, gdb_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    calls = _install_gdb_seams(
        monkeypatch,
        gdb_vm,
        returncode=2,
        stderr="bridge startup failed",
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
    assert payload == {"ok": False, "error": "bridge startup failed"}
    assert "warning" not in payload
    assert "cpu_state" not in payload
    assert _SYMBOL_FIELDS.isdisjoint(payload)
    assert text_rc == 1
    assert captured.err == ""
    assert captured.out == "pry launch failed: bridge startup failed\n"
    assert "HALTED" not in captured.out
    assert "link-time" not in captured.out
    assert "qmu kbase" not in captured.out
    assert calls[0][0] == _symbols_argv(symbols)
    assert calls[1][0] == _symbols_argv(symbols)
