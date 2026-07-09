from __future__ import annotations

import json

from qmu import cli
from qmu.commands import guest
from qmu.instance import VMInstance


OLD_CRASH = (
    "[ 1.0] BUG: KASAN: slab-use-after-free in old_bug\n"
    "[ 1.1] Kernel panic - not syncing: old_bug panic\n"
    "[ 1.2] ---[ end Kernel panic - not syncing: old_bug panic ]---\n"
)
NEW_CRASH = (
    "[ 2.0] BUG: KASAN: slab-use-after-free in new_bug\n"
    "[ 2.1] Kernel panic - not syncing: new_bug panic\n"
    "[ 2.2] ---[ end Kernel panic - not syncing: new_bug panic ]---\n"
)
CLEAN_RESTORED_OUTPUT = "[ 2.0] restored guest booted cleanly\n"
EXPECTED_KEYS = {
    "ok",
    "crash_detected",
    "scope",
    "reason",
    "serial_log",
    "crash",
}


def _instance(serial_log: str, boundary: int) -> VMInstance:
    return VMInstance(
        vm_id="crash-vm",
        pid=4242,
        qmp_socket="/tmp/crash-vm.qmp.sock",
        ssh_port=10022,
        ssh_key="/tmp/key",
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs="/tmp/rootfs.img",
        memory="2G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        guest_epoch_serial_offset=boundary,
    )


def _patch_crash_instance(monkeypatch, tmp_path, current_output: str):
    log = tmp_path / "crash-vm.serial.log"
    log.write_text(OLD_CRASH + current_output)
    inst = _instance(str(log), len(OLD_CRASH.encode()))

    def find_instance(vm):
        assert vm == "crash-vm"
        return inst

    monkeypatch.setattr(guest, "find_instance", find_instance)
    return inst


def test_crash_defaults_to_current_epoch(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, CLEAN_RESTORED_OUTPUT)

    rc = cli.main(["crash", "--vm", "crash-vm"])
    text = capsys.readouterr().out

    assert rc == 1
    assert "current guest epoch" in text
    assert "old_bug" not in text


def test_crash_full_history_finds_pre_epoch_crash(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, CLEAN_RESTORED_OUTPUT)

    rc = cli.main(["crash", "--vm", "crash-vm", "--full-history"])
    text = capsys.readouterr().out

    assert rc == 0
    assert "retained serial history" in text
    assert "forensics" in text
    assert "old_bug" in text


def test_crash_current_epoch_finds_only_fresh_crash(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, NEW_CRASH)

    rc = cli.main(["crash", "--vm", "crash-vm"])
    text = capsys.readouterr().out

    assert rc == 0
    assert "current guest epoch" in text
    assert "new_bug" in text
    assert "old_bug" not in text


def test_crash_current_json_contract(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, NEW_CRASH)

    rc = cli.main(["crash", "--vm", "crash-vm", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert set(payload) == EXPECTED_KEYS
    assert payload["scope"] == "current"
    assert payload["ok"] is payload["crash_detected"]
    assert "current guest epoch" in payload["reason"]
    assert "new_bug" in payload["crash"]
    assert "old_bug" not in payload["crash"]
    assert rc == (0 if payload["ok"] else 1)


def test_crash_full_history_json_contract(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, CLEAN_RESTORED_OUTPUT)

    rc = cli.main([
        "--format",
        "json",
        "crash",
        "--vm",
        "crash-vm",
        "--full-history",
    ])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert set(payload) == EXPECTED_KEYS
    assert payload["ok"] is True
    assert payload["crash_detected"] is True
    assert payload["scope"] == "history"
    assert "retained serial history" in payload["reason"]
    assert "old_bug" in payload["crash"]


def test_crash_no_current_crash_json_exit_1(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, CLEAN_RESTORED_OUTPUT)

    rc = cli.main(["crash", "--vm", "crash-vm", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert set(payload) == EXPECTED_KEYS
    assert payload["ok"] is False
    assert payload["crash_detected"] is False
    assert payload["scope"] == "current"
    assert payload["crash"] is None
    assert payload["reason"] == "no crash markers found in current guest epoch"


def test_crash_ndjson_is_one_scope_aware_object(monkeypatch, tmp_path, capsys):
    _patch_crash_instance(monkeypatch, tmp_path, CLEAN_RESTORED_OUTPUT)

    rc = cli.main([
        "crash",
        "--vm",
        "crash-vm",
        "--full-history",
        "--format",
        "ndjson",
    ])
    lines = [line for line in capsys.readouterr().out.splitlines() if line]

    assert rc == 0
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert set(payload) == EXPECTED_KEYS
    assert payload["scope"] == "history"
    assert payload["ok"] is True
    assert payload["crash_detected"] is True
    assert "old_bug" in payload["crash"]
