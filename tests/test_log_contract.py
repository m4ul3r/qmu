"""qmu log query contract: successful empty/missing and available content."""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import guest
from qmu.instance import VMInstance


def _fake_instance(serial_log: str) -> VMInstance:
    return VMInstance(
        vm_id="log-vm",
        pid=4242,
        qmp_socket="/tmp/log-vm.qmp.sock",
        ssh_port=10099,
        ssh_key="/tmp/log-vm.key",
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-29T00:00:00Z",
        harness=False,
    )


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
@pytest.mark.parametrize("case", ["missing", "zero-byte", "tail-zero"])
def test_empty_log_query_is_successful_and_explicit(
    monkeypatch, tmp_path, capsys, fmt, case
):
    serial = tmp_path / "vm.serial.log"
    tail = "50"
    if case == "zero-byte":
        serial.write_text("")
    elif case == "tail-zero":
        serial.write_text("boot line\n")
        tail = "0"
    inst = _fake_instance(str(serial))
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: inst)

    rc = cli.main(["--format", fmt, "log", "--tail", tail])

    output = capsys.readouterr().out
    if fmt == "ndjson":
        assert len(output.splitlines()) == 1
    payload = json.loads(output)
    assert rc == 0
    assert payload == {
        "ok": True,
        "log": "",
        "available": False,
        "empty": True,
    }


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_nonempty_log_query_is_available(monkeypatch, tmp_path, capsys, fmt):
    serial = tmp_path / "vm.serial.log"
    serial.write_text("first\nsecond\n")
    inst = _fake_instance(str(serial))
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: inst)

    rc = cli.main(["--format", fmt, "log", "--tail", "1"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload == {
        "ok": True,
        "log": "second\n",
        "available": True,
        "empty": False,
    }


def test_empty_log_text_is_successful_message(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    inst = _fake_instance(str(serial))  # missing file
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: inst)

    rc = cli.main(["log"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() == "Serial log is empty or missing."


def test_nonempty_log_text_returns_content(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    serial.write_text("first\nsecond\n")
    inst = _fake_instance(str(serial))
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: inst)

    rc = cli.main(["log", "--tail", "1"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out == "second\n"


def test_log_json_ndjson_semantic_parity(monkeypatch, tmp_path, capsys):
    cases = [
        ("missing", None, "50"),
        ("zero-byte", "", "50"),
        ("nonempty", "first\nsecond\n", "1"),
    ]
    for name, content, tail in cases:
        payloads = {}
        rcs = {}
        for fmt in ("json", "ndjson"):
            serial = tmp_path / f"{name}-{fmt}.serial.log"
            if content is not None:
                serial.write_text(content)
            inst = _fake_instance(str(serial))
            monkeypatch.setattr(guest, "find_instance", lambda vm=None, i=inst: i)
            rcs[fmt] = cli.main(["--format", fmt, "log", "--tail", tail])
            out = capsys.readouterr().out
            if fmt == "ndjson":
                assert len(out.splitlines()) == 1, name
            payloads[fmt] = json.loads(out)
            assert (rcs[fmt] == 0) is payloads[fmt]["ok"], name
        assert payloads["json"] == payloads["ndjson"], name
        assert rcs["json"] == rcs["ndjson"], name
