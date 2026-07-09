from __future__ import annotations

import argparse
import contextlib
from dataclasses import replace
from pathlib import Path

import pytest

from qmu.commands import qmp_cmds
from qmu.instance import VMInstance
from qmu.qmp import QMPError


def _inst(serial_log: str, offset: int = 3) -> VMInstance:
    return VMInstance(
        vm_id="snap-vm", pid=42, qmp_socket="/tmp/snap.qmp", ssh_port=10022,
        ssh_key="/tmp/key", gdb_port=None, serial_log=serial_log,
        kernel="/boot/bzImage", rootfs="/tmp/rootfs.qcow2", memory="2G",
        cpus=2, cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        guest_epoch_serial_offset=offset,
    )


def _load_args() -> argparse.Namespace:
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_load_captures_before_load_and_saves_before_success_emit(
    tmp_path, monkeypatch
):
    log = tmp_path / "snap.serial.log"
    old = b"old epoch panic\n"
    log.write_bytes(old)
    inst = _inst(str(log))
    calls = []

    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))

    def capture(path):
        calls.append("capture")
        return Path(path).stat().st_size

    def load(qmp, name):
        calls.append("load")
        with log.open("ab") as stream:
            stream.write(b"restored guest output\n")
        return "Snapshot 'clean' loaded."

    def save_epoch(record, offset):
        calls.append(("save", offset))
        return replace(record, guest_epoch_serial_offset=offset)

    def emit(*args, **kwargs):
        calls.append(("emit", kwargs["data"]["ok"]))

    monkeypatch.setattr(qmp_cmds, "serial_log_offset", capture, raising=False)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", load)
    monkeypatch.setattr(
        qmp_cmds,
        "save_guest_epoch_serial_offset",
        save_epoch,
        raising=False,
    )
    monkeypatch.setattr(qmp_cmds, "_emit", emit)

    assert qmp_cmds._handle_snapshot_load(_load_args()) == 0
    assert calls == ["capture", "load", ("save", len(old)), ("emit", True)]


@pytest.mark.parametrize(
    "message",
    ["Error: Section footer error", "Missing section footer for slirp"],
)
def test_snapshot_load_hmp_failure_preserves_epoch(message, tmp_path, monkeypatch):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    saved = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name: message)
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    assert qmp_cmds._handle_snapshot_load(_load_args()) == 1
    assert saved == []


def test_snapshot_load_qmp_exception_does_not_save(tmp_path, monkeypatch):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    saved = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name: (_ for _ in ()).throw(QMPError("load failed")),
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    with pytest.raises(QMPError, match="load failed"):
        qmp_cmds._handle_snapshot_load(_load_args())
    assert saved == []


def test_snapshot_load_metadata_failure_emits_no_success(tmp_path, monkeypatch):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    emitted = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot", lambda qmp, name: "Snapshot 'clean' loaded."
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: (_ for _ in ()).throw(OSError("metadata failed")),
        raising=False,
    )
    monkeypatch.setattr(qmp_cmds, "_emit", lambda *a, **kw: emitted.append(kw))

    with pytest.raises(OSError, match="metadata failed"):
        qmp_cmds._handle_snapshot_load(_load_args())
    assert emitted == []


def test_snapshot_save_does_not_advance_epoch(tmp_path, monkeypatch):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    saved = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot", lambda qmp, name: "Snapshot 'clean' saved."
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    args = argparse.Namespace(vm=None, name="clean", format="text", out=None)
    assert qmp_cmds._handle_snapshot_save(args) == 0
    assert saved == []
