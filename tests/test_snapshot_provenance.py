from __future__ import annotations

import argparse
import contextlib
from dataclasses import replace
from pathlib import Path

import pytest

from qmu.commands import qmp_cmds
from qmu.instance import VMInstance
from qmu.qmp import QMPError
from qmu.snapshot import SnapshotResult
from qmu._cliutil import render


def _run(handler, args):
    """Call a handler as `cli.main` would: render its Result, return the exit code."""
    return render(args, handler(args))


@pytest.fixture(autouse=True)
def _no_ssh_master(monkeypatch):
    """The handlers tear down the SSH ControlMaster around a load; that is a
    real `ssh -O exit` subprocess and not what these tests are about."""
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)


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

    def load(qmp, name, **kw):
        calls.append("load")
        with log.open("ab") as stream:
            stream.write(b"restored guest output\n")
        return SnapshotResult(True, "Snapshot 'clean' loaded.")

    def save_epoch(record, offset):
        calls.append(("save", offset))
        return replace(record, guest_epoch_serial_offset=offset)

    monkeypatch.setattr(qmp_cmds, "serial_log_offset", capture, raising=False)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", load)
    monkeypatch.setattr(
        qmp_cmds,
        "save_guest_epoch_serial_offset",
        save_epoch,
        raising=False,
    )

    # The success Result is produced only after the epoch is saved: the
    # handler's return is the "emit" of the old emit-in-handler flow.
    result = qmp_cmds._handle_snapshot_load(_load_args())
    calls.append(("emit", result.data["ok"]))
    assert render(_load_args(), result) == 0
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
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot", lambda qmp, name, **kw: SnapshotResult(False, message)
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    assert _run(qmp_cmds._handle_snapshot_load, _load_args()) == 1
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
        lambda qmp, name, **kw: (_ for _ in ()).throw(QMPError("load failed")),
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    with pytest.raises(QMPError, match="load failed"):
        _run(qmp_cmds._handle_snapshot_load, _load_args())
    assert saved == []


def test_snapshot_load_metadata_failure_emits_no_success(tmp_path, monkeypatch, capsys):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name, **kw: SnapshotResult(True, "Snapshot 'clean' loaded."),
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: (_ for _ in ()).throw(OSError("metadata failed")),
        raising=False,
    )

    with pytest.raises(OSError, match="metadata failed"):
        _run(qmp_cmds._handle_snapshot_load, _load_args())
    # The failure escaped before the handler produced a Result: nothing was
    # rendered, so no success envelope reached stdout.
    assert capsys.readouterr().out == ""


def test_snapshot_save_does_not_advance_epoch(tmp_path, monkeypatch):
    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log), offset=11)
    saved = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot",
        lambda qmp, name, **kw: SnapshotResult(True, "Snapshot 'clean' saved."),
    )
    monkeypatch.setattr(
        qmp_cmds, "save_guest_epoch_serial_offset",
        lambda record, offset: saved.append(offset),
        raising=False,
    )

    args = argparse.Namespace(vm=None, name="clean", format="text", out=None)
    assert _run(qmp_cmds._handle_snapshot_save, args) == 0
    assert saved == []


@pytest.mark.parametrize("listed", [True, False])
def test_only_an_attempted_load_cuts_the_guest_sessions(listed, tmp_path, monkeypatch):
    """A tag the pre-check refuses mutates nothing, so it must not close the
    SSH ControlMaster either: that cut an exec whose process then ran on in
    the guest while the exec was told it had been rewound away (review of
    #221). A load that reaches `loadvm` cuts them and stamps the record."""
    from qmu.instance import load_instance, save_instance
    from tests.test_snapshot import QEMU11_SINGLE, FakeQMP

    log = tmp_path / "snap.serial.log"
    log.write_text("old\n")
    inst = _inst(str(log))
    save_instance(inst)
    drops = []
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: drops.append(inst.vm_id))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    qmp = FakeQMP("", listing=QEMU11_SINGLE if listed else "")
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(qmp))

    rc = _run(qmp_cmds._handle_snapshot_load, _load_args())

    record = load_instance("snap-vm")
    if listed:
        assert rc == 0
        assert drops and record.ssh_severed_by == "snapshot load"
    else:
        assert rc == 1
        assert "loadvm clean" not in qmp.calls
        assert drops == []
        assert record.ssh_severed_at is None
