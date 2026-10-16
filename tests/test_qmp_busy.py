"""QMP single-client contention: a held socket is `busy`, not `connected`.

QEMU serves one QMP client. A second connect() completes in the kernel's
listen backlog and then hears nothing until the first client leaves. Measured
before the fix: `status` 0.27 s → 19.7 s (two connects × the 10 s greeting
timeout) and it still said `qmp: connected`; `kill` 14 s because its graceful
`quit` queued behind a `wait`. The silence is a positive contention signal.
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from qmu import _cliutil, cli
from qmu import instance as instance_mod
from qmu.commands import lifecycle
from qmu.instance import VMInstance
from qmu.qmp import QMPBusyError, QMPClient, QMPError


@pytest.fixture
def held_socket(tmp_path):
    """A listening Unix socket that accepts in the backlog and never greets —
    exactly what a QEMU with its one QMP slot taken looks like to a second
    client."""
    path = tmp_path / "held.qmp.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(4)
    yield path
    server.close()


def test_connect_to_a_held_socket_is_busy_not_a_hang(held_socket):
    client = QMPClient(held_socket)
    client.greeting_timeout = 0.2

    started = time.monotonic()
    with pytest.raises(QMPBusyError) as excinfo:
        client.connect()
    elapsed = time.monotonic() - started

    assert elapsed < 1.0
    assert "another qmu command" in str(excinfo.value)
    assert isinstance(excinfo.value, QMPError)


def test_busy_default_is_two_seconds():
    assert QMPClient("/nonexistent").greeting_timeout == pytest.approx(2.0)


def test_a_full_backlog_is_busy_not_unreachable(tmp_path):
    """Probes queued behind the held slot fill the listen backlog; the next
    connect() gets EAGAIN at once. `list` reported that `unreachable` while
    `status`, one probe earlier, said `busy` — same socket, same holder."""
    path = tmp_path / "full.qmp.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(0)
    queued = []
    try:
        # Fill the backlog with connections the "server" never accepts.
        for _ in range(8):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect(str(path))
            except OSError:
                s.close()
                break
            queued.append(s)

        client = QMPClient(path)
        client.greeting_timeout = 0.2
        started = time.monotonic()
        with pytest.raises(QMPBusyError) as excinfo:
            client.connect()
        assert time.monotonic() - started < 1.0
        assert "another qmu command" in str(excinfo.value)
    finally:
        for s in queued:
            s.close()
        server.close()


def test_missing_socket_is_unreachable_not_busy(tmp_path):
    with pytest.raises(QMPError) as excinfo:
        QMPClient(tmp_path / "absent.sock").connect()
    assert not isinstance(excinfo.value, QMPBusyError)


# ---------------------------------------------------------------------------
# status / list render busy and skip QMP-derived fields
# ---------------------------------------------------------------------------


def _vm(tmp_path, sock, *, vm_id="busy-vm"):
    serial = tmp_path / f"{vm_id}.serial.log"
    serial.write_text("[    0.000000] Linux version 7.0.0 (b@h) (gcc 13) #1 SMP\n")
    return VMInstance(
        vm_id=vm_id, pid=4242, qmp_socket=str(sock), ssh_port=None, ssh_key=None,
        gdb_port=None, serial_log=str(serial), kernel="/boot/bzImage", rootfs=None,
        memory="4G", cpus=2, cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=True,
    )


def _register(monkeypatch, inst):
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "list_stopped_instances", lambda: [])
    monkeypatch.setattr(QMPClient, "greeting_timeout", 0.2)


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_status_reports_busy_quickly_and_claims_nothing_qmp_derived(
    fmt, held_socket, tmp_path, monkeypatch, capsys
):
    inst = _vm(tmp_path, held_socket)
    _register(monkeypatch, inst)

    started = time.monotonic()
    rc = cli.main(["--format", fmt, "status", "--vm", "busy-vm"])
    elapsed = time.monotonic() - started
    out = capsys.readouterr().out

    assert rc == 0
    assert elapsed < 1.5
    if fmt == "json":
        payload = json.loads(out)
        assert payload["qmp"] == "busy"
        assert payload["qemu_status"] == "unknown"
        assert payload["guest"] == "unknown"
        assert "QMP busy" in payload["guest_detail"]
    else:
        assert "QMP:       busy" in out
        assert "QEMU:      unknown" in out
        assert "connected" not in out
        assert "guest unknown" not in out.lower() or "QMP busy" in out


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_list_reports_busy_without_stalling(
    fmt, held_socket, tmp_path, monkeypatch, capsys
):
    inst = _vm(tmp_path, held_socket)
    _register(monkeypatch, inst)

    started = time.monotonic()
    rc = cli.main(["--format", fmt, "list"])
    elapsed = time.monotonic() - started
    out = capsys.readouterr().out

    assert rc == 0
    assert elapsed < 1.5
    if fmt == "json":
        row = json.loads(out)["vms"][0]
        assert row["qmp"] == "busy"
        assert row["guest"] == "unknown"
        assert "QMP busy" in row["guest_detail"]
    else:
        assert "qmp=busy" in out
        assert "guest unknown (QMP busy" in out


# ---------------------------------------------------------------------------
# kill on a held socket goes straight to the signal
# ---------------------------------------------------------------------------


def test_kill_on_a_busy_socket_signals_within_about_a_second(
    held_socket, tmp_path, monkeypatch
):
    inst = _vm(tmp_path, held_socket)
    signals = []
    alive = [True, True, False]

    monkeypatch.setattr(
        _cliutil, "is_pid_alive",
        lambda pid: alive.pop(0) if len(alive) > 1 else alive[0],
    )
    monkeypatch.setattr(_cliutil.os, "kill", lambda pid, sig: signals.append(sig))
    monkeypatch.setattr(_cliutil, "remove_instance", lambda vm_id: None)
    # Zombie reaping is a no-op for a pid that is not our child.
    monkeypatch.setattr(
        _cliutil.os, "waitpid",
        lambda pid, flags: (_ for _ in ()).throw(ChildProcessError()),
        raising=False,
    )

    started = time.monotonic()
    _cliutil._kill_vm(inst, force=False, clean=False)
    elapsed = time.monotonic() - started

    assert signals and signals[0] == _cliutil.signal.SIGTERM
    assert elapsed < 1.6
