"""QMPClient against a QEMU whose main loop is wedged in a long command (#73).

Three facts about QEMU's monitor drive these tests, all observed live on
QEMU 8.2.2 with a `savevm` that outlived `snapshot save --timeout`:

* the reply to a command is owed to the *connection*, not the client: when the
  client that sent `savevm` closes its socket and a new client connects, QEMU
  writes the late `{"return": ""}` to the new client, which read it as the
  answer to its own `qmp_capabilities` and then took the real capabilities
  reply `{"return": {}}` as `info snapshots` -> "No snapshots.";
* the greeting arrives at once (it is written from accept()), while the first
  dispatched command — `qmp_capabilities` — waits for the main loop, so the
  handshake budget must cover both;
* a client that times out must close its socket, or the late reply lands on
  the next command it sends.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from qmu.qmp import QMPBusyError, QMPClient, QMPTimeoutError


class _ScriptedServer:
    """Unix-socket QMP server replaying `script`: a list of raw lines to send
    after each received request (None = send nothing, i.e. hang)."""

    def __init__(self, script: list[list[bytes] | None], *, stale_first: list[bytes] | None = None):
        self.tmpdir = tempfile.mkdtemp()
        self.sockpath = os.path.join(self.tmpdir, "qmp.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.sockpath)
        self.sock.listen(1)
        self.script = list(script)
        self.stale_first = stale_first or []
        self.requests: list[dict] = []
        self.client_closed = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        greeting = {"QMP": {"version": {"qemu": {"major": 8}}, "capabilities": []}}
        conn.sendall(json.dumps(greeting).encode() + b"\n")
        for line in self.stale_first:
            conn.sendall(line + b"\n")
        buf = b""
        try:
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    chunk = conn.recv(4096)
                    if not chunk:
                        self.client_closed.set()
                        return
                    buf += chunk
                    continue
                line, buf = buf[:nl], buf[nl + 1:]
                if not line.strip():
                    continue
                req = json.loads(line)
                self.requests.append(req)
                replies = self.script.pop(0) if self.script else [b'{"return": {}}']
                if replies is None:
                    continue  # wedged: never answer this one
                for reply in replies:
                    conn.sendall(reply.replace(b"$ID", json.dumps(req["id"]).encode()) + b"\n")
        except OSError:
            return

    def close(self) -> None:
        try:
            self.sock.close()
        finally:
            Path(self.sockpath).unlink(missing_ok=True)


@pytest.fixture
def server():
    made: list[_ScriptedServer] = []

    def make(*a, **kw):
        s = _ScriptedServer(*a, **kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def test_every_command_carries_a_client_unique_id(server):
    srv = server([[b'{"return": {}, "id": $ID}'], [b'{"return": {"status": "running"}, "id": $ID}']])
    with QMPClient(srv.sockpath) as qmp:
        assert qmp.execute("query-status", timeout=2.0) == {"status": "running"}
    ids = [r["id"] for r in srv.requests]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert all(isinstance(i, str) and i.startswith("qmu-") for i in ids)


def test_stale_reply_from_an_abandoned_client_is_not_taken_as_the_answer(server):
    # The late savevm reply (another client's id) arrives right after the
    # greeting; the real capabilities reply and the real answer follow.
    srv = server(
        [
            [b'{"return": {}, "id": $ID}'],
            [b'{"return": "List of snapshots present on all disks:\\r\\nID TAG VM SIZE DATE VM CLOCK ICOUNT\\r\\n-- clean 325 MiB 2026-10-16 23:24:01 00:00:29.574", "id": $ID}'],
        ],
        stale_first=[b'{"return": "", "id": "qmu-999-abcdef:1"}'],
    )
    with QMPClient(srv.sockpath) as qmp:
        out = qmp.execute_hmp("info snapshots", timeout=2.0)
    assert "clean" in out
    assert qmp.stale_replies == 1


def test_stale_error_reply_is_dropped_too(server):
    srv = server(
        [
            [
                b'{"error": {"class": "GenericError", "desc": "stale"}, "id": "qmu-1-aaaaaa:7"}',
                b'{"return": {}, "id": $ID}',
            ],
            [b'{"return": {"running": true}, "id": $ID}'],
        ]
    )
    with QMPClient(srv.sockpath) as qmp:
        assert qmp.execute("query-status", timeout=2.0) == {"running": True}


def test_reply_without_an_id_is_trusted(server):
    # Test doubles and the capturing server in test_qmp_execute answer
    # without echoing the id; those replies are still the answer.
    srv = server([[b'{"return": {}}'], [b'{"return": {"status": "paused"}}']])
    with QMPClient(srv.sockpath) as qmp:
        assert qmp.execute("query-status", timeout=2.0) == {"status": "paused"}
    assert qmp.stale_replies == 0


def test_timeout_raises_qmp_timeout_error_and_closes_the_socket(server):
    srv = server([[b'{"return": {}, "id": $ID}'], None])
    qmp = QMPClient(srv.sockpath)
    qmp.connect()
    with pytest.raises(QMPTimeoutError) as excinfo:
        qmp.execute_hmp("savevm clean", timeout=0.2)
    err = excinfo.value
    assert err.timeout == 0.2
    assert "savevm clean" in str(err)
    assert "may still be running" in str(err)
    # The socket is gone: a second command does not read the late reply, it
    # reports a dead client — and the server saw the close.
    assert qmp._sock is None
    assert srv.client_closed.wait(2.0)
    with pytest.raises(Exception, match="Not connected"):
        qmp.execute("query-status")


def test_handshake_budget_covers_the_capabilities_reply(server):
    # Greeting at once, capabilities never: that is the wedged-main-loop
    # signature, and it is `busy`, bounded by the handshake budget — not a
    # raw socket timeout surfacing as "timed out" (exit 4 catch-all).
    srv = server([None])
    qmp = QMPClient(srv.sockpath)
    qmp.greeting_timeout = 0.1
    qmp.capabilities_timeout = 0.3
    start = time.monotonic()
    with pytest.raises(QMPBusyError, match="qmp_capabilities"):
        qmp.connect()
    # max(capabilities_timeout, greeting_timeout): the floor wins here.
    assert 0.25 <= time.monotonic() - start <= 2.0
    assert qmp._sock is None


def test_handshake_budget_is_raised_with_greeting_timeout(server):
    srv = server([[b'{"return": {}, "id": $ID}'], [b'{"return": {}, "id": $ID}']])
    qmp = QMPClient(srv.sockpath)
    qmp.greeting_timeout = 30.0
    qmp.connect()
    # The capabilities exchange ran under the 30 s budget, not 10 s.
    assert qmp._sock.gettimeout() == 30.0
    qmp.close()
