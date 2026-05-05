"""QMPClient.wait_event correctness — tested against a fake unix socket server."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from qmu.qmp import QMPClient


class _FakeQMPServer:
    """Minimal QMP server that scripts a sequence of messages to send."""

    def __init__(self, messages: list[dict]):
        self.messages = messages
        self.tmpdir = tempfile.mkdtemp()
        self.sockpath = os.path.join(self.tmpdir, "qmp.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.sockpath)
        self.sock.listen(1)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        # ready file flag
        self._client_received: list[bytes] = []

    def _run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        # Greeting first
        greeting = {"QMP": {"version": {"qemu": {"major": 9}}, "capabilities": []}}
        conn.sendall(json.dumps(greeting).encode() + b"\n")
        # Wait for qmp_capabilities request
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        # Acknowledge
        conn.sendall(b'{"return": {}}\n')
        # Send the scripted messages with a tiny gap so the client doesn't
        # consume them all in one chunk.
        for msg in self.messages:
            conn.sendall(json.dumps(msg).encode() + b"\n")
            time.sleep(0.01)
        # Keep the connection open until the client closes; the test will
        # close the QMPClient which closes our peer.
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
        try:
            Path(self.sockpath).unlink(missing_ok=True)
        except OSError:
            pass


@pytest.fixture
def fake_server():
    servers: list[_FakeQMPServer] = []

    def make(messages: list[dict]) -> _FakeQMPServer:
        s = _FakeQMPServer(messages)
        servers.append(s)
        return s

    yield make

    for s in servers:
        s.close()


def test_wait_event_returns_matching_event(fake_server):
    server = fake_server([
        {"event": "STOP", "timestamp": {"seconds": 1, "microseconds": 0}, "data": {}},
    ])
    with QMPClient(server.sockpath) as qmp:
        ev = qmp.wait_event({"STOP", "SHUTDOWN"}, timeout=2.0)
    assert ev is not None
    assert ev["event"] == "STOP"


def test_wait_event_skips_unrelated_buffers_them(fake_server):
    server = fake_server([
        {"event": "RESUME", "timestamp": {"seconds": 1, "microseconds": 0}, "data": {}},
        {"event": "SHUTDOWN", "timestamp": {"seconds": 2, "microseconds": 0},
         "data": {"guest": True, "reason": "guest-shutdown"}},
    ])
    with QMPClient(server.sockpath) as qmp:
        ev = qmp.wait_event({"SHUTDOWN"}, timeout=2.0)
        assert ev is not None
        assert ev["event"] == "SHUTDOWN"
        # The unrelated RESUME event should be buffered (not dropped).
        buffered = [e["event"] for e in qmp._events]
        assert "RESUME" in buffered


def test_wait_event_drains_buffer_first(fake_server):
    """Already-buffered matching events are returned without reading from socket."""
    server = fake_server([])
    with QMPClient(server.sockpath) as qmp:
        # Manually pre-load the buffer.
        qmp._events.append({"event": "STOP", "timestamp": {}, "data": {}})
        ev = qmp.wait_event({"STOP"}, timeout=0.1)
    assert ev is not None
    assert ev["event"] == "STOP"


def test_wait_event_timeout_returns_none(fake_server):
    server = fake_server([])  # server sends nothing
    with QMPClient(server.sockpath) as qmp:
        ev = qmp.wait_event({"STOP"}, timeout=0.2)
    assert ev is None


def test_wait_event_string_arg_normalized(fake_server):
    """Passing a single str should also work (not just a set)."""
    server = fake_server([
        {"event": "POWERDOWN", "timestamp": {"seconds": 1, "microseconds": 0}, "data": {}},
    ])
    with QMPClient(server.sockpath) as qmp:
        ev = qmp.wait_event("POWERDOWN", timeout=2.0)
    assert ev is not None
    assert ev["event"] == "POWERDOWN"
