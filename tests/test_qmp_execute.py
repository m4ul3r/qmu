"""QMPClient.execute wire-format — tested against a fake unix socket server.

Regression coverage for the arguments guard: an explicitly-empty dict must be
sent as "arguments": {}, while the default None omits the key entirely.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from qmu.qmp import QMPClient


class _CapturingQMPServer:
    """QMP server that records each client request and replies with a return.

    Mirrors the greeting/capabilities handshake of the real monitor, then
    echoes an empty return for every subsequent command so execute() unblocks.
    Requests are exposed as parsed dicts in ``requests`` (capabilities excluded).
    """

    def __init__(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sockpath = os.path.join(self.tmpdir, "qmp.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.sockpath)
        self.sock.listen(1)
        self.requests: list[dict] = []
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        greeting = {"QMP": {"version": {"qemu": {"major": 9}}, "capabilities": []}}
        conn.sendall(json.dumps(greeting).encode() + b"\n")
        buf = b""
        first = True  # first line is qmp_capabilities negotiation
        try:
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                    continue
                line = buf[:nl]
                buf = buf[nl + 1:]
                if not line.strip():
                    continue
                if not first:
                    self.requests.append(json.loads(line))
                first = False
                conn.sendall(b'{"return": {}}\n')
        except OSError:
            return

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
def capturing_server():
    servers: list[_CapturingQMPServer] = []

    def make() -> _CapturingQMPServer:
        s = _CapturingQMPServer()
        servers.append(s)
        return s

    yield make

    for s in servers:
        s.close()


def test_execute_omits_arguments_when_none(capturing_server):
    server = capturing_server()
    with QMPClient(server.sockpath) as qmp:
        qmp.execute("query-status", timeout=2.0)
    assert server.requests == [{"execute": "query-status"}]
    assert "arguments" not in server.requests[0]


def test_execute_sends_explicit_empty_arguments(capturing_server):
    server = capturing_server()
    with QMPClient(server.sockpath) as qmp:
        qmp.execute("query-status", {}, timeout=2.0)
    assert server.requests == [{"execute": "query-status", "arguments": {}}]


def test_execute_sends_populated_arguments(capturing_server):
    server = capturing_server()
    with QMPClient(server.sockpath) as qmp:
        qmp.execute("device_add", {"foo": 1}, timeout=2.0)
    assert server.requests == [{"execute": "device_add", "arguments": {"foo": 1}}]
