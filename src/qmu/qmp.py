from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


class QMPError(RuntimeError):
    pass


class QMPClient:
    """Synchronous QMP (QEMU Machine Protocol) client over Unix socket."""

    def __init__(self, socket_path: str | Path):
        self.socket_path = str(socket_path)
        self._sock: socket.socket | None = None
        self._buf = b""
        # Buffered async events received while waiting for command responses.
        self._events: list[dict] = []

    def connect(self) -> dict:
        """Connect to QMP socket and negotiate capabilities. Returns greeting."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(10.0)
        try:
            self._sock.connect(self.socket_path)
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            self.close()
            raise QMPError(f"Cannot connect to QMP socket {self.socket_path}: {exc}") from exc

        greeting = self._recv_json()
        if "QMP" not in greeting:
            self.close()
            raise QMPError(f"Unexpected QMP greeting: {greeting}")

        # Negotiate capabilities
        self._send_json({"execute": "qmp_capabilities"})
        resp = self._recv_response()
        return greeting

    def execute(
        self,
        command: str,
        arguments: dict | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Execute a QMP command and return the result."""
        if self._sock is None:
            raise QMPError("Not connected")
        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        self._sock.settimeout(timeout)
        self._send_json(msg)
        return self._recv_response()

    def execute_hmp(self, command_line: str, timeout: float = 30.0) -> str:
        """Execute an HMP command via QMP's human-monitor-command."""
        result = self.execute(
            "human-monitor-command",
            {"command-line": command_line},
            timeout=timeout,
        )
        if isinstance(result, str):
            return result
        return str(result)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._buf = b""

    def _send_json(self, obj: dict) -> None:
        assert self._sock is not None
        data = json.dumps(obj).encode("utf-8") + b"\n"
        self._sock.sendall(data)

    def _recv_json(self) -> dict:
        """Read one complete JSON object (newline-delimited) from the socket."""
        assert self._sock is not None
        while True:
            # Try to extract a complete line from the buffer
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = self._buf[:nl]
                self._buf = self._buf[nl + 1:]
                if line.strip():
                    return json.loads(line)
                continue  # skip empty lines

            # Also try parsing the entire buffer as a JSON object
            # (some QEMU versions may not use trailing newline for greeting)
            stripped = self._buf.strip()
            if stripped:
                try:
                    obj = json.loads(stripped)
                    self._buf = b""
                    return obj
                except json.JSONDecodeError:
                    pass

            chunk = self._sock.recv(65536)
            if not chunk:
                raise QMPError("QMP connection closed unexpectedly")
            self._buf += chunk

    def _recv_response(self) -> Any:
        """Read responses, buffer async events, return on return/error."""
        while True:
            msg = self._recv_json()
            if "return" in msg:
                return msg["return"]
            if "error" in msg:
                err = msg["error"]
                desc = err.get("desc", err.get("class", "unknown error"))
                raise QMPError(f"QMP error: {desc}")
            if "event" in msg:
                # Buffer for later wait_event() calls.
                self._events.append(msg)
                continue

    def wait_event(
        self,
        event_names: set[str] | str,
        timeout: float | None = None,
    ) -> dict | None:
        """Block until any named QMP event fires. Returns the event dict, or None on timeout.

        Drains previously-buffered events first, then reads from the socket.
        Caller must not interleave execute() with wait_event() — buffered command
        responses would be discarded.
        """
        if isinstance(event_names, str):
            event_names = {event_names}

        # First scan the buffer for an already-queued match.
        for i, ev in enumerate(self._events):
            if ev.get("event") in event_names:
                return self._events.pop(i)

        if self._sock is None:
            raise QMPError("Not connected")
        self._sock.settimeout(timeout)
        try:
            while True:
                msg = self._recv_json()
                if "event" in msg:
                    if msg["event"] in event_names:
                        return msg
                    self._events.append(msg)
                    continue
                # Stray return/error (no execute() in flight) — drop it; caller
                # should not be interleaving execute() with wait_event().
        except (socket.timeout, TimeoutError):
            return None

    def __enter__(self) -> QMPClient:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
