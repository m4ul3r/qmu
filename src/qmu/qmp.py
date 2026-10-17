from __future__ import annotations

import json
import os
import re
import socket
import uuid
from pathlib import Path
from typing import Any


class QMPError(RuntimeError):
    pass


class QMPBusyError(QMPError):
    """The socket accepted the connection but QEMU never greeted it.

    QEMU serves one QMP client at a time: a second connect() completes in the
    kernel's listen backlog and then hears nothing until the first client
    leaves. That silence is a positive contention signal, not a dead VM, and
    it has to be told apart from "unreachable" — `status` used to stall 10 s
    per connect behind a `wait` and then report `qmp: connected`.
    """


class QMPTimeoutError(QMPError):
    """A command was sent but QEMU did not answer within the budget.

    Raised by `QMPClient.execute` after it has closed the socket: the reply is
    still owed and may arrive at any time, so a client that kept the
    connection would read it as the answer to its *next* command. QEMU's main
    loop is wedged in the command meanwhile (an HMP `savevm` of a large guest
    under host I/O load is the everyday case, #73), so the operation may
    still complete after the client gave up — the caller knows the command
    and decides what that means.
    """

    def __init__(self, command: str, timeout: float):
        super().__init__(
            f"QEMU did not answer `{command}` within {timeout:g}s; the command "
            "may still be running inside QEMU"
        )
        self.command = command
        self.timeout = timeout


# HMP reports its own failures as ordinary result text: `human-monitor-command`
# returns `{"return": "Error: ..."}` with no QMP error reply, so nothing raises
# and a wrapper that trusts "the call returned" reports success for an op that
# did nothing (`savevm 'has space'`, `monitor nonsense-cmd`). These are the
# forms QEMU's HMP layer and the snapshot/block/migration code emit, measured
# from QEMU 8.2.2 and the captured QEMU 11 transcript. Each is anchored at the
# start of a line, because every one of them is printed as its own line
# (`hmp_handle_error` -> `Error: <msg>`, the HMP parser's `monitor_printf`s,
# migration's `error_report`s) -- while result DATA can carry the same words
# anywhere else: a snapshot tagged `Error:checkpoint` sits in an `info
# snapshots` row behind the ID column, and an unanchored substring test made
# `qmu monitor 'info snapshots'` exit 1 on that perfectly good table (#86).
# Deliberately NOT included: the benign savevm slirp warning ("warning: Slirp:
# Save of field ... failed"), which precedes a snapshot that still lists and
# loads.
_HMP_ERROR_LINE_RES = tuple(
    re.compile(pattern)
    for pattern in (
        r"Error: ",                                  # hmp_handle_error / error_reportf_err
        r"unknown command: ",                        # HMP parser: no such verb
        r"\S+: extraneous characters at the end of line",  # HMP parser: `savevm has space`
        r'Try "help',                                # HMP parser usage epilogue
        r"Snapshot '.*' does not exist",             # pre-Error:-prefix loadvm/delvm
        r"[A-Za-z ]+ '[^']*' not found\.?$",         # Device 'x' not found and kin
        r"Device '[^']*' (is writable but )?does not support snapshots",
        r"Could not open ",                          # savevm/loadvm vmstate file
        r"No block device ",                         # no drive can hold a snapshot
        r"Missing section footer",                   # loadvm restore failures
        r"Section footer error",
        r"error while loading state",                # qemu_loadvm_state per-device
        r"Parameter '",                              # QAPI visitor: missing/unexpected member
        r"Invalid ",                                 # Invalid parameter / Invalid JSON
        r"invalid ",
    )
)


def hmp_failed(output: str) -> bool:
    """Whether HMP result text describes a failed command.

    The one classifier for every path that wraps `human-monitor-command`:
    the snapshot handlers, `qmu monitor`, and `qmu qmp human-monitor-command`.
    Empty output is success (most HMP verbs are silent when they work). A
    line is a failure report only when it BEGINS with one of QEMU's error
    frames; the same words inside a table row or a register dump are data.
    """
    return any(
        pattern.match(line.lstrip())
        for line in output.splitlines()
        for pattern in _HMP_ERROR_LINE_RES
    )



class QMPCommandError(QMPError):
    """A QEMU error *reply* to a command that was successfully sent.

    Distinct from every other QMPError, which carries a transport fault (socket
    refused, greeting rejected, connection closed, read timeout): here the wire
    worked and QEMU answered "no". QEMU's error ``class`` is the only
    machine-readable discriminator between a caller mistake (mistyped method ->
    ``CommandNotFound``; arguments the QAPI schema rejects -> ``GenericError``)
    and a host/VM-state failure, and carrying it out of ``_recv_response`` is
    what lets `qmu qmp` map the former onto the caller-error exit code instead
    of the infra one (#36: exit 4 made an agent retry or declare infra breakage
    over a typo). Subclasses QMPError so every existing ``except QMPError``
    site — the liveness/status probes in `_cliutil` and `lifecycle`, `kill`'s
    best-effort `quit` — keeps behaving identically.
    """

    def __init__(self, desc: str, qmp_class: str) -> None:
        super().__init__(desc)
        self.desc = desc
        self.qmp_class = qmp_class


class QMPClient:
    """Synchronous QMP (QEMU Machine Protocol) client over Unix socket."""

    # How long an accepted connection may stay silent before it is declared
    # held by another client. QEMU writes the greeting from accept(), so a
    # healthy server answers in microseconds; a main loop wedged in `savevm`
    # is the only other way to miss this, and that is contention too.
    greeting_timeout: float = 2.0
    # Floor for the capabilities reply after a greeting; see `connect`.
    capabilities_timeout: float = 10.0

    def __init__(self, socket_path: str | Path):
        self.socket_path = str(socket_path)
        self._sock: socket.socket | None = None
        self._buf = b""
        # Buffered async events received while waiting for command responses.
        self._events: list[dict] = []
        # Every command carries a client-unique `id`; replies are matched on
        # it so a reply owed to an earlier, abandoned client is never taken
        # as this one's answer (see `_recv_response`).
        self._id_prefix = f"qmu-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self._seq = 0
        self.stale_replies = 0

    def connect(self) -> dict:
        """Connect to QMP socket and negotiate capabilities. Returns greeting."""
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self.greeting_timeout)
        try:
            self._sock.connect(self.socket_path)
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            self.close()
            raise QMPError(f"Cannot connect to QMP socket {self.socket_path}: {exc}") from exc
        except (BlockingIOError, InterruptedError, socket.timeout, TimeoutError) as exc:
            # EAGAIN on a unix-socket connect() means the listen backlog is
            # full: QEMU has not accepted the connections queued behind the
            # client it is serving. That is the same contention as a silent
            # greeting, and it used to be reported as `unreachable` by one
            # command and `busy` by the next, depending on how many probes
            # were already queued.
            self.close()
            raise QMPBusyError(
                f"QMP socket {self.socket_path} is not accepting connections "
                f"({exc}). QEMU serves one QMP client at a time, so it is most "
                "likely held by another qmu command such as `wait`, or by a "
                "debugger bridge."
            ) from exc

        try:
            greeting = self._recv_json()
        except (socket.timeout, TimeoutError) as exc:
            self.close()
            raise QMPBusyError(
                f"QMP socket {self.socket_path} accepted the connection but sent "
                f"no greeting within {self.greeting_timeout:g}s. QEMU serves one "
                "QMP client at a time, so it is most likely held by another qmu "
                "command such as `wait`, or by a debugger bridge."
            ) from exc
        if "QMP" not in greeting:
            self.close()
            raise QMPError(f"Unexpected QMP greeting: {greeting}")
        # The greeting is written from accept(), but the capabilities reply is
        # the first thing QEMU's monitor *dispatches* for this client, so a
        # main loop wedged in `savevm` greets at once and then holds it (#73).
        # Same `busy` verdict as a missing greeting; the budget is whichever
        # of the two is longer, so `greeting_timeout` raised by a caller that
        # expects to wait (`snapshot list --timeout`) covers the handshake.
        handshake = max(self.capabilities_timeout, self.greeting_timeout)
        self._sock.settimeout(handshake)
        try:
            msg_id = self._send_command({"execute": "qmp_capabilities"})
            self._recv_response(msg_id)
        except (socket.timeout, TimeoutError) as exc:
            self.close()
            raise QMPBusyError(
                f"QMP socket {self.socket_path} greeted the connection but did "
                f"not answer qmp_capabilities within {handshake:g}s. QEMU's main "
                "loop is most likely inside a long command such as savevm, or "
                "the slot is held by another client."
            ) from exc
        return greeting

    def execute(
        self,
        command: str,
        arguments: dict | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Execute a QMP command and return the result.

        Raises `QMPTimeoutError` — with the socket already closed — when no
        reply arrives within `timeout`.
        """
        if self._sock is None:
            raise QMPError("Not connected")
        msg: dict[str, Any] = {"execute": command}
        # Distinguish "no arguments" (None) from an explicitly-empty dict: a
        # caller passing {} wants "arguments": {} on the wire, e.g. `qmp <cmd>
        # --args '{}'`. Only the default None omits the key entirely.
        if arguments is not None:
            msg["arguments"] = arguments
        self._sock.settimeout(timeout)
        try:
            msg_id = self._send_command(msg)
            return self._recv_response(msg_id)
        except (socket.timeout, TimeoutError) as exc:
            # Never leave the client behind: the late reply would otherwise
            # be read as the answer to the next command on this socket.
            self.close()
            label = command
            if command == "human-monitor-command" and arguments:
                label = f"human-monitor-command '{arguments.get('command-line', '')}'"
            raise QMPTimeoutError(label, timeout) from exc

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

    def _recv_response(self, expect_id: str | None = None) -> Any:
        """Read responses, buffer async events, return on return/error.

        A `return`/`error` tagged with an `id` other than `expect_id` is a
        stale reply and is dropped: QEMU delivers the answer to a command whose
        client went away — a `savevm` that outlived `snapshot save --timeout`
        — to whichever client holds the socket when it finishes, and read as
        this command's answer it made `query-status` return `{}` and `info
        snapshots` return "No snapshots." (#73). Replies without an `id` are
        trusted (test doubles, monitors that do not echo it).
        """
        while True:
            msg = self._recv_json()
            if "return" in msg or "error" in msg:
                reply_id = msg.get("id")
                if (
                    expect_id is not None
                    and reply_id is not None
                    and reply_id != expect_id
                ):
                    self.stale_replies += 1
                    continue
            if "return" in msg:
                return msg["return"]
            if "error" in msg:
                err = msg["error"]
                qmp_class = str(err.get("class", ""))
                desc = str(err.get("desc", qmp_class or "unknown error"))
                # No "QMP error: " prefix here: cli.main already renders a
                # QMPError under its own "[qmu] QMP error:" heading, which
                # produced "[qmu] QMP error: QMP error: The command ... has not
                # been found" — the string agents regex-match and paste.
                raise QMPCommandError(desc, qmp_class)
            if "event" in msg:
                # Buffer for later wait_event() calls.
                self._events.append(msg)
                continue

    def _send_command(self, msg: dict[str, Any]) -> str:
        """Tag `msg` with a client-unique `id`, send it, return the id."""
        self._seq += 1
        msg_id = f"{self._id_prefix}:{self._seq}"
        msg["id"] = msg_id
        self._send_json(msg)
        return msg_id

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
