"""The qmu daemon (#70): one supervisor per cache dir that owns each watched
VM's single QMP connection and its serial-log scan.

Why a daemon
------------
QEMU serves ONE QMP client. Every qmu command used to open its own
short-lived connection, so two concurrent commands contended (`qmp: busy`),
and nobody held a connection long enough to *see* events — a guest-initiated
reboot had to be inferred from the kernel's boot banner, a panic from
polling the log at 250 ms. The daemon holds the connection, consumes the
event stream, keeps the per-VM record's guest epoch current, and lets any
number of CLI commands read the cached state or proxy a command through the
one connection under a per-VM lock. `wait` blocks on the daemon's socket and
is woken by the daemon's 100 ms serial tick instead of polling itself.

Process model
-------------
`qmu daemon run` is this module's `serve()` in the foreground; the client
(`qmu.daemon_client`) spawns it detached on demand. `<cache>/daemon.json` is
the record (pid, /proc start-time, build id, socket path), written only after
the socket is bound so a record always names a listener. The daemon exits on
`shutdown`, on SIGTERM/SIGINT, or after `idle_exit` seconds with no client
connected and no watched VM alive.

Protocol
--------
Newline-delimited JSON over a Unix stream socket. Request `{"id": n, "op":
..., ...params}`; reply `{"id": n, "ok": true, "result": {...}}` or `{"id":
n, "ok": false, "error": ..., "error_type": ...}`; a streaming op emits
`{"id": n, "event": {...}}` lines before its reply. Ops: `ping`, `watch`,
`unwatch`, `vm_state`, `epoch` (a boundary a command persisted without a
RESET, e.g. `snapshot load`), `qmp`, `wait`, `shutdown`.

Two state axes, as everywhere in qmu: `exited` is the existence axis (the
recorded process is gone); `running`/`panicked` describe the guest.

Ownership rule (#118, #119)
---------------------------
A subscribed `wait` is never stranded. The daemon keeps a watch until the
recorded process is positively gone — `kill` sends `quit` THROUGH the
daemon's connection and the EOF-then-PID check marks the watch `exited`, so
every subscriber gets `process_exited`. QMP `SHUTDOWN` alone never counts
as death. When ownership ends while the process lives — an explicit
`unwatch`, or the daemon itself stopping — every subscriber is answered
with `reason: "released"` (after a `{"kind": "released"}` event) and
finishes standalone on PID liveness; `unwatch` answers `released: true`
only after the QMP reader is shut down and joined, so QEMU's slot is free
the moment the client reads the reply.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import debug as debug_mod
from .daemon_client import (
    build_id as compute_build_id,
    default_socket_path,
    read_record,
    record_alive,
    record_path,
)
from .instance import (
    VMInstance,
    instance_alive,
    list_instances,
    load_instance,
    proc_pid_start,
    save_guest_epoch_serial_offset,
)
from .paths import cache_home
from .qmp import QMPBusyError, QMPClient, QMPCommandError, QMPError, QMPTimeoutError
from .serial import (
    SerialTail,
    count_boot_banners,
    current_boot_offset,
    scan_console_growth,
    scan_for_pattern,
    serial_log_offset,
)
from .ssh import SSHClient

# The serial tick: one `os.stat` per watched log per tick, a scan only on
# growth. 100 ms bounds `wait --pattern` latency; the standalone loop polls at
# 250 ms and a shell loop at seconds.
TICK_SECONDS = 0.1
# Liveness (`/proc/<pid>/stat`) is re-checked this often per watched VM, in
# addition to the QMP EOF that normally announces an exit first.
LIVENESS_EVERY_TICKS = 10
# QEMU closes QMP ~100 ms before its pid vanishes; after EOF the supervisor
# polls identity for at most this long before deciding the transport broke
# under a VM that lives on.
EOF_GRACE_SECONDS = 1.0
# An exited VM's state stays queryable this long so a `wait` or `status`
# racing the exit gets `exited: true` rather than "not watched".
EXITED_RETENTION_SECONDS = 60.0
# A `--pattern` wait re-tests the withheld trailing fragment after this much
# silence (a `login:` prompt never gets its newline).
FRAGMENT_IDLE_SECONDS = 0.25
# Budget for the daemon's own QMP connect when adopting a VM. Short: a slot
# held by a standalone command is a fact to report, not to wait out.
ADOPT_GREETING_TIMEOUT = 1.0
# How long `close()` waits for the reader thread to notice the shutdown. A
# shutdown wakes it immediately; the bound only guards against a wedged host.
READER_JOIN_SECONDS = 2.0
# How long a stopping daemon waits for its in-flight `wait` ops to answer
# `released` before cutting their connections.
SHUTDOWN_RELEASE_SECONDS = 1.0

QMP_EVENT_SOURCE = "qmp"

# The events that describe the guest's life, and so are worth reporting as
# `last_event`. QEMU also streams device chatter (NIC_RX_FILTER_CHANGED,
# RTC_CHANGE, BLOCK_IO_ERROR…) that would otherwise bury the one that matters.
LIFECYCLE_EVENTS = frozenset({
    "RESET", "STOP", "RESUME", "SHUTDOWN", "POWERDOWN", "GUEST_PANICKED",
    "WATCHDOG", "SUSPEND", "WAKEUP", "GUEST_CRASHLOADED",
})


def _log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    sys.stderr.write(f"{stamp} [qmu-daemon] {message}\n")
    sys.stderr.flush()


# --- the supervised QMP connection ---------------------------------------------


class _EventQMP:
    """One QMP connection whose socket is read by a dedicated thread.

    Commands are tagged with an id and parked on an Event until the reader
    delivers their reply; events go to `on_event` as they arrive. The
    handshake reuses `QMPClient` (greeting, `qmp_capabilities`, the busy
    verdicts) and then takes over its socket.
    """

    def __init__(self, socket_path: str, on_event, on_closed):
        self._client = QMPClient(socket_path)
        self._client.greeting_timeout = ADOPT_GREETING_TIMEOUT
        self._on_event = on_event
        self._on_closed = on_closed
        self._pending: dict[str, dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.closed = False

    def connect(self) -> None:
        self._client.connect()
        self._thread = threading.Thread(target=self._reader, daemon=True, name="qmp-reader")
        self._thread.start()
        # Events QEMU sent during the handshake were buffered by the client.
        for msg in self._client._events:
            self._on_event(msg)
        self._client._events.clear()

    def _reader(self) -> None:
        sock = self._client._sock
        buf = self._client._buf
        self._client._buf = b""
        try:
            sock.settimeout(None)
            while True:
                nl = buf.find(b"\n")
                if nl >= 0:
                    line = buf[:nl]
                    buf = buf[nl + 1:]
                    if line.strip():
                        try:
                            self._dispatch(json.loads(line))
                        except ValueError:
                            pass
                    continue
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        finally:
            self._fail_pending(QMPError("QMP connection closed"))
            was_closed = self.closed
            self.closed = True
            if not was_closed:
                self._on_closed()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        if "event" in msg:
            self._on_event(msg)
            return
        if "return" in msg or "error" in msg:
            msg_id = msg.get("id")
            with self._pending_lock:
                slot = self._pending.pop(msg_id, None) if msg_id is not None else None
            if slot is None:
                return  # a reply owed to a command whose caller gave up
            slot["reply"] = msg
            slot["event"].set()

    def _fail_pending(self, exc: Exception) -> None:
        with self._pending_lock:
            slots = list(self._pending.values())
            self._pending.clear()
        for slot in slots:
            slot["error"] = exc
            slot["event"].set()

    def command(self, execute: str, arguments: dict | None, timeout: float) -> Any:
        if self.closed:
            raise QMPError("QMP connection closed")
        msg: dict[str, Any] = {"execute": execute}
        if arguments is not None:
            msg["arguments"] = arguments
        self._client._seq += 1
        msg_id = f"{self._client._id_prefix}:{self._client._seq}"
        msg["id"] = msg_id
        slot: dict[str, Any] = {"event": threading.Event()}
        with self._pending_lock:
            self._pending[msg_id] = slot
        try:
            with self._send_lock:
                self._client._sock.sendall(json.dumps(msg).encode("utf-8") + b"\n")
        except OSError as exc:
            with self._pending_lock:
                self._pending.pop(msg_id, None)
            raise QMPError(f"QMP send failed: {exc}") from exc
        if not slot["event"].wait(timeout):
            with self._pending_lock:
                self._pending.pop(msg_id, None)
            label = execute
            if execute == "human-monitor-command" and arguments:
                label = f"human-monitor-command '{arguments.get('command-line', '')}'"
            raise QMPTimeoutError(label, timeout)
        if "error" in slot and "reply" not in slot:
            raise slot["error"]
        reply = slot["reply"]
        if "error" in reply:
            err = reply["error"]
            qmp_class = str(err.get("class", ""))
            raise QMPCommandError(str(err.get("desc", qmp_class or "unknown error")), qmp_class)
        return reply.get("return")

    def close(self) -> None:
        """Drop the connection and return only once the reader has let go.

        `QMPClient.close()` shuts the socket down, which wakes the reader
        with EOF; joining it (bounded) is what makes `released: true` mean
        the slot is free — a client that connected on that answer while the
        reader was still parked in `recv` got no greeting (#119). Never
        joins from the reader itself (`_mark_exited` runs on it after EOF).
        """
        self.closed = True
        self._client.close()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(READER_JOIN_SECONDS)


# --- per-VM state --------------------------------------------------------------


@dataclass
class VMWatch:
    vm_id: str
    inst: VMInstance
    qmp: _EventQMP | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    # guest axis
    running: bool | None = None
    qemu_status: str = "unknown"
    panicked: bool = False
    last_event: str | None = None
    last_event_at: float | None = None
    event_data: Any = None
    event_seq: int = 0
    # existence axis
    exited: bool = False
    exit_reason: str | None = None
    exited_at: float | None = None
    qmp_lost: bool = False
    # ownership: an explicit `unwatch` ended the daemon's supervision while
    # the process lives on. Every subscribed wait is told (`released`) and
    # finishes standalone; the watch itself is already out of `watches`.
    released: bool = False
    # console scan
    epoch_offset: int = 0
    epoch_source: str | None = None
    banners_since_epoch: int = 0
    boot_offset: int = 0
    scanned: int = 0
    log_size: int = -1
    needs_refresh: bool = False
    # A command a client proxied through this connection (`op_qmp`) is
    # executing; QEMU runs it on its main loop, so nothing else is answered
    # until it returns. `status_stale`: QEMU stopped the vCPUs under such a
    # command (`savevm`/`loadvm` emit STOP) and no `query-status` has
    # answered since — the cached run state is unknown, not `paused` (#137).
    qmp_inflight: str | None = None
    status_stale: bool = False
    watched_at: float = field(default_factory=time.time)

    def state(self) -> dict[str, Any]:
        observed = self.epoch_source == "observed" and self.banners_since_epoch <= 1
        # Busy is what the standalone path reports for the same condition
        # (QEMU greets but does not answer): the run state is unknown until
        # QEMU answers again. Synthesising `paused` from the STOP handed every
        # concurrent `status`/`list` the debugger-halt signature and its
        # `qmu cont` recovery for the length of a save.
        busy = self.status_stale
        return {
            "watched": True,
            "vm_id": self.vm_id,
            "pid": self.inst.pid,
            "running": None if busy else self.running,
            "qemu_status": "unknown" if busy else self.qemu_status,
            "qmp_busy": busy,
            "qmp_inflight": self.qmp_inflight,
            "panicked": self.panicked,
            "last_event": self.last_event,
            "last_event_at": self.last_event_at,
            "event_data": self.event_data,
            "exited": self.exited,
            "exit_reason": self.exit_reason,
            "qmp_lost": self.qmp_lost,
            "boot_offset": self.boot_offset,
            "epoch_offset": self.epoch_offset,
            "epoch_source": "observed" if observed else "banner",
            "log_size": max(self.log_size, 0),
        }


class Daemon:
    def __init__(self, cache_dir: Path, *, idle_exit: float = 600.0):
        self.cache_dir = cache_dir
        self.idle_exit = idle_exit
        self.build_id = compute_build_id()
        self.started = time.time()
        self.socket_path = default_socket_path(cache_dir)
        self.cond = threading.Condition()
        self.watches: dict[str, VMWatch] = {}
        self._adopt_locks: dict[str, threading.Lock] = {}
        self.clients: set[_ClientSession] = set()
        self.stop = threading.Event()
        self._idle_since: float | None = None
        self._listener: socket.socket | None = None
        # `wait` ops between dispatch and reply; `_cleanup` drains it.
        self._waits_in_flight = 0

    # --- lifecycle -------------------------------------------------------------

    def serve(self) -> int:
        existing = read_record(self.cache_dir)
        if record_alive(existing) and existing.get("pid") != os.getpid():
            _log(f"another daemon (pid {existing.get('pid')}) serves {self.cache_dir}; exiting")
            return 0
        self._bind()
        self._write_record()
        _log(f"serving {self.cache_dir} on {self.socket_path} (build {self.build_id}, pid {os.getpid()})")
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, lambda *_: self.stop.set())
            except (ValueError, OSError):
                pass
        threading.Thread(target=self._tick_loop, daemon=True, name="serial-tick").start()
        # Adopt every live record in the background: a busy slot costs a
        # greeting budget per VM, and the client that spawned us is waiting
        # on the socket, not on the adoption.
        threading.Thread(target=self._adopt_all, daemon=True, name="adopt").start()
        try:
            self._accept_loop()
        finally:
            self._cleanup()
        _log("stopped")
        return 0

    def _adopt_all(self) -> None:
        for inst in list_instances():
            if self.stop.is_set():
                return
            try:
                self.watch(inst.vm_id)
            except Exception as exc:  # noqa: BLE001 — adoption is best-effort
                _log(f"could not adopt {inst.vm_id}: {exc}")

    def _bind(self) -> None:
        path = self.socket_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.5)
            try:
                probe.connect(str(path))
                live = True
            except OSError:
                live = False
            finally:
                probe.close()
            if live:
                raise SystemExit(f"a daemon already listens on {path}")
            path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(64)
        listener.settimeout(0.5)
        self._listener = listener

    def _write_record(self) -> None:
        record = {
            "pid": os.getpid(),
            "pid_start": proc_pid_start(os.getpid()),
            "build_id": self.build_id,
            "socket": str(self.socket_path),
            "cache_dir": str(self.cache_dir),
            "started_at": self.started,
            "idle_exit": self.idle_exit,
        }
        path = record_path(self.cache_dir)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        with os.fdopen(fd, "w") as handle:
            json.dump(record, handle)
        os.replace(tmp, path)

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self.stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            session = _ClientSession(self, conn)
            with self.cond:
                self.clients.add(session)
            session.start()

    def _cleanup(self) -> None:
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        # A stopping daemon no longer owns any VM: every subscribed wait gets
        # its `released` transition and answers before its connection is cut,
        # so a build-id respawn mid-wait is a hand-off, not an exit 4.
        with self.cond:
            watches = list(self.watches.values())
            for watch in watches:
                if not watch.exited:
                    watch.released = True
            self.cond.notify_all()
            deadline = time.monotonic() + SHUTDOWN_RELEASE_SECONDS
            while self._waits_in_flight > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.cond.wait(remaining)
            clients = list(self.clients)
        for watch in watches:
            if watch.qmp is not None:
                watch.qmp.close()
        for client in clients:
            client.close()
        record = read_record(self.cache_dir)
        if record is None or record.get("pid") == os.getpid():
            for path in (self.socket_path, record_path(self.cache_dir)):
                try:
                    path.unlink()
                except OSError:
                    pass

    def _client_gone(self, session: _ClientSession) -> None:
        with self.cond:
            self.clients.discard(session)
            self.cond.notify_all()

    # --- watch management ------------------------------------------------------

    def _adopt_lock(self, vm_id: str) -> threading.Lock:
        with self.cond:
            lock = self._adopt_locks.get(vm_id)
            if lock is None:
                lock = self._adopt_locks[vm_id] = threading.Lock()
            return lock

    def watch(self, vm_id: str) -> dict[str, Any]:
        # Single-flight per VM: the startup adoption sweep and a client's
        # `watch` can race, and two supervisors on one VM would mean two QMP
        # connections queued on QEMU's single slot and double bookkeeping.
        with self._adopt_lock(vm_id):
            return self._watch(vm_id)

    def _watch(self, vm_id: str) -> dict[str, Any]:
        with self.cond:
            current = self.watches.get(vm_id)
            if current is not None and not current.exited:
                return current.state()
        inst = load_instance(vm_id)
        if inst is None:
            raise _OpError(f"VM '{vm_id}' has no instance record", "NoRecord")
        if not instance_alive(inst):
            raise _OpError(f"VM '{vm_id}' is not running", "NotRunning")
        watch = VMWatch(vm_id=vm_id, inst=inst)
        watch.epoch_offset = inst.guest_epoch_serial_offset or 0
        watch.epoch_source = inst.guest_epoch_source
        watch.boot_offset = current_boot_offset(inst.serial_log, watch.epoch_offset)
        # Banners between the recorded epoch and the boot boundary tell whether
        # that epoch still describes the current boot (none or one: yes; more:
        # an unwitnessed reboot). The boundary's own banner is counted by the
        # first scan, which starts exactly there.
        watch.banners_since_epoch = count_boot_banners(
            inst.serial_log, start_offset=watch.epoch_offset, end_offset=watch.boot_offset
        )
        watch.scanned = watch.boot_offset
        qmp = _EventQMP(
            inst.qmp_socket,
            on_event=lambda msg, w=watch: self._on_qmp_event(w, msg),
            on_closed=lambda w=watch: self._on_qmp_closed(w),
        )
        try:
            qmp.connect()
        except QMPBusyError as exc:
            raise _OpError(str(exc), "QMPBusyError") from exc
        except (QMPError, OSError) as exc:
            raise _OpError(f"cannot connect to QMP of '{vm_id}': {exc}", "QMPError") from exc
        watch.qmp = qmp
        try:
            self._apply_status(watch, qmp.command("query-status", None, 5.0))
        except QMPError as exc:
            qmp.close()
            raise _OpError(f"query-status on '{vm_id}' failed: {exc}", "QMPError") from exc
        self._scan(watch)
        with self.cond:
            self.watches[vm_id] = watch
            self.cond.notify_all()
        _log(f"watching {vm_id} (pid {inst.pid}, epoch {watch.epoch_offset}, boot {watch.boot_offset})")
        return watch.state()

    def unwatch(self, vm_id: str) -> bool:
        """End the daemon's ownership of `vm_id` while its process lives on.

        Two promises make `released: true` mean what it says (#118, #119):
        every wait subscribed to the watch is woken with a terminal
        `released` transition (it then finishes standalone on PID liveness),
        and the QMP reader has been shut down and joined, so QEMU's one slot
        is free for whoever asked. A VM that already exited is simply
        forgotten — its waiters got `exited` first.
        """
        with self.cond:
            watch = self.watches.pop(vm_id, None)
            if watch is not None and not watch.exited:
                watch.released = True
            self.cond.notify_all()
        if watch is None:
            return False
        if watch.qmp is not None:
            watch.qmp.close()
        _log(f"released {vm_id}" + (" (subscribers told)" if watch.released else ""))
        return True

    def vm_state(self, vm_id: str) -> dict[str, Any]:
        with self.cond:
            watch = self.watches.get(vm_id)
            if watch is None:
                return {"watched": False, "vm_id": vm_id}
            return watch.state()

    def adopt_epoch(self, vm_id: str, offset: int) -> dict[str, Any]:
        """A guest boundary a qmu command persisted with no RESET to show for it.

        `loadvm` rewinds the guest without a QMP RESET, so the event stream
        never sees the generation change `snapshot load` records: the watch
        kept the epoch it copied at adoption, and daemon-backed `status`/
        `list` went on attributing the rewound-away crash while `qmu crash`,
        reading the record, found none (#135). The command hands the offset
        it just persisted to the daemon; only a forward move within the
        current log is taken, so a stale or foreign offset cannot rewind an
        epoch the daemon itself observed later.
        """
        with self.cond:
            watch = self.watches.get(vm_id)
            if watch is None or watch.exited:
                return {"watched": False, "vm_id": vm_id}
        size = serial_log_offset(watch.inst.serial_log)
        with self.cond:
            adopted = watch.epoch_offset < offset <= size
            if adopted:
                self._advance_epoch(watch, offset)
                self.cond.notify_all()
            state = watch.state()
        if adopted:
            _log(f"{vm_id}: epoch -> {offset} (recorded by a qmu command)")
        return state

    def _apply_status(self, watch: VMWatch, status: Any) -> None:
        if not isinstance(status, dict):
            return
        running = status.get("running")
        name = status.get("status")
        with self.cond:
            if isinstance(running, bool):
                watch.running = running
            if isinstance(name, str):
                watch.qemu_status = name
            watch.status_stale = False
            self.cond.notify_all()

    def _advance_epoch(self, watch: VMWatch, epoch: int) -> None:
        """Under `self.cond`: the guest's current generation starts at `epoch`.

        Everything before it belongs to a guest that no longer exists — a
        reset rebooted it, a `loadvm` rewound it — so a panic seen there no
        longer describes this one.
        """
        watch.epoch_offset = epoch
        watch.epoch_source = "observed"
        watch.banners_since_epoch = 0
        watch.boot_offset = max(watch.boot_offset, epoch)
        watch.scanned = max(watch.scanned, epoch)
        watch.panicked = False

    # --- QMP events --------------------------------------------------------------

    def _record_event(self, watch: VMWatch, name: str, data: Any) -> None:
        watch.last_event = name
        watch.last_event_at = time.time()
        watch.event_data = {"source": QMP_EVENT_SOURCE, **(data if isinstance(data, dict) else {})}
        watch.event_seq += 1

    def _on_qmp_event(self, watch: VMWatch, msg: dict[str, Any]) -> None:
        name = str(msg.get("event", ""))
        if name not in LIFECYCLE_EVENTS:
            return
        data = msg.get("data")
        with self.cond:
            self._record_event(watch, name, data)
            if name == "RESET":
                self._advance_epoch(watch, serial_log_offset(watch.inst.serial_log))
                watch.running = True
                watch.qemu_status = "running"
                watch.status_stale = False
                watch.needs_refresh = True
            elif name == "STOP":
                watch.running = False
                if watch.qmp_inflight is not None:
                    # QEMU stopped the vCPUs itself to run the command a
                    # client proxied through us (`savevm` does this for the
                    # whole save) and answers nothing else until it returns:
                    # the run state is unknown, and the refresh below waits
                    # behind the command.
                    watch.status_stale = True
                elif watch.qemu_status == "running":
                    watch.qemu_status = "paused"
                watch.needs_refresh = True
            elif name == "RESUME":
                watch.running = True
                watch.qemu_status = "running"
                watch.status_stale = False
            elif name == "GUEST_PANICKED":
                watch.panicked = True
                watch.needs_refresh = True
            elif name in ("SHUTDOWN", "POWERDOWN"):
                if name == "SHUTDOWN":
                    watch.running = False
                    watch.qemu_status = "shutdown"
            self.cond.notify_all()
        if name == "RESET":
            threading.Thread(
                target=self._persist_reset, args=(watch, watch.epoch_offset), daemon=True
            ).start()

    def _persist_reset(self, watch: VMWatch, epoch: int) -> None:
        """Write the observed epoch through a fresh read of the record, and drop
        the SSH ControlMaster that now points at a host key the new boot may
        not have."""
        inst = load_instance(watch.vm_id)
        if inst is not None:
            try:
                watch.inst = save_guest_epoch_serial_offset(inst, epoch, source="observed")
            except (OSError, TypeError, ValueError) as exc:
                _log(f"{watch.vm_id}: could not persist epoch {epoch}: {exc}")
        _log(f"{watch.vm_id}: RESET observed, epoch -> {epoch}")
        inst = watch.inst
        if not inst.harness and inst.ssh_port is not None and inst.ssh_key:
            try:
                SSHClient(port=inst.ssh_port, key_path=inst.ssh_key, user=inst.ssh_user).close_control_master()
            except Exception as exc:  # noqa: BLE001 — best-effort teardown
                _log(f"{watch.vm_id}: ssh master teardown failed: {exc}")

    def _on_qmp_closed(self, watch: VMWatch) -> None:
        # A daemon that is shutting down no longer owns the VM's story: an
        # EOF arriving during teardown must not reap bridges or rewrite
        # records that the next daemon (or the standalone path) will own.
        deadline = time.monotonic() + EOF_GRACE_SECONDS
        while instance_alive(watch.inst) and time.monotonic() < deadline:
            if self.stop.is_set():
                return
            time.sleep(0.02)
        if self.stop.is_set():
            return
        if instance_alive(watch.inst):
            with self.cond:
                watch.qmp_lost = True
                self.cond.notify_all()
            _log(f"{watch.vm_id}: QMP closed but pid {watch.inst.pid} lives on")
            return
        self._mark_exited(watch, "process_exited")

    def _mark_exited(self, watch: VMWatch, reason: str) -> None:
        with self.cond:
            if watch.exited or self.stop.is_set():
                return
            watch.exited = True
            watch.exit_reason = reason
            watch.exited_at = time.time()
            watch.running = False
            self.cond.notify_all()
        if watch.qmp is not None:
            watch.qmp.close()
        _log(f"{watch.vm_id}: exited ({reason})")
        threading.Thread(
            target=debug_mod.reap_bridge_on_exit, args=(watch.vm_id,), daemon=True
        ).start()

    # --- the serial tick ---------------------------------------------------------

    def _scan(self, watch: VMWatch) -> None:
        """One incremental console scan for `watch`; notifies on growth."""
        size = serial_log_offset(watch.inst.serial_log)
        if size == watch.log_size:
            return
        scanned_from = watch.scanned
        scanned, banner, panicked = scan_console_growth(
            watch.inst.serial_log, scanned=scanned_from, boot_offset=watch.boot_offset
        )
        shrank = banner < watch.boot_offset or scanned < scanned_from
        new_banners = 0 if shrank else count_boot_banners(
            watch.inst.serial_log, start_offset=scanned_from, end_offset=scanned
        )
        with self.cond:
            if shrank:
                # The log shrank: a new log generation, nothing observed
                # about it yet.
                watch.banners_since_epoch = count_boot_banners(
                    watch.inst.serial_log, start_offset=0, end_offset=scanned
                )
                watch.epoch_offset = 0
                watch.epoch_source = None
            else:
                watch.banners_since_epoch += new_banners
            if banner != watch.boot_offset:
                watch.boot_offset = banner
                watch.panicked = False
            if panicked:
                watch.panicked = True
            watch.scanned = scanned
            watch.log_size = size
            self.cond.notify_all()

    def _tick_loop(self) -> None:
        ticks = 0
        while not self.stop.is_set():
            ticks += 1
            with self.cond:
                watches = list(self.watches.values())
            now = time.time()
            for watch in watches:
                if watch.exited:
                    if watch.exited_at is not None and now - watch.exited_at > EXITED_RETENTION_SECONDS:
                        with self.cond:
                            self.watches.pop(watch.vm_id, None)
                    continue
                try:
                    self._scan(watch)
                except Exception as exc:  # noqa: BLE001 — one bad log must not stop the tick
                    _log(f"{watch.vm_id}: scan failed: {exc}")
                if ticks % LIVENESS_EVERY_TICKS == 0 and not instance_alive(watch.inst):
                    self._mark_exited(watch, "process_exited")
                    continue
                if watch.needs_refresh and watch.qmp is not None and not watch.qmp.closed:
                    watch.needs_refresh = False
                    threading.Thread(target=self._refresh_status, args=(watch,), daemon=True).start()
            self._check_idle(now)
            time.sleep(TICK_SECONDS)

    def _refresh_status(self, watch: VMWatch) -> None:
        if watch.qmp is None:
            return
        with watch.lock:
            try:
                status = watch.qmp.command("query-status", None, 5.0)
            except QMPError:
                # A run state left unknown under a proxied command stays
                # unknown until QEMU answers: a client that gave up on a
                # `savevm` (exit 124) leaves QEMU saving, and the next tick
                # asks again rather than freezing `busy` (or a guess) forever.
                if watch.status_stale:
                    watch.needs_refresh = True
                return
        self._apply_status(watch, status)

    def _check_idle(self, now: float) -> None:
        if self.idle_exit <= 0:
            return
        with self.cond:
            busy = bool(self.clients) or any(not w.exited for w in self.watches.values())
        if busy:
            self._idle_since = None
            return
        if self._idle_since is None:
            self._idle_since = now
        elif now - self._idle_since >= self.idle_exit:
            _log(f"idle for {self.idle_exit:g}s; exiting")
            self.stop.set()

    # --- ops -------------------------------------------------------------------

    def op_ping(self) -> dict[str, Any]:
        with self.cond:
            vms = [
                {
                    "vm_id": w.vm_id,
                    "pid": w.inst.pid,
                    "running": w.running,
                    "qemu_status": w.qemu_status,
                    "last_event": w.last_event,
                    "exited": w.exited,
                    "panicked": w.panicked,
                }
                for w in self.watches.values()
            ]
            clients = len(self.clients)
        return {
            "build_id": self.build_id,
            "pid": os.getpid(),
            "uptime": round(time.time() - self.started, 3),
            "idle_exit": self.idle_exit,
            "socket": str(self.socket_path),
            "cache_dir": str(self.cache_dir),
            "clients": clients,
            "vms": vms,
        }

    def op_qmp(self, vm_id: str, execute: str, arguments: Any, timeout: float) -> dict[str, Any]:
        with self.cond:
            watch = self.watches.get(vm_id)
        if watch is None:
            raise _OpError(f"VM '{vm_id}' is not watched", "NotWatched")
        if watch.exited or watch.qmp is None or watch.qmp.closed:
            raise _OpError(f"VM '{vm_id}' QMP connection is gone", "QMPError")
        if not isinstance(execute, str) or not execute:
            raise _OpError("qmp: 'execute' must be a non-empty string", "ValueError")
        label = execute
        if execute == "human-monitor-command" and isinstance(arguments, dict):
            label = f"{execute} {str(arguments.get('command-line', '')).split(' ', 1)[0]}".rstrip()
        with watch.lock:
            with self.cond:
                watch.qmp_inflight = label
            try:
                result = watch.qmp.command(
                    execute, arguments if isinstance(arguments, dict) else None, timeout
                )
            except QMPCommandError as exc:
                raise _OpError(str(exc), "QMPCommandError", qmp_class=exc.qmp_class) from exc
            except QMPTimeoutError as exc:
                raise _OpError(str(exc), "QMPTimeoutError") from exc
            except QMPError as exc:
                raise _OpError(str(exc), "QMPError") from exc
            finally:
                with self.cond:
                    watch.qmp_inflight = None
                    self.cond.notify_all()
        return {"return": result}

    def op_wait(
        self,
        session: _ClientSession,
        request_id: Any,
        vm_id: str,
        *,
        timeout: float | None,
        pattern: str | None,
        start_offset: int | None,
        ignore_crash: bool,
    ) -> dict[str, Any]:
        with self.cond:
            watch = self.watches.get(vm_id)
        if watch is None:
            raise _OpError(f"VM '{vm_id}' is not watched", "NotWatched")
        start = time.monotonic()
        deadline = start + timeout if timeout is not None else None
        sent_seq = watch.event_seq

        def pending_event() -> dict[str, Any] | None:
            """Under `self.cond`: the newest QMP event not yet streamed, if any."""
            nonlocal sent_seq
            if watch.event_seq == sent_seq:
                return None
            sent_seq = watch.event_seq
            return {
                "kind": "qmp_event",
                "name": watch.last_event,
                "data": watch.event_data,
                "boot_offset": watch.boot_offset,
            }

        def stream(event: dict[str, Any] | None) -> None:
            if event is not None:
                session.send_event(request_id, event)

        # A `progress` event at most once per second while the wait is idle,
        # so an in-process caller (the MCP façade) can relay liveness to its
        # client; the CLI ignores it. `scanned` is the serial-log byte the
        # scan has reached.
        last_progress = start

        def progress(scanned: int) -> None:
            nonlocal last_progress
            now = time.monotonic()
            if now - last_progress < 1.0:
                return
            last_progress = now
            stream({"kind": "progress", "elapsed": round(now - start, 3), "scanned": scanned})

        if pattern is None:
            return self._wait_bare(session, watch, start, deadline, pending_event, stream, progress)
        return self._wait_pattern(
            session, watch, start, deadline, pending_event, stream, progress,
            pattern=pattern, start_offset=start_offset, ignore_crash=ignore_crash,
        )

    def _wait_bare(
        self, session, watch: VMWatch, start, deadline, pending_event, stream, progress
    ) -> dict[str, Any]:
        reason = "timeout"
        stopped = False
        while True:
            with self.cond:
                event = pending_event()
                if watch.exited:
                    stopped = True
                    reason = "process_exited"
                    break
                if watch.panicked:
                    reason = "terminal_panic"
                    break
                if watch.released:
                    reason = "released"
                    break
                if watch.qmp_lost:
                    raise _OpError(
                        f"QMP error during wait: connection to '{watch.vm_id}' closed "
                        "while its process lives on", "QMPError",
                    )
                if session.closed.is_set():
                    raise _ClientGone()
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    reason = "timeout"
                    break
                if event is None:
                    self.cond.wait(1.0 if remaining is None else min(1.0, remaining))
            # Sent outside the lock: a slow client must not stall the tick.
            stream(event)
            progress(watch.scanned)
        stream(event)
        if reason == "released":
            # The terminal transition an explicit `unwatch` owes every
            # subscriber: the client finishes standalone (#118).
            stream({"kind": "released"})
        with self.cond:
            snapshot = watch.state()
        return {
            "stopped": stopped,
            "reason": reason,
            "elapsed": round(time.monotonic() - start, 3),
            "running": snapshot["running"],
            "qemu_status": snapshot["qemu_status"],
            "qmp_busy": snapshot["qmp_busy"],
            "last_event": watch.last_event,
            "event_data": watch.event_data,
            "boot_offset": watch.boot_offset,
            "panicked": watch.panicked,
            "exited": watch.exited,
        }

    def _wait_pattern(
        self, session, watch: VMWatch, start, deadline, pending_event, stream, progress, *,
        pattern: str, start_offset: int | None, ignore_crash: bool,
    ) -> dict[str, Any]:
        try:
            matcher = re.compile(pattern)
        except re.error as exc:
            raise _OpError(f"Invalid --pattern regex {pattern!r}: {exc}", "InvalidPattern") from exc
        scan_from = watch.boot_offset if start_offset is None else start_offset
        tail = SerialTail(watch.inst.serial_log, offset=scan_from)
        reason = "timeout"
        matched: str | None = None
        terminal_panic_seen = False
        while True:
            with self.cond:
                event = pending_event()
                final = watch.exited
                seen_size = watch.log_size
                if session.closed.is_set():
                    raise _ClientGone()
            stream(event)
            progress(tail.offset)
            try:
                scan = scan_for_pattern(tail, matcher, final=final, stop_at_panic=not ignore_crash)
            except OSError as exc:
                raise _OpError(
                    f"Cannot inspect serial log for '{watch.vm_id}': {exc}. "
                    "Pattern result is inconclusive.",
                    type(exc).__name__, inconclusive=True,
                ) from exc
            if scan.terminal_panic:
                terminal_panic_seen = True
            if scan.matched_line is not None:
                matched = scan.matched_line
                reason = "pattern_matched"
                break
            if terminal_panic_seen and not ignore_crash:
                reason = "crash"
                break
            if final:
                reason = "process_exited"
                break
            if watch.released:
                reason = "released"
                break
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                reason = "timeout"
                break
            wake = now + FRAGMENT_IDLE_SECONDS
            if deadline is not None:
                wake = min(wake, deadline)
            with self.cond:
                while (
                    watch.log_size == seen_size and not watch.exited
                    and not watch.released and not session.closed.is_set()
                ):
                    remaining = wake - time.monotonic()
                    if remaining <= 0:
                        break
                    self.cond.wait(remaining)
        if reason == "released":
            stream({"kind": "released"})
        return {
            "matched_line": matched,
            "reason": reason,
            "terminal_panic_seen": terminal_panic_seen,
            "elapsed": round(time.monotonic() - start, 3),
            "scan_offset": scan_from,
            "exited": watch.exited,
        }


class _OpError(Exception):
    def __init__(self, message: str, error_type: str, **fields: Any):
        super().__init__(message)
        self.error_type = error_type
        self.fields = fields


class _ClientGone(Exception):
    """The client hung up mid-wait; there is nobody to answer."""


class _ClientSession(threading.Thread):
    """One connection: a reader thread that dispatches each request to its own
    worker, so a long `wait` never blocks a `vm_state` on the same socket and a
    hang-up is noticed while a wait is in flight."""

    def __init__(self, daemon: Daemon, conn: socket.socket):
        super().__init__(daemon=True, name="client")
        self.daemon = daemon
        self.conn = conn
        self.closed = threading.Event()
        self._write_lock = threading.Lock()

    def run(self) -> None:
        buf = b""
        try:
            self.conn.settimeout(None)
            while True:
                nl = buf.find(b"\n")
                if nl >= 0:
                    line = buf[:nl]
                    buf = buf[nl + 1:]
                    if line.strip():
                        self._dispatch(line)
                    continue
                chunk = self.conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        finally:
            self.close()
            self.daemon._client_gone(self)

    def close(self) -> None:
        self.closed.set()
        try:
            self.conn.close()
        except OSError:
            pass

    def _send(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8") + b"\n"
        with self._write_lock:
            try:
                self.conn.sendall(data)
            except OSError:
                self.closed.set()

    def send_event(self, request_id: Any, event: dict[str, Any]) -> None:
        self._send({"id": request_id, "event": event})

    def _dispatch(self, line: bytes) -> None:
        try:
            request = json.loads(line)
        except ValueError:
            self._send({"id": None, "ok": False, "error": "malformed request", "error_type": "ValueError"})
            return
        if not isinstance(request, dict):
            self._send({"id": None, "ok": False, "error": "request must be an object", "error_type": "ValueError"})
            return
        threading.Thread(target=self._handle, args=(request,), daemon=True).start()

    def _handle(self, request: dict[str, Any]) -> None:
        request_id = request.get("id")
        op = request.get("op")
        # A `wait` is counted until its reply is on the wire: shutdown waits
        # for that count so the `released` verdict reaches the client before
        # its connection is cut.
        if op == "wait":
            with self.daemon.cond:
                self.daemon._waits_in_flight += 1
        try:
            self._reply(request_id, op, request)
        finally:
            if op == "wait":
                with self.daemon.cond:
                    self.daemon._waits_in_flight -= 1
                    self.daemon.cond.notify_all()

    def _reply(self, request_id: Any, op: Any, request: dict[str, Any]) -> None:
        try:
            result = self._run_op(request_id, op, request)
        except _ClientGone:
            return
        except _OpError as exc:
            self._send({
                "id": request_id, "ok": False, "error": str(exc),
                "error_type": exc.error_type, **exc.fields,
            })
            return
        except Exception as exc:  # noqa: BLE001 — never kill the session on one bad op
            _log(f"op {op!r} failed: {exc!r}")
            self._send({
                "id": request_id, "ok": False, "error": str(exc),
                "error_type": type(exc).__name__,
            })
            return
        self._send({"id": request_id, "ok": True, "result": result})

    def _run_op(self, request_id: Any, op: Any, request: dict[str, Any]) -> dict[str, Any]:
        daemon = self.daemon
        if op == "ping":
            return daemon.op_ping()
        if op == "shutdown":
            daemon.stop.set()
            return {"stopping": True}
        vm_id = request.get("vm_id")
        if op in ("watch", "unwatch", "vm_state", "epoch", "qmp", "wait") and not isinstance(vm_id, str):
            raise _OpError(f"{op}: 'vm_id' is required", "ValueError")
        if op == "watch":
            return daemon.watch(vm_id)
        if op == "unwatch":
            return {"released": daemon.unwatch(vm_id)}
        if op == "vm_state":
            return daemon.vm_state(vm_id)
        if op == "epoch":
            offset = request.get("offset")
            if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
                raise _OpError("epoch: 'offset' must be a non-negative integer", "ValueError")
            return daemon.adopt_epoch(vm_id, offset)
        if op == "qmp":
            timeout = request.get("qmp_timeout", 30.0)
            return daemon.op_qmp(
                vm_id, request.get("execute"), request.get("arguments"),
                float(timeout) if isinstance(timeout, (int, float)) else 30.0,
            )
        if op == "wait":
            timeout = request.get("timeout")
            start_offset = request.get("start_offset")
            return daemon.op_wait(
                self, request_id, vm_id,
                timeout=float(timeout) if isinstance(timeout, (int, float)) else None,
                pattern=request.get("pattern") if isinstance(request.get("pattern"), str) else None,
                start_offset=int(start_offset) if isinstance(start_offset, int) else None,
                ignore_crash=bool(request.get("ignore_crash", False)),
            )
        raise _OpError(f"unknown op {op!r}", "UnknownOp")


def serve(cache_dir: Path | None = None, *, idle_exit: float = 600.0) -> int:
    """Run the daemon in the foreground until it stops; returns the exit code."""
    return Daemon(cache_dir or cache_home(), idle_exit=idle_exit).serve()
