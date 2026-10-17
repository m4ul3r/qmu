"""Client side of the per-cache-dir qmu daemon (#70): discovery, autostart,
the wire protocol, and the QMP-shaped proxy handlers use without knowing.

The daemon (`qmu.daemon`) owns ONE QMP connection per watched VM so that
events (RESET, STOP, SHUTDOWN, GUEST_PANICKED) are observed instead of
inferred, and so that concurrent commands never contend for QEMU's single
QMP client slot. Everything here is best-effort: when no daemon can be
reached, every caller falls back to today's standalone path silently.

Discovery
---------
`<cache>/daemon.json` records `{pid, pid_start, build_id, socket}`; the
socket normally lives at `<cache>/daemon.sock` but the record is the
authority (a cache path too long for `sockaddr_un` moves it under the
runtime dir). A record whose pid is gone or whose /proc start-time differs
(the same recycled-pid guard `instance_alive` applies) is stale and ignored.

Policy
------
`QMU_DAEMON=off|auto|require` (default `auto`). `off` disables the layer
entirely — no connect, no spawn — which is what a script that must not
leave processes behind, and the test suite, want. `auto` connects to a live
daemon or spawns one when `[daemon] autostart` allows, and falls back on
any failure. `require` turns an unavailable daemon into a `QMUError`.

Build id
--------
Editable installs change under a long-lived daemon. `build_id()` hashes the
package directory and the newest mtime of its sources; a client that sees
a different id asks the daemon to shut down and respawns it, so the daemon
never serves code older than the CLI talking to it.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Callable

from .config import resolve_config
from .instance import QMUError, is_pid_alive, proc_pid_start
from .paths import cache_home, runtime_root, _sun_path_budget
from .qmp import QMPCommandError, QMPError, QMPTimeoutError

DAEMON_SOCKET_NAME = "daemon.sock"
DAEMON_RECORD_NAME = "daemon.json"
DAEMON_LOG_NAME = "daemon.log"

# How long a client gives a freshly spawned daemon to bind its socket.
SPAWN_WAIT_SECONDS = 2.0
# Connect/ping budget against a socket that exists; a daemon that cannot
# answer a ping this fast is treated as absent, never waited on.
CONNECT_TIMEOUT = 1.0

MODE_OFF = "off"
MODE_AUTO = "auto"
MODE_REQUIRE = "require"

# Progress sink for in-process callers (#70, the MCP façade): the
# daemon-backed `wait` path calls `report_progress(elapsed, scanned_bytes,
# note)` on each daemon `progress`/QMP event. Default: no sink, no-op — the
# CLI never sets one.
progress_sink: ContextVar[Callable[[float, int, str], None] | None] = ContextVar(
    "qmu_progress_sink", default=None
)


def report_progress(elapsed: float, scanned: int, note: str) -> None:
    sink = progress_sink.get()
    if sink is not None:
        sink(elapsed, scanned, note)


class DaemonError(Exception):
    """The daemon answered a request with `ok: false`."""

    def __init__(self, message: str, error_type: str = "DaemonError", **fields: Any):
        super().__init__(message)
        self.error_type = error_type
        self.fields = fields


class DaemonUnavailable(Exception):
    """No daemon could be reached (and none was spawned)."""


def daemon_mode() -> str:
    """`off`, `auto` or `require` from `QMU_DAEMON`; unknown values are `auto`."""
    value = os.environ.get("QMU_DAEMON", MODE_AUTO).strip().lower()
    if value in ("0", "no", "false", "none", MODE_OFF):
        return MODE_OFF
    if value == MODE_REQUIRE:
        return MODE_REQUIRE
    return MODE_AUTO


def enabled() -> bool:
    return daemon_mode() != MODE_OFF


def _package_dir() -> Path:
    import qmu  # local: avoid a cycle at import time

    return Path(qmu.__file__).resolve().parent


def build_id() -> str:
    """Identity of the code a daemon serves: package path + newest source mtime."""
    root = _package_dir()
    newest = 0
    for path in root.rglob("*.py"):
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            continue
        if mtime > newest:
            newest = mtime
    digest = hashlib.sha256(f"{root}\n{newest}".encode()).hexdigest()
    return digest[:16]


# --- paths and the record ---------------------------------------------------


def record_path(cache_dir: Path | None = None) -> Path:
    return (cache_dir or cache_home()) / DAEMON_RECORD_NAME


def log_path(cache_dir: Path | None = None) -> Path:
    return (cache_dir or cache_home()) / DAEMON_LOG_NAME


def default_socket_path(cache_dir: Path | None = None) -> Path:
    """`<cache>/daemon.sock`, or a runtime-dir path when that cannot be bound.

    `sun_path` is ~107 bytes on Linux; a deep `QMU_CACHE_DIR` can exceed it,
    and bind() would fail with ENAMETOOLONG. The record carries whichever
    path was used, so clients never guess.
    """
    cache = cache_dir or cache_home()
    candidate = cache / DAEMON_SOCKET_NAME
    if len(os.fsencode(str(candidate))) < _sun_path_budget():
        return candidate
    tag = hashlib.sha256(str(cache).encode()).hexdigest()[:12]
    short = runtime_root() / f"daemon-{tag}.sock"
    if len(os.fsencode(str(short))) < _sun_path_budget():
        return short
    return Path(f"/tmp/qmu-daemon-{tag}.sock")


def read_record(cache_dir: Path | None = None) -> dict[str, Any] | None:
    try:
        data = json.loads(record_path(cache_dir).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def process_gone(pid: int) -> bool:
    """Whether `pid` has exited — including a zombie this process has not
    reaped. A daemon spawned by THIS process stays a zombie after it exits
    (nobody waits on it), and `kill(pid, 0)` keeps succeeding on a zombie,
    so a plain liveness probe would call a finished daemon alive forever."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    if not is_pid_alive(pid):
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        # /proc entry vanished between the probes: it exited. Without /proc
        # at all (non-Linux) the kill(0) probe above is the only answer.
        return os.path.isdir("/proc")
    rest = stat.rsplit(")", 1)[1].split()
    return bool(rest) and rest[0] == "Z"


def record_alive(record: dict[str, Any] | None) -> bool:
    """Whether the record names a live daemon process (pid + start-time)."""
    if not record:
        return False
    pid = record.get("pid")
    if not isinstance(pid, int) or process_gone(pid):
        return False
    recorded = record.get("pid_start")
    if recorded is None:
        return True
    current = proc_pid_start(pid)
    if current is None:
        return not os.path.isdir("/proc")
    return current == recorded


def socket_path_for(cache_dir: Path | None = None) -> Path:
    """The socket a live record names, else the default location."""
    record = read_record(cache_dir)
    if record and isinstance(record.get("socket"), str):
        return Path(record["socket"])
    return default_socket_path(cache_dir)


def _remove_stale(cache_dir: Path | None) -> None:
    """Drop the socket + record of a daemon that is positively gone."""
    record = read_record(cache_dir)
    if record_alive(record):
        return
    for path in (socket_path_for(cache_dir), record_path(cache_dir)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


# --- the wire ---------------------------------------------------------------


class DaemonConnection:
    """One newline-delimited-JSON session with the daemon.

    `request()` sends `{"id": n, "op": ..., ...}` and blocks until the reply
    tagged `n` arrives; `{"id": n, "event": {...}}` lines that precede it are
    handed to `on_event`. `reads` counts socket reads so a test can prove the
    client blocked instead of polling.
    """

    def __init__(self, sock: socket.socket, path: Path):
        self._sock = sock
        self.path = path
        self._buf = b""
        self._seq = 0
        self.reads = 0
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> DaemonConnection:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _readline(self, timeout: float | None) -> dict[str, Any]:
        self._sock.settimeout(timeout)
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line = self._buf[:nl]
                self._buf = self._buf[nl + 1:]
                if line.strip():
                    return json.loads(line)
                continue
            chunk = self._sock.recv(65536)
            self.reads += 1
            if not chunk:
                raise DaemonUnavailable("daemon closed the connection")
            self._buf += chunk

    def request(
        self,
        op: str,
        *,
        budget: float | None = CONNECT_TIMEOUT,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        **params: Any,
    ) -> dict[str, Any]:
        """Send `op` with `params`; block up to `budget` seconds (None =
        forever) for its reply. `budget` is the SOCKET read budget — a
        request parameter named `timeout` (the `wait` op's deadline) travels
        in `params` untouched."""
        self._seq += 1
        msg_id = self._seq
        payload = {"id": msg_id, "op": op, **params}
        try:
            self._sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            while True:
                msg = self._readline(budget)
                if msg.get("id") != msg_id:
                    continue
                if "event" in msg:
                    if on_event is not None:
                        on_event(msg["event"])
                    continue
                if msg.get("ok"):
                    result = msg.get("result")
                    return result if isinstance(result, dict) else {}
                fields = {
                    k: v for k, v in msg.items()
                    if k not in ("id", "ok", "error", "error_type")
                }
                raise DaemonError(
                    str(msg.get("error", "daemon error")),
                    str(msg.get("error_type", "DaemonError")),
                    **fields,
                )
        except (OSError, ValueError) as exc:
            self.close()
            raise DaemonUnavailable(f"daemon connection failed: {exc}") from exc


def _connect_socket(path: Path, timeout: float = CONNECT_TIMEOUT) -> DaemonConnection | None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
    except OSError:
        sock.close()
        return None
    return DaemonConnection(sock, path)


# --- spawn + policy -------------------------------------------------------------


def autostart_allowed() -> bool:
    """`[daemon] autostart` from the resolved config; True when unresolvable.

    A broken project config has already been refused by the dispatch gate for
    every gated command; the few that reach here ungated must not turn a
    config problem into a second, unrelated failure.
    """
    try:
        return bool(resolve_config().daemon_autostart)
    except Exception:  # noqa: BLE001 — policy lookup must never raise
        return True


def spawn_daemon(cache_dir: Path | None = None) -> int:
    """Start `python -m qmu daemon run` detached; returns its pid.

    stdio goes to `<cache>/daemon.log` so a crash is diagnosable; the child is
    its own session so the CLI that spawned it can exit at once.
    """
    cache = cache_dir or cache_home()
    cache.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["QMU_CACHE_DIR"] = str(cache)
    # The child must never recurse into spawning, and must not be disabled by
    # the policy that decided to spawn it.
    env["QMU_DAEMON"] = MODE_OFF
    log = log_path(cache).open("ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "qmu", "daemon", "run"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            env=env,
        )
    finally:
        log.close()
    return proc.pid


def _wait_for_socket(cache_dir: Path | None, deadline: float) -> DaemonConnection | None:
    while True:
        path = socket_path_for(cache_dir)
        if path.exists():
            conn = _connect_socket(path)
            if conn is not None:
                return conn
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.02)


def _ping(conn: DaemonConnection) -> dict[str, Any] | None:
    try:
        return conn.request("ping")
    except (DaemonError, DaemonUnavailable):
        conn.close()
        return None


def _shutdown_and_wait(conn: DaemonConnection, cache_dir: Path | None, pid: int | None) -> None:
    try:
        conn.request("shutdown")
    except (DaemonError, DaemonUnavailable):
        pass
    conn.close()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if (pid is None or process_gone(pid)) and not socket_path_for(cache_dir).exists():
            return
        time.sleep(0.02)


# Per-process memory of failures that would otherwise repeat their cost on
# every `_qmp_ctx`/`_observe_guest` in one command: a spawn that did not come
# up (2 s each) and a VM the daemon could not adopt (a busy greeting budget
# each). `reset()` clears both; the test suite's own daemon tests call it.
_spawn_failed = False
_unwatchable: set[str] = set()


def reset() -> None:
    global _spawn_failed
    _spawn_failed = False
    _unwatchable.clear()


def connect(
    cache_dir: Path | None = None,
    *,
    autostart: bool | None = None,
    spawn_wait: float = SPAWN_WAIT_SECONDS,
) -> DaemonConnection | None:
    """A pinged, build-matched connection to the cache dir's daemon, or None.

    `autostart=None` consults `[daemon] autostart`; `False` never spawns
    (`doctor`, `daemon status`, `daemon stop`). Under `QMU_DAEMON=require` an
    unreachable daemon raises `QMUError` instead of returning None.
    """
    global _spawn_failed
    mode = daemon_mode()
    if mode == MODE_OFF:
        return None
    cache = cache_dir or cache_home()

    conn = _connect_socket(socket_path_for(cache))
    if conn is not None:
        info = _ping(conn)
        if info is not None:
            if info.get("build_id") == build_id():
                return conn
            # The daemon runs older code than this CLI: retire it and respawn.
            pid = info.get("pid") if isinstance(info.get("pid"), int) else None
            _shutdown_and_wait(conn, cache, pid)
        conn = None

    _remove_stale(cache)
    if autostart is None:
        autostart = autostart_allowed()
    if autostart and not _spawn_failed:
        try:
            spawn_daemon(cache)
        except OSError as exc:
            _spawn_failed = True
            if mode == MODE_REQUIRE:
                raise QMUError(f"QMU_DAEMON=require but the daemon could not be spawned: {exc}") from exc
            return None
        conn = _wait_for_socket(cache, time.monotonic() + spawn_wait)
        if conn is not None:
            info = _ping(conn)
            if info is not None:
                return conn
        _spawn_failed = True
    if mode == MODE_REQUIRE:
        raise QMUError(
            "QMU_DAEMON=require but no daemon is reachable. Start one with: "
            "qmu daemon start (log: " + str(log_path(cache)) + ")"
        )
    return None


# --- convenience ops ----------------------------------------------------------


def watch(vm_id: str, *, autostart: bool | None = None) -> dict[str, Any] | None:
    """Ask the daemon to supervise `vm_id`; returns its state or None."""
    conn = connect(autostart=autostart)
    if conn is None:
        return None
    with conn:
        try:
            return conn.request("watch", vm_id=vm_id, budget=5.0)
        except (DaemonError, DaemonUnavailable):
            return None


def unwatch(vm_id: str) -> bool:
    """Release `vm_id`'s QMP connection ahead of a kill; False when no daemon."""
    conn = connect(autostart=False)
    if conn is None:
        return False
    with conn:
        try:
            conn.request("unwatch", vm_id=vm_id, budget=5.0)
        except (DaemonError, DaemonUnavailable):
            return False
    return True


def vm_state(vm_id: str, *, adopt: bool = True) -> dict[str, Any] | None:
    """The daemon's cached view of `vm_id`, adopting a live record on request.

    None when the layer is off/unavailable or the VM is not (and cannot be)
    watched — callers then take the standalone path. A VM the daemon refused
    to adopt (no record, not running, QMP slot held elsewhere) is remembered
    for the rest of this process so the refusal is paid for once.
    """
    if vm_id in _unwatchable:
        return None
    conn = connect()
    if conn is None:
        return None
    with conn:
        try:
            if adopt:
                return conn.request("watch", vm_id=vm_id, budget=5.0)
            state = conn.request("vm_state", vm_id=vm_id)
        except DaemonError:
            _unwatchable.add(vm_id)
            return None
        except DaemonUnavailable:
            return None
    return state if state.get("watched") else None


def summarize(info: dict[str, Any]) -> dict[str, Any]:
    """The `ping` fields `daemon status`/`doctor` report."""
    return {
        "pid": info.get("pid"),
        "uptime": info.get("uptime"),
        "build_id": info.get("build_id"),
        "socket": info.get("socket"),
        "cache_dir": info.get("cache_dir"),
        "idle_exit": info.get("idle_exit"),
        "clients": info.get("clients"),
        "vms": info.get("vms", []),
    }


def probe() -> dict[str, Any]:
    """What `daemon status` and `doctor` both report; never spawns.

    `running` is the one bool to branch on; `reason` names why not:
    `disabled (QMU_DAEMON=off)`, `not running`, `stale record` (a record
    names a dead pid) or `unresponsive`. `build_current` is False when the
    daemon serves older code than this CLI (the next command respawns it).
    """
    mode = daemon_mode()
    if mode == MODE_OFF:
        return {"running": False, "mode": mode, "reason": "disabled (QMU_DAEMON=off)"}
    record = read_record()
    conn = _connect_socket(socket_path_for(None))
    if conn is None:
        reason = "stale record" if record and not record_alive(record) else "not running"
        return {"running": False, "mode": mode, "reason": reason, "record": record}
    with conn:
        try:
            info = conn.request("ping")
        except (DaemonError, DaemonUnavailable) as exc:
            return {"running": False, "mode": mode, "reason": f"unresponsive ({exc})", "record": record}
    out = {"running": True, "mode": mode, "reason": None, **summarize(info)}
    out["build_current"] = info.get("build_id") == build_id()
    return out


class DaemonQMP:
    """The `QMPClient` surface handlers use, routed through the daemon.

    Constructed by `_cliutil._qmp_ctx`. `connect()` decides the backend: the
    daemon when it is reachable and already watches the VM, else a direct
    `QMPClient` on the VM's socket (the exact object `_qmp_ctx` returned
    before the daemon existed — `greeting_timeout` set before connecting is
    honoured on that path). Attribute access that is not `execute`/
    `execute_hmp`/`connect`/`close` falls through to the direct client so
    callers inspecting `stale_replies` or `socket_path` keep working.
    """

    def __init__(self, inst: Any, direct_factory: Callable[[str], Any]):
        self._inst = inst
        self._direct = direct_factory(inst.qmp_socket)
        self._conn: DaemonConnection | None = None
        self.via_daemon = False

    # The direct client's tunables, forwarded both ways.
    @property
    def greeting_timeout(self) -> float:
        return self._direct.greeting_timeout

    @greeting_timeout.setter
    def greeting_timeout(self, value: float) -> None:
        self._direct.greeting_timeout = value

    @property
    def capabilities_timeout(self) -> float:
        return self._direct.capabilities_timeout

    @capabilities_timeout.setter
    def capabilities_timeout(self, value: float) -> None:
        self._direct.capabilities_timeout = value

    def __getattr__(self, name: str) -> Any:
        return getattr(self._direct, name)

    def connect(self) -> dict:
        conn = connect()
        if conn is not None:
            try:
                state = conn.request("vm_state", vm_id=self._inst.vm_id)
            except (DaemonError, DaemonUnavailable):
                state = {}
            if state.get("watched") and not state.get("exited"):
                self._conn = conn
                self.via_daemon = True
                return {"QMP": {"daemon": True}}
            conn.close()
        return self._direct.connect()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        self._direct.close()

    def execute(self, command: str, arguments: dict | None = None, timeout: float = 30.0) -> Any:
        if self._conn is None:
            return self._direct.execute(command, arguments, timeout=timeout)
        try:
            # The daemon enforces `qmp_timeout` on the QEMU side; the socket
            # budget only guards against a daemon that died mid-command.
            result = self._conn.request(
                "qmp",
                budget=timeout + 5.0,
                vm_id=self._inst.vm_id,
                execute=command,
                arguments=arguments,
                qmp_timeout=timeout,
            )
        except DaemonError as exc:
            raise _qmp_error_from(exc, command, arguments, timeout) from None
        except DaemonUnavailable as exc:
            raise QMPError(f"daemon connection lost during {command}: {exc}") from exc
        return result.get("return")

    def execute_hmp(self, command_line: str, timeout: float = 30.0) -> str:
        result = self.execute(
            "human-monitor-command", {"command-line": command_line}, timeout=timeout
        )
        return result if isinstance(result, str) else str(result)

    def __enter__(self) -> DaemonQMP:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _qmp_error_from(exc: DaemonError, command: str, arguments: dict | None, timeout: float) -> QMPError:
    """Re-raise a daemon-reported QMP failure as the class handlers catch."""
    if exc.error_type == "QMPCommandError":
        return QMPCommandError(str(exc), str(exc.fields.get("qmp_class", "")))
    if exc.error_type == "QMPTimeoutError":
        label = command
        if command == "human-monitor-command" and arguments:
            label = f"human-monitor-command '{arguments.get('command-line', '')}'"
        return QMPTimeoutError(label, timeout)
    return QMPError(str(exc))
