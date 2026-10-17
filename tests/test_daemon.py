"""The qmu daemon (#70): supervision, proxying, waiting, lifecycle.

These are the ONLY tests that run with the daemon layer on. The autouse
`isolate_qmu_env` fixture sets `QMU_DAEMON=off` for the rest of the suite;
here `daemon_env` flips it to `require` and runs a `Daemon` in-process on the
test's isolated cache dir, against a fake QMP server standing in for QEMU.
Nothing here spawns a detached process except the two tests that exercise
autostart, which stop what they start.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from qmu import cli, daemon_client
from qmu.commands import lifecycle
from qmu.daemon import Daemon
from qmu.instance import VMInstance, load_instance, save_instance
from qmu.paths import cache_home, instances_dir


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class FakeQMPServer:
    """A QEMU-shaped QMP endpoint: greeting, `qmp_capabilities`, canned
    replies keyed by command, and events the test injects at will. Serves
    one client at a time, exactly like QEMU."""

    def __init__(self, path: Path):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(1)
        self.replies: dict[str, object] = {
            "query-status": {"status": "running", "running": True, "singlestep": False},
        }
        self.requests: list[dict] = []
        self.conn: socket.socket | None = None
        self.connected = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conn = conn
            self.connected.set()
            try:
                self._session(conn)
            except OSError:
                pass
            finally:
                self.connected.clear()
                try:
                    conn.close()
                except OSError:
                    pass

    def _session(self, conn: socket.socket) -> None:
        self._send(conn, {"QMP": {"version": {"qemu": {"major": 9}}, "capabilities": []}})
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                req = json.loads(line)
                self.requests.append(req)
                cmd = req.get("execute")
                if cmd == "quit":
                    self._send(conn, {"return": {}, "id": req.get("id")})
                    return
                reply = self.replies.get(cmd, {})
                if isinstance(reply, Exception):
                    self._send(conn, {"error": {"class": "GenericError", "desc": str(reply)}, "id": req.get("id")})
                else:
                    self._send(conn, {"return": reply, "id": req.get("id")})

    def _send(self, conn: socket.socket, msg: dict) -> None:
        with self._lock:
            conn.sendall(json.dumps(msg).encode() + b"\n")

    def emit(self, event: str, data: dict | None = None) -> None:
        assert self.conn is not None, "no client connected"
        self._send(self.conn, {
            "event": event,
            "timestamp": {"seconds": int(time.time()), "microseconds": 0},
            "data": data or {},
        })

    def drop_client(self) -> None:
        if self.conn is not None:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self) -> None:
        self.drop_client()
        try:
            self.sock.close()
        except OSError:
            pass


def _write_instance(vm_id: str, qmp_socket: Path, serial_log: Path, **extra) -> VMInstance:
    inst = VMInstance(
        vm_id=vm_id,
        pid=os.getpid(),
        qmp_socket=str(qmp_socket),
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=str(serial_log),
        kernel="/k",
        rootfs=None,
        memory="1G",
        cpus=1,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="now",
        harness=True,
        pid_start=None,
        **extra,
    )
    save_instance(inst)
    return inst


BANNER = "[    0.000000] Linux version 6.8.0 (gcc) #1 SMP\n"


@pytest.fixture
def daemon_env(monkeypatch):
    """An in-process Daemon on the isolated cache dir, with the layer on."""
    monkeypatch.setenv("QMU_DAEMON", "require")
    daemon_client.reset()
    cache = cache_home()
    cache.mkdir(parents=True, exist_ok=True)
    instances_dir().mkdir(parents=True, exist_ok=True)
    daemon = Daemon(cache, idle_exit=0)
    thread = threading.Thread(target=daemon.serve, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not daemon.socket_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert daemon.socket_path.exists()
    yield daemon
    daemon.stop.set()
    thread.join(timeout=5)


@pytest.fixture
def vm(tmp_path):
    """A fake running VM: record + fake QMP server + serial log with one boot."""
    log = tmp_path / "vm.serial.log"
    log.write_text(BANNER + "booting\n")
    server = FakeQMPServer(tmp_path / "vm.qmp.sock")
    inst = _write_instance("fake-vm", server.path, log)
    yield {"inst": inst, "server": server, "log": log}
    server.close()


def _wait_until(predicate, timeout=5.0, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail(f"timed out waiting for {what}")


# ---------------------------------------------------------------------------
# supervision
# ---------------------------------------------------------------------------


def test_watch_connects_once_and_reports_cached_state(daemon_env, vm):
    conn = daemon_client.connect()
    assert conn is not None
    with conn:
        state = conn.request("watch", vm_id="fake-vm", budget=5.0)
        assert state["watched"] is True
        assert state["running"] is True
        assert state["qemu_status"] == "running"
        assert state["boot_offset"] == 0
        assert state["epoch_source"] == "banner"
        again = conn.request("vm_state", vm_id="fake-vm")
    assert again["watched"] is True
    # One QMP connection, negotiated once: capabilities + the initial status.
    commands = [r.get("execute") for r in vm["server"].requests]
    assert commands == ["qmp_capabilities", "query-status"]


def test_reset_advances_the_record_epoch_and_flips_source_to_observed(daemon_env, vm):
    log: Path = vm["log"]
    daemon_client.watch("fake-vm")
    with log.open("a") as f:
        f.write("[   12.000000] Kernel panic - not syncing: boom\n")
    before = log.stat().st_size
    vm["server"].emit("RESET", {"guest": True, "reason": "guest-reset"})
    _wait_until(
        lambda: load_instance("fake-vm").guest_epoch_serial_offset == before,
        what="record epoch to advance",
    )
    record = load_instance("fake-vm")
    assert record.guest_epoch_serial_offset == before
    assert record.guest_epoch_source == "observed"
    # The new boot's banner lands exactly at the epoch: still the observed
    # boot, and the scope starts there.
    with log.open("a") as f:
        f.write(BANNER + "second boot\n")
    _wait_until(
        lambda: daemon_client.vm_state("fake-vm")["log_size"] > before,
        what="banner to be scanned",
    )
    state = daemon_client.vm_state("fake-vm")
    assert state["boot_offset"] == before
    state = daemon_client.vm_state("fake-vm")
    assert state["epoch_source"] == "observed"
    assert state["panicked"] is False
    # `status` reports the same, with the pre-reboot panic out of scope.
    obs = lifecycle._observe_guest(vm["inst"])
    assert obs.epoch_source == "observed"
    assert obs.guest != lifecycle.GUEST_PANICKED
    assert obs.qmp_state == lifecycle.QMP_DAEMON


def test_record_write_on_reset_does_not_clobber_other_fields(daemon_env, vm):
    daemon_client.watch("fake-vm")
    # Another command records a bridge pid after the watch began.
    inst = load_instance("fake-vm")
    inst.gdb_bridge_pid = 424242
    save_instance(inst)
    vm["server"].emit("RESET", {"guest": True})
    _wait_until(lambda: load_instance("fake-vm").guest_epoch_source == "observed", what="epoch")
    assert load_instance("fake-vm").gdb_bridge_pid == 424242


def test_stop_and_resume_events_update_running(daemon_env, vm):
    daemon_client.watch("fake-vm")
    vm["server"].replies["query-status"] = {"status": "debug", "running": False}
    vm["server"].emit("STOP")
    _wait_until(lambda: daemon_client.vm_state("fake-vm")["qemu_status"] == "debug", what="refresh")
    assert daemon_client.vm_state("fake-vm")["running"] is False
    vm["server"].replies["query-status"] = {"status": "running", "running": True}
    vm["server"].emit("RESUME")
    _wait_until(lambda: daemon_client.vm_state("fake-vm")["running"] is True, what="resume")


def test_qmp_eof_marks_exited_once_the_process_is_gone(daemon_env, vm, monkeypatch):
    import qmu.daemon as daemon_mod

    daemon_client.watch("fake-vm")
    alive = {"v": True}
    monkeypatch.setattr(daemon_mod, "instance_alive", lambda inst: alive["v"])
    reaped: list[str] = []
    monkeypatch.setattr(daemon_mod.debug_mod, "reap_bridge_on_exit", lambda vm_id: reaped.append(vm_id))
    alive["v"] = False
    vm["server"].drop_client()
    _wait_until(lambda: daemon_env.vm_state("fake-vm").get("exited") is True, what="exit")
    state = daemon_env.vm_state("fake-vm")
    assert state["exit_reason"] == "process_exited"
    _wait_until(lambda: reaped == ["fake-vm"], what="bridge reap")
    # The CLI treats an exited watch as "take the standalone path".
    assert lifecycle._daemon_state(vm["inst"]) is None


# ---------------------------------------------------------------------------
# proxying
# ---------------------------------------------------------------------------


def test_eight_concurrent_qmp_ops_never_see_busy_and_all_correlate(daemon_env, vm):
    daemon_client.watch("fake-vm")
    vm["server"].replies["query-name"] = {"name": "fake"}
    results: list[object] = []
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            qmp = lifecycle._qmp_ctx(vm["inst"])
            with qmp:
                assert qmp.via_daemon
                for _ in range(5):
                    out = qmp.execute("query-name")
                    results.append(out)
                    status = qmp.execute("query-status")
                    results.append(status)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert not errors, errors
    assert len(results) == 80
    assert all(r in ({"name": "fake"}, vm["server"].replies["query-status"]) for r in results)
    names = [r for r in results if r == {"name": "fake"}]
    assert len(names) == 40
    # Every request carried a distinct id on the one QMP connection.
    ids = [r["id"] for r in vm["server"].requests if "id" in r]
    assert len(ids) == len(set(ids))


def test_qmp_error_replies_surface_as_the_classes_handlers_catch(daemon_env, vm):
    from qmu.qmp import QMPCommandError

    daemon_client.watch("fake-vm")
    vm["server"].replies["bogus"] = RuntimeError("The command bogus has not been found")
    with lifecycle._qmp_ctx(vm["inst"]) as qmp:
        with pytest.raises(QMPCommandError, match="has not been found") as excinfo:
            qmp.execute("bogus")
    assert excinfo.value.qmp_class == "GenericError"


def test_status_through_the_daemon_reports_observed_scope(daemon_env, vm, monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [vm["inst"]])
    rc = cli.main(["--format", "json", "status", "--vm", "fake-vm"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["qmp"] == "daemon"
    assert payload["guest_epoch_source"] == "banner"
    assert payload["guest_epoch_serial_offset"] == 0
    assert payload["qemu_status"] == "running"


def test_status_with_the_layer_off_has_no_daemon_keys(daemon_env, vm, monkeypatch, capsys):
    monkeypatch.setenv("QMU_DAEMON", "off")
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    rc = cli.main(["--format", "json", "status", "--vm", "fake-vm"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["qmp"] == "connected"
    assert "guest_epoch_source" not in payload
    assert "boot_offset" not in payload


def test_kill_releases_the_watch_before_signalling(daemon_env, vm, monkeypatch, capsys):
    daemon_client.watch("fake-vm")
    order: list[str] = []
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    real_release = lifecycle._release_from_daemon

    def release(inst):
        order.append("release")
        return real_release(inst)

    monkeypatch.setattr(lifecycle, "_release_from_daemon", release)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda inst, force=False, clean=True: order.append("kill"))
    rc = cli.main(["--format", "json", "kill", "--vm", "fake-vm"])
    assert rc == 0
    assert order == ["release", "kill"]
    assert daemon_env.vm_state("fake-vm") == {"watched": False, "vm_id": "fake-vm"}


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


def test_pattern_wait_returns_on_append_without_client_polling(daemon_env, vm):
    daemon_client.watch("fake-vm")
    conn = daemon_client.connect()
    assert conn is not None
    got: dict = {}

    def waiter() -> None:
        with conn:
            got.update(conn.request(
                "wait", budget=15.0, vm_id="fake-vm", pattern="MARKER", timeout=10.0,
                start_offset=0,
            ))

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.3)
    started = time.monotonic()
    with vm["log"].open("a") as f:
        f.write("=== MARKER ===\n")
    t.join(timeout=5)
    latency = time.monotonic() - started
    assert got["reason"] == "pattern_matched"
    assert got["matched_line"] == "=== MARKER ==="
    assert latency < 1.0
    # The client blocked on the socket: one read for the ping reply and one
    # (maybe two) for the wait reply, not a read per poll interval.
    assert conn.reads <= 4


def test_wait_deadline_is_enforced_by_the_daemon(daemon_env, vm):
    """The `timeout` request field is the wait's deadline — distinct from the
    client's socket budget. A deadline that never reached the daemon made a
    `wait --timeout 12` hang until the socket budget tripped (exit 4)."""
    daemon_client.watch("fake-vm")
    conn = daemon_client.connect()
    assert conn is not None
    started = time.monotonic()
    with conn:
        reply = conn.request(
            "wait", budget=10.0, vm_id="fake-vm", pattern="NEVER", timeout=0.4, start_offset=0,
        )
    assert reply["reason"] == "timeout"
    assert 0.3 < time.monotonic() - started < 3.0


def test_cli_pattern_wait_goes_through_the_daemon(daemon_env, vm, monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    monkeypatch.setattr(lifecycle, "instance_alive", lambda inst: True)
    via_daemon: list[str] = []
    real = lifecycle._pattern_wait_via_daemon

    def spy(*a, **k):
        via_daemon.append("yes")
        return real(*a, **k)

    monkeypatch.setattr(lifecycle, "_pattern_wait_via_daemon", spy)
    threading.Timer(0.3, lambda: vm["log"].open("a").write("RESULT OK\n")).start()
    rc = cli.main(["--format", "json", "wait", "--pattern", "RESULT", "--timeout", "10"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert payload["matched_line"] == "RESULT OK"
    assert payload["scan_scope"] == "epoch"
    assert via_daemon == ["yes"]


def test_bare_wait_ends_on_observed_exit(daemon_env, vm, monkeypatch, capsys):
    import qmu.daemon as daemon_mod

    daemon_client.watch("fake-vm")
    alive = {"v": True}
    monkeypatch.setattr(daemon_mod, "instance_alive", lambda inst: alive["v"])
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    monkeypatch.setattr(lifecycle, "instance_alive", lambda inst: alive["v"])

    def die() -> None:
        vm["server"].emit("SHUTDOWN", {"guest": True, "reason": "guest-shutdown"})
        time.sleep(0.05)
        alive["v"] = False
        vm["server"].drop_client()

    threading.Timer(0.3, die).start()
    rc = cli.main(["--format", "json", "wait", "--timeout", "10", "--no-clean"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert payload["stopped"] is True
    assert payload["reason"] == "process_exited"
    assert payload["last_event"] == "SHUTDOWN"
    assert payload["qmp"] == "daemon"


def test_bare_wait_terminal_panic_exits_three(daemon_env, vm, monkeypatch, capsys):
    daemon_client.watch("fake-vm")
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm_id=None: vm["inst"])
    monkeypatch.setattr(lifecycle, "_CRASH_SETTLE_MAX", 0.2)
    threading.Timer(0.3, lambda: vm["log"].open("a").write(
        "[   10.0] BUG: KASAN: boom\n[   10.1] Kernel panic - not syncing: Fatal exception\n"
    )).start()
    rc = cli.main(["--format", "json", "wait", "--timeout", "10"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3, payload
    assert payload["reason"] == "terminal_panic"
    assert payload["guest"] == "panicked"
    assert "Kernel panic" in (payload["crash"] or "")


# ---------------------------------------------------------------------------
# lifecycle: idle exit, stale socket, build id
# ---------------------------------------------------------------------------


def test_idle_exit_stops_a_daemon_with_no_vm_and_no_client(monkeypatch):
    monkeypatch.setenv("QMU_DAEMON", "require")
    daemon_client.reset()
    cache = cache_home()
    cache.mkdir(parents=True, exist_ok=True)
    daemon = Daemon(cache, idle_exit=0.3)
    thread = threading.Thread(target=daemon.serve, daemon=True)
    thread.start()
    _wait_until(lambda: daemon.socket_path.exists(), what="socket")
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not daemon.socket_path.exists()
    assert not daemon_client.record_path(cache).exists()


def test_stale_socket_and_record_are_removed_and_respawned(monkeypatch):
    """A socket file left by a dead daemon must not block autostart."""
    monkeypatch.setenv("QMU_DAEMON", "require")
    daemon_client.reset()
    cache = cache_home()
    cache.mkdir(parents=True, exist_ok=True)
    stale_sock = daemon_client.default_socket_path(cache)
    stale_sock.write_text("")  # a plain file where a socket should be
    daemon_client.record_path(cache).write_text(json.dumps({
        "pid": 2**22 - 1, "pid_start": "1", "build_id": "old", "socket": str(stale_sock),
    }))
    spawned: list[str] = []

    def fake_spawn(cache_dir=None):
        spawned.append(str(cache_dir))
        d = Daemon(cache, idle_exit=0)
        threading.Thread(target=d.serve, daemon=True).start()
        monkeypatch.setattr(daemon_client, "_running", d, raising=False)
        return 1

    monkeypatch.setattr(daemon_client, "spawn_daemon", fake_spawn)
    conn = daemon_client.connect(cache)
    assert conn is not None
    with conn:
        info = conn.request("ping")
    assert spawned == [str(cache)]
    assert info["build_id"] == daemon_client.build_id()
    daemon_client._running.stop.set()  # type: ignore[attr-defined]


def test_build_id_mismatch_shuts_down_and_respawns(daemon_env, monkeypatch):
    """A daemon serving older code is retired by the first client that notices."""
    daemon_env.build_id = "stale-build"
    spawned: list[int] = []
    replacement: dict = {}

    def fake_spawn(cache_dir=None):
        spawned.append(1)
        d = Daemon(cache_home(), idle_exit=0)
        replacement["d"] = d
        threading.Thread(target=d.serve, daemon=True).start()
        return 1

    monkeypatch.setattr(daemon_client, "spawn_daemon", fake_spawn)
    conn = daemon_client.connect()
    assert conn is not None
    with conn:
        info = conn.request("ping")
    assert spawned == [1]
    assert info["build_id"] == daemon_client.build_id()
    assert daemon_env.stop.is_set()
    replacement["d"].stop.set()


def test_build_id_changes_when_a_source_file_is_touched(monkeypatch):
    before = daemon_client.build_id()
    pkg = Path(daemon_client.__file__).parent
    target = pkg / "__init__.py"
    st = target.stat()
    try:
        # `touch` sets "now", newer than every other source; mirror that.
        os.utime(target, ns=(st.st_atime_ns, time.time_ns() + 10**9 * 60))
        assert daemon_client.build_id() != before
    finally:
        os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert daemon_client.build_id() == before


def test_require_mode_errors_when_no_daemon_can_be_reached(monkeypatch):
    from qmu.instance import QMUError

    monkeypatch.setenv("QMU_DAEMON", "require")
    daemon_client.reset()
    monkeypatch.setattr(daemon_client, "spawn_daemon", lambda cache_dir=None: 1)
    with pytest.raises(QMUError, match="QMU_DAEMON=require"):
        daemon_client.connect(spawn_wait=0.1)


def test_off_mode_never_touches_the_socket_or_spawns(monkeypatch, capsys):
    """The autouse fixture's `QMU_DAEMON=off` keeps the suite daemon-free."""
    assert os.environ["QMU_DAEMON"] == "off"
    monkeypatch.setattr(daemon_client, "spawn_daemon", lambda cache_dir=None: pytest.fail("spawned"))
    rc = cli.main(["list"])
    assert rc == 0
    assert not (cache_home() / "daemon.sock").exists()
    assert not (cache_home() / "daemon.json").exists()
    assert daemon_client.connect() is None


def test_daemon_status_command_without_a_daemon(monkeypatch, capsys):
    monkeypatch.setenv("QMU_DAEMON", "auto")
    daemon_client.reset()
    rc = cli.main(["--format", "json", "daemon", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["running"] is False
    assert payload["reason"] == "not running"
    assert not daemon_client.socket_path_for(None).exists()


def test_daemon_status_command_with_a_daemon(daemon_env, vm, capsys):
    daemon_client.watch("fake-vm")
    rc = cli.main(["--format", "json", "daemon", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["running"] is True
    assert payload["pid"] == os.getpid()
    assert payload["build_current"] is True
    assert [v["vm_id"] for v in payload["vms"]] == ["fake-vm"]
    rc = cli.main(["daemon", "status"])
    text = capsys.readouterr().out
    assert rc == 0
    assert "Daemon: running" in text and "fake-vm" in text


def test_daemon_start_and_stop_spawn_and_reap_a_real_process(monkeypatch, capsys):
    """The one end-to-end spawn: a real `python -m qmu daemon run` on the
    isolated cache dir, stopped before the test ends."""
    monkeypatch.setenv("QMU_DAEMON", "auto")
    daemon_client.reset()
    rc = cli.main(["--format", "json", "daemon", "start"])
    started = json.loads(capsys.readouterr().out)
    assert rc == 0, started
    pid = started["pid"]
    try:
        assert started["started"] is True
        assert daemon_client.record_alive(daemon_client.read_record())
        rc = cli.main(["--format", "json", "daemon", "start"])
        again = json.loads(capsys.readouterr().out)
        assert again["already_running"] is True and again["pid"] == pid
    finally:
        rc = cli.main(["--format", "json", "daemon", "stop"])
        stopped = json.loads(capsys.readouterr().out)
    assert rc == 0, stopped
    assert stopped["stopped"] is True
    assert not daemon_client.socket_path_for(None).exists()
    log = daemon_client.log_path().read_text()
    assert "serving" in log and "stopped" in log
