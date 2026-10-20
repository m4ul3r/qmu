from __future__ import annotations

import fcntl
import os
import subprocess
from pathlib import Path

import pytest

import qmu.vm as vm_module
from qmu.config import QMUConfig
from qmu.instance import load_instance, list_stopped_instances
from qmu.paths import instances_dir, qmp_socket_path, qemu_log_path, serial_log_path
from qmu.vm import launch_vm


def _lock_held(path: Path) -> bool:
    """True when another open file description still holds `path` (flock)."""
    if not path.exists():
        return False
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


class FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        returncode: int | None = None,
        ignore_term: bool = False,
        ignore_kill: bool = False,
    ):
        self.pid = pid
        self.returncode = returncode
        self.ignore_term = ignore_term
        self.ignore_kill = ignore_kill
        self.calls: list[tuple[str, float | None]] = []
        self._wait_count = 0
        self.stdout = None
        self.stderr = None
        self.stdin = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append(("terminate", None))
        if not self.ignore_term and self.returncode is None:
            self.returncode = -15

    def kill(self):
        self.calls.append(("kill", None))
        if not self.ignore_kill:
            self.returncode = -9

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        self._wait_count += 1
        if self.ignore_term and self._wait_count == 1 and self.returncode is None:
            raise subprocess.TimeoutExpired("qemu", timeout)
        if self.ignore_kill and self.returncode is None:
            raise subprocess.TimeoutExpired("qemu", timeout)
        if self.returncode is None:
            self.returncode = -15
        return self.returncode


class FakeQMP:
    def __init__(self, socket_path, *, fail_on: str | None = None):
        self.socket_path = str(socket_path)
        self.fail_on = fail_on
        self.calls: list[str] = []
        self.closed = False

    def connect(self):
        self.calls.append("connect")
        if self.fail_on == "connect":
            raise OSError("connect refused")
        return {"QMP": {}}

    def execute(self, command, arguments=None, timeout=30.0):
        self.calls.append(f"execute:{command}")
        if self.fail_on == "query-status" and command == "query-status":
            raise OSError("query failed")
        return {"status": "running"}

    def close(self):
        self.calls.append("close")
        self.closed = True

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def test_terminate_and_reap_waits_for_already_exited_child():
    proc = FakeProcess(pid=11, returncode=1)
    vm_module._terminate_and_reap(proc)
    assert proc.calls == [("wait", 1.0)]


def test_terminate_and_reap_terminates_then_waits():
    proc = FakeProcess(pid=12)
    vm_module._terminate_and_reap(proc)
    assert proc.calls == [("terminate", None), ("wait", 1.0)]
    assert proc.returncode == -15


def test_terminate_and_reap_escalates_to_kill_then_waits():
    proc = FakeProcess(pid=13, ignore_term=True)
    vm_module._terminate_and_reap(proc)
    assert proc.calls == [
        ("terminate", None),
        ("wait", 1.0),
        ("kill", None),
        ("wait", 1.0),
    ]
    assert proc.returncode == -9


def test_terminate_and_reap_surfaces_timeout_after_kill():
    proc = FakeProcess(pid=14, ignore_term=True, ignore_kill=True)
    with pytest.raises(subprocess.TimeoutExpired):
        vm_module._terminate_and_reap(proc)
    assert proc.calls == [
        ("terminate", None),
        ("wait", 1.0),
        ("kill", None),
        ("wait", 1.0),
    ]


def _kernel(tmp_path: Path) -> Path:
    kernel = tmp_path / "bzImage"
    kernel.touch()
    return kernel


def _attempt_paths(vm_id: str) -> tuple[Path, Path, Path, Path]:
    return (
        instances_dir() / f"{vm_id}.json",
        qmp_socket_path(vm_id),
        serial_log_path(vm_id),
        qemu_log_path(vm_id),
    )


def test_launch_spawn_failure_closes_log_and_removes_partial_artifacts(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    captured: dict = {}

    def boom(*args, **kwargs):
        captured["stdout"] = kwargs.get("stdout")
        raise OSError("spawn failed")

    monkeypatch.setattr(vm_module.subprocess, "Popen", boom)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    with pytest.raises(OSError, match="spawn failed"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert captured["stdout"].closed
    json_path, qmp, serial, qemu = _attempt_paths("txn-vm")
    assert not json_path.exists()
    assert not qmp.exists()
    assert not serial.exists()
    assert not qemu.exists()


def test_launch_immediate_exit_reaps_and_removes_attempt_artifacts(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=101, returncode=1)

    def fake_popen(cmd, **kwargs):
        # Write diagnostic into the log path QEMU would have used.
        log_path = qemu_log_path("txn-vm")
        # Parent may still be writing via context manager; write after open.
        # The implementation opens then Popen; content is read after wait.
        return proc

    # After spawn, poll says exited. Write diagnostic on first poll via side effect.
    original_poll = proc.poll

    def poll_and_write():
        qemu_log_path("txn-vm").write_text("fatal diagnostic\n")
        return original_poll()

    proc.poll = poll_and_write  # type: ignore[method-assign]

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    with pytest.raises(vm_module.QMUError) as exc:
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert ("wait", 1.0) in proc.calls or any(c[0] == "wait" for c in proc.calls)
    assert ("terminate", None) not in proc.calls
    assert ("kill", None) not in proc.calls
    assert "code 1" in str(exc.value)
    assert "fatal diagnostic" in str(exc.value)
    json_path, qmp, serial, qemu = _attempt_paths("txn-vm")
    assert not json_path.exists()
    assert not qmp.exists()
    assert not serial.exists()
    assert not qemu.exists()


def test_launch_bind_race_retry_rolls_back_before_next_spawn(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    first = FakeProcess(pid=201, returncode=1)
    second = FakeProcess(pid=202)
    procs = [first, second]
    popen_order: list[int] = []
    ports = iter([22022, 22023])

    def fake_popen(cmd, **kwargs):
        proc = procs.pop(0)
        popen_order.append(proc.pid)
        if proc is first:
            qemu_log_path("vm-22022").write_text("Address already in use\n")
        else:
            # Second attempt: create QMP socket so validation can proceed.
            qmp_socket_path("txn-vm" if False else "vm-22023").parent.mkdir(
                parents=True, exist_ok=True
            )
            qmp_socket_path("vm-22023").write_text("sock")
        return proc

    def fake_find_free_port(start, max_tries=100):
        return next(ports)

    qmp_clients: list[FakeQMP] = []

    def fake_qmp(path):
        client = FakeQMP(path)
        qmp_clients.append(client)
        return client

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "find_free_port", fake_find_free_port)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: f"start-{pid}")
    monkeypatch.setattr(vm_module, "QMPClient", fake_qmp)
    # Keep QMP appearance path simple: second process stays alive and socket exists.
    second.returncode = None

    # Need rootfs/ssh for non-harness with ssh port auto. Use harness=False with
    # auto_ssh — plan uses harness=True with name. For bind race we need auto ports.
    # Use non-harness with fake rootfs/key so SSH port is allocated.
    rootfs = tmp_path / "rootfs.img"
    rootfs.touch()
    key = tmp_path / "id_rsa"
    key.touch()
    config = QMUConfig()
    config.rootfs = str(rootfs)
    config.ssh_key = str(key)

    inst = launch_vm(config=config, kernel=str(kernel), name=None)

    assert first.calls[0][0] == "wait" or ("wait", 1.0) in first.calls
    assert popen_order == [201, 202]
    assert any(c[0] == "wait" for c in first.calls)
    # First attempt artifacts gone
    assert not qemu_log_path("vm-22022").exists()
    assert not qmp_socket_path("vm-22022").exists()
    assert not serial_log_path("vm-22022").exists()
    assert not (instances_dir() / "vm-22022.json").exists()
    # Committed second
    assert inst.pid == 202
    assert inst.vm_id == "vm-22023"
    assert load_instance("vm-22023") is not None
    assert ("terminate", None) not in second.calls
    # The lock is released once QMP answered; a sibling can allocate now.
    assert not _lock_held(instances_dir() / "ports.lock")


def test_launch_bind_retry_exhaustion_reaps_every_child_and_removes_every_attempt(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    procs = [
        FakeProcess(pid=301, returncode=1),
        FakeProcess(pid=302, returncode=1),
        FakeProcess(pid=303, returncode=1),
    ]
    created: list[FakeProcess] = []
    ports = iter([23001, 23002, 23003])

    def fake_popen(cmd, **kwargs):
        proc = procs[len(created)]
        created.append(proc)
        vm_id = f"vm-{[23001, 23002, 23003][len(created) - 1]}"
        qemu_log_path(vm_id).write_text(
            f"Address already in use attempt {len(created)}\n"
        )
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        vm_module, "find_free_port", lambda start, max_tries=100: next(ports)
    )
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    rootfs = tmp_path / "rootfs.img"
    rootfs.touch()
    key = tmp_path / "id_rsa"
    key.touch()
    config = QMUConfig()
    config.rootfs = str(rootfs)
    config.ssh_key = str(key)

    with pytest.raises(vm_module.QMUError) as exc:
        launch_vm(config=config, kernel=str(kernel))

    assert len(created) == 3
    for proc in created:
        assert any(c[0] == "wait" for c in proc.calls)
    for port in (23001, 23002, 23003):
        vm_id = f"vm-{port}"
        assert not qemu_log_path(vm_id).exists()
        assert not qmp_socket_path(vm_id).exists()
        assert not serial_log_path(vm_id).exists()
        assert not (instances_dir() / f"{vm_id}.json").exists()
    assert "attempt 3" in str(exc.value)
    # Three losses under the allocation lock: concurrent qmu launches are
    # excluded, so the error names the lock and blames a foreign listener.
    assert f"while holding {instances_dir() / 'ports.lock'}" in str(exc.value)
    assert "foreign listener" in str(exc.value)
    assert not _lock_held(instances_dir() / "ports.lock")


def test_launch_qmp_appearance_timeout_terminates_waits_and_cleans(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=401)

    monkeypatch.setattr(
        vm_module.subprocess, "Popen", lambda *a, **k: proc
    )
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    # Force timeout immediately.
    monkeypatch.setattr(vm_module.time, "monotonic", lambda: 0.0)
    # deadline = 0 + 10 = 10; make loop always past deadline
    times = iter([0.0, 100.0])

    def mono():
        try:
            return next(times)
        except StopIteration:
            return 100.0

    monkeypatch.setattr(vm_module.time, "monotonic", mono)
    monkeypatch.setattr(vm_module.time, "sleep", lambda s: None)

    with pytest.raises(vm_module.QMUError, match="Timed out waiting for QMP"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert ("terminate", None) in proc.calls
    assert any(c[0] == "wait" for c in proc.calls)
    json_path, qmp, serial, qemu = _attempt_paths("txn-vm")
    assert not json_path.exists()
    assert not qmp.exists()
    assert not serial.exists()
    assert not qemu.exists()


def test_launch_qmp_appearance_timeout_escalates_to_kill_and_reaps(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=402, ignore_term=True)

    monkeypatch.setattr(vm_module.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    times = iter([0.0, 100.0])
    monkeypatch.setattr(
        vm_module.time,
        "monotonic",
        lambda: next(times, 100.0),
    )
    monkeypatch.setattr(vm_module.time, "sleep", lambda s: None)

    with pytest.raises(vm_module.QMUError, match="Timed out waiting for QMP"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert ("terminate", None) in proc.calls
    assert ("kill", None) in proc.calls
    assert proc.returncode == -9
    assert not qemu_log_path("txn-vm").exists()


def test_launch_qmp_connect_failure_closes_client_terminates_reaps_and_cleans(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=501)
    clients: list[FakeQMP] = []

    def fake_popen(*a, **k):
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        return proc

    def fake_qmp(path):
        client = FakeQMP(path, fail_on="connect")
        clients.append(client)
        return client

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", fake_qmp)

    with pytest.raises(vm_module.QMUError, match="QMP connection failed"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert clients and clients[0].closed
    assert "close" in clients[0].calls
    assert ("terminate", None) in proc.calls
    assert any(c[0] == "wait" for c in proc.calls)
    assert not qemu_log_path("txn-vm").exists()
    assert not qmp_socket_path("txn-vm").exists()


def test_launch_qmp_query_status_failure_closes_client_terminates_reaps_and_cleans(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=502)
    clients: list[FakeQMP] = []

    def fake_popen(*a, **k):
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        return proc

    def fake_qmp(path):
        client = FakeQMP(path, fail_on="query-status")
        clients.append(client)
        return client

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", fake_qmp)

    with pytest.raises(vm_module.QMUError, match="QMP connection failed"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert clients and clients[0].closed
    assert "close" in clients[0].calls
    assert ("terminate", None) in proc.calls
    assert not qemu_log_path("txn-vm").exists()


def test_launch_metadata_save_failure_rolls_back_live_child(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=601)

    def fake_popen(*a, **k):
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        serial_log_path("txn-vm").write_text("serial")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", lambda path: FakeQMP(path))
    monkeypatch.setattr(
        vm_module, "save_instance", lambda inst: (_ for _ in ()).throw(OSError("disk full"))
    )

    with pytest.raises(OSError, match="disk full"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert ("terminate", None) in proc.calls
    assert any(c[0] == "wait" for c in proc.calls)
    assert load_instance("txn-vm") is None
    assert not qemu_log_path("txn-vm").exists()
    assert not qmp_socket_path("txn-vm").exists()
    assert not serial_log_path("txn-vm").exists()
    assert list_stopped_instances() == []


def test_launch_metadata_save_failure_escalates_when_child_ignores_term(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=602, ignore_term=True)

    def fake_popen(*a, **k):
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", lambda path: FakeQMP(path))
    monkeypatch.setattr(
        vm_module, "save_instance", lambda inst: (_ for _ in ()).throw(OSError("disk full"))
    )

    with pytest.raises(OSError, match="disk full"):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert ("kill", None) in proc.calls
    assert proc.returncode == -9
    assert not qemu_log_path("txn-vm").exists()


def test_launch_failure_cleanup_handles_qemu_log_only_artifacts(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=701, returncode=1)

    def fake_popen(*a, **k):
        qemu_log_path("txn-vm").write_text("boom\n")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    with pytest.raises(vm_module.QMUError):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert not qemu_log_path("txn-vm").exists()
    assert not qmp_socket_path("txn-vm").exists()
    assert not serial_log_path("txn-vm").exists()


def test_launch_failure_cleanup_handles_qmp_only_artifacts(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=702)

    # Timeout path after QMP appears would leave QMP; force timeout without socket
    # by creating only QMP then failing QMP validation.
    def fake_popen(*a, **k):
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(
        vm_module,
        "QMPClient",
        lambda path: FakeQMP(path, fail_on="connect"),
    )

    with pytest.raises(vm_module.QMUError):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert not qmp_socket_path("txn-vm").exists()
    assert not qemu_log_path("txn-vm").exists()


def test_launch_failure_cleanup_handles_serial_only_artifacts(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=703, returncode=1)

    def fake_popen(*a, **k):
        serial_log_path("txn-vm").write_text("serial only")
        qemu_log_path("txn-vm").write_text("exit\n")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    with pytest.raises(vm_module.QMUError):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert not serial_log_path("txn-vm").exists()
    assert not qemu_log_path("txn-vm").exists()


def test_launch_cleanup_does_not_remove_adjacent_qmu_looking_sentinels(
    tmp_path, monkeypatch
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=704, returncode=1)
    sentinel = instances_dir() / "txn-vm.unknown"
    other = instances_dir() / "other-vm.qemu.log"
    instances_dir().mkdir(parents=True, exist_ok=True)
    sentinel.write_text("keep")
    other.write_text("keep")

    def fake_popen(*a, **k):
        qemu_log_path("txn-vm").write_text("exit\n")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")

    with pytest.raises(vm_module.QMUError):
        launch_vm(
            config=QMUConfig(),
            kernel=str(kernel),
            harness=True,
            name="txn-vm",
        )

    assert sentinel.read_text() == "keep"
    assert other.read_text() == "keep"


def test_launch_success_commits_metadata_without_stopping_child(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=801)
    log_fd_holder: dict = {}

    def fake_popen(*a, **kwargs):
        log_fd_holder["fd"] = kwargs.get("stdout")
        qmp_socket_path("txn-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("txn-vm").write_text("x")
        serial_log_path("txn-vm").write_text("serial")
        return proc

    client = FakeQMP("txn-vm")
    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "start-801")
    monkeypatch.setattr(vm_module, "QMPClient", lambda path: client)

    inst = launch_vm(
        config=QMUConfig(),
        kernel=str(kernel),
        harness=True,
        name="txn-vm",
    )

    assert inst.pid == 801
    assert load_instance("txn-vm") is not None
    assert qemu_log_path("txn-vm").exists()
    assert qmp_socket_path("txn-vm").exists()
    assert serial_log_path("txn-vm").exists()
    assert ("terminate", None) not in proc.calls
    assert ("kill", None) not in proc.calls
    assert not any(c[0] == "wait" for c in proc.calls)
    assert log_fd_holder["fd"].closed
    assert client.closed
    assert "connect" in client.calls
    assert "execute:query-status" in client.calls


@pytest.mark.parametrize("phase", ["appearance", "connect", "query-status"])
def test_launch_qmp_failure_preserves_final_diagnostic_before_cleanup(
    tmp_path, monkeypatch, phase
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=901)
    original_wait = proc.wait

    def wait_with_final_output(timeout=None):
        result = original_wait(timeout)
        qemu_log_path("diagnostic-vm").write_bytes(
            b"discarded-log-prefix\n" + b"x" * 3000
            + b"\n\xffprivate-qemu-failure-token\n"
        )
        return result

    proc.wait = wait_with_final_output

    def fake_popen(*args, **kwargs):
        if phase != "appearance":
            qmp_socket_path("diagnostic-vm").write_text("socket")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(
        vm_module, "QMPClient", lambda path: FakeQMP(path, fail_on=phase)
    )
    if phase == "appearance":
        times = iter([0.0, 100.0])
        monkeypatch.setattr(vm_module.time, "monotonic", lambda: next(times, 100.0))

    with pytest.raises(vm_module.QMUError) as error:
        launch_vm(
            config=QMUConfig(), kernel=str(kernel), harness=True,
            name="diagnostic-vm",
        )

    assert "private-qemu-failure-token" in str(error.value)
    assert "discarded-log-prefix" not in str(error.value)
    assert proc.returncode is not None
    assert not any(path.exists() for path in _attempt_paths("diagnostic-vm"))


# ---------------------------------------------------------------------------
# First QMP connect reset by peer. QEMU creates the listener before it serves
# it, so under host load a concurrent launch saw ECONNRESET on the very first
# connect and was reported failed — unlike the bind race, which retried.
# ---------------------------------------------------------------------------


class _FlakyQMP(FakeQMP):
    """Fails the first `failures` connects with a transient fault, then works."""

    plan: list[BaseException] = []
    seen: list[str] = []

    def connect(self):
        self.calls.append("connect")
        _FlakyQMP.seen.append("connect")
        if _FlakyQMP.plan:
            raise _FlakyQMP.plan.pop(0)
        return {"QMP": {}}


@pytest.mark.parametrize(
    "fault",
    [
        ConnectionResetError(104, "Connection reset by peer"),
        ConnectionRefusedError(111, "Connection refused"),
        vm_module.QMPError("Cannot connect to QMP socket /x: [Errno 111] Connection refused"),
        vm_module.QMPError("QMP connection closed unexpectedly"),
    ],
    ids=["econnreset", "econnrefused", "wrapped-refused", "closed-unexpectedly"],
)
def test_transient_first_qmp_connect_is_retried_while_qemu_lives(
    tmp_path, monkeypatch, fault
):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1001)
    _FlakyQMP.plan = [fault, fault]
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)

    inst = launch_vm(
        config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm"
    )

    assert inst.vm_id == "flaky-vm"
    assert _FlakyQMP.seen.count("connect") == 3
    assert proc.returncode is None  # never terminated
    assert load_instance("flaky-vm") is not None


def test_transient_qmp_fault_gives_up_after_the_retry_budget(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1002)
    _FlakyQMP.plan = [ConnectionResetError(104, "reset")] * 1000
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    clock = iter(i / 10.0 for i in range(0, 1000000))
    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(vm_module.time, "monotonic", lambda: next(clock))

    with pytest.raises(vm_module.QMUError, match="QMP connection failed"):
        launch_vm(
            config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm"
        )

    # Bounded: a handful of attempts, not thousands, then the usual rollback.
    assert 1 < _FlakyQMP.seen.count("connect") < 50
    assert proc.returncode is not None
    assert not qmp_socket_path("flaky-vm").exists()


def test_non_transient_qmp_fault_is_not_retried(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1003)
    _FlakyQMP.plan = [vm_module.QMPError("Unexpected QMP greeting: {}")] * 5
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)

    with pytest.raises(vm_module.QMUError, match="Unexpected QMP greeting"):
        launch_vm(
            config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm"
        )

    assert _FlakyQMP.seen.count("connect") == 1


def _busy(text="accepted the connection but sent no greeting within 2s"):
    return vm_module.QMPBusyError(f"QMP socket /x {text}")


def _launch_flaky(tmp_path, monkeypatch, *, pid, clock_step):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=pid)

    def fake_popen(*a, **k):
        qmp_socket_path("slow-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("slow-vm").write_text("x")
        return proc

    # Each attempt costs the greeting budget in real life; the fake clock
    # makes that cost visible without sleeping it.
    clock = iter(i * clock_step for i in range(1_000_000))
    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(vm_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(vm_module, "_exits_within", lambda proc, grace: False)
    notes: list[str] = []
    inst = launch_vm(
        config=QMUConfig(), kernel=str(kernel), harness=True, name="slow-vm",
        notes=notes,
    )
    return inst, proc, notes


def test_a_slow_qmp_handshake_on_a_fresh_vm_is_waited_for(tmp_path, monkeypatch):
    """#157: nothing can hold a fresh VM's QMP slot, so an ungreeted connect
    means QEMU is still initialising — waited for, never blamed on a phantom
    `wait`/debugger and rolled back. Measured live: the identical relaunch
    succeeded 8 s later."""
    _FlakyQMP.plan = [_busy(), _busy("greeted the connection but did not answer qmp_capabilities")]
    _FlakyQMP.seen = []

    inst, proc, notes = _launch_flaky(tmp_path, monkeypatch, pid=1010, clock_step=1.0)

    assert inst.vm_id == "slow-vm"
    assert _FlakyQMP.seen.count("connect") == 3
    assert proc.returncode is None
    assert load_instance("slow-vm") is not None
    assert len(notes) == 1 and notes[0].startswith("QMP connect retried 2× over ")
    assert "QEMU still initialising" in notes[0]


def test_a_qmp_handshake_that_never_completes_retains_the_live_vm(tmp_path, monkeypatch):
    """Past the startup budget the live QEMU is kept with its logs (the SSH
    wait then decides: ready, `no-console-output` 4 or 124), and the note
    names the real cause instead of a concurrent client."""
    _FlakyQMP.plan = [_busy()] * 10_000
    _FlakyQMP.seen = []

    inst, proc, notes = _launch_flaky(tmp_path, monkeypatch, pid=1011, clock_step=2.0)

    assert inst.vm_id == "slow-vm"
    assert 1 < _FlakyQMP.seen.count("connect") < 50
    assert proc.returncode is None
    assert qmp_socket_path("slow-vm").exists()
    assert load_instance("slow-vm") is not None
    assert len(notes) == 1
    assert "VM 'slow-vm' is retained" in notes[0]
    assert "another qmu command" not in notes[0]


def test_a_retained_pending_vm_keeps_its_ports_from_a_concurrent_launch(
    tmp_path, monkeypatch
):
    """#157 review: QEMU creates its QMP listener before it binds -netdev
    hostfwd, so a VM retained with its handshake pending may not own its SSH
    port yet. The next launch's probe then saw the port free, both VMs were
    recorded on it, the slow one died on `Could not set up host forwarding
    rule` and still reported `ssh_status: ready` — from the other VM's sshd.
    The lock is held until the pending VM's record exists, and allocation
    skips every port a live record claims."""
    import qmu.instance as instance_mod

    kernel = _kernel(tmp_path)
    rootfs = tmp_path / "rootfs.img"
    rootfs.touch()
    key = tmp_path / "id_rsa"
    key.touch()
    config = QMUConfig()
    config.rootfs = str(rootfs)
    config.ssh_key = str(key)
    config.ssh_port_start = vm_module.find_free_port(39100)
    lock_path = instances_dir() / vm_module.PORT_LOCK_NAME

    procs = {"race-a": FakeProcess(pid=1020), "race-b": FakeProcess(pid=1021)}

    def fake_popen(cmd, **kwargs):
        name = next(n for n in procs if f"{n}.qmp.sock" in " ".join(cmd))
        qmp_socket_path(name).parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path(name).write_text("x")
        return procs[name]

    lock_at_save: dict[str, bool] = {}
    real_save = vm_module.save_instance

    def watching_save(inst):
        lock_at_save[inst.vm_id] = _lock_held(lock_path)
        real_save(inst)

    clock = iter(i * 2.0 for i in range(1_000_000))
    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module, "save_instance", watching_save)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)
    monkeypatch.setattr(vm_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(vm_module, "_exits_within", lambda proc, grace: False)
    # Both fakes are "alive" for the recorded-claim scan.
    monkeypatch.setattr(instance_mod, "instance_alive", lambda inst: True)

    # A: QEMU never answers QMP (and never binds) — retained, pending.
    _FlakyQMP.plan = [_busy()] * 10_000
    _FlakyQMP.seen = []
    a = launch_vm(config=config, kernel=str(kernel), name="race-a", notes=[])
    # B: an ordinary launch right after, probing from the same start.
    _FlakyQMP.plan = []
    b = launch_vm(config=config, kernel=str(kernel), name="race-b", notes=[])

    assert a.ssh_port == config.ssh_port_start  # nothing listens on it
    assert b.ssh_port != a.ssh_port
    assert lock_at_save["race-a"] is True  # claimed before siblings could probe
    assert not _lock_held(lock_path)


def test_a_rolled_back_qmp_failure_names_the_vm_and_its_real_state(tmp_path, monkeypatch):
    """A non-busy QMP fault still rolls back, but the envelope names the VM
    and the hint says it is gone — not `qmu status --vm <vm_id>`."""
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1012)
    _FlakyQMP.plan = [vm_module.QMPError("Unexpected QMP greeting: {}")]
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module, "_exits_within", lambda proc, grace: False)

    with pytest.raises(vm_module.QMUError) as raised:
        launch_vm(config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm")

    assert raised.value.envelope_fields() == {"vm_id": "flaky-vm"}
    assert "rolled back" in raised.value.hint
    assert "<vm_id>" not in raised.value.hint


def test_qmp_connect_retry_is_reported_in_launch_notes(tmp_path, monkeypatch):
    """#76: a retry that fires is observable — `notes` (mirrored into the
    launch envelope's `warnings[]`) names the count and the errno — instead
    of being silently absorbed, so a live reproduction can count it."""
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1004)
    _FlakyQMP.plan = [
        ConnectionRefusedError(111, "Connection refused"),
        ConnectionResetError(104, "Connection reset by peer"),
    ]
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)

    notes: list[str] = []
    inst = launch_vm(
        config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm",
        notes=notes,
    )
    assert inst.vm_id == "flaky-vm"
    # The last fault names the retry; the wrapped form resolves to its errno.
    assert notes == ["QMP connect retried 2× (ECONNRESET)"]


def test_wrapped_qmp_fault_note_names_the_underlying_errno(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1005)
    fault = vm_module.QMPError("Cannot connect to QMP socket /x: [Errno 111] Connection refused")
    fault.__cause__ = ConnectionRefusedError(111, "Connection refused")
    _FlakyQMP.plan = [fault]
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)
    monkeypatch.setattr(vm_module.time, "sleep", lambda _s: None)

    notes: list[str] = []
    launch_vm(config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm", notes=notes)
    assert notes == ["QMP connect retried 1× (ECONNREFUSED)"]


def test_clean_first_connect_leaves_no_note(tmp_path, monkeypatch):
    kernel = _kernel(tmp_path)
    proc = FakeProcess(pid=1006)
    _FlakyQMP.plan = []
    _FlakyQMP.seen = []

    def fake_popen(*a, **k):
        qmp_socket_path("flaky-vm").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("flaky-vm").write_text("x")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", _FlakyQMP)

    notes: list[str] = []
    launch_vm(config=QMUConfig(), kernel=str(kernel), harness=True, name="flaky-vm", notes=notes)
    assert notes == []
