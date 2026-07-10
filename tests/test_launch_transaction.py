from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import qmu.vm as vm_module
from qmu.config import QMUConfig
from qmu.instance import load_instance, list_stopped_instances
from qmu.paths import instances_dir, qmp_socket_path, qemu_log_path, serial_log_path
from qmu.vm import launch_vm


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
