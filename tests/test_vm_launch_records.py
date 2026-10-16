"""What `launch_vm` records on the instance, and what it blames on failure.

Three audit findings share a root: the instance record (and the error) said
something QEMU was never told.

- `--no-net` without `--ssh-port` recorded an auto-allocated SSH port qmu
  never bound; whichever VM was later handed that port answered
  `qmu exec --vm <this>` (crossarch P0).
- `--drive` launches recorded the configured rootfs they did not attach, so
  `rootfs inject` named the wrong holder and `status.rootfs` lied (harness P1).
- QEMU dying during `-netdev` setup — after the QMP socket exists — was
  reported as "QMP connection failed … Connection refused" with QEMU's own
  one-line reason discarded (crossarch/harness P2).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from qmu import vm as vm_module
from qmu.config import QMUConfig
from qmu.instance import QMUError, load_instance
from qmu.paths import qemu_log_path, qmp_socket_path
from qmu.vm import launch_vm


class FakeProcess:
    def __init__(self, *, pid: int, returncode: int | None = None):
        self.pid = pid
        self.returncode = returncode
        self.calls: list[tuple[str, float | None]] = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append(("terminate", None))
        if self.returncode is None:
            self.returncode = -15

    def kill(self):
        self.calls.append(("kill", None))
        self.returncode = -9

    def wait(self, timeout=None):
        self.calls.append(("wait", timeout))
        if self.returncode is None:
            self.returncode = -15
        return self.returncode


class FakeQMP:
    def __init__(self, socket_path, *, fail: bool = False):
        self.fail = fail

    def connect(self):
        if self.fail:
            raise OSError("[Errno 111] Connection refused")
        return {"QMP": {}}

    def execute(self, command, arguments=None, timeout=30.0):
        return {"status": "running"}

    def close(self):
        pass


@pytest.fixture
def boot_files(tmp_path):
    kernel = tmp_path / "bzImage"
    rootfs = tmp_path / "rootfs.img"
    key = tmp_path / "id_ed25519"
    for path in (kernel, rootfs, key):
        path.write_bytes(b"")
    return {"kernel": kernel, "rootfs": rootfs, "key": key}


def _config(boot_files) -> QMUConfig:
    return QMUConfig(
        rootfs=str(boot_files["rootfs"]), ssh_key=str(boot_files["key"])
    )


@pytest.fixture
def healthy_qemu(monkeypatch):
    """Popen/QMP doubles for a launch that commits; records the argv used."""
    spawned: list[list[str]] = []
    allocated: list[int] = []

    def fake_popen(cmd, **kwargs):
        spawned.append(list(cmd))
        vm_id = Path(cmd[cmd.index("-qmp") + 1].split("unix:", 1)[1].split(",")[0]).name
        vm_id = vm_id.removesuffix(".qmp.sock")
        qmp_socket_path(vm_id).parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path(vm_id).write_text("sock")
        return FakeProcess(pid=4242)

    def fake_find_free_port(start, max_tries=100):
        allocated.append(start)
        return start + 5

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "find_free_port", fake_find_free_port)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: f"start-{pid}")
    monkeypatch.setattr(vm_module, "QMPClient", FakeQMP)
    return {"spawned": spawned, "allocated": allocated}


# ---------------------------------------------------------------------------
# --no-net never records an SSH port qmu did not bind
# ---------------------------------------------------------------------------


def test_no_net_without_ssh_port_records_no_ssh_endpoint(boot_files, healthy_qemu):
    inst = launch_vm(
        config=_config(boot_files),
        kernel=str(boot_files["kernel"]),
        name="nonet",
        no_net=True,
    )

    assert inst.ssh_port is None
    assert inst.harness is False
    # No port was even looked for: there is nothing for one to describe.
    assert healthy_qemu["allocated"] == []
    cmd = healthy_qemu["spawned"][0]
    assert cmd[cmd.index("-nic") + 1] == "none"
    assert not any("hostfwd" in part for part in cmd)
    assert load_instance("nonet").ssh_port is None


def test_no_net_with_explicit_ssh_port_keeps_it(boot_files, healthy_qemu):
    """The arm32 recipe pins --ssh-port to its own hostfwd in extra args."""
    inst = launch_vm(
        config=_config(boot_files),
        kernel=str(boot_files["kernel"]),
        name="nonet-pinned",
        no_net=True,
        ssh_port=10099,
    )

    assert inst.ssh_port == 10099
    assert healthy_qemu["allocated"] == []


def test_no_net_unnamed_vm_id_is_not_labelled_harness(boot_files, healthy_qemu):
    inst = launch_vm(
        config=_config(boot_files), kernel=str(boot_files["kernel"]), no_net=True
    )

    assert inst.vm_id.startswith("vm-n")
    assert inst.harness is False


def test_networked_launch_still_allocates_an_ssh_port(boot_files, healthy_qemu):
    inst = launch_vm(
        config=_config(boot_files), kernel=str(boot_files["kernel"]), name="net"
    )

    assert inst.ssh_port == 10021 + 5
    assert healthy_qemu["allocated"] == [10021]


# ---------------------------------------------------------------------------
# rootfs is recorded only when it was attached
# ---------------------------------------------------------------------------


def test_drive_launch_records_no_rootfs(boot_files, healthy_qemu):
    inst = launch_vm(
        config=_config(boot_files),
        kernel=str(boot_files["kernel"]),
        name="drives",
        drives=["file=./other.img,format=raw,snapshot=on"],
    )

    assert inst.rootfs is None
    cmd = healthy_qemu["spawned"][0]
    assert str(boot_files["rootfs"]) not in " ".join(cmd)
    assert "file=./other.img,format=raw,snapshot=on" in cmd


def test_harness_drive_launch_records_no_rootfs(boot_files, healthy_qemu):
    inst = launch_vm(
        config=_config(boot_files),
        kernel=str(boot_files["kernel"]),
        name="harness-drives",
        harness=True,
        drives=["file=./other.img,format=raw"],
    )

    assert inst.rootfs is None


def test_harness_without_drive_records_the_attached_config_rootfs(
    boot_files, healthy_qemu
):
    """Harness mode without --drive DOES attach the configured rootfs; the
    record must say so, because `root=` in the cmdline depends on it."""
    inst = launch_vm(
        config=_config(boot_files),
        kernel=str(boot_files["kernel"]),
        name="harness-cfg",
        harness=True,
    )

    assert inst.rootfs == str(boot_files["rootfs"].resolve())
    cmd = healthy_qemu["spawned"][0]
    assert any(str(boot_files["rootfs"].resolve()) in part for part in cmd)


def test_harness_without_drive_or_rootfs_records_none(tmp_path, healthy_qemu):
    kernel = tmp_path / "bzImage"
    kernel.write_bytes(b"")

    inst = launch_vm(config=QMUConfig(), kernel=str(kernel), name="bare", harness=True)

    assert inst.rootfs is None
    assert "-drive" not in healthy_qemu["spawned"][0]


# ---------------------------------------------------------------------------
# A QEMU that dies after creating its QMP socket is reported as QEMU dying
# ---------------------------------------------------------------------------


def test_qemu_exit_after_qmp_socket_reports_qemu_output_not_qmp(
    boot_files, monkeypatch
):
    """-netdev hostfwd is applied after the QMP listener exists, so a taken
    port kills QEMU with the socket already on disk; the connect is then
    refused. The error must carry QEMU's reason, not blame QMP."""
    proc = FakeProcess(pid=777)

    def fake_popen(cmd, **kwargs):
        qmp_socket_path("dying").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("dying").write_text("sock")
        qemu_log_path("dying").write_text(
            "qemu-system-x86_64: -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10021-:22: "
            "Could not set up host forwarding rule 'tcp:127.0.0.1:10021-:22'\n"
        )
        return proc

    def fake_qmp(path):
        # QEMU exits between the socket appearing and the connect attempt.
        proc.returncode = 1
        return FakeQMP(path, fail=True)

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", fake_qmp)

    with pytest.raises(QMUError) as exc:
        launch_vm(
            config=_config(boot_files),
            kernel=str(boot_files["kernel"]),
            name="dying",
            no_net=True,
            ssh_port=10021,  # pinned: never retried on a bind failure
        )

    message = str(exc.value)
    assert message.startswith("QEMU exited immediately (code 1)")
    assert "Could not set up host forwarding rule" in message
    assert "QMP connection failed" not in message
    # The attempt is rolled back like every other startup failure.
    assert not qmp_socket_path("dying").exists()
    assert not qemu_log_path("dying").exists()
    assert load_instance("dying") is None


def test_qmp_failure_with_live_qemu_is_still_a_qmp_error(boot_files, monkeypatch):
    proc = FakeProcess(pid=778)

    def fake_popen(cmd, **kwargs):
        qmp_socket_path("alive").parent.mkdir(parents=True, exist_ok=True)
        qmp_socket_path("alive").write_text("sock")
        return proc

    monkeypatch.setattr(vm_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm_module, "proc_pid_start", lambda pid: "1")
    monkeypatch.setattr(vm_module, "QMPClient", lambda path: FakeQMP(path, fail=True))
    monkeypatch.setattr(vm_module, "_exits_within", lambda proc, grace: False)

    with pytest.raises(QMUError, match="QMP connection failed after launch"):
        launch_vm(
            config=_config(boot_files),
            kernel=str(boot_files["kernel"]),
            name="alive",
            harness=True,
        )

    assert ("terminate", None) in proc.calls


def test_exits_within_returns_promptly_for_a_dead_child():
    proc = FakeProcess(pid=1, returncode=1)
    assert vm_module._exits_within(proc, 5.0) is True


def test_exits_within_gives_up_after_grace():
    proc = FakeProcess(pid=1)
    assert vm_module._exits_within(proc, 0.05) is False
    assert proc.calls == []  # polled only; never signalled or reaped


# ---------------------------------------------------------------------------
# Boot-file errors name the resolved path and the config that set it
# ---------------------------------------------------------------------------


def test_missing_kernel_error_names_resolved_path_and_config_source(tmp_path):
    cfg = QMUConfig(kernel="./bzImage")
    cfg._path_sources["kernel"] = f"project: {tmp_path / 'qmu.toml'}"

    with pytest.raises(QMUError) as exc:
        launch_vm(config=cfg, kernel=cfg.kernel, harness=True)

    message = str(exc.value)
    assert message.startswith(f"Kernel not found: {Path.cwd() / 'bzImage'}")
    assert f"(from [boot] kernel in project: {tmp_path / 'qmu.toml'})" in message


def test_missing_kernel_from_a_flag_carries_no_config_source(tmp_path):
    with pytest.raises(QMUError) as exc:
        launch_vm(config=QMUConfig(), kernel=str(tmp_path / "nope"), harness=True)

    assert str(exc.value) == f"Kernel not found: {tmp_path / 'nope'}"


def test_missing_rootfs_and_key_errors_name_resolved_path_and_source(tmp_path):
    kernel = tmp_path / "bzImage"
    kernel.write_bytes(b"")
    cfg = QMUConfig(
        kernel=str(kernel),
        rootfs=str(tmp_path / "missing.img"),
        ssh_key=str(tmp_path / "missing_key"),
    )
    cfg._path_sources["rootfs"] = "global: /home/me/.config/qmu/config.toml"
    cfg._path_sources["ssh_key"] = "config: /work/cfg.toml"

    with pytest.raises(QMUError) as exc:
        launch_vm(config=cfg, kernel=cfg.kernel)
    assert str(exc.value) == (
        f"Rootfs image not found: {tmp_path / 'missing.img'} "
        "(from [drive] rootfs in global: /home/me/.config/qmu/config.toml)"
    )

    (tmp_path / "missing.img").write_bytes(b"")
    with pytest.raises(QMUError) as exc:
        launch_vm(config=cfg, kernel=cfg.kernel)
    assert str(exc.value) == (
        f"SSH key not found: {tmp_path / 'missing_key'} "
        "(from [ssh] key in config: /work/cfg.toml)"
    )
