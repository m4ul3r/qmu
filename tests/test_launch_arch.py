from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from qmu import vm
from qmu.config import QMUConfig
from qmu.instance import load_instance


class _ConnectedQMP:
    def __init__(self, socket_path):
        self.socket_path = socket_path

    def connect(self):
        return {"QMP": {}}

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, command, **kwargs):
        return {"status": "running"}


def test_launch_persists_configured_guest_architecture(monkeypatch, tmp_path):
    kernel = tmp_path / "Image"
    rootfs = tmp_path / "rootfs.img"
    key = tmp_path / "id_ed25519"
    for path in (kernel, rootfs, key):
        path.write_bytes(b"")

    config = QMUConfig(
        arch="aarch64",
        rootfs=str(rootfs),
        ssh_key=str(key),
    )

    def fake_popen(command, **kwargs):
        qmp_arg = command[command.index("-qmp") + 1]
        qmp_socket = qmp_arg.removeprefix("unix:").split(",", 1)[0]
        Path(qmp_socket).touch()
        kwargs["stdout"].close()

        class _FakeProc:
            pid = 4242
            returncode = None

            def poll(self):
                return self.returncode

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

            def wait(self, timeout=None):
                if self.returncode is None:
                    self.returncode = 0
                return self.returncode

        return _FakeProc()

    monkeypatch.setattr(vm.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vm, "QMPClient", _ConnectedQMP)

    vm.launch_vm(
        config=config,
        kernel=str(kernel),
        name="arch-metadata",
        ssh_port=10022,
    )

    loaded = load_instance("arch-metadata")
    assert loaded is not None
    assert loaded.arch == "aarch64"
