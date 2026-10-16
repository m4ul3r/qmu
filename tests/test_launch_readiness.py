"""A launched process is not a successful requested SSH readiness check."""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance, load_instance, save_instance


@pytest.fixture
def launch_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text('[boot]\nkernel = "Image"\n')
    serial = tmp_path / "readiness.serial.log"
    serial.write_text("boot observation retained\n")
    inst = VMInstance(
        vm_id="readiness", pid=0, qmp_socket=str(tmp_path / "unused.qmp"),
        ssh_port=10021, ssh_key=str(tmp_path / "unused-key"), gdb_port=None,
        serial_log=str(serial), kernel="Image", rootfs=None, memory="128M",
        cpus=1, cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-09-14T00:00:00Z",
    )
    state = {"ready": False, "forbid_probe": False}

    def launch(**kwargs):
        inst.harness = kwargs["harness"]
        if inst.harness:
            inst.ssh_port = None
        save_instance(inst)
        return inst

    class SSH:
        def wait_ready(self, *, timeout):
            assert not state["forbid_probe"], "an opted-out readiness probe ran"
            return state["ready"]

    monkeypatch.setattr(lifecycle, "launch_vm", launch)
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda inst: SSH())
    return inst, serial, state


@pytest.mark.parametrize("output_format", ["json", "ndjson", "text"])
def test_requested_ssh_timeout_fails_and_retains_vm(launch_env, capsys, output_format):
    inst, serial, _ = launch_env

    rc = cli.main(["launch", "--ssh-timeout", "0", "--format", output_format])
    output = capsys.readouterr()

    assert rc == 4
    if output_format == "text":
        assert "SSH" in output.out
        assert "timeout" in output.out
        assert f"qmu log --vm {inst.vm_id}" in output.err
    else:
        payload = json.loads(output.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "SSHError"
        assert "SSH" in payload["error"]
        assert "timeout" in payload["ssh_status"]
        assert payload["vm_id"] == inst.vm_id
        assert payload["serial_log"] == str(serial)
    assert load_instance(inst.vm_id) is not None
    assert serial.read_text() == "boot observation retained\n"


def test_successful_ssh_readiness_remains_success(launch_env, capsys):
    _, _, state = launch_env
    state["ready"] = True

    rc = cli.main(["launch", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["ssh_status"] == "ready"
    assert "error" not in payload


@pytest.mark.parametrize("mode", ["--no-wait-ssh", "--harness"])
def test_opted_out_readiness_is_not_a_launch_failure(launch_env, capsys, mode):
    _, _, state = launch_env
    state["forbid_probe"] = True

    rc = cli.main(["launch", mode, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["ssh_status"] != "ready"
    assert "error" not in payload
