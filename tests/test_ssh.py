from __future__ import annotations

from pathlib import Path

import pytest

from qmu import ssh


def _control_path(opts: list[str]) -> str:
    return next(
        value.split("=", 1)[1]
        for value in opts
        if value.startswith("ControlPath=")
    )


def _options(command: list[str]) -> set[str]:
    return {
        command[index + 1]
        for index, value in enumerate(command[:-1])
        if value == "-o"
    }


def test_control_opts_uses_current_runtime_override(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    first = Path("a")
    second = Path("b")
    monkeypatch.setenv("QMU_TEMP_DIR", str(first))
    first_path = _control_path(ssh._control_opts())
    monkeypatch.setenv("QMU_TEMP_DIR", str(second))
    second_path = _control_path(ssh._control_opts())
    assert first_path == str(first / "ssh" / "cm-%C")
    assert second_path == str(second / "ssh" / "cm-%C")


def test_overlong_runtime_override_disables_multiplexing(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_TEMP_DIR", str(tmp_path / ("x" * 80)))
    assert ssh._control_opts() == []


def test_control_directory_creation_failure_disables_multiplexing(monkeypatch):
    def fail_control_path():
        raise OSError("denied")

    monkeypatch.setattr(ssh, "ssh_control_path", fail_control_path)
    assert ssh._control_opts() == []


@pytest.mark.parametrize(
    "root_name,safe",
    [
        pytest.param("x" * 35, True, id="safe-boundary"),
        pytest.param("x" * 51, False, id="99-byte-expanded-path"),
        pytest.param("x" * 80, False, id="overlong-root"),
    ],
)
def test_ssh_and_scp_builders_share_current_bounded_control_options(
    tmp_path, monkeypatch, root_name, safe
):
    monkeypatch.chdir(tmp_path)
    runtime = Path(root_name)
    monkeypatch.setenv("QMU_TEMP_DIR", str(runtime))
    client = ssh.SSHClient(port=2222, key_path="test-key")
    expected = {
        "ControlMaster=auto",
        "ControlPersist=60",
        f"ControlPath={runtime / 'ssh' / 'cm-%C'}",
    }

    for command in (client._ssh_base(), client._scp_base()):
        options = _options(command)
        if safe:
            assert expected <= options
        else:
            assert not any(option.startswith("Control") for option in options)
