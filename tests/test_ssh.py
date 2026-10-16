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


@pytest.mark.parametrize("method", ["run", "push", "pull"])
def test_guest_streams_are_decoded_lossily_never_raised(monkeypatch, tmp_path, method):
    """Guest output is arbitrary bytes (a leak primitive dumping raw memory).

    `text=True` without `errors=` made `exec 'head -c 100 /dev/urandom'` exit
    4 `UnicodeDecodeError` with the output discarded. Every subprocess call
    that decodes guest-originated bytes must do so lossily.
    """
    seen: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        import subprocess
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)
    client = ssh.SSHClient(port=10022, key_path="/tmp/test-key")
    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")
    if method == "run":
        client.run("head -c 100 /dev/urandom")
    elif method == "push":
        client.push(str(source), "/root/")
    else:
        client.pull("/root/payload.bin", str(tmp_path / "out.bin"))

    assert seen["text"] is True
    assert seen["errors"] == "replace"


def test_run_delivers_non_utf8_output_with_real_subprocess(tmp_path, monkeypatch):
    """End to end through a real child: bytes that are not UTF-8 come back
    as text (U+FFFD for the undecodable ones), with the exit code intact."""
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\nprintf '\\377\\376\\200abc\\n'\nexit 7\n")
    fake_ssh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    client = ssh.SSHClient(port=10022, key_path="/tmp/test-key")

    rc, stdout, stderr = client.run("true")

    assert rc == 7
    assert stdout.endswith("abc\n")
    assert "\ufffd" in stdout
