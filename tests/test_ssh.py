from __future__ import annotations

import subprocess
import time
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


def test_is_ready_probe_never_spawns_a_control_master(tmp_path, monkeypatch):
    """`list`/`status`/launch probe every serving VM on the host; a multiplexed
    probe left a persistent `ssh [mux]` master (ControlPersist 60) per VM —
    including other users' — under the prober's QMU_TEMP_DIR."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("QMU_TEMP_DIR", str(Path("rt")))
    client = ssh.SSHClient(port=2222, key_path="test-key")
    seen: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)
    assert client.is_ready() is True
    options = _options(seen["cmd"])
    assert "ControlMaster=no" in options
    assert not any(o.startswith(("ControlPath=", "ControlPersist=")) for o in options)
    # Commands keep the shared master.
    assert "ControlMaster=auto" in _options(client._ssh_base())


@pytest.mark.parametrize("method", ["push", "pull"])
def test_scp_stderr_is_decoded_lossily_never_raised(monkeypatch, tmp_path, method):
    """Guest output is arbitrary bytes (a leak primitive dumping raw memory).

    `text=True` without `errors=` made `exec 'head -c 100 /dev/urandom'` exit
    4 `UnicodeDecodeError` with the output discarded. scp's stderr (the one
    stream it carries) goes through the same byte drain as `run` and is
    decoded lossily.
    """
    client = ssh.SSHClient(port=10022, key_path="/tmp/test-key")
    monkeypatch.setattr(
        client,
        "_scp_base",
        lambda: ["sh", "-c", "printf 'bad \\377 byte' >&2; exit 255", "scp-stub"],
    )
    source = tmp_path / "payload.bin"
    source.write_bytes(b"data")
    with pytest.raises(ssh.SSHError) as raised:
        if method == "push":
            client.push(str(source), "/root/")
        else:
            client.pull("/root/payload.bin", str(tmp_path / "out.bin"))

    assert raised.value.returncode == 255
    assert raised.value.stderr == "bad \ufffd byte"


def _fake_ssh_on_path(tmp_path, monkeypatch, script: str) -> ssh.SSHClient:
    """Put a shell script named `ssh` first on PATH and return a client."""
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\n" + script)
    fake_ssh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    return ssh.SSHClient(port=10022, key_path="/tmp/test-key")


def test_run_delivers_non_utf8_output_with_real_subprocess(tmp_path, monkeypatch):
    """End to end through a real child: bytes that are not UTF-8 come back
    as text (U+FFFD for the undecodable ones) for the envelope, with the
    exact bytes on `.raw` for text mode and `.lossy` recording the
    replacement; the exit code is intact."""
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch, "printf '\\377\\376\\200abc\\n'\necho err >&2\nexit 7\n"
    )

    rc, stdout, stderr = client.run("true")

    assert rc == 7
    assert stdout.endswith("abc\n")
    assert "\ufffd" in stdout
    assert isinstance(stdout, ssh.GuestText)
    assert stdout.raw == b"\xff\xfe\x80abc\n"
    assert stdout.lossy is True
    assert stderr == "err\n"
    assert stderr.raw == b"err\n"
    assert stderr.lossy is False
    assert ssh.guest_bytes(stdout) == stdout.raw
    assert ssh.guest_bytes("plain") == b"plain"
    assert ssh.guest_lossy("plain") is False


def test_run_timeout_keeps_partial_output_and_does_not_wait_for_the_remote(
    tmp_path, monkeypatch
):
    """`--timeout` reports what the command printed before the deadline.

    Under ControlMaster the ssh child hands its pipes to the mux master, which
    keeps them open until the REMOTE command ends — modelled here by a
    background child holding stdout. `communicate()` after `kill()` therefore
    blocked for the remote command's whole lifetime (measured: `--timeout 2`
    on `sleep 10` returned after 10 s); the select loop must not.
    """
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch,
        "echo partial\necho progress >&2\n(sleep 20) &\nsleep 20\n",
    )

    started = time.monotonic()
    with pytest.raises(ssh.SSHError) as excinfo:
        client.run("echo partial; sleep 20", timeout=0.5)

    assert time.monotonic() - started < 5
    assert not isinstance(excinfo.value, ssh.SSHAborted)
    assert "timed out after 0.5s" in str(excinfo.value)
    assert excinfo.value.stdout == "partial\n"
    assert excinfo.value.stderr == "progress\n"


def test_run_abort_when_stops_the_child_with_its_output(tmp_path, monkeypatch):
    """The watcher predicate ends the command as soon as it fires (the serial
    log shows a panic) instead of waiting for ssh's keepalive to notice."""
    client = _fake_ssh_on_path(tmp_path, monkeypatch, "echo pre\nsleep 20\n")
    polls: list[float] = []

    def panicked() -> bool:
        polls.append(time.monotonic())
        return len(polls) >= 2

    started = time.monotonic()
    with pytest.raises(ssh.SSHAborted) as excinfo:
        client.run("trigger", timeout=30, abort_when=panicked, poll_interval=0.1)

    assert time.monotonic() - started < 5
    assert len(polls) == 2
    assert excinfo.value.stdout == "pre\n"


def test_run_completed_child_is_never_reported_as_timed_out(tmp_path, monkeypatch):
    """A child that finishes inside the budget returns normally even when the
    watcher is armed, and the predicate is not consulted after it exits."""
    client = _fake_ssh_on_path(tmp_path, monkeypatch, "echo done\nexit 0\n")

    rc, stdout, stderr = client.run(
        "true", timeout=5, abort_when=lambda: True, poll_interval=5
    )

    assert (rc, stdout, stderr) == (0, "done\n", "")
