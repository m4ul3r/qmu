from __future__ import annotations

import subprocess

import pytest

from qmu.ssh import SSHClient, SSHError, is_transport_failure


@pytest.fixture
def client():
    return SSHClient(port=10022, key_path="/tmp/test-key")


@pytest.mark.parametrize(
    ("operation", "returncode", "stderr", "transport"),
    [
        ("push", 1, "No such file or directory", False),
        ("pull", 1, "Permission denied", False),
        ("push", 1, "protocol error", False),
        ("pull", 255, "scp: Connection closed", False),
        ("push", 255, "mux failed: Broken pipe", True),
        ("pull", 255, "Connection timed out during banner exchange", True),
    ],
)
def test_scp_nonzero_retains_classification_evidence(
    monkeypatch, tmp_path, client, operation, returncode, stderr, transport
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    monkeypatch.setattr(
        "qmu.ssh.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=returncode, stdout="", stderr=stderr
        ),
    )

    with pytest.raises(SSHError) as raised:
        if operation == "push":
            client.push(str(source), "/root/source.bin")
        else:
            client.pull("/root/source.bin", str(tmp_path / "dest.bin"))

    assert raised.value.__class__ is SSHError
    assert raised.value.returncode == returncode
    assert raised.value.stderr == stderr
    assert is_transport_failure(raised.value.returncode, raised.value.stderr) is transport


def test_push_missing_local_source_does_not_spawn_scp(monkeypatch, tmp_path, client):
    def forbidden(*args, **kwargs):
        raise AssertionError("scp must not run for a missing local source")

    monkeypatch.setattr("qmu.ssh.subprocess.run", forbidden)
    missing = tmp_path / "missing.bin"

    with pytest.raises(SSHError, match=f"Local file not found: {missing}") as raised:
        client.push(str(missing), "/root/")

    assert raised.value.returncode is None
    assert raised.value.stderr == ""


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_scp_timeout_has_no_positive_transport_evidence(
    monkeypatch, tmp_path, client, operation
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], timeout=30)

    monkeypatch.setattr("qmu.ssh.subprocess.run", timeout)
    with pytest.raises(SSHError) as raised:
        if operation == "push":
            client.push(str(source), "/root/source.bin")
        else:
            client.pull("/root/source.bin", str(tmp_path / "dest.bin"))

    assert raised.value.returncode is None
    assert raised.value.stderr == ""


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_scp_success_returns_none_and_keeps_argument_direction(
    monkeypatch, tmp_path, client, operation
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    dest = tmp_path / "dest.bin"
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("qmu.ssh.subprocess.run", fake_run)

    if operation == "push":
        result = client.push(str(source), "/root/source.bin")
        assert result is None
        assert str(source) in captured["cmd"]
        local_idx = captured["cmd"].index(str(source))
        remote_idx = next(
            i for i, arg in enumerate(captured["cmd"]) if arg.endswith(":/root/source.bin")
        )
        assert local_idx < remote_idx
        assert captured["cmd"][remote_idx].startswith("root@localhost:")
    else:
        result = client.pull("/root/source.bin", str(dest))
        assert result is None
        remote_idx = next(
            i for i, arg in enumerate(captured["cmd"]) if arg.endswith(":/root/source.bin")
        )
        local_idx = captured["cmd"].index(str(dest))
        assert remote_idx < local_idx
        assert captured["cmd"][remote_idx].startswith("root@localhost:")
