from __future__ import annotations

import json
import shlex

import pytest

from qmu.instance import QMUError
from qmu.ssh import SCPFileError, SSHAborted, SSHClient, SSHError, is_transport_failure


@pytest.fixture
def client():
    return SSHClient(port=10022, key_path="/tmp/test-key")


def _stub_scp(monkeypatch, client, tmp_path, *, rc=0, stderr="", sleep=0.0):
    """Replace the scp argv with a shell stub that records its arguments,
    prints `stderr`, optionally sleeps and exits `rc`. The transfer arguments
    (`local`, `user@host:remote`) land in $1/$2 exactly as scp would see
    them, so argument order is still observable."""
    record = tmp_path / "argv.json"
    script = (
        f"printf '%s' {shlex.quote(stderr)} >&2; "
        f"python3 -c 'import json,sys; json.dump(sys.argv[2:], open(sys.argv[1], \"w\"))' "
        f"{shlex.quote(str(record))} \"$@\"; "
        f"sleep {sleep}; exit {rc}"
    )
    monkeypatch.setattr(client, "_scp_base", lambda: ["sh", "-c", script, "scp-stub"])
    return lambda: json.loads(record.read_text()) if record.exists() else None


@pytest.mark.parametrize(
    ("operation", "returncode", "stderr", "error_class", "transport"),
    [
        # scp's own file handling on a working connection: caller errors.
        ("push", 1, "No such file or directory", SCPFileError, False),
        ("pull", 1, "Permission denied", SCPFileError, False),
        ("push", 1, "protocol error", SCPFileError, False),
        # ssh itself failed (255): transport class, with evidence retained.
        # (A bare `scp: Connection closed` is the SFTP-refusal signature and
        # is retried with `scp -O` first: test_guest_reach.py.)
        ("pull", 255, "ssh: Could not resolve hostname guest: Name or service not known", SSHError, False),
        ("push", 255, "mux failed: Broken pipe", SSHError, True),
        ("pull", 255, "Connection timed out during banner exchange", SSHError, True),
    ],
)
def test_scp_nonzero_maps_exit_code_to_error_class(
    monkeypatch, tmp_path, client, operation, returncode, stderr, error_class, transport
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    _stub_scp(monkeypatch, client, tmp_path, rc=returncode, stderr=stderr)

    with pytest.raises(error_class) as raised:
        if operation == "push":
            client.push(str(source), "/root/source.bin")
        else:
            client.pull("/root/source.bin", str(tmp_path / "dest.bin"))

    assert raised.value.__class__ is error_class
    assert raised.value.returncode == returncode
    assert raised.value.stderr == stderr
    # The scp wording is preserved so the reason stays visible to the caller.
    assert str(raised.value) == f"SCP {operation} failed: {stderr}"
    if error_class is SSHError:
        assert is_transport_failure(raised.value.returncode, raised.value.stderr) is transport


def test_scp_file_error_is_operational_not_transport():
    """exit 1 (`QMUError`), never the infra class an agent retries on."""
    assert issubclass(SCPFileError, QMUError)
    assert not issubclass(SCPFileError, SSHError)


def test_push_missing_local_source_does_not_spawn_scp(monkeypatch, tmp_path, client):
    def forbidden(*args, **kwargs):
        raise AssertionError("scp must not run for a missing local source")

    monkeypatch.setattr("qmu.ssh.subprocess.Popen", forbidden)
    missing = tmp_path / "missing.bin"

    with pytest.raises(SCPFileError, match=f"Local file not found: {missing}") as raised:
        client.push(str(missing), "/root/")

    assert raised.value.returncode is None
    assert raised.value.stderr == ""


def test_push_directory_is_refused_before_scp(monkeypatch, tmp_path, client):
    def forbidden(*args, **kwargs):
        raise AssertionError("scp must not run for a directory")

    monkeypatch.setattr("qmu.ssh.subprocess.Popen", forbidden)
    directory = tmp_path / "adir"
    directory.mkdir()

    with pytest.raises(SCPFileError, match="single files only") as raised:
        client.push(str(directory), "/root/")

    assert str(directory) in str(raised.value)


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_scp_timeout_has_no_positive_transport_evidence(
    monkeypatch, tmp_path, client, operation
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    _stub_scp(monkeypatch, client, tmp_path, sleep=5)
    monkeypatch.setattr(client, "scp_timeout", 0.3)

    with pytest.raises(SSHError, match=f"SCP {operation} timed out after 0.3s") as raised:
        if operation == "push":
            client.push(str(source), "/root/source.bin")
        else:
            client.pull("/root/source.bin", str(tmp_path / "dest.bin"))

    assert not isinstance(raised.value, SSHAborted)
    assert raised.value.returncode is None
    assert raised.value.stderr == ""


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_scp_is_aborted_when_the_watcher_fires(monkeypatch, tmp_path, client, operation):
    """A transfer is an ssh session: a breakpoint armed on a syscall sshd's
    login path makes halts the vCPU under scp, and an unwatched transfer sat
    out its whole budget before a bare timeout. `abort_when` is polled every
    0.5 s like `run`'s and stops the child with the aborted class."""
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    _stub_scp(monkeypatch, client, tmp_path, sleep=5)
    monkeypatch.setattr(client, "scp_timeout", 10.0)
    polls: list[int] = []

    def halted() -> bool:
        polls.append(1)
        return True

    with pytest.raises(SSHAborted, match=f"SCP {operation} aborted by qmu"):
        if operation == "push":
            client.push(str(source), "/root/source.bin", abort_when=halted)
        else:
            client.pull("/root/source.bin", str(tmp_path / "dest.bin"), abort_when=halted)

    assert polls == [1]


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_scp_success_returns_none_and_keeps_argument_direction(
    monkeypatch, tmp_path, client, operation
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    dest = tmp_path / "dest.bin"
    argv = _stub_scp(monkeypatch, client, tmp_path)

    if operation == "push":
        result = client.push(str(source), "/root/source.bin")
        assert result is None
        assert argv() == [str(source), "root@localhost:/root/source.bin"]
    else:
        result = client.pull("/root/source.bin", str(dest))
        assert result is None
        assert argv() == ["root@localhost:/root/source.bin", str(dest)]
