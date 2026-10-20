from __future__ import annotations

import shutil
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


class _FakeProbe:
    """Stand-in for the probe's ssh child. Each `communicate` call consumes
    one of `answers`: bytes = the child exited with `rc` and that stderr; an
    exception instance is raised (a TimeoutExpired carrying partial stderr)."""

    def __init__(self, seen: dict, answers: list, rc: int = 0):
        self.seen, self.answers, self.returncode = seen, list(answers), None
        self._rc = rc
        self.killed = False

    def __call__(self, cmd, **kwargs):
        self.seen["cmd"] = cmd
        self.seen["timeouts"] = []
        return self

    def communicate(self, timeout=None):
        self.seen["timeouts"].append(timeout)
        if self.killed:
            return b"", b""
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        self.returncode = self._rc
        return b"", answer

    def kill(self):
        self.killed = True


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

    monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe(seen, [b""]))
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


def test_run_abort_with_detach_leaves_the_command_running(tmp_path, monkeypatch):
    """#143: a debugger stop must not kill the command it interrupted. The
    child keeps its pipes — a drainer holds them — so a write after the
    abort neither kills it (SIGPIPE) nor gets lost."""
    marker = tmp_path / "finished"
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch,
        f"echo before\nsleep 1\necho after\necho late >&2\ntouch {marker}\n",
    )
    drained = tmp_path / "detached.txt"
    drained.touch()

    with pytest.raises(ssh.SSHAborted) as excinfo:
        client.run(
            "trigger", timeout=30, abort_when=lambda: True, poll_interval=0.2,
            detach_to=lambda: drained,
        )

    assert excinfo.value.detached_output == drained
    assert excinfo.value.stdout == "before\n"
    deadline = time.monotonic() + 10
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert marker.exists(), "the detached command died instead of finishing"
    while b"late" not in drained.read_bytes() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert drained.read_bytes() == b"after\nlate\n"



def test_run_relays_chunks_as_they_arrive_and_returns_the_same_bytes(
    tmp_path, monkeypatch
):
    """#71(a): a long-running exploit's progress reaches `on_chunk` while the
    child still runs — at least two separate reads before exit, stdout and
    stderr told apart — and the returned output is those bytes joined."""
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch,
        "printf 'one\\n'\nsleep 0.3\nprintf 'err\\n' >&2\nsleep 0.3\nprintf 'two\\377'\n",
    )
    seen: list[tuple[str, bytes, float]] = []

    rc, stdout, stderr = client.run(
        "progress", on_chunk=lambda s, d: seen.append((s, d, time.monotonic()))
    )

    assert rc == 0
    out_chunks = [d for s, d, _ in seen if s == "stdout"]
    assert len(out_chunks) >= 2
    assert b"".join(out_chunks) == stdout.raw == b"one\ntwo\xff"
    assert b"".join(d for s, d, _ in seen if s == "stderr") == stderr.raw == b"err\n"
    first, last = seen[0][2], seen[-1][2]
    assert last - first >= 0.4  # relayed live, not drained after exit


def test_run_timeout_relays_the_partial_output_before_raising(tmp_path, monkeypatch):
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch, "echo partial\n(sleep 20) &\nsleep 20\n"
    )
    seen: list[bytes] = []

    with pytest.raises(ssh.SSHError) as excinfo:
        client.run("x", timeout=0.5, on_chunk=lambda s, d: seen.append(d))

    assert b"".join(seen) == b"partial\n"
    assert excinfo.value.stdout == "partial\n"


def test_run_kills_the_child_when_the_chunk_callback_raises(tmp_path, monkeypatch):
    """A reader that closed the pipe (`| head`) must not leave the ssh child
    running: the drain loop is the only thing reaping it."""
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch, "echo $$ > \"$0.pid\"\necho go\nsleep 20\n"
    )

    def boom(stream: str, data: bytes) -> None:
        raise BrokenPipeError("reader gone")

    started = time.monotonic()
    with pytest.raises(BrokenPipeError):
        client.run("x", timeout=30, on_chunk=boom)
    assert time.monotonic() - started < 5
    pid = int((tmp_path / "ssh.pid").read_text())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            __import__("os").kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("ssh child survived the callback failure")


def test_run_completed_child_is_never_reported_as_timed_out(tmp_path, monkeypatch):
    """A child that finishes inside the budget returns normally even when the
    watcher is armed, and the predicate is not consulted after it exits."""
    client = _fake_ssh_on_path(tmp_path, monkeypatch, "echo done\nexit 0\n")

    rc, stdout, stderr = client.run(
        "true", timeout=5, abort_when=lambda: True, poll_interval=5
    )

    assert (rc, stdout, stderr) == (0, "done\n", "")


def test_run_deadline_wins_over_a_child_that_finished_during_a_slow_predicate(
    tmp_path, monkeypatch
):
    """#90: `exec --timeout 1.05 'sleep 1.1; printf late'` with the QMP socket
    held returned exit 0 with `late`. The watcher sampled the clock, then
    blocked in the bounded QMP probe; the child finished inside that window
    but after the deadline, and `proc.poll()` was trusted over the budget.
    The budget is re-checked after the predicate returns, and the result is
    a timeout that keeps the output the child managed to print."""
    client = _fake_ssh_on_path(tmp_path, monkeypatch, "sleep 0.6\nprintf late\n")

    def slow_probe() -> bool:
        time.sleep(0.5)  # a held QMP socket: the probe returns after the deadline
        return False

    started = time.monotonic()
    with pytest.raises(ssh.SSHError) as excinfo:
        client.run("sleep 0.6; printf late", timeout=0.5, abort_when=slow_probe, poll_interval=0.3)

    assert time.monotonic() - started < 3
    assert not isinstance(excinfo.value, ssh.SSHAborted)
    assert "timed out after 0.5s" in str(excinfo.value)
    assert excinfo.value.stdout == "late"


def test_is_ready_subprocess_cap_is_connect_timeout_plus_a_small_grace(monkeypatch):
    """#77: ssh's ConnectTimeout already bounds the banner exchange, so the
    subprocess cap is a backstop (timeout + 0.25 s), not a second budget. The
    old timeout + 3 s made a port that accepts but never speaks cost
    `list`/`status` 5 s per VM; + 0.5 s left `status` at 2.62 s wall against
    the 2.6 s end-to-end budget."""
    client = ssh.SSHClient(port=2222, key_path="test-key")
    seen: dict[str, object] = {}

    def hang(cmd):
        # Accepts TCP, never finishes the handshake: no service-accept line.
        return subprocess.TimeoutExpired(cmd, 0, stderr=b"debug1: Connecting to localhost\n")

    monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe(seen, [hang(["ssh"])]))
    assert client.is_ready() is False
    assert ssh.PROBE_GRACE_SECONDS == 0.25
    assert seen["timeouts"][0] == 2.25
    assert "ConnectTimeout=2" in _options(seen["cmd"])

    monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe(seen, [hang(["ssh"])]))
    assert client.is_ready(timeout=3) is False
    assert seen["timeouts"][0] == 3.25
    assert "ConnectTimeout=3" in _options(seen["cmd"])


def test_probe_waits_for_the_verdict_once_sshd_is_authenticating(monkeypatch):
    """#158: sshd that has accepted the userauth service is up; a slow refusal
    (PAM fail delay on the `none` method, 4.2 s measured) used to be killed at
    the connect cap and reported `down`. It now gets the auth grace."""
    client = ssh.SSHClient(port=2222, key_path="test-key", user="lowpriv")
    seen: dict[str, object] = {}
    in_auth = subprocess.TimeoutExpired(
        ["ssh"], 2.25, stderr=b"debug1: SSH2_MSG_SERVICE_ACCEPT received\n"
    )
    refused = (
        b"debug1: SSH2_MSG_SERVICE_ACCEPT received\n"
        b"lowpriv@localhost: Permission denied (publickey,password).\n"
    )
    monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe(seen, [in_auth, refused], rc=255))

    assert client.probe() == ssh.PROBE_AUTH_FAILED
    assert seen["timeouts"] == [2.25, ssh.PROBE_AUTH_GRACE_SECONDS]
    assert client.last_probe_stderr == "lowpriv@localhost: Permission denied (publickey,password)."


@pytest.mark.parametrize(
    "rc,stderr,expected",
    [
        (255, b"lowpriv@localhost: Permission denied (publickey,password).\r\n", ssh.PROBE_AUTH_FAILED),
        (255, b"ssh: connect to host localhost port 2222: Connection refused\r\n", ssh.PROBE_DOWN),
        (255, b"Connection timed out during banner exchange\r\n", ssh.PROBE_DOWN),
        (0, b"", ssh.PROBE_READY),
    ],
)
def test_probe_tells_a_refused_login_from_a_dead_port(monkeypatch, rc, stderr, expected):
    client = ssh.SSHClient(port=2222, key_path="k", user="lowpriv")
    monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe({}, [stderr], rc=rc))

    assert client.probe() == expected
    assert client.last_probe == expected


def test_an_emulated_guest_probe_gets_the_tcg_budget(monkeypatch):
    """#161: a TCG sshd under host load needs >2 s just to send its banner,
    so the KVM-sized probe called a serving guest `ssh: down`. The budget
    is floored for `kvm: false`; KVM and unknown-accel guests keep 2 s.

    The budget is checked as OpenSSH resolves it (`ssh -G`), not as argv
    text: ssh keeps the FIRST value of a repeated `-o`, so an appended
    `ConnectTimeout=8` behind the base `ConnectTimeout=5` was in argv yet
    held the banner wait at 5 s."""
    from qmu._cliutil import _make_ssh
    from qmu.instance import VMInstance

    real_run = subprocess.run
    seen: dict[str, object] = {}

    def inst(kvm):
        return VMInstance(
            vm_id="v", pid=1, qmp_socket="/q", ssh_port=2222, ssh_key="k",
            gdb_port=None, serial_log="/s", kernel="/k", rootfs=None,
            memory="1G", cpus=1, cmdline="", profile="exploit-dev",
            started_at="", harness=False, kvm=kvm,
        )

    expected = {False: ssh.EMULATED_PROBE_SECONDS, True: 2, None: 2}
    for kvm, budget in expected.items():
        hang = subprocess.TimeoutExpired(["ssh"], budget, stderr=b"")
        monkeypatch.setattr(ssh.subprocess, "Popen", _FakeProbe(seen, [hang]))
        assert _make_ssh(inst(kvm)).is_ready() is False
        assert seen["timeouts"][0] == budget + ssh.PROBE_GRACE_SECONDS, kvm
        cmd = list(seen["cmd"])
        timeouts = [o for o in cmd if o.startswith("ConnectTimeout=")]
        assert timeouts == [f"ConnectTimeout={budget}"], kvm
        monkeypatch.undo()  # the real Popen for `ssh -G`
        if shutil.which("ssh"):
            # `ssh -G` prints the resolved config without connecting.
            resolved = real_run(
                [cmd[0], "-G", *cmd[1:-1]], capture_output=True, text=True,
                timeout=10,
            ).stdout
            assert f"connecttimeout {budget}\n" in resolved, kvm


@pytest.mark.skipif(shutil.which("ssh") is None, reason="needs the OpenSSH client")
@pytest.mark.parametrize("tool", ["ssh", "scp"])
def test_a_debugger_halt_of_any_length_cannot_drop_the_guest_connection(tool):
    """#182: the ControlMaster (opened by whichever of ssh/scp runs first)
    carries a detached trigger's session through a debugger stop. A halted
    vCPU answers no keepalive, and `ServerAliveCountMax=3` dropped the
    master — and the trigger's output — 15 s into the stop. Read through
    `ssh -G`, so what is checked is the bound OpenSSH will actually apply."""
    client = ssh.SSHClient(10021, "/nonexistent-key")
    argv = client._ssh_base() if tool == "ssh" else client._scp_base()
    opts = [arg for i, a in enumerate(argv) if a == "-o" for arg in ("-o", argv[i + 1])]
    resolved = subprocess.run(
        ["ssh", "-G", "-F", "/dev/null", *opts, "localhost"],
        capture_output=True, text=True, check=True,
    ).stdout
    conf = dict(line.split(" ", 1) for line in resolved.splitlines() if " " in line)
    interval = int(conf["serveraliveinterval"])
    count = int(conf["serveralivecountmax"])
    assert interval == 0 or interval * count >= 365 * 24 * 3600
