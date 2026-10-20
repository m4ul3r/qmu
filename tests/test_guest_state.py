from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from qmu import _cliutil, cli
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.qmp import QMPError
from qmu.ssh import SSHError


CASES = ("push", "pull", "exec", "compile", "dmesg")


def _instance(tmp_path) -> VMInstance:
    return VMInstance(
        vm_id="state-vm",
        pid=4242,
        qmp_socket=str(tmp_path / "state-vm.qmp.sock"),
        ssh_port=10099,
        ssh_key=str(tmp_path / "state-vm.key"),
        gdb_port=1234,
        serial_log=str(tmp_path / "state-vm.serial.log"),
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        harness=False,
    )


def _case(case: str, tmp_path, fmt: str):
    source = tmp_path / "x.c"
    source.write_text("int main(void) { return 0; }\n")
    destination = tmp_path / "pulled"
    if case == "push":
        return (
            ["--format", fmt, "push", "--vm", "state-vm", str(source), "/root/x.c"],
            [("ssh", "push", str(source), "/root/x.c")],
        )
    if case == "pull":
        return (
            ["--format", fmt, "pull", "--vm", "state-vm", "/root/x", str(destination)],
            [("ssh", "pull", "/root/x", str(destination))],
        )
    if case == "exec":
        return (
            ["--format", fmt, "exec", "--vm", "state-vm", "true"],
            [("ssh", "run", "true", 30.0)],
        )
    if case == "compile":
        return (
            ["--format", fmt, "compile", "--vm", "state-vm", str(source)],
            [
                ("ssh", "push", str(source), "/root/x.c"),
                ("ssh", "run", "gcc -static -lpthread -o /root/x /root/x.c", 30),
            ],
        )
    if case == "dmesg":
        return (
            ["--format", fmt, "dmesg", "--vm", "state-vm"],
            [("ssh", "run", "dmesg", 15)],
        )
    raise AssertionError(f"unknown case: {case}")


class FakeQMP:
    def __init__(self, trace, *, status="running", enter_error=None, execute_error=None):
        self.trace = trace
        self.status = status
        self.enter_error = enter_error
        self.execute_error = execute_error

    def __enter__(self):
        self.trace.append(("qmp", "enter"))
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command):
        self.trace.append(("qmp", command))
        if self.execute_error is not None:
            raise self.execute_error
        assert command == "query-status"
        return {"running": self.status == "running", "status": self.status}


class FakeSSH:
    def __init__(self, trace):
        self.trace = trace

    def push(self, local, remote, **kwargs):
        self.trace.append(("ssh", "push", local, remote))

    def pull(self, remote, local, **kwargs):
        self.trace.append(("ssh", "pull", remote, local))

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self.trace.append(("ssh", "run", command, timeout))
        return 0, "", ""

    def is_ready(self, timeout=2):
        self.trace.append(("ssh", "is_ready", timeout))
        return True


@pytest.mark.parametrize("fmt", ("json", "ndjson"))
@pytest.mark.parametrize("case", CASES)
def test_paused_guest_fails_before_ssh_for_every_handler(
    case, fmt, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, _ = _case(case, tmp_path, fmt)
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="paused"),
    )
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert trace == [("qmp", "enter"), ("qmp", "query-status")]
    make_ssh.assert_not_called()
    assert payload["ok"] is False
    assert payload["vm_id"] == "state-vm"
    assert payload["qemu_status"] == "paused"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert "crash" not in payload
    assert "qmu cont --vm state-vm" in payload["hint"]
    assert "pry continue" in payload["hint"]


@pytest.mark.parametrize("case", CASES)
def test_running_guest_preflight_dispatches_every_ssh_handler(
    case, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case(case, tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="running"),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace[:3] == [
        ("qmp", "enter"),
        ("qmp", "query-status"),
        ("ssh", "construct"),
    ]
    assert trace[3:] == expected_ssh


@pytest.mark.parametrize("case", CASES)
def test_qmp_unavailable_falls_back_to_every_ssh_handler(
    case, monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case(case, tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(
            trace,
            enter_error=QMPError("QMP socket unavailable"),
        ),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace == [
        ("qmp", "enter"),
        ("ssh", "construct"),
        *expected_ssh,
    ]


def test_qmp_oserror_during_query_falls_back_to_ssh(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, expected_ssh = _case("exec", tmp_path, "json")
    fake_ssh = FakeSSH(trace)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(
            trace,
            execute_error=OSError("QMP disappeared"),
        ),
    )

    def make_ssh(selected):
        trace.append(("ssh", "construct"))
        return fake_ssh

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert trace == [
        ("qmp", "enter"),
        ("qmp", "query-status"),
        ("ssh", "construct"),
        *expected_ssh,
    ]


def test_debug_state_uses_same_operational_failure(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    argv, _ = _case("exec", tmp_path, "json")
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="debug"),
    )
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    make_ssh.assert_not_called()
    assert payload["qemu_status"] == "debug"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert "crash" not in payload


def test_paused_guest_text_names_state_and_recovery_without_crash_wording(
    monkeypatch, tmp_path, capsys
):
    inst = _instance(tmp_path)
    trace = []
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil,
        "_qmp_ctx",
        lambda selected: FakeQMP(trace, status="paused"),
    )
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(["exec", "--vm", "state-vm", "true"])
    captured = capsys.readouterr()

    assert rc == 1
    make_ssh.assert_not_called()
    # A refusal is prose, not a result: it goes to stderr with the documented
    # prefix so `eval "$(qmu kbase ...)"` / `qmu exec ... | grep` never see it.
    assert captured.out == ""
    assert captured.err.startswith("[qmu] Error: VM 'state-vm' is paused")
    assert "qmu cont --vm state-vm" in captured.err
    assert "pry continue" in captured.err
    assert "SSH connection lost" not in captured.err
    assert "crash" not in captured.err.lower()


@pytest.mark.parametrize("status", ("restore-vm", "prelaunch", "inmigrate"))
@pytest.mark.parametrize("case", CASES)
def test_any_non_running_qmp_status_fails_before_ssh(
    case, status, monkeypatch, tmp_path, capsys
):
    """The gate keys on `running: false`, not on the names paused/debug.

    A failed `snapshot load` leaves QEMU in `restore-vm`; `status` called it
    `paused` while every SSH command spent 15–30 s and exited 4 "unreachable".
    """
    inst = _instance(tmp_path)
    trace = []
    argv, _ = _case(case, tmp_path, "json")
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil, "_qmp_ctx", lambda selected: FakeQMP(trace, status=status)
    )
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    make_ssh.assert_not_called()
    assert payload["ok"] is False
    assert payload["guest_state"] == "paused"
    assert payload["qemu_status"] == status
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    if status == "restore-vm":
        # A load that failed mid-restore: resuming is the inconsistent machine
        # #87 is about, so the recovery is another load or a relaunch.
        assert "qmu cont" not in payload["hint"]
        assert "qmu snapshot load" in payload["hint"]
        assert "qmu kill --vm state-vm" in payload["hint"]
    else:
        assert "qmu cont --vm state-vm" in payload["hint"]


TERMINAL_PANIC = (
    "[    0.000000] Linux version 7.0.0 (qmu@kbuild) (gcc 13) #1 SMP\n"
    "[    9.1] sysrq: Trigger a crash\n"
    "[    9.2] Kernel panic - not syncing: sysrq triggered crash\n"
    "[    9.3] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---\n"
)


@pytest.mark.parametrize("fmt", ("json", "text"))
@pytest.mark.parametrize("case", CASES)
def test_panicked_guest_fails_before_ssh_and_qmp(
    case, fmt, monkeypatch, tmp_path, capsys
):
    """A terminal panic in the current boot refuses SSH work in <1 s.

    Measured live: `exec true` on a VM `status` already called PANICKED spent
    15.8 s in ssh keepalive and reported exit 4 "No fresh crash detected".
    Exit 1, not 3: the panic is not fresh for this command; not 4: the guest
    is known gone, not merely unreachable.
    """
    inst = _instance(tmp_path)
    (tmp_path / "state-vm.serial.log").write_text(TERMINAL_PANIC)
    argv, _ = _case(case, tmp_path, fmt)
    make_ssh = Mock(side_effect=AssertionError("SSH client was constructed"))
    qmp = Mock(side_effect=AssertionError("QMP was consulted"))
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(_cliutil, "_qmp_ctx", qmp)
    monkeypatch.setattr(guest, "_make_ssh", make_ssh)

    rc = cli.main(argv)
    captured = capsys.readouterr()

    assert rc == 1
    make_ssh.assert_not_called()
    qmp.assert_not_called()
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["vm_id"] == "state-vm"
        assert payload["guest_state"] == "panicked"
        assert payload["ssh_error"] is False
        assert payload["crash_detected"] is False
        assert "crash" not in payload
        assert "qmu crash --vm state-vm" in payload["hint"]
        assert "qmu kill --vm state-vm" in payload["hint"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("[qmu] Error: VM 'state-vm' guest is PANICKED")
        assert "qmu crash --vm state-vm" in captured.err
        assert "qmu kill --vm state-vm" in captured.err


@pytest.mark.parametrize("case", CASES)
def test_panic_followed_by_reboot_is_not_refused(
    case, monkeypatch, tmp_path, capsys
):
    """Scope is the current boot: a banner after the panic means a new guest."""
    inst = _instance(tmp_path)
    (tmp_path / "state-vm.serial.log").write_text(
        TERMINAL_PANIC
        + "[    9.4] Rebooting in 3 seconds..\n"
        + "[    0.000000] Linux version 7.0.0 (qmu@kbuild) (gcc 13) #1 SMP\n"
        + "localhost login: \n"
    )
    trace = []
    argv, expected_ssh = _case(case, tmp_path, "json")
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil, "_qmp_ctx", lambda selected: FakeQMP(trace, status="running")
    )
    monkeypatch.setattr(guest, "_make_ssh", lambda selected: FakeSSH(trace))

    rc = cli.main(argv)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert [t for t in trace if t[0] == "ssh"] == expected_ssh


class _BreakpointSSH:
    """`ssh.run` times out because a breakpoint halted the vCPU mid-command."""

    def __init__(self):
        self.is_ready_calls = 0

    def run(self, command, timeout=30.0, check=False, **kwargs):
        raise SSHError(f"SSH command timed out after {timeout}s: {command}")

    def is_ready(self, timeout=2):
        self.is_ready_calls += 1
        return False


def test_debugger_stop_mid_exec_is_reported_not_transport_loss(
    monkeypatch, tmp_path, capsys
):
    """Measured live: 26.7 s on `--timeout 15`, exit 4 "VM may be unreachable"
    while QMP said `debug`. The vCPU state explains the loss; no probe."""
    inst = _instance(tmp_path)
    (tmp_path / "state-vm.serial.log").write_text("[ 0.0] Linux version 7.0.0 (x) #1\n")
    trace = []
    qmp_status = {"status": "running"}
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        _cliutil, "_qmp_ctx",
        lambda selected: FakeQMP(trace, status=qmp_status["status"]),
    )
    fake = _BreakpointSSH()

    def make_ssh(selected):
        qmp_status["status"] = "debug"  # the breakpoint fires during run()
        return fake

    monkeypatch.setattr(guest, "_make_ssh", make_ssh)
    monkeypatch.setattr(guest.time, "sleep", lambda _: None)

    rc = cli.main(["--format", "json", "exec", "--vm", "state-vm", "--timeout", "15", "uname -r"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert fake.is_ready_calls == 0
    assert payload["ok"] is False
    assert payload["guest_state"] == "paused"
    assert payload["qemu_status"] == "debug"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert payload["exit_code"] is None
    assert payload["command"] == "uname -r"
    assert "pry continue" in payload["hint"]


# ---------------------------------------------------------------------------
# dmesg must apply the SAME crash-vs-transport-loss discrimination as its
# SSH-facing siblings.
#
# Measured on a really panicked guest before this: `exec`/`push`/`pull` all
# reported exit 4 with ssh_error/crash_detected, while `qmu dmesg --tail 5`
# reported exit 1 with `[dmesg failed, exit 255] Connection timed out during
# banner exchange` — rc 1 is the "guest command non-zero" class, so the agent
# read "dmesg failed inside the guest" and never learned the kernel was gone.
# ---------------------------------------------------------------------------


DMESG_PANIC = (
    "[    9.101] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[    9.102] Kernel panic - not syncing: Fatal exception\n"
    "[    9.103] RIP: 0010:sysrq_handle_crash+0x16/0x20\n"
)


class LostSSH:
    """SSH whose dmesg read fails the way a panicked guest makes it fail."""

    def __init__(self, serial_path, *, rc=255, stderr="", ready=False,
                 append="", run_error=None, client_log=None):
        self._serial_path = serial_path
        self._rc = rc
        self._stderr = stderr
        self._ready = ready
        self._append = append
        self._run_error = run_error
        # What the real client's `-E` log would hold for this run (#199).
        self.last_client_log = client_log
        self.runs: list[str] = []
        self.is_ready_calls = 0

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self.runs.append(command)
        if self._append:
            with self._serial_path.open("a") as stream:
                stream.write(self._append)
            self._append = ""
        if self._run_error is not None:
            raise self._run_error
        return self._rc, "", self._stderr

    def is_ready(self, timeout=2):
        self.is_ready_calls += 1
        return self._ready


@pytest.fixture
def dmesg_ssh(monkeypatch, tmp_path):
    """Wire `qmu dmesg` at the production seam with a controllable transport."""
    def install(*, initial_serial="boot ok\n", **kwargs):
        inst = _instance(tmp_path)
        serial = tmp_path / "state-vm.serial.log"
        serial.write_text(initial_serial)
        fake = LostSSH(serial, **kwargs)
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda selected: fake)
        monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
        monkeypatch.setattr(guest.time, "sleep", lambda _: None)
        return fake

    return install


@pytest.mark.parametrize("sshd_up_by_probe", [False, True])
def test_dmesg_transport_loss_without_fresh_crash_is_exit4(
    dmesg_ssh, capsys, sshd_up_by_probe
):
    """The exact dogfooded shape: rc=255 + banner-exchange timeout, no panic.

    Exit 4 (guest merely unreachable), never 1 and never 3 — the contract
    `exec`/`push`/`pull` already met. ssh never connected, so dmesg never
    ran: an sshd that answers by the time qmu would re-probe does not turn
    it into "dmesg exited 255" (#177).
    """
    banner_timeout = "Connection timed out during banner exchange\r\n"
    dmesg_ssh(
        stderr=banner_timeout,
        client_log=banner_timeout,
        ready=sshd_up_by_probe,
    )

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm", "--tail", "5"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 4
    assert payload["ok"] is False
    assert payload["exit_code"] is None
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None
    assert "qmu log --vm state-vm --tail 100" in payload["hint"]


def test_dmesg_transport_loss_with_fresh_crash_is_exit3(dmesg_ssh, capsys):
    """A corroborating fresh serial report is what promotes 4 -> 3."""
    dmesg_ssh(initial_serial="old boot\n", append=DMESG_PANIC)

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "panic" in payload["crash"].lower()
    assert "qmu crash" in payload["hint"]


def test_dmesg_transport_loss_ignores_a_stale_precommand_crash(dmesg_ssh, capsys):
    """Crash extraction is scoped to the command, as it is for exec."""
    dmesg_ssh(initial_serial=DMESG_PANIC)

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 4
    assert payload["crash_detected"] is False
    assert payload["crash"] is None
    assert "Fatal exception" not in out


def test_dmesg_nonzero_in_a_healthy_guest_is_still_exit1(dmesg_ssh, capsys):
    """The real "guest command non-zero" case must NOT move to 4.

    A permission failure inside a live guest keeps exit 1 and the byte-stable
    text/JSON shape (no ssh_error/crash keys appear on this path).
    """
    dmesg_ssh(rc=1, stderr="dmesg: read kernel buffer failed: Operation not permitted",
              ready=True)

    rc = cli.main(["dmesg", "--vm", "state-vm"])
    captured = capsys.readouterr()

    assert rc == 1
    assert "[dmesg failed, exit 1] dmesg: read kernel buffer failed" in captured.err
    assert "SSH connection lost" not in captured.out + captured.err


def test_dmesg_guest_exit255_on_a_live_guest_is_not_a_crash(dmesg_ssh, capsys):
    """rc=255 is a legal guest exit code; the liveness probe is the
    discriminator, so a reachable guest keeps exit 1 with the old envelope."""
    fake = dmesg_ssh(rc=255, ready=True, initial_serial=DMESG_PANIC)

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert fake.is_ready_calls >= 1
    assert set(payload) == {"ok", "exit_code", "text", "stderr", "vm_id", "hint"}
    assert "crash_detected" not in payload and "ssh_error" not in payload
    assert payload["exit_code"] == 255


def test_dmesg_success_envelope_is_unchanged(dmesg_ssh, capsys):
    dmesg_ssh(rc=0, ready=True)

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert set(payload) == {"ok", "exit_code", "text", "stderr", "vm_id"}
    assert payload["ok"] is True


def test_dmesg_ssh_timeout_on_a_live_guest_stays_infra(dmesg_ssh, capsys):
    """A slow dmesg on a guest that still answers is infra (4) with no crash
    claim — the same probe-first rule exec applies to its own timeout."""
    fake = dmesg_ssh(ready=True, run_error=SSHError("command timed out"))

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 4
    assert fake.is_ready_calls >= 1
    assert payload["error_type"] == "SSHError"
    assert "crash_detected" not in payload


def test_dmesg_ssh_timeout_on_a_dead_guest_takes_the_crash_path(dmesg_ssh, capsys):
    dmesg_ssh(
        initial_serial="old boot\n",
        append=DMESG_PANIC,
        run_error=SSHError("command timed out"),
    )

    rc = cli.main(["--format", "json", "dmesg", "--vm", "state-vm"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True


@pytest.mark.parametrize("panicked", [True, False])
def test_compile_run_transport_loss_names_the_same_follow_up_as_exec(
    panicked, monkeypatch, tmp_path, capsys
):
    """`compile --run` used to emit no `hint` at all, so the one command that
    shows the panic (`qmu crash`) went unnamed on the path most likely to
    produce one. The hint text now comes from the shared helper."""
    inst = _instance(tmp_path)
    serial = tmp_path / "state-vm.serial.log"
    serial.write_text("old boot\n")
    source = tmp_path / "poc.c"
    source.write_text("int main(void) { return 0; }\n")

    class CompileSSH(LostSSH):
        def __init__(self):
            super().__init__(serial, append=DMESG_PANIC if panicked else "")
            self._compiled = False

        def push(self, local, remote, **kwargs):
            pass

        def run(self, command, timeout=30.0, check=False, **kwargs):
            if not self._compiled:
                self._compiled = True
                return 0, "", ""
            return super().run(command, timeout=timeout)

    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest, "_make_ssh", lambda selected: CompileSSH())
    monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest.time, "sleep", lambda _: None)

    rc = cli.main(
        ["--format", "json", "compile", "--vm", "state-vm", str(source), "--run"]
    )

    payload = json.loads(capsys.readouterr().out)
    # Same split exec/dmesg/push/pull use: 3 only with a fresh report, else 4.
    assert rc == (3 if panicked else 4)
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is panicked
    assert ("qmu crash --vm state-vm" in payload["hint"]) is panicked
    assert ("qmu log --vm state-vm --tail 100" in payload["hint"]) is not panicked
