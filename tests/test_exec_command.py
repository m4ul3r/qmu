"""`qmu exec` as an agent sees it: argv, streams, the panic watcher, envelopes.

Pins the second-wave guest-I/O contract:

  * the guest command is a `nargs="+"` positional — one quoted argument
    reaches the guest shell verbatim, several are shlex-joined, `--` lets the
    command carry its own dash-words, qmu flags apply wherever they appear
    (`qmu exec "./exploit" --timeout 120`), an unquoted `uname -a` is a usage
    error that hints at the quoted/`--` forms, an empty command is a usage
    error;
  * text-mode stdout is the guest's stdout, byte for byte; guest stderr and
    the `[exit code: N]` trailer go to stderr, so `qmu exec ... > out.txt`
    collects guest output only;
  * the ssh child is watched against the serial log: the predicate handed to
    `SSHClient.run` sees a panic appended after the command started (and not
    one that was already there), and an abort takes the crash path (exit 3)
    with the output collected so far;
  * `--timeout` keeps partial output (`stdout`/`stderr`, `exit_code: null`);
  * every guest-command envelope carries `vm_id`, success and failure alike.

Doubles are installed on `qmu.commands.guest`, the module that owns the
handlers (see CLAUDE.md on the command-package DAG).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time

import pytest

from qmu import cli
from qmu._cliutil import _wait_pid_exit
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.ssh import SSHAborted, SSHError

PANIC = (
    "[    3.111] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[    3.112] Kernel panic - not syncing: Fatal exception\n"
    "[    3.113] RIP: 0010:do_the_bad_thing+0x40/0x80\n"
)


def _instance(serial_log: str) -> VMInstance:
    return VMInstance(
        vm_id="exec-vm",
        pid=4242,
        qmp_socket="/tmp/exec-vm.qmp.sock",
        ssh_port=10099,
        ssh_key="/tmp/exec-vm.key",
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-29T00:00:00Z",
        harness=False,
    )


class WatchedSSH:
    """A fake whose `run` honours `abort_when` the way the real client does.

    `append_during_run` lands in the serial log while the command "runs"; the
    predicate is then consulted, and a True answer aborts with the partial
    output — which is exactly the production contract the handler relies on.
    """

    def __init__(
        self,
        serial_path,
        *,
        rc=0,
        stdout="",
        stderr="",
        ready=True,
        append_during_run="",
        raises=None,
    ):
        self._serial_path = serial_path
        self._rc, self._stdout, self._stderr = rc, stdout, stderr
        self._ready = ready
        self._append = append_during_run
        self._raises = raises
        self.runs: list[str] = []
        self.timeouts: list[float] = []
        self.predicate_answers: list[bool] = []
        self.pushes: list[tuple[str, str]] = []
        self.pulls: list[tuple[str, str]] = []

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self.runs.append(command)
        self.timeouts.append(timeout)
        if self._append:
            with open(self._serial_path, "a", encoding="utf-8") as stream:
                stream.write(self._append)
        abort_when = kwargs.get("abort_when")
        if abort_when is not None:
            fired = abort_when()
            self.predicate_answers.append(fired)
            if fired:
                raise SSHAborted(
                    f"SSH command aborted (guest kernel panicked): {command}",
                    stdout=self._stdout,
                    stderr=self._stderr,
                )
        if self._raises is not None:
            raise self._raises
        return self._rc, self._stdout, self._stderr

    def is_ready(self, timeout=2):
        return self._ready

    def push(self, local, remote, **kwargs):
        self.pushes.append((local, remote))

    def pull(self, remote, local, **kwargs):
        self.pulls.append((remote, local))


@pytest.fixture
def wired(monkeypatch, tmp_path):
    serial = tmp_path / "exec-vm.serial.log"

    def install(*, initial_serial="boot ok\n", **ssh_kw):
        serial.write_text(initial_serial)
        inst = _instance(str(serial))
        fake = WatchedSSH(serial, **ssh_kw)
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda i: fake)
        monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
        monkeypatch.setattr(guest, "_require_running_vm", lambda vm, command: None)
        monkeypatch.setattr(guest.time, "sleep", lambda _: None)
        return fake

    return install


# --- argv -------------------------------------------------------------------


def test_unquoted_words_are_joined_into_one_command(wired):
    fake = wired()

    rc = cli.main(["exec", "--vm", "exec-vm", "echo", "hi"])

    assert rc == 0
    assert fake.runs == ["echo hi"]


def test_a_single_quoted_argument_reaches_the_guest_shell_verbatim(wired):
    fake = wired()

    cli.main(["exec", "--vm", "exec-vm", "cat /proc/slabinfo | grep kmalloc-192"])

    assert fake.runs == ["cat /proc/slabinfo | grep kmalloc-192"]


def test_several_words_keep_the_token_per_argument_model(wired):
    fake = wired()

    cli.main(["exec", "--vm", "exec-vm", "grep", "two words", "f"])

    assert fake.runs == ["grep 'two words' f"]


def test_double_dash_hands_dash_words_to_the_guest(wired):
    fake = wired()

    cli.main(["exec", "--vm", "exec-vm", "--", "ls", "-la", "/root"])

    assert fake.runs == ["ls -la /root"]


def test_qmu_flags_after_the_command_are_qmus(wired):
    """`qmu exec "./exploit" --timeout 120` is the documented form; REMAINDER
    once handed `--timeout 120` to the guest and ran with the default 30 s."""
    fake = wired()

    rc = cli.main(["exec", "--vm", "exec-vm", "./exploit", "--timeout", "7"])

    assert rc == 0
    assert fake.runs == ["./exploit"]
    assert fake.timeouts == [7.0]


def test_vm_before_and_format_after_the_command(wired, capsys):
    fake = wired(stdout="hi\n")

    rc = cli.main(["exec", "--vm", "exec-vm", "echo", "hi", "--format", "json"])

    assert rc == 0
    assert fake.runs == ["echo hi"]
    assert json.loads(capsys.readouterr().out)["stdout"] == "hi\n"


def test_unquoted_dash_words_are_a_usage_error_with_a_hint(wired, capsys):
    wired()

    with pytest.raises(SystemExit) as exc:
        cli.main(["exec", "--vm", "exec-vm", "uname", "-a"])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unrecognized arguments: -a" in err
    assert (
        "Hint: quote the guest command ('uname -a') or put -- before it "
        "(qmu exec -- uname -a); qmu flags may appear anywhere." in err
    )


def test_unquoted_dash_words_hint_rides_in_the_json_envelope(wired, capsys):
    wired()

    with pytest.raises(SystemExit) as exc:
        cli.main(["exec", "--vm", "exec-vm", "--format", "json", "uname", "-a"])

    assert exc.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "UsageError"
    assert payload["error"] == "unrecognized arguments: -a"
    assert payload["hint"].startswith("Hint: quote the guest command")


def test_an_empty_command_is_a_usage_error(wired, capsys):
    wired()

    with pytest.raises(SystemExit) as exc:
        cli.main(["exec", "--vm", "exec-vm"])

    assert exc.value.code == 2
    assert "the following arguments are required: command" in capsys.readouterr().err


# --- text-mode streams ------------------------------------------------------


def test_text_mode_keeps_stdout_for_guest_stdout_only(wired, capsys):
    """`qmu exec 'echo out; echo err >&2; exit 5' > o 2> e` measured live:
    o = `out\\n[stderr] err\\n[exit code: 5]`, e empty. Now o is the guest's
    stdout alone and the decorations are on stderr."""
    wired(rc=5, stdout="out\n", stderr="err\n")

    rc = cli.main(["exec", "--vm", "exec-vm", "cmd"])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == "out\n"
    assert captured.err == "err\n[exit code: 5]\n"


def test_text_mode_prints_nothing_for_a_silent_successful_command(wired, capsys):
    """`qmu exec true` used to print `[exit code: 0]`; byte-exact means empty."""
    wired(rc=0)

    rc = cli.main(["exec", "--vm", "exec-vm", "true"])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err == ""


def test_text_mode_guest_stdout_is_not_stripped_or_decorated(wired, capsys):
    wired(rc=0, stdout="a\n\n  b  \n\n")

    cli.main(["exec", "--vm", "exec-vm", "cmd"])

    assert capsys.readouterr().out == "a\n\n  b  \n\n"


def test_json_mode_is_unchanged_by_the_stream_split(wired, capsys):
    wired(rc=5, stdout="out\n", stderr="err\n")

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "cmd"])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["stdout"] == "out\n"
    assert payload["stderr"] == "err\n"
    assert payload["exit_code"] == 5
    assert payload["vm_id"] == "exec-vm"


# --- the serial watcher -----------------------------------------------------


def test_a_panic_during_the_command_aborts_it_into_the_crash_path(wired, capsys):
    """The predicate sees the panic appended after the command started and the
    abort is reported as exit 3 with the report and the partial output —
    without waiting for ssh's keepalive (measured 20–50 s before)."""
    fake = wired(stdout="pre\n", append_during_run=PANIC)

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "trigger"])

    assert rc == 3
    assert fake.predicate_answers == [True]
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert payload["ssh_error"] is True
    assert "Kernel panic - not syncing" in payload["crash"]
    assert payload["exit_code"] is None
    assert payload["stdout"] == "pre\n"
    assert payload["vm_id"] == "exec-vm"


def test_the_watcher_ignores_a_panic_from_before_the_command(wired):
    """Scope is the command: a report already in the log must not abort a
    healthy command (it is the `_explain_lost_transport` scoping, applied to
    the watcher too)."""
    fake = wired(initial_serial=PANIC, rc=0, stdout="fine\n")

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "true"])

    assert rc == 0
    assert fake.predicate_answers == [False]


def test_abort_text_mode_leads_with_partial_stdout_then_the_report(wired, capsys):
    wired(stdout="step 1\nstep 2\n", stderr="warn\n", append_during_run=PANIC)

    rc = cli.main(["exec", "--vm", "exec-vm", "trigger"])

    captured = capsys.readouterr()
    assert rc == 3
    assert captured.out.startswith("step 1\nstep 2\nSSH connection lost while running: trigger\n")
    assert "Kernel panic - not syncing" in captured.out
    assert captured.err == "warn\n"


@pytest.mark.parametrize("command", ["compile", "dmesg"])
def test_compile_run_and_dmesg_are_watched_too(wired, tmp_path, capsys, command):
    fake = wired(append_during_run=PANIC)
    if command == "compile":
        source = tmp_path / "x.c"
        source.write_text("int main(void){return 0;}\n")
        # First run() is the guest compile (no watcher); the second is the
        # executable, which the panic lands under.
        fake._append, pending = "", PANIC
        original = fake.run

        def run(cmd, *a, **kw):
            nonlocal pending
            if cmd.startswith("/root/x"):
                fake._append, pending = pending, ""
            return original(cmd, *a, **kw)

        fake.run = run
        argv = ["--format", "json", "compile", "--vm", "exec-vm", str(source), "--run"]
    else:
        argv = ["--format", "json", "dmesg", "--vm", "exec-vm"]

    rc = cli.main(argv)

    assert rc == 3
    assert fake.predicate_answers[-1] is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert payload["vm_id"] == "exec-vm"


# --- the watcher also sees a halted vCPU -----------------------------------


def _halt_qmp(monkeypatch, running_polls: int = 0):
    """QMP reports a halted vCPU (`debug`) — a breakpoint fired mid-command —
    after answering "running" to the first `running_polls` queries. The clock
    jumps past the 1 s QMP cadence on every read so the predicate consults
    QMP on its first poll."""
    calls: list[str] = []

    def stopped(inst):
        calls.append(inst.vm_id)
        return None if len(calls) <= running_polls else "debug"

    monkeypatch.setattr(guest, "_qmp_stopped_status", stopped)
    clock = [1000.0]

    def monotonic():
        clock[0] += 2.0
        return clock[0]

    monkeypatch.setattr(guest.time, "monotonic", monotonic)
    return calls


def test_a_breakpoint_halting_the_vcpu_aborts_exec_into_the_paused_envelope(
    wired, monkeypatch, capsys
):
    """No serial output accompanies a halted vCPU, so the serial-only watcher
    let ssh run to its keepalive window: `exec uname -r` against an armed
    `__x64_sys_newuname` took 20 s to report `is debug`. QMP is polled too,
    and the abort renders the preflight's paused envelope (exit 1, never the
    crash/transport class)."""
    fake = wired(stdout="partial\n")
    _halt_qmp(monkeypatch)

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "uname -r"])

    assert rc == 1
    assert fake.predicate_answers == [True]
    payload = json.loads(capsys.readouterr().out)
    assert payload["guest_state"] == "paused"
    assert payload["qemu_status"] == "debug"
    assert payload["crash_detected"] is False
    assert payload["ssh_error"] is False
    assert payload["exit_code"] is None
    assert payload["stdout"] == "partial\n"
    assert "qmu cont --vm exec-vm" in payload["hint"]


def test_the_watcher_does_not_ask_qmp_before_its_cadence(wired, monkeypatch):
    """QMP is best-effort and rate-limited: a predicate poll inside the first
    second reads the serial log only, so a busy socket never slows the
    common path."""
    calls: list[str] = []
    monkeypatch.setattr(
        guest, "_qmp_stopped_status", lambda inst: calls.append(inst.vm_id) or "debug"
    )
    fake = wired(stdout="ok\n")

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "true"])

    assert rc == 0
    assert fake.predicate_answers == [False]
    assert calls == []


@pytest.mark.parametrize("command", ["compile", "dmesg"])
def test_compile_run_and_dmesg_abort_on_a_halted_vcpu_too(
    wired, monkeypatch, tmp_path, capsys, command
):
    fake = wired(stdout="partial\n")
    # The guest compile step is watched too; halt only once the binary runs.
    _halt_qmp(monkeypatch, running_polls=1 if command == "compile" else 0)
    if command == "compile":
        source = tmp_path / "x.c"
        source.write_text("int main(void){return 0;}\n")
        argv = ["--format", "json", "compile", "--vm", "exec-vm", str(source), "--run"]
    else:
        argv = ["--format", "json", "dmesg", "--vm", "exec-vm"]

    rc = cli.main(argv)

    assert rc == 1
    assert fake.predicate_answers[-1] is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["guest_state"] == "paused"
    assert payload["qemu_status"] == "debug"
    assert payload["crash_detected"] is False
    assert "qmu cont --vm exec-vm" in payload["hint"]
    assert payload["vm_id"] == "exec-vm"
    if command == "compile":
        assert payload["compiled"] is True
        assert payload["run_exit"] is None
        assert payload["run_stdout"] == "partial\n"


def test_the_guest_compile_step_is_watched_too(wired, monkeypatch, tmp_path, capsys):
    """A breakpoint on a syscall the login shell makes (`uname`) halts the
    vCPU under gcc; the unwatched 30 s compile budget then expired into a bare
    infra error (exit 4) with no mention of the debugger."""
    fake = wired()
    calls = _halt_qmp(monkeypatch)
    source = tmp_path / "x.c"
    source.write_text("int main(void){return 0;}\n")

    rc = cli.main(["--format", "json", "compile", "--vm", "exec-vm", str(source), "--run"])

    assert rc == 1
    assert fake.predicate_answers == [True]
    assert [cmd.startswith("gcc") for cmd in fake.runs] == [True]
    assert calls  # QMP was consulted
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["guest_state"] == "paused"
    assert payload["qemu_status"] == "debug"
    assert payload["command"].startswith("gcc")
    assert "compiled" not in payload


# --- --timeout keeps partial output -----------------------------------------


def test_timeout_payload_carries_the_partial_output(wired, capsys):
    wired(raises=SSHError(
        "SSH command timed out after 2.0s: echo partial; sleep 10",
        stdout="partial\n",
        stderr="",
    ))

    rc = cli.main([
        "--format", "json", "exec", "--vm", "exec-vm", "--timeout", "2",
        "echo partial; sleep 10",
    ])

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert payload["timed_out"] is True
    assert payload["exit_code"] is None
    assert payload["stdout"] == "partial\n"
    assert payload["stderr"] == ""
    assert payload["vm_id"] == "exec-vm"


def test_timeout_text_mode_prints_partial_stdout_then_the_notice(wired, capsys):
    wired(raises=SSHError("SSH command timed out after 2.0s: cmd", stdout="partial\n"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--timeout", "2", "cmd"])

    captured = capsys.readouterr()
    assert rc == 124
    assert captured.out.startswith("partial\nGuest command timed out after 2s")


# --- envelope key consistency -----------------------------------------------


def _exec_argv(cmd):
    return ["--format", "json", cmd, "--vm", "exec-vm"]


@pytest.mark.parametrize(
    "scenario",
    ["exec-ok", "exec-nonzero", "exec-panic", "exec-timeout",
     "dmesg-ok", "dmesg-nonzero", "dmesg-panic",
     "compile-ok", "compile-fail", "compile-run-ok", "compile-run-nonzero",
     "push-ok", "pull-ok"],
)
def test_every_guest_command_envelope_carries_vm_id(wired, tmp_path, capsys, scenario):
    """Success and failure paths alike: a caller correlating envelopes with
    VMs reads one key on every one of them (`vm` was never emitted by these
    commands, so there is no duplicate to keep)."""
    command, _, outcome = scenario.partition("-")
    kw = {}
    if outcome.startswith("nonzero") or outcome == "fail":
        kw = {"rc": 7, "stderr": "boom\n"}
    elif outcome == "panic":
        kw = {"append_during_run": PANIC}
    elif outcome == "timeout":
        kw = {"raises": SSHError("timed out", stdout="p\n")}
    if outcome == "run" or outcome.startswith("run-"):
        # compile --run: compile succeeds (first run), the executable's result
        # is the scenario's.
        results = iter([(0, "", ""), (7 if outcome.endswith("nonzero") else 0, "out\n", "")])
        fake = wired()
        fake.run = lambda cmd, *a, **k: (fake.runs.append(cmd), next(results))[1]
    else:
        fake = wired(**kw)

    if command == "exec":
        argv = [*_exec_argv("exec"), "cmd"]
    elif command == "dmesg":
        argv = _exec_argv("dmesg")
    elif command == "compile":
        source = tmp_path / "x.c"
        source.write_text("int main(void){return 0;}\n")
        argv = [*_exec_argv("compile"), str(source)]
        if outcome.startswith("run"):
            argv.append("--run")
    elif command == "push":
        local = tmp_path / "payload.bin"
        local.write_bytes(b"x")
        argv = [*_exec_argv("push"), str(local), "/root/"]
    else:
        argv = [*_exec_argv("pull"), "/root/payload.bin", str(tmp_path)]

    cli.main(argv)

    payload = json.loads(capsys.readouterr().out)
    assert payload["vm_id"] == "exec-vm", scenario
    assert "vm" not in payload, scenario


# --- reaping an in-process QEMU child ---------------------------------------


def test_wait_pid_exit_reaps_an_exited_child_instead_of_waiting_on_its_zombie():
    """`qmu run` launches QEMU in-process, so after `quit` the pid is a zombie
    child: `kill(pid, 0)` keeps succeeding and every escalation step burned
    its full budget (2 s per run). The poll loop must reap it."""
    child = subprocess.Popen(["sleep", "60"])
    os.kill(child.pid, signal.SIGKILL)
    time.sleep(0.1)  # let the kernel turn it into a zombie

    started = time.monotonic()
    assert _wait_pid_exit(child.pid, timeout=1.0) is True
    assert time.monotonic() - started < 0.5


def test_wait_pid_exit_on_a_foreign_pid_still_times_out_only_while_alive():
    """A live pid that is not our child (`waitpid` → `ChildProcessError`) is
    handled like before: the budget elapses and the pid is reported alive."""
    assert _wait_pid_exit(os.getppid(), timeout=0.1) is False
