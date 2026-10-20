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
import sys
import time
from pathlib import Path

import pytest

from qmu import cli
from qmu._cliutil import _wait_pid_exit
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.ssh import GuestText, SSHAborted, SSHError

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


def test_text_mode_stdout_is_the_guest_bytes_with_no_added_newline(wired, capsysbinary):
    """`qmu run -- 'printf x' | od` measured `78 0a` and `printf '\\377'`
    measured `ef bf bd 0a` against the help text's "byte for byte": the text
    renderer decoded and line-terminated the guest's output. The guest's
    bytes reach stdout untouched; the lossy decode is for JSON only."""
    wired(rc=0, stdout=GuestText(b"x"))

    rc = cli.main(["exec", "--vm", "exec-vm", "printf x"])

    assert rc == 0
    assert capsysbinary.readouterr().out == b"x"


def test_text_mode_delivers_non_utf8_stdout_and_stderr_verbatim(wired, capsysbinary):
    wired(rc=3, stdout=GuestText(b"\xff\xfe\x80leak"), stderr=GuestText(b"\xffwarn"))

    rc = cli.main(["exec", "--vm", "exec-vm", "./leak"])

    captured = capsysbinary.readouterr()
    assert rc == 1
    assert captured.out == b"\xff\xfe\x80leak"
    # guest stderr verbatim; qmu's trailer starts on its own line after it
    assert captured.err == b"\xffwarn\n[exit code: 3]\n"


def test_json_marks_a_lossy_decode_and_keeps_the_replacement_string(wired, capsys):
    wired(rc=0, stdout=GuestText(b"\xffabc\n"), stderr=GuestText(b"ok\n"))

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "cmd"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stdout"] == "\ufffdabc\n"
    assert payload["stdout_lossy"] is True
    assert "stderr_lossy" not in payload


def test_json_has_no_lossy_flag_for_clean_output(wired, capsys):
    wired(rc=0, stdout=GuestText("caf\u00e9\n".encode()))

    cli.main(["--format", "json", "exec", "--vm", "exec-vm", "cmd"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["stdout"] == "caf\u00e9\n"
    assert "stdout_lossy" not in payload


def test_lost_transport_text_keeps_stdout_to_the_exact_guest_bytes(wired, capsysbinary):
    """The partial output before a panic keeps its bytes, and stdout holds
    nothing else: the report goes to stderr (#172)."""
    wired(stdout=GuestText(b"\xff step"), append_during_run=PANIC)

    rc = cli.main(["exec", "--vm", "exec-vm", "trigger"])

    captured = capsysbinary.readouterr()
    assert rc == 3
    assert captured.out == b"\xff step"
    assert b"Kernel panic - not syncing" in captured.err


def test_text_out_file_holds_the_exact_stdout_bytes(wired, tmp_path, capsys):
    out = tmp_path / "stdout.bin"
    wired(rc=0, stdout=GuestText(b"\x00\xff no newline"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--out", str(out), "cmd"])

    assert rc == 0
    assert out.read_bytes() == b"\x00\xff no newline"
    pointer = capsys.readouterr().out
    assert pointer.startswith(f"[qmu] Output written to {out} (13 bytes")


def test_text_spill_preserves_the_bytes_in_the_artifact(
    wired, capsysbinary, monkeypatch, tmp_path
):
    """Streamed stdout cannot be sized before it is written: the first
    STREAM_SPILL_BYTES go by live, the rest is diverted to a spill file that
    holds the whole output, and the pointer + preview trailer close the
    stream (they used to open a buffered one)."""
    monkeypatch.setenv("QMU_TEMP_DIR", str(tmp_path / "rt"))
    body = b"\xff" + b"0" * 200_000
    wired(rc=0, stdout=GuestText(body))

    rc = cli.main(["exec", "--vm", "exec-vm", "cmd"])

    captured = capsysbinary.readouterr()
    assert rc == 0
    head = captured.out[: guest.STREAM_SPILL_BYTES]
    pointer, trailer = captured.out[guest.STREAM_SPILL_BYTES:].decode().splitlines()
    assert head == body[: guest.STREAM_SPILL_BYTES]
    assert pointer.startswith("[qmu] Output spilled to ")
    assert trailer.startswith(
        f"[qmu] Preview: first {guest.STREAM_SPILL_BYTES} of {len(body)} bytes"
    )
    artifact = pointer.split(" ")[4]
    assert artifact.endswith(".txt")
    with open(artifact, "rb") as stream:
        assert stream.read() == body


def test_failed_command_text_out_envelope_reports_the_failure(wired, tmp_path, capsys):
    """#108: `exec --out f 'printf nope; exit 7'` exited 1 but the pointer
    envelope said `ok: true` — the writer's own success leaked in as the
    operation's. The envelope carries the guest command's outcome and its
    exit code; the bytes are still delivered exactly."""
    out = tmp_path / "failed-stdout.bin"
    wired(rc=7, stdout=GuestText(b"nope"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--out", str(out), "printf nope; exit 7"])

    assert rc == 1
    assert out.read_bytes() == b"nope"
    pointer = capsys.readouterr().out
    assert pointer.startswith(f"[qmu] Output written to {out} (4 bytes")
    assert "exit 7" in pointer


def test_failed_command_json_out_envelope_reports_the_failure(wired, tmp_path, capsys):
    out = tmp_path / "failed.json"
    wired(rc=7, stdout=GuestText(b"nope"))

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "--out", str(out), "cmd"])

    assert rc == 1
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    payload = json.loads(out.read_text())
    assert payload["ok"] is False
    assert payload["exit_code"] == 7
    assert payload["stdout"] == "nope"


@pytest.mark.parametrize("timed_out, exit_class", [(False, 1), (True, 124)])
def test_a_spilled_failure_keeps_its_classification_on_the_pointer(
    wired, capsys, monkeypatch, tmp_path, timed_out, exit_class
):
    """#156: a failing exec whose envelope spilled printed only the artifact
    keys, so `exit 7` (1), a timeout (124) and a crash (3) were the same
    pointer and there was no `hint` to run. The pointer repeats the
    outcome keys the artifact holds; the bulky output stays in the file."""
    monkeypatch.setenv("QMU_TEMP_DIR", str(tmp_path / "rt"))
    big = "x" * 200_000
    if timed_out:
        wired(raises=SSHError(
            "SSH command timed out after 3.0s: cmd", stdout=big, stderr=""
        ))
    else:
        wired(rc=7, stdout=big)

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "cmd"])

    assert rc == exit_class
    pointer = json.loads(capsys.readouterr().out)
    stored = json.loads(Path(pointer["artifact_path"]).read_text())
    assert pointer["ok"] is False and "stdout" not in pointer
    for key in ("vm_id", "exit_code", "crash_detected", "ssh_error", "hint"):
        assert pointer[key] == stored[key], key
    assert pointer.get("timed_out") == stored.get("timed_out")
    assert pointer["hint"]


def test_failed_command_text_spill_keeps_the_bytes_and_the_failure(
    wired, capsysbinary, monkeypatch, tmp_path
):
    monkeypatch.setenv("QMU_TEMP_DIR", str(tmp_path / "rt"))
    body = b"\xff" + b"0" * 200_000
    wired(rc=7, stdout=GuestText(body))

    rc = cli.main(["exec", "--vm", "exec-vm", "cmd"])

    captured = capsysbinary.readouterr()
    assert rc == 1
    pointer = captured.out[guest.STREAM_SPILL_BYTES:].decode().splitlines()[0]
    assert pointer.startswith("[qmu] Output spilled to ")
    with open(pointer.split(" ")[4], "rb") as stream:
        assert stream.read() == body
    assert captured.err == b"[qmu] Output spilled to " + pointer.split(" ")[4].encode() + b"\n[exit code: 7]\n"


def test_successful_command_text_out_envelope_has_no_failure_marks(wired, tmp_path, capsys):
    out = tmp_path / "ok.bin"
    wired(rc=0, stdout=GuestText(b"fine"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--out", str(out), "cmd"])

    assert rc == 0
    assert capsys.readouterr().out == f"[qmu] Output written to {out} (4 bytes, exit 0)\n"


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


def test_abort_text_mode_puts_partial_stdout_on_stdout_and_the_report_on_stderr(
    wired, capsys
):
    wired(stdout="step 1\nstep 2\n", stderr="warn\n", append_during_run=PANIC)

    rc = cli.main(["exec", "--vm", "exec-vm", "trigger"])

    captured = capsys.readouterr()
    assert rc == 3
    assert captured.out == "step 1\nstep 2\n"
    assert captured.err.startswith("warn\n")
    assert "Kernel panic - not syncing" in captured.err


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


# --- a held QMP socket must not move the deadline ---------------------------


def _fake_ssh_on_path(tmp_path, monkeypatch, script: str):
    fake_ssh = tmp_path / "ssh"
    fake_ssh.write_text("#!/bin/sh\n" + script)
    fake_ssh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    from qmu.ssh import SSHClient

    return SSHClient(port=10022, key_path="/tmp/test-key")


def test_a_blocked_qmp_probe_does_not_defeat_the_command_deadline(
    tmp_path, monkeypatch
):
    """Measured with a sibling holding the QMP socket: `exec --timeout 2
    'sleep 2.5; printf done'` returned 0 after 3.1 s. The watcher's QMP
    probe ran synchronously inside the drain loop and sat out the 2 s
    greeting budget per cadence, so the loop neither drained nor enforced
    the deadline while blocked, and a child that finished meanwhile was
    accepted as completed. The probe is now off-thread with a bounded wait:
    the deadline holds — well before the >= 3 s a synchronous 2 s stall at
    the 1 s QMP cadence would take, with headroom for a loaded shared host —
    output seen before it is kept, and the busy socket is still treated as
    "running" (no spurious abort). The child sleeps past any such slack so
    its later output can never race the kill."""
    def held_qmp(inst):
        time.sleep(2.0)  # a QMPClient.connect() waiting out its greeting budget
        return None

    monkeypatch.setattr(guest, "_qmp_stopped_status", held_qmp)
    serial = tmp_path / "vm.serial.log"
    serial.write_text("boot ok\n")
    client = _fake_ssh_on_path(
        tmp_path, monkeypatch, "echo early\nsleep 4\nprintf done\n"
    )
    watcher = guest._guest_abort_watcher(_instance(str(serial)), start_offset=0)

    started = time.monotonic()
    with pytest.raises(SSHError) as excinfo:
        client.run("sleep 4; printf done", timeout=2.0, abort_when=watcher)
    elapsed = time.monotonic() - started

    assert not isinstance(excinfo.value, SSHAborted)
    assert elapsed < 2.75, elapsed
    assert excinfo.value.stdout == "early\n"


def test_a_slow_qmp_answer_is_still_read_on_a_later_tick(monkeypatch, tmp_path):
    """The bounded wait defers, it does not discard: a halt QMP reports after
    the first tick's budget is seen on a later tick, so the halted-vCPU
    abort still happens without a synchronous stall."""
    def slow_halt(inst):
        time.sleep(0.5)
        return "debug"

    monkeypatch.setattr(guest, "_qmp_stopped_status", slow_halt)
    serial = tmp_path / "vm.serial.log"
    serial.write_text("boot ok\n")
    watcher = guest._guest_abort_watcher(
        _instance(str(serial)), start_offset=0, qmp_interval=0.0
    )

    first = time.monotonic()
    answers = [watcher()]
    first_cost = time.monotonic() - first
    deadline = time.monotonic() + 3.0
    while not answers[-1] and time.monotonic() < deadline:
        time.sleep(0.1)
        answers.append(watcher())

    assert first_cost < 0.4, first_cost
    assert answers[0] is False and answers[-1] is True


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


def test_timeout_text_mode_prints_partial_stdout_and_the_notice_on_stderr(wired, capsys):
    """A pipeline reading guest stdout must not receive qmu's timeout
    narrative as if the guest had printed it (#172)."""
    wired(raises=SSHError("SSH command timed out after 2.0s: cmd", stdout="partial\n"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--timeout", "2", "cmd"])

    captured = capsys.readouterr()
    assert rc == 124
    assert captured.out == "partial\n"
    assert "timed out" in captured.err


@pytest.mark.parametrize("terminal", [True, False])
def test_notice_after_open_stdout_line_starts_a_fresh_terminal_line(
    wired, capsys, monkeypatch, terminal
):
    """Guest stdout that ends mid-line must not glue the stderr notice onto
    it on a terminal; piped stdout stays byte-exact either way."""
    monkeypatch.setattr(guest, "_stdout_is_terminal", lambda: terminal)
    wired(raises=SSHError("SSH command timed out after 2.0s: cmd", stdout="partial"))

    rc = cli.main(["exec", "--vm", "exec-vm", "--timeout", "2", "cmd"])

    captured = capsys.readouterr()
    assert rc == 124
    assert captured.out == "partial"
    assert captured.err.startswith("\nGuest command timed out" if terminal else "Guest command timed out")


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_compile_run_timeout_on_a_serving_guest_is_124_with_partial_output(
    wired, tmp_path, capsys, fmt
):
    """`compile ./slow.c --run --timeout 1` on a program that prints then
    sleeps measured 4 `ssh_error:true` ("VM unreachable") against a guest
    that answered the very next exec. `compile --run` kept its own copy of
    the lost-transport branch and never asked whether the guest still
    answers; it now takes exec's classification: 124, `timed_out`, the
    partial `run_stdout`, no crash claim."""
    fake = wired(ready=True)
    source = tmp_path / "slow.c"
    source.write_text("int main(void){return 0;}\n")
    original = fake.run

    def run(cmd, *a, **kw):
        if cmd.startswith("/root/slow"):
            fake.runs.append(cmd)
            raise SSHError(
                f"SSH command timed out after 1.0s: {cmd}", stdout="before-timeout\n"
            )
        return original(cmd, *a, **kw)

    fake.run = run

    rc = cli.main([
        "--format", fmt, "compile", "--vm", "exec-vm", str(source), "--run",
        "--timeout", "1",
    ])

    captured = capsys.readouterr()
    assert rc == 124
    assert fake.runs[-1] == "/root/slow"
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["compiled"] is True
        assert payload["timed_out"] is True
        assert payload["ssh_error"] is False
        assert payload["crash_detected"] is False
        assert payload["run_exit"] is None
        assert payload["run_stdout"] == "before-timeout\n"
        assert payload["timeout"] == 1.0
        assert "command" not in payload
    else:
        assert captured.out == "before-timeout\n"
        assert captured.err.startswith("Compiled and ran slow.c:\n")
        assert "timed out" in captured.err


def test_a_panic_under_the_guest_compile_step_is_the_crash_class(wired, tmp_path, capsys):
    """The gcc step is watched; its abort used to re-raise as a bare infra
    error unless QMP said halted. A terminal panic appended under gcc is the
    same exit 3 with the report every other watched step produces."""
    fake = wired(append_during_run=PANIC)
    source = tmp_path / "x.c"
    source.write_text("int main(void){return 0;}\n")

    rc = cli.main(["--format", "json", "compile", "--vm", "exec-vm", str(source), "--run"])

    assert rc == 3
    assert [cmd.startswith("gcc") for cmd in fake.runs] == [True]
    payload = json.loads(capsys.readouterr().out)
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "Kernel panic - not syncing" in payload["crash"]
    assert payload["command"].startswith("gcc")
    assert "compiled" not in payload


@pytest.mark.parametrize("failure", ["aborted", "timeout"])
def test_a_panic_under_the_source_push_is_the_crash_class(wired, tmp_path, capsys, failure):
    fake = wired()
    source = tmp_path / "x.c"
    source.write_text("int main(void){return 0;}\n")

    def push(local, remote, **kwargs):
        fake.pushes.append((local, remote))
        with open(fake._serial_path, "a") as stream:
            stream.write(PANIC)
        if failure == "aborted":
            assert kwargs["abort_when"]() is True
            raise SSHAborted(f"SCP push aborted by qmu: {local} -> {remote}")
        raise SSHError(f"SCP push timed out after 30s: {local} -> {remote}")

    fake.push = push

    rc = cli.main(["--format", "json", "compile", "--vm", "exec-vm", str(source)])

    assert rc == 3
    assert fake.runs == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert payload["operation"] == "push"
    assert payload["remote"] == "/root/x.c"


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


# --- streamed output (#71a) ---------------------------------------------------


class StreamingSSH(WatchedSSH):
    """A fake whose `run` relays `chunks` through `on_chunk` before returning
    (or aborting with) the joined output, the way the real client does."""

    def __init__(self, serial_path, *, chunks, **kw):
        super().__init__(serial_path, **kw)
        self._chunks = chunks
        self.chunk_order: list[tuple[str, bytes]] = []

    def run(self, command, timeout=30.0, check=False, **kwargs):
        on_chunk = kwargs.get("on_chunk")
        out, err = b"", b""
        for stream, data in self._chunks:
            if stream == "stdout":
                out += data
            else:
                err += data
            if on_chunk is not None:
                on_chunk(stream, data)
                self.chunk_order.append((stream, data))
        self._stdout, self._stderr = GuestText(out), GuestText(err)
        return super().run(command, timeout, check, **kwargs)


@pytest.fixture
def streaming(monkeypatch, tmp_path):
    serial = tmp_path / "exec-vm.serial.log"

    def install(chunks, *, initial_serial="boot ok\n", **ssh_kw):
        serial.write_text(initial_serial)
        inst = _instance(str(serial))
        fake = StreamingSSH(serial, chunks=chunks, **ssh_kw)
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda i: fake)
        monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
        monkeypatch.setattr(guest, "_require_running_vm", lambda vm, command: None)
        monkeypatch.setattr(guest.time, "sleep", lambda _: None)
        return fake

    return install


CHUNKS = [
    ("stdout", b"a\x00b"),
    ("stderr", b"warn"),
    ("stdout", b"\n2\n"),
]


def test_text_mode_streams_stdout_and_stderr_as_they_arrive(streaming, capsysbinary):
    """Chunks go to stdout/stderr in arrival order, byte for byte (`printf
    'a\\0b'` included); guest stderr is not repeated after the stream and the
    `[exit code: N]` trailer starts on a fresh line after it."""
    fake = streaming(CHUNKS, rc=3)
    snapshots: list[tuple[bytes, bytes]] = []
    original = fake.run

    def run(command, *a, **kw):
        on_chunk = kw["on_chunk"]

        def observe(stream, data):
            on_chunk(stream, data)
            snapshots.append(
                (sys.stdout.buffer.getvalue(), sys.stderr.buffer.getvalue())
            )

        kw["on_chunk"] = observe
        return original(command, *a, **kw)

    fake.run = run

    rc = cli.main(["exec", "--vm", "exec-vm", "cmd"])

    captured = capsysbinary.readouterr()
    assert rc == 1
    assert captured.out == b"a\x00b\n2\n"
    assert captured.err == b"warn\n[exit code: 3]\n"
    assert fake.chunk_order == CHUNKS
    # Each chunk was on its stream before the next one arrived.
    assert snapshots == [
        (b"a\x00b", b""),
        (b"a\x00b", b"warn"),
        (b"a\x00b\n2\n", b"warn"),
    ]


def test_text_mode_streamed_stdout_is_byte_identical_to_the_buffered_rendering(
    streaming, wired, capsysbinary
):
    body = b"\xff\x00 no newline \xfe"
    wired(rc=0, stdout=GuestText(body))
    cli.main(["exec", "--vm", "exec-vm", "cmd"])
    buffered = capsysbinary.readouterr().out

    streaming([("stdout", body[:5]), ("stdout", body[5:])], rc=0)
    rc = cli.main(["exec", "--vm", "exec-vm", "cmd"])

    assert rc == 0
    assert capsysbinary.readouterr().out == buffered == body


def test_ndjson_mode_emits_chunk_events_then_the_final_envelope(streaming, capsys):
    streaming(CHUNKS, rc=0)

    rc = cli.main(["--format", "ndjson", "exec", "--vm", "exec-vm", "cmd"])

    assert rc == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    events, envelope = lines[:-1], lines[-1]
    assert events == [
        {"event": "chunk", "stream": "stdout", "data": "a\x00b"},
        {"event": "chunk", "stream": "stderr", "data": "warn"},
        {"event": "chunk", "stream": "stdout", "data": "\n2\n"},
    ]
    assert all("ok" not in event for event in events)
    assert envelope["ok"] is True
    assert "event" not in envelope
    assert envelope["stdout"] == "a\x00b\n2\n"
    assert envelope["stderr"] == "warn"


def test_ndjson_chunk_data_round_trips_undecodable_bytes_with_surrogateescape(
    streaming, capsys
):
    streaming([("stdout", b"\xff\xfe")], rc=0)

    cli.main(["--format", "ndjson", "exec", "--vm", "exec-vm", "cmd"])

    event = json.loads(capsys.readouterr().out.splitlines()[0])
    assert event["data"].encode("utf-8", errors="surrogateescape") == b"\xff\xfe"


def test_json_mode_buffers_the_envelope_with_no_chunk_lines(streaming, capsys):
    streaming(CHUNKS, rc=0)

    cli.main(["--format", "json", "exec", "--vm", "exec-vm", "cmd"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["stdout"] == "a\x00b\n2\n"


def test_text_out_streams_into_the_file_and_points_at_it_last(
    streaming, tmp_path, capsysbinary
):
    out = tmp_path / "streamed.bin"
    fake = streaming([("stdout", b"first"), ("stdout", b" second")], rc=0)
    sizes: list[int] = []
    original = fake.run

    def run(command, *a, **kw):
        on_chunk = kw["on_chunk"]

        def observe(stream, data):
            on_chunk(stream, data)
            sizes.append(out.stat().st_size)

        kw["on_chunk"] = observe
        return original(command, *a, **kw)

    fake.run = run

    rc = cli.main(["exec", "--vm", "exec-vm", "--out", str(out), "cmd"])

    assert rc == 0
    assert sizes == [5, 12]  # each chunk was on disk before the next arrived
    assert out.read_bytes() == b"first second"
    assert capsysbinary.readouterr().out == (
        f"[qmu] Output written to {out} (12 bytes, exit 0)\n".encode()
    )


def test_a_panic_mid_stream_keeps_the_delivered_lines_and_exits_3(
    streaming, capsysbinary
):
    """What was already on stdout stays and stdout holds nothing else; the
    crash report goes to stderr (exit 3), and nothing is printed twice."""
    fake = streaming([("stdout", b"line 1\n")], append_during_run=PANIC)

    rc = cli.main(["exec", "--vm", "exec-vm", "trigger"])

    captured = capsysbinary.readouterr()
    assert rc == 3
    assert fake.predicate_answers == [True]
    assert captured.out == b"line 1\n"
    assert b"Kernel panic - not syncing" in captured.err


# --- ssh that never reached the guest (#177) -----------------------------------


@pytest.mark.parametrize(
    "stdout, stderr, expected_rc",
    [
        ("", "Connection timed out during banner exchange\r\n", 4),
        ("", "kex_exchange_identification: read: Connection reset by peer\r\n", 4),
        ("", "ssh: connect to host localhost port 10021: Connection refused\r\n", 4),
        # Guest output alongside ssh-like words: the session ran the command,
        # which exited 255 itself.
        ("", "Connection timed out during banner exchange\nretry failed\n", 1),
        ("partial\n", "Connection timed out during banner exchange\r\n", 1),
    ],
)
def test_a_session_that_never_connected_is_transport_class_whatever_the_probe_says(
    wired, capsys, stdout, stderr, expected_rc
):
    """ssh's own pre-session failure means the command never ran: exit 4,
    `exit_code: null`, even when sshd is up by the time qmu would re-probe.
    It used to be "the guest command exited 255" (exit 1) whenever sshd won
    that race — right after `launch --no-wait-ssh` or a reboot."""
    wired(rc=255, stdout=stdout, stderr=stderr, ready=True)

    rc = cli.main(["--format", "json", "exec", "--vm", "exec-vm", "true"])

    payload = json.loads(capsys.readouterr().out)
    assert rc == expected_rc
    assert payload["ok"] is False
    if expected_rc == 4:
        assert payload["exit_code"] is None
        assert payload["ssh_error"] is True
        assert "qmu log --vm exec-vm --tail 100" in payload["hint"]
    else:
        assert payload["exit_code"] == 255
        assert payload["ssh_error"] is False
