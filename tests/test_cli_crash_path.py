"""CORR-2: the PRODUCTION crash-disambiguation path in `qmu exec`.

test_cli_crash.py covers the standalone `qmu.ssh.is_transport_failure` helper,
but the CLI never calls it. The real production path (cli._handle_exec) decides
"kernel crashed vs. guest legitimately exited 255" with:

    if rc == 255 and not ssh.is_ready(...):   # -> crash / SSH-lost (exit 3)
    else:                                       # -> normal rc=255 (exit 1)

These tests drive that production seam directly via `cli.main(["exec", ...])`
with NO VM, by:

  * monkeypatching cli.choose_instance -> a fake NON-harness VMInstance (so the
    _require_ssh gate passes and exec proceeds), and
  * monkeypatching cli._make_ssh -> a FakeSSH whose run() returns (255, "", "")
    and whose is_ready() returns a controllable bool.

This pins the contract from the task's EXIT CODE map:
  * rc==255 + is_ready()==False  -> SSH-lost / probable crash -> exit 3,
    JSON envelope carries ssh_error=True and crash_detected wired to whether a
    crash report was extracted from the serial log.
  * rc==255 + is_ready()==True   -> the guest genuinely returned 255 -> exit 1,
    NOT a crash (ssh_error=False, crash_detected=False).

Findings exercised: CORR-2 / H1 (production path).
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.ssh import SSHError


def _fake_instance(serial_log: str) -> VMInstance:
    """A minimal NON-harness, SSH-capable instance so cli._require_ssh passes."""
    return VMInstance(
        vm_id="crash-vm",
        pid=4242,
        qmp_socket="/tmp/crash-vm.qmp.sock",
        ssh_port=10099,
        ssh_key="/tmp/crash-vm.key",
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


class FakeSSH:
    """Stand-in for the SSH client with serial output synchronized to run()."""

    def __init__(
        self,
        *,
        rc: int,
        stdout: str,
        stderr: str,
        ready: bool,
        serial_path,
        serial_during_run: str,
        run_error: SSHError | None = None,
    ):
        self._rc = rc
        self._stdout = stdout
        self._stderr = stderr
        self._ready = ready
        self._serial_path = serial_path
        self._serial_during_run = serial_during_run
        self._run_error = run_error
        self.run_calls: list[str] = []
        self.is_ready_calls: int = 0

    def run(self, command, timeout=30.0, check=False):
        self.run_calls.append(command)
        if self._serial_during_run:
            with self._serial_path.open("a") as stream:
                stream.write(self._serial_during_run)
            self._serial_during_run = ""
        if self._run_error is not None:
            raise self._run_error
        return self._rc, self._stdout, self._stderr

    def is_ready(self, timeout: int = 2) -> bool:
        self.is_ready_calls += 1
        return self._ready


@pytest.fixture
def patch_exec(monkeypatch, tmp_path):
    """Wire exec with serial bytes written before and during the SSH command."""
    def install(
        rc,
        ready,
        *,
        initial_serial="boot ok\n",
        serial_during_run="",
        run_error=None,
        stdout="",
        stderr="",
    ):
        serial = tmp_path / "crash-vm.serial.log"
        serial.write_text(initial_serial)
        inst = _fake_instance(str(serial))
        fake = FakeSSH(
            rc=rc,
            stdout=stdout,
            stderr=stderr,
            ready=ready,
            serial_path=serial,
            serial_during_run=serial_during_run,
            run_error=run_error,
        )
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda i: fake)
        monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
        monkeypatch.setattr(guest.time, "sleep", lambda _: None)
        return fake

    return install


# A realistic kernel-panic banner that cli.extract_crash() will detect in the
# serial log, so crash_detected can be asserted True on the SSH-lost path.
PANIC_LOG = (
    "[    3.111] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[    3.112] Kernel panic - not syncing: Fatal exception\n"
    "[    3.113] RIP: 0010:do_the_bad_thing+0x40/0x80\n"
)


def test_rc255_ssh_down_reports_crash_appended_during_command(patch_exec, capsys):
    fake = patch_exec(
        255,
        ready=False,
        initial_serial="old boot\n",
        serial_during_run=PANIC_LOG,
    )
    rc = cli.main(["--format", "json", "exec", "trigger"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert fake.is_ready_calls >= 1
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "panic" in payload["crash"].lower()


def test_rc255_ssh_down_ignores_precommand_crash(patch_exec, capsys):
    patch_exec(255, ready=False, initial_serial=PANIC_LOG, serial_during_run="")
    rc = cli.main(["--format", "json", "exec", "trigger"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None
    assert "unreachable" in payload["hint"].lower()


def test_exec_timeout_ignores_precommand_crash(patch_exec, capsys):
    patch_exec(
        255,
        ready=False,
        initial_serial=PANIC_LOG,
        run_error=SSHError("command timed out"),
    )
    rc = cli.main(["--format", "json", "exec", "trigger"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None


def test_rc255_ssh_down_no_crash_in_log_still_exit3(patch_exec, capsys):
    """SSH lost but no panic markers in the log: still the crash/SSH-lost path
    (exit 3), but crash_detected=False so the agent knows to look elsewhere."""
    fake = patch_exec(255, ready=False, initial_serial="ordinary boot log\n")

    rc = cli.main(["--format", "json", "exec", "trigger"])

    assert rc == 3
    assert fake.is_ready_calls >= 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None


def test_rc255_ssh_up_is_normal_nonzero_exit1(patch_exec, capsys):
    """rc=255 AND is_ready()==True -> the guest legitimately returned 255.

    This is the NO-false-positive case: exit 1 (ordinary non-zero), NOT a crash.
    The JSON envelope must report ssh_error=False / crash_detected=False and
    surface the actual exit_code 255."""
    fake = patch_exec(255, ready=True, initial_serial=PANIC_LOG)

    rc = cli.main(["--format", "json", "exec", "exit 255"])

    assert rc == 1
    # is_ready() must still be consulted to rule out a transport loss.
    assert fake.is_ready_calls >= 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 255
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert payload["kernel_warning_detected"] is False
    assert payload["kernel_warning"] is None


def test_rc255_ssh_down_text_mode_reports_crash(patch_exec, capsys):
    """Text mode for the crash path: exit 3 and the crash report is rendered."""
    patch_exec(
        255,
        ready=False,
        initial_serial="old boot\n",
        serial_during_run=PANIC_LOG,
    )

    rc = cli.main(["exec", "trigger"])

    assert rc == 3
    out = capsys.readouterr().out
    assert "SSH connection lost" in out
    assert "panic" in out.lower()



REPORT_KASAN = (
    "[   10.000] BUG: KASAN: slab-out-of-bounds in report_bug+0x1/0x2\n"
    "[   10.001] Call Trace:\n"
    "[   10.002]  report_bug+0x1/0x2\n"
    "[   10.003] ---[ end trace 2222222222222222 ]---\n"
)


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_exec_report_mode_kasan_success_is_nonfatal_warning(patch_exec, capsys, fmt):
    patch_exec(
        0,
        ready=True,
        initial_serial="boot ok\n",
        serial_during_run=REPORT_KASAN,
        stdout="STILL_ALIVE\n",
        stderr="",
    )
    rc = cli.main(["--format", fmt, "exec", "modprobe", "kasan_test"])
    out = capsys.readouterr().out
    if fmt == "ndjson":
        assert len(out.splitlines()) == 1
    payload = json.loads(out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert payload["kernel_warning_detected"] is True
    assert "BUG: KASAN" in payload["kernel_warning"]
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False


def test_exec_report_mode_kasan_text_warns_without_failing(patch_exec, capsys):
    patch_exec(
        0,
        ready=True,
        initial_serial="boot ok\n",
        serial_during_run=REPORT_KASAN,
        stdout="STILL_ALIVE\n",
        stderr="",
    )
    rc = cli.main(["exec", "modprobe", "kasan_test"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "STILL_ALIVE" in out
    assert "Kernel warning from command serial output:" in out
    assert "BUG: KASAN" in out


def test_exec_clean_success_has_stable_empty_warning_fields(patch_exec, capsys):
    patch_exec(
        0,
        ready=True,
        initial_serial="boot ok\n",
        serial_during_run="ordinary serial chatter\n",
        stdout="ok\n",
        stderr="",
    )
    rc = cli.main(["--format", "json", "exec", "true"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["kernel_warning_detected"] is False
    assert payload["kernel_warning"] is None


def test_exec_guest_nonzero_with_warning_preserves_remote_authority(patch_exec, capsys):
    patch_exec(
        7,
        ready=True,
        initial_serial="boot ok\n",
        serial_during_run=REPORT_KASAN,
        stdout="",
        stderr="guest failed\n",
    )
    rc = cli.main(["--format", "json", "exec", "false"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert payload["exit_code"] == 7
    assert payload["kernel_warning_detected"] is True
    assert "BUG: KASAN" in payload["kernel_warning"]
    assert payload["ssh_error"] is False

    # text path
    patch_exec(
        7,
        ready=True,
        initial_serial="boot ok\n",
        serial_during_run=REPORT_KASAN,
        stdout="",
        stderr="guest failed\n",
    )
    rc = cli.main(["exec", "false"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "[exit code: 7]" in out


def test_exec_transport_loss_with_fresh_crash_is_exit3_json(patch_exec, capsys):
    patch_exec(
        255,
        ready=False,
        initial_serial="boot ok\n",
        serial_during_run=PANIC_LOG,
    )
    rc = cli.main(["--format", "json", "exec", "trigger"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "panic" in payload["crash"].lower()
    assert "boot ok" not in (payload["crash"] or "")


def test_exec_transport_loss_ignores_stale_precommand_crash(patch_exec, capsys):
    patch_exec(255, ready=False, initial_serial=PANIC_LOG, serial_during_run="")
    rc = cli.main(["--format", "json", "exec", "trigger"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 3
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None


def test_exec_json_ndjson_status_parity(patch_exec, capsys):
    scenarios = [
        ("clean", 0, True, "boot ok\n", "ordinary chatter\n", "ok\n", "", 0),
        ("warning", 0, True, "boot ok\n", REPORT_KASAN, "STILL_ALIVE\n", "", 0),
        ("guest_nonzero", 7, True, "boot ok\n", "", "", "guest failed\n", 1),
        ("fatal", 255, False, "boot ok\n", PANIC_LOG, "", "", 3),
    ]
    for name, guest_rc, ready, initial, during, stdout, stderr, expected_qmu in scenarios:
        payloads = {}
        rcs = {}
        for fmt in ("json", "ndjson"):
            patch_exec(
                guest_rc,
                ready=ready,
                initial_serial=initial,
                serial_during_run=during,
                stdout=stdout,
                stderr=stderr,
            )
            rcs[fmt] = cli.main(["--format", fmt, "exec", "cmd"])
            out = capsys.readouterr().out
            if fmt == "ndjson":
                assert len(out.splitlines()) == 1, name
            payloads[fmt] = json.loads(out)
            assert rcs[fmt] == expected_qmu, name
            assert (rcs[fmt] == 0) is payloads[fmt]["ok"], name
        assert payloads["json"] == payloads["ndjson"], name
        assert rcs["json"] == rcs["ndjson"], name


class FakeCompileSSH:
    def __init__(self, serial_path, serial_during_run):
        self._serial_path = serial_path
        self._serial_during_run = serial_during_run
        self._run_count = 0

    def push(self, local, remote):
        pass

    def run(self, command, timeout=30.0, check=False):
        self._run_count += 1
        if self._run_count == 1:
            return 0, "", ""
        if self._serial_during_run:
            with self._serial_path.open("a") as stream:
                stream.write(self._serial_during_run)
            self._serial_during_run = ""
        return 255, "", ""

    def is_ready(self, timeout=2):
        return False


def _run_compile_crash_case(
    monkeypatch, tmp_path, capsys, *, initial_serial, serial_during_run
):
    source = tmp_path / "poc.c"
    source.write_text("int main(void) { return 0; }\n")
    serial = tmp_path / "compile.serial.log"
    serial.write_text(initial_serial)
    inst = _fake_instance(str(serial))
    fake = FakeCompileSSH(serial, serial_during_run)
    monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest, "_make_ssh", lambda selected: fake)
    monkeypatch.setattr(guest.time, "sleep", lambda _: None)

    rc = cli.main(["--format", "json", "compile", str(source), "--run"])
    return rc, json.loads(capsys.readouterr().out)


def test_compile_run_ignores_precommand_crash(monkeypatch, tmp_path, capsys):
    rc, payload = _run_compile_crash_case(
        monkeypatch,
        tmp_path,
        capsys,
        initial_serial=PANIC_LOG,
        serial_during_run="",
    )
    assert rc == 3
    assert payload["crash_detected"] is False
    assert payload["crash"] is None


def test_compile_run_reports_crash_appended_during_executable(
    monkeypatch, tmp_path, capsys
):
    rc, payload = _run_compile_crash_case(
        monkeypatch,
        tmp_path,
        capsys,
        initial_serial="old boot\n",
        serial_during_run=PANIC_LOG,
    )
    assert rc == 3
    assert payload["crash_detected"] is True
    assert "panic" in payload["crash"].lower()
