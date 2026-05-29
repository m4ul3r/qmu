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
from qmu.instance import VMInstance


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
    """Stand-in for cli._make_ssh's SSHClient.

    run() always returns the supplied (rc, stdout, stderr); is_ready() returns
    the supplied liveness verdict. Both calls are recorded so a test can assert
    the liveness probe actually fired on the rc=255 path.
    """

    def __init__(self, *, rc: int, stdout: str, stderr: str, ready: bool):
        self._rc = rc
        self._stdout = stdout
        self._stderr = stderr
        self._ready = ready
        self.run_calls: list[str] = []
        self.is_ready_calls: int = 0

    def run(self, command, timeout=30.0, check=False):
        self.run_calls.append(command)
        return self._rc, self._stdout, self._stderr

    def is_ready(self, timeout: int = 2) -> bool:
        self.is_ready_calls += 1
        return self._ready


@pytest.fixture
def patch_exec(monkeypatch, tmp_path):
    """Wire choose_instance + _make_ssh so `qmu exec` runs without a real VM.

    Returns a function: install(rc, ready, *, crash_text=None, serial_present)
    -> the FakeSSH, after writing/omitting a serial log so extract_crash() has a
    real file (or not) to read on the crash path.
    """
    def install(rc, ready, *, crash_text=None, serial_present=True):
        serial = tmp_path / "crash-vm.serial.log"
        if serial_present:
            serial.write_text(crash_text or "boot ok\n")
        inst = _fake_instance(str(serial))
        fake = FakeSSH(rc=rc, stdout="", stderr="", ready=ready)
        monkeypatch.setattr(cli, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(cli, "_make_ssh", lambda i: fake)
        return fake

    return install


# A realistic kernel-panic banner that cli.extract_crash() will detect in the
# serial log, so crash_detected can be asserted True on the SSH-lost path.
PANIC_LOG = (
    "[    3.111] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[    3.112] Kernel panic - not syncing: Fatal exception\n"
    "[    3.113] RIP: 0010:do_the_bad_thing+0x40/0x80\n"
)


def test_rc255_ssh_down_is_crash_exit3_json(patch_exec, capsys):
    """rc=255 AND is_ready()==False -> SSH-lost / probable crash -> exit 3.

    Under --format json the result envelope must carry ssh_error=True and
    crash_detected=True (a panic is present in the serial log)."""
    fake = patch_exec(255, ready=False, crash_text=PANIC_LOG)

    rc = cli.main(["--format", "json", "exec", "trigger"])

    assert rc == 3
    # The liveness probe MUST have fired to disambiguate rc=255.
    assert fake.is_ready_calls >= 1
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert payload["crash"] is not None
    assert "panic" in payload["crash"].lower()


def test_rc255_ssh_down_no_crash_in_log_still_exit3(patch_exec, capsys):
    """SSH lost but no panic markers in the log: still the crash/SSH-lost path
    (exit 3), but crash_detected=False so the agent knows to look elsewhere."""
    fake = patch_exec(255, ready=False, crash_text="ordinary boot log, no panic\n")

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
    fake = patch_exec(255, ready=True, crash_text=PANIC_LOG)

    rc = cli.main(["--format", "json", "exec", "exit 255"])

    assert rc == 1
    # is_ready() must still be consulted to rule out a transport loss.
    assert fake.is_ready_calls >= 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 255
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False


def test_rc255_ssh_down_text_mode_reports_crash(patch_exec, capsys):
    """Text mode for the crash path: exit 3 and the crash report is rendered."""
    patch_exec(255, ready=False, crash_text=PANIC_LOG)

    rc = cli.main(["exec", "trigger"])

    assert rc == 3
    out = capsys.readouterr().out
    assert "SSH connection lost" in out
    assert "panic" in out.lower()
