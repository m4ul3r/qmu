"""Bare `qmu wait` (no --pattern): process exit, terminal panic, contention.

Bare wait polls — one short-lived `query-status` per tick plus a serial-log
scan — instead of holding QEMU's single QMP client slot for its whole
duration. These tests drive the production handler through `cli.main` with
the collaborators patched on the owning module (`lifecycle`), a fake clock,
and a real serial log under tmp_path.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from qmu import cli
from qmu import instance as instance_mod
from qmu.commands import lifecycle
from qmu.instance import VMInstance
from qmu.qmp import QMPBusyError, QMPError


BOOT = "[    0.000000] Linux version 7.0.0 (builder@host) (gcc 13.3.0) #1 SMP\n"
TERMINAL_PANIC = (
    "[    2.0] Kernel panic - not syncing: sysrq triggered crash\n"
    "[    2.1] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---\n"
)
SURVIVED_OOPS = (
    "[    1.6] BUG: kernel NULL pointer dereference, address: 0000000000000083\n"
    "[    1.6] Oops: 0000 [#1] SMP NOPTI\n"
    "[    1.6] ---[ end trace 0000000000000000 ]---\n"
)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


class FakeQMP:
    """One fresh connection per poll, answering `query-status` from a script.

    `statuses` is consumed one entry per connection: a status name, an
    exception to raise at connect time, or a callable invoked at connect
    time (a side effect that happens WHILE the probe blocks) returning either
    of those (the last entry repeats). `connects` counts how many short-lived
    connections the wait opened.
    """

    def __init__(self, statuses=("running",)):
        self.statuses = list(statuses)
        self.connects = 0

    def _current(self):
        if len(self.statuses) > 1:
            return self.statuses.pop(0)
        return self.statuses[0]

    def __enter__(self):
        self.connects += 1
        self._status = self._current()
        if callable(self._status):
            self._status = self._status()
        if isinstance(self._status, Exception):
            raise self._status
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command):
        assert command == "query-status"
        return {"running": self._status == "running", "status": self._status}


def _instance(tmp_path, *, harness=True, epoch=0) -> VMInstance:
    return VMInstance(
        vm_id="wait-vm",
        pid=4243,
        pid_start="recorded-start",
        qmp_socket=str(tmp_path / "wait-vm.qmp.sock"),
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=str(tmp_path / "wait-vm.serial.log"),
        kernel="/boot/bzImage",
        rootfs=None,
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        harness=harness,
        guest_epoch_serial_offset=epoch,
    )


def _invoke_wait(
    monkeypatch,
    capsys,
    tmp_path,
    *,
    statuses=("running",),
    alive=(True,),
    harness=True,
    timeout=1.0,
    no_clean=False,
    fmt="json",
    serial=BOOT,
    epoch=0,
    inst=None,
):
    """Run `wait --vm wait-vm` against a scripted VM; returns the receipts.

    `alive` is a sequence consumed one value per `instance_alive` call (the
    last repeats) or a callable of the fake clock's time.
    """
    inst = inst or _instance(tmp_path, harness=harness, epoch=epoch)
    if serial is not None:
        Path(inst.serial_log).write_text(serial)
    clock = FakeClock()
    qmp = FakeQMP(statuses)
    alive_values = None if callable(alive) else list(alive)
    remove_calls = []

    def identity_alive(selected):
        if alive_values is None:
            return alive(clock.now)
        value = alive_values[0]
        if len(alive_values) > 1:
            alive_values.pop(0)
        return value

    def forbidden_kill(*args, **kwargs):
        raise AssertionError("wait must not call _kill_vm after identity death")

    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle.time, "sleep", clock.sleep)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_require_running", lambda vm, cmd: None)
    monkeypatch.setattr(lifecycle, "_orphan_serial_logs", lambda: {})
    monkeypatch.setattr(
        lifecycle, "classify_vm",
        lambda vm_id, **kw: {"state": "running", "instance": inst, "pid": inst.pid,
                             "serial_log": inst.serial_log},
    )
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", identity_alive)
    monkeypatch.setattr(
        lifecycle,
        "is_pid_alive",
        lambda pid: (_ for _ in ()).throw(
            AssertionError("wait used pid-only liveness")
        ),
    )
    monkeypatch.setattr(
        lifecycle,
        "remove_instance",
        lambda vm_id: remove_calls.append(vm_id),
    )
    monkeypatch.setattr(lifecycle, "_kill_vm", forbidden_kill)

    argv = ["wait", "--vm", "wait-vm"]
    if timeout is not None:
        argv.extend(["--timeout", str(timeout)])
    if no_clean:
        argv.append("--no-clean")
    if fmt != "text":
        argv.extend(["--format", fmt])

    rc = cli.main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if fmt != "text" else None
    return rc, payload, captured, qmp, clock, remove_calls


# ---------------------------------------------------------------------------
# Process exit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("exit_at", [0.1, 1.0])
def test_wait_returns_when_the_recorded_process_exits(
    exit_at, monkeypatch, capsys, tmp_path
):
    rc, payload, _, qmp, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=lambda now: now < exit_at,
        timeout=None,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["reason"] == "process_exited"
    # No process, no guest axis: `unknown` read as a probe that failed.
    assert payload["guest"] is None
    assert payload["crash"] is None
    assert payload["cleaned"] is True
    # The run's own evidence rides along, because the auto-clean just
    # removed the log it came from (r2-harness finding 1).
    assert payload["console_tail"] == BOOT.rstrip("\n").splitlines()[-20:]
    assert remove_calls == ["wait-vm"]
    assert qmp.connects >= 1


def test_wait_reports_the_crash_of_a_process_that_exited(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[False],
        serial=BOOT + TERMINAL_PANIC,
    )

    assert rc == 0
    assert payload["stopped"] is True
    assert payload["guest"] is None
    assert "sysrq triggered crash" in payload["crash"]
    assert payload["console_tail"][-1] == TERMINAL_PANIC.rstrip("\n").splitlines()[-1]


def test_wait_non_harness_exit_does_not_auto_clean(monkeypatch, capsys, tmp_path):
    rc, payload, _, _, _, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=[False], harness=False,
    )

    assert rc == 0
    assert payload["stopped"] is True
    assert payload["cleaned"] is False
    assert remove_calls == []


def test_wait_no_clean_preserves_terminal_harness_metadata(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, _, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=[False], no_clean=True,
    )

    assert rc == 0
    assert payload["cleaned"] is False
    assert remove_calls == []


@pytest.mark.parametrize(("alive", "expected_rc"), (([False], 0), ([True], 124)))
def test_wait_zero_timeout_checks_identity_once(
    alive, expected_rc, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, clock, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, harness=False, timeout=0,
    )

    assert rc == expected_rc
    assert clock.now == 0
    assert payload["stopped"] is (expected_rc == 0)
    assert payload["reason"] == (
        "process_exited" if expected_rc == 0 else "timeout"
    )


def test_wait_terminal_crash_uses_current_epoch(monkeypatch, capsys, tmp_path):
    old = (
        "[ 1.0] WARNING: CPU: uaf_init\n"
        "[ 1.1] old trace body\n"
        "[ 1.2] ---[ end trace 111 ]---\n"
    )
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[False], harness=False,
        serial=old + TERMINAL_PANIC, epoch=len(old.encode()),
    )

    assert rc == 0
    assert payload["stopped"] is True
    assert "sysrq triggered crash" in payload["crash"]
    assert "uaf_init" not in payload["crash"]


def test_wait_process_exit_text_is_terminal(monkeypatch, capsys, tmp_path):
    rc, _, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[False], harness=False, fmt="text", serial=BOOT + TERMINAL_PANIC,
    )

    assert rc == 0
    assert "VM 'wait-vm' stopped (process_exited" in captured.out
    assert "Guest:" not in captured.out
    assert "Crash from serial log:\n" in captured.out
    # The crash IS the evidence; the tail would only repeat it.
    assert "Console tail:" not in captured.out
    assert "still running" not in captured.out


def test_wait_process_exit_text_shows_the_console_tail(
    monkeypatch, capsys, tmp_path
):
    """A harness that printed its marker and powered off: the marker is the
    result, and text mode must show it without a second `qmu log`."""
    rc, _, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[False], fmt="text", serial=BOOT + "=== HARNESS DONE ===\n",
    )

    assert rc == 0
    assert "Console tail:" in captured.out
    assert "  === HARNESS DONE ===" in captured.out
    assert "Instance metadata cleaned up" in captured.out


# ---------------------------------------------------------------------------
# Timeout with a live process: the QMP slot is never held across polls
# ---------------------------------------------------------------------------


def test_wait_polls_with_one_connection_per_tick(monkeypatch, capsys, tmp_path):
    rc, payload, _, qmp, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=[True], timeout=2.0,
    )

    assert rc == 124
    assert payload["ok"] is False
    assert payload["stopped"] is False
    assert payload["reason"] == "timeout"
    assert payload["guest"] == "serving"
    assert payload["qmp"] == "connected"
    assert payload["qemu_status"] == "running"
    assert payload["last_event"] is None
    assert payload["crash"] is None
    assert payload["cleaned"] is False
    assert clock.now == pytest.approx(2.0)
    # 2 s at a 0.5 s tick: five polls, each on its own short-lived connection.
    assert qmp.connects == 5
    assert remove_calls == []


@pytest.mark.parametrize("status", ("paused", "postmigrate", "guest-panicked"))
def test_wait_initial_nonrunning_status_with_live_pid_times_out(
    status, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, _, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path, statuses=[status], alive=[True],
    )

    assert rc == 124
    assert payload["stopped"] is False
    assert payload["reason"] == "timeout"
    assert payload["qemu_status"] == status
    # A status that was already in force when the wait began is not an event.
    assert payload["last_event"] is None
    assert payload["event_data"] is None
    assert payload["guest"] == "paused"
    assert remove_calls == []


@pytest.mark.parametrize(
    ("status", "event"),
    (("shutdown", "SHUTDOWN"), ("paused", "STOP"), ("guest-panicked", "GUEST_PANICKED")),
)
def test_wait_reports_a_status_transition_as_the_event_qemu_would_have_sent(
    status, event, monkeypatch, capsys, tmp_path
):
    rc, payload, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", status], alive=[True], timeout=1.0,
    )

    assert rc == 124
    assert payload["stopped"] is False
    assert payload["qemu_status"] == status
    assert payload["last_event"] == event
    assert payload["event_data"] == {
        "source": "query-status", "from": "running", "to": status,
    }


def test_wait_keeps_the_latest_transition_until_timeout(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", "paused", "running"], alive=[True], timeout=1.5,
    )

    assert rc == 124
    assert payload["last_event"] == "RUNNING"
    assert payload["event_data"]["from"] == "paused"
    assert payload["qemu_status"] == "running"


def test_wait_text_does_not_call_live_vm_stopped(monkeypatch, capsys, tmp_path):
    rc, _, captured, _, _, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", "paused"], alive=[True], fmt="text",
    )

    assert rc == 124
    assert "VM 'wait-vm' still running" in captured.out
    assert "Observed QMP event STOP (QEMU process still running)." in captured.out
    assert "Observed QEMU status paused (QEMU process still running)." in captured.out
    assert "VM 'wait-vm' stopped" not in captured.out
    assert "Crash from serial log" not in captured.out
    assert "Instance metadata cleaned up" not in captured.out
    assert remove_calls == []


def test_wait_does_not_repeat_the_profile_param_note(monkeypatch, capsys, tmp_path):
    """`apparmor=0` unclaimed is `launch`'s note; every wait re-printing it was
    the alarm fatigue the operator/profile split exists to end."""
    inst = replace(
        _instance(tmp_path),
        cmdline="console=ttyS0 apparmor=0 panic_on_oopsy=1",
        profile="exploit-dev",
    )
    monkeypatch.setattr(
        lifecycle, "extract_unknown_params",
        lambda *a, **k: ["apparmor=0", "panic_on_oopsy=1"],
    )
    monkeypatch.setattr(lifecycle, "_profile_params", lambda i: {"apparmor=0"})
    rc, payload, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=[True], inst=inst,
    )

    assert rc == 124
    assert "Note: unclaimed by this kernel, from profile" not in captured.err
    assert "panic_on_oopsy=1" in captured.err
    assert payload["unknown_kernel_params_by_source"]["profile"] == ["apparmor=0"]


# ---------------------------------------------------------------------------
# QMP contention and transport loss
# ---------------------------------------------------------------------------


def test_wait_keeps_waiting_while_another_client_holds_qmp(
    monkeypatch, capsys, tmp_path
):
    """Busy is a sibling command, not a dead VM: liveness and the serial log
    still decide; QMP-derived fields are reported as not observed."""
    busy = QMPBusyError("no greeting")
    rc, payload, captured, qmp, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=[busy], alive=[True, True, False], timeout=5.0,
    )

    assert rc == 0
    assert payload["reason"] == "process_exited"
    assert payload["qmp"] == "busy"
    assert payload["qemu_status"] == "unknown"
    assert qmp.connects == 2


def test_wait_busy_timeout_reports_the_unobserved_status(
    monkeypatch, capsys, tmp_path
):
    busy = QMPBusyError("no greeting")
    rc, payload, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, statuses=[busy], alive=[True], fmt="text",
    )

    assert rc == 124
    assert "QMP: busy (held by another client" in captured.out
    # Names the likely holder, as the `status` busy classification does.
    assert "another qmu command such as `wait`/`status`, or a debugger bridge" in captured.out
    assert "still running" in captured.out


def test_wait_panic_during_the_final_busy_probe_is_terminal(
    monkeypatch, capsys, tmp_path
):
    """#91 (receipt 140): a sibling holds QMP, so the probe blocks for its
    whole connect timeout, and the guest panics meanwhile. The deadline
    decides when the wait ends, not what the guest did: a 124 with
    `crash: null` beside a console_tail showing the panic sent callers back
    to wait on a dead guest."""
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)

    def blocking_busy_probe():
        # The probe blocks past the deadline (`lifecycle.time.sleep` is the
        # fake clock); the panic lands while it does.
        lifecycle.time.sleep(2.0)
        with log.open("a") as stream:
            stream.write(TERMINAL_PANIC)
        return QMPBusyError("no greeting")

    rc, payload, _, qmp, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=[blocking_busy_probe], alive=[True], timeout=1.0, inst=inst,
    )

    assert rc == 3
    assert payload["reason"] == "terminal_panic"
    assert payload["guest"] == "panicked"
    assert payload["crash"] is not None and "Kernel panic" in payload["crash"]
    assert payload["qmp"] == "busy"
    assert payload["qemu_status"] == "unknown"
    assert qmp.connects == 1


def test_wait_connected_then_busy_reports_no_current_qemu_status(
    monkeypatch, capsys, tmp_path
):
    """#92 (receipt 174): the busy final probe observed nothing, so a
    `qemu_status` carried over from the earlier connected tick is a stale
    value presented as current."""
    busy = QMPBusyError("no greeting")
    rc, payload, _, qmp, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", busy], alive=[True], timeout=1.0,
    )

    assert rc == 124
    assert payload["qmp"] == "busy"
    assert payload["qemu_status"] == "unknown"
    assert payload["last_event"] is None
    assert qmp.connects >= 2


def test_wait_busy_tick_between_two_connected_ticks_keeps_the_transition(
    monkeypatch, capsys, tmp_path
):
    """History survives a busy tick: the transition is still reported from
    the last CONNECTED reading, and the final connected probe is current."""
    busy = QMPBusyError("no greeting")
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", busy, "paused"], alive=[True], timeout=1.0,
    )

    assert rc == 124
    assert payload["qmp"] == "connected"
    assert payload["qemu_status"] == "paused"
    assert payload["last_event"] == "STOP"
    assert payload["event_data"] == {
        "source": "query-status", "from": "running", "to": "paused",
    }


def test_wait_adopts_a_replaced_log_and_sees_its_panic(
    monkeypatch, capsys, tmp_path
):
    """#103 at the consumer: the log is replaced by a shorter generation
    whose panic sits below the retained boot boundary. The boundary must
    follow the log, and the persisted epoch with it."""
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    checks = 0
    saved = []

    def alive(selected):
        nonlocal checks
        checks += 1
        if checks == 2:
            log.write_text(BOOT + TERMINAL_PANIC)
        return True

    def save_epoch(record, offset):
        saved.append(offset)
        return replace(record, guest_epoch_serial_offset=offset)

    monkeypatch.setattr(lifecycle, "save_guest_epoch_serial_offset", save_epoch)
    long_first_boot = BOOT + "noise\n" * 400 + BOOT + "login: \n"
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, inst=inst, timeout=5.0,
        serial=long_first_boot,
    )

    assert rc == 3
    assert payload["reason"] == "terminal_panic"
    assert payload["crash"] is not None and "Kernel panic" in payload["crash"]
    assert payload["event_data"] == {"source": "log-replaced", "offset": 0}
    assert saved[-1] == 0
    assert payload["console_tail"][-1] in TERMINAL_PANIC


@pytest.mark.parametrize("exit_at", [0.1, 1.0])
def test_wait_qmp_loss_allows_bounded_identity_exit(
    exit_at, monkeypatch, capsys, tmp_path
):
    """QEMU closes QMP ~100 ms before its pid vanishes; a lost connection is
    followed by identity polling only, for at most one second."""
    rc, payload, _, _, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=[QMPError("Cannot connect to QMP socket")],
        alive=lambda now: now < exit_at,
        timeout=None,
    )

    assert rc == 0
    assert payload["stopped"] is True
    assert payload["reason"] == "process_exited"
    assert payload["elapsed"] == pytest.approx(exit_at)
    assert remove_calls == ["wait-vm"]


@pytest.mark.parametrize(
    "error",
    [QMPError("Cannot connect to QMP socket"), OSError("connection refused")],
)
def test_wait_persistent_transport_failure_is_infrastructure_and_keeps_state(
    error, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path, statuses=[error], timeout=None,
    )

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "QMPError"
    assert str(error) in payload["error"]
    assert "stopped" not in payload
    assert clock.now == pytest.approx(1.0)
    assert remove_calls == []


@pytest.mark.parametrize("exits_at_deadline", [False, True])
def test_wait_transport_grace_uses_remaining_deadline_and_checks_boundary(
    exits_at_deadline, monkeypatch, capsys, tmp_path
):
    """A transport lost at 0.5 s of a 1 s deadline gets 0.5 s of grace, and the
    identity is checked AT the deadline, never after it."""
    rc, payload, _, _, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=["running", QMPError("QMP connection closed unexpectedly")],
        alive=lambda now: not exits_at_deadline or now < 1.0,
        timeout=1.0,
    )

    assert clock.now == pytest.approx(1.0)
    if exits_at_deadline:
        assert rc == 0
        assert payload["reason"] == "process_exited"
        assert remove_calls == ["wait-vm"]
    else:
        assert rc == 4
        assert payload["error_type"] == "QMPError"
        assert remove_calls == []


@pytest.mark.parametrize("alive", [False, True])
def test_wait_connection_failure_at_zero_deadline_checks_identity_without_grace(
    alive, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, clock, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        statuses=[OSError("connection refused")], alive=[True, alive], timeout=0,
    )

    assert clock.now == 0
    if alive:
        assert rc == 4
        assert payload["error_type"] == "QMPError"
        assert remove_calls == []
    else:
        assert rc == 0
        assert payload["reason"] == "process_exited"
        assert remove_calls == ["wait-vm"]


# ---------------------------------------------------------------------------
# Terminal panic while QEMU keeps running (#27)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_wait_terminal_panic_with_a_live_process_exits_three(
    fmt, monkeypatch, capsys, tmp_path
):
    """No -no-reboot and panic=0: the guest is gone, QEMU is not. Reporting
    "still running" here contradicted `status` and sent the reader back to
    wait again for a marker that can never come."""
    rc, payload, captured, _, _, remove_calls = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[True], serial=BOOT + TERMINAL_PANIC, fmt=fmt, timeout=30.0,
    )

    assert rc == 3
    if fmt == "json":
        assert payload["ok"] is False
        assert payload["stopped"] is False
        assert payload["reason"] == "terminal_panic"
        assert payload["guest"] == "panicked"
        assert "sysrq triggered crash" in payload["crash"]
        assert payload["cleaned"] is False
    else:
        assert "VM 'wait-vm' guest PANICKED (terminal_panic" in captured.out
        assert "qmu kill --vm wait-vm" in captured.out
        assert "Crash from serial log:\n" in captured.out
        assert "still running (" not in captured.out
    assert remove_calls == []


def test_wait_terminal_panic_is_found_before_any_sleep(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, clock, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[True], serial=BOOT + TERMINAL_PANIC, timeout=30.0,
    )

    assert rc == 3
    # Only the crash-settle pause, never a poll tick.
    assert clock.now < lifecycle._WAIT_POLL_INTERVAL


def test_wait_terminal_panic_detected_mid_wait(monkeypatch, capsys, tmp_path):
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    polls = 0

    def alive(selected):
        nonlocal polls
        polls += 1
        if polls == 2:
            log.write_text(log.read_text() + TERMINAL_PANIC)
        return True

    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, timeout=5.0, inst=inst,
    )

    assert rc == 3
    assert payload["reason"] == "terminal_panic"
    assert payload["elapsed"] == pytest.approx(0.5 + lifecycle._CRASH_SETTLE_INTERVAL)


def test_wait_panic_before_a_reboot_is_not_terminal(monkeypatch, capsys, tmp_path):
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path,
        alive=[True], serial=BOOT + TERMINAL_PANIC + BOOT + "login: \n",
    )

    assert rc == 124
    assert payload["reason"] == "timeout"
    assert payload["guest"] == "serving"
    assert payload["crash"] is None


def test_wait_survived_oops_is_not_terminal(monkeypatch, capsys, tmp_path):
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=[True], serial=BOOT + SURVIVED_OOPS,
    )

    assert rc == 124
    assert payload["guest"] == "crashed"
    assert payload["crash"] is None


# ---------------------------------------------------------------------------
# Guest-initiated reboot, observed through the boot banner
# ---------------------------------------------------------------------------


def test_wait_observes_a_reboot_and_persists_the_epoch_before_the_next_liveness_check(
    monkeypatch, capsys, tmp_path
):
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    calls = []
    saved_offsets = []
    checks = 0

    def alive(selected):
        nonlocal checks
        checks += 1
        calls.append(f"alive{checks}")
        if checks == 1:
            with log.open("a") as stream:
                stream.write("[ 9.0] reboot: Restarting system\n" + BOOT)
        return True

    def save_epoch(record, offset):
        calls.append("save_epoch")
        saved_offsets.append(offset)
        return replace(record, guest_epoch_serial_offset=offset)

    monkeypatch.setattr(lifecycle, "save_guest_epoch_serial_offset", save_epoch)
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, inst=inst, timeout=1.0,
    )

    assert rc == 124
    assert payload["last_event"] == "RESET"
    assert payload["event_data"]["source"] == "boot-banner"
    expected = len(BOOT.encode()) + len("[ 9.0] reboot: Restarting system\n".encode())
    assert saved_offsets == [expected]
    assert calls.index("alive1") < calls.index("save_epoch") < calls.index("alive2")


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_wait_reset_under_a_debugger_warns_once_on_the_result(
    fmt, monkeypatch, capsys, tmp_path
):
    """#121, the standalone manifestation: the #46 coherence warning used to
    go straight to stderr from the scan closure, so a JSON reader never saw
    it. It rides the Result: `warnings[]` carries it, stderr has it exactly
    once — even across two reboots in one wait."""
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    checks = 0

    def alive(selected):
        nonlocal checks
        checks += 1
        if checks in (1, 2):
            with log.open("a") as stream:
                stream.write("[ 9.0] reboot: Restarting system\n" + BOOT)
        return True

    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: True)
    monkeypatch.setattr(
        lifecycle, "save_guest_epoch_serial_offset",
        lambda record, offset: replace(record, guest_epoch_serial_offset=offset),
    )
    rc, payload, captured, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, inst=inst, timeout=2.0, fmt=fmt,
    )

    assert rc == 124
    assert captured.err.count("was just reset") == 1
    if fmt == "json":
        assert payload["last_event"] == "RESET"
        assert len(payload["warnings"]) == 1 and "was just reset" in payload["warnings"][0]
        assert "--timeout" in payload["hint"]



def test_wait_reboot_scopes_the_exit_crash_to_the_new_boot(
    monkeypatch, capsys, tmp_path
):
    """panic=1 loop: the VM reboots past a panic and then exits; the report
    belongs to the last boot, and a clean last boot reports none."""
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    checks = 0

    def alive(selected):
        nonlocal checks
        checks += 1
        if checks == 1:
            log.write_text(BOOT + TERMINAL_PANIC + BOOT + "clean boot\n")
            return True
        return False

    monkeypatch.setattr(
        lifecycle, "save_guest_epoch_serial_offset",
        lambda record, offset: replace(record, guest_epoch_serial_offset=offset),
    )
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, inst=inst, serial="",
    )

    assert rc == 0
    assert payload["reason"] == "process_exited"
    assert payload["last_event"] == "RESET"
    assert payload["crash"] is None
    assert payload["guest"] is None


def test_wait_reset_persistence_failure_prevents_live_result(
    monkeypatch, capsys, tmp_path
):
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    checks = 0

    def alive(selected):
        nonlocal checks
        checks += 1
        if checks == 1:
            log.write_text(log.read_text() + BOOT)
        return True

    monkeypatch.setattr(
        lifecycle, "save_guest_epoch_serial_offset",
        lambda record, offset: (_ for _ in ()).throw(OSError("metadata failed")),
    )
    rc, payload, _, _, clock, _ = _invoke_wait(
        monkeypatch, capsys, tmp_path, alive=alive, inst=inst,
    )

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "OSError"
    assert "metadata failed" in payload["error"]
    assert "stopped" not in payload
    assert checks == 1
    assert clock.now == 0


# ---------------------------------------------------------------------------
# Already stopped before the wait began (#28)
# ---------------------------------------------------------------------------


def _stopped_record(tmp_path, *, harness, serial, epoch=0):
    """A real stopped instance record under the isolated cache dir."""
    inst = replace(
        _instance(tmp_path, harness=harness, epoch=epoch),
        pid=0, pid_start=None,
    )
    Path(inst.serial_log).write_text(serial)
    instance_mod.save_instance(inst)
    monkeypatch_targets = (lifecycle, instance_mod)
    return inst, monkeypatch_targets


def _invoke_stopped_wait(monkeypatch, capsys, tmp_path, *, harness, serial,
                         epoch=0, no_clean=False, fmt="json"):
    inst, mods = _stopped_record(tmp_path, harness=harness, serial=serial, epoch=epoch)
    for mod in mods:
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda *a, **k: pytest.fail("kill"))
    argv = ["wait", "--vm", "wait-vm", "--timeout", "5"]
    if no_clean:
        argv.append("--no-clean")
    if fmt != "text":
        argv.extend(["--format", fmt])
    rc = cli.main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if fmt != "text" else None
    return rc, payload, captured, inst


def test_wait_on_an_already_stopped_vm_is_a_finished_wait(
    monkeypatch, capsys, tmp_path
):
    """A 3 s harness beats a two-call agent to the exit; the answer must not
    depend on whether `wait` started a second earlier or later."""
    rc, payload, _, _ = _invoke_stopped_wait(
        monkeypatch, capsys, tmp_path, harness=False, serial=BOOT + "done\n",
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["reason"] == "already_stopped"
    assert payload["guest"] is None
    assert payload["crash"] is None
    assert payload["cleaned"] is False
    assert payload["elapsed"] == 0.0
    assert payload["console_tail"][-1] == "done"


def test_wait_on_an_already_stopped_vm_reports_its_last_boot_crash(
    monkeypatch, capsys, tmp_path
):
    old = BOOT + "[ 1.0] WARNING: CPU: old_warning\n[ 1.1] ---[ end trace 1 ]---\n"
    rc, payload, captured, _ = _invoke_stopped_wait(
        monkeypatch, capsys, tmp_path, harness=False,
        serial=old + BOOT + TERMINAL_PANIC,
    )

    assert rc == 0
    assert payload["reason"] == "already_stopped"
    assert payload["guest"] is None
    assert "sysrq triggered crash" in payload["crash"]
    assert "old_warning" not in payload["crash"]
    # The tail is scoped to the last boot like the crash is.
    assert not any("old_warning" in line for line in payload["console_tail"])


@pytest.mark.parametrize("no_clean", [False, True])
def test_wait_on_an_already_stopped_harness_vm_honours_auto_clean(
    no_clean, monkeypatch, capsys, tmp_path
):
    rc, payload, _, inst = _invoke_stopped_wait(
        monkeypatch, capsys, tmp_path, harness=True, serial=BOOT, no_clean=no_clean,
    )

    assert rc == 0
    assert payload["reason"] == "already_stopped"
    assert payload["cleaned"] is (not no_clean)
    assert (instance_mod.load_instance("wait-vm") is None) is (not no_clean)


def test_wait_on_an_already_stopped_vm_text(monkeypatch, capsys, tmp_path):
    rc, _, captured, _ = _invoke_stopped_wait(
        monkeypatch, capsys, tmp_path, harness=False, serial=BOOT, fmt="text",
    )

    assert rc == 0
    assert "VM 'wait-vm' stopped (already_stopped" in captured.out
    assert "not found" not in captured.out + captured.err


def test_wait_without_explicit_vm_still_needs_a_running_vm(
    monkeypatch, capsys, tmp_path
):
    """Implicit selection stays running-only: an old stopped VM must not
    silently satisfy a new wait."""
    _stopped_record(tmp_path, harness=False, serial=BOOT)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)

    rc = cli.main(["wait", "--timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["ok"] is False
    assert "No running VMs" in payload["error"]
