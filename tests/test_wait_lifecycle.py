from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class FakeQMP:
    def __init__(self, clock, *, status="running", events=()):
        self.clock = clock
        self.status = status
        self.events = list(events)
        self.wait_calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command):
        assert command == "query-status"
        return {"running": self.status == "running", "status": self.status}

    def wait_event(self, event_names, timeout=None):
        self.wait_calls.append((event_names, timeout))
        if self.events:
            return self.events.pop(0)
        self.clock.now += 0.0 if timeout is None else timeout
        return None


def _instance(tmp_path, *, harness=True) -> VMInstance:
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
    )


def _invoke_wait(
    monkeypatch,
    capsys,
    tmp_path,
    *,
    status="running",
    events=(),
    alive=(True,),
    harness=True,
    timeout=1.0,
    no_clean=False,
    fmt="json",
    crash_text="terminal panic",
):
    inst = _instance(tmp_path, harness=harness)
    clock = FakeClock()
    qmp = FakeQMP(clock, status=status, events=events)
    alive_values = list(alive)
    remove_calls = []
    crash_calls = []

    def identity_alive(selected):
        value = alive_values[0]
        if len(alive_values) > 1:
            alive_values.pop(0)
        return value

    def extract(path):
        crash_calls.append(path)
        return crash_text

    def forbidden_kill(*args, **kwargs):
        raise AssertionError("wait must not call _kill_vm after identity death")

    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", identity_alive)
    monkeypatch.setattr(
        lifecycle,
        "is_pid_alive",
        lambda pid: (_ for _ in ()).throw(
            AssertionError("wait used pid-only liveness")
        ),
    )
    monkeypatch.setattr(lifecycle, "extract_crash", extract)
    monkeypatch.setattr(
        lifecycle,
        "remove_instance",
        lambda vm_id: remove_calls.append(vm_id),
    )
    monkeypatch.setattr(lifecycle, "_kill_vm", forbidden_kill)

    argv = ["wait", "--vm", "wait-vm", "--timeout", str(timeout)]
    if no_clean:
        argv.append("--no-clean")
    if fmt != "text":
        argv.extend(["--format", fmt])

    rc = cli.main(argv)
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if fmt != "text" else None
    return rc, payload, captured.out, qmp, remove_calls, crash_calls


def test_wait_reset_with_live_pid_times_out_and_preserves_observation(
    monkeypatch, capsys, tmp_path
):
    reset = {
        "event": "RESET",
        "data": {"guest": True, "reason": "guest-reset"},
    }
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        events=[reset],
        alive=[True],
    )

    assert rc == 124
    assert payload["ok"] is False
    assert payload["stopped"] is False
    assert payload["reason"] == "timeout"
    assert payload["qemu_status"] == "running"
    assert payload["last_event"] == "RESET"
    assert payload["event_data"] == reset["data"]
    assert payload["crash"] is None
    assert payload["cleaned"] is False
    assert remove_calls == []
    assert crash_calls == []


@pytest.mark.parametrize("event_name", ("STOP", "SHUTDOWN", "POWERDOWN"))
def test_wait_nonterminal_event_with_live_pid_times_out(
    event_name, monkeypatch, capsys, tmp_path
):
    event = {"event": event_name, "data": {"source": "test"}}
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        events=[event],
        alive=[True],
    )

    assert rc == 124
    assert payload["ok"] is False
    assert payload["stopped"] is False
    assert payload["reason"] == "timeout"
    assert payload["last_event"] == event_name
    assert payload["event_data"] == event["data"]
    assert payload["crash"] is None
    assert payload["cleaned"] is False
    assert remove_calls == []
    assert crash_calls == []


@pytest.mark.parametrize("status", ("paused", "postmigrate", "guest-panicked"))
def test_wait_initial_nonrunning_status_with_live_pid_times_out(
    status, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        status=status,
        alive=[True],
    )

    assert rc == 124
    assert payload["ok"] is False
    assert payload["stopped"] is False
    assert payload["reason"] == "timeout"
    assert payload["qemu_status"] == status
    assert payload["last_event"] is None
    assert payload["event_data"] is None
    assert payload["crash"] is None
    assert payload["cleaned"] is False
    assert remove_calls == []
    assert crash_calls == []


def test_wait_observation_continues_until_recorded_process_exits(
    monkeypatch, capsys, tmp_path
):
    reset = {
        "event": "RESET",
        "data": {"guest": True, "reason": "guest-reset"},
    }
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        events=[reset],
        alive=[True, False],
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["reason"] == "process_exited"
    assert payload["last_event"] == "RESET"
    assert payload["event_data"] == reset["data"]
    assert payload["crash"] == "terminal panic"
    assert payload["cleaned"] is True
    assert remove_calls == ["wait-vm"]
    assert crash_calls == [str(tmp_path / "wait-vm.serial.log")]


def test_wait_harness_cleanup_only_after_process_identity_exit(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        alive=[False],
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["reason"] == "process_exited"
    assert payload["cleaned"] is True
    assert remove_calls == ["wait-vm"]
    assert len(crash_calls) == 1


def test_wait_no_clean_preserves_terminal_harness_metadata(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        alive=[False],
        no_clean=True,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["cleaned"] is False
    assert remove_calls == []
    assert len(crash_calls) == 1


def test_wait_non_harness_exit_does_not_auto_clean(
    monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        alive=[False],
        harness=False,
    )

    assert rc == 0
    assert payload["ok"] is True
    assert payload["stopped"] is True
    assert payload["cleaned"] is False
    assert remove_calls == []
    assert len(crash_calls) == 1


@pytest.mark.parametrize(
    ("status", "events", "observation"),
    (
        (
            "running",
            [{"event": "RESET", "data": {"reason": "guest-reset"}}],
            "Observed QMP event RESET",
        ),
        ("paused", [], "Observed QEMU status paused"),
    ),
)
def test_wait_text_does_not_call_live_vm_stopped(
    status, events, observation, monkeypatch, capsys, tmp_path
):
    rc, _, text, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        status=status,
        events=events,
        alive=[True],
        fmt="text",
    )

    assert rc == 124
    assert "VM 'wait-vm' still running" in text
    assert observation in text
    assert "QEMU process still running" in text
    assert "VM 'wait-vm' stopped" not in text
    assert "Crash from serial log" not in text
    assert "Instance metadata cleaned up" not in text
    assert remove_calls == []
    assert crash_calls == []


@pytest.mark.parametrize(("alive", "expected_rc"), (([False], 0), ([True], 124)))
def test_wait_zero_timeout_checks_identity_once(
    alive, expected_rc, monkeypatch, capsys, tmp_path
):
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        alive=alive,
        harness=False,
        timeout=0,
    )

    assert rc == expected_rc
    assert payload["stopped"] is (expected_rc == 0)
    assert payload["reason"] == (
        "process_exited" if expected_rc == 0 else "timeout"
    )


def test_wait_preserves_latest_qmp_event_until_timeout(
    monkeypatch, capsys, tmp_path
):
    stop = {"event": "STOP", "data": {"sequence": 1}}
    reset = {"event": "RESET", "data": {"sequence": 2}}
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        events=[stop, reset],
        alive=[True],
    )

    assert rc == 124
    assert payload["last_event"] == "RESET"
    assert payload["event_data"] == {"sequence": 2}


def test_wait_process_exit_text_is_terminal(monkeypatch, capsys, tmp_path):
    rc, _, text, _, remove_calls, crash_calls = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        alive=[False],
        harness=False,
        fmt="text",
    )

    assert rc == 0
    assert "VM 'wait-vm' stopped (process_exited" in text
    assert "Crash from serial log:\nterminal panic" in text
    assert "still running" not in text
    assert remove_calls == []
    assert len(crash_calls) == 1


def test_wait_reset_advances_epoch_before_next_liveness_check(
    monkeypatch, capsys, tmp_path
):
    old = b"old epoch\n"
    inst = _instance(tmp_path)
    Path(inst.serial_log).write_bytes(old)
    clock = FakeClock()
    qmp = FakeQMP(
        clock,
        events=[{"event": "RESET", "data": {"reason": "guest-reset"}}],
    )
    calls = []
    saved_offsets = []
    original_wait = qmp.wait_event

    def wait_event(event_names, timeout=None):
        event = original_wait(event_names, timeout)
        if event is not None:
            calls.append(f"event:{event['event']}")
        return event

    qmp.wait_event = wait_event
    alive_checks = 0

    def identity_alive(selected):
        nonlocal alive_checks
        calls.append(
            "alive_before_reset" if alive_checks == 0 else "alive_after_reset"
        )
        alive_checks += 1
        return True

    def save_epoch(record, offset):
        calls.append("save_epoch")
        saved_offsets.append(offset)
        return replace(record, guest_epoch_serial_offset=offset)

    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", identity_alive)
    monkeypatch.setattr(
        lifecycle,
        "serial_log_offset",
        lambda path: Path(path).stat().st_size,
        raising=False,
    )
    monkeypatch.setattr(
        lifecycle,
        "save_guest_epoch_serial_offset",
        save_epoch,
        raising=False,
    )

    rc = cli.main(["wait", "--vm", "wait-vm", "--timeout", "1", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 124
    assert payload["stopped"] is False
    assert payload["last_event"] == "RESET"
    assert saved_offsets == [len(old)]
    assert calls.index("event:RESET") < calls.index("save_epoch")
    assert calls.index("save_epoch") < calls.index("alive_after_reset")


@pytest.mark.parametrize("event", ["STOP", "SHUTDOWN", "POWERDOWN"])
def test_wait_nonreset_observation_does_not_advance_epoch(
    event, monkeypatch, capsys, tmp_path
):
    saved_offsets = []
    monkeypatch.setattr(
        lifecycle,
        "save_guest_epoch_serial_offset",
        lambda record, offset: saved_offsets.append(offset),
        raising=False,
    )
    rc, payload, _, _, _, _ = _invoke_wait(
        monkeypatch,
        capsys,
        tmp_path,
        events=[{"event": event, "data": {"source": "test"}}],
        alive=[True],
    )

    assert rc == 124
    assert payload["stopped"] is False
    assert payload["last_event"] == event
    assert saved_offsets == []


def test_wait_repeated_reset_uses_latest_boundary(monkeypatch, capsys, tmp_path):
    old = b"old epoch\n"
    appended = b"new generation output\n"
    inst = _instance(tmp_path)
    log = Path(inst.serial_log)
    log.write_bytes(old)
    clock = FakeClock()
    reset = {"event": "RESET", "data": {"reason": "guest-reset"}}
    qmp = FakeQMP(clock, events=[reset, reset])
    original_wait = qmp.wait_event
    observed = 0
    saved_offsets = []

    def wait_event(event_names, timeout=None):
        nonlocal observed
        if qmp.events and observed == 1:
            with log.open("ab") as stream:
                stream.write(appended)
        event = original_wait(event_names, timeout)
        if event is not None:
            observed += 1
        return event

    qmp.wait_event = wait_event

    def save_epoch(record, offset):
        saved_offsets.append(offset)
        return replace(record, guest_epoch_serial_offset=offset)

    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda selected: True)
    monkeypatch.setattr(
        lifecycle,
        "serial_log_offset",
        lambda path: Path(path).stat().st_size,
        raising=False,
    )
    monkeypatch.setattr(
        lifecycle,
        "save_guest_epoch_serial_offset",
        save_epoch,
        raising=False,
    )

    rc = cli.main(["wait", "--vm", "wait-vm", "--timeout", "1", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 124
    assert payload["stopped"] is False
    assert payload["last_event"] == "RESET"
    assert saved_offsets == [len(old), len(old) + len(appended)]


def test_wait_reset_persistence_failure_prevents_live_result(
    monkeypatch, capsys, tmp_path
):
    inst = _instance(tmp_path)
    Path(inst.serial_log).write_text("old epoch\n")
    clock = FakeClock()
    qmp = FakeQMP(clock, events=[{"event": "RESET", "data": {}}])
    alive_checks = 0

    def identity_alive(selected):
        nonlocal alive_checks
        alive_checks += 1
        return True

    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", identity_alive)
    monkeypatch.setattr(lifecycle, "serial_log_offset", lambda path: 10, raising=False)
    monkeypatch.setattr(
        lifecycle,
        "save_guest_epoch_serial_offset",
        lambda record, offset: (_ for _ in ()).throw(OSError("metadata failed")),
        raising=False,
    )

    rc = cli.main(["wait", "--vm", "wait-vm", "--timeout", "1", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "OSError"
    assert "metadata failed" in payload["error"]
    assert "stopped" not in payload
    assert alive_checks == 1


def test_wait_terminal_crash_uses_current_epoch(monkeypatch, capsys, tmp_path):
    old = (
        "[ 1.0] WARNING: CPU: uaf_init\n"
        "[ 1.1] old trace body\n"
        "[ 1.2] ---[ end trace 111 ]---\n"
    )
    new = (
        "[ 2.0] Kernel panic - not syncing: sysrq triggered crash\n"
        "[ 2.1] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---\n"
    )
    inst = replace(
        _instance(tmp_path, harness=False),
        guest_epoch_serial_offset=len(old.encode()),
    )
    Path(inst.serial_log).write_text(old + new)
    clock = FakeClock()
    qmp = FakeQMP(clock)
    monkeypatch.setattr(lifecycle.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda selected: qmp)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda selected: False)

    rc = cli.main(["wait", "--vm", "wait-vm", "--timeout", "1", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["stopped"] is True
    assert "sysrq triggered crash" in payload["crash"]
    assert "uaf_init" not in payload["crash"]
