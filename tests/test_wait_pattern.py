"""`qmu wait --pattern` — serial-console pattern waiting and its exit codes.

This replaces the `until grep -q ... serial.log; do sleep 2; done` loop agents
otherwise hand-roll. The contract that matters is that every way the wait can
end is distinguishable by exit code, and that neither a panic nor a dead VM can
hang the caller forever.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance
from qmu.serial import SerialTail


KASAN_SPLAT = (
    "BUG: KASAN: slab-use-after-free in perf_event_release_kernel+0x1a0/0x3c0\n"
    "Read of size 8 at addr ffff888012345678 by task exploit/142\n"
    "---[ end trace 0000000000000000 ]---\n"
)


def _instance(serial_log: str, *, epoch: int = 0) -> VMInstance:
    return VMInstance(
        vm_id="wait-vm",
        pid=4242,
        qmp_socket="/tmp/wait-vm.qmp.sock",
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs=None,
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z",
        harness=True,
        guest_epoch_serial_offset=epoch,
    )


@pytest.fixture
def wait_env(monkeypatch, tmp_path):
    """Wire the wait handler to a serial log this test controls."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text("")
    inst = _instance(str(serial))
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)
    return serial


def _run(*argv: str) -> tuple[int, dict]:
    rc = cli.main(["--format", "json", "wait", *argv])
    return rc, None


def _run_json(capsys, *argv: str) -> tuple[int, dict]:
    rc = cli.main(["--format", "json", "wait", *argv])
    return rc, json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# SerialTail
# ---------------------------------------------------------------------------


def test_serial_tail_reads_only_new_lines(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("one\ntwo\n")
    tail = SerialTail(log)

    assert tail.read_lines() == ["one", "two"]
    assert tail.read_lines() == []

    log.write_text("one\ntwo\nthree\n")
    assert tail.read_lines() == ["three"]


def test_serial_tail_withholds_partial_line_until_complete(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("comp")
    tail = SerialTail(log)

    # A half-written line must not be handed to a matcher: "comp" would
    # spuriously satisfy a wait for /comp/ when the guest is writing
    # "compilation failed".
    assert tail.read_lines() == []

    log.write_text("complete\n")
    assert tail.read_lines() == ["complete"]


def test_serial_tail_flush_releases_unterminated_line(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("no trailing newline")
    tail = SerialTail(log)

    assert tail.read_lines() == []
    assert tail.flush() == ["no trailing newline"]
    assert tail.flush() == []


def test_serial_tail_restarts_when_log_is_truncated(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("first boot\n")
    tail = SerialTail(log)
    assert tail.read_lines() == ["first boot"]

    log.write_text("x\n")  # shorter than the offset we already advanced past
    assert tail.read_lines() == ["x"]


def test_serial_tail_honors_start_offset(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("stale\nfresh\n")
    tail = SerialTail(log, offset=len("stale\n"))

    assert tail.read_lines() == ["fresh"]


# ---------------------------------------------------------------------------
# exit-code contract
# ---------------------------------------------------------------------------


def test_pattern_match_exits_zero_with_matched_line(wait_env, capsys):
    wait_env.write_text("booting\n=== results ===\npwned\n")

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "5")

    assert rc == 0
    assert payload["ok"] is True
    assert payload["matched"] is True
    assert payload["matched_line"] == "=== results ==="
    assert payload["reason"] == "pattern_matched"


def test_pattern_is_a_regex_not_a_literal(wait_env, capsys):
    wait_env.write_text("attempt 3: leaked 0xffff888012345678\n")

    rc, payload = _run_json(
        capsys, "--pattern", r"leaked 0x[0-9a-f]{16}", "--timeout", "5"
    )

    assert rc == 0
    assert payload["matched"] is True


TERMINAL_PANIC_LOG = KASAN_SPLAT + (
    "Kernel panic - not syncing: Fatal exception\n"
    "---[ end Kernel panic - not syncing: Fatal exception ]---\n"
)


def test_terminal_panic_aborts_the_wait_with_exit_three(wait_env, capsys):
    """A panic before the marker must end the wait, not hang it forever."""
    wait_env.write_text("booting\n" + TERMINAL_PANIC_LOG)

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "5")

    assert rc == 3
    assert payload["ok"] is False
    assert payload["reason"] == "crash"
    assert "KASAN" in payload["crash"]


def test_a_survived_crash_does_not_abort_the_wait(wait_env, capsys):
    """Under the default profile a survived Oops is the EXPECTED outcome.

    Aborting on it made every wait carry `--ignore-crash`, and a reflexive
    `--ignore-crash` is how a real panic gets missed. The guest is still
    running, so the marker can still arrive.
    """
    wait_env.write_text("booting\n" + KASAN_SPLAT + "=== results ===\n")

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "5")

    assert rc == 0
    assert payload["matched"] is True


def test_a_survived_crash_alone_times_out_rather_than_aborting(wait_env, capsys):
    wait_env.write_text("booting\n" + KASAN_SPLAT)

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "0")

    assert rc == 124
    assert payload["reason"] == "timeout"


def test_ignore_crash_keeps_waiting_through_a_terminal_panic(wait_env, capsys):
    """--ignore-crash now only matters for a TERMINAL panic; survived crashes
    no longer abort at all, so the flag is rarely needed."""
    wait_env.write_text("booting\n" + TERMINAL_PANIC_LOG + "=== results ===\n")

    rc, payload = _run_json(
        capsys, "--pattern", "=== results ===", "--ignore-crash", "--timeout", "5"
    )

    assert rc == 0
    assert payload["matched"] is True


def test_dead_vm_without_match_exits_one(wait_env, monkeypatch, capsys):
    wait_env.write_text("booting\n")
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: False)

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "5")

    assert rc == 1
    assert payload["matched"] is False
    assert payload["reason"] == "process_exited"


def test_final_line_written_just_before_exit_still_matches(
    wait_env, monkeypatch, capsys
):
    """The guest can print the marker and die between two polls; don't lose it."""
    wait_env.write_text("booting\n")
    states = iter([True, False, False])

    def alive(inst):
        try:
            return next(states)
        except StopIteration:
            return False

    def poll_side_effect(_seconds):
        # Simulate the guest writing its marker after the first scan.
        wait_env.write_text("booting\n=== results ===\n")

    monkeypatch.setattr(lifecycle, "instance_alive", alive)
    monkeypatch.setattr(lifecycle.time, "sleep", poll_side_effect)

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "5")

    assert rc == 0
    assert payload["matched"] is True


def test_unterminated_final_line_matches_after_the_vm_dies(
    wait_env, monkeypatch, capsys
):
    wait_env.write_text("booting\nEXPLOIT SUCCESS")  # no trailing newline
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: False)

    rc, payload = _run_json(capsys, "--pattern", "EXPLOIT SUCCESS", "--timeout", "5")

    assert rc == 0
    assert payload["matched_line"] == "EXPLOIT SUCCESS"


def test_timeout_exits_124(wait_env, capsys):
    wait_env.write_text("booting\n")

    rc, payload = _run_json(capsys, "--pattern", "never appears", "--timeout", "0")

    assert rc == 124
    assert payload["matched"] is False
    assert payload["reason"] == "timeout"


def test_guest_epoch_offset_hides_the_previous_boot(monkeypatch, tmp_path, capsys):
    """After a RESET, a marker from the prior boot must not satisfy the wait."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text("=== results ===\n")
    inst = _instance(str(serial), epoch=len("=== results ===\n"))
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)

    rc, payload = _run_json(capsys, "--pattern", "=== results ===", "--timeout", "0")

    assert rc == 124
    assert payload["matched"] is False


def test_invalid_regex_is_a_usage_grade_error_not_a_traceback(wait_env, capsys):
    rc = cli.main(["wait", "--pattern", "unbalanced(", "--timeout", "1"])

    assert rc == 1
    assert "Invalid --pattern regex" in capsys.readouterr().err


def test_wait_without_pattern_keeps_its_original_behavior(monkeypatch, tmp_path):
    """The QMP exit-wait path must be untouched by the pattern feature."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text("")
    inst = _instance(str(serial))
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: False)

    rc = cli.main(["--format", "json", "wait", "--timeout", "1"])

    assert rc == 0
