"""`qmu log --grep/--context/--full` — serial-log filtering inside qmu.

Without these, evidence extraction happens as `grep -E ... ~/.cache/qmu/
instances/<vm>.serial.log`, which hardcodes an internal path and bypasses the
JSON envelope and the spill guard.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import guest
from qmu.instance import VMInstance


SERIAL = "\n".join(
    [
        "[    0.000000] Linux version 6.12.0",
        "before-1",
        "before-2",
        "=== results ===",
        "after-1",
        "after-2",
        "leaked 0xffff888012345678",
        "Done.",
    ]
) + "\n"


def _instance(serial_log: str) -> VMInstance:
    return VMInstance(
        vm_id="grep-vm",
        pid=4242,
        qmp_socket="/tmp/grep-vm.qmp.sock",
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
    )


@pytest.fixture
def log_env(monkeypatch, tmp_path):
    serial = tmp_path / "vm.serial.log"
    serial.write_text(SERIAL)
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: _instance(str(serial)))
    return serial


def _run(capsys, *argv: str) -> tuple[int, dict]:
    rc = cli.main(["--format", "json", "log", *argv])
    return rc, json.loads(capsys.readouterr().out)


def test_grep_searches_the_whole_log_not_just_the_tail(monkeypatch, tmp_path, capsys):
    """Regression: --tail applied before --grep produced false negatives.

    A 50-line default window silently scoped crash triage to the end of the
    boot, so `--grep "BUG:"` reported no matches while the report sat 200
    lines up.
    """
    serial = tmp_path / "vm.serial.log"
    serial.write_text("BUG: KASAN: slab-use-after-free\n" + "filler\n" * 500)
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: _instance(str(serial)))

    rc, payload = _run(capsys, "--grep", "BUG: KASAN")

    assert rc == 0
    assert payload["matches"] == 1
    assert payload["scope"] == "full"


def test_explicit_tail_still_narrows_the_grep_window(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    serial.write_text("BUG: KASAN: slab-use-after-free\n" + "filler\n" * 500)
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: _instance(str(serial)))

    rc, payload = _run(capsys, "--grep", "BUG: KASAN", "--tail", "10")

    assert rc == 0
    assert payload["matches"] == 0
    assert payload["scope"] == "last 10 lines"


def test_plain_tail_default_is_unchanged_at_50(monkeypatch, tmp_path, capsys):
    """Widening the scope must apply to --grep only, not to a bare `qmu log`."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text("".join(f"line-{i}\n" for i in range(200)))
    monkeypatch.setattr(guest, "find_instance", lambda vm=None: _instance(str(serial)))

    rc, payload = _run(capsys)

    assert rc == 0
    assert len(payload["log"].splitlines()) == 50


def test_grep_keeps_only_matching_lines(log_env, capsys):
    rc, payload = _run(capsys, "--grep", "results")

    assert rc == 0
    assert payload["log"] == "=== results ===\n"
    assert payload["matches"] == 1
    assert payload["grep"] == "results"


def test_grep_is_a_regex(log_env, capsys):
    rc, payload = _run(capsys, "--grep", r"0x[0-9a-f]{16}")

    assert rc == 0
    assert payload["log"] == "leaked 0xffff888012345678\n"


def test_context_includes_surrounding_lines(log_env, capsys):
    rc, payload = _run(capsys, "--grep", "results", "--context", "2")

    assert rc == 0
    assert payload["log"].splitlines() == [
        "before-1",
        "before-2",
        "=== results ===",
        "after-1",
        "after-2",
    ]


def test_disjoint_context_windows_are_separated(log_env, capsys):
    rc, payload = _run(capsys, "--grep", "Linux version|Done", "--context", "1")

    lines = payload["log"].splitlines()
    assert "--" in lines
    assert payload["matches"] == 2


def test_no_match_is_success_with_an_explicit_message(log_env, capsys):
    rc, payload = _run(capsys, "--grep", "no such line")

    assert rc == 0
    assert payload["ok"] is True
    assert payload["log"] == ""
    assert payload["matches"] == 0
    assert payload["empty"] is True


def test_no_match_text_mode_names_the_scope_searched(log_env, capsys):
    rc = cli.main(["log", "--grep", "no such line"])

    assert rc == 0
    assert "No lines in the serial log matched" in capsys.readouterr().out


def test_no_match_under_explicit_tail_says_it_was_windowed(log_env, capsys):
    """A zero-match result must never be mistaken for a claim about the log."""
    rc = cli.main(["log", "--grep", "Linux version", "--tail", "2"])

    assert rc == 0
    assert "the last 2 lines" in capsys.readouterr().out


def test_full_emits_the_whole_log_ignoring_tail(log_env, capsys):
    rc, payload = _run(capsys, "--full", "--tail", "1")

    assert rc == 0
    assert payload["log"] == SERIAL


def test_tail_still_bounds_output_by_default(log_env, capsys):
    rc, payload = _run(capsys, "--tail", "2")

    assert rc == 0
    assert payload["log"].splitlines() == ["leaked 0xffff888012345678", "Done."]


def test_grep_composes_with_full(log_env, capsys):
    rc, payload = _run(capsys, "--full", "--grep", "before")

    assert rc == 0
    assert payload["log"].splitlines() == ["before-1", "before-2"]


def test_plain_log_payload_has_no_grep_keys(log_env, capsys):
    """The pre-existing envelope shape must be unchanged when --grep is absent."""
    rc, payload = _run(capsys, "--tail", "1")

    assert rc == 0
    assert set(payload) == {"ok", "log", "available", "empty"}


def test_invalid_grep_regex_is_reported_not_raised(log_env, capsys):
    rc = cli.main(["log", "--grep", "unbalanced("])

    assert rc == 1
    assert "Invalid --grep regex" in capsys.readouterr().err
