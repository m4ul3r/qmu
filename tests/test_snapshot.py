"""Tests for qmu.snapshot — parse_snapshot_list + save/load/delete outcomes.

These tests require NO VM. parse_snapshot_list is pure string parsing fed by HMP
'info snapshots' output; save/load/delete are driven by a tiny FakeQMP stub.

parse_snapshot_list tests pin the regex against both the QEMU 11 vm_clock format
('HHHH:MM:SS.mmm') seen in tests/live-transcript.md and the older docstring
format (with a trailing ICOUNT column).

The save/load/delete tests pin the outcome contract: HMP loadvm/savevm/delvm
errors arrive as a normal result string, not a QMP protocol error, and HMP is
silent for some failures (`delvm` of a missing tag) and chatty for some
successes (the benign savevm slirp warning). snapshot.py therefore classifies
the text with `qmp.hmp_failed`, cross-checks `info snapshots` where the text
alone cannot decide, and restores the pre-load run state when `loadvm` fails
(QEMU stops the guest first and restarts it only on success).
"""

from __future__ import annotations

import pytest

from qmu.snapshot import (
    SnapshotResult,
    parse_snapshot_list,
    save_snapshot,
    load_snapshot,
    delete_snapshot,
)


# --- parse_snapshot_list ---

# Verbatim QEMU 11 'info snapshots' block, matching tests/live-transcript.md:212-214.
QEMU11_SINGLE = """\
List of snapshots present on all disks:
ID        TAG               VM SIZE                DATE       VM CLOCK     ICOUNT
--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992
"""

# Older docstring-style format with a trailing ICOUNT column.
OLDER_WITH_ICOUNT = """\
List of snapshots present on all disks:
ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
1         boot              913 MiB 2026-03-25 23:42:16 00:00:28.552 123456789
"""

MULTI_ROW = """\
List of snapshots present on all disks:
ID        TAG               VM SIZE                DATE       VM CLOCK     ICOUNT
--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992
2         post-trigger      512 MiB 2026-05-28 23:15:03 0000:02:10.005
"""

NO_SNAPSHOTS = ""


def test_parse_qemu11_single_row():
    rows = parse_snapshot_list(QEMU11_SINGLE)
    assert len(rows) == 1
    assert rows[0] == {
        "id": "--",
        "tag": "clean",
        "vm_size": "486 MiB",
        "date": "2026-05-28",
        "time": "23:11:52",
        "vm_clock": "0000:01:01.992",
    }


def test_parse_older_format_with_icount():
    rows = parse_snapshot_list(OLDER_WITH_ICOUNT)
    assert len(rows) == 1
    r = rows[0]
    assert r["id"] == "1"
    assert r["tag"] == "boot"
    assert r["vm_size"] == "913 MiB"
    assert r["date"] == "2026-03-25"
    assert r["time"] == "23:42:16"
    # trailing ICOUNT column must NOT bleed into vm_clock
    assert r["vm_clock"] == "00:00:28.552"


def test_parse_multiple_rows_in_order():
    rows = parse_snapshot_list(MULTI_ROW)
    assert [r["tag"] for r in rows] == ["clean", "post-trigger"]
    assert rows[1]["vm_size"] == "512 MiB"


def test_parse_skips_header_and_blank_lines():
    rows = parse_snapshot_list(
        "List of snapshots present on all disks:\n"
        "ID        TAG               VM SIZE                DATE       VM CLOCK\n"
        "\n"
    )
    assert rows == []


def test_parse_empty_returns_empty_list():
    assert parse_snapshot_list(NO_SNAPSHOTS) == []


# --- save/load/delete outcomes via FakeQMP ---

_LISTED_CLEAN = """\
List of snapshots present on all disks:
ID        TAG               VM SIZE                DATE       VM CLOCK     ICOUNT
--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992
"""


class FakeQMP:
    """Minimal QMPClient stand-in.

    `execute_hmp` answers `info snapshots` from `listing` and every other verb
    with `response`; `execute` answers `query-status` from `running` (a list
    of successive answers) and records `cont`.
    """

    def __init__(self, response: str, *, listing: str = "", running=None):
        self._response = response
        self._listing = listing
        self._running = list(running or [])
        self.calls: list[str] = []
        self.qmp_calls: list[str] = []

    def execute_hmp(self, command_line: str, timeout: float = 30.0) -> str:
        self.calls.append(command_line)
        if command_line == "info snapshots":
            return self._listing
        return self._response

    def execute(self, command, arguments=None, timeout=30.0):
        self.qmp_calls.append(command)
        if command == "query-status":
            running = self._running.pop(0) if self._running else True
            return {"running": running, "status": "running" if running else "paused"}
        return {}


def test_save_empty_output_synthesizes_success_when_listed():
    qmp = FakeQMP("", listing=_LISTED_CLEAN)
    assert save_snapshot(qmp, "clean") == SnapshotResult(True, "Snapshot 'clean' saved.")
    assert qmp.calls == ["savevm clean", "info snapshots"]


def test_save_passes_through_warning_text_verbatim_when_listed():
    """Slirp save warnings (live-transcript.md:205-206) come back verbatim and
    are NOT a failure: the snapshot is listable afterwards."""
    warn = "warning: Slirp: Save of field slirp_bootpclient/macaddr failed"
    qmp = FakeQMP(warn, listing=_LISTED_CLEAN)
    assert save_snapshot(qmp, "clean") == SnapshotResult(True, warn)


def test_save_hmp_parse_error_is_a_failure_without_listing():
    """`savevm has space` → HMP parse error, nothing written (audit D4)."""
    err = 'savevm: extraneous characters at the end of line\r\nTry "help savevm" for more information'
    qmp = FakeQMP(err, listing="")
    result = save_snapshot(qmp, "has space")
    assert result.ok is False
    assert "extraneous characters" in result.message
    assert result.reason == "bad_name"
    assert qmp.calls == ["savevm has space"]


def test_save_silent_but_unlisted_is_a_failure():
    qmp = FakeQMP("", listing="")
    result = save_snapshot(qmp, "clean")
    assert result.ok is False
    assert "not listed" in result.message
    assert result.reason == "hmp"


def test_load_empty_output_synthesizes_success_message():
    qmp = FakeQMP("")
    assert load_snapshot(qmp, "clean") == SnapshotResult(True, "Snapshot 'clean' loaded.")
    assert qmp.calls == ["loadvm clean"]
    assert "cont" not in qmp.qmp_calls


def test_load_error_is_a_failure_with_the_text_intact():
    """A loadvm HMP error ('Missing section footer / Section footer error') must
    survive verbatim in the result so the CLI can show it."""
    err = "Missing section footer for slirp\nError: Section footer error, section_id: 1"
    qmp = FakeQMP(err, running=[True, True])
    result = load_snapshot(qmp, "clean")
    assert result.ok is False
    assert "Missing section footer" in result.message
    assert "Section footer error" in result.message


def test_failed_load_resumes_a_guest_that_was_running():
    """QEMU's hmp_loadvm stops the guest before it looks for the tag and only
    restarts it on success (audit D2): a typo must not leave it paused."""
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    # before: running; after loadvm: stopped; after cont: running again
    qmp = FakeQMP(err, running=[True, False, True])
    result = load_snapshot(qmp, "nope")
    assert result == SnapshotResult(
        False, err, resumed=True, guest_paused=False, reason="missing"
    )
    assert qmp.qmp_calls == ["query-status", "query-status", "cont", "query-status"]


def test_failed_load_reports_guest_paused_when_cont_does_not_take():
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    qmp = FakeQMP(err, running=[True, False, False])
    result = load_snapshot(qmp, "nope")
    assert result == SnapshotResult(
        False, err, resumed=False, guest_paused=True, reason="missing"
    )


def test_failed_load_leaves_an_already_paused_guest_alone():
    """A guest the operator paused on purpose stays paused: qmu only restores
    the state IT saw before the load."""
    err = "Error: Snapshot 'nope' does not exist in one or more devices"
    qmp = FakeQMP(err, running=[False])
    result = load_snapshot(qmp, "nope")
    assert result == SnapshotResult(False, err, reason="missing")
    assert "cont" not in qmp.qmp_calls


def test_delete_listed_tag_synthesizes_success_message():
    qmp = FakeQMP("", listing=_LISTED_CLEAN)
    assert delete_snapshot(qmp, "clean") == SnapshotResult(True, "Snapshot 'clean' deleted.")
    assert qmp.calls == ["info snapshots", "delvm clean"]


def test_delete_missing_tag_is_a_failure_and_sends_no_delvm():
    """HMP `delvm` is silent for a missing tag (audit D3), so the tag is
    checked first and the silent no-op never reads as success."""
    qmp = FakeQMP("", listing="")
    result = delete_snapshot(qmp, "never-existed")
    assert result.ok is False
    assert "does not exist" in result.message
    assert result.reason == "missing"
    assert qmp.calls == ["info snapshots"]
