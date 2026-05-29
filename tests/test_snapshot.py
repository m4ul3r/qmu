"""Tests for qmu.snapshot — parse_snapshot_list + save/load message handling.

These tests require NO VM. parse_snapshot_list is pure string parsing fed by HMP
'info snapshots' output; save/load/delete are driven by a tiny FakeQMP stub.

parse_snapshot_list tests pin the regex against both the QEMU 11 vm_clock format
('HHHH:MM:SS.mmm') seen in tests/live-transcript.md and the older docstring
format (with a trailing ICOUNT column).

The save/load/delete message tests pin the BY-DESIGN contract: the snapshot.py
layer returns the HMP output VERBATIM (including any error text). HMP loadvm/savevm
errors arrive as a normal result string, not a QMP protocol error, so snapshot.py
deliberately does NOT classify them — the CLI layer (cli._snapshot_failed, see
test_snapshot_exit.py) inspects the returned text and sets a non-zero exit code.
test_load_error_passed_through_as_message guards that the raw error text reaches
the caller intact so the CLI can detect it.

Findings exercised: TC-9 / TC-10 / SNAP-1 (the failure-detection half lives in
test_snapshot_exit.py).
"""

from __future__ import annotations

import pytest

from qmu.snapshot import (
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


# --- save/load/delete message handling via FakeQMP ---

class FakeQMP:
    """Minimal QMPClient stand-in: execute_hmp returns a canned string.

    Matches the real signature qmp.execute_hmp(command_line, timeout) -> str.
    """

    def __init__(self, response: str):
        self._response = response
        self.calls: list[str] = []

    def execute_hmp(self, command_line: str, timeout: float = 30.0) -> str:
        self.calls.append(command_line)
        return self._response


def test_save_empty_output_synthesizes_success_message():
    qmp = FakeQMP("")
    msg = save_snapshot(qmp, "clean")
    assert msg == "Snapshot 'clean' saved."
    assert qmp.calls == ["savevm clean"]


def test_save_passes_through_warning_text_verbatim():
    """Slirp save warnings (live-transcript.md:205-206) come back verbatim."""
    warn = "warning: Slirp: Save of field slirp_bootpclient/macaddr failed"
    qmp = FakeQMP(warn)
    msg = save_snapshot(qmp, "clean")
    assert msg == warn


def test_load_empty_output_synthesizes_success_message():
    qmp = FakeQMP("")
    msg = load_snapshot(qmp, "clean")
    assert msg == "Snapshot 'clean' loaded."
    assert qmp.calls == ["loadvm clean"]


def test_delete_empty_output_synthesizes_success_message():
    qmp = FakeQMP("")
    msg = delete_snapshot(qmp, "clean")
    assert msg == "Snapshot 'clean' deleted."
    assert qmp.calls == ["delvm clean"]


def test_load_error_passed_through_as_message():
    """A loadvm HMP error ('Missing section footer / Section footer error') is
    returned VERBATIM by load_snapshot so the CLI layer (cli._snapshot_failed)
    can detect it and exit non-zero. snapshot.py deliberately does not classify
    it (HMP errors arrive as a result string, not a QMP protocol error)."""
    err = "Missing section footer for slirp\nError: Section footer error, section_id: 1"
    qmp = FakeQMP(err)
    msg = load_snapshot(qmp, "clean")
    # The raw error text must survive intact for the CLI to inspect.
    assert "Missing section footer" in msg
    assert "Section footer error" in msg
