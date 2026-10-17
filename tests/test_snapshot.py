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
alone cannot decide, and after a failed `loadvm` restores the pre-load run
state ONLY when QEMU provably refused before restoring anything -- a load
that failed after the disks were reverted is left paused (#87).
"""

from __future__ import annotations

import pytest

from qmu.snapshot import (
    SnapshotResult,
    parse_snapshot_list,
    save_snapshot,
    load_snapshot,
    loadvm_restore_state,
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

    def __init__(self, response: str, *, listing: str = "", running=None, stopped="paused"):
        self._response = response
        self._listing = listing
        self._running = list(running or [])
        self._stopped = stopped
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
            return {"running": running, "status": "running" if running else self._stopped}
        return {}


@pytest.mark.parametrize("vm_size", ["1.36 GiB", "1e+03 GiB"])
def test_large_snapshots_remain_visible_and_operable(vm_size):
    listing = _LISTED_CLEAN.replace("486 MiB", vm_size)

    rows = parse_snapshot_list(listing)
    assert [(row["tag"], row["vm_size"]) for row in rows] == [("clean", vm_size)]
    assert save_snapshot(FakeQMP("", listing=listing), "clean").ok is True
    assert delete_snapshot(FakeQMP("", listing=listing), "clean").ok is True


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
    qmp = FakeQMP("", listing=_LISTED_CLEAN)
    assert load_snapshot(qmp, "clean") == SnapshotResult(True, "Snapshot 'clean' loaded.")
    assert qmp.calls == ["info snapshots", "loadvm clean"]
    assert "cont" not in qmp.qmp_calls


def test_successful_load_resumes_a_guest_stopped_by_a_failed_restore():
    """The recovery #87's hint names: `hmp_loadvm` restarts the guest after a
    successful load only if it was running before, so loading a known-good
    tag over a `restore-vm` pause would succeed and leave the guest stopped
    with no error saying so."""
    qmp = FakeQMP("", listing=_LISTED_CLEAN, running=[False, True], stopped="restore-vm")
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(True, "Snapshot 'clean' loaded.", resumed=True)
    assert qmp.qmp_calls == ["query-status", "cont", "query-status"]


@pytest.mark.parametrize("stopped", ["paused", "debug"])
def test_successful_load_leaves_an_operator_or_debugger_pause_alone(stopped):
    qmp = FakeQMP("", listing=_LISTED_CLEAN, running=[False], stopped=stopped)
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(True, "Snapshot 'clean' loaded.")
    assert "cont" not in qmp.qmp_calls


def test_load_missing_tag_never_reaches_loadvm():
    """QEMU's hmp_loadvm stops the guest BEFORE it looks for the tag, so the
    common typo used to pause a running guest and need a resume; the listing
    pre-check (the same one `delete` does) keeps loadvm from being issued at
    all, and the guest never stops."""
    qmp = FakeQMP("", listing="", running=[True])
    result = load_snapshot(qmp, "nope")
    assert result == SnapshotResult(
        False, "Snapshot 'nope' does not exist", reason="missing", restore_state="none"
    )
    assert qmp.calls == ["info snapshots"]
    assert qmp.qmp_calls == []


# The receipt-165 failure verbatim (QEMU 8.2.2): a snapshot saved under an
# e1000 NIC loaded into a virtio-net boot. QEMU had already reverted the disks
# (`bdrv_all_goto_snapshot`) and reset the machine when the vmstate load hit
# the unknown RAM block; what is left is pre-snapshot devices over
# post-snapshot disks, stopped in `restore-vm`.
_INCOMPATIBLE_DEVICE_LOAD = (
    'Unknown ramblock "0000:00:03.0/e1000.rom", cannot accept migration\r\n'
    "error while loading state for instance 0x0 of device 'ram'\r\n"
    "Error: Error -22 while loading VM state"
)


def test_load_error_is_a_failure_with_the_text_intact():
    """A loadvm HMP error ('Missing section footer / Section footer error') must
    survive verbatim in the result so the CLI can show it."""
    err = "Missing section footer for slirp\nError: Section footer error, section_id: 1"
    qmp = FakeQMP(err, listing=_LISTED_CLEAN, running=[True, False])
    result = load_snapshot(qmp, "clean")
    assert result.ok is False
    assert "Missing section footer" in result.message
    assert "Section footer error" in result.message
    assert result.restore_state == "partial"


@pytest.mark.parametrize("message, expected", [
    ("Error: Snapshot 'nope' does not exist in one or more devices", "none"),
    ("Snapshot 'nope' does not exist in one or more devices", "none"),
    ("Error: This is a disk-only snapshot. Revert to it  offline using qemu-img", "none"),
    ("Error: No block device supports snapshots", "none"),
    ("Error: Device 'ide0-hd0' is writable but does not support snapshots", "none"),
    ('loadvm: extraneous characters at the end of line\r\nTry "help loadvm" for more information', "none"),
    (_INCOMPATIBLE_DEVICE_LOAD, "partial"),
    ("Missing section footer for slirp\nError: Section footer error, section_id: 1", "partial"),
    ("Error: Could not open VM state file", "partial"),
    ("Error: Could not load snapshot 'clean' on 'drive0': Failed to load snapshot", "partial"),
    ("Error: Error -5 while loading VM state", "partial"),
    # A pre-restore line followed by a post-restore one is still partial.
    ("Error: Snapshot 'x' does not exist\nError: Error -22 while loading VM state", "partial"),
    # Anything qmu cannot place must not be guessed safe.
    ("Error: Some refusal this table has never seen", "unknown"),
    ("", "unknown"),
])
def test_loadvm_restore_state_places_qemu_error_forms(message, expected):
    assert loadvm_restore_state(message) == expected


def test_failed_load_resumes_a_guest_that_was_running():
    """QEMU refused before touching the machine (the tag is listed -- a
    partial, non-loadable snapshot passes the pre-check -- but loadvm's own
    check says no): the guest is exactly what it was, so the pause QEMU
    applied first is undone."""
    err = "Error: Snapshot 'clean' does not exist in one or more devices"
    # before: running; after loadvm: stopped; after cont: running again
    qmp = FakeQMP(err, listing=_LISTED_CLEAN, running=[True, False, True])
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(
        False, err, resumed=True, guest_paused=False, reason="missing",
        restore_state="none",
    )
    assert qmp.qmp_calls == ["query-status", "query-status", "cont", "query-status"]


def test_failed_load_reports_guest_paused_when_cont_does_not_take():
    err = "Error: Snapshot 'clean' does not exist in one or more devices"
    qmp = FakeQMP(err, listing=_LISTED_CLEAN, running=[True, False, False])
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(
        False, err, resumed=False, guest_paused=True, reason="missing",
        restore_state="none",
    )


def test_failed_load_leaves_an_already_paused_guest_alone():
    """A guest the operator paused on purpose stays paused: qmu only restores
    the state IT saw before the load."""
    err = "Error: Snapshot 'clean' does not exist in one or more devices"
    qmp = FakeQMP(err, listing=_LISTED_CLEAN, running=[False])
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(False, err, reason="missing", restore_state="none")
    assert "cont" not in qmp.qmp_calls


@pytest.mark.parametrize("err, restore_state", [
    (_INCOMPATIBLE_DEVICE_LOAD, "partial"),
    ("Error: Some refusal this table has never seen", "unknown"),
])
def test_failed_load_after_restoration_began_is_left_paused(err, restore_state):
    """#87: the disks are already rewound when the vmstate load fails, so the
    paused machine is inconsistent. `cont` on it is not a rollback -- the old
    code issued one anyway and reported `resumed: true` -- so no `cont` is
    sent and the pause is reported as the state the caller must deal with."""
    qmp = FakeQMP(err, listing=_LISTED_CLEAN, running=[True, False])
    result = load_snapshot(qmp, "clean")
    assert result == SnapshotResult(
        False, err, resumed=False, guest_paused=True, reason="hmp",
        restore_state=restore_state,
    )
    assert "cont" not in qmp.qmp_calls
    assert qmp.calls == ["info snapshots", "loadvm clean"]


def test_failed_partial_load_of_a_paused_guest_still_reports_the_pause():
    """The inconsistency does not depend on the pre-load run state."""
    qmp = FakeQMP(_INCOMPATIBLE_DEVICE_LOAD, listing=_LISTED_CLEAN, running=[False, False])
    result = load_snapshot(qmp, "clean")
    assert result.guest_paused is True
    assert result.restore_state == "partial"
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


# --- savevm budget (#73) ---


@pytest.mark.parametrize(
    "memory, gib",
    [
        ("4G", 4.0), ("1G", 1.0), ("4096M", 4.0), ("512M", 0.5), ("2048", 2.0),
        ("1.5G", 1.5), ("4GiB", 4.0), ("size=4G,slots=2,maxmem=8G", 4.0),
        ("1T", 1024.0), ("", None), (None, None), ("lots", None),
    ],
)
def test_memory_gib_reads_qemu_m_values(memory, gib):
    from qmu.snapshot import memory_gib

    assert memory_gib(memory) == gib


@pytest.mark.parametrize(
    "memory, budget",
    [("1G", 80.0), ("4G", 140.0), ("16G", 380.0), ("512M", 70.0), ("lots", 140.0), (None, 140.0)],
)
def test_savevm_timeout_is_base_plus_per_gib_with_a_4gib_fallback(memory, budget):
    """60 s + 20 s/GiB: >= 3x the loaded measurement at every size (4 GiB
    dirty RAM under 4 dd writers + 10 CPU burners took 22.2 s), and never a
    zero budget for a size qmu cannot read."""
    from qmu.snapshot import SAVEVM_BASE_SECONDS, SAVEVM_SECONDS_PER_GIB, savevm_timeout

    assert (SAVEVM_BASE_SECONDS, SAVEVM_SECONDS_PER_GIB) == (60.0, 20.0)
    assert savevm_timeout(memory) == budget


def test_save_passes_its_budget_to_savevm_and_timeout_propagates():
    from qmu.qmp import QMPTimeoutError
    from qmu.snapshot import list_snapshots

    class BudgetQMP(FakeQMP):
        def __init__(self):
            super().__init__("", listing=_LISTED_CLEAN)
            self.timeouts = []

        def execute_hmp(self, command_line, timeout=30.0):
            self.timeouts.append((command_line, timeout))
            if command_line.startswith("savevm") and timeout < 1:
                raise QMPTimeoutError(command_line, timeout)
            return super().execute_hmp(command_line)

    qmp = BudgetQMP()
    assert save_snapshot(qmp, "clean", timeout=140.0).ok is True
    assert qmp.timeouts[0] == ("savevm clean", 140.0)
    with pytest.raises(QMPTimeoutError):
        save_snapshot(qmp, "clean", timeout=0.5)
    list_snapshots(qmp, timeout=300.0)
    assert qmp.timeouts[-1] == ("info snapshots", 300.0)
