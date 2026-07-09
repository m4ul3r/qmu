"""Tests for qmu.serial.extract_crash — crash-report extraction from serial logs.

These tests require NO VM. They feed synthetic serial-log text (the same shape
the real KASAN / sysrq panics produced in tests/live-transcript.md) to
extract_crash() and assert the FULL report is returned.

Findings exercised: SER-1 / QMU-2 / TC-1 (H2).

Root cause that was fixed (serial.py): the end-of-panic banner line
"---[ end Kernel panic - not syncing: ... ]---" contains the substring
"Kernel panic", which matches a CRASH_START_PATTERN via .search(). The old
extract_crash recorded the LAST start-matching line, so the end banner became
the detected crash_start; the capture loop then immediately hit a
CRASH_END_PATTERN on that same line and returned a single useless line.

The fix makes any CRASH_END line END-only (never a start) and anchors the start
on the FIRST start pattern of the last crash block, so the whole report is
captured. The assertions below pin that FIXED behavior:

  * test_extract_crash_kasan_full_report / test_extract_crash_sysrq_panic assert
    the full multi-line report (BUG/Call Trace/RIP + end banner) is returned.
  * test_end_banner_alone_is_not_a_standalone_start guards that the end banner
    is END-only and never a standalone start.
  * the clean-boot / missing-file / empty-file tests guard the None paths.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qmu.serial import (
    _is_crash_end,
    _is_crash_start,
    extract_crash,
    serial_log_offset,
    tail_log,
)


# A realistic KASAN slab-use-after-free report, exactly as it appears on the
# serial console: the genuine report comes first (BUG/Call Trace/RIP), and the
# kernel then terminates with the "---[ end Kernel panic ... ]---" banner.
KASAN_UAF_LOG = """\
[   86.640001] Run /sbin/init as init process
[   86.640500] uaf: loading out-of-tree module taints kernel.
[   86.641000] ==================================================================
[   86.641500] BUG: KASAN: slab-use-after-free in uaf_init+0x80/0x120 [uaf]
[   86.642000] Read of size 8 at addr ffff88800abc1000 by task insmod/142
[   86.642500]
[   86.643000] CPU: 0 PID: 142 Comm: insmod Tainted: G    B   6.6.75 #1
[   86.643500] Call Trace:
[   86.644000]  <TASK>
[   86.644100]  dump_stack_lvl+0x4d/0x70
[   86.644200]  print_report+0xc4/0x620
[   86.644300]  kasan_report+0xb6/0xf0
[   86.644400]  uaf_init+0x80/0x120 [uaf]
[   86.644500]  do_one_initcall+0x8e/0x2a0
[   86.644600]  </TASK>
[   86.645000] RIP: 0010:uaf_init+0x80/0x120 [uaf]
[   86.645500] ==================================================================
[   86.646000] Kernel panic - not syncing: kasan.fault=panic set ...
[   86.646174] ---[ end Kernel panic - not syncing: kasan.fault=panic set ... ]---
"""

# A non-KASAN sysrq-triggered panic. The real "Kernel panic - not syncing"
# START line precedes the matching end banner.
SYSRQ_PANIC_LOG = """\
[    6.670000] sysrq: Trigger a crash
[    6.671000] Kernel panic - not syncing: sysrq triggered crash
[    6.671500] CPU: 1 PID: 99 Comm: bash Not tainted 6.6.75 #1
[    6.672000] Call Trace:
[    6.672100]  <TASK>
[    6.672200]  dump_stack_lvl+0x4d/0x70
[    6.672300]  panic+0x33b/0x340
[    6.672400]  sysrq_handle_crash+0x18/0x20
[    6.672500]  </TASK>
[    6.673000] RIP: 0010:sysrq_handle_crash+0x18/0x20
[    6.673365] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---
"""

# A relocatable (KASLR) kernel prints a multi-line panic EPILOGUE: a
# "Kernel Offset:" line (which is itself a CRASH_END pattern) immediately before
# the "---[ end Kernel panic ... ]---" banner. Both belong to the SAME crash and
# must not be treated as block boundaries. This is the exact shape the real
# linux-6.6.75 VM emitted (tests/live-transcript.md). Regression guard for the
# block-boundary bug the adversarial review caught.
KASLR_PANIC_LOG = """\
[    6.517000] sysrq: Trigger a crash
[    6.519126] BUG: KASAN: slab-use-after-free in uaf_init+0x4b/0xff0 [uaf]
[    6.519407] Read of size 1 at addr ffff88800abc1000 by task insmod/142
[    6.519600] CPU: 0 PID: 142 Comm: insmod Tainted: G    B   6.6.75 #1
[    6.519700] Call Trace:
[    6.519800]  <TASK>
[    6.519900]  dump_stack_lvl+0x4d/0x70
[    6.520000]  uaf_init+0x4b/0xff0 [uaf]
[    6.520100]  </TASK>
[    6.520200] RIP: 0010:uaf_init+0x4b/0xff0 [uaf]
[    6.519407] Kernel panic - not syncing: kasan.fault=panic set ...
[    6.530887] Kernel Offset: 0x19c00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[    6.531537] ---[ end Kernel panic - not syncing: kasan.fault=panic set ... ]---
"""

# CORR-7: a WARNING/BUG that fires under panic_on_warn prints its OWN report
# epilogue "---[ end trace ... ]---" and is then IMMEDIATELY followed by the
# fatal "Kernel panic - not syncing" + final "---[ end Kernel panic ]---"
# banner. The interior "---[ end trace ]---" is NOT the end of the crash event;
# capture must span the FULL block [first start .. LAST end-marker], not stop
# at the interior marker (which would drop the WARNING root cause, Call Trace
# and RIP — the only useful content). Regression guard for interior-end-marker
# truncation.
WARN_PANIC_ON_WARN_LOG = """\
[   10.000000] ------------[ cut here ]------------
[   10.000100] WARNING: CPU: 0 PID: 142 at mm/slub.c:1234 kfree+0x1a/0x2b
[   10.000200] Modules linked in: uaf
[   10.000300] CPU: 0 PID: 142 Comm: insmod Tainted: G    W   6.6.75 #1
[   10.000400] Call Trace:
[   10.000500]  <TASK>
[   10.000600]  dump_stack_lvl+0x4d/0x70
[   10.000700]  __warn+0x81/0x130
[   10.000800]  kfree+0x1a/0x2b
[   10.000900]  </TASK>
[   10.001000] RIP: 0010:kfree+0x1a/0x2b
[   10.001100] ---[ end trace 0000000000000000 ]---
[   10.001200] Kernel panic - not syncing: panic_on_warn set ...
[   10.001300] CPU: 0 PID: 142 Comm: insmod Tainted: G    W   6.6.75 #1
[   10.001400] Kernel Offset: 0x19c00000 from 0xffffffff81000000
[   10.001500] ---[ end Kernel panic - not syncing: panic_on_warn set ... ]---
"""

# Two genuinely DISTINCT crashes: an earlier WARNING the kernel survived (normal
# output resumes for many lines), then a later fatal panic. extract_crash must
# return ONLY the last crash event, never leak the earlier one.
TWO_DISTINCT_CRASHES_LOG = """\
[    5.000000] WARNING: CPU: 0 PID: 10 at foo.c:1 old_warn+0x1/0x2
[    5.000100] Call Trace:
[    5.000200]  old_warn+0x1/0x2
[    5.000300] ---[ end trace 1111111111111111 ]---
[    6.000000] systemd[1]: Started Some Service.
[    6.100000] EXT4-fs (sda): mounted filesystem
[    6.200000] random: crng init done
[    6.300000] usb 1-1: new high-speed USB device
[    6.400000] eth0: link becomes ready
[    6.500000] NetworkManager: connection activated
[    6.600000] cron[123]: (CRON) STARTUP
[    6.700000] sshd[200]: Server listening on 0.0.0.0 port 22
[    9.000000] BUG: KASAN: slab-use-after-free in real_bug+0x5/0x6 [uaf]
[    9.000100] Read of size 8 at addr ffff88800abc1000 by task insmod/142
[    9.000200] Call Trace:
[    9.000300]  real_bug+0x5/0x6 [uaf]
[    9.000400] RIP: 0010:real_bug+0x5/0x6 [uaf]
[    9.000500] Kernel panic - not syncing: kasan.fault=panic set
[    9.000600] ---[ end Kernel panic - not syncing: kasan.fault=panic set ]---
"""

CLEAN_BOOT_LOG = """\
[    0.000000] Linux version 6.6.75 (builder@host) #1 SMP
[    0.500000] Command line: console=ttyS0 root=/dev/sda
[    1.200000] systemd[1]: Started Login Service.
[    2.000000] Debian GNU/Linux 12 qmu ttyS0
[    2.100000] qmu login: root (automatic login)
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


def test_serial_log_offset_is_binary_byte_size(tmp_path):
    log = tmp_path / "bytes.serial.log"
    text = "µboot\n"
    log.write_text(text)
    assert serial_log_offset(log) == len(text.encode("utf-8"))


def test_serial_log_offset_missing_or_unreadable_is_zero(tmp_path, monkeypatch):
    missing = tmp_path / "missing.serial.log"
    assert serial_log_offset(missing) == 0

    log = tmp_path / "denied.serial.log"
    log.write_text("boot\n")
    original_open = Path.open

    def deny_open(self, *args, **kwargs):
        if self == log:
            raise PermissionError("denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_open)
    assert serial_log_offset(log) == 0


def test_extract_crash_kasan_full_report(tmp_path):
    """The KASAN report (BUG/Call Trace/RIP) must be returned in full, not just
    the trailing '---[ end Kernel panic ... ]---' banner."""
    log = _write(tmp_path, "kasan.serial.log", KASAN_UAF_LOG)
    report = extract_crash(log)

    assert report is not None, "extract_crash returned None on a real KASAN panic"
    # The single most important content for an exploit-dev agent:
    assert "BUG: KASAN: slab-use-after-free in uaf_init" in report
    assert "Call Trace:" in report
    assert "RIP: 0010:uaf_init" in report
    # The end banner should still be included as the terminator:
    assert "---[ end Kernel panic" in report
    # And it must be a multi-line report, not a single banner line:
    assert report.count("\n") > 5, (
        "extract_crash collapsed the crash to a single line "
        f"(got {report.count(chr(10))} newlines): {report!r}"
    )


def test_extract_crash_sysrq_panic(tmp_path):
    """The 'Kernel panic - not syncing' START line and the Call Trace must be
    captured, not only the end banner."""
    log = _write(tmp_path, "sysrq.serial.log", SYSRQ_PANIC_LOG)
    report = extract_crash(log)

    assert report is not None
    assert "Kernel panic - not syncing: sysrq triggered crash" in report
    assert "Call Trace:" in report
    assert "RIP: 0010:sysrq_handle_crash" in report
    assert "---[ end Kernel panic" in report
    assert report.count("\n") > 3, (
        "extract_crash collapsed the sysrq panic to a single line: " + repr(report)
    )


def test_extract_crash_kaslr_panic_with_kernel_offset(tmp_path):
    """Regression: a relocatable kernel emits 'Kernel Offset:' (an end-pattern)
    BEFORE the '---[ end Kernel panic ]---' banner. Both are the same crash's
    epilogue and must NOT split the block — the full BUG/Call Trace/RIP report
    must still be returned, not None and not a fragment."""
    log = _write(tmp_path, "kaslr.serial.log", KASLR_PANIC_LOG)
    report = extract_crash(log)

    assert report is not None, (
        "extract_crash returned None on a realistic KASLR panic — the "
        "'Kernel Offset:' line was wrongly treated as a crash-block boundary"
    )
    assert "BUG: KASAN: slab-use-after-free in uaf_init" in report
    assert "Call Trace:" in report
    assert "RIP: 0010:uaf_init" in report
    assert "Kernel Offset:" in report          # epilogue kept, not used as a split
    assert "---[ end Kernel panic" in report   # captured through the final banner
    assert report.count("\n") > 8, (
        "extract_crash dropped most of the KASLR panic report: " + repr(report)
    )


def test_end_banner_alone_is_not_a_standalone_start():
    """Regression guard: the end-of-panic banner must NOT be treated as the START
    of a crash. It contains the substring 'Kernel panic', which is the root cause
    of the truncation bug; the fix makes any end-marker line END-only."""
    end_banner = "[   86.646174] ---[ end Kernel panic - not syncing: kasan.fault=panic set ... ]---"
    assert _is_crash_end(end_banner), "sanity: the banner is an end marker"
    assert not _is_crash_start(end_banner), (
        "the '---[ end Kernel panic ...' banner is wrongly matched as a crash "
        "START, so it becomes the detected crash_start and capture stops at one line"
    )


def test_extract_crash_interior_end_marker_not_truncated(tmp_path):
    """CORR-7: an interior '---[ end trace ]---' (the WARNING epilogue) emitted
    before the final panic banner under panic_on_warn must NOT truncate the
    report. The full block — WARNING root cause, Call Trace, RIP, the interior
    marker, the panic banner — must be returned, anchored at the FIRST start."""
    log = _write(tmp_path, "warn_panic.serial.log", WARN_PANIC_ON_WARN_LOG)
    report = extract_crash(log)

    assert report is not None
    # The root cause and full report body MUST survive the interior end-marker:
    assert "WARNING: CPU:" in report, (
        "extract_crash truncated at the interior '---[ end trace ]---' and lost "
        "the WARNING root cause"
    )
    assert "kfree+0x1a/0x2b" in report
    assert "Call Trace:" in report
    assert "RIP: 0010:kfree" in report
    # The interior marker is kept INSIDE the block, not used as the boundary:
    assert "---[ end trace 0000000000000000 ]---" in report
    # And capture runs through the FINAL banner, not the interior one:
    assert "---[ end Kernel panic" in report
    assert report.count("\n") > 10, (
        "extract_crash dropped the WARNING report body: " + repr(report)
    )


def test_extract_crash_returns_only_last_distinct_crash(tmp_path):
    """A survived earlier WARNING followed by resumed normal output and then a
    later fatal panic: only the LAST crash event is returned, never the earlier
    distinct one."""
    log = _write(tmp_path, "two.serial.log", TWO_DISTINCT_CRASHES_LOG)
    report = extract_crash(log)

    assert report is not None
    assert "real_bug" in report, "lost the last (fatal) crash"
    assert "BUG: KASAN: slab-use-after-free in real_bug" in report
    assert "old_warn" not in report, (
        "leaked the earlier, distinct crash — extract_crash must return only the "
        "last crash event"
    )
    assert "---[ end trace 1111111111111111 ]---" not in report


def test_extract_crash_ignores_complete_preboundary_crash(tmp_path):
    log = _write(tmp_path, "stale.serial.log", KASAN_UAF_LOG)
    boundary = serial_log_offset(log)
    assert extract_crash(log, start_offset=boundary) is None


def test_extract_crash_finds_only_postboundary_crash(tmp_path):
    log = _write(tmp_path, "fresh.serial.log", KASAN_UAF_LOG)
    boundary = serial_log_offset(log)
    with log.open("a") as stream:
        stream.write(SYSRQ_PANIC_LOG)

    report = extract_crash(log, start_offset=boundary)
    assert report is not None
    assert "sysrq triggered crash" in report
    assert "uaf_init" not in report


def test_extract_crash_uses_byte_not_character_offset(tmp_path):
    prefix = "µ restored epoch\n"
    log = _write(tmp_path, "utf8.serial.log", prefix + SYSRQ_PANIC_LOG)
    boundary = len(prefix.encode("utf-8"))
    report = extract_crash(log, start_offset=boundary)
    assert report is not None
    assert "sysrq triggered crash" in report


def test_extract_crash_tolerates_offset_inside_utf8_and_invalid_bytes(tmp_path):
    log = tmp_path / "invalid.serial.log"
    prefix = "µ".encode("utf-8")
    log.write_bytes(prefix + b"\xff\n" + SYSRQ_PANIC_LOG.encode())
    report = extract_crash(log, start_offset=1)
    assert report is not None
    assert "sysrq triggered crash" in report


def test_extract_crash_stale_offset_resets_after_truncation(tmp_path):
    log = _write(tmp_path, "truncated.serial.log", KASAN_UAF_LOG + KASAN_UAF_LOG)
    stale = serial_log_offset(log)
    log.write_text(SYSRQ_PANIC_LOG)
    assert stale > serial_log_offset(log)

    report = extract_crash(log, start_offset=stale)
    assert report is not None
    assert "sysrq triggered crash" in report


def test_extract_crash_stale_offset_resets_after_smaller_rotation(tmp_path):
    log = _write(tmp_path, "rotated.serial.log", KASAN_UAF_LOG + KASAN_UAF_LOG)
    stale = serial_log_offset(log)
    log.rename(tmp_path / "rotated.serial.log.1")
    log.write_text(SYSRQ_PANIC_LOG)

    report = extract_crash(log, start_offset=stale)
    assert report is not None
    assert "sysrq triggered crash" in report


def test_extract_crash_negative_offset_scans_from_zero(tmp_path):
    log = _write(tmp_path, "negative.serial.log", SYSRQ_PANIC_LOG)
    assert extract_crash(log, start_offset=-1) == extract_crash(log)


def test_extract_crash_does_not_attribute_event_started_before_boundary(tmp_path):
    start = "[ 1.0] Kernel panic - not syncing: old event\n"
    ending = "[ 1.1] ---[ end Kernel panic - not syncing: old event ]---\n"
    log = _write(tmp_path, "partial.serial.log", start)
    boundary = serial_log_offset(log)
    with log.open("a") as stream:
        stream.write(ending)
    assert extract_crash(log, start_offset=boundary) is None


def test_extract_crash_unreadable_returns_none(tmp_path, monkeypatch):
    log = _write(tmp_path, "denied.serial.log", SYSRQ_PANIC_LOG)
    original_open = Path.open

    def deny_open(self, *args, **kwargs):
        if self == log:
            raise PermissionError("denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_open)
    assert extract_crash(log, start_offset=0) is None


# --- These guard the None / no-crash branches ---

def test_extract_crash_clean_boot_returns_none(tmp_path):
    """A normal boot log with no BUG/panic lines yields None."""
    log = _write(tmp_path, "clean.serial.log", CLEAN_BOOT_LOG)
    assert extract_crash(log) is None


def test_extract_crash_missing_file_returns_none(tmp_path):
    """A nonexistent serial log path yields None (no exception)."""
    assert extract_crash(tmp_path / "does-not-exist.log") is None


def test_extract_crash_empty_file_returns_none(tmp_path):
    """An empty serial log yields None."""
    log = _write(tmp_path, "empty.serial.log", "")
    assert extract_crash(log) is None


# --- tail_log ---

def test_tail_log_zero_lines_returns_empty_string(tmp_path):
    """Regression: `qmu log --tail 0` must print NOTHING. all_lines[-0:] is the
    WHOLE list, so an unguarded slice dumps the entire serial log. Like
    `tail -n 0`, lines=0 returns "" — and "" stays distinguishable from a
    missing file (None)."""
    log = _write(tmp_path, "tail.serial.log", CLEAN_BOOT_LOG)
    out = tail_log(log, lines=0)

    assert out is not None, "lines=0 on an existing file must not look like a missing file"
    assert out == "", (
        "tail_log(lines=0) dumped content instead of nothing: " + repr(out)
    )
    # Negative values must not dump the whole file either:
    assert tail_log(log, lines=-3) == ""


def test_tail_log_positive_lines_returns_last_n(tmp_path):
    """A normal positive tail returns exactly the last N lines, newline-terminated."""
    log = _write(tmp_path, "tail.serial.log", CLEAN_BOOT_LOG)
    out = tail_log(log, lines=2)

    assert out is not None
    assert out == (
        "[    2.000000] Debian GNU/Linux 12 qmu ttyS0\n"
        "[    2.100000] qmu login: root (automatic login)\n"
    )
    # Asking for more lines than exist returns the whole file's lines:
    assert tail_log(log, lines=500) == CLEAN_BOOT_LOG


def test_tail_log_missing_file_returns_none(tmp_path):
    """A nonexistent log path yields None — including with lines=0, so the
    empty-tail case ("") never masks a missing file (None)."""
    assert tail_log(tmp_path / "does-not-exist.log") is None
    assert tail_log(tmp_path / "does-not-exist.log", lines=0) is None
