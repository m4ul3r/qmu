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
    has_terminal_panic,
    scan_console_growth,
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
[    0.044413] kasan: KernelAddressSanitizer initialized
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


def test_extract_crash_does_not_bridge_close_independent_events(tmp_path):
    log = _write(
        tmp_path,
        "close.serial.log",
        "[ 1.0] WARNING: CPU: old_warn\n"
        "[ 1.1] old body\n"
        "[ 1.2] ---[ end trace 111 ]---\n"
        "[ 1.3] service resumed\n"
        "[ 2.0] BUG: KASAN: slab-use-after-free in new_bug\n"
        "[ 2.1] Kernel panic - not syncing: new panic\n"
        "[ 2.2] ---[ end Kernel panic - not syncing: new panic ]---\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert "new_bug" in report
    assert "old_warn" not in report
    assert "end trace 111" not in report


def test_extract_crash_sysrq_panic_does_not_bridge_resumed_warning(tmp_path):
    log = _write(
        tmp_path,
        "resumed-sysrq.serial.log",
        "[ 1.0] WARNING: CPU: old_warning at old_root_cause\n"
        "[ 1.1] old warning body\n"
        "[ 1.2] ---[ end trace 111 ]---\n"
        "[ 1.3] service resumed normally\n"
        "[ 2.0] sysrq: Trigger a crash\n"
        "[ 2.1] Kernel panic - not syncing: sysrq triggered crash\n",
    )

    report = extract_crash(log)

    assert report is not None
    assert "Kernel panic - not syncing: sysrq triggered crash" in report
    assert "old_warning" not in report
    assert "old_root_cause" not in report
    assert "end trace 111" not in report



def test_extract_crash_final_panic_banner_is_hard_boundary(tmp_path):
    log = _write(
        tmp_path,
        "adjacent-panics.serial.log",
        "[ 1.0] Kernel panic - not syncing: first\n"
        "[ 1.1] ---[ end Kernel panic - not syncing: first ]---\n"
        "[ 2.0] Kernel panic - not syncing: second\n"
        "[ 2.1] ---[ end Kernel panic - not syncing: second ]---\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert "second" in report
    assert "first" not in report


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


def test_extract_crash_finds_panic_buried_under_a_later_boot(tmp_path):
    """A `panic=N` guest reboots and appends ~700 boot lines after the panic.

    The old 500-line tail window dropped it: `qmu crash --full-history` said
    "no crash markers found" for a panic `qmu log --grep` printed. The whole
    requested scope is scanned now; the report is unchanged.
    """
    reboot = (
        "[    5.0] Rebooting in 3 seconds..\n"
        "[    0.000000] Linux version 7.0.0 (qmu@kbuild) (gcc 13) #1 SMP\n"
        + "".join(f"[    0.{i:06d}] boot line {i}\n" for i in range(2000))
        + "localhost login: \n"
    )
    log = _write(tmp_path, "rebooted.serial.log", SYSRQ_PANIC_LOG + reboot)

    report = extract_crash(log)

    alone = extract_crash(_write(tmp_path, "alone.serial.log", SYSRQ_PANIC_LOG))
    # Same report; the reboot notice is itself an end marker and so is kept.
    assert report.startswith(alone)
    assert report.endswith("Rebooting in 3 seconds..\n")
    assert "Kernel panic - not syncing: sysrq triggered crash" in report
    assert "boot line" not in report


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


# --- #140: the report starts at the event's headline -------------------------

# arm64 6.6.75 (live, `insmod oopsmod.ko`): the fault headline and the whole
# abort decode precede `Internal error: Oops:`. Register lines trimmed.
ARM64_FAULT_LOG = """\
localhost login: [   36.037407] oopsmod: loading out-of-tree module taints kernel.
[   36.047816] oopsmod: about to dereference NULL (xarch survivable oops)
[   36.048967] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
[   36.049552] Mem abort info:
[   36.049765]   ESR = 0x0000000096000044
[   36.050069]   EC = 0x25: DABT (current EL), IL = 32 bits
[   36.051273]   FSC = 0x04: level 0 translation fault
[   36.051617] Data abort info:
[   36.052274]   CM = 0, WnR = 1, TnD = 0, TagAccess = 0
[   36.053110] user pgtable: 4k pages, 48-bit VAs, pgdp=000000004b8b4000
[   36.053575] [0000000000000000] pgd=0000000000000000, p4d=0000000000000000
[   36.054270] Internal error: Oops: 0000000096000044 [#1] PREEMPT SMP
[   36.054965] Modules linked in: oopsmod(O+)
[   36.057559] pc : oopsmod_init+0x24/0x1000 [oopsmod]
[   36.065203] Call trace:
[   36.065450]  oopsmod_init+0x24/0x1000 [oopsmod]
[   36.069387] Code: 9400000b d2800001 52800822 52800000 (b9000022)
[   36.069966] ---[ end trace 0000000000000000 ]---
"""

# arm32 7.0 (live): the headline carries the write direction.
ARM32_FAULT_LOG = """\
[   34.523658] oopsmod: about to dereference NULL (xarch survivable oops)
[   34.523978] 8<--- cut here ---
[   34.524015] Unable to handle kernel NULL pointer dereference at virtual address 00000000 when write
[   34.524057] [00000000] *pgd=00000000
[   34.524925] Internal error: Oops: 805 [#1] SMP ARM
[   34.528596] PC is at oopsmod_init+0x18/0x1000 [oopsmod]
[   34.543316] Code: e34b0f00 eb4bf76c e3a00000 e3a03041 (e5803000)
[   34.543894] ---[ end trace 0000000000000000 ]---
"""

# x86 die() on a breakpoint byte baked into the kernel text (a snapshot saved
# with an armed software breakpoint, #45): `int3: 0000 [#1]` is the die
# header, the register re-dump follows the end-trace banner, then the panic.
INT3_OOPS_PANIC_LOG = """\
[  357.736000] [poc] pipe prepared
[  357.736541] int3: 0000 [#1] SMP KASAN NOPTI
[  357.737102] CPU: 0 PID: 233 Comm: poc Not tainted 5.11.0 #1
[  357.737900] RIP: 0010:copy_page_to_iter+0x2e8/0x580
[  357.738400] Code: 48 8b 45 00 cc <8d> 7d 18 48 89 fa 48 c1 ea 03
[  357.739000] RSP: 0018:ffffc90000a3fc68 EFLAGS: 00000246
[  357.739500] Call Trace:
[  357.739600]  generic_file_splice_read+0x2a1/0x4b0
[  357.739700]  __x64_sys_splice+0x1b4/0x220
[  357.739800]  do_syscall_64+0x33/0x40
[  357.739900] Modules linked in:
[  357.740000] ---[ end trace 3052687ea0439622 ]---
[  357.740100] RIP: 0010:copy_page_to_iter+0x2e8/0x580
[  357.740200] RSP: 0018:ffffc90000a3fc68 EFLAGS: 00000246
[  357.740300] RAX: 0000000000000000 RBX: ffff888006a1c000 RCX: 0000000000000000
[  357.740400] CR2: 00007f5ad3a3c000 CR3: 000000000b80e000 CR4: 00000000000006f0
[  357.740500] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  357.793490] Kernel panic - not syncing: Fatal exception in interrupt
[  357.793870] Kernel Offset: disabled
"""


@pytest.mark.parametrize(
    "log, headline, kept",
    [
        (
            ARM64_FAULT_LOG,
            "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000",
            ["WnR = 1", "Internal error: Oops", "end trace"],
        ),
        (
            ARM32_FAULT_LOG,
            "Unable to handle kernel NULL pointer dereference at virtual address 00000000 when write",
            ["*pgd=00000000", "Internal error: Oops: 805", "end trace"],
        ),
        (
            INT3_OOPS_PANIC_LOG,
            "int3: 0000 [#1] SMP KASAN NOPTI",
            ["RIP: 0010:copy_page_to_iter", "cc <8d>", "Kernel panic - not syncing"],
        ),
    ],
    ids=["arm64-fault", "arm32-fault", "x86-int3"],
)
def test_extract_crash_starts_at_the_event_headline(tmp_path, log, headline, kept):
    """#140: the faulting address, the write direction and the breakpointed
    RIP exist only in the lines before the generic `Oops:` marker (or, for
    `int3`, before the panic), so the report must start at the headline."""
    report = extract_crash(_write(tmp_path, "event.serial.log", log))
    assert report is not None
    first = report.splitlines()[0]
    assert first.endswith(headline), first
    for line in kept:
        assert line in report
    assert "oopsmod: about to" not in report and "[poc] pipe prepared" not in report


def test_kernel_bug_headline_starts_the_report(tmp_path):
    """`BUG()` prints its source location before the die header."""
    log = _write(
        tmp_path,
        "bug.serial.log",
        "[ 5.0] ------------[ cut here ]------------\n"
        "[ 5.1] kernel BUG at mm/slub.c:4012!\n"
        "[ 5.2] invalid opcode: 0000 [#1] PREEMPT SMP KASAN NOPTI\n"
        "[ 5.3] RIP: 0010:kfree+0x10/0x20\n"
        "[ 5.4] ---[ end trace 0000000000000000 ]---\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert report.startswith("[ 5.1] kernel BUG at mm/slub.c:4012!\n")


# 6.1.11 x86_64, 2 vCPUs under KVM (live, `insmod int3mod.ko`): the int3 die
# escalates to "Fatal exception in interrupt", and AFTER the panic's end
# banner the scheduler's IPI to the stopped CPU prints a WARNING. Trimmed.
INT3_PANIC_THEN_RESCHEDULE_WARNING_LOG = """\
localhost login: [   18.819419] int3mod: loading out-of-tree module taints kernel.
[   18.825542] int3mod: executing int3 in kernel mode
[   18.827244] int3: 0000 [#1] PREEMPT SMP KASAN NOPTI
[   18.827254] CPU: 0 PID: 166 Comm: insmod Tainted: G           O       6.1.11 #1
[   18.827267] RIP: 0010:int3mod_init+0xd/0x1000 [int3mod]
[   18.827546] Modules linked in: int3mod(O+)
[   18.924161] ---[ end trace 0000000000000000 ]---
[   18.924167] RIP: 0010:int3mod_init+0xd/0x1000 [int3mod]
[   18.924238] CR2: ffffffffc0397fe3 CR3: 00000000035aa000 CR4: 00000000000006f0
[   18.924246] Kernel panic - not syncing: Fatal exception in interrupt
[   18.924402] Kernel Offset: 0x14000000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[   18.954063] ---[ end Kernel panic - not syncing: Fatal exception in interrupt ]---
[   18.956285] ------------[ cut here ]------------
[   18.956289] sched: Unexpected reschedule of offline CPU#1!
[   18.956305] WARNING: CPU: 0 PID: 166 at arch/x86/kernel/apic/ipi.c:68 native_smp_send_reschedule+0x66/0x70
[   18.956319] Modules linked in: int3mod(O+)
[   18.957079]  </TASK>
[   18.957082] ---[ end trace 0000000000000000 ]---
"""


def test_extract_crash_ignores_what_a_finished_panic_prints_afterwards(tmp_path):
    """The panic's end banner is the end of that kernel: the reschedule
    WARNING after it is panic-path noise, and returning it as "the last
    crash" hid the Oops that killed the guest."""
    report = extract_crash(
        _write(tmp_path, "int3.serial.log", INT3_PANIC_THEN_RESCHEDULE_WARNING_LOG)
    )
    assert report is not None
    assert report.startswith("[   18.827244] int3: 0000 [#1]")
    assert report.rstrip("\n").endswith("Fatal exception in interrupt ]---")
    assert "native_smp_send_reschedule" not in report


def test_extract_crash_after_a_reboot_reports_the_new_boot(tmp_path):
    """Over `--full-history`, a boot that follows a finished panic is a new
    kernel whose own events are the newest crash."""
    report = extract_crash(
        _write(
            tmp_path,
            "reboot.serial.log",
            INT3_PANIC_THEN_RESCHEDULE_WARNING_LOG
            + BANNER
            + "[    5.000000] WARNING: CPU: 1 PID: 9 at fs/x.c:1 new_boot_warn+0x1/0x2\n"
            + "[    5.000100] ---[ end trace 0000000000000000 ]---\n",
        )
    )
    assert report is not None
    assert report.startswith("[    5.000000] WARNING: CPU: 1")


def test_extract_crash_after_a_clean_reboot_still_reports_the_panic(tmp_path):
    """A reboot ends the noise too: with a clean new boot after it, the
    newest crash in the history is the panic, not its reschedule WARNING."""
    report = extract_crash(
        _write(
            tmp_path,
            "clean-reboot.serial.log",
            INT3_PANIC_THEN_RESCHEDULE_WARNING_LOG + BANNER + "[    1.000000] systemd[1]: started\n",
        )
    )
    assert report is not None
    assert report.startswith("[   18.827244] int3: 0000 [#1]")
    assert "native_smp_send_reschedule" not in report


@pytest.mark.parametrize("clock", ["12.40", "18.97"], ids=["rewound", "past-the-panic"])
def test_extract_crash_after_a_snapshot_load_reports_the_restored_guests_crash(
    tmp_path, clock
):
    """`loadvm` rewinds the guest without a boot banner, and the restored
    clock may already be past the panic's (live: 27 ms short of it after a
    save one second before the panic). A crash the restored guest takes is
    newer than the panic and must win a `--full-history` scan."""
    report = extract_crash(
        _write(
            tmp_path,
            "load.serial.log",
            INT3_PANIC_THEN_RESCHEDULE_WARNING_LOG
            + f"[   {clock}0000] nullmod: about to store through NULL (survivable oops)\n"
            + f"[   {clock}0100] BUG: kernel NULL pointer dereference, address: 0000000000000000\n"
            + f"[   {clock}0200] Oops: 0002 [#1] PREEMPT SMP KASAN NOPTI\n"
            + f"[   {clock}0300] ---[ end trace 0000000000000000 ]---\n",
        )
    )
    assert report is not None
    assert report.startswith(f"[   {clock}0100] BUG: kernel NULL pointer dereference")
    assert "int3" not in report


def test_extract_crash_restored_guest_crashing_on_its_first_line_is_not_noise(tmp_path):
    """Review round 2, live: after the load the restored guest's Oops was the
    very next log line, 0.23 s after the panic's end banner on the guest
    clock. Adjacent and in the window, it still is not the dying kernel's
    reschedule splat."""
    report = extract_crash(
        _write(
            tmp_path,
            "load-first-line.serial.log",
            "[   84.736941] BUG: kernel NULL pointer dereference, address: 0000000000000000\n"
            "[   84.737000] Oops: 0002 [#1] PREEMPT SMP KASAN NOPTI\n"
            "[   84.800000] Kernel panic - not syncing: Fatal exception\n"
            "[   84.815646] ---[ end Kernel panic - not syncing: Fatal exception ]---\n"
            "[   85.046159] BUG: kernel NULL pointer dereference, address: 0000000000000000\n"
            "[   85.046300] Oops: 0002 [#1] PREEMPT SMP KASAN NOPTI\n"
            "[   85.046400] RIP: 0010:w3r_write+0x10/0x20 [w3r]\n"
            "[   85.046500] ---[ end trace 0000000000000000 ]---\n",
        )
    )
    assert report is not None
    assert report.startswith("[   85.046159] BUG: kernel NULL pointer dereference")



# --- #142: a sanitizer report flood is many events, not one -------------------

_RULE = "=" * 66


def _kasan_report(stamp: int, addr: str, *, opening: str = "") -> str:
    return (
        f"{opening}[  {stamp}.000000] {_RULE}\n"
        f"[  {stamp}.000100] BUG: KASAN: slab-out-of-bounds in __perf_read_group_add+0x3e1/0x460\n"
        f"[  {stamp}.000200] Read of size 8 at addr {addr} by task repro/171\n"
        f"[  {stamp}.000300] Call Trace:\n"
        f"[  {stamp}.000400]  kasan_report+0xad/0x130\n"
        f"[  {stamp}.000500] The buggy address belongs to the object at ffff888001f9d000\n"
        f"[  {stamp}.000600] Memory state around the buggy address:\n"
        f"[  {stamp}.000700] >ffff888001f9d800: fc fc fc fc fc fc fc fc\n"
        f"[  {stamp}.000800]                    ^\n"
        f"[  {stamp}.000900] {_RULE}\n"
    )


def test_extract_crash_returns_the_newest_report_of_a_kasan_flood(tmp_path):
    """`kasan_multi_shot` + `kasan.fault=report` prints report after report
    with no `end trace` between them; the first rule follows a `login:`
    prompt on the same console line. Only the newest report is the crash."""
    log = _write(
        tmp_path,
        "flood.serial.log",
        "[  OK  ] Reached target multi-user.target\n"
        + _kasan_report(17, "ffff888001f9d800", opening="localhost login: ")
        + "[  17.454507] Disabling lock debugging due to kernel taint\n"
        + _kasan_report(18, "ffff888001f9d808")
        + _kasan_report(19, "ffff888001f9d810")
        + "[  20.000000] systemd-journald[120]: Under memory pressure\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert report.count("BUG: KASAN") == 1
    assert report.startswith("[  19.000100] BUG: KASAN:")
    assert "ffff888001f9d810" in report
    assert report.rstrip("\n").endswith(_RULE)
    assert "journald" not in report


def test_extract_crash_bridges_a_kasan_report_into_its_panic(tmp_path):
    """The closing rule is a soft end: a report that escalates to a panic
    (`panic_on_warn`, which taints first on 5.x, or `kasan.fault=panic`) is
    one event from `BUG: KASAN` through the panic, and the earlier report
    of the same boot stays out of it."""
    log = _write(
        tmp_path,
        "kasan-panic.serial.log",
        _kasan_report(17, "ffff888001f9d800")
        + _kasan_report(18, "ffff888001f9d808")
        + "[  18.100000] Disabling lock debugging due to kernel taint\n"
        + "[  18.100100] Kernel panic - not syncing: panic_on_warn set ...\n"
        + "[  18.100200] Kernel Offset: disabled\n"
        + "[  18.100300] ---[ end Kernel panic - not syncing: panic_on_warn set ... ]---\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert report.startswith("[  18.000100] BUG: KASAN:")
    assert report.count("BUG: KASAN") == 1
    assert "Kernel panic - not syncing: panic_on_warn" in report
    assert report.rstrip("\n").endswith("]---")


def test_extract_crash_prefers_the_newest_complete_report_over_one_half_printed(tmp_path):
    """A flood read mid-print ends in a report with only its headline: the
    complete report before it carries the object/alloc/free detail."""
    log = _write(
        tmp_path,
        "inflight.serial.log",
        _kasan_report(17, "ffff888001f9d800")
        + _kasan_report(18, "ffff888001f9d808")
        + f"[  19.000000] {_RULE}\n"
        + "[  19.000100] BUG: KASAN: slab-out-of-bounds in __perf_read_group_add+0x3e1/0x460\n"
        + "[  19.000200] Read of size 8 at addr ffff888001f9d810 by task repro/171\n",
    )
    report = extract_crash(log)
    assert report is not None
    assert report.startswith("[  18.000100] BUG: KASAN:")
    assert "The buggy address belongs to the object" in report
    assert "ffff888001f9d810" not in report


def test_extract_crash_returns_a_lone_report_still_being_printed(tmp_path):
    log = _write(
        tmp_path,
        "lone.serial.log",
        f"[  19.000000] {_RULE}\n"
        "[  19.000100] BUG: KASAN: slab-out-of-bounds in f+0x1/0x2\n"
        "[  19.000200] Read of size 8 at addr ffff888001f9d810 by task repro/171\n",
    )
    report = extract_crash(log)
    assert report is not None and report.startswith("[  19.000100] BUG: KASAN:")


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


def test_tail_log_zero_byte_file_returns_empty_string(tmp_path):
    log = _write(tmp_path, "empty-tail.serial.log", "")
    assert tail_log(log, lines=50) == ""


# ---------------------------------------------------------------------------
# scan_console_growth: the incremental banner/panic scanner the bare `wait`
# loop polls with. r2-shared measured 10 s of CPU for a 20 s wait when every
# tick rescanned the whole boot; each tick must now touch only new bytes.
# ---------------------------------------------------------------------------

BANNER = "[    0.000000] Linux version 7.0.0 (builder@host) (gcc 13.3.0) #1 SMP\n"
PANIC = "[    2.0] Kernel panic - not syncing: sysrq triggered crash\n"


def test_scan_growth_reads_only_appended_bytes(tmp_path):
    log = _write(tmp_path, "g.serial.log", BANNER + "line one\n")
    scanned, boot, panicked = scan_console_growth(log, scanned=0, boot_offset=0)
    assert (scanned, boot, panicked) == (len(BANNER + "line one\n"), 0, False)

    # Nothing new: no read, same high-water mark.
    assert scan_console_growth(log, scanned=scanned, boot_offset=boot) == (
        scanned, boot, False,
    )

    with log.open("a") as f:
        f.write("line two\n")
    scanned2, boot2, panicked2 = scan_console_growth(log, scanned=scanned, boot_offset=boot)
    assert scanned2 == scanned + len("line two\n")
    assert boot2 == 0 and panicked2 is False


def test_scan_growth_withholds_a_partial_line_until_it_completes(tmp_path):
    log = _write(tmp_path, "p.serial.log", BANNER + "[    2.0] Kernel pan")
    scanned, _, panicked = scan_console_growth(log, scanned=0, boot_offset=0)
    assert scanned == len(BANNER), "the fragment must be re-read next tick"
    assert panicked is False

    with log.open("a") as f:
        f.write("ic - not syncing: Fatal exception\n")
    scanned, _, panicked = scan_console_growth(log, scanned=scanned, boot_offset=0)
    assert panicked is True
    assert scanned == serial_log_offset(log)


def test_scan_growth_moves_the_boot_past_a_new_banner(tmp_path):
    first = BANNER + PANIC
    log = _write(tmp_path, "r.serial.log", first)
    scanned, boot, panicked = scan_console_growth(log, scanned=0, boot_offset=0)
    assert panicked is True and boot == 0

    # panic=1 reboot: a second banner starts a new guest; the old panic must
    # not be re-reported against it, and the boot offset is the banner's.
    with log.open("a") as f:
        f.write(BANNER + "fresh boot\n")
    scanned, boot, panicked = scan_console_growth(log, scanned=scanned, boot_offset=boot)
    assert boot == len(first)
    assert panicked is False


def test_scan_growth_panic_before_a_banner_in_the_same_chunk_does_not_count(tmp_path):
    log = _write(tmp_path, "s.serial.log", "")
    with log.open("a") as f:
        f.write(BANNER + PANIC + BANNER + "fresh\n")
    scanned, boot, panicked = scan_console_growth(log, scanned=0, boot_offset=0)
    assert boot == len(BANNER + PANIC)
    assert panicked is False


def test_scan_growth_rescans_a_log_that_truly_shrank_with_a_retained_boundary(tmp_path):
    """Receipt 226: a ~4.6 KB log whose last banner sat near its end is
    replaced by a ~100-byte banner+panic. The old boot boundary must not
    survive the shrink — it hid every byte of the new generation (#103)."""
    old = BANNER + "old-line\n" * 500 + BANNER + "current boot\n"
    log = _write(tmp_path, "t.serial.log", old)
    scanned, boot, panicked = scan_console_growth(log, scanned=0, boot_offset=0)
    assert scanned == serial_log_offset(log) == len(old)
    assert boot == len(old) - len(BANNER + "current boot\n") and panicked is False

    log.write_text(BANNER + PANIC)
    assert serial_log_offset(log) == len(BANNER + PANIC) < boot
    scanned, boot, panicked = scan_console_growth(log, scanned=scanned, boot_offset=boot)
    assert panicked is True
    assert boot == 0, "the boundary follows the new log's banner, not the old generation's"
    assert scanned == serial_log_offset(log)
    assert has_terminal_panic(log, start_offset=boot) is True


def test_scan_growth_shrunk_log_without_a_banner_rescans_from_zero(tmp_path):
    log = _write(tmp_path, "u.serial.log", BANNER + "x\n" * 200 + BANNER + "y\n")
    scanned, boot, _ = scan_console_growth(log, scanned=0, boot_offset=0)
    assert boot > 0

    log.write_text(PANIC)
    scanned, boot, panicked = scan_console_growth(log, scanned=scanned, boot_offset=boot)
    assert (scanned, boot, panicked) == (len(PANIC), 0, True)


def test_scan_growth_missing_log_is_inert(tmp_path):
    assert scan_console_growth(tmp_path / "nope.log", scanned=7, boot_offset=3) == (7, 3, False)


def test_kernel_init_done_is_scoped_to_the_boot_after_the_offset(tmp_path):
    """The reset re-sync arms breakpoints only once the new boot has finished
    kernel init (its boot-time text patching is over); the previous boot's
    end-of-init lines must not count, and a `quiet` boot shows none."""
    from qmu.serial import kernel_init_done

    old = (
        b"[    0.000000] Linux version 6.1.11 (b@h) (gcc) #1 SMP\n"
        b"[    1.353989] Run /sbin/init as init process\n"
    )
    new_banner = b"[    0.000000] Linux version 6.1.11 (b@h) (gcc) #1 SMP\n"
    log = tmp_path / "s.log"
    log.write_bytes(old + new_banner)
    assert kernel_init_done(log, start_offset=0) is True
    assert kernel_init_done(log, start_offset=len(old)) is False
    # arm64 words free_initmem differently; any end-of-init line counts.
    log.write_bytes(old + new_banner + b"[    2.1] Freeing unused kernel memory: 9024K\n")
    assert kernel_init_done(log, start_offset=len(old)) is True
    assert kernel_init_done(tmp_path / "missing.log") is False
    # #205: a `quiet` boot prints none of those lines but its getty prompt,
    # which comes after init; a kernel line mentioning `login:` is no prompt.
    log.write_bytes(old + b"[    3.2] audit: type=1 msg='op=login: res=1'\n")
    assert kernel_init_done(log, start_offset=len(old)) is False
    log.write_bytes(old + b"\r\nDebian GNU/Linux 12 drv ttyS0\r\n\r\ndrv login: ")
    assert kernel_init_done(log, start_offset=len(old)) is True
