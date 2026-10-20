from __future__ import annotations

import bisect
import os
import re
from pathlib import Path


# The first line of each event class. A report must start at its headline,
# not at a later line of the same event: arm/arm64 print the fault headline
# (`Unable to handle kernel ...`) and the whole abort decode (faulting
# address, `WnR`/`when write`) BEFORE `Internal error: Oops:`, and x86
# `BUG()` prints `kernel BUG at file:line!` before its die header (#140).
# The die header itself is matched by shape, `<what>: <hex> [#<n>]`, because
# its wording is per trap: `int3: 0000 [#1]`, `invalid opcode: 0000 [#1]`,
# `Internal error: Oops - BUG: ... [#1]` — `int3` matched nothing at all, so
# a baked-in breakpoint's report fell through to its trailing panic line.
CRASH_START_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"BUG: KASAN:",
        r"BUG: KMSAN:",
        r"BUG: KCSAN:",
        r"BUG: kernel NULL pointer dereference",
        r"BUG: unable to handle",
        r"BUG: soft lockup",
        r"Unable to handle kernel",
        r"kernel BUG at",
        r": [0-9a-f]+ \[#\d+\]",
        r"UBSAN:",
        r"WARNING: CPU:",
        r"Oops:",
        r"general protection fault",
        r"kernel panic",
        r"Kernel panic",
        r"slab-use-after-free",
        r"slab-out-of-bounds",
        r"stack-out-of-bounds",
        r"use-after-free in",
        r"double-free or invalid-free",
    ]
]

# The `=====...` rule KASAN/KMSAN/KCSAN (and pre-6.5 UBSAN) print above and
# below every report, as the whole printk message. It is the only boundary
# between two back-to-back reports: `kasan_multi_shot` with
# `kasan.fault=report` floods hundreds of them with no `end trace` between,
# and without this marker the backward walk merged the flood into one
# multi-megabyte "crash" headed by the FIRST report (#142). Matched after a
# printk timestamp or at line start; the first rule of a flood can follow a
# `login:` prompt on the same console line. Written to begin with a literal
# `=` and test what precedes it by lookbehind: `(?:^|\] )={40,}` has no
# literal prefix and cost 0.3 s on an 8 MB flood, this form 10 ms.
_REPORT_RULE = r"(?m:=(?:(?<=\] =)|(?<=^=))={39,}[ \t\r]*$)"

CRASH_END_PATTERNS = [
    re.compile(p)
    for p in [
        r"---\[ end trace",
        r"Kernel Offset:",
        r"Rebooting in \d+ seconds",
        r"---\[ end Kernel panic",
        _REPORT_RULE,
    ]
]

# One alternation per list: the classifiers run on every line of a scan, and
# `extract_crash` walks a whole boot (megabytes on a chatty guest) for every
# `status`/`list`/`wait`. Searching 21 patterns per line cost 1.1 s on a 3 MB
# log; one search each is linear in the log and nothing else.
_CRASH_START_RE = re.compile(
    "|".join(p.pattern for p in CRASH_START_PATTERNS), re.IGNORECASE
)
_CRASH_END_RE = re.compile("|".join(p.pattern for p in CRASH_END_PATTERNS))


# End markers that close a report the kernel may still escalate into a fatal
# panic (`panic_on_warn`, `kasan.fault=panic`): the WARNING/Oops `end trace`
# banner and a sanitizer report's closing rule. Every other end marker is a
# hard boundary.
_SOFT_END = re.compile(r"---\[ end trace|" + _REPORT_RULE)
_FATAL_PANIC_START = re.compile(r"Kernel panic - not syncing", re.IGNORECASE)
# The banner a panic prints once it is done (no `panic=N` reboot pending).
_PANIC_END_BANNER = "---[ end Kernel panic"
# The per-line text form of `_BOOT_BANNER` (below), for a walk over lines.
_BOOT_BANNER_LINE = re.compile(r"\[\s*\d+\.\d+\] Linux version \S+ \(")


def _is_crash_start(line: str) -> bool:
    # An end-trace banner (e.g. "---[ end Kernel panic ... ]---") contains the
    # substring "Kernel panic" and would otherwise match a start pattern. Treat
    # any end-marker line as END-only so it can never be mistaken for a start.
    if _is_crash_end(line):
        return False
    return _CRASH_START_RE.search(line) is not None


def _is_crash_end(line: str) -> bool:
    return _CRASH_END_RE.search(line) is not None


# How far past a soft "end trace" banner a fatal panic may appear and still
# belong to the same crash episode. A real x86 die() prints a register re-dump,
# CR registers, and a "note: <task> exited with irqs disabled" line between the
# two — checking only the next nonblank line declared a hard boundary there and
# truncated the report to its three-line panic epilogue, dropping the RIP/RDI
# and backtrace that are the entire evidentiary value of a crash.
_PANIC_CONTINUATION_WINDOW = 40

_TIMESTAMP = re.compile(r"^\[\s*\d+\.\d+\]\s*")

# Lines a die() epilogue prints between the "end trace" banner and the fatal
# panic: the register re-dump (debug registers included when a debugger set
# them), the module list, the frame list, and the "note: <task> exited with
# irqs disabled" tail. A sanitizer report that escalates to `panic_on_warn`
# taints the kernel between its closing rule and the panic on older kernels.
_EPILOGUE_LINE = re.compile(
    r"^(?:"
    r"(?:R[A-Z0-9]{1,3}|RIP|RSP|RBP|CR[0-9]|DR[0-7]|FS|GS|DS|ES|CS|SS|EFLAGS|PKRU)\b"
    r"|Code:"
    r"|Modules linked in:"
    r"|note: .*exited"
    r"|Call Trace:"
    r"|Hardware name:|CPU:|Comm:|Tainted:"
    r"|</?TASK>"
    r"|Disabling lock debugging due to kernel taint"
    r"|[?\s]*[A-Za-z_][A-Za-z_0-9.]*\+0x[0-9a-f]+"
    r")"
)


def _is_epilogue_line(line: str) -> bool:
    return bool(_EPILOGUE_LINE.match(_TIMESTAMP.sub("", line).strip()))


def _soft_end_links_to_fatal_panic(lines: list[str], end_index: int) -> bool:
    """Return whether a fatal panic continues this event soon after `end_index`.

    A real x86 die() prints its register re-dump and "note: ... exited" AFTER
    the end-trace banner and BEFORE the panic, so checking only the next
    nonblank line truncated the report to the panic epilogue and dropped the
    RIP/registers/backtrace.

    Scanning ahead unconditionally is wrong the other way: a WARNING that ended
    cleanly, followed later by an unrelated panic, would be glued into one
    event and reported as the WARNING. So the window only bridges while every
    intervening line is itself crash epilogue — ordinary kernel output between
    the two proves the first event really ended.
    """
    seen = 0
    for index in range(end_index + 1, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        seen += 1
        if seen > _PANIC_CONTINUATION_WINDOW:
            return False
        if _FATAL_PANIC_START.search(line) and not _is_crash_end(line):
            return True
        if _is_crash_end(line):
            # Another end marker with no panic yet: this episode is over.
            if not _SOFT_END.search(line):
                return False
            continue
        if not _is_epilogue_line(line):
            # The machine went back to normal work; a later panic is a
            # different event.
            return False
    return False


def serial_log_offset(log_path: str | Path) -> int:
    """Return the readable serial stream's current byte size, or zero."""
    try:
        with Path(log_path).open("rb") as stream:
            return os.fstat(stream.fileno()).st_size
    except OSError:
        return 0


class SerialTail:
    """Incremental line reader over a serial log that is still being written.

    Holds a byte offset so a poll loop rescans only what QEMU appended since
    the last call. A trailing fragment with no newline yet is withheld until
    it is complete, so a matcher never sees half a line; ``flush()`` releases
    it for the final pass, which is how an unterminated line (a shell prompt,
    a crash still in progress) can still be matched once the VM is gone.
    """

    def __init__(self, log_path: str | Path, offset: int = 0) -> None:
        self.path = Path(log_path)
        self.offset = max(0, offset)
        self._partial = ""

    def read_lines(self, *, missing_ok: bool = True) -> list[str]:
        try:
            with self.path.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if self.offset > size:
                    # Truncated or replaced underneath us — restart cleanly
                    # rather than seeking past the end and reading nothing.
                    self.offset = 0
                    self._partial = ""
                stream.seek(self.offset)
                chunk = stream.read()
        except FileNotFoundError:
            if missing_ok:
                return []
            raise

        self.offset += len(chunk)
        if not chunk:
            return []
        text = self._partial + chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self._partial = lines.pop()
        # A serial console emits CRLF, so every line carries a trailing \r.
        # Strip it here: it is a terminal artifact, and leaving it in leaks an
        # escape into JSON `matched_line` and breaks `$`-anchored patterns.
        return [line.rstrip("\r") for line in lines]

    def peek_fragment(self) -> str | None:
        """The withheld trailing fragment, left in place; None when empty.

        For a matcher that wants to see a line the guest will never finish —
        a `login:` prompt waits for input, not for a newline. The fragment is
        not consumed: if more bytes do arrive, ``read_lines`` still returns
        the completed line whole.
        """
        if not self._partial:
            return None
        return self._partial.rstrip("\r")

    def flush(self) -> list[str]:
        """Return any withheld trailing fragment, then clear it."""
        if not self._partial:
            return []
        remainder = self._partial.rstrip("\r")
        self._partial = ""
        return [remainder]


class PatternScan:
    """One tick of a `--pattern` wait over a :class:`SerialTail`.

    `matched_line` is the first line (or, on an idle tick, the withheld
    fragment) the matcher hit; `terminal_panic` whether a terminal panic
    start line was seen in the lines examined; `grew` whether the tail
    advanced. The daemon's `wait` op and the standalone `_wait_for_pattern`
    loop both run this exact step, so the two can never disagree about what
    counts as a match.
    """

    __slots__ = ("matched_line", "terminal_panic", "grew")

    def __init__(self, matched_line: str | None, terminal_panic: bool, grew: bool):
        self.matched_line = matched_line
        self.terminal_panic = terminal_panic
        self.grew = grew


def scan_for_pattern(
    tail: SerialTail,
    matcher: re.Pattern[str],
    *,
    final: bool = False,
    stop_at_panic: bool = True,
) -> PatternScan:
    """Advance `tail` once and look for `matcher` and a terminal panic.

    `final` is the pass after the process is known gone: the log must exist
    (OSError propagates) and the withheld trailing fragment is released, since
    the marker may be the last newline-less line QEMU wrote. On a non-final
    tick where nothing arrived, the fragment is tested in place (never
    consumed) so a prompt that waits for input can still match whole.
    `stop_at_panic` stops examining lines at a terminal panic start, as a wait
    without `--ignore-crash` does; with it False, a later line can still match.
    """
    read_from = tail.offset
    lines = tail.read_lines(missing_ok=not final)
    if final:
        lines.extend(tail.flush())
    matched: str | None = None
    panic = False
    for line in lines:
        if matcher.search(line):
            matched = line
            break
        if is_terminal_panic_start(line):
            panic = True
            if stop_at_panic:
                break
    grew = tail.offset != read_from
    if matched is None and not final and not grew:
        fragment = tail.peek_fragment()
        if fragment is not None and matcher.search(fragment):
            matched = fragment
    return PatternScan(matched, panic, grew)


def extract_crash(
    log_path: str | Path,
    *,
    start_offset: int = 0,
) -> str | None:
    """Return the last crash wholly discoverable at or after a byte boundary.

    The whole slice from `start_offset` to EOF is scanned. A fixed tail window
    (500 lines, once) silently dropped any crash followed by more output than
    the window held — a `panic=N` guest reboots and appends ~700 boot lines,
    so `qmu crash --full-history` answered "no crash markers" for a panic the
    log plainly held. Serial logs are megabytes at most; the walk is linear.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = start_offset
            if offset < 0 or offset > size:
                offset = 0
            stream.seek(offset)
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    tail = text.splitlines()
    if not tail:
        return None

    # Classify every line with whole-text passes instead of two regex
    # searches per line: on a 3 MB boot the per-line calls alone cost 0.5 s,
    # and `status`/`list`/`wait` each pay this walk once.
    end_lines = _lines_matching(CRASH_END_PATTERNS, text)
    start_lines = _lines_matching(CRASH_START_PATTERNS, text) - end_lines

    # A panic that printed its own `---[ end Kernel panic` banner is the end
    # of that kernel: what it prints right afterwards is panic-path noise,
    # not a newer crash. On SMP KVM guests that is routinely a WARNING from
    # `native_smp_send_reschedule` ("Unexpected reschedule of offline CPU"),
    # which a last-event walk returned in place of the Oops that killed the
    # guest (seen with an `int3` die, #140). Only the splat adjacent to the
    # banner on the dying kernel's clock is noise, never "the rest of the
    # log": a `snapshot load` rewinds the guest without printing a boot
    # banner, and a crash the restored guest takes later must still be the
    # newest one.
    noise = _post_panic_noise(tail, start_lines, end_lines)
    if noise:
        start_lines -= noise
        end_lines -= noise

    event = _last_event(tail, start_lines, end_lines, len(tail))
    if event is None:
        return None
    crash_start, end = event

    # A sanitizer flood still being printed ends in a half-written report
    # (headline and access line, no object/alloc/free detail yet). When the
    # report right before it is complete, that one is the useful newest
    # crash; a lone report in progress is still returned as it stands.
    if not any(i in end_lines for i in range(crash_start, len(tail))):
        opening = _previous_nonblank(tail, crash_start)
        if opening is not None and _is_report_rule(tail[opening]):
            closing = _previous_nonblank(tail, opening, skip=_TAINT_NOTICE)
            if closing is not None and _is_report_rule(tail[closing]):
                complete = _last_event(tail, start_lines, end_lines, closing + 1)
                if complete is not None:
                    crash_start, end = complete

    return "\n".join(tail[crash_start:end]) + "\n"


# A dying kernel's post-panic splat starts right after its end banner — after
# at most a `cut here` line and its message — within milliseconds on its own
# clock, and says what it is: the scheduler IPIs a CPU `panic()` already
# stopped ("sched: Unexpected reschedule of offline CPU#N!", a WARNING in
# `native_smp_send_reschedule`). Position and clock alone are not enough: a
# guest restored by `snapshot load` can crash on its very first line, within
# the same second of guest time.
_POST_PANIC_NOISE_SECONDS = 1.0
_POST_PANIC_LEAD = re.compile(r"cut here|sched: Unexpected reschedule")
_POST_PANIC_SIGNATURE = re.compile(r"Unexpected reschedule of offline CPU|smp_send_reschedule")
# Lines a splat may run before its `end trace`; one that is still being
# printed at the end of the log counts through EOF.
_POST_PANIC_EVENT_MAX = 400

_PRINTK_TIME = re.compile(r"\[\s*(\d+\.\d+)\]")
_REPORT_RULE_LINE = re.compile(_REPORT_RULE)
_TAINT_NOTICE = "Disabling lock debugging due to kernel taint"


def _printk_time(line: str) -> float | None:
    match = _PRINTK_TIME.search(line)
    return float(match.group(1)) if match else None


def _is_report_rule(line: str) -> bool:
    return _REPORT_RULE_LINE.search(line) is not None


def _post_panic_noise(
    tail: list[str], start_lines: set[int], end_lines: set[int]
) -> set[int]:
    """Line indices of the splats a finished panic's kernel printed after it.

    Only events that begin immediately after the `---[ end Kernel panic`
    banner (blank, `cut here` and `sched: Unexpected reschedule` lines
    allowed before the headline) on the dying kernel's clock — a timestamp
    not earlier than the banner's and at most `_POST_PANIC_NOISE_SECONDS`
    later — AND carry the post-panic reschedule signature in their lead or
    headline, through their end marker, repeatedly. Bounding it by "the rest
    of the log" hid every later crash: `snapshot load` prints no boot banner,
    and the restored guest's first line can be its own crash headline within
    a second of the panic on the guest clock, so neither a banner, the clock
    nor adjacency alone separates the two. A banner without a timestamp
    (`printk.time=0`) claims nothing.
    """
    noise: set[int] = set()
    for banner in sorted(i for i in end_lines if _PANIC_END_BANNER in tail[i]):
        stamp = _printk_time(tail[banner])
        if stamp is None:
            continue
        index = banner + 1
        while (splat := _adjacent_splat(tail, start_lines, end_lines, index, stamp)) is not None:
            noise.update(range(index, splat))
            index = splat
    return noise


def _adjacent_splat(
    tail: list[str], start_lines: set[int], end_lines: set[int], index: int, stamp: float
) -> int | None:
    """One past the end of the post-panic splat starting at `index`, or None."""
    headline = None
    signed = False
    for i in range(index, len(tail)):
        line = tail[i]
        if not line.strip():
            continue
        when = _printk_time(line)
        if when is None or not stamp <= when <= stamp + _POST_PANIC_NOISE_SECONDS:
            return None
        signed = signed or _POST_PANIC_SIGNATURE.search(line) is not None
        if i in start_lines and not is_terminal_panic_start(line):
            headline = i
            break
        if not _POST_PANIC_LEAD.search(line):
            return None
    if headline is None or not signed:
        return None
    last = min(len(tail), headline + _POST_PANIC_EVENT_MAX)
    for j in range(headline + 1, last):
        if j in end_lines:
            return None if _PANIC_END_BANNER in tail[j] else j + 1
    return len(tail) if last == len(tail) else None


def _previous_nonblank(tail: list[str], index: int, *, skip: str | None = None) -> int | None:
    """The nearest line above `index` that is not blank (nor contains `skip`)."""
    for i in range(index - 1, -1, -1):
        line = tail[i]
        if not line.strip() or (skip is not None and skip in line):
            continue
        return i
    return None


def _last_event(
    tail: list[str], start_lines: set[int], end_lines: set[int], limit: int
) -> tuple[int, int] | None:
    """`(first, past_last)` line indices of the last crash event in `tail[:limit]`.

    Walks backwards to the first line of the last event. A soft end (a
    WARNING "end trace", a sanitizer report's closing rule) remains part of
    the same event only when it leads directly to a fatal panic
    continuation. Every other end marker is a hard boundary between discrete
    events — so of a flood of back-to-back sanitizer reports only the newest
    is returned, not the flood headed by the oldest. The event runs through
    the LAST end marker before `limit` (the epilogue may have several), or
    to `limit` for a crash still in progress.
    """
    crash_start = None
    for i in range(limit - 1, -1, -1):
        if i in start_lines:
            crash_start = i
        elif crash_start is not None and i in end_lines:
            if _SOFT_END.search(tail[i]) and _soft_end_links_to_fatal_panic(tail, i):
                continue
            break
    if crash_start is None:
        return None
    end = limit
    for i in range(limit - 1, crash_start, -1):
        if i in end_lines:
            end = i + 1
            break
    return crash_start, end


_REGEX_META = frozenset("\\[](){}.*+?^$|")


def _marker_positions(pattern: re.Pattern[str], text: str, lowered: str) -> list[int]:
    """Start offsets of every hit of one marker pattern in `text`.

    A marker is a literal (`BUG: KASAN:`) far more often than a regex; for
    those `str.find` on a lowercased copy is the same case-insensitive test
    at memchr speed, where a 17-way IGNORECASE alternation ran at ~10 MB/s.
    """
    if (
        any(ch in _REGEX_META for ch in pattern.pattern)
        # A lowercase form that changed length would desync the offsets.
        or len(lowered) != len(text)
    ):
        return [m.start() for m in pattern.finditer(text)]
    haystack = lowered if pattern.flags & re.IGNORECASE else text
    needle = pattern.pattern.lower() if pattern.flags & re.IGNORECASE else pattern.pattern
    positions: list[int] = []
    pos = haystack.find(needle)
    while pos >= 0:
        positions.append(pos)
        pos = haystack.find(needle, pos + 1)
    return positions


def _lines_matching(patterns: list[re.Pattern[str]], text: str) -> set[int]:
    """Indices (in `text.splitlines()` numbering) of the lines any pattern hits."""
    lowered = text.lower()
    positions: list[int] = []
    for pattern in patterns:
        positions.extend(_marker_positions(pattern, text, lowered))
    hits: set[int] = set()
    if not positions:
        return hits
    starts = [0]
    for line in text.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))
    for pos in positions:
        hits.add(bisect.bisect_right(starts, pos) - 1)
    return hits


def _text_has_terminal_panic(text: str) -> bool:
    """A `Kernel panic - not syncing` line that is not itself an end banner."""
    for match in _FATAL_PANIC_START.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_end = text.find("\n", match.end())
        line = text[line_start:] if line_end < 0 else text[line_start:line_end]
        if not _is_crash_end(line):
            return True
    return False


_UNKNOWN_PARAMS = re.compile(
    r'Unknown kernel command line parameters\s+"([^"]*)"'
)

# Params the kernel always reports as "unknown" because init consumes them.
# Warning about these would train the reader to ignore the warning.
_INIT_PARAMS = {"root", "rw", "ro", "init", "console", "BOOT_IMAGE", "initrd"}

# Params consumed BEFORE the main kernel's parameter table exists, so the
# kernel lists them as "unknown" even though they took full effect. On x86
# these are read by the decompressor via cmdline_find_option*() in
# arch/x86/boot/compressed/ — there is no __setup entry to claim them, so the
# later accounting cannot know they were honored. (riscv registers a do-nothing
# `early_param("nokaslr", print_nokaslr)` in arch/riscv/mm/init.c purely to stop
# this false report; x86 has no equivalent.)
#
# Reporting `nokaslr` as ineffective is worse than noise: it is the single most
# used parameter in kernel exploit development, and "fixing" a correct cmdline
# on that advice silently breaks every hardcoded-address exploit.
# These lists are ARCH-SPECIFIC and must stay that way. Suppressing an x86 name
# on arm hides a parameter that is genuinely doing nothing there: `grep -rn
# nokaslr arch/arm/` finds no KASLR, no early_param, and no decompressor read,
# so on arm32 the kernel's report is correct and must reach the user. arm64 is
# unaffected either way — it registers a do-nothing early_param("nokaslr") in
# arch/arm64/kernel/kaslr.c, so the name never reaches the unknown list there.
_PRE_PARSE_BY_ARCH: dict[str, frozenset[str]] = {
    "x86_64": frozenset({
        "nokaslr", "no5lvl", "acpi", "acpi_rsdp", "mem_encrypt",
        "earlyprintk", "forcepae", "edd", "quiet", "debug",
    }),
    "aarch64": frozenset({"nokaslr", "quiet", "debug", "acpi"}),
    "riscv64": frozenset({"nokaslr", "no5lvl", "quiet", "debug"}),
    # arm32 has no KASLR at all — nothing to exempt beyond the generic names.
    "arm": frozenset({"quiet", "debug"}),
}
_PRE_PARSE_BY_ARCH["i386"] = _PRE_PARSE_BY_ARCH["x86_64"]
_PRE_PARSE_BY_ARCH["riscv"] = _PRE_PARSE_BY_ARCH["riscv64"]

# Used when the instance predates the recorded-arch field. Suppress only the
# names that are inert everywhere, so an unknown arch never hides a real dud.
_PRE_PARSE_UNKNOWN_ARCH = frozenset({"quiet", "debug"})


def _pre_parse_params(arch: str | None) -> frozenset[str]:
    if arch is None:
        return _PRE_PARSE_UNKNOWN_ARCH
    return _PRE_PARSE_BY_ARCH.get(arch, _PRE_PARSE_UNKNOWN_ARCH)


def extract_unknown_params(
    log_path: str | Path, *, start_offset: int = 0, arch: str | None = None
) -> list[str]:
    """Return boot params the kernel did not claim in its parameter table.

    Catches the silent class of bug where a cmdline parameter looks right but
    does nothing — e.g. `panic_on_oops=1`, which is a sysctl, not a boot
    parameter (the boot form is `oops=panic`), so a profile built on it never
    panics.

    Two limits are deliberate. Params consumed before the parameter table
    exists (`_PRE_PARSE_PARAMS`) are excluded, because the kernel reports them
    as unknown while honoring them. And *dotted* params (`kasan.fault=panic`)
    never reach this line at all — the kernel routes them to the module-param
    path — so a typo like `kasan.faul=panic` is invisible here and is caught
    instead by the launch-time spell check in `vm.suspect_dotted_params`.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = start_offset if 0 <= start_offset <= size else 0
            stream.seek(offset)
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return []

    exempt = _pre_parse_params(arch)
    unknown: list[str] = []
    for match in _UNKNOWN_PARAMS.finditer(text):
        for token in match.group(1).split():
            name = token.split("=", 1)[0]
            if name in _INIT_PARAMS or name in exempt:
                continue
            if token in unknown:
                continue
            unknown.append(token)
    return unknown


# The kernel's own boot banner, one per boot. Matched in bytes so the returned
# offset is a true byte position (a decode with errors="replace" can change
# lengths and desync it from the file).
#
# The leading printk timestamp is REQUIRED: the real banner is emitted by printk
# and carries one, so a bare `echo` or `cat /proc/version` to the console cannot
# forge it. It does NOT exclude a `dmesg` replay written to the console, which
# reproduces the timestamped line verbatim — that residual case is accepted and
# made visible instead: `wait --pattern` reports the boundary it scanned from
# (`scan_offset`/`scan_scope`). Matching at line start additionally stops a
# banner quoted mid-line from counting.
_BOOT_BANNER = re.compile(rb"(?m)^\[\s*\d+\.\d+\] Linux version \S+ \(")


def last_boot_offset(log_path: str | Path, *, start_offset: int = 0) -> int:
    """Byte offset of the newest kernel boot banner, else `start_offset`.

    The guest-epoch offset only advances when qmu observes a QMP RESET, which
    requires being connected at the moment it fires — so a guest-initiated
    reboot (`panic=1`, kexec, a harness calling `reboot`, a watchdog) between
    two commands is invisible and the epoch never moves. The log itself holds
    the ground truth either way: a second banner means a second boot, and
    anything before it belongs to a guest that no longer exists.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = start_offset if 0 <= start_offset <= size else 0
            stream.seek(offset)
            chunk = stream.read()
    except OSError:
        return start_offset

    last = None
    for match in _BOOT_BANNER.finditer(chunk):
        last = match
    return offset + last.start() if last is not None else offset


def count_boot_banners(
    log_path: str | Path, *, start_offset: int = 0, end_offset: int | None = None
) -> int:
    """How many kernel boot banners appear in `[start_offset, end_offset)`
    (`end_offset` None = EOF).

    The daemon uses this to tell an epoch it *observed* from one the banner
    heuristic would have to infer: a RESET it saw is followed by exactly one
    banner (the boot it started); a second banner after the recorded epoch
    means a reboot nobody witnessed, and the record's `observed` label no
    longer describes the current boot. The incremental caller bounds the
    range at its line-aligned scan mark so a banner split across two reads
    is counted once.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = start_offset if 0 <= start_offset <= size else 0
            stream.seek(offset)
            length = -1 if end_offset is None else max(0, end_offset - offset)
            chunk = stream.read(length)
    except OSError:
        return 0
    return sum(1 for _ in _BOOT_BANNER.finditer(chunk))


def current_boot_offset(log_path: str | Path, epoch_offset: int | None) -> int:
    """Byte offset where the *current* guest's output begins.

    The later of the recorded guest epoch (advanced only on an observed QMP
    RESET) and the newest kernel boot banner in the log. This is the one scope
    every reader of guest state must share — the guest-usability axis, SSH
    preflight, and `wait --pattern` — so that a panic from a previous boot can
    never label a healthy guest as gone on one path while another path calls
    it serving.
    """
    start = epoch_offset or 0
    return max(start, last_boot_offset(log_path, start_offset=start))


def is_terminal_panic_start(line: str) -> bool:
    """Match a terminal panic start, not a prior report's end banner."""
    return bool(_FATAL_PANIC_START.search(line)) and not _is_crash_end(line)


def has_terminal_panic(log_path: str | Path, *, start_offset: int = 0) -> bool:
    """Whether the guest took a panic it cannot return from.

    The discriminator between a guest that DIED and one that merely reported a
    crash and kept running. `extract_crash` matches Oops/WARNING/KASAN too, and
    under the default `exploit-dev` profile (deliberately no `oops=panic`) an
    Oops kills only the faulting task — the guest keeps serving. Treating that
    as death tells the operator to reap a working VM.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = start_offset if 0 <= start_offset <= size else 0
            stream.seek(offset)
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    return _text_has_terminal_panic(text)


def scan_console_growth(
    log_path: str | Path, *, scanned: int, boot_offset: int
) -> tuple[int, int, bool]:
    """Examine only the bytes appended since `scanned`; return
    `(scanned, boot_offset, terminal_panic)`.

    The incremental form of `last_boot_offset` + `has_terminal_panic` for a
    poll loop: both read from `boot_offset` to EOF on every call, so a wait
    over a chatty guest cost O(log size) per tick (r2-shared measured 10 s of
    CPU for a 20 s wait). `scanned` is line-aligned — the trailing fragment
    without a newline is re-read next call, so a banner or panic split across
    two reads is still seen whole. A newer banner moves `boot_offset`, and
    only lines after it count toward the panic verdict: a panic before the
    banner belongs to the boot that just ended. A log that shrank underneath
    the loop (truncated, replaced) is a new log generation: BOTH boundaries
    reset and the whole file is rescanned, so the returned `boot_offset` can
    be lower than the one passed in. Resetting `scanned` alone kept the old
    generation's boot boundary, which then hid every byte of the new log —
    banner and panic included — behind an offset past its end.
    """
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            shrank = scanned > size
            if shrank:
                scanned = 0
                boot_offset = 0
            if size <= scanned:
                return scanned, boot_offset, False
            stream.seek(scanned)
            chunk = stream.read()
    except OSError:
        return scanned, boot_offset, False

    last = None
    for match in _BOOT_BANNER.finditer(chunk):
        last = match
    region_start = 0
    if last is not None and (shrank or scanned + last.start() > boot_offset):
        boot_offset = scanned + last.start()
        region_start = last.start()
    elif scanned < boot_offset:
        # A caller whose `scanned` trails its `boot_offset`: skip what
        # precedes the boot.
        region_start = min(len(chunk), boot_offset - scanned)

    newline = chunk.rfind(b"\n")
    complete = chunk[: newline + 1] if newline >= 0 else b""
    panicked = _text_has_terminal_panic(
        chunk[region_start:].decode("utf-8", errors="replace")
    )
    return scanned + len(complete), boot_offset, panicked


def read_log(log_path: str | Path) -> str | None:
    """Return the whole serial log, or None when it is missing/unreadable."""
    path = Path(log_path)
    if not path.exists():
        return None
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def tail_log(log_path: str | Path, lines: int = 50) -> str | None:
    """Return the last N lines of the serial log.

    Like ``tail -n``, ``lines <= 0`` yields no output: it returns "" (empty
    string), which stays distinguishable from a missing/unreadable file
    (None). NOTE: ``all_lines[-0:]`` would be the WHOLE list, so the
    ``lines <= 0`` case must be handled before slicing.
    """
    path = Path(log_path)
    if not path.exists():
        return None

    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None

    if lines <= 0:
        return ""

    all_lines = text.splitlines()
    selected = all_lines[-lines:]
    return "\n".join(selected) + ("\n" if selected else "")
