from __future__ import annotations

import bisect
import os
import re
from pathlib import Path


CRASH_START_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"BUG: KASAN:",
        r"BUG: KMSAN:",
        r"BUG: KCSAN:",
        r"BUG: kernel NULL pointer dereference",
        r"BUG: unable to handle",
        r"BUG: soft lockup",
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

CRASH_END_PATTERNS = [
    re.compile(p)
    for p in [
        r"---\[ end trace",
        r"Kernel Offset:",
        r"Rebooting in \d+ seconds",
        r"---\[ end Kernel panic",
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


_SOFT_END_TRACE = re.compile(r"---\[ end trace")
_FATAL_PANIC_START = re.compile(r"Kernel panic - not syncing", re.IGNORECASE)


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
# panic: the register re-dump, the module list, the frame list, and the
# "note: <task> exited with irqs disabled" tail.
_EPILOGUE_LINE = re.compile(
    r"^(?:"
    r"(?:R[A-Z0-9]{1,3}|RIP|RSP|RBP|CR[0-9]|FS|GS|DS|ES|CS|SS|EFLAGS|PKRU)\b"
    r"|Code:"
    r"|Modules linked in:"
    r"|note: .*exited"
    r"|Call Trace:"
    r"|Hardware name:|CPU:|Comm:|Tainted:"
    r"|</?TASK>"
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
    for line in lines[end_index + 1:]:
        if not line.strip():
            continue
        seen += 1
        if seen > _PANIC_CONTINUATION_WINDOW:
            return False
        if _FATAL_PANIC_START.search(line) and not _is_crash_end(line):
            return True
        if _is_crash_end(line):
            # Another end marker with no panic yet: this episode is over.
            if not _SOFT_END_TRACE.search(line):
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

    # Walk backwards to find the first line of the last crash event. A soft
    # WARNING "end trace" remains part of the same event only when it leads
    # directly to a fatal panic continuation. Every other end marker is a hard
    # boundary between discrete events.
    crash_start = None
    for i in range(len(tail) - 1, -1, -1):
        if i in start_lines:
            crash_start = i
        elif crash_start is not None and i in end_lines:
            if _SOFT_END_TRACE.search(tail[i]) and _soft_end_links_to_fatal_panic(tail, i):
                continue
            break

    if crash_start is None:
        return None

    # Capture through the LAST end-marker at or after the start (the epilogue may
    # have several end lines); fall back to end-of-tail for a crash still in
    # progress (no end banner yet).
    end = len(tail)
    for i in range(len(tail) - 1, crash_start, -1):
        if i in end_lines:
            end = i + 1
            break

    return "\n".join(tail[crash_start:end]) + "\n"


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
