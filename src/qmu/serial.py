from __future__ import annotations

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
        r"KASAN:",
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


_SOFT_END_TRACE = re.compile(r"---\[ end trace")
_FATAL_PANIC_START = re.compile(r"Kernel panic - not syncing", re.IGNORECASE)


def _is_crash_start(line: str) -> bool:
    # An end-trace banner (e.g. "---[ end Kernel panic ... ]---") contains the
    # substring "Kernel panic" and would otherwise match a start pattern. Treat
    # any end-marker line as END-only so it can never be mistaken for a start.
    if _is_crash_end(line):
        return False
    return any(p.search(line) for p in CRASH_START_PATTERNS)


def _is_crash_end(line: str) -> bool:
    return any(p.search(line) for p in CRASH_END_PATTERNS)


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

    def read_lines(self) -> list[str]:
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
        except OSError:
            return []

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

    def flush(self) -> list[str]:
        """Return any withheld trailing fragment, then clear it."""
        if not self._partial:
            return []
        remainder = self._partial.rstrip("\r")
        self._partial = ""
        return [remainder]


def extract_crash(
    log_path: str | Path,
    max_context_lines: int = 500,
    *,
    start_offset: int = 0,
) -> str | None:
    """Return the last crash wholly discoverable at or after a byte boundary."""
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

    lines = text.splitlines()
    if not lines:
        return None

    # Only scan the tail for performance
    tail = lines[-max_context_lines:]

    # Walk backwards to find the first line of the last crash event. A soft
    # WARNING "end trace" remains part of the same event only when it leads
    # directly to a fatal panic continuation. Every other end marker is a hard
    # boundary between discrete events.
    crash_start = None
    for i in range(len(tail) - 1, -1, -1):
        if _is_crash_start(tail[i]):
            crash_start = i
        elif crash_start is not None and _is_crash_end(tail[i]):
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
        if _is_crash_end(tail[i]):
            end = i + 1
            break

    return "\n".join(tail[crash_start:end]) + "\n"


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
# The leading printk timestamp is REQUIRED, and is the whole point: the real
# banner is emitted by printk and carries one, while anything userspace echoes
# to the console cannot. Without it a guest could write a banner-shaped line
# after a survived crash — `dmesg` or `cat /proc/version` to the console does it
# without trying — and hide that crash from the guest-state axis. Matching at
# line start additionally stops a banner quoted mid-line from counting.
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
    return bool(_FATAL_PANIC_START.search(text))


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
