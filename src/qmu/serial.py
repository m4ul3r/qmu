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


def _soft_end_links_to_fatal_panic(lines: list[str], end_index: int) -> bool:
    """Return whether the next nonblank line is the fatal panic continuation."""
    for line in lines[end_index + 1:]:
        if not line.strip():
            continue
        return bool(
            _FATAL_PANIC_START.search(line) and not _is_crash_end(line)
        )
    return False


def serial_log_offset(log_path: str | Path) -> int:
    """Return the readable serial stream's current byte size, or zero."""
    try:
        with Path(log_path).open("rb") as stream:
            return os.fstat(stream.fileno()).st_size
    except OSError:
        return 0


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
