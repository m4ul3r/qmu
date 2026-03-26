from __future__ import annotations

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


def _is_crash_start(line: str) -> bool:
    return any(p.search(line) for p in CRASH_START_PATTERNS)


def _is_crash_end(line: str) -> bool:
    return any(p.search(line) for p in CRASH_END_PATTERNS)


def extract_crash(log_path: str | Path, max_context_lines: int = 500) -> str | None:
    """Extract the last crash/KASAN report from the serial log.

    Reads the last max_context_lines of the file, finds the start of the
    last crash block, and captures everything from that point to a crash
    end marker (or end of file).
    """
    path = Path(log_path)
    if not path.exists():
        return None

    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    # Only scan the tail for performance
    tail = lines[-max_context_lines:]

    # Find the last crash start
    crash_start = None
    for i, line in enumerate(tail):
        if _is_crash_start(line):
            crash_start = i

    if crash_start is None:
        return None

    # Capture from crash start to crash end (or end of tail)
    crash_lines = []
    for line in tail[crash_start:]:
        crash_lines.append(line)
        if _is_crash_end(line):
            break

    return "\n".join(crash_lines) + "\n"


def tail_log(log_path: str | Path, lines: int = 50) -> str | None:
    """Return the last N lines of the serial log."""
    path = Path(log_path)
    if not path.exists():
        return None

    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None

    all_lines = text.splitlines()
    selected = all_lines[-lines:] if len(all_lines) > lines else all_lines
    return "\n".join(selected) + "\n"
