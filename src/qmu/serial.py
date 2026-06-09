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
    # An end-trace banner (e.g. "---[ end Kernel panic ... ]---") contains the
    # substring "Kernel panic" and would otherwise match a start pattern. Treat
    # any end-marker line as END-only so it can never be mistaken for a start.
    if _is_crash_end(line):
        return False
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

    # Walk backwards to find the FIRST line of the LAST crash event. Going
    # backwards, keep moving the anchor earlier across start lines. An
    # end-marker does NOT necessarily terminate the block: a single logical
    # crash event commonly contains INTERIOR end-markers. The canonical case is
    # a WARNING/BUG that, under panic_on_warn, prints its own report epilogue
    # ("---[ end trace ]---") and is then IMMEDIATELY followed by a fatal
    # "Kernel panic - not syncing" + final "---[ end Kernel panic ]---" banner.
    # The interior "---[ end trace ]---" must not truncate the report (it would
    # drop the WARNING/BUG root cause, RIP and Call Trace — the only useful
    # part). A call trace can be arbitrarily long, so we cannot bound the
    # distance from a start line ABOVE the marker; instead we look just BELOW
    # the marker: an interior epilogue end-marker is followed almost immediately
    # by the next crash-start of the SAME event (the panic banner), whereas an
    # end-marker that closed a *previous, distinct* crash is followed by a run
    # of ordinary resumed kernel/boot output before any later crash. Epilogue
    # end-markers that precede the first start (a relocatable kernel prints
    # "Kernel Offset:" then the banner) are seen while the anchor is still None
    # and never split the block either.
    #
    # EPILOGUE_GAP: how soon below an interior end-marker the next crash-start
    # of the same event appears. Real panic_on_warn output goes from
    # "---[ end trace ]---" to "Kernel panic - not syncing" within a couple of
    # lines; a distinct prior crash is followed by far more resumed output.
    EPILOGUE_GAP = 8
    crash_start = None
    for i in range(len(tail) - 1, -1, -1):
        if _is_crash_start(tail[i]):
            crash_start = i
        elif crash_start is not None and _is_crash_end(tail[i]):
            # Is the next crash-start within EPILOGUE_GAP lines BELOW this
            # marker (i.e. between it and content we have already anchored)? If
            # so, the marker is interior to one event — don't split. Blank
            # lines do not count against the gap.
            window_end = min(len(tail), i + 1 + EPILOGUE_GAP)
            interior = False
            for j in range(i + 1, window_end):
                if _is_crash_start(tail[j]):
                    interior = True
                    break
            if interior:
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
    selected = all_lines[-lines:] if len(all_lines) > lines else all_lines
    return "\n".join(selected) + "\n"
