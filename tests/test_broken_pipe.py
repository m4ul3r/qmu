"""A closed stdout reader is not an operation failure (#208).

`qmu … | head -1` with the reader gone used to print `[qmu] Error: [Errno 32]
Broken pipe` and exit 4 (infra) after the command had done its work. These
run the real CLI in a subprocess whose stdout is a pipe with no reader, the
only way to get a real EPIPE on fd 1.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


def _run_into_widowed_pipe(*argv: str) -> subprocess.CompletedProcess:
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        return subprocess.run(
            [sys.executable, "-m", "qmu", *argv],
            stdout=write_end, stderr=subprocess.PIPE, timeout=60,
        )
    finally:
        os.close(write_end)


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_success_keeps_exit_zero_and_writes_no_error(fmt):
    proc = _run_into_widowed_pipe("--format", fmt, "version")
    assert proc.returncode == 0
    assert proc.stderr == b""


def test_a_failed_operation_keeps_its_own_code_not_infra():
    proc = _run_into_widowed_pipe("--format", "json", "status", "--vm", "no-such-vm")
    assert proc.returncode == 1
    assert b"Broken pipe" not in proc.stderr


def test_a_usage_error_keeps_exit_2_without_a_traceback():
    proc = _run_into_widowed_pipe("--format", "json", "status", "--bogus")
    assert proc.returncode == 2
    assert b"Traceback" not in proc.stderr
