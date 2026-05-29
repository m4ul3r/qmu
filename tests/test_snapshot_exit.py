"""Tests for the snapshot failure detector (cli._snapshot_failed) — H3.

HMP loadvm/savevm errors arrive as a normal result string, not a QMP protocol
error, so nothing raises and the snapshot handlers previously returned exit 0
even when loadvm did NOT restore the VM. cli._snapshot_failed(msg) classifies the
returned HMP text so the handlers can exit non-zero on a real failure while still
treating benign savevm slirp WARNINGS as success.

The marker set must be specific enough that a benign
"warning: Slirp: Save of field ... failed" (live-transcript.md:205-206) is NOT a
failure, while real loadvm errors ("Section footer error" / "Missing section
footer for slirp") ARE.

Findings exercised: SNAP-1 / ERG-3 / QMU-3 / H3.
"""

from __future__ import annotations

import pytest

from qmu import cli


def _snapshot_failed(msg: str) -> bool:
    """Resolve the detector at call time so a not-yet-implemented fix surfaces as
    a clean test failure (RED) rather than a collection-time ImportError that
    aborts the whole suite."""
    fn = getattr(cli, "_snapshot_failed", None)
    assert fn is not None, (
        "cli._snapshot_failed is not implemented yet (H3/Fix 3 — snapshot "
        "load/save/delete must report HMP errors as failure)"
    )
    return fn(msg)


def test_section_footer_error_is_failure():
    assert _snapshot_failed("Error: Section footer error, section_id: 1") is True


def test_missing_section_footer_is_failure():
    assert _snapshot_failed("Missing section footer for slirp") is True


def test_combined_loadvm_error_is_failure():
    msg = "Missing section footer for slirp\nError: Section footer error, section_id: 1"
    assert _snapshot_failed(msg) is True


def test_benign_slirp_save_warning_is_not_failure():
    """The save-time slirp warning must NOT be classified as a hard failure — the
    snapshot still produced a listable image (live-transcript.md:203-208)."""
    warn = "warning: Slirp: Save of field slirp_bootpclient/macaddr failed"
    assert _snapshot_failed(warn) is False


def test_plain_success_message_is_not_failure():
    assert _snapshot_failed("Snapshot 'clean' loaded.") is False
    assert _snapshot_failed("Snapshot 'clean' saved.") is False
    assert _snapshot_failed("") is False
