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


# --- Fix #4: `snapshot save` failure emits an actionable qcow2/passt hint ----


import argparse
import contextlib


class _FakeInst:
    vm_id = "dev"
    qmp_socket = "/tmp/nonexistent.sock"


def _patch_save(monkeypatch, msg):
    """Stub the handler's collaborators so _handle_snapshot_save runs offline:
    choose_instance returns a dummy inst, _qmp_ctx is a no-op CM, and
    save_snapshot returns the HMP `msg` verbatim (as snapshot.py does)."""
    monkeypatch.setattr(cli, "choose_instance", lambda vm: _FakeInst())
    monkeypatch.setattr(cli, "_qmp_ctx", lambda inst: contextlib.nullcontext(None))
    monkeypatch.setattr(cli, "save_snapshot", lambda qmp, name: msg)


def _save_args():
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_save_failure_hint_mentions_qcow2_and_passt(monkeypatch, capsys):
    # savevm against the default raw disk fails; the stderr hint must explain the
    # real requirement (writable qcow2 rootfs) and the networking caveat (passt),
    # mirroring the load handler's actionable hint.
    _patch_save(monkeypatch, "Error: Could not open 'savevm' section")
    rc = cli._handle_snapshot_save(_save_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "qcow2" in err
    assert "raw" in err
    assert "passt" in err
    assert "savevm" in err


def test_snapshot_save_success_emits_no_hint(monkeypatch, capsys):
    # A clean save must not print the failure hint or exit non-zero.
    _patch_save(monkeypatch, "Snapshot 'clean' saved.")
    rc = cli._handle_snapshot_save(_save_args())
    assert rc == 0
    captured = capsys.readouterr()
    assert "qcow2" not in captured.err
    assert "snapshot save failed" not in captured.err
