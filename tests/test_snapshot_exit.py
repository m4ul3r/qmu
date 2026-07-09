"""Tests for the snapshot failure detector (cli._snapshot_failed) — H3.

HMP loadvm/savevm errors arrive as a normal result string, not a QMP protocol
error, so nothing raises and the snapshot handlers previously returned exit 0
even when loadvm did NOT restore the VM. cli._snapshot_failed(msg) classifies the
returned HMP text so the handlers can exit non-zero on a real failure while still
treating benign savevm slirp WARNINGS as success.

The marker set reflects the captured QEMU 11 HMP transcript: a benign
"warning: Slirp: Save of field ... failed" save still produced a listable
image, while the observed load error contained "Section footer error" and
"Missing section footer for slirp".

Findings exercised: SNAP-1 / ERG-3 / QMU-3 / H3.
"""

from __future__ import annotations

import pytest

from qmu import cli
from qmu.commands import qmp_cmds


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


# --- Snapshot runtime failure guidance -------------------------------------


import argparse
import contextlib


class _FakeInst:
    vm_id = "dev"
    qmp_socket = "/tmp/nonexistent.sock"


def _patch_save(monkeypatch, msg):
    """Stub the handler's collaborators so _handle_snapshot_save runs offline:
    choose_instance returns a dummy inst, _qmp_ctx is a no-op CM, and
    save_snapshot returns the HMP `msg` verbatim (as snapshot.py does)."""
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _FakeInst())
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(None))
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name: msg)


def _save_args():
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_save_failure_hint_distinguishes_temporary_and_durable(monkeypatch, capsys):
    _patch_save(monkeypatch, "Error: Could not open 'savevm' section")
    rc = qmp_cmds._handle_snapshot_save(_save_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "Could not open 'savevm' section" in err
    assert "temporary" in err
    assert "snapshot=on" in err
    assert "in-session" in err
    assert "raw or qcow2" in err
    assert "durable" in err
    assert "writable qcow2" in err
    assert "without snapshot=on" in err
    assert "--drive" in err
    assert "changing [drive] format alone" in err.lower()
    assert "passt" not in err.lower()
    assert "raw images cannot hold" not in err.lower()


def test_snapshot_save_success_emits_no_hint(monkeypatch, capsys):
    # A clean save must not print the failure hint or exit non-zero.
    _patch_save(monkeypatch, "Snapshot 'clean' saved.")
    rc = qmp_cmds._handle_snapshot_save(_save_args())
    assert rc == 0
    captured = capsys.readouterr()
    assert "qcow2" not in captured.err
    assert "snapshot save failed" not in captured.err


def _patch_load(monkeypatch, msg):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: _FakeInst())
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(None))
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name: msg)


def _load_args():
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_load_slirp_error_has_conditional_compatibility_guidance(monkeypatch, capsys):
    msg = "Missing section footer for slirp\nError: Section footer error, section_id: 1"
    _patch_load(monkeypatch, msg)
    rc = qmp_cmds._handle_snapshot_load(_load_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert msg in err
    assert "names slirp" in err
    assert "often works" in err
    assert "this QEMU/build/device combination" in err
    assert "advertises native '-netdev passt'" in err
    assert "QEMU 10.1" in err
    assert "build-optional" in err
    assert "external passt" in err
    assert "stream" in err
    assert "qmu does not manage" in err
    assert "cannot serialize NIC state" not in err


def test_snapshot_load_slirp_detection_is_case_insensitive(monkeypatch, capsys):
    msg = "Missing section footer for SLIRP"
    _patch_load(monkeypatch, msg)
    rc = qmp_cmds._handle_snapshot_load(_load_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert msg in err
    assert "names slirp" in err
    assert "advertises native '-netdev passt'" in err


def test_snapshot_load_non_slirp_error_does_not_diagnose_network(monkeypatch, capsys):
    msg = "Error: Snapshot 'missing' does not exist"
    _patch_load(monkeypatch, msg)
    rc = qmp_cmds._handle_snapshot_load(_load_args())
    assert rc == 1
    err = capsys.readouterr().err
    assert "snapshot load failed" in err
    assert msg in err
    assert "passt" not in err.lower()
    assert "stream" not in err.lower()
    assert "slirp" not in err.lower()
