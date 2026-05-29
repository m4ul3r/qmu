"""Tests for qmu.ssh.is_transport_failure — the rc=255 crash-disambiguation seam.

These tests require NO VM. They pin the H1 fix: a kernel panic drops the SSH
connection and ssh exits rc=255 *normally* (not TimeoutExpired), so the crash
path was previously skipped. is_transport_failure(rc, stderr) distinguishes a
genuine ssh transport loss (rc==255 AND a known local-client transport marker on
stderr) from an ordinary guest process that legitimately exits 255.

Findings exercised: SSH-1 / QMU-1 / ERG-1 / H1.
"""

from __future__ import annotations

import pytest

from qmu.ssh import SSH_TRANSPORT_ERROR_MARKERS, is_transport_failure


def test_transport_loss_on_banner_exchange_is_failure():
    """rc=255 with the keepalive banner-exchange marker -> transport loss
    (probable kernel panic)."""
    stderr = "ssh: connect to host localhost port 10021: " \
             "Connection timed out during banner exchange"
    assert is_transport_failure(255, stderr) is True


def test_ordinary_guest_stderr_is_not_failure():
    """rc=255 with ordinary guest stderr (no transport marker) -> NOT a transport
    loss; a guest may legitimately exit(255)."""
    assert is_transport_failure(255, "ordinary guest stderr") is False
    assert is_transport_failure(255, "") is False


def test_non_255_rc_is_never_transport_failure():
    """Only rc==255 can be a transport loss; rc=3 with a marker is a guest exit."""
    marker = SSH_TRANSPORT_ERROR_MARKERS[0]
    assert is_transport_failure(3, marker) is False
    assert is_transport_failure(0, marker) is False
    assert is_transport_failure(1, marker) is False


def test_every_marker_classifies_rc255_as_failure():
    """Each documented marker, embedded in a realistic stderr, is detected."""
    assert SSH_TRANSPORT_ERROR_MARKERS  # non-empty contract
    for marker in SSH_TRANSPORT_ERROR_MARKERS:
        stderr = f"client: {marker} -- giving up"
        assert is_transport_failure(255, stderr) is True, marker
