from __future__ import annotations

import pytest

from qmu.config import render_starter_config


def test_generated_config_distinguishes_all_three_snapshot_modes():
    text = render_starter_config("x86_64")
    guidance = " ".join(text.replace("#", " ").split()).lower()

    assert "temporary snapshot=on overlay" in guidance
    assert "raw or qcow2" in guidance
    assert "in-session" in guidance
    assert "disappear when qemu exits" in guidance

    assert "durable" in guidance
    assert "writable qcow2" in guidance
    assert "without snapshot=on" in guidance
    assert "--drive 'file=./rootfs.qcow2,format=qcow2'" in guidance
    assert "changing [drive] format alone" in guidance

    assert "default user/slirp often restores" in guidance
    assert "if loadvm reports slirp" in guidance
    assert "selected qemu must advertise native passt" in guidance
    assert "qemu 10.1" in guidance
    assert "build-optional" in guidance
    assert "external passt" in guidance
    assert "stream" in guidance
    assert "qmu does not manage" in guidance


@pytest.mark.parametrize(
    "legacy_claim",
    [
        "slirp cannot be snapshotted",
        "snapshots also require a qcow2",
        "raw images cannot hold them",
        'set format = "qcow2" to use snapshots',
        "so snapshots work",
        "qemu 9",
        "10.1+",
    ],
)
def test_generated_config_has_no_obsolete_absolute_snapshot_claims(legacy_claim):
    assert legacy_claim not in render_starter_config("x86_64").lower()
