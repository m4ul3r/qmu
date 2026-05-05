"""qmu rootfs — guestfish missing should produce a clear install hint."""

from __future__ import annotations

from unittest import mock

import pytest

from qmu.instance import QMUError
from qmu import rootfs as rootfs_mod


def test_missing_guestfish_raises_with_install_hint():
    with mock.patch.object(rootfs_mod.shutil, "which", return_value=None):
        with pytest.raises(QMUError) as excinfo:
            rootfs_mod._require_guestfish()
    msg = str(excinfo.value)
    assert "guestfish" in msg
    assert "libguestfs-tools" in msg


def test_parse_mapping_basic():
    assert rootfs_mod.parse_mapping("./run.sh:/root/") == ("./run.sh", "/root/")


def test_parse_mapping_only_first_colon_splits():
    """Guest paths could in principle contain colons (rare); split on first only."""
    local, guest = rootfs_mod.parse_mapping("/tmp/a:/etc/rc:d/foo")
    assert local == "/tmp/a"
    assert guest == "/etc/rc:d/foo"


def test_parse_mapping_rejects_missing_colon():
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping("nope")


def test_parse_mapping_rejects_empty_side():
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping(":foo")
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping("foo:")


def test_mount_args_partition_zero_uses_whole_disk():
    assert rootfs_mod._mount_args(0) == ["-m", "/dev/sda"]


def test_mount_args_partition_one_default():
    assert rootfs_mod._mount_args(1) == ["-m", "/dev/sda1"]


def test_inject_image_missing_raises():
    with pytest.raises(QMUError):
        rootfs_mod.inject("/nonexistent/img", [], partition=1)
