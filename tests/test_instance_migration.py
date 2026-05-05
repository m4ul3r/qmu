"""Old-schema VMInstance JSON should load tolerantly — fills new fields with defaults."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qmu.instance import _instance_from_dict


def test_old_schema_fills_defaults():
    """A pre-harness JSON dict (lacking harness/nic_model) loads with defaults."""
    raw = {
        "vm_id": "vm-10022",
        "pid": 12345,
        "qmp_socket": "/tmp/qmp.sock",
        "ssh_port": 10022,
        "ssh_key": "/home/u/.ssh/id_rsa",
        "gdb_port": None,
        "serial_log": "/tmp/serial.log",
        "kernel": "/boot/bzImage",
        "rootfs": "/var/rootfs.img",
        "memory": "4G",
        "cpus": 2,
        "cmdline": "console=ttyS0",
        "profile": "exploit-dev",
        "started_at": "2026-05-05T00:00:00Z",
    }
    inst = _instance_from_dict(raw)
    assert inst.harness is False
    assert inst.nic_model is None
    assert inst.ssh_port == 10022
    assert inst.rootfs == "/var/rootfs.img"


def test_unknown_keys_are_ignored():
    """Future schema additions in JSON files don't crash older clients."""
    raw = {
        "vm_id": "vm-10022",
        "pid": 12345,
        "qmp_socket": "/tmp/qmp.sock",
        "ssh_port": 10022,
        "ssh_key": "/home/u/.ssh/id_rsa",
        "gdb_port": None,
        "serial_log": "/tmp/serial.log",
        "kernel": "/boot/bzImage",
        "rootfs": "/var/rootfs.img",
        "memory": "4G",
        "cpus": 2,
        "cmdline": "console=ttyS0",
        "profile": "exploit-dev",
        "started_at": "2026-05-05T00:00:00Z",
        # Hypothetical future field
        "future_thing": {"a": 1},
    }
    inst = _instance_from_dict(raw)
    assert inst.vm_id == "vm-10022"


def test_harness_instance_with_nulls():
    raw = {
        "vm_id": "vm-h12345",
        "pid": 99,
        "qmp_socket": "/tmp/qmp.sock",
        "ssh_port": None,
        "ssh_key": None,
        "gdb_port": None,
        "serial_log": "/tmp/serial.log",
        "kernel": "/boot/bzImage",
        "rootfs": None,
        "memory": "3.5G",
        "cpus": 2,
        "cmdline": "init=/run.sh",
        "profile": "exploit-dev",
        "started_at": "2026-05-05T00:00:00Z",
        "harness": True,
        "nic_model": "virtio-net-pci",
    }
    inst = _instance_from_dict(raw)
    assert inst.harness is True
    assert inst.ssh_port is None
    assert inst.ssh_key is None
    assert inst.rootfs is None


def test_missing_required_field_raises():
    """Genuinely-broken JSON (missing required field) still errors."""
    with pytest.raises(TypeError):
        _instance_from_dict({"vm_id": "x"})  # missing tons of required fields
