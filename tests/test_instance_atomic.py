"""save_instance must write atomically: no truncated .json, no leftover temps.

A crash mid-write previously left a partial file that readers silently skip,
making a live VM vanish from `qmu list`. These tests pin the atomic-replace
behavior. The autouse isolate_qmu_env fixture (conftest.py) points
QMU_CACHE_DIR at a per-test tmp dir, so instances_dir() is disposable here.
"""

from __future__ import annotations

import pytest

from qmu.instance import (
    VMInstance,
    load_instance,
    remove_instance,
    save_guest_epoch_serial_offset,
    save_instance,
)
from qmu.paths import instances_dir


def _make(vm_id: str, **overrides) -> VMInstance:
    kw = dict(
        vm_id=vm_id,
        pid=4242,
        qmp_socket="/tmp/qmp.sock",
        ssh_port=10022,
        ssh_key="/home/u/.ssh/id_rsa",
        gdb_port=None,
        serial_log="/tmp/serial.log",
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-05T00:00:00Z",
    )
    kw.update(overrides)
    return VMInstance(**kw)


def test_save_load_roundtrip():
    inst = _make("vm-10022")
    path = save_instance(inst)
    assert path.exists()
    loaded = load_instance("vm-10022")
    assert loaded == inst


def test_guest_epoch_offset_roundtrips():
    inst = _make("vm-10022", guest_epoch_serial_offset=4096)
    save_instance(inst)
    assert load_instance("vm-10022") == inst


def test_save_guest_epoch_offset_returns_new_persisted_record():
    original = _make("vm-10022", guest_epoch_serial_offset=7)
    save_instance(original)

    updated = save_guest_epoch_serial_offset(original, 99)

    assert original.guest_epoch_serial_offset == 7
    assert updated.guest_epoch_serial_offset == 99
    assert load_instance("vm-10022") == updated


@pytest.mark.parametrize(
    ("offset", "expected_error"),
    (
        pytest.param(-1, ValueError, id="negative"),
        pytest.param(True, TypeError, id="bool"),
        pytest.param(1.5, TypeError, id="float"),
        pytest.param("99", TypeError, id="string"),
        pytest.param(None, TypeError, id="none"),
    ),
)
def test_save_guest_epoch_offset_rejects_invalid_without_persisting(
    offset, expected_error
):
    original = _make("vm-10022", guest_epoch_serial_offset=7)
    record = save_instance(original)
    original_json = record.read_bytes()

    with pytest.raises(expected_error):
        save_guest_epoch_serial_offset(original, offset)

    assert original.guest_epoch_serial_offset == 7
    assert record.read_bytes() == original_json
    assert load_instance("vm-10022") == original
    assert list(instances_dir().glob("*.tmp")) == []


def test_failed_epoch_replace_preserves_old_record_and_caller(monkeypatch):
    original = _make("vm-10022", guest_epoch_serial_offset=7)
    save_instance(original)

    def fail_replace(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr("qmu.instance.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        save_guest_epoch_serial_offset(original, 99)

    assert original.guest_epoch_serial_offset == 7
    assert load_instance("vm-10022") == original
    assert list(instances_dir().glob("*.tmp")) == []


def test_no_leftover_temp_files():
    save_instance(_make("vm-10022"))
    leftovers = list(instances_dir().glob("*.tmp"))
    assert leftovers == [], f"stray temp files remain: {leftovers}"


def test_overwrite_replaces_existing():
    save_instance(_make("vm-10022", pid=1))
    save_instance(_make("vm-10022", pid=2))

    loaded = load_instance("vm-10022")
    assert loaded is not None and loaded.pid == 2
    # A single record file, and no temp debris from the second write.
    assert list(instances_dir().glob("vm-10022.json*")) == [
        instances_dir() / "vm-10022.json"
    ]


def test_pretty_printed_with_trailing_newline():
    path = save_instance(_make("vm-10022"))
    text = path.read_text()
    assert text.endswith("\n")
    assert "\n  " in text  # indent=2 pretty printing


def _touch(vm_id: str, suffix: str) -> None:
    (instances_dir() / f"{vm_id}{suffix}").write_text("x")


def test_remove_instance_clears_qemu_log_by_default():
    save_instance(_make("vm-10022"))
    # launch_vm writes a <vm_id>.qemu.log alongside the serial log; a default
    # kill/prune must not orphan it.
    _touch("vm-10022", ".serial.log")
    _touch("vm-10022", ".qemu.log")

    remove_instance("vm-10022")

    idir = instances_dir()
    assert not (idir / "vm-10022.json").exists()
    assert not (idir / "vm-10022.serial.log").exists()
    assert not (idir / "vm-10022.qemu.log").exists()


def test_remove_instance_keep_logs_preserves_both_logs():
    save_instance(_make("vm-10022"))
    _touch("vm-10022", ".serial.log")
    _touch("vm-10022", ".qemu.log")

    remove_instance("vm-10022", keep_logs=True)

    idir = instances_dir()
    assert not (idir / "vm-10022.json").exists()
    assert (idir / "vm-10022.serial.log").exists()
    assert (idir / "vm-10022.qemu.log").exists()
