from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from qmu import cli
import qmu.instance as instance_module
from qmu.instance import (
    InstanceArtifacts,
    VMInstance,
    discover_instance_artifacts,
    list_prunable_instance_ids,
    proc_pid_start,
    remove_instance,
    save_instance,
)
from qmu.paths import instances_dir, spill_root, ssh_control_dir
from qmu.runtime import mark_spill_artifact


@pytest.fixture(autouse=True)
def short_isolated_roots(tmp_path, monkeypatch):
    """Keep real Unix socket paths short and every artifact per-test."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("QMU_CACHE_DIR", "cache")
    monkeypatch.setenv("QMU_TEMP_DIR", "runtime")


def _touch(vm_id: str, suffix: str, *, mtime: float = 1.0) -> Path:
    path = instances_dir() / f"{vm_id}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    os.utime(path, (mtime, mtime))
    return path


def _instance(
    vm_id: str,
    *,
    pid: int = 999_999_999,
    pid_start: str | None = None,
) -> VMInstance:
    return VMInstance(
        vm_id=vm_id,
        pid=pid,
        qmp_socket=str(instances_dir() / f"{vm_id}.qmp.sock"),
        ssh_port=None,
        ssh_key=None,
        ssh_user="root",
        gdb_port=None,
        serial_log=str(instances_dir() / f"{vm_id}.serial.log"),
        kernel="/boot/bzImage",
        rootfs=None,
        memory="1G",
        cpus=1,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00Z",
        harness=True,
        nic_model=None,
        pid_start=pid_start,
    )


def _stale_qmp(vm_id: str, *, mtime: float = 1.0) -> Path:
    path = instances_dir() / f"{vm_id}.qmp.sock"
    path.parent.mkdir(parents=True, exist_ok=True)
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        control.bind(str(path))
    finally:
        control.close()
    os.utime(path, (mtime, mtime))
    return path


@pytest.fixture
def sleeper():
    proc = subprocess.Popen(["sleep", "30"])
    try:
        yield proc
    finally:
        if proc.returncode is None:
            proc.terminate()
            proc.wait()


def test_discover_instance_artifacts_groups_only_known_suffixes():
    json_path = _touch("failed", ".json")
    qmp = _touch("failed", ".qmp.sock")
    serial = _touch("failed", ".serial.log")
    qemu = _touch("failed", ".qemu.log")
    _touch("failed", ".unknown")

    assert discover_instance_artifacts() == [
        InstanceArtifacts(
            vm_id="failed",
            instance=None,
            invalid_json=True,
            json_path=json_path,
            qmp_socket=qmp,
            serial_log=serial,
            qemu_log=qemu,
        )
    ]


def test_qemu_log_only_remnant_is_discoverable_and_age_gated():
    _touch("failed", ".qemu.log", mtime=900.0)
    assert [item.vm_id for item in discover_instance_artifacts()] == ["failed"]
    assert list_prunable_instance_ids(
        older_than_seconds=100.0, now=1000.0
    ) == ["failed"]
    assert list_prunable_instance_ids(
        older_than_seconds=100.1, now=1000.0
    ) == []


def test_qmp_only_remnant_is_discoverable():
    qmp = _touch("qmp-only", ".qmp.sock")
    assert discover_instance_artifacts() == [
        InstanceArtifacts(
            vm_id="qmp-only",
            instance=None,
            invalid_json=False,
            json_path=None,
            qmp_socket=qmp,
            serial_log=None,
            qemu_log=None,
        )
    ]


def test_live_qmp_only_bundle_is_not_prunable():
    path = instances_dir() / "live-qmp.qmp.sock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()
        os.utime(path, (1.0, 1.0))
        assert list_prunable_instance_ids(
            older_than_seconds=0.0, now=1000.0
        ) == []
        assert path.exists()


def test_stale_qmp_only_bundle_is_prunable_at_age_boundary():
    _stale_qmp("stale-qmp", mtime=900.0)
    assert list_prunable_instance_ids(
        older_than_seconds=100.0, now=1000.0
    ) == ["stale-qmp"]


def test_indeterminate_qmp_probe_is_not_prunable(monkeypatch):
    path = _stale_qmp("uncertain-qmp", mtime=1.0)
    monkeypatch.setattr(
        instance_module, "probe_unix_socket", lambda _path: "indeterminate"
    )
    assert list_prunable_instance_ids(
        older_than_seconds=0.0, now=1000.0
    ) == []
    assert path.exists()


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="live identity needs /proc")
def test_parseable_live_instance_is_never_prunable(sleeper):
    start = proc_pid_start(sleeper.pid)
    assert start is not None
    save_instance(_instance("live", pid=sleeper.pid, pid_start=start))
    _touch("live", ".qemu.log", mtime=1.0)

    assert list_prunable_instance_ids(
        older_than_seconds=0.0, now=1000.0
    ) == []


def test_parseable_stopped_instance_retains_immediate_prune_behavior():
    save_instance(_instance("stopped"))
    assert list_prunable_instance_ids(
        older_than_seconds=1_000_000.0, now=1000.0
    ) == ["stopped"]


def test_serial_only_orphan_retains_immediate_prune_behavior():
    _touch("serial-only", ".serial.log", mtime=999.9)
    assert list_prunable_instance_ids(
        older_than_seconds=1_000_000.0, now=1000.0
    ) == ["serial-only"]


def test_malformed_json_without_serial_is_skipped_conservatively():
    json_path = _touch("invalid", ".json", mtime=1.0)
    json_path.write_text("{not-json")
    _touch("invalid", ".qemu.log", mtime=1.0)

    bundles = discover_instance_artifacts()
    assert [(bundle.vm_id, bundle.invalid_json) for bundle in bundles] == [
        ("invalid", True)
    ]
    assert list_prunable_instance_ids(
        older_than_seconds=0.0, now=1000.0
    ) == []


def test_discovery_ignores_unknown_suffixes_nested_content_and_unrelated_files():
    real = _touch("real", ".qemu.log")
    _touch("unknown", ".other")
    nested = instances_dir() / "nested"
    nested.mkdir()
    (nested / "nested.qemu.log").write_text("nested")
    directory = instances_dir() / "directory.qemu.log"
    directory.mkdir()
    symlink = instances_dir() / "symlink.qemu.log"
    symlink.symlink_to(real.resolve())

    assert [bundle.vm_id for bundle in discover_instance_artifacts()] == ["real"]


def test_remove_instance_is_idempotent_for_qemu_log_and_qmp_only_bundle():
    qemu = _touch("failed", ".qemu.log")
    qmp = _touch("failed", ".qmp.sock")

    remove_instance("failed")
    remove_instance("failed")

    assert not qemu.exists()
    assert not qmp.exists()


def test_prune_all_removes_aged_qemu_log_only_bundle(capsys):
    qemu = _touch("old-log", ".qemu.log", mtime=1.0)

    rc = cli.main(
        ["prune", "--all", "--older-than", "100", "--format", "text"]
    )

    assert rc == 0
    assert not qemu.exists()
    assert "old-log" in capsys.readouterr().out


def test_prune_all_skips_young_qemu_log_only_bundle(capsys):
    qemu = _touch("young-log", ".qemu.log", mtime=1.0)

    rc = cli.main(
        ["prune", "--all", "--older-than", "1e20", "--format", "text"]
    )

    assert rc == 0
    assert qemu.exists()
    assert capsys.readouterr().out == "No stopped VMs to prune.\n"


def test_prune_all_skips_live_qmp_only_bundle(capsys):
    path = instances_dir() / "live-cli.qmp.sock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen()
        os.utime(path, (1.0, 1.0))

        rc = cli.main(
            ["prune", "--all", "--older-than", "0", "--format", "text"]
        )

        assert rc == 0
        assert path.exists()
        assert capsys.readouterr().out == "No stopped VMs to prune.\n"


def test_prune_vm_removes_stale_qmp_only_bundle(capsys):
    path = _stale_qmp("stale-cli", mtime=1.0)

    rc = cli.main(
        [
            "prune",
            "--vm",
            "stale-cli",
            "--older-than",
            "0",
            "--format",
            "text",
        ]
    )

    assert rc == 0
    assert not path.exists()
    assert "stale-cli" in capsys.readouterr().out


def test_prune_keep_logs_preserves_both_logs_for_orphan_bundle(capsys):
    serial = _touch("forensics", ".serial.log")
    qemu = _touch("forensics", ".qemu.log")
    qmp = _touch("forensics", ".qmp.sock")

    rc = cli.main(
        [
            "prune",
            "--all",
            "--older-than",
            "0",
            "--keep-logs",
            "--format",
            "json",
        ]
    )

    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "pruned": ["forensics"],
        "keep_logs": True,
    }
    assert serial.exists()
    assert qemu.exists()
    assert not qmp.exists()


def test_prune_instance_is_idempotent(capsys):
    qemu = _touch("once", ".qemu.log", mtime=1.0)

    first = cli.main(
        ["prune", "--all", "--older-than", "0", "--format", "text"]
    )
    capsys.readouterr()
    second = cli.main(
        ["prune", "--all", "--older-than", "0", "--format", "text"]
    )

    assert first == second == 0
    assert not qemu.exists()
    assert capsys.readouterr().out == "No stopped VMs to prune.\n"


def test_prune_runtime_json_result_shape(capsys):
    artifact = spill_root() / "old.txt"
    artifact.write_text("owned")
    mark_spill_artifact(artifact, created_at=1.0)
    control_path = ssh_control_dir() / "cm-live"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(control_path))
        listener.listen()
        os.utime(control_path, (1.0, 1.0))

        rc = cli.main(
            [
                "prune",
                "--runtime",
                "--older-than",
                "86400",
                "--format",
                "json",
            ]
        )

        assert rc == 0
        assert json.loads(capsys.readouterr().out) == {
            "ok": True,
            "runtime": {
                "older_than_seconds": 86400.0,
                "removed": [{"kind": "spill", "path": str(artifact)}],
                "skipped_live": [
                    {"kind": "ssh-control", "path": str(control_path)}
                ],
                "skipped_indeterminate": [],
            },
        }
        assert not artifact.exists()
        assert control_path.exists()


def test_prune_runtime_ndjson_is_one_valid_object_line(capsys):
    rc = cli.main(
        [
            "prune",
            "--runtime",
            "--older-than",
            "0",
            "--format",
            "ndjson",
        ]
    )
    lines = capsys.readouterr().out.splitlines()

    assert rc == 0
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "ok": True,
        "runtime": {
            "older_than_seconds": 0.0,
            "removed": [],
            "skipped_live": [],
            "skipped_indeterminate": [],
        },
    }


def test_prune_runtime_text_reports_counts(capsys):
    artifact = spill_root() / "old.txt"
    artifact.write_text("owned")
    mark_spill_artifact(artifact, created_at=1.0)

    rc = cli.main(
        ["prune", "--runtime", "--older-than", "0", "--format", "text"]
    )

    assert rc == 0
    assert capsys.readouterr().out == (
        "Pruned 1 qmu-owned runtime artifact(s); "
        "skipped 0 live and 0 indeterminate.\n"
    )
    assert not artifact.exists()


def test_prune_runtime_rejects_keep_logs(capsys):
    rc = cli.main(
        [
            "prune",
            "--runtime",
            "--older-than",
            "0",
            "--keep-logs",
            "--format",
            "text",
        ]
    )

    assert rc == 1
    assert "--keep-logs applies only to instance pruning." in capsys.readouterr().err
