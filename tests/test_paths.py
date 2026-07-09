from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from qmu.paths import (
    SSH_CONTROL_PATH_MAX_BYTES,
    runtime_root,
    spill_root,
    ssh_control_dir,
    ssh_control_path,
)


def test_runtime_root_prefers_qmu_temp_dir(tmp_path, monkeypatch):
    override = tmp_path / "override"
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("QMU_TEMP_DIR", str(override))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    assert runtime_root() == override


def test_runtime_root_uses_usable_xdg_runtime_dir(tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    xdg.mkdir(mode=0o700)
    monkeypatch.delenv("QMU_TEMP_DIR", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    assert runtime_root() == xdg / "qmu"


def test_runtime_root_rejects_relative_xdg_and_falls_back(tmp_path, monkeypatch):
    platform_tmp = tmp_path / "platform-tmp"
    platform_tmp.mkdir()
    monkeypatch.delenv("QMU_TEMP_DIR", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "relative/runtime")
    monkeypatch.setenv("TMPDIR", str(platform_tmp))
    monkeypatch.setattr(tempfile, "tempdir", None)
    assert runtime_root() == platform_tmp / "qmu"


def test_runtime_root_falls_back_when_xdg_is_missing(tmp_path, monkeypatch):
    platform_tmp = tmp_path / "platform-tmp"
    platform_tmp.mkdir()
    monkeypatch.delenv("QMU_TEMP_DIR", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setenv("TMPDIR", str(platform_tmp))
    monkeypatch.setattr(tempfile, "tempdir", None)
    assert runtime_root() == platform_tmp / "qmu"


def test_runtime_root_falls_back_when_xdg_is_not_a_directory(
    tmp_path, monkeypatch
):
    platform_tmp = tmp_path / "platform-tmp"
    platform_tmp.mkdir()
    xdg = tmp_path / "xdg-file"
    xdg.write_text("not a directory")
    monkeypatch.delenv("QMU_TEMP_DIR", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    monkeypatch.setenv("TMPDIR", str(platform_tmp))
    monkeypatch.setattr(tempfile, "tempdir", None)
    assert runtime_root() == platform_tmp / "qmu"


def test_runtime_children_derive_from_override_and_are_private(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    monkeypatch.setenv("QMU_TEMP_DIR", str(root))
    assert spill_root() == root / "spills"
    assert ssh_control_dir() == root / "ssh"
    assert stat.S_IMODE(spill_root().stat().st_mode) == 0o700
    assert stat.S_IMODE(ssh_control_dir().stat().st_mode) == 0o700


def test_control_path_expansion_stays_inside_portable_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_TEMP_DIR", str(tmp_path / "r"))
    path = ssh_control_path()
    assert path is not None
    expanded = os.fsencode(str(path).replace("%C", "0" * 40))
    assert len(expanded) <= SSH_CONTROL_PATH_MAX_BYTES == 100


def test_overlong_explicit_root_disables_control_path(tmp_path, monkeypatch):
    root = tmp_path / ("x" * 80)
    monkeypatch.setenv("QMU_TEMP_DIR", str(root))
    assert ssh_control_path() is None


def test_helpers_resolve_environment_on_every_call(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    root_a = Path("a")
    root_b = Path("b")

    monkeypatch.setenv("QMU_TEMP_DIR", str(root_a))
    assert runtime_root() == root_a
    assert spill_root() == root_a / "spills"
    assert ssh_control_dir() == root_a / "ssh"
    assert ssh_control_path() == root_a / "ssh" / "cm-%C"

    monkeypatch.setenv("QMU_TEMP_DIR", str(root_b))
    assert runtime_root() == root_b
    assert spill_root() == root_b / "spills"
    assert ssh_control_dir() == root_b / "ssh"
    assert ssh_control_path() == root_b / "ssh" / "cm-%C"
