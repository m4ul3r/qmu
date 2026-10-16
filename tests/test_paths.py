from __future__ import annotations

import stat
import sys
import tempfile
from pathlib import Path

import pytest

from qmu import paths as paths_mod
from qmu.paths import (
    SSH_CONTROL_PATH_MAX_BYTES,
    SSH_CONTROL_PATH_TEMP_SUFFIX_BYTES,
    runtime_root,
    spill_root,
    ssh_control_dir,
    ssh_control_path,
)

# A relative root `<name>/ssh/cm-<40-byte %C>` costs len(name) + 48 bytes;
# the longest name that still fits with OpenSSH's temporary suffix is this.
_FITTING_ROOT_LEN = SSH_CONTROL_PATH_MAX_BYTES - SSH_CONTROL_PATH_TEMP_SUFFIX_BYTES - 48


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


@pytest.mark.parametrize(
    "root_name,safe",
    [
        pytest.param("x" * _FITTING_ROOT_LEN, True, id="temporary-path-at-budget"),
        pytest.param("x" * (_FITTING_ROOT_LEN + 1), False, id="temporary-path-one-byte-over"),
        pytest.param("x" * (_FITTING_ROOT_LEN + 16), False, id="expanded-path-alone-near-budget"),
        pytest.param("é" * (_FITTING_ROOT_LEN // 2) + "x" * (_FITTING_ROOT_LEN % 2), True,
                     id="utf8-at-byte-boundary"),
        pytest.param("é" * (_FITTING_ROOT_LEN // 2 + 1), False,
                     id="utf8-bytes-exceed-character-count"),
    ],
)
def test_control_path_budgets_openssh_temporary_name(
    tmp_path, monkeypatch, root_name, safe
):
    monkeypatch.chdir(tmp_path)
    root = Path(root_name)
    monkeypatch.setenv("QMU_TEMP_DIR", root_name)
    expected = root / "ssh" / "cm-%C" if safe else None
    assert ssh_control_path() == expected


def test_budget_is_the_platform_sun_path_limit():
    """Linux binds 107 bytes + NUL; macOS/BSD 103 + NUL. The old flat 100
    lost multiplexing for a documented 85-byte private root (102 + NUL fits)."""
    if sys.platform.startswith("linux"):
        assert SSH_CONTROL_PATH_MAX_BYTES == 107
    else:
        assert SSH_CONTROL_PATH_MAX_BYTES == 103
    assert paths_mod._sun_path_budget() == SSH_CONTROL_PATH_MAX_BYTES


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux sun_path budget")
def test_documented_private_root_keeps_multiplexing_on_linux(monkeypatch):
    """`QMU_TEMP_DIR=<home>/qmu-audit/<facet>/run` expands to 85 bytes with
    the %C hash; 85 + 17 = 102 fits Linux's 107 and must keep ControlMaster."""
    root = "/home/" + "u" * 6 + "/qmu-audit/issues-prs/run"
    expanded = f"{root}/ssh/cm-" + "0" * 40
    assert len(expanded.encode()) + 17 <= 107
    assert 100 < len(expanded.encode()) + 17  # the old flat budget rejected it
    monkeypatch.setattr(paths_mod, "_runtime_child", lambda name: Path(root) / name)
    assert ssh_control_path() == Path(root) / "ssh" / "cm-%C"


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
