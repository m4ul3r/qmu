"""Shared pytest fixtures for the qmu test suite.

The autouse `isolate_qmu_env` fixture redirects every qmu storage location to
per-test temp dirs so the suite NEVER touches the developer's real
~/.cache/qmu, ~/.config/qmu, or shared runtime directories, and so the repo's
own tests/qmu.toml cannot leak into config-resolution tests.

Seams (see src/qmu/paths.py):
  * QMU_CACHE_DIR   -> paths.cache_home()        (instances, sockets, serial logs)
  * QMU_CONFIG_DIR  -> paths.config_home()       (global config.toml)
  * QMU_TEMP_DIR    -> paths.runtime_root()      (spills, SSH control sockets)
  * TMPDIR          -> tempfile.gettempdir()     (runtime fallback and shell tests)
Individual tests may further override these (e.g. test_config.py sets its own
QMU_CONFIG_DIR and chdir's into an empty dir); that is fine — monkeypatch within
a test wins over this autouse default and is undone at test teardown.
"""

from __future__ import annotations

import tempfile

import pytest


@pytest.fixture(autouse=True)
def isolate_qmu_env(tmp_path_factory, monkeypatch):
    cache_dir = tmp_path_factory.mktemp("qmu-cache")
    config_dir = tmp_path_factory.mktemp("qmu-config")
    tmp_dir = tmp_path_factory.mktemp("qmu-tmp")
    runtime_dir = tmp_path_factory.mktemp("qmu-runtime")

    monkeypatch.setenv("QMU_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("QMU_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("QMU_TEMP_DIR", str(runtime_dir))
    monkeypatch.setenv("TMPDIR", str(tmp_dir))

    # TMPDIR is honored by tempfile.gettempdir() when tests exercise the
    # platform-temp fallback.
    monkeypatch.setattr(tempfile, "tempdir", None)

    yield

    # Restore tempfile's cache after the test so later code re-resolves cleanly.
    monkeypatch.setattr(tempfile, "tempdir", None)
