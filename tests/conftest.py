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
  * HOME            -> paths.skill_install_roots() and every *_home() default
Individual tests may further override these (e.g. test_config.py sets its own
QMU_CONFIG_DIR and chdir's into an empty dir); that is fine — monkeypatch within
a test wins over this autouse default and is undone at test teardown.

HOME is in that list because `qmu skill install` MUTATES it: it symlinks each
skill into every root `paths.skill_install_roots()` returns. Any test that
reaches that handler (today `test_cli_config_errors`'s exempt-verb sweep runs
it for real) writes into whatever homes are live. Guarding the individual
*_HOME overrides per test does not close this: the set of roots GROWS — the
~/.agents root arrived with OMP support and immediately turned that sweep into
a rewrite of the developer's real ~/.agents/skills links, pointing them at the
throwaway checkout the suite happened to run from. One redirect at the seam
every root derives from is the only version that stays correct when the next
root is added; the overrides are cleared with it so an exported CLAUDE_HOME or
AGENTS_HOME in the developer's shell cannot re-escape the sandbox.
"""

from __future__ import annotations

import tempfile

import pytest

from qmu.config import reset_global_config_warnings


@pytest.fixture(autouse=True)
def isolate_qmu_env(tmp_path_factory, monkeypatch):
    cache_dir = tmp_path_factory.mktemp("qmu-cache")
    config_dir = tmp_path_factory.mktemp("qmu-config")
    tmp_dir = tmp_path_factory.mktemp("qmu-tmp")
    runtime_dir = tmp_path_factory.mktemp("qmu-runtime")
    home_dir = tmp_path_factory.mktemp("qmu-home")

    monkeypatch.setenv("QMU_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("QMU_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("QMU_TEMP_DIR", str(runtime_dir))
    monkeypatch.setenv("TMPDIR", str(tmp_dir))
    monkeypatch.setenv("HOME", str(home_dir))
    for var in ("CLAUDE_HOME", "CODEX_HOME", "AGENTS_HOME", "PI_CODING_AGENT_DIR"):
        monkeypatch.delenv(var, raising=False)

    # TMPDIR is honored by tempfile.gettempdir() when tests exercise the
    # platform-temp fallback.
    monkeypatch.setattr(tempfile, "tempdir", None)

    # A leftover warn-once entry from a previous test (or a test that calls
    # resolve_config() directly, bypassing cli.main's own reset) must not
    # mask the same message in this test.
    reset_global_config_warnings()

    yield

    # Restore tempfile's cache after the test so later code re-resolves cleanly.
    monkeypatch.setattr(tempfile, "tempdir", None)
