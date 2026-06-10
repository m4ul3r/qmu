"""Tests for qmu.config.resolve_config — layered config precedence + profile merge.

These tests require NO VM. They exercise the documented contract
(SKILL.md:12-17): defaults < global < project < CLI.

Isolation seams used:
  * QMU_CONFIG_DIR  -> paths.config_home()/global_config_path() (the GLOBAL layer)
  * config_path_override=  -> the PROJECT layer (explicit --config)
  * monkeypatched CWD       -> so find_project_config() does NOT pick up the
                               repo's own tests/qmu.toml during the defaults test.

All tests here PASS against the current implementation; they pin the layering
logic so a precedence regression (e.g. global winning over project, or a CLI
None clobbering a config value) would be caught.

Findings exercised: TC-4 / TC-5.
"""

from __future__ import annotations

import pytest

from qmu.config import CONFIG_FILENAME, DEFAULT_PROFILES, resolve_config
from qmu.instance import QMUError


@pytest.fixture(autouse=True)
def isolate_config(tmp_path, monkeypatch):
    """Point the global-config dir at an empty tmp dir and chdir into an empty
    dir so neither the user's real global config nor the repo's tests/qmu.toml
    leak into resolve_config()."""
    global_dir = tmp_path / "global-config"
    global_dir.mkdir()
    monkeypatch.setenv("QMU_CONFIG_DIR", str(global_dir))
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return tmp_path


def _write_toml(path, text):
    path.write_text(text)
    return path


def _global_config(tmp_path, text):
    """config_home() == $QMU_CONFIG_DIR; global file is config_home()/config.toml."""
    return _write_toml(tmp_path / "global-config" / "config.toml", text)


def test_defaults_only(isolate_config):
    """No global, no project, no CLI -> built-in defaults."""
    cfg = resolve_config()
    assert cfg.arch == "x86_64"
    assert cfg.memory == "4G"
    assert cfg.cpus == 2
    assert cfg.profiles == DEFAULT_PROFILES
    assert cfg._sources == ["built-in defaults"]


def test_global_overrides_defaults(isolate_config):
    _global_config(isolate_config, '[machine]\nmemory = "8G"\n')
    cfg = resolve_config()
    assert cfg.memory == "8G"
    # arch untouched -> still default
    assert cfg.arch == "x86_64"
    assert any(s.startswith("global:") for s in cfg._sources)


def test_project_overrides_global(isolate_config):
    """Project layer (via config_path_override) wins over global; sources are
    ordered defaults -> global -> project."""
    _global_config(isolate_config, '[machine]\nmemory = "8G"\ncpus = 4\n')
    project = _write_toml(
        isolate_config / "project.toml", '[machine]\nmemory = "16G"\n'
    )
    cfg = resolve_config(config_path_override=project)
    assert cfg.memory == "16G"        # project wins over global
    assert cfg.cpus == 4              # only-in-global value preserved
    src = cfg._sources
    assert src[0] == "built-in defaults"
    assert any(s.startswith("global:") for s in src)
    assert any(s.startswith("config:") for s in src)
    assert src.index(next(s for s in src if s.startswith("global:"))) < src.index(
        next(s for s in src if s.startswith("config:"))
    )


def test_cli_overrides_all(isolate_config):
    _global_config(isolate_config, '[machine]\nmemory = "8G"\n')
    project = _write_toml(
        isolate_config / "project.toml", '[machine]\nmemory = "16G"\n'
    )
    cfg = resolve_config(
        cli_overrides={"memory": "32G"}, config_path_override=project
    )
    assert cfg.memory == "32G"
    assert cfg._sources[-1] == "CLI flags"


def test_cli_none_does_not_clobber(isolate_config):
    """A CLI override of None must NOT overwrite a config/default value
    (pins config.py:130-136)."""
    project = _write_toml(
        isolate_config / "project.toml", '[machine]\nmemory = "16G"\n'
    )
    cfg = resolve_config(
        cli_overrides={"memory": None, "cpus": None}, config_path_override=project
    )
    assert cfg.memory == "16G"   # not clobbered by None
    assert cfg.cpus == 2         # default preserved


def test_cli_int_coercion(isolate_config):
    """cpus/port_start are coerced to int from TOML (pins config.py:96,112)."""
    project = _write_toml(
        isolate_config / "project.toml",
        '[machine]\ncpus = 8\n[ssh]\nport_start = 12000\n',
    )
    cfg = resolve_config(config_path_override=project)
    assert cfg.cpus == 8
    assert isinstance(cfg.cpus, int)
    assert cfg.ssh_port_start == 12000
    assert isinstance(cfg.ssh_port_start, int)


def test_profiles_extend_not_replace_dict_form(isolate_config):
    """A project-defined profile (dict/cmdline form) is ADDED to the defaults,
    not replacing them (pins config.py:118-125)."""
    project = _write_toml(
        isolate_config / "project.toml",
        '[profiles.custom]\ncmdline = "console=ttyS0 my=custom"\n',
    )
    cfg = resolve_config(config_path_override=project)
    # default profiles still present
    for name in DEFAULT_PROFILES:
        assert name in cfg.profiles
    # plus the custom one
    assert cfg.profiles["custom"] == "console=ttyS0 my=custom"


def test_profiles_string_form(isolate_config):
    """A project profile given as a bare string is accepted (config.py:124-125)."""
    project = _write_toml(
        isolate_config / "project.toml",
        '[profiles]\nbare = "console=ttyS0 bare=1"\n',
    )
    cfg = resolve_config(config_path_override=project)
    assert cfg.profiles["bare"] == "console=ttyS0 bare=1"


def test_profile_override_existing_name(isolate_config):
    """Defining a profile with an existing default name overrides that entry."""
    project = _write_toml(
        isolate_config / "project.toml",
        '[profiles.exploit-dev]\ncmdline = "console=ttyS0 overridden=1"\n',
    )
    cfg = resolve_config(config_path_override=project)
    assert cfg.profiles["exploit-dev"] == "console=ttyS0 overridden=1"
    # other defaults untouched
    assert cfg.profiles["trigger-test"] == DEFAULT_PROFILES["trigger-test"]


def test_broken_global_config_is_skipped(isolate_config, capsys):
    """Malformed global TOML must not raise; resolve_config falls back to
    lower layers but emits a one-line stderr warning naming the file."""
    gpath = _global_config(isolate_config, "this is = = not valid toml [[[\n")
    project = _write_toml(
        isolate_config / "project.toml", '[machine]\nmemory = "16G"\n'
    )
    cfg = resolve_config(config_path_override=project)  # must not raise
    assert cfg.memory == "16G"
    # global layer skipped -> not recorded as a source
    assert not any(s.startswith("global:") for s in cfg._sources)
    err = capsys.readouterr().err
    assert "Warning" in err
    assert str(gpath) in err


def test_broken_global_config_alone_yields_defaults(isolate_config, capsys):
    """With ONLY a broken global config present, resolve_config still returns
    built-in defaults (non-fatal) and warns on stderr."""
    _global_config(isolate_config, "not [ valid = toml\n")
    cfg = resolve_config()  # must not raise
    assert cfg.memory == "4G"
    assert cfg.arch == "x86_64"
    assert cfg._sources == ["built-in defaults"]
    assert "Warning" in capsys.readouterr().err


def test_broken_explicit_config_raises_qmu_error(isolate_config):
    """A broken --config file is FATAL: QMUError naming the file, not a raw
    tomllib traceback."""
    project = _write_toml(
        isolate_config / "project.toml", "this is = = not valid toml [[[\n"
    )
    with pytest.raises(QMUError, match="Failed to parse config"):
        resolve_config(config_path_override=project)


def test_broken_explicit_config_error_names_file(isolate_config):
    project = _write_toml(isolate_config / "project.toml", "broken = [\n")
    with pytest.raises(QMUError) as excinfo:
        resolve_config(config_path_override=project)
    assert str(project.resolve()) in str(excinfo.value)
    # original parse error chained for debugging
    assert excinfo.value.__cause__ is not None


def test_broken_discovered_project_config_raises_qmu_error(
    isolate_config, monkeypatch
):
    """A broken qmu.toml discovered via the CWD walk-up is also FATAL with a
    QMUError naming the file."""
    projdir = isolate_config / "proj"
    projdir.mkdir()
    broken = _write_toml(projdir / CONFIG_FILENAME, "broken = = toml [[[\n")
    monkeypatch.chdir(projdir)
    with pytest.raises(QMUError, match="Failed to parse config") as excinfo:
        resolve_config()
    assert str(broken) in str(excinfo.value)
