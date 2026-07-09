"""Tests for qmu.config.resolve_config — layered config precedence + profile merge.

These tests require NO VM. They exercise the documented contract
(SKILL.md:12-17): defaults < global < project < CLI.

Isolation seams used:
  * QMU_CONFIG_DIR  -> paths.config_home()/global_config_path() (the GLOBAL layer)
  * config_path_override=  -> the PROJECT layer (explicit --config)
  * monkeypatched CWD       -> so find_project_config() does NOT pick up the
                               repo's own tests/qmu.toml during the defaults test.

The compatibility tests pin layering and profile behavior. The schema tests
define the strict source-aware validation contract and intentionally fail until
the production validator is implemented.

Findings exercised: TC-4 / TC-5.
"""

from __future__ import annotations

import tomllib

import pytest

import qmu.config as config_module
from qmu.config import (
    CONFIG_FILENAME,
    DEFAULT_PROFILES,
    ConfigError,
    resolve_config,
)


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


_FLAT_MIGRATIONS = [
    pytest.param('rootfs = "/tmp/rootfs.img"\n', "rootfs", "[drive] rootfs", id="rootfs"),
    pytest.param('ssh_key = "/tmp/id_ed25519"\n', "ssh_key", "[ssh] key", id="ssh-key"),
    pytest.param('arch = "x86_64"\n', "arch", "[machine] arch", id="arch"),
]

_UNKNOWN_KEYS = [
    pytest.param('machien = { memory = "8G" }\n', "machien", id="top-level"),
    pytest.param('[machine]\nmemroy = "8G"\n', "machine.memroy", id="machine"),
    pytest.param('[drive]\nformt = "raw"\n', "drive.formt", id="drive"),
    pytest.param('[ssh]\nusr = "root"\n', "ssh.usr", id="ssh"),
    pytest.param('[gdb]\nport = 1234\n', "gdb.port", id="gdb"),
    pytest.param('[profiles.custom]\nextra = "bad"\n', "profiles.custom.extra", id="profile"),
]

_WRONG_PLACEMENTS = [
    pytest.param('[ssh]\narch = "x86_64"\n', "ssh.arch", "[machine] arch", id="arch-in-ssh"),
    pytest.param('[drive]\nmemory = "8G"\n', "drive.memory", "[machine] memory", id="memory-in-drive"),
    pytest.param('port_start = 10021\n', "port_start", "[ssh] port_start", id="ambiguous-port-ssh"),
]

_NON_TABLE_SECTIONS = [
    pytest.param('machine = "x86_64"\n', "machine", "string", id="machine"),
    pytest.param('drive = []\n', "drive", "array", id="drive"),
    pytest.param('ssh = false\n', "ssh", "boolean", id="ssh"),
    pytest.param('gdb = 1234\n', "gdb", "integer", id="gdb"),
    pytest.param('profiles = "console=ttyS0"\n', "profiles", "string", id="profiles"),
]

_WRONG_VALUE_TYPES = [
    pytest.param('[machine]\narch = 1\n', "machine.arch", "string", id="arch"),
    pytest.param('[machine]\nmemory = 8\n', "machine.memory", "string", id="memory"),
    pytest.param('[machine]\ncpus = true\n', "machine.cpus", "integer", id="cpus-bool"),
    pytest.param('[machine]\ncpu = 1\n', "machine.cpu", "string", id="cpu"),
    pytest.param('[machine]\nnic_model = 1\n', "machine.nic_model", "string", id="nic-model"),
    pytest.param('[machine]\nnet_backend = 1\n', "machine.net_backend", "string", id="net-backend-type"),
    pytest.param('[machine]\nextra_args = "-M virt"\n', "machine.extra_args", "array of strings", id="extra-args-scalar"),
    pytest.param('[machine]\nextra_args = ["-M", 1]\n', "machine.extra_args[1]", "string", id="extra-args-element"),
    pytest.param('[drive]\nrootfs = 1\n', "drive.rootfs", "string", id="rootfs"),
    pytest.param('[drive]\nformat = 1\n', "drive.format", "string", id="drive-format"),
    pytest.param('[ssh]\nkey = 1\n', "ssh.key", "string", id="ssh-key"),
    pytest.param('[ssh]\nuser = 1\n', "ssh.user", "string", id="ssh-user"),
    pytest.param('[ssh]\nport_start = true\n', "ssh.port_start", "integer", id="ssh-port"),
    pytest.param('[gdb]\nport_start = "1234"\n', "gdb.port_start", "integer", id="gdb-port"),
    pytest.param('[profiles]\ncustom = 1\n', "profiles.custom", "string or table", id="profile-value"),
    pytest.param('[profiles.custom]\ncmdline = 1\n', "profiles.custom.cmdline", "string", id="profile-cmdline"),
]


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


@pytest.mark.parametrize(("text", "key_path", "destination"), _FLAT_MIGRATIONS)
def test_flat_known_key_reports_migration_hint(
    isolate_config, text, key_path, destination
):
    path = _write_toml(isolate_config / "flat.toml", text)
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    error = excinfo.value
    assert error.source == path.resolve()
    assert error.key_path == key_path
    assert str(path.resolve()) in str(error)
    assert f"key '{key_path}'" in str(error)
    assert destination in str(error)


@pytest.mark.parametrize(("text", "key_path"), _UNKNOWN_KEYS)
def test_unknown_key_reports_exact_source_and_path(isolate_config, text, key_path):
    path = _write_toml(isolate_config / "unknown.toml", text)
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    assert excinfo.value.source == path.resolve()
    assert excinfo.value.key_path == key_path
    assert "unknown" in str(excinfo.value)


@pytest.mark.parametrize(("text", "key_path", "destination"), _WRONG_PLACEMENTS)
def test_known_key_in_wrong_place_reports_destination(
    isolate_config, text, key_path, destination
):
    path = _write_toml(isolate_config / "misplaced.toml", text)
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    assert excinfo.value.key_path == key_path
    assert destination in str(excinfo.value)
    if key_path == "port_start":
        assert "[gdb] port_start" in str(excinfo.value)


@pytest.mark.parametrize(("text", "key_path", "actual_type"), _NON_TABLE_SECTIONS)
def test_known_section_must_be_a_table(
    isolate_config, text, key_path, actual_type
):
    path = _write_toml(isolate_config / "section-type.toml", text)
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    assert excinfo.value.key_path == key_path
    assert "expected table" in str(excinfo.value)
    assert actual_type in str(excinfo.value)


@pytest.mark.parametrize(("text", "key_path", "expected_type"), _WRONG_VALUE_TYPES)
def test_wrong_value_type_reports_exact_key(
    isolate_config, text, key_path, expected_type
):
    path = _write_toml(isolate_config / "value-type.toml", text)
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    assert excinfo.value.source == path.resolve()
    assert excinfo.value.key_path == key_path
    assert f"expected {expected_type}" in str(excinfo.value)


def test_invalid_net_backend_is_source_aware(isolate_config):
    path = _write_toml(
        isolate_config / "backend.toml",
        '[machine]\nnet_backend = "bridge"\n',
    )
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(config_path_override=path)
    assert excinfo.value.key_path == "machine.net_backend"
    assert "expected one of: user, passt" in str(excinfo.value)


def _install_source(isolate_config, monkeypatch, source_kind, text):
    if source_kind == "global":
        path = _global_config(isolate_config, text)
        return path, {}
    if source_kind == "project":
        project_dir = isolate_config / "discovered"
        project_dir.mkdir(exist_ok=True)
        path = _write_toml(project_dir / CONFIG_FILENAME, text)
        monkeypatch.chdir(project_dir)
        return path, {}
    path = _write_toml(isolate_config / "explicit.toml", text)
    return path, {"config_path_override": path}


@pytest.mark.parametrize("source_kind", ["global", "project", "explicit"])
def test_malformed_toml_is_fatal_and_source_aware(
    isolate_config, monkeypatch, source_kind
):
    path, kwargs = _install_source(
        isolate_config, monkeypatch, source_kind, "broken = [\n"
    )
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(**kwargs)
    assert excinfo.value.source == path.resolve()
    assert excinfo.value.key_path is None
    assert "failed to parse TOML" in str(excinfo.value)
    assert isinstance(excinfo.value.__cause__, tomllib.TOMLDecodeError)


@pytest.mark.parametrize("source_kind", ["global", "project", "explicit"])
def test_schema_invalid_toml_is_fatal_for_every_source(
    isolate_config, monkeypatch, source_kind
):
    path, kwargs = _install_source(
        isolate_config, monkeypatch, source_kind, 'rootfs = "/tmp/rootfs.img"\n'
    )
    with pytest.raises(ConfigError) as excinfo:
        resolve_config(**kwargs)
    assert excinfo.value.source == path.resolve()
    assert excinfo.value.key_path == "rootfs"
    assert "[drive] rootfs" in str(excinfo.value)


def test_invalid_layer_is_not_applied_before_validation(
    isolate_config, monkeypatch
):
    path = _write_toml(
        isolate_config / "atomic.toml",
        '[machine]\nmemory = "32G"\nunknown = true\n',
    )
    calls = []

    def record_apply(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(config_module, "_apply_toml", record_apply)
    with pytest.raises(ConfigError):
        resolve_config(config_path_override=path)
    assert calls == []


def test_empty_explicit_config_is_a_valid_recorded_layer(isolate_config):
    path = _write_toml(isolate_config / "empty.toml", "")
    cfg = resolve_config(config_path_override=path)
    assert cfg._sources == ["built-in defaults", f"config: {path.resolve()}"]


@pytest.mark.parametrize(
    "text",
    [
        "[machine]\n",
        "[drive]\n",
        "[ssh]\n",
        "[gdb]\n",
        "[profiles]\n",
        '[machine]\nmemory = "8G"\n',
        '[drive]\nformat = "raw"\n',
        '[ssh]\nuser = "root"\n',
        '[gdb]\nport_start = 2345\n',
        '[profiles.custom]\ncmdline = "console=ttyS0"\n',
        '[profiles]\nbare = "console=ttyS0"\n',
        "[profiles.empty]\n",
    ],
)
def test_partial_known_config_is_valid_without_drive_or_ssh(
    isolate_config, text
):
    path = _write_toml(isolate_config / "partial.toml", text)
    cfg = resolve_config(config_path_override=path)
    assert f"config: {path.resolve()}" in cfg._sources


def test_partial_layers_preserve_precedence_and_omitted_values(
    isolate_config, monkeypatch
):
    global_path = _global_config(
        isolate_config,
        '[machine]\nmemory = "8G"\n[drive]\nformat = "qcow2"\n',
    )
    project_dir = isolate_config / "layered-project"
    project_dir.mkdir()
    project_path = _write_toml(
        project_dir / CONFIG_FILENAME,
        '[machine]\ncpus = 6\n[ssh]\nuser = "builder"\n',
    )
    monkeypatch.chdir(project_dir)
    cfg = resolve_config(cli_overrides={"memory": "16G", "rootfs": None})
    assert cfg.memory == "16G"
    assert cfg.cpus == 6
    assert cfg.drive_format == "qcow2"
    assert cfg.ssh_user == "builder"
    assert cfg._sources == [
        "built-in defaults",
        f"global: {global_path.resolve()}",
        f"project: {project_path.resolve()}",
        "CLI flags",
    ]


def test_explicit_config_suppresses_invalid_discovered_project(
    isolate_config, monkeypatch
):
    project_dir = isolate_config / "project-with-invalid-file"
    project_dir.mkdir()
    _write_toml(project_dir / CONFIG_FILENAME, "arch = 'bad'\n")
    explicit = _write_toml(
        isolate_config / "valid-explicit.toml",
        '[machine]\narch = "aarch64"\n',
    )
    monkeypatch.chdir(project_dir)
    cfg = resolve_config(config_path_override=explicit)
    assert cfg.arch == "aarch64"
    assert f"config: {explicit.resolve()}" in cfg._sources
    assert not any(source.startswith("project:") for source in cfg._sources)
