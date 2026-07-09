from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qmu import cli
from qmu.commands import lifecycle


@pytest.fixture
def config_cli_env(tmp_path, monkeypatch):
    global_dir = tmp_path / "global-config"
    project_dir = tmp_path / "project"
    global_dir.mkdir()
    project_dir.mkdir()
    monkeypatch.setenv("QMU_CONFIG_DIR", str(global_dir))
    monkeypatch.chdir(project_dir)
    return {
        "global": global_dir / "config.toml",
        "project": project_dir / "qmu.toml",
        "explicit": tmp_path / "explicit.toml",
        "kernel": tmp_path / "unused-bzImage",
    }


def _install_source(env, source_kind, text):
    path = env[source_kind]
    path.write_text(text)
    explicit_args = ["--config", str(path.resolve())] if source_kind == "explicit" else []
    return path.resolve(), explicit_args


def _command_argv(command, env, explicit_args):
    if command == "config-show":
        return ["config", "show", *explicit_args]
    if command == "doctor":
        return ["doctor", *explicit_args]
    return [
        "launch",
        "--kernel",
        str(env["kernel"]),
        "--harness",
        *explicit_args,
    ]


def _assert_error(captured, rc, fmt, source, key_path=None, hint=None):
    assert rc == 1
    if fmt == "text":
        assert captured.out == ""
        assert "[qmu] Error:" in captured.err
        message = captured.err
    else:
        assert captured.err == ""
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "ConfigError"
        message = payload["error"]
    assert str(source) in message
    if key_path is not None:
        assert f"key '{key_path}'" in message
    if hint is not None:
        assert hint in message


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("command", ["config-show", "doctor", "launch"])
@pytest.mark.parametrize("source_kind", ["project", "explicit"])
def test_flat_rootfs_fails_every_command_and_source(
    config_cli_env,
    monkeypatch,
    capsys,
    fmt,
    command,
    source_kind,
):
    def unexpected_launch(**kwargs):
        pytest.fail("launch_vm must not run for invalid config")

    monkeypatch.setattr(lifecycle, "launch_vm", unexpected_launch)
    source, explicit_args = _install_source(
        config_cli_env,
        source_kind,
        'rootfs = "/tmp/rootfs.img"\n',
    )
    rc = cli.main(["--format", fmt, *_command_argv(command, config_cli_env, explicit_args)])
    _assert_error(
        capsys.readouterr(),
        rc,
        fmt,
        source,
        key_path="rootfs",
        hint="[drive] rootfs",
    )


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("command", ["config-show", "doctor", "launch"])
@pytest.mark.parametrize("source_kind", ["project", "explicit"])
def test_malformed_toml_fails_every_command_and_source(
    config_cli_env,
    monkeypatch,
    capsys,
    fmt,
    command,
    source_kind,
):
    def unexpected_launch(**kwargs):
        pytest.fail("launch_vm must not run for malformed config")

    monkeypatch.setattr(lifecycle, "launch_vm", unexpected_launch)
    source, explicit_args = _install_source(
        config_cli_env,
        source_kind,
        "broken = [\n",
    )
    rc = cli.main(["--format", fmt, *_command_argv(command, config_cli_env, explicit_args)])
    _assert_error(capsys.readouterr(), rc, fmt, source)


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("bad", ['rootfs = "/tmp/rootfs.img"\n', "broken = [\n"])
def test_broken_global_config_does_not_fail_commands(
    config_cli_env, capsys, fmt, bad
):
    """A broken GLOBAL config (schema-invalid or malformed) must warn and be
    skipped, not turn every command into an exit-1 failure. Regression guard
    for the CLAUDE.md contract: only project/explicit configs are fatal."""
    source, _ = _install_source(config_cli_env, "global", bad)

    rc = cli.main(["--format", fmt, "config", "show"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "[qmu] Warning:" in captured.err
    assert str(source) in captured.err
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is True


@pytest.mark.parametrize("command", ["config-show", "doctor", "launch"])
def test_config_error_ndjson_is_one_object(
    config_cli_env, monkeypatch, capsys, command
):
    def unexpected_launch(**kwargs):
        pytest.fail("launch_vm must not run for invalid config")

    monkeypatch.setattr(lifecycle, "launch_vm", unexpected_launch)
    source, explicit_args = _install_source(
        config_cli_env,
        "project",
        '[machine]\nmemroy = "8G"\n',
    )
    rc = cli.main([
        "--format",
        "ndjson",
        *_command_argv(command, config_cli_env, explicit_args),
    ])
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["ok"] is False
    assert payload["error_type"] == "ConfigError"
    assert str(source) in payload["error"]
    assert "machine.memroy" in payload["error"]
    assert captured.err == ""
    assert rc == 1


@pytest.mark.parametrize(
    ("text", "key_path", "fragment"),
    [
        ('machien = {}\n', "machien", "unknown top-level key"),
        ('[machine]\nmemroy = "8G"\n', "machine.memroy", "unknown key"),
        ('[ssh]\narch = "x86_64"\n', "ssh.arch", "[machine] arch"),
        ('machine = "x86_64"\n', "machine", "expected table"),
        ('[machine]\ncpus = true\n', "machine.cpus", "expected integer"),
    ],
)
def test_config_show_json_preserves_schema_detail(
    config_cli_env, capsys, text, key_path, fragment
):
    source, explicit_args = _install_source(config_cli_env, "explicit", text)
    rc = cli.main([
        "--format",
        "json",
        "config",
        "show",
        *explicit_args,
    ])
    captured = capsys.readouterr()
    _assert_error(captured, rc, "json", source, key_path=key_path)
    assert fragment in json.loads(captured.out)["error"]


def test_harness_launch_accepts_machine_only_config(
    config_cli_env, monkeypatch, capsys
):
    source, explicit_args = _install_source(
        config_cli_env,
        "explicit",
        '[machine]\nmemory = "1G"\n',
    )
    seen = {}

    def fake_launch_vm(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(
            harness=True,
            ssh_port=None,
            vm_id="schema-harness",
            pid=12345,
            gdb_port=None,
            kernel=str(config_cli_env["kernel"]),
            profile="exploit-dev",
            serial_log="/tmp/schema-harness.serial",
        )

    monkeypatch.setattr(lifecycle, "launch_vm", fake_launch_vm)
    rc = cli.main([
        "--format",
        "json",
        "launch",
        "--kernel",
        str(config_cli_env["kernel"]),
        "--harness",
        *explicit_args,
    ])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert rc == 0
    assert captured.err == ""
    assert payload["ok"] is True
    assert seen["harness"] is True
    assert seen["no_net"] is True
    assert seen["config"].rootfs is None
    assert seen["config"].ssh_key is None
    assert f"config: {source}" in seen["config"]._sources
