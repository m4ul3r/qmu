from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from qmu import cli
from qmu.cli import build_parser
from qmu.commands import lifecycle
from qmu.instance import VMInstance, proc_pid_start, save_instance
from qmu.paths import instances_dir


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


# ---------------------------------------------------------------------------
# status: the last command that answered in project context without resolving
# project/explicit config (issue repro). status reads no boot settings from
# qmu.toml, but it operates in project context like launch/run/doctor/
# config-show, so a fatally-invalid project or --config source must gate it
# with the same exit-1 ConfigError those commands emit.
# ---------------------------------------------------------------------------

UNKNOWN_KEY = "definitely_not_a_qmu_key"


@pytest.fixture
def running_instance():
    """A real saved instance record whose pid is this test process, so
    choose_instance auto-selects it exactly as it would for a live VM."""
    d = instances_dir()
    pid = os.getpid()
    inst = VMInstance(
        vm_id="live", pid=pid,
        qmp_socket=str(d / "live.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log=str(d / "live.serial.log"), kernel="bzImage",
        rootfs="r.img", memory="1G", cpus=1, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="now",
        pid_start=proc_pid_start(pid),
    )
    save_instance(inst)
    (d / "live.serial.log").write_text("serial-of-live\n")
    (d / "live.qemu.log").write_text("")
    return inst


def _status_fatal_case(env, running_instance, capsys, argv):
    """Run `argv` against an unknown-top-level-key qmu.toml; assert the
    documented refusal names BOTH the source path and the offending key."""
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(env["project"].resolve()) in captured.err
    assert UNKNOWN_KEY in captured.err
    assert "unknown top-level key" in captured.err
    return captured


def test_status_fatal_on_invalid_project_config(
    config_cli_env, running_instance, capsys
):
    """The issue repro: a running instance exists and status would otherwise
    answer, but the project qmu.toml next to it carries an unknown top-level
    key — status must refuse with the exact error `config show` emits."""
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    captured = _status_fatal_case(
        config_cli_env, running_instance, capsys, ["status"]
    )

    # The refusal must match what `config show` emits byte-for-byte, so an
    # agent triaging via either command sees one message, not two dialects.
    rc = cli.main(["config", "show"])
    show_captured = capsys.readouterr()
    assert rc == 1
    assert show_captured.err == captured.err


def test_status_show_alias_fatal_on_invalid_project_config_too(
    config_cli_env, running_instance, capsys
):
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')
    _status_fatal_case(config_cli_env, running_instance, capsys, ["show"])


def test_status_explicit_config_fatal_on_invalid_path(
    config_cli_env, running_instance, capsys
):
    """The explicit-source layer of the same bypass: --config pointing at a
    fatally-invalid file must gate status like it gates config show."""
    bad = config_cli_env["explicit"]
    bad.write_text(f'{UNKNOWN_KEY} = "typo"\n')

    rc = cli.main(["status", "--config", str(bad.resolve())])
    captured = capsys.readouterr()

    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(bad.resolve()) in captured.err
    assert UNKNOWN_KEY in captured.err


def test_status_missing_explicit_config_path_is_error(
    config_cli_env, running_instance, capsys
):
    """A --config path that does not exist at all (not just invalid content)
    used to fall straight through resolve_config's `if ppath.is_file()` guard
    and answer on the pre-#37 message ("No running VMs") instead of refusing."""
    missing = config_cli_env["explicit"]  # never written

    rc = cli.main(["status", "--config", str(missing)])
    captured = capsys.readouterr()

    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(missing.resolve()) in captured.err


def test_list_missing_explicit_config_path_is_error(
    config_cli_env, running_instance, capsys
):
    """Same bypass through `list`: before the fix this silently dropped the
    explicit layer and printed "No VMs." at rc 0 instead of refusing."""
    missing = config_cli_env["explicit"]  # never written

    rc = cli.main(["list", "--config", str(missing)])
    captured = capsys.readouterr()

    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(missing.resolve()) in captured.err


def test_config_show_missing_explicit_config_path_is_error(
    config_cli_env, capsys
):
    missing = config_cli_env["explicit"]  # never written

    rc = cli.main(["config", "show", "--config", str(missing)])
    captured = capsys.readouterr()

    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(missing.resolve()) in captured.err


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_status_config_error_emits_exactly_one_false_record(
    config_cli_env, running_instance, capsys, fmt
):
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    rc = cli.main(["--format", fmt, "status"])
    captured = capsys.readouterr()

    assert rc == 1
    if fmt == "json":
        payloads = [json.loads(captured.out)]
    else:
        out_lines = captured.out.splitlines()
        assert len(out_lines) == 1
        payloads = [json.loads(out_lines[0])]
    (payload,) = payloads
    assert payload["ok"] is False
    assert payload["error_type"] == "ConfigError"
    assert UNKNOWN_KEY in payload["error"]


def test_broken_global_config_warns_and_status_continues(
    config_cli_env, running_instance, capsys
):
    """A broken GLOBAL config is never fatal — not even for status. It warns
    and answers on defaults, exactly like every other command."""
    config_cli_env["global"].write_text("broken = [\n")

    rc = cli.main(["--format", "json", "status"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert "[qmu] Warning: ignoring global config" in captured.err
    assert payload["ok"] is True
    assert payload["vm_id"] == "live"


def test_valid_project_config_keeps_status_working(
    config_cli_env, running_instance, capsys
):
    """The fatal gate must not fire on a healthy project: a schema-valid
    qmu.toml leaves status answering unchanged (exit 0, ok:true record)."""
    config_cli_env["project"].write_text(
        '[machine]\nmemory = "2G"\n[boot]\nkernel = "bzImage"\n'
    )

    rc = cli.main(["--format", "json", "status"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert captured.err == ""
    assert payload["ok"] is True
    assert payload["vm_id"] == "live"



@pytest.mark.parametrize("argv", [
    ["list"],
    ["log", "--vm", "live"],
    ["crash", "--vm", "live"],
], ids=["list", "log", "crash"])
def test_sibling_instance_commands_fatal_on_invalid_project_config(
    argv, config_cli_env, running_instance, capsys
):
    """Same bypass class as pre-fix #37 status: list/log/crash answer from
    instance records but operate in project context, so a fatally-invalid
    project qmu.toml must refuse them exactly like config show/status —
    exit 1 naming the source path and the offending key."""
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    rc = cli.main(argv)
    captured = capsys.readouterr()

    assert rc == 1
    assert "[qmu] Error:" in captured.err
    assert str(config_cli_env["project"].resolve()) in captured.err
    assert UNKNOWN_KEY in captured.err


@pytest.mark.parametrize("argv", [
    ["list"],
    ["log", "--vm", "live"],
])
def test_sibling_instance_commands_work_with_valid_project_config(
    argv, config_cli_env, running_instance, capsys
):
    """The gate must not break the happy path: with a valid (or absent)
    project qmu.toml the sibling commands behave exactly as before."""
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "[qmu] Error:" not in captured.err


def _subcommand_names() -> set[str]:
    parser = build_parser()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("no subparsers action on the qmu parser")


# Minimal argv that PARSES for each gated verb: argparse errors exit 2 before the
# dispatch gate runs, so a verb with a required positional needs one supplied.
MINIMAL_ARGV = {
    "launch": ["launch"], "run": ["run", "true"], "kill": ["kill"],
    "prune": ["prune"], "wait": ["wait"], "list": ["list"],
    "status": ["status"], "show": ["show"], "snapshot": ["snapshot"],
    "push": ["push", "f"], "pull": ["pull", "f"], "exec": ["exec", "true"],
    "compile": ["compile", "x.c"], "dmesg": ["dmesg"], "crash": ["crash"],
    "log": ["log"], "gdb": ["gdb"], "cont": ["cont"],
    # kbase's --symbols is required, so a bare ["kbase"] would exit 2 in
    # argparse before ever reaching the dispatch gate under test.
    "kbase": ["kbase", "--symbols", "System.map"],
    "qmp": ["qmp", "query-status"], "monitor": ["monitor", "info", "status"],
}


def test_minimal_argv_matches_gated_verbs():
    """MINIMAL_ARGV and the exempt set must partition the real subcommand
    list identically. Without this, moving a verb INTO the exempt set (e.g.
    appending "kill" to _CONFIG_EXEMPT_SUBCOMMANDS) silently deletes its row
    from the parametrize list below instead of failing anything — the exact
    #37 regression the reviewer reintroduced undetected."""
    assert set(MINIMAL_ARGV) == _subcommand_names() - cli._CONFIG_EXEMPT_SUBCOMMANDS


@pytest.mark.parametrize(
    "verb", sorted(_subcommand_names() - cli._CONFIG_EXEMPT_SUBCOMMANDS)
)
def test_every_non_exempt_verb_refuses_invalid_project_config(
    verb, config_cli_env, capsys
):
    """#37/#62: the gate is at the dispatch choke point, so EVERY non-exempt verb
    refuses before its handler runs. A new verb with no MINIMAL_ARGV entry fails
    here rather than silently joining the bypass class."""
    assert verb in MINIMAL_ARGV, (
        f"{verb!r}: add minimal argv here, or add it to "
        "cli._CONFIG_EXEMPT_SUBCOMMANDS with a written reason"
    )
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')
    rc = cli.main(MINIMAL_ARGV[verb])
    captured = capsys.readouterr()
    assert rc == 1, f"{verb}: expected fatal config refusal, got rc={rc}"
    assert "[qmu] Error:" in captured.err, verb
    assert str(config_cli_env["project"].resolve()) in captured.err, verb
    assert UNKNOWN_KEY in captured.err, verb


def test_exempt_subcommands_are_real_and_stay_usable(config_cli_env, capsys):
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')
    assert cli._CONFIG_EXEMPT_SUBCOMMANDS <= _subcommand_names()
    assert cli.main(["version"]) == 0
    assert UNKNOWN_KEY not in capsys.readouterr().err
    # doctor is exempt because it diagnoses the same fault itself.
    assert cli.main(["doctor"]) == 1
    assert UNKNOWN_KEY in capsys.readouterr().err


def test_broken_global_config_warns_once_per_command(
    config_cli_env, monkeypatch, capsys
):
    """launch resolves config twice (dispatch gate + _prepare_boot); the caller must
    still see one warning line, not two."""
    config_cli_env["global"].write_text("broken = [\n")
    monkeypatch.setattr(
        lifecycle, "launch_vm",
        lambda **kw: pytest.fail("launch_vm must not run without a kernel"),
    )
    rc = cli.main(["launch", "--harness"])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.err.count("ignoring global config") == 1


EXEMPT_MINIMAL_ARGV = {
    # config's own handler (`config show`) independently resolves config and
    # must keep reporting the fault itself — resolve_config only appears in
    # _handle_config_show, not _handle_config_path/_handle_config_init.
    "config": ["config", "show"],
    "doctor": ["doctor"],
    "cache": ["cache", "du"],
    # rootfs requires the `image` positional on every leaf subcommand; a
    # missing image is a legitimate "Image not found" QMUError, unrelated to
    # project config.
    "rootfs": ["rootfs", "ls", "does-not-exist.img"],
    "skill": ["skill", "install"],
    "version": ["version"],
}


@pytest.mark.parametrize("verb", sorted(cli._CONFIG_EXEMPT_SUBCOMMANDS))
def test_every_exempt_verb_never_surfaces_project_config_error(
    verb, config_cli_env, capsys, real_developer_home
):
    """`_CONFIG_EXEMPT_SUBCOMMANDS <= _subcommand_names()` (the existing
    test_exempt_subcommands_are_real_and_stay_usable assertion) is satisfied
    by ANY registered verb name, so a verb that quietly grows a
    resolve_config() call would join the exempt set with no failing test —
    the #37 shape again. Actually run each exempt verb's real handler and
    assert the project config's unknown key never reaches stderr — except
    config/doctor, which read/diagnose qmu.toml themselves and MUST still
    report it."""
    assert verb in EXEMPT_MINIMAL_ARGV, (
        f"{verb!r}: add minimal argv to EXEMPT_MINIMAL_ARGV"
    )
    # This sweep runs each verb's REAL handler, and `skill install` is the one
    # that mutates: it symlinks into every paths.skill_install_roots() entry.
    # conftest's autouse isolation redirects HOME so those roots land in a temp
    # dir, but that containment is asserted where the mutation happens rather
    # than assumed: Path.home() falls back to the passwd entry when HOME is
    # merely UNSET, so a future test that delenv's it — or a revert of the
    # redirect — would silently rewrite the developer's own skill links, which
    # is exactly what happened when the ~/.agents root was added and only
    # CLAUDE_HOME/CODEX_HOME were guarded here.
    if verb == "skill":
        assert Path.home().resolve() != real_developer_home, (
            "refusing to run the mutating `skill install` handler against the "
            "developer's real home; conftest's HOME redirect is not in effect"
        )
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    cli.main(EXEMPT_MINIMAL_ARGV[verb])
    captured = capsys.readouterr()

    if verb in ("config", "doctor"):
        assert UNKNOWN_KEY in captured.err, verb
    else:
        assert UNKNOWN_KEY not in captured.err, verb


def test_broken_global_config_warns_again_on_next_command(
    config_cli_env, capsys
):
    """The dedup is per-command (cli.main resets it before each dispatch),
    not per-process: a second, separate `qmu` invocation against the same
    broken global config must warn again, exactly like a second real
    invocation would."""
    config_cli_env["global"].write_text("broken = [\n")

    cli.main(["--format", "json", "config", "show"])
    capsys.readouterr()

    rc = cli.main(["--format", "json", "config", "show"])
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.err.count("ignoring global config") == 1


# ---------------------------------------------------------------------------
# The refusal has to be actionable. Measured on the branch before this: from a
# project dir with one unknown key, `qmu kill --vm X` refused with nothing but
# "Invalid config <path>: key '...': unknown top-level key" — no sign that the
# check precedes every non-exempt verb rather than saying something about the
# VM — and the obvious next move, `qmu kill --vm X --config good.toml`, is
# argparse exit 2 with the TOP-LEVEL usage, so the caller could not even see
# which flags `kill` accepts. Two round trips, then a dead end.
# ---------------------------------------------------------------------------


def test_project_config_refusal_names_the_gate_and_the_escape_hatch(
    config_cli_env, capsys
):
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    rc = cli.main(["kill", "--vm", "anything"])
    err = capsys.readouterr().err

    assert rc == 1
    # First line unchanged: it is the line `config show` prints, and the #37
    # contract is that every surface says the same thing about the same file.
    first = err.splitlines()[0]
    assert first == (
        f"[qmu] Error: Invalid config {config_cli_env['project'].resolve()}: "
        f"key '{UNKNOWN_KEY}': unknown top-level key"
    )
    # ...and then the two facts the caller cannot get anywhere else.
    assert "before every non-exempt subcommand" in err
    for verb in ("kill", "prune", "wait"):
        assert f"`{verb}`" in err, verb
    assert "re-run from a directory outside the project" in err
    assert "walks up from the current directory" in err
    # `kill` does not register --config, and the guidance must not send the
    # caller to a flag whose answer is argparse exit 2.
    assert "--config" not in err


def test_kill_still_has_no_config_flag_so_the_hint_must_not_prescribe_one(
    config_cli_env, capsys
):
    """Pins the premise of the message above. --config cannot simply be added
    to every verb: _add_common_opts is applied to every subparser and
    _add_launch_opts already registers --config for launch/run, so hoisting it
    raises an argparse conflict. Verbs that DO take it are enumerated."""
    parser = build_parser()
    subparsers = next(
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    with_config = {
        name
        for name, sub in subparsers.choices.items()
        if any("--config" in a.option_strings for a in sub._actions)
    }
    assert with_config == {
        "launch", "run", "status", "show", "list", "log", "crash", "doctor",
    }
    assert "kill" not in with_config

    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["kill", "--vm", "anything", "--config", "/tmp/good.toml"])
    assert exit_info.value.code == 2


def test_gated_verb_and_config_show_still_refuse_byte_identically(
    config_cli_env, running_instance, capsys
):
    """The guidance rides on the ConfigError, not on the gate in cli.main, so
    the exempt diagnostic verbs reach the identical message through their own
    resolve_config call. Putting it in the gate alone would have made `status`
    and `config show` disagree about the same file — the text-vs-text sibling
    divergence the #37 test exists to prevent."""
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    assert cli.main(["status"]) == 1
    status_err = capsys.readouterr().err
    assert cli.main(["config", "show"]) == 1
    show_err = capsys.readouterr().err
    assert cli.main(["kill"]) == 1
    kill_err = capsys.readouterr().err

    assert status_err == show_err == kill_err
    assert "before every non-exempt subcommand" in show_err


def test_explicit_config_refusal_points_at_the_flag_not_at_cwd(
    config_cli_env, capsys
):
    """With --config the caller named the file, so "run it from another
    directory" is not a way out — dropping the flag is."""
    source, explicit_args = _install_source(
        config_cli_env, "explicit", f'{UNKNOWN_KEY} = "typo"\n'
    )

    rc = cli.main(["status", *explicit_args])
    err = capsys.readouterr().err

    assert rc == 1
    assert str(source) in err
    assert "before every non-exempt subcommand" in err
    assert "drop `--config`" in err
    assert "outside the project" not in err


def test_missing_explicit_config_path_also_carries_the_guidance(
    config_cli_env, capsys
):
    missing = config_cli_env["explicit"]  # never written

    rc = cli.main(["status", "--config", str(missing)])
    err = capsys.readouterr().err

    assert rc == 1
    assert f"Invalid config {missing.resolve()}: file not found" in err
    assert "drop `--config`" in err


def test_recovery_guidance_survives_json_as_one_record(config_cli_env, capsys):
    """The message now spans two lines; the envelope must stay one object with
    error_type ConfigError (the re-render rebuilds the class, not a wrapper)."""
    config_cli_env["project"].write_text(f'{UNKNOWN_KEY} = "typo"\n')

    rc = cli.main(["--format", "ndjson", "kill"])
    out = capsys.readouterr().out

    assert rc == 1
    assert len(out.strip().splitlines()) == 1
    payload = json.loads(out)
    assert payload["ok"] is False
    assert payload["error_type"] == "ConfigError"
    assert payload["error"].startswith("Invalid config ")
    assert "before every non-exempt subcommand" in payload["error"]


# ---------------------------------------------------------------------------
# doctor must not report an INVALID global config as an ABSENT one (F7).
# ---------------------------------------------------------------------------


def test_resolve_config_records_a_skipped_global_layer(config_cli_env):
    """The skip was only ever announced on stderr, so `doctor` — which reads
    config._sources — could not tell "rejected" from "never existed"."""
    from qmu.config import resolve_config

    config_cli_env["global"].write_text("broken = [\n")

    cfg = resolve_config()

    assert not any(s.startswith("global:") for s in cfg._sources)
    assert len(cfg._skipped_sources) == 1
    skipped = cfg._skipped_sources[0]
    assert skipped["kind"] == "global"
    assert skipped["path"] == str(config_cli_env["global"].resolve())
    assert "failed to parse TOML" in skipped["problem"]
    # The path belongs to the row that renders it, not to the problem text.
    assert str(config_cli_env["global"].resolve()) not in skipped["problem"]


def test_a_valid_global_records_no_skip(config_cli_env):
    from qmu.config import resolve_config

    config_cli_env["global"].write_text('[machine]\nmemory = "8G"\n')

    cfg = resolve_config()

    assert cfg.memory == "8G"
    assert cfg._skipped_sources == []


def test_schema_invalid_global_records_the_offending_key(config_cli_env):
    from qmu.config import resolve_config

    config_cli_env["global"].write_text('rootfs = "/tmp/rootfs.img"\n')

    cfg = resolve_config()

    problem = cfg._skipped_sources[0]["problem"]
    assert "key 'rootfs'" in problem
