"""Usage errors (exit 2) honor --format like every other error path.

`qmu --help` promises that every error path emits `{"ok": false, ...}` under
--format json|ndjson, but argparse printed usage text to stderr and left
stdout empty — the one error class an agent branching on the envelope could
not parse. The parser now raises instead of exiting, and `cli.main` renders
the usage error per format while keeping argparse's exit (SystemExit 2) and
its text-mode output.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli


def _run(argv, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(argv)
    out, err = capsys.readouterr()
    return exit_info.value.code, out, err


def test_text_mode_usage_error_is_unchanged(capsys):
    code, out, err = _run(["launch", "--bogus"], capsys)

    assert code == 2
    assert out == ""
    assert err.startswith("usage: qmu")
    assert err.rstrip().endswith("qmu: error: unrecognized arguments: --bogus")


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_usage_error_emits_envelope_under_json_formats(fmt, capsys):
    code, out, err = _run(["launch", "--bogus", "--format", fmt], capsys)

    assert code == 2
    assert err == ""
    payload = json.loads(out)
    assert payload == {
        "ok": False,
        "error": "unrecognized arguments: --bogus",
        "error_type": "UsageError",
        "usage": payload["usage"],
        # #74: every ok:false envelope carries a hint; a usage error with no
        # specific one points at the subcommand's help.
        "hint": "qmu launch --help",
    }
    assert payload["usage"].startswith("usage: qmu")
    if fmt == "ndjson":
        assert out.count("\n") == 1


def test_subparser_usage_error_names_the_subcommand(capsys):
    """Errors raised by a subparser (missing required flag) carry that
    subparser's usage, not the root's."""
    code, out, _ = _run(["--format", "json", "kbase"], capsys)

    assert code == 2
    payload = json.loads(out)
    assert payload["ok"] is False
    assert payload["error_type"] == "UsageError"
    assert "--symbols" in payload["error"]
    assert payload["usage"].startswith("usage: qmu kbase")


def test_format_after_subcommand_and_in_equals_form_are_both_seen(capsys):
    code, out, _ = _run(["version", "--bogus", "--format=json"], capsys)

    assert code == 2
    assert json.loads(out)["error_type"] == "UsageError"


def test_format_after_double_dash_is_a_guest_argument(capsys):
    """`run ... -- cmd --format json` hands --format to the guest; a usage
    error there must stay text."""
    code, out, err = _run(
        ["run", "--bogus", "--", "true", "--format", "json"], capsys
    )

    assert code == 2
    assert out == ""
    assert "qmu: error: unrecognized arguments: --bogus" in err


def test_guest_command_dash_words_get_a_hint_in_text_and_json(capsys):
    """`qmu exec uname -a` is "unrecognized arguments: -a"; the hint names the
    two working forms. Other subcommands' usage errors fall back to the
    `<prog> --help` default (#74) and print no hint line in text mode."""
    hint = (
        "Hint: quote the guest command ('uname -a') or put -- before it "
        "(qmu exec -- uname -a); qmu flags may appear anywhere."
    )
    code, out, err = _run(["exec", "--vm", "x", "uname", "-a"], capsys)
    assert code == 2
    assert out == ""
    assert err.rstrip().endswith(f"qmu: error: unrecognized arguments: -a\n{hint}")

    code, out, _ = _run(["--vm", "x", "exec", "uname", "-a", "--format", "json"], capsys)
    assert code == 2
    payload = json.loads(out)
    assert payload["error"] == "unrecognized arguments: -a"
    assert payload["hint"] == hint

    code, out, err = _run(["launch", "--bogus", "--format", "json"], capsys)
    assert code == 2
    assert json.loads(out)["hint"] == "qmu launch --help"
    code, out, err = _run(["kbase", "--format", "json"], capsys)
    assert code == 2
    assert json.loads(out)["hint"] == "qmu kbase --help"
    code, _, err = _run(["launch", "--bogus"], capsys)
    assert code == 2
    assert "Hint" not in err and "--help" not in err.splitlines()[-1]


def test_missing_subcommand_under_json_is_an_envelope(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--format", "json"])
    out, _ = capsys.readouterr()

    assert exit_info.value.code == 2
    payload = json.loads(out)
    assert payload["ok"] is False
    assert payload["error_type"] == "UsageError"
    assert payload["error"] == "a subcommand is required"


def test_missing_subcommand_in_text_prints_help(capsys):
    rc = cli.main([])
    out, _ = capsys.readouterr()

    assert rc == 2
    assert out.startswith("usage: qmu")


def test_help_still_exits_zero(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["launch", "--help", "--format", "json"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("usage: qmu launch")


# ---------------------------------------------------------------------------
# `qmu --version` was an exit-2 "unrecognized arguments"; every CLI answers it.
# ---------------------------------------------------------------------------


def test_top_level_version_flag_matches_the_version_subcommand(capsys):
    from qmu.version import VERSION

    code, out, err = _run(["--version"], capsys)
    assert code == 0
    assert err == ""
    assert out == f"qmu {VERSION}\n"

    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out == out


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_top_level_version_flag_honors_a_preceding_format(fmt, capsys):
    from qmu.version import VERSION

    code, out, err = _run(["--format", fmt, "--version"], capsys)
    assert code == 0
    assert json.loads(out) == {"ok": True, "version": VERSION}
