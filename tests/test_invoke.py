"""`cli.invoke`: the render-free seam `main` is built on (#70).

`invoke(argv)` parses, applies the project-config gate and dispatches, then
hands back the handler's `Result` without writing anything. `main` is
`invoke` + `render` + the exception -> exit-code mapping, so every contract
pinned here is one `main` already honours: the same `QMUError` that `main`
maps to exit 1 propagates from `invoke`; a usage error is argparse's own
`SystemExit(2)` from both.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu._cliutil import Result, render
from qmu.commands import lifecycle
from qmu.instance import QMUError
from qmu.version import VERSION


def test_invoke_version_returns_result_without_rendering(capsys):
    result = cli.invoke(["version"])

    assert isinstance(result, Result)
    assert result.data["version"] == VERSION
    assert result.data["ok"] is True
    assert result.text == f"qmu {VERSION}"
    assert result.exit_code == 0
    # Nothing was written: rendering is the caller's decision.
    assert capsys.readouterr() == ("", "")


def test_render_of_invoked_result_matches_main(capsys):
    text_rc = render(cli._parse(["version"]), cli.invoke(["version"]))
    text_out = capsys.readouterr().out
    assert text_rc == cli.main(["version"])
    assert text_out == capsys.readouterr().out == f"qmu {VERSION}\n"

    json_rc = render(
        cli._parse(["--format", "json", "version"]),
        cli.invoke(["--format", "json", "version"]),
    )
    assert json_rc == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "version": VERSION}


def test_invoke_raises_the_qmuerror_main_maps_to_exit_1(monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [])
    monkeypatch.setattr(lifecycle, "list_stopped_instances", lambda: [])

    with pytest.raises(QMUError) as raised:
        cli.invoke(["status", "--vm", "nope"])
    assert capsys.readouterr() == ("", "")

    assert cli.main(["status", "--vm", "nope"]) == 1
    err = capsys.readouterr().err
    # main() renders the same exception plus its specific recovery hint;
    # invoke() (above) wrote nothing and left both to the caller.
    assert err == (
        f"[qmu] Error: {raised.value}\n"
        "[qmu] Hint: qmu list; qmu launch --name <name> --no-replace\n"
    )


def test_invoke_usage_error_is_argparse_systemexit_2(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.invoke(["status", "--bogus"])
    assert raised.value.code == 2
    invoke_err = capsys.readouterr().err

    with pytest.raises(SystemExit) as raised_main:
        cli.main(["status", "--bogus"])
    assert raised_main.value.code == 2
    assert capsys.readouterr().err == invoke_err
    assert invoke_err.rstrip().endswith("error: unrecognized arguments: --bogus")


def test_invoke_without_subcommand_prints_help_and_exits_2(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.invoke([])
    assert raised.value.code == 2
    assert "usage: qmu" in capsys.readouterr().out

    # `main` returns the same code rather than raising, as it always has.
    assert cli.main([]) == 2
    assert "usage: qmu" in capsys.readouterr().out
