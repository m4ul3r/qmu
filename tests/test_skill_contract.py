"""Every command documented in skills/qmu/SKILL.md must exist in the CLI.

The skill is the agent's map of this tool. When it drifts from the code the
agent follows instructions that fail -- and the failure is expensive, because
an agent burns a round-trip and a few hundred tokens discovering it.

This caught a real one: SKILL.md promised "with one VM running, commands
auto-select it", which was true for every command using choose_instance and
false for `log`/`crash`, the two that also accept stopped VMs. Syntax drift is
mechanically checkable, so it is checked here rather than by review.
"""

from __future__ import annotations

import argparse
import io
import re
import shlex
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from qmu._cliutil import _add_top_level_common_opts
from qmu.commands import guest, lifecycle, meta, qmp_cmds, run

SKILL = Path(__file__).resolve().parents[1] / "skills" / "qmu" / "SKILL.md"

# A documented line containing any of these is a template, not a runnable
# command; its VALUE checks may fail, but an unknown flag still must not.
PLACEHOLDER = re.compile(r"[<>]|\.\.\.|\$\{|\$[A-Z_]|\*")


def _build_parser() -> argparse.ArgumentParser:
    """Mirror cli.main's parser construction without dispatching handlers."""
    parser = argparse.ArgumentParser(prog="qmu")
    _add_top_level_common_opts(parser)
    sub = parser.add_subparsers(dest="subcommand")
    registrars = [
        lifecycle._add_launch, run._add_run, lifecycle._add_kill,
        lifecycle._add_prune, lifecycle._add_wait, lifecycle._add_list,
        lifecycle._add_status, lifecycle._add_doctor,
        meta._add_config, qmp_cmds._add_snapshot,
        guest._add_push, guest._add_pull, guest._add_exec, guest._add_compile,
        guest._add_dmesg, guest._add_crash, guest._add_log,
        qmp_cmds._add_gdb, qmp_cmds._add_kbase, qmp_cmds._add_cont,
        qmp_cmds._add_qmp, qmp_cmds._add_monitor,
        meta._add_rootfs, meta._add_skill, meta._add_version,
    ]
    # This mirror re-lists cli.main's registrars by hand, so a subcommand that
    # arrives on a sibling branch (e.g. `qmu cache`, meta._add_cache) would
    # otherwise desync it: the command's own documented lines in SKILL.md would
    # fail to parse here even though the real CLI accepts them. Pick up such
    # registrars by name when the symbol is present, absorbing the drift instead
    # of hard-failing on the very lines the sibling PR also adds to the skill.
    for owner, name in ((meta, "_add_cache"),):
        fn = getattr(owner, name, None)
        if fn is not None:
            registrars.append(fn)
    for register in registrars:
        register(sub)
    return parser


def _cut_at_unquoted(line: str) -> str:
    """Truncate at the first comment, pipe or redirect that is OUTSIDE quotes.

    Naive splitting mangles real documented lines two ways: a quoted argument
    may legitimately contain `>` or `|` (`-- 'echo c > /proc/sysrq-trigger'`),
    and an apostrophe in a trailing comment (`won't`, `VM's`) defeats any
    quote-counting heuristic.
    """
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].strip()
        elif ch in "|>&" and (i == 0 or line[i - 1].isspace()):
            return line[:i].strip()
        i += 1
    return line.strip()


def _documented_commands() -> list[tuple[int, str]]:
    """Every `qmu ...` invocation inside a fenced code block, with its line number.

    Backslash continuations are JOINED rather than skipped: the multi-line
    `launch` examples carry the most flags in the whole document, so they are
    exactly the ones worth validating.
    """
    found: list[tuple[int, str]] = []
    fenced = False
    pending: list[str] = []
    start = 0

    def flush() -> None:
        if not pending:
            return
        line = _cut_at_unquoted(" ".join(pending))
        if line:
            found.append((start, line))
        pending.clear()

    for lineno, raw in enumerate(SKILL.read_text().splitlines(), 1):
        if raw.lstrip().startswith("```"):
            flush()
            fenced = not fenced
            continue
        if not fenced:
            continue
        stripped = raw.strip()
        if pending:
            cont = stripped.endswith("\\")
            pending.append(stripped.rstrip("\\").strip())
            if not cont:
                flush()
            continue
        line = re.sub(r"^\$\s*", "", stripped)
        if not line.startswith("qmu "):
            continue
        start = lineno
        if line.endswith("\\"):
            pending.append(line.rstrip("\\").strip())
        else:
            pending.append(line)
            flush()
    flush()
    return found


DOCUMENTED = _documented_commands()


def test_skill_documents_some_commands():
    """Guard the extractor itself: a silent zero would make this file vacuous."""
    assert len(DOCUMENTED) > 50, f"only found {len(DOCUMENTED)} commands"


@pytest.mark.parametrize(
    "lineno,command",
    DOCUMENTED,
    ids=[f"L{n}" for n, _ in DOCUMENTED],
)
def test_documented_command_parses(lineno, command):
    parser = _build_parser()
    try:
        argv = shlex.split(command)[1:]
    except ValueError as exc:
        pytest.fail(f"SKILL.md:{lineno} is not shell-parseable: {exc}\n  $ {command}")
    assert argv, f"SKILL.md:{lineno}: bare 'qmu'"

    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code in (0, None):
            return  # --help
        reason = (err.getvalue().strip().splitlines() or ["exit"])[-1]
        unknown = "unrecognized arguments" in reason or "invalid choice" in reason
        if PLACEHOLDER.search(command) and not unknown:
            pytest.skip(f"template line: {command}")
        pytest.fail(
            f"SKILL.md:{lineno} documents a command the CLI rejects:\n"
            f"  $ {command}\n  -> {reason}"
        )
