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

import io
import re
import shlex
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from qmu.cli import build_parser

SKILL = Path(__file__).resolve().parents[1] / "skills" / "qmu" / "SKILL.md"

# A documented line containing any of these is a template, not a runnable
# command; its VALUE checks may fail, but an unknown flag still must not.
PLACEHOLDER = re.compile(r"[<>]|\.\.\.|\$\{|\$[A-Z_]|\*")


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
    parser = build_parser()
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


def test_skill_schema_section_matches_validator():
    """#55: the documented accepted-schema bullets must equal config._FIXED_SCHEMA.
    The `accel` key existed in the validator for a release before the skill listed it.

    Two holes found in review of this guard itself: (a) building `documented` with
    a plain dict is last-wins, so a second, differently-shaped bullet for a table
    anywhere in the file silently masks a drifted authoritative one; (b) scanning
    the whole bullet tail for backticked tokens turns trailing prose like
    "(default `1234`, see `doctor`)" into phantom schema keys. Both are guarded
    below: duplicate table bullets are a hard failure, and the key list is read
    only from the leading comma-separated backtick run.
    """
    from qmu.config import _FIXED_SCHEMA

    bullet_re = re.compile(r"^- `\[(\w+)\]`: (.+)$")
    key_run_re = re.compile(r"^`(\w+)`\s*")

    def leading_key_run(tail: str) -> set[str]:
        """The key list is a leading comma-separated run of `key` tokens;
        trailing prose is not schema even when it contains inline code."""
        keys: set[str] = set()
        rest = tail
        while True:
            m = key_run_re.match(rest)
            if not m:
                break
            keys.add(m.group(1))
            rest = rest[m.end():]
            if rest.startswith(","):
                rest = rest[1:].lstrip()
            else:
                break
        return keys

    documented: dict[str, set[str]] = {}
    duplicate_tables: list[str] = []
    for line in SKILL.read_text().splitlines():
        m = bullet_re.match(line.strip())
        if m:
            table = m.group(1)
            if table in documented:
                duplicate_tables.append(table)
            documented[table] = leading_key_run(m.group(2))

    assert documented, "schema bullets not found in SKILL.md"
    assert not duplicate_tables, (
        f"duplicate schema bullet(s) for table(s) {duplicate_tables}: a second "
        "bullet for the same table silently masks the first"
    )
    assert set(documented) == set(_FIXED_SCHEMA)
    for table, keys in _FIXED_SCHEMA.items():
        assert documented[table] == set(keys), table


def test_config_init_table_enumeration_matches_the_generator():
    """#55's recurrence class, one sentence over: SKILL.md enumerates the
    tables `qmu config init` writes, and it omitted `[boot]` — the FIRST table
    the generator emits and the one carrying the `# CHANGE ME` kernel line, so
    an agent reading the skill did not learn that the boot settings can live in
    the starter file at all. "All keys commented" is not the exclusion rule:
    `[gdb]` was listed and its only key is commented too.
    """
    from qmu.config import render_starter_config

    generated = [
        line[1:-1]
        for line in render_starter_config("x86_64").splitlines()
        if line.startswith("[") and line.endswith("]")
    ]

    sentence = next(
        line for line in SKILL.read_text().splitlines()
        if line.startswith("`qmu config init` writes ")
    )
    documented = re.findall(r"`\[([\w.<>*-]+)\]`", sentence)

    # `[profiles.*]` is documented as one collapsed bullet ("three
    # `[profiles.*]` blocks"); every other table is named literally.
    profiles = [t for t in generated if t.startswith("profiles.")]
    literal = [t for t in generated if not t.startswith("profiles.")]

    assert documented[:len(literal)] == literal, (
        f"SKILL.md enumerates {documented} but `qmu config init` writes "
        f"{literal} + {len(profiles)} profile blocks"
    )
    assert "profiles.*" in documented
    assert f"{len(profiles)} `[profiles.*]` blocks" in sentence.replace(
        "three", str(len(profiles))
    )
