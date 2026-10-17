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

from qmu.cli import _UsageError, build_parser

SKILL = Path(__file__).resolve().parents[1] / "skills" / "qmu" / "SKILL.md"
ROOT = SKILL.parents[2]
README = ROOT / "README.md"
UBUNTU_SKILL = ROOT / "skills" / "qmu-ubuntu-target" / "SKILL.md"
MKTARGET = ROOT / "tools" / "mktarget.sh"
REFERENCE_DIR = SKILL.parent / "reference"
# #42 split moved the config schema and `config init` enumeration here.
TROUBLESHOOTING = REFERENCE_DIR / "troubleshooting.md"
# #42 split: every companion file is scanned for `qmu …` lines too, so moving a
# section out of SKILL.md never moves it out of the contract.
SKILL_FILES = [SKILL, *sorted(REFERENCE_DIR.glob("*.md"))]

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


def _documented_commands(path: Path = SKILL) -> list[tuple[int, str]]:
    """Every `qmu ...` invocation inside a fenced code block of PATH, with its line number.

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

    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
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


DOCUMENTED = [
    (path, lineno, command)
    for path in SKILL_FILES
    for lineno, command in _documented_commands(path)
]


def test_skill_documents_some_commands():
    """Guard the extractor itself: a silent zero would make this file vacuous."""
    assert len(DOCUMENTED) > 50, f"only found {len(DOCUMENTED)} commands"


@pytest.mark.parametrize(
    "path,lineno,command",
    DOCUMENTED,
    ids=[f"{p.name}:L{n}" for p, n, _ in DOCUMENTED],
)
def test_documented_command_parses(path, lineno, command):
    parser = build_parser()
    try:
        argv = shlex.split(command)[1:]
    except ValueError as exc:
        pytest.fail(f"{path.name}:{lineno} is not shell-parseable: {exc}\n  $ {command}")
    assert argv, f"{path.name}:{lineno}: bare 'qmu'"

    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            parser.parse_args(argv)
    except _UsageError as exc:
        # build_parser() raises instead of exiting so `main` can render the
        # UsageError envelope; the message is what argparse would have printed.
        reason = exc.message
    except SystemExit as exc:
        if exc.code in (0, None):
            return  # --help
        reason = (err.getvalue().strip().splitlines() or ["exit"])[-1]
    else:
        return
    unknown = "unrecognized arguments" in reason or "invalid choice" in reason
    if PLACEHOLDER.search(command) and not unknown:
        pytest.skip(f"template line: {command}")
    pytest.fail(
        f"{path.name}:{lineno} documents a command the CLI rejects:\n"
        f"  $ {command}\n  -> {reason}"
    )


MAX_SKILL_LINES = 400


def test_main_skill_stays_short():
    """#42: the main skill is the hot path an agent reads on every task; detail
    belongs in reference/. The cap is a regression guard, not a target."""
    lines = len(SKILL.read_text().splitlines())
    assert lines <= MAX_SKILL_LINES, (
        f"SKILL.md is {lines} lines (> {MAX_SKILL_LINES}); move detail to reference/"
    )


def test_daemon_reference_claims_match_the_code():
    """#70: daemon.md's load-bearing numbers and names come from the code, not
    from memory: the idle default, the socket/record names, the QMU_DAEMON
    modes, the ops list, and the `qmp: daemon` / `guest_epoch_source` keys."""
    from qmu import daemon_client
    from qmu.config import QMUConfig

    page = (SKILL.parent / "reference" / "daemon.md").read_text()
    skill = SKILL.read_text()
    assert "reference/daemon.md" in skill
    assert f"idles out after {QMUConfig().daemon_idle_exit} s" in skill
    assert f"(default {QMUConfig().daemon_idle_exit}; 0 =" in page
    assert f"<cache>/{daemon_client.DAEMON_SOCKET_NAME}" in page
    assert f"<cache>/{daemon_client.DAEMON_RECORD_NAME}" in page
    assert f"<cache>/{daemon_client.DAEMON_LOG_NAME}" in page
    for mode in (daemon_client.MODE_OFF, daemon_client.MODE_REQUIRE):
        assert f"`QMU_DAEMON={mode}`" in page, mode
    for key in ("`qmp: \"daemon\"`", "`guest_epoch_source: \"observed\"|\"banner\"`"):
        assert key in page, key
    for verb in ("status", "start", "stop", "run"):
        assert f"`daemon {verb}`" in page, verb


# Claims a second round of fresh-agent dogfooding proved wrong against the
# tool. Each regex is the wording that misled; the reason says what is true.
RETIRED_CLAIMS = [
    (r"--older-than 0\s+# finally drop the retained logs",
     "kill-preserved logs prune at any age; only metadata-free .qemu.log/.qmp.sock remnants are gated"),
    (r"stale one reports\s+`exited \(code 0\)`",
     "a stale hand-started bridge fails with RuntimeError: Remote target disappeared"),
    (r"wait` ends in `124` with `crash: null` instead of reporting the panic",
     "bare wait returns 3 at the panic line whether or not --no-reboot is set"),
    (r"15-60 s on a busy host", "list takes a few seconds; the estimate was wrong"),
    (r"the `profile` bucket is noise\)",
     "profile-sourced unknown params are JSON-only, never printed"),
    (r"pointing at\s+`qmu prune --all` — do not run",
     "qmu never recommends prune --all; its hints name prune --vm <id>"),
    (r"auto-selection needs exactly one running VM\)\.",
     "auto-selection is announced on stderr + autoselected: true; QMU_REQUIRE_VM=1 forbids it"),
    # Review of #65–#69 (#79): qmu exits 0/1 on the guest's status and keeps
    # the guest's own code in JSON `exit_code`; 2/3/4/124 are reserved.
    (r"exit code (?:=|is) the guest(?:'s| command's)",
     "qmu exits 1 for any non-zero guest status; the guest code is JSON exit_code"),
    (r"`exit 255` is 255",
     "exit 255 in the guest is qmu exit 1 with exit_code: 255"),
    # #106: a stopped `status` omits `qmp`; only bare `wait` carries `qmp: null`.
    (r"null \(stopped, in `status`",
     "stopped status has no qmp key at all; test for presence, not null"),
    (r"concurrent probe may report a held slot as `unreachable`",
     "list and status both classify a held QMP slot as busy (observed agreeing)"),
    # #77: the probe cap is ConnectTimeout + 0.5 s now; the 5 s figure is retired.
    (r"status --vm X\s+#.*< ?1 s",
     "status is typically sub-second but up to ~2 s (held QMP) / ~2.5 s (SSH accepts, never answers)"),
    (r"~5 s when the SSH port accepts but never answers",
     "the probe is capped at ConnectTimeout + 0.5 s (~2.5 s); status/list report ssh_probe_ms"),
    (r"tracked in #77",
     "#77 is closed: list/status report the probe's wall time as ssh_probe_ms"),
    # The attach gate refuses a second `qmu gdb` while a client is connected.
    (r"would spawn a second bridge",
     "qmu gdb exits 1 naming the attached bridge pid and spawns nothing"),
]


@pytest.mark.parametrize("pattern,reason", RETIRED_CLAIMS, ids=[r for _, r in RETIRED_CLAIMS])
def test_retired_claims_stay_retired(pattern, reason):
    rx = re.compile(pattern)
    hits = [
        f"{p.name}:{n}" for p in SKILL_FILES
        for n, line in enumerate(p.read_text().splitlines(), 1) if rx.search(line)
    ]
    assert not hits, f"retired claim back in {hits}: {reason}"


# Contracts the skill must carry so an agent branches on the tool, not on a
# guess. (file, phrase) — every phrase is a literal the tool emits or a key.
REQUIRED_CLAIMS = [
    (SKILL, "QMU_REQUIRE_VM"),
    (SKILL, "autoselected: true"),
    (SKILL, "console_tail"),
    (SKILL, "already_stopped: true"),
    (SKILL, "[stopped — crash report retained]"),
    (SKILL, "skipped (debugger attached)"),
    (SKILL, "--format text --out report.txt"),
    # #79: the decision rows and the run section must state the 0/1 mapping and
    # point at `exit_code` for the guest's own code.
    (SKILL, "exit 0 if the guest command exited 0, else 1"),
    (SKILL, "Exit 0 when the guest command exited 0, 1 when it exited non-zero"),
    (REFERENCE_DIR / "guest-commands.md", "qmu's own exit is **not** the guest's"),
    # #102: the offline-inject row must carry --partition 0 on BOTH steps.
    (SKILL, "qmu rootfs inject ./rootfs.img ./exploit:/root/ --partition 0"),
    (SKILL, "qmu rootfs ls ./rootfs.img /root --partition 0"),
    # #106: stopped status shape; savevm warning exception.
    (REFERENCE_DIR / "launch.md", "A stopped `status` **omits** `qmp`"),
    (REFERENCE_DIR / "debugging.md", "**Exception: `snapshot save`.**"),
    (REFERENCE_DIR / "debugging.md", "A debugger client is already attached to port N"),
    (SKILL, "--partition 0"),
    (SKILL, "10.0.2.15"),
    (SKILL, "pry --instance qmu-"),
    (REFERENCE_DIR / "wait.md", "console_tail"),
    (REFERENCE_DIR / "launch.md", "logs_retained"),
    (REFERENCE_DIR / "debugging.md", "Remote target disappeared"),
    (REFERENCE_DIR / "debugging.md", "bridge_instance_id"),
    (REFERENCE_DIR / "snapshots.md", "vm_clock"),
    (REFERENCE_DIR / "troubleshooting.md", "paths.<key>.exists"),
    (REFERENCE_DIR / "troubleshooting.md", "qmu config path"),
    (REFERENCE_DIR / "cross-arch.md", "[boot]"),
    # #106 (reopened): list row schema — qemu_status on running rows only.
    (REFERENCE_DIR / "launch.md", "a running row carries `qmp` and\n`qemu_status`"),
    # #110: the failed-restore recovery must be stated where the agent copies from.
    (SKILL, "`qemu_status: \"restore-vm\"`"),
    (REFERENCE_DIR / "snapshots.md", "`qmu cont --vm X` enforces this"),
    (REFERENCE_DIR / "output-contract.md", "The pointer's `ok`/exit is the **operation's** result"),
    # #53: `skill install` statuses — the relink receipt is the whole point.
    (SKILL, "relinked"),
    (REFERENCE_DIR / "troubleshooting.md", "`relinked` (pointed at another checkout — JSON `previous_target` names it)"),
    (REFERENCE_DIR / "troubleshooting.md", "`current` (already right; left untouched"),
    (README, "reported as `relinked` together with the target it replaced"),
    (README, "reported as `current`"),
    # #75: the two new doctor rows; #76: the no_reboot config key.
    (SKILL, "rootfs sshd policy ([~] permissive"),
    (REFERENCE_DIR / "troubleshooting.md", "| `initrd` | same shape:"),
    (REFERENCE_DIR / "troubleshooting.md", "[~] permissive (image predates key-only sshd; rebuild with tools/mkrootfs.sh)"),
    (REFERENCE_DIR / "troubleshooting.md", "`[i] not checked (<reason>)`"),
    (REFERENCE_DIR / "guest-commands.md", "[+] rootfs sshd policy: key-only"),
    (REFERENCE_DIR / "guest-commands.md", "`ls` is one\n  guestfish session"),
    (REFERENCE_DIR / "launch.md", "Config key: `[machine] no_reboot = true`"),
    (REFERENCE_DIR / "troubleshooting.md", "`accel`, `no_reboot`, `extra_args`"),
    # #73: a save that outran its budget is an UNKNOWN result (124), not exit 4.
    (SKILL, "`snapshot save` outran its budget (result **unknown**, not failed)"),
    (SKILL, "| `snapshot save` exit 124, `may_have_landed: true` |"),
    (SKILL, "budget 60 s + 20 s/GiB, `--timeout N` overrides"),
    (REFERENCE_DIR / "snapshots.md", "**60 s + 20 s per GiB of guest\nRAM**"),
    (REFERENCE_DIR / "snapshots.md", "`may_have_landed: true`"),
    (REFERENCE_DIR / "snapshots.md", "`may_have_landed: false`"),
    (REFERENCE_DIR / "snapshots.md", "a reply tagged with another client's `id` is dropped"),
    (REFERENCE_DIR / "wait.md", "`124` means the same thing on every command"),
    # #77: the probe's cost is an observable on status and list rows.
    (SKILL, "`ssh_probe_ms` says"),
    (REFERENCE_DIR / "launch.md", "`ssh_probe_ms` (the probe's wall time in ms; null when no\nprobe was sent"),
    (REFERENCE_DIR / "launch.md", "≤ 2.5 s when the SSH port accepts but never answers"),
    # #76: the first-QMP-connect retry is observable and field-evidenced.
    (REFERENCE_DIR / "launch.md", "`warnings[]` gains `QMP connect retried N× (ECONNRESET)`"),
    (REFERENCE_DIR / "launch.md", "`~/qmu-audit/crashpaths` receipt 2"),
    # #113: concurrent launches serialise port allocation; the lock is named.
    (REFERENCE_DIR / "launch.md", "holds `flock` on `<cache>/instances/ports.lock`"),
    (REFERENCE_DIR / "launch.md", "Waited N.Ns for the port-allocation lock"),
    # #74: every exception-path envelope carries `hint`; warnings ride in `warnings[]`.
    (SKILL, "run the `hint` (every `error_type` envelope has one)"),
    (REFERENCE_DIR / "output-contract.md", "**Every exception-path `ok: false` envelope carries `hint`**"),
    (REFERENCE_DIR / "output-contract.md", "`SSHError` → `qmu status --vm X; qmu log --vm X --tail 50`"),
    (REFERENCE_DIR / "output-contract.md", "**`warnings: [str]`** rides in every json/ndjson envelope"),
    (REFERENCE_DIR / "output-contract.md", "the `ignoring global config` notice"),
    (REFERENCE_DIR / "output-contract.md", "only for a site-specific hint, never for a type default"),
    # #72: launch and run agree that an expired --ssh-timeout is 124.
    (SKILL, "`launch`/`run` `--ssh-timeout` expired before SSH answered (`launch` keeps the VM, `ssh_status: \"timeout\"`)"),
    (SKILL, "| `ssh_status: \"timeout\"`, `timed_out: true` (launch exit 124) |"),
    (REFERENCE_DIR / "launch.md", "on expiry both `launch` and `run` exit **124**"),
    (REFERENCE_DIR / "launch.md", "`error_type: \"TimeoutError\"`, `error`, `hint`"),
    (REFERENCE_DIR / "output-contract.md", "an expired `--ssh-timeout` on `launch`/`run`\n  (exit 124, `error_type: \"TimeoutError\"`"),
    # #71(b): text --out prints a text pointer, never JSON.
    (REFERENCE_DIR / "output-contract.md", "**text prints one line**, `[qmu] Output written to <path>\n(<N> bytes, exit <code>)`"),
    # #71(a): guest output streams; ndjson carries `chunk` events; the
    # streamed-spill pointer trails the preview.
    (SKILL, "**streamed\nas the guest writes it**"),
    (SKILL, "ndjson\ngets `chunk` events, json stays buffered"),
    (REFERENCE_DIR / "guest-commands.md", "- Output is **streamed**"),
    (REFERENCE_DIR / "output-contract.md", "### Streaming (`exec`, `run`, `compile --run`)"),
    (REFERENCE_DIR / "output-contract.md", "`{\"event\": \"chunk\", \"stream\":\n  \"stdout\"|\"stderr\", \"data\": \"<text>\"}`"),
    (REFERENCE_DIR / "output-contract.md", "carry `event` and **no** `ok`"),
    (REFERENCE_DIR / "output-contract.md", "UTF-8 with `surrogateescape`"),
    (REFERENCE_DIR / "output-contract.md", "streamed above` — pointer *after* the preview"),
    (REFERENCE_DIR / "output-contract.md", "`compile --run` streams only the program's run"),
]


@pytest.mark.parametrize(
    "path,phrase", REQUIRED_CLAIMS, ids=[f"{p.name}:{s}" for p, s in REQUIRED_CLAIMS]
)
def test_required_claims_present(path, phrase):
    assert phrase in path.read_text(), f"{path.name} no longer states {phrase!r}"


def _recovery_rows(path: Path) -> list[tuple[int, str, str]]:
    """(lineno, symptom, do) for every row of the Recovery table in PATH."""
    rows: list[tuple[int, str, str]] = []
    in_table = False
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        if raw.startswith("## "):
            in_table = raw.startswith("## Recovery")
            continue
        if in_table and raw.startswith("| `"):
            cells = [c.strip() for c in raw.strip().strip("|").split(" | ")]
            if len(cells) == 3:
                rows.append((lineno, cells[0], cells[2]))
    return rows


def test_recovery_table_never_resumes_a_failed_restore():
    """#110: `cont` is the one action a mid-restore failure must not get.

    The runtime (#87) leaves a `partial`/`unknown` load paused in `restore-vm`
    on purpose; a recovery row that answers `paused` with `qmu cont --vm X`
    walks the agent straight into the inconsistent resume. The failed-restore
    state therefore needs its own row, and an ordinary-pause row must not
    claim that state.
    """
    rows = _recovery_rows(SKILL)
    restore_rows = [r for r in rows if "restore-vm" in r[1]]
    assert restore_rows, "no recovery row keyed on qemu_status restore-vm"
    for lineno, _symptom, do in restore_rows:
        assert "qmu cont --vm X`" not in do, f"SKILL.md:{lineno} resumes a failed restore"
        assert "qmu snapshot load" in do and "qmu kill --vm X" in do, lineno
    plain_pause = [
        r for r in rows if r[1].startswith("| `guest: \"paused\"`") or r[1].startswith("`guest: \"paused\"`")
    ]
    plain_pause = [r for r in plain_pause if "restore-vm" not in r[1]]
    assert plain_pause, "no ordinary paused row"
    for lineno, symptom, _do in plain_pause:
        assert "restore" not in symptom.lower(), f"SKILL.md:{lineno} lumps a failed restore into the cont row"


def _table_commands(path: Path) -> list[tuple[int, str]]:
    """Every inline-code `qmu …` span inside a markdown table row of PATH.

    The decision and recovery tables in the main skill are what an agent
    copies first, so a flag the CLI rejects there costs more than one in
    prose. Spans joined by `→` or `…` are separate spans, checked separately.
    """
    found: list[tuple[int, str]] = []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw.lstrip().startswith("|"):
            continue
        for span in re.findall(r"`([^`]*)`", raw):
            if span.startswith("qmu "):
                found.append((lineno, _cut_at_unquoted(span)))
    return found


TABLE_DOCUMENTED = [
    (SKILL, lineno, command) for lineno, command in _table_commands(SKILL)
]


@pytest.mark.parametrize(
    "path,lineno,command",
    TABLE_DOCUMENTED,
    ids=[f"{p.name}:L{n}:table" for p, n, _ in TABLE_DOCUMENTED],
)
def test_table_command_parses(path, lineno, command):
    test_documented_command_parses(path, lineno, command)


_PARTITION = re.compile(r"--partition\s+(\S+)")


def _rootfs_rows(path: Path) -> list[tuple[int, list[str]]]:
    """Table rows that chain two or more `qmu rootfs …` commands (inject → ls)."""
    rows: dict[int, list[str]] = {}
    for lineno, command in _table_commands(path):
        if command.startswith("qmu rootfs "):
            rows.setdefault(lineno, []).append(command)
    return [(n, cmds) for n, cmds in rows.items() if len(cmds) >= 2]


def test_rootfs_decision_rows_select_the_same_partition():
    """#102: an inject with `--partition 0` verified by an `ls` that defaults to
    partition 1 exits 1 (`Partition /dev/sda1 was not found`) on the very image
    the inject just wrote. Every chained rootfs row must name one partition on
    all of its commands — not merely parse."""
    rows = _rootfs_rows(SKILL)
    assert rows, "no decision row chains qmu rootfs commands; the extractor is vacuous"
    for lineno, cmds in rows:
        parts = {(_PARTITION.search(c) or [None, None])[1] for c in cmds}
        assert len(parts) == 1 and None not in parts, (
            f"SKILL.md:{lineno}: rootfs commands select different partitions {cmds}"
        )


def test_reference_files_exist_and_are_pointed_at():
    """#42: every `reference/<file>.md` the main skill names must exist, and
    every companion file must be reachable from the main skill — a moved
    section whose pointer was lost is invisible to the agent that needs it."""
    text = SKILL.read_text()
    named = set(re.findall(r"reference/([\w-]+\.md)", text))
    assert named, "SKILL.md points at no reference files"
    on_disk = {p.name for p in REFERENCE_DIR.glob("*.md")}
    assert named <= on_disk, f"dangling reference pointers: {sorted(named - on_disk)}"
    assert on_disk <= named, f"companion files nothing points at: {sorted(on_disk - named)}"


@pytest.mark.parametrize("path", SKILL_FILES, ids=[p.name for p in SKILL_FILES])
def test_markdown_anchors_resolve(path):
    """`](#anchor)` links must name a heading in the same file."""
    text = path.read_text()

    def slug(heading: str) -> str:
        heading = re.sub(r"[`*_]", "", heading).strip().lower()
        heading = re.sub(r"[^\w\s-]", "", heading)
        return re.sub(r"\s+", "-", heading)

    headings = {slug(m) for m in re.findall(r"^#+\s+(.+)$", text, flags=re.M)}
    for anchor in re.findall(r"\]\(#([^)]+)\)", text):
        assert anchor in headings, f"{path.name}: dangling anchor #{anchor}"


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
    for line in TROUBLESHOOTING.read_text().splitlines():
        m = bullet_re.match(line.strip())
        if m:
            table = m.group(1)
            if table in documented:
                duplicate_tables.append(table)
            documented[table] = leading_key_run(m.group(2))

    assert documented, "schema bullets not found in troubleshooting.md"
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
        line for line in TROUBLESHOOTING.read_text().splitlines()
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


def _mktarget_usage_flags() -> list[str]:
    """Long options listed under `Optional:` in mktarget.sh's usage() heredoc."""
    text = MKTARGET.read_text()
    block = text.split("\nOptional:\n", 1)[1].split("\nEnvironment:\n", 1)[0]
    return re.findall(r"^  (--[a-z-]+)", block, re.MULTILINE)


def _mktarget_parsed_flags() -> list[str]:
    """Long options the `case "$1"` arg parser actually accepts."""
    text = MKTARGET.read_text()
    block = text.split("# parse args\n", 1)[1].split("\ndone\n", 1)[0]
    return re.findall(r"^\s+(--[a-z-]+)(?:=\*)?\)", block, re.MULTILINE)


def _ubuntu_skill_flag_rows() -> list[str]:
    """First-column flag of every row in the ubuntu-target skill's flag table."""
    rows: list[str] = []
    in_table = False
    for raw in UBUNTU_SKILL.read_text().splitlines():
        if raw.startswith("## "):
            in_table = raw.startswith("## Flags and environment")
            continue
        if in_table and raw.startswith("| `--"):
            rows.append(raw.split("`", 2)[1].split()[0].split("[", 1)[0])
    return rows


def test_ubuntu_target_flag_table_matches_mktarget_usage_and_parser():
    """#53 (second half): `--modules-extra` was parsed but absent from usage(),
    and the installed skill copy described a suite default and an auto-skip the
    script never had. Three sources describe the flag set — usage(), the arg
    parser, the skill table — and they must enumerate the same options, in the
    same order for the two that are tables.
    """
    usage = _mktarget_usage_flags()
    parsed = _mktarget_parsed_flags()
    skill = _ubuntu_skill_flag_rows()

    assert set(parsed) - {"--help"} == set(usage), (
        f"parsed but undocumented in usage(): {sorted(set(parsed) - set(usage) - {'--help'})}; "
        f"documented but not parsed: {sorted(set(usage) - set(parsed))}"
    )
    assert skill == usage, (
        f"skill flag table {skill} != usage() {usage}"
    )


def test_ubuntu_target_skill_default_suite_matches_mktarget():
    """#53: the installed copy claimed `resolute` was the default suite."""
    script = MKTARGET.read_text()
    suite = re.search(r'^SUITE="([a-z]+)"$', script, re.MULTILINE).group(1)
    assert suite == "noble"
    assert f"Ubuntu suite (default: {suite})" in script
    text = UBUNTU_SKILL.read_text()
    assert f"| `--suite SUITE` | Ubuntu suite (default `{suite}`)" in text
    assert f"Default target: {suite} (24.04)" in text
    assert "resolute` | 26.04 LTS | **default**" not in text
