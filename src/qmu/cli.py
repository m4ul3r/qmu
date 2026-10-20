"""qmu command-line entry point.

This is the thin parser + dispatcher: it builds the ``argparse`` tree by calling
each command's ``_add_*`` register function (in display order) and maps the
handler's exception class to the documented exit code. All command handlers live
in :mod:`qmu.commands` and all shared helpers in :mod:`qmu._cliutil`.

Dependency direction is strictly one-way:

    cli -> commands.* -> _cliutil -> (config, instance, qmp, output, ssh, ...)

Each command module imports its own patchable collaborators directly from the
domain modules, so tests patch the command module that owns the handler (e.g.
``monkeypatch.setattr(lifecycle, "choose_instance", ...)`` for ``status``/``wait``,
``monkeypatch.setattr(guest, ...)`` for ``exec``) rather than this module.
"""

from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from .config import global_config_warnings, reset_global_config_warnings
from .instance import QMUError, reset_autoselection
from .output import render_value
from .qmp import QMPError
from .ssh import SSHError
from .version import VERSION

from ._cliutil import (
    Result,
    _add_top_level_common_opts,
    _emit_error,
    _resolve_config_from_args,
    render,
)
from .commands import daemon_cmds, guest, lifecycle, mcp_cmds, meta, qmp_cmds, run

# Re-exported solely so test_snapshot_exit can reach it as ``cli._snapshot_failed``.
from .commands.qmp_cmds import _snapshot_failed  # noqa: F401


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


# Uniform project-config gate (#37): any command operating in a project
# context refuses a fatally-invalid project/explicit qmu.toml, byte-
# matching `config show`'s refusal — no sibling verb may disagree about
# whether the project is valid. Exempt verbs: those that never read
# qmu.toml (skill/version), author it (config init), diagnose it
# read-only (doctor), or operate purely on host artifact dirs
# (cache/rootfs build-side). `mcp serve` is a long-lived server: each tool
# call dispatches through this gate itself, so the error lands in that
# call's envelope rather than refusing to start. Gated handlers may resolve
# again; the resolution is idempotent and the error identical.
_CONFIG_EXEMPT_SUBCOMMANDS = frozenset({
    "cache", "config", "doctor", "mcp", "rootfs", "skill", "version",
})


class _UsageError(Exception):
    """An argparse usage error, carried out of parse_args instead of exiting.

    argparse's `error()` prints usage and calls sys.exit(2) itself, which is
    why usage errors under `--format json` used to produce an empty stdout —
    the one error path that broke the "every error emits the envelope"
    contract. The parser raises this instead and `main` renders it per format.
    """

    def __init__(self, parser: argparse.ArgumentParser, message: str) -> None:
        super().__init__(message)
        self.parser = parser
        self.message = message


class _QMUArgumentParser(argparse.ArgumentParser):
    """ArgumentParser whose usage errors are exceptions, not sys.exit calls.

    `add_subparsers` defaults `parser_class` to `type(self)`, so every
    subparser (and nested sub-subparser) created from this root is this class
    too; `--help` still exits 0 through `exit()`, which is untouched.
    """

    def error(self, message: str) -> NoReturn:
        raise _UsageError(self, message)

    def parse_args(self, args=None, namespace=None):  # type: ignore[override]
        parsed, extras = self.parse_known_args(args, namespace)
        if extras:
            _absorb_trailing_positionals(self, parsed, extras)
        return parsed


class _VersionAction(argparse.Action):
    """`qmu --version`: the same answer as `qmu version`, exit 0.

    Every CLI answers `--version`; here it was an argparse exit 2. Honors a
    `--format json|ndjson` given before it so the envelope contract holds.
    """

    def __init__(self, option_strings, dest=argparse.SUPPRESS, **kwargs):
        super().__init__(option_strings, dest=dest, nargs=0, help=kwargs.get("help"))

    def __call__(self, parser, namespace, values, option_string=None):
        fmt = getattr(namespace, "format", None) or "text"
        if fmt == "text":
            sys.stdout.write(f"qmu {VERSION}\n")
        else:
            sys.stdout.write(render_value({"ok": True, "version": VERSION}, fmt))
        parser.exit(0)


def build_parser() -> argparse.ArgumentParser:
    """Build the full argparse tree. Separate from :func:`main` so tests can
    exercise the REAL parser instead of a hand-mirrored copy that can desync."""
    parser = _QMUArgumentParser(
        prog="qmu",
        description="Agent-friendly QEMU VM management CLI for kernel research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0    success\n"
            "  1    operation failed (guest command non-zero, doctor unhealthy,\n"
            "       snapshot op failed, no crash found, qmu operational errors\n"
            "       such as 'no running VM' or 'kernel not found')\n"
            "  2    usage / argparse error (bad flags or arguments) — ONLY\n"
            "  3    guest kernel crash (corroborated by a fresh serial crash report)\n"
            "  4    infrastructure / internal error (QMP or SSH layer failures,\n"
            "       unexpected qmu errors, infra-subprocess failures such as a\n"
            "       pry/gdb hang)\n"
            "  124  timeout: 'wait' deadline, 'launch'/'run' --ssh-timeout expired\n"
            "       before the guest answered SSH (VM retained, timed_out: true),\n"
            "       'run'/'exec' COMMAND outlived --timeout, 'snapshot save'\n"
            "       budget expired (result unknown, may_have_landed: true)\n"
            "\n"
            "json contract:\n"
            "  With --format json|ndjson every result is a JSON object carrying\n"
            "  \"ok\": <bool>. Every error path emits\n"
            "  {\"ok\": false, \"error\": ..., \"error_type\": ..., \"hint\": ...}\n"
            "  to stdout — usage errors (exit 2) included, as error_type\n"
            "  \"UsageError\" with a \"usage\" field. Warnings that also went to\n"
            "  stderr ride in the envelope as \"warnings\": [...]."
        ),
    )
    # Register --vm/--format/--out on the top-level parser so they may be given
    # BEFORE the subcommand (e.g. `qmu --vm X exec "uname -r"`); the same flags
    # are also added to each subparser (after the subcommand) via
    # _add_common_opts with SUPPRESS defaults so neither order clobbers the other.
    _add_top_level_common_opts(parser)
    parser.add_argument(
        "--version", action=_VersionAction,
        help="Print the qmu version and exit (same as `qmu version`)",
    )
    sub = parser.add_subparsers(dest="subcommand")

    lifecycle._add_launch(sub)
    run._add_run(sub)
    lifecycle._add_kill(sub)
    lifecycle._add_prune(sub)
    lifecycle._add_wait(sub)
    lifecycle._add_list(sub)
    lifecycle._add_status(sub)
    lifecycle._add_doctor(sub)
    meta._add_cache(sub)
    meta._add_config(sub)
    qmp_cmds._add_snapshot(sub)
    guest._add_push(sub)
    guest._add_pull(sub)
    guest._add_exec(sub)
    guest._add_compile(sub)
    guest._add_dmesg(sub)
    guest._add_crash(sub)
    guest._add_log(sub)
    qmp_cmds._add_gdb(sub)
    qmp_cmds._add_kbase(sub)
    qmp_cmds._add_cont(sub)
    qmp_cmds._add_qmp(sub)
    qmp_cmds._add_monitor(sub)
    meta._add_rootfs(sub)
    daemon_cmds._add_daemon(sub)
    mcp_cmds._add_mcp(sub)
    meta._add_skill(sub)
    meta._add_version(sub)
    return parser


def _requested_format(argv: list[str]) -> str:
    """The --format value in argv, scanned without parsing.

    Usage errors happen before argparse has produced a namespace, so this is
    the only way to honor `--format json` on that path. Scanning stops at a
    bare `--`: everything after it is a guest or QEMU argument.
    """
    fmt = "text"
    tokens = iter(argv)
    for token in tokens:
        if token == "--":
            break
        if token == "--format":
            fmt = next(tokens, fmt)
        elif token.startswith("--format="):
            fmt = token.split("=", 1)[1]
    return fmt if fmt in ("json", "ndjson") else "text"


_GUEST_COMMAND_HINT = (
    "Hint: quote the guest command ('uname -a') or put -- before it "
    "(qmu exec -- uname -a); qmu flags may appear anywhere."
)


def _invoked_subcommand(argv: list[str]) -> str | None:
    """The subcommand token in argv, scanned without parsing.

    Skips the root options that take a value (`--vm X`, `--format json`,
    `--out F`) and any `--x=y`; the first remaining non-dash token is the
    subcommand. Stops at a bare `--`.
    """
    tokens = iter(argv)
    for token in tokens:
        if token == "--":
            return None
        if token in ("--vm", "--format", "--out"):
            next(tokens, None)
        elif not token.startswith("-"):
            return token
    return None


def _usage_hint(exc: _UsageError, argv: list[str]) -> str | None:
    """A follow-up for the usage errors whose fix is not obvious from argparse.

    `qmu exec uname -a` is rejected with "unrecognized arguments: -a" because
    the guest command's dash-words are classified as qmu options; the message
    alone sends callers hunting for a qmu flag named `-a`.
    """
    if exc.message.startswith("unrecognized arguments:") and _invoked_subcommand(
        argv
    ) in ("exec", "run"):
        return _GUEST_COMMAND_HINT
    return None


def _emit_usage_error(exc: _UsageError, argv: list[str]) -> NoReturn:
    """Report a usage error, then exit 2 exactly as argparse would have.

    Text mode reproduces argparse's own output (usage, then
    `qmu <sub>: error: <message>` on stderr). Under --format json|ndjson the
    same error is the documented `{"ok": false, ...}` envelope on stdout, so
    an agent branching on the envelope is never handed an empty stdout. The
    exit is still `parser.exit(2)` (a SystemExit), so callers that treated
    argparse errors as SystemExit keep seeing one. A :func:`_usage_hint`
    follows the message in text mode and rides as `hint` in the envelope;
    without one the envelope's `hint` is `qmu <sub> --help` (#74: every
    `ok: false` envelope carries a hint) and text mode stays as argparse
    prints it.
    """
    fmt = _requested_format(argv)
    usage = exc.parser.format_usage()
    hint = _usage_hint(exc, argv)
    if fmt == "text":
        sys.stderr.write(usage)
        trailer = f"\n{hint}\n" if hint else "\n"
        exc.parser.exit(2, f"{exc.parser.prog}: error: {exc.message}{trailer}")
    if hint is None:
        sub = _invoked_subcommand(argv)
        hint = f"qmu {sub} --help" if sub else "qmu --help"
    payload = {
        "ok": False,
        "error": exc.message,
        "error_type": "UsageError",
        "usage": usage.strip(),
        "hint": hint,
    }
    sys.stdout.write(render_value(payload, fmt))
    exc.parser.exit(2)


def _parse(argv: list[str]) -> argparse.Namespace | None:
    """Parse `argv` into a dispatchable namespace.

    A usage error is reported as argparse would and raises ``SystemExit(2)``
    (via :func:`_emit_usage_error`). A missing subcommand under ``--format
    json|ndjson`` is the same usage-error envelope; in text mode the top-level
    help is printed and ``None`` is returned so the caller decides how to
    exit 2 (``main`` returns it, ``invoke`` raises it).
    """
    # Per-command, not per-process: two separate `qmu` invocations must each
    # warn on a broken global config; only resolve_config() calls WITHIN this
    # one dispatch (the gate below plus a handler that resolves again) dedupe.
    reset_global_config_warnings()
    reset_autoselection()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        _emit_usage_error(exc, argv)

    if not args.subcommand or getattr(args, "handler", None) is None:
        if _requested_format(argv) == "text":
            parser.print_help()
            return None
        _emit_usage_error(_UsageError(parser, "a subcommand is required"), argv)
    return args


def _absorb_trailing_positionals(
    parser: argparse.ArgumentParser, args: argparse.Namespace, extras: list[str]
) -> None:
    """Append positional leftovers to a leaf's `nargs='*'` list, else refuse.

    Before Python 3.12 a `*` positional after another positional
    (`compile SOURCE [ARG ...]`) only takes words contiguous with the first
    one: `compile poc.c --run -- /tmp/t 1` left `-- /tmp/t 1` unrecognized
    (exit 2) there while 3.12+ parsed it. A leaf names the list in
    `set_defaults(trailing_positionals=<dest>)`; what follows `--` and any
    non-option word is appended in order. Anything else is the usage error
    `parse_args` would have raised, word for word.
    """
    dest = getattr(args, "trailing_positionals", None)
    absorbed: list[str] = []
    if dest is not None:
        rest = list(extras)
        while rest:
            word = rest.pop(0)
            if word == "--":
                absorbed.extend(rest)
                rest = []
            elif word.startswith("-") and word != "-":
                absorbed = []
                break
            else:
                absorbed.append(word)
        else:
            setattr(args, dest, [*(getattr(args, dest) or []), *absorbed])
            return
    raise _UsageError(parser, f"unrecognized arguments: {' '.join(extras)}")



def _dispatch(args: argparse.Namespace) -> Result:
    """Apply the project-config gate, then run the handler; nothing rendered.

    Warnings the gate (or the handler's own config resolution) recorded — a
    broken global config is skipped with a warning, never fatal — are
    attached to the Result so they reach stderr and the envelope's
    `warnings[]` through the same rendering as every other warning (#74).
    """
    if args.subcommand not in _CONFIG_EXEMPT_SUBCOMMANDS:
        _resolve_config_from_args(args)
    result = args.handler(args)
    return result.warn(*global_config_warnings())


def invoke(argv: list[str]) -> Result:
    """Parse `argv`, apply the project-config gate, dispatch; return the Result.

    Nothing is rendered: this is the in-process seam (MCP façade, daemon).
    Handler exceptions propagate exactly as the handler raised them —
    :class:`QMUError`, :class:`QMPError`, :class:`SSHError`, anything else —
    and :func:`main` owns the exception -> exit-code mapping. A usage error
    (and a missing subcommand) raises ``SystemExit(2)`` after argparse's own
    report, exactly as :func:`main` lets it escape.
    """
    args = _parse(argv)
    if args is None:
        raise SystemExit(2)
    return _dispatch(args)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = _parse(argv)
    if args is None:
        return 2
    return run_parsed(args)


def run_parsed(args: argparse.Namespace) -> int:
    """Dispatch an already-parsed namespace, render, map exceptions to exit codes.

    The second half of :func:`main`, exposed so the MCP façade can run the
    real parser and then force ``args.format``/``args.out`` (#123) before
    anything is dispatched or rendered.
    """
    try:
        return render(args, _dispatch(args))
    except QMUError as exc:
        # Exit-code contract: 2 is reserved for argparse usage errors (argparse
        # itself calls sys.exit(2)). Library errors get distinct codes so an
        # agent can tell a typo from an operational/infra failure:
        #   QMUError (operational, e.g. "no running VM", "kernel not found") -> 1
        #   QMPError/SSHError (infrastructure transport failures)            -> 4
        _emit_error(args, exc, "[qmu] Error:")
        return 1
    except QMPError as exc:
        _emit_error(args, exc, "[qmu] QMP error:")
        return 4
    except SSHError as exc:
        _emit_error(args, exc, "[qmu] SSH error:")
        return 4
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 — agent-facing catch-all
        # CORR-3: never surface a raw Python traceback to the agent. Any
        # unexpected internal error (the main() catch-all, plus infra-subprocess
        # failures such as a pry/gdb/scp hang) becomes a machine-actionable
        # message + JSON envelope with exit code 4 (internal/unexpected qmu
        # error) so it is NOT confused with a guest kernel crash / SSH
        # transport-loss (exit 3) or an ordinary non-zero guest command (exit 1).
        _emit_error(args, exc, "[qmu] Error:")
        return 4
