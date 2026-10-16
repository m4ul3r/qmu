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

from .config import reset_global_config_warnings
from .instance import QMUError
from .output import render_value
from .qmp import QMPError
from .ssh import SSHError

from ._cliutil import (
    _add_top_level_common_opts,
    _emit_error,
    _resolve_config_from_args,
)
from .commands import guest, lifecycle, meta, qmp_cmds, run

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
# (cache/rootfs build-side). Gated handlers may resolve again; the
# resolution is idempotent and the error identical.
_CONFIG_EXEMPT_SUBCOMMANDS = frozenset({
    "cache", "config", "doctor", "rootfs", "skill", "version",
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
            "  124  wait timeout (also: 'run' gave up waiting for the guest)\n"
            "\n"
            "json contract:\n"
            "  With --format json|ndjson every result is a JSON object carrying\n"
            "  \"ok\": <bool>. Every error path emits\n"
            "  {\"ok\": false, \"error\": ..., \"error_type\": ...} to stdout —\n"
            "  usage errors (exit 2) included, as error_type \"UsageError\"\n"
            "  with a \"usage\" field."
        ),
    )
    # Register --vm/--format/--out on the top-level parser so they may be given
    # BEFORE the subcommand (e.g. `qmu --vm X exec "uname -r"`); the same flags
    # are also added to each subparser (after the subcommand) via
    # _add_common_opts with SUPPRESS defaults so neither order clobbers the other.
    _add_top_level_common_opts(parser)
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


def _emit_usage_error(exc: _UsageError, argv: list[str]) -> NoReturn:
    """Report a usage error, then exit 2 exactly as argparse would have.

    Text mode reproduces argparse's own output (usage, then
    `qmu <sub>: error: <message>` on stderr). Under --format json|ndjson the
    same error is the documented `{"ok": false, ...}` envelope on stdout, so
    an agent branching on the envelope is never handed an empty stdout. The
    exit is still `parser.exit(2)` (a SystemExit), so callers that treated
    argparse errors as SystemExit keep seeing one.
    """
    fmt = _requested_format(argv)
    usage = exc.parser.format_usage()
    if fmt == "text":
        sys.stderr.write(usage)
        exc.parser.exit(2, f"{exc.parser.prog}: error: {exc.message}\n")
    payload = {
        "ok": False,
        "error": exc.message,
        "error_type": "UsageError",
        "usage": usage.strip(),
    }
    sys.stdout.write(render_value(payload, fmt))
    exc.parser.exit(2)


def main(argv: list[str] | None = None) -> int:
    # Per-command, not per-process: two separate `qmu` invocations must each
    # warn on a broken global config; only resolve_config() calls WITHIN this
    # one dispatch (the gate below plus a handler that resolves again) dedupe.
    reset_global_config_warnings()
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        _emit_usage_error(exc, argv)

    if not args.subcommand or getattr(args, "handler", None) is None:
        if _requested_format(argv) == "text":
            parser.print_help()
            return 2
        _emit_usage_error(_UsageError(parser, "a subcommand is required"), argv)
    handler = args.handler

    try:
        if args.subcommand not in _CONFIG_EXEMPT_SUBCOMMANDS:
            _resolve_config_from_args(args)
        return handler(args)
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
