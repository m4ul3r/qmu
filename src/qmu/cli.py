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

from .instance import QMUError
from .qmp import QMPError
from .ssh import SSHError

from ._cliutil import _add_top_level_common_opts, _emit_error
from .commands import guest, lifecycle, meta, qmp_cmds

# Re-exported solely so test_snapshot_exit can reach it as ``cli._snapshot_failed``.
from .commands.qmp_cmds import _snapshot_failed  # noqa: F401


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
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
            "  3    guest kernel crash or SSH transport-loss\n"
            "  4    infrastructure / internal error (QMP or SSH layer failures,\n"
            "       unexpected qmu errors, infra-subprocess failures such as a\n"
            "       pry/gdb hang)\n"
            "  124  wait timeout\n"
            "\n"
            "json contract:\n"
            "  With --format json|ndjson every result is a JSON object carrying\n"
            "  \"ok\": <bool>. Every error path emits\n"
            "  {\"ok\": false, \"error\": ..., \"error_type\": ...} to stdout."
        ),
    )
    # Register --vm/--format/--out on the top-level parser so they may be given
    # BEFORE the subcommand (e.g. `qmu --vm X exec "uname -r"`); the same flags
    # are also added to each subparser (after the subcommand) via
    # _add_common_opts with SUPPRESS defaults so neither order clobbers the other.
    _add_top_level_common_opts(parser)
    sub = parser.add_subparsers(dest="subcommand")

    lifecycle._add_launch(sub)
    lifecycle._add_kill(sub)
    lifecycle._add_prune(sub)
    lifecycle._add_wait(sub)
    lifecycle._add_list(sub)
    lifecycle._add_status(sub)
    lifecycle._add_doctor(sub)
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

    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 2

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2

    try:
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
