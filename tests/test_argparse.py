"""Tests for the qmu argument parser — --vm flag placement (H5).

SKILL.md documents BOTH `qmu --vm X exec ...` (pre-subcommand) and
`qmu exec --vm X ...` (post-subcommand). The top-level parser must accept either
order and resolve args.vm == "X" in both. These tests pin that contract.

No VM is launched: the subcommand handler is replaced with a stub that captures
the parsed Namespace and returns 0, so only argparse resolution is exercised.

Findings exercised: ARG-1 / H5.
"""

from __future__ import annotations

import pytest

from qmu import cli


@pytest.fixture
def captured_exec_args(monkeypatch):
    """Replace _handle_exec with a stub that records args. _add_exec binds the
    handler from the module global at parser-build time (inside main()), so
    patching cli._handle_exec before calling main() takes effect."""
    captured = {}

    def _stub(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_handle_exec", _stub)
    return captured


# The command is given as a single token (e.g. the quoted "uname -r" form
# SKILL.md uses for guest commands) so these tests isolate H5 (--vm PLACEMENT)
# and do not also exercise the orthogonal argparse quirk of a leading-dash token
# being swallowed by the nargs="+" positional.

def test_vm_flag_before_subcommand(captured_exec_args):
    """qmu --vm X exec <cmd>  ->  args.vm == 'X'."""
    rc = cli.main(["--vm", "kasan-vm", "exec", "uname"])
    assert rc == 0
    args = captured_exec_args["args"]
    assert args.vm == "kasan-vm"
    assert args.command == ["uname"]


def test_vm_flag_after_subcommand(captured_exec_args):
    """qmu exec --vm X <cmd>  ->  args.vm == 'X'."""
    rc = cli.main(["exec", "--vm", "kasan-vm", "uname"])
    assert rc == 0
    args = captured_exec_args["args"]
    assert args.vm == "kasan-vm"
    assert args.command == ["uname"]


def test_both_orders_resolve_identically(captured_exec_args):
    """Both placements yield the same resolved vm value."""
    cli.main(["--vm", "X", "exec", "uname"])
    before = captured_exec_args["args"].vm
    cli.main(["exec", "--vm", "X", "uname"])
    after = captured_exec_args["args"].vm
    assert before == after == "X"
