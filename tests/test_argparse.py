"""Tests for the qmu argument parser — --vm flag placement (H5).

SKILL.md documents BOTH `qmu --vm X exec ...` (pre-subcommand) and
`qmu exec --vm X ...` (post-subcommand). The top-level parser must accept either
order and resolve args.vm == "X" in both. These tests pin that contract.

No VM is launched: the subcommand handler is replaced with a stub that captures
the parsed Namespace and returns 0, so only argparse resolution is exercised.

Findings exercised: ARG-1 / H5.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from qmu import cli
from qmu.commands import guest, lifecycle


@pytest.fixture
def captured_exec_args(monkeypatch):
    """Replace _handle_exec with a stub that records args. _add_exec binds the
    handler from the module global at parser-build time (inside main()), so
    patching cli._handle_exec before calling main() takes effect."""
    captured = {}

    def _stub(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr(guest, "_handle_exec", _stub)
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


def test_launch_arch_and_backend_overrides_reach_launch_vm(monkeypatch):
    captured = {}

    def fake_launch_vm(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            harness=True,
            ssh_port=None,
            gdb_port=None,
            vm_id="selection",
            pid=4242,
            kernel=kwargs["kernel"],
            profile=kwargs["profile"],
            serial_log="/tmp/selection.serial.log",
        )

    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(lifecycle, "launch_vm", fake_launch_vm)

    rc = cli.main([
        "launch",
        "--kernel", "/not-opened-by-stub",
        "--arch", "aarch64",
        "--net-backend", "passt",
        "--harness",
        "--name", "selection",
    ])

    assert rc == 0
    assert captured["config"].arch == "aarch64"
    assert captured["net_backend"] == "passt"


def test_launch_help_describes_passt_as_conditional_migration_backend(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["launch", "--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "migration-compatible" in help_text
    assert "selected QEMU" in help_text
    assert "advertises" in help_text
    assert "snapshots work" not in help_text
    assert "10.1+" not in help_text
    assert "QEMU 9" not in help_text


class TestJoinExecCommand:
    """_join_exec_command turns `qmu exec` positionals into the guest command.

    A single quoted argument is the documented agent-facing form and must reach
    the guest login shell verbatim so `qmu exec "uname -a"` and pipe/redirect
    forms work. Multiple args keep the shlex token-per-arg model. Pins the fix
    for the broken `qmu exec "<shell string>"` interface.
    """

    def test_single_multiword_arg_passed_verbatim(self):
        # The documented form: one quoted string -> guest shell runs it as-is.
        assert guest._join_exec_command(["uname -a"]) == "uname -a"

    def test_single_arg_with_pipe_preserved(self):
        # Pipes/redirects must survive untouched for the guest shell to interpret.
        cmd = "cat /proc/slabinfo | grep kmalloc-192"
        assert guest._join_exec_command([cmd]) == cmd

    def test_single_simple_arg(self):
        assert guest._join_exec_command(["uname"]) == "uname"

    def test_multiple_args_use_shlex_join(self):
        # Token-per-arg: an arg with spaces stays one quoted shell token.
        assert guest._join_exec_command(["grep", "two words", "f"]) == "grep 'two words' f"

    def test_multiple_simple_args(self):
        assert guest._join_exec_command(["uname", "-a"]) == "uname -a"


class TestPruneVmPlacement:
    """`qmu --vm X prune` must target X (fix #2).

    prune declares its own `--vm` in a mutually_exclusive_group. Previously it
    used default=None, which clobbered a top-level `--vm X` given BEFORE the
    subcommand, so `qmu --vm foo prune` fell through to the bare
    "Specify either --vm <name> or --all." path. With default=argparse.SUPPRESS
    (matching every other subcommand) the pre-subcommand value survives.

    No VM state is touched: list_instances / list_stopped_instances are stubbed
    empty so the handler reaches its name-lookup branch deterministically.
    """

    @pytest.fixture(autouse=True)
    def _no_vms(self, monkeypatch):
        monkeypatch.setattr(lifecycle, "list_instances", lambda: [])
        monkeypatch.setattr(lifecycle, "list_stopped_instances", lambda: [])

    def test_vm_before_subcommand_targets_name(self, capsys):
        # Reaches the specific "No stopped VM named 'foo'." branch (target
        # lookup) — proof the top-level --vm reached _handle_prune.
        rc = cli.main(["--vm", "foo", "prune"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "No stopped VM named 'foo'." in err
        assert "Specify either" not in err

    def test_vm_after_subcommand_targets_name(self, capsys):
        rc = cli.main(["prune", "--vm", "foo"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "No stopped VM named 'foo'." in err

    def test_no_vm_no_all_still_prompts(self, capsys):
        # The bare form (neither --vm nor --all) must still hit the guidance.
        rc = cli.main(["prune"])
        assert rc == 1
        assert "Specify either --vm <name> or --all." in capsys.readouterr().err

    def test_all_flag_still_works(self, capsys):
        # --all path is unaffected; empty stopped list => benign no-op, exit 0.
        rc = cli.main(["prune", "--all"])
        assert rc == 0
        assert "No stopped VMs to prune." in capsys.readouterr().out

    def test_vm_and_all_are_mutually_exclusive(self):
        # argparse enforces the mutual exclusion -> usage error (SystemExit / 2).
        with pytest.raises(SystemExit) as exc:
            cli.main(["prune", "--vm", "foo", "--all"])
        assert exc.value.code == 2
