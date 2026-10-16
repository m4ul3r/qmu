"""State x command x branch x format agreement matrix.

Six rounds of dogfooding produced the same defect over and over: a fix improved
one path's message and left its siblings contradicting it. The missed siblings
were always on one of four axes — preview vs real, branch vs branch, text vs
JSON, subcommand vs subcommand — so per-fix rules cannot catch the class. This
matrix can: for each observable state, every command that reports on it must
agree that it exists and what it is.

Adding a state or a command that reports on one means adding a row here.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from qmu import cli
from qmu import instance as instance_mod
from qmu.commands import guest as guest_mod
from qmu.commands import lifecycle
from qmu.instance import (
    VM_ABSENT,
    VM_HELD_BACK,
    VM_ORPHANED,
    VM_RUNNING,
    VM_STOPPED,
    VMInstance,
    classify_vm,
)
from qmu.ssh import SSHError


VM = "subject"


def _write_remnant(cache, vm_id=VM, *, size=64):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text("x" * size + "\n")
    (idir / f"{vm_id}.qemu.log").write_text("qemu\n")
    return serial


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    return tmp_path


def _decoy_running(monkeypatch):
    """A second, healthy VM.

    Without one, `choose_instance` short-circuits to "No running VMs" and the
    invariant assertion never exercises the "VM 'X' not found. Running: ..."
    branch — the exact message the real CLI produced on a shared box. A double
    with an empty instance list hides the bug the matrix exists to catch.
    """
    decoy = VMInstance(
        vm_id="decoy", pid=1, qmp_socket="/tmp/decoy.qmp.sock",
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log="/tmp/decoy.serial.log", kernel="/boot/bzImage",
        rootfs=None, memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-08-17T00:00:00Z", harness=True,
    )
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy], raising=False)
    monkeypatch.setattr(
        "qmu.commands.guest.choose_instance",
        lambda vm=None: (_ for _ in ()).throw(
            __import__("qmu.instance", fromlist=["QMUError"]).QMUError(
                f"VM '{vm}' not found. Running: decoy"
            )
        ) if vm != "decoy" else decoy,
    )
    return decoy


def _make_state(state, cache, monkeypatch):
    """Materialize one observable state and return its expected pid."""
    if state == VM_ABSENT:
        (cache / "instances").mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
        return None

    serial = _write_remnant(cache)

    if state == VM_ORPHANED:
        monkeypatch.setattr(
            lifecycle, "find_orphan_qemus",
            lambda: [{"pid": 4242, "serial_log": str(serial), "cmdline": "qemu"}],
        )
        monkeypatch.setattr(
            instance_mod, "find_orphan_qemus",
            lambda: [{"pid": 4242, "serial_log": str(serial), "cmdline": "qemu"}],
        )
        return 4242

    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    return None


# ---------------------------------------------------------------------------
# The classifier is the single authority every command must route through.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", [VM_ABSENT, VM_ORPHANED, VM_STOPPED])
def test_classifier_returns_the_expected_state(state, cache, monkeypatch):
    _make_state(state, cache, monkeypatch)
    older = 0.0 if state == VM_STOPPED else 86400.0

    info = classify_vm(VM, older_than_seconds=older)

    assert info["state"] == state


def test_held_back_is_distinct_from_stopped(cache, monkeypatch):
    """Same artifacts, different cutoff — the states must not collapse."""
    _make_state(VM_STOPPED, cache, monkeypatch)

    assert classify_vm(VM, older_than_seconds=0.0)["state"] == VM_STOPPED
    assert classify_vm(VM, older_than_seconds=86400.0)["state"] == VM_HELD_BACK


@pytest.mark.parametrize("failure", ["missing", "read"])
def test_unavailable_stopped_serial_is_inconclusive_not_a_negative(
    cache, monkeypatch, capsys, failure
):
    inst = _vm_with_log(cache, VM, "booting\n")
    inst.pid = 0
    instance_mod.save_instance(inst)
    serial = Path(inst.serial_log)
    if failure == "missing":
        serial.unlink()
    else:
        import io

        class Unreadable(io.FileIO):
            def read(self, size=-1):
                raise OSError("serial fixture I/O failure")

        original_open = Path.open

        def open_serial(path, *args, **kwargs):
            if path == serial and args == ("rb",):
                return Unreadable(path, "r")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_serial)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    rc = cli.main(["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
                   "--timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    # Infra class, never the exit 1 a genuine no-match returns: an agent
    # branching on the code must not file unreadable evidence as a failed
    # experiment.
    assert rc == 4
    assert payload["ok"] is False
    assert payload["inconclusive"] is True
    assert "error" in payload
    assert "error_type" in payload
    assert "matched" not in payload
    assert instance_mod.load_instance(VM) is not None


@pytest.mark.parametrize("with_metadata", [False, True])
@pytest.mark.parametrize("output_format", ["text", "json", "ndjson"])
def test_explicit_stopped_pattern_wait_agrees_with_retained_log(
    cache, monkeypatch, capsys, with_metadata, output_format
):
    serial = _write_remnant(cache)
    serial.write_text("booting\nQMU-BOOT-DONE")  # final fragment without newline
    inst = _vm_with_log(cache, VM, serial.read_text())
    inst.pid = 0
    if with_metadata:
        instance_mod.save_instance(inst)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    rc = cli.main(["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
                   "--timeout", "0", "--format", output_format])
    output = capsys.readouterr().out

    assert rc == 0
    if output_format == "text":
        assert "QMU-BOOT-DONE" in output
    else:
        payload = json.loads(output)
        assert payload["ok"] is True
        assert payload["vm_id"] == VM
        assert payload["matched_line"] == "QMU-BOOT-DONE"
    assert serial.read_text() == "booting\nQMU-BOOT-DONE"
    assert (instance_mod.load_instance(VM) is not None) == with_metadata


def test_stopped_pattern_wait_without_match_is_not_a_timeout(
    cache, monkeypatch, capsys
):
    serial = _write_remnant(cache)
    content = (
        "[    0.044413] kasan: KernelAddressSanitizer initialized\n"
        "probe did not complete\n"
    )
    serial.write_text(content)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    rc = cli.main(["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
                   "--timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["ok"] is False
    assert payload["matched"] is False
    assert payload["reason"] == "process_exited"
    assert payload["crash"] is None
    assert serial.read_text() == content


@pytest.mark.parametrize("terminal", [False, True])
def test_stopped_wait_requires_terminal_evidence_for_exit_three(
    cache, monkeypatch, capsys, terminal
):
    report = (
        "BUG: KASAN: slab-out-of-bounds in fixture_operation\n"
        "Read of size 1 by task fixture/42\n"
        "---[ end trace 0000000000000000 ]---\n"
    )
    if terminal:
        report += (
            "Kernel panic - not syncing: test panic\n"
            "---[ end Kernel panic - not syncing: test panic ]---\n"
        )
    content = report + "reboot: Power down\n"
    serial = _write_remnant(cache)
    serial.write_text(content)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    args = ["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
            "--timeout", "0", "--format", "json"]
    if terminal:
        # Ignore the early abort to exercise classification after process exit.
        args.append("--ignore-crash")
    rc = cli.main(args)
    payload = json.loads(capsys.readouterr().out)

    assert rc == (3 if terminal else 1)
    assert payload["ok"] is False
    assert payload["matched"] is False
    assert payload["reason"] == "process_exited"
    assert "BUG: KASAN:" in payload["crash"]
    assert serial.read_text() == content


@pytest.mark.parametrize(("content", "pattern", "ignore_crash", "expected"), [
    ("Kernel panic - not syncing: test panic\nQMU-BOOT-DONE\n",
     "QMU-BOOT-DONE", False, 3),
    ("QMU-BOOT-DONE\nKernel panic - not syncing: test panic\n",
     "QMU-BOOT-DONE", False, 0),
    ("Kernel panic - not syncing: test panic\nQMU-BOOT-DONE\n",
     "QMU-BOOT-DONE", True, 0),
    ("Kernel panic - not syncing: test panic\n",
     "Kernel panic - not syncing", False, 0),
])
def test_stopped_pattern_obeys_panic_marker_order(
    cache, monkeypatch, capsys, content, pattern, ignore_crash, expected
):
    serial = _write_remnant(cache)
    serial.write_text(content)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    args = ["wait", "--vm", VM, "--pattern", pattern,
            "--timeout", "0", "--format", "json"]
    if ignore_crash:
        args.append("--ignore-crash")
    rc = cli.main(args)
    payload = json.loads(capsys.readouterr().out)

    assert rc == expected
    assert payload["ok"] == (expected == 0)
    assert payload["matched"] == (expected == 0)
    if expected == 3:
        assert payload["reason"] == "crash"
        assert "Kernel panic - not syncing" in payload["crash"]
    assert serial.read_text() == content


def test_stopped_pattern_ignores_pre_epoch_panic_tail(cache, monkeypatch, capsys):
    previous = "Kernel panic - not syncing: old panic\n"
    current = "---[ end Kernel panic - not syncing: old panic ]---\nQMU-BOOT-DONE\n"
    inst = _vm_with_log(cache, VM, previous + current)
    inst.pid = 0
    inst.guest_epoch_serial_offset = len(previous)
    instance_mod.save_instance(inst)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    rc = cli.main(["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
                   "--timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["matched_line"] == "QMU-BOOT-DONE"
    assert payload["crash"] is None


@pytest.mark.parametrize("boundary", ["recorded-epoch", "kernel-banner"])
def test_stopped_pattern_wait_does_not_reuse_previous_boot_evidence(
    cache, monkeypatch, capsys, boundary
):
    old = "QMU-BOOT-DONE\n"
    current = "[    0.000000] Linux version 6.6.75 (builder@host)\nbooting\n"
    inst = _vm_with_log(cache, VM, old + current)
    inst.pid = 0
    inst.guest_epoch_serial_offset = len(old) if boundary == "recorded-epoch" else 0
    instance_mod.save_instance(inst)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    _decoy_running(monkeypatch)

    rc = cli.main(["wait", "--vm", VM, "--pattern", "QMU-BOOT-DONE",
                   "--timeout", "0", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["matched"] is False
    assert payload["reason"] == "process_exited"
    # The boundary that excluded the marker is reported, never implicit: an
    # agent reading `reason` alone cannot tell "never printed" from "printed
    # before the scanned range".
    assert payload["scan_offset"] == len(old)
    assert payload["scan_scope"] == (
        "epoch" if boundary == "recorded-epoch" else "boot-banner"
    )


# ---------------------------------------------------------------------------
# Axis 4: subcommand vs subcommand. No command may deny what `list` displays.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", [VM_ORPHANED, VM_HELD_BACK])
# wait/exec/kill were omitted from this list in round 7 and were exactly the
# three commands still violating the invariant — 7 failing cells the matrix
# could not see. The command list IS the coverage; extending it is the cheapest
# and highest-value edit available here.
@pytest.mark.parametrize(
    "command", ["status", "show", "log", "prune", "wait", "exec", "kill"]
)
def test_no_command_calls_a_listed_vm_nonexistent(
    state, command, cache, monkeypatch, capsys
):
    """The recurring bug, pinned once for every command that can express it."""
    _make_state(state, cache, monkeypatch)
    _decoy_running(monkeypatch)

    cli.main(["list"])
    listing = capsys.readouterr().out
    assert VM in listing, "fixture did not produce a listed VM"

    argv = {
        "prune": ["prune", "--vm", VM],
        "wait": ["wait", "--vm", VM, "--timeout", "0"],
        "exec": ["exec", "--vm", VM, "true"],
    }.get(command, [command, "--vm", VM])
    cli.main(argv)
    combined = capsys.readouterr()
    message = combined.out + combined.err

    assert "not found" not in message, (
        f"`qmu {command}` denies a VM that `qmu list` displays"
    )
    assert "No stopped VM named" not in message


@pytest.mark.parametrize("state", [VM_ORPHANED, VM_HELD_BACK])
def test_status_explains_rather_than_denying(state, cache, monkeypatch, capsys):
    _make_state(state, cache, monkeypatch)

    rc = cli.main(["status", "--vm", VM])
    err = capsys.readouterr().err

    assert rc == 1
    assert VM in err
    # It must say what the thing IS, and name a command that acts on it.
    assert ("orphaned remnant" in err) or ("is stopped" in err)
    assert "qmu " in err


def test_status_names_the_live_pid_for_an_orphan(cache, monkeypatch, capsys):
    """`list` shows a pid; `status` must not describe the same VM without one."""
    pid = _make_state(VM_ORPHANED, cache, monkeypatch)

    cli.main(["status", "--vm", VM])

    assert str(pid) in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Axis 1: preview vs real. They must not disagree about the same cache.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extra", [[], ["--keep-logs"]])
def test_prune_all_preview_and_real_agree_on_held_back(
    extra, cache, monkeypatch, capsys
):
    """The preview is what a cautious operator runs first; it must not lie."""
    _make_state(VM_HELD_BACK, cache, monkeypatch)

    cli.main(["--format", "json", "prune", "--all", "--dry-run", *extra])
    preview = json.loads(capsys.readouterr().out)

    cli.main(["--format", "json", "prune", "--all", *extra])
    real = json.loads(capsys.readouterr().out)

    assert preview["held_back"] == real["held_back"] == [VM]


def test_preview_and_real_agree_on_a_mixed_cache(cache, monkeypatch, capsys):
    """The realistic case: something prunable AND something held back."""
    _write_remnant(cache, "prunable")
    _write_remnant(cache, "held")
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    # Age out only "prunable" by making the cutoff match nothing else.
    real_prunable = lifecycle.list_prunable_instance_ids
    monkeypatch.setattr(
        lifecycle, "list_prunable_instance_ids",
        lambda **kw: ["prunable"],
    )
    monkeypatch.setattr(
        instance_mod, "list_prunable_instance_ids",
        lambda **kw: ["prunable"],
    )

    cli.main(["--format", "json", "prune", "--all", "--dry-run"])
    preview = json.loads(capsys.readouterr().out)

    assert preview["would_prune"] == ["prunable"]
    # The bug: a mixed cache mentioned neither, so "Pruned 1" read as "clean".
    assert preview["held_back"] == ["held"]


# ---------------------------------------------------------------------------
# Axis 3: text vs JSON. Anything the text says must be machine-readable.
# ---------------------------------------------------------------------------


def test_held_back_appears_in_both_text_and_json(cache, monkeypatch, capsys):
    _make_state(VM_HELD_BACK, cache, monkeypatch)

    cli.main(["prune", "--all"])
    text = capsys.readouterr().out

    cli.main(["--format", "json", "prune", "--all"])
    payload = json.loads(capsys.readouterr().out)

    assert VM in text
    assert payload["held_back"] == [VM]


def test_orphan_state_appears_in_both_text_and_json(cache, monkeypatch, capsys):
    pid = _make_state(VM_ORPHANED, cache, monkeypatch)

    cli.main(["list"])
    text = capsys.readouterr().out

    cli.main(["--format", "json", "list"])
    payload = json.loads(capsys.readouterr().out)

    entry = [v for v in payload["vms"] if v["vm_id"] == VM][0]
    assert "ORPHANED" in text
    assert entry["status"] == "orphaned"
    assert entry["pid"] == pid


# ---------------------------------------------------------------------------
# Axis 2: branch vs branch. An empty result and a partial one must be
# equally honest about what was left behind.
# ---------------------------------------------------------------------------


def test_empty_and_partial_prune_are_equally_disclosing(cache, monkeypatch, capsys):
    _make_state(VM_HELD_BACK, cache, monkeypatch)

    cli.main(["--format", "json", "prune", "--all"])
    nothing_pruned = json.loads(capsys.readouterr().out)

    _write_remnant(cache, "prunable")
    monkeypatch.setattr(
        instance_mod, "list_prunable_instance_ids", lambda **kw: ["prunable"],
    )
    monkeypatch.setattr(
        lifecycle, "list_prunable_instance_ids", lambda **kw: ["prunable"],
    )
    cli.main(["--format", "json", "prune", "--all"])
    something_pruned = json.loads(capsys.readouterr().out)

    assert nothing_pruned["held_back"] == [VM]
    assert something_pruned["held_back"] == [VM]
    assert something_pruned["pruned"] == ["prunable"]


# ---------------------------------------------------------------------------
# Axes 1+2+3 at once, for the two prune outcomes that used to be errors on the
# `--vm` branch while `--all` reported them as facts: an absent subject
# (issue #56 — a default `kill` already removed everything, so the cleanup
# idiom `kill && prune --vm` failed) and an age-held one (`--vm --dry-run`
# exited 1 and prescribed the destructive run it exists to preview).
# ---------------------------------------------------------------------------


def _prune_argv(mode, dry_run, output_format):
    selector = [mode, VM] if mode == "--vm" else [mode]
    return ["--format", output_format, "prune", *selector] + (
        ["--dry-run"] if dry_run else []
    )


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("mode", ["--vm", "--all"])
def test_absent_subject_is_a_clean_prune_no_op(
    mode, dry_run, output_format, cache, monkeypatch, capsys
):
    _make_state(VM_ABSENT, cache, monkeypatch)
    _decoy_running(monkeypatch)

    rc = cli.main(_prune_argv(mode, dry_run, output_format))
    captured = capsys.readouterr()
    message = captured.out + captured.err

    assert rc == 0
    assert "No stopped VM named" not in message
    assert "not found" not in message
    assert "Error" not in message
    if output_format == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is True
        assert payload["pruned"] == []
        assert payload["dry_run"] is dry_run
        assert payload["held_back"] == []
        if dry_run:
            assert payload["would_prune"] == []
        if mode == "--vm":
            assert payload["found"] is False
        else:
            assert "found" not in payload
    elif mode == "--vm":
        assert f"Nothing to prune for '{VM}'" in captured.out
        assert "no state on disk" in captured.out


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_held_back_subject_is_reported_the_same_by_vm_and_all(
    dry_run, output_format, cache, monkeypatch, capsys
):
    _make_state(VM_HELD_BACK, cache, monkeypatch)
    serial = cache / "instances" / f"{VM}.serial.log"
    _decoy_running(monkeypatch)

    results = {}
    for mode in ("--vm", "--all"):
        rc = cli.main(_prune_argv(mode, dry_run, output_format))
        captured = capsys.readouterr()
        results[mode] = (rc, captured.out, captured.err)

    for mode, (rc, out, err) in results.items():
        assert rc == 0, mode
        assert "Error" not in out + err, mode
        assert VM in out, mode
        if output_format == "text":
            assert "--older-than 0" in out, mode
        # A preview must never prescribe the destructive run as the remedy.
        assert "to remove it now" not in out, mode
        if output_format == "json":
            payload = json.loads(out)
            assert payload["ok"] is True, mode
            assert payload["held_back"] == [VM], mode
            assert payload["pruned"] == [], mode
            assert payload["dry_run"] is dry_run, mode
            if dry_run:
                assert payload["would_prune"] == [], mode
    if output_format == "json":
        assert json.loads(results["--vm"][1])["found"] is True
    # Held back means held back: the remnant survives both modes.
    assert serial.exists()


def test_vm_and_all_agree_on_what_an_old_enough_remnant_is(
    cache, monkeypatch, capsys
):
    """The cutoff that lets `--all` prune a remnant must let `--vm` prune it."""
    _make_state(VM_HELD_BACK, cache, monkeypatch)
    _decoy_running(monkeypatch)

    cli.main(["--format", "json", "prune", "--all", "--dry-run", "--older-than", "0"])
    via_all = json.loads(capsys.readouterr().out)
    cli.main(["--format", "json", "prune", "--vm", VM, "--dry-run", "--older-than", "0"])
    via_vm = json.loads(capsys.readouterr().out)

    assert via_all["would_prune"] == via_vm["would_prune"] == [VM]
    assert via_all["held_back"] == via_vm["held_back"] == []
    assert via_vm["found"] is True


# ---------------------------------------------------------------------------
# The second axis: guest usability, orthogonal to existence.
#
# Proven orthogonal by a real VM that was simultaneously orphaned AND panicked.
# A flat enum cannot carry both facts, so these are two fields — and `list`
# reported only the first, presenting a panicked VM identically to a healthy one.
# ---------------------------------------------------------------------------


def _panicked_instance(cache, vm_id="gp"):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text(
        "[ 1.1] Kernel panic - not syncing: Fatal exception\n"
        "[ 1.1] ---[ end Kernel panic - not syncing: Fatal exception ]---\n"
    )
    return VMInstance(
        vm_id=vm_id, pid=4242, qmp_socket=str(idir / f"{vm_id}.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log=str(serial), kernel="/boot/bzImage", rootfs=None,
        memory="4G", cpus=2, cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=True,
    )


def test_a_panicked_guest_is_not_presented_as_healthy(cache, monkeypatch, capsys):
    """Every successful trigger under exploit-test lands here."""
    inst = _panicked_instance(cache)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [inst])
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    cli.main(["list"])

    assert "GUEST PANICKED" in capsys.readouterr().out


def test_guest_axis_is_machine_readable(cache, monkeypatch, capsys):
    inst = _panicked_instance(cache)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [inst])
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    cli.main(["--format", "json", "list"])
    payload = json.loads(capsys.readouterr().out)

    entry = payload["vms"][0]
    assert entry["status"] == "running"
    assert entry["guest"] == "panicked"


def test_paused_guest_is_not_reported_as_plainly_running(cache, monkeypatch, capsys):
    """`qmu gdb` halts the vCPU, so every pry session leaves a VM here."""
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / "pz.serial.log"
    serial.write_text("ordinary boot\n")
    inst = VMInstance(
        vm_id="pz", pid=4242, qmp_socket=str(idir / "pz.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None, serial_log=str(serial),
        kernel="/boot/bzImage", rootfs=None, memory="4G", cpus=2,
        cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=True,
    )
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [inst])
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    class FakeQMP:
        def execute(self, cmd):
            return {"running": False, "status": "paused"}

    class Ctx:
        def __enter__(self): return FakeQMP()
        def __exit__(self, *a): return False

    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda inst: Ctx())

    cli.main(["list"])
    text = capsys.readouterr().out

    cli.main(["--format", "json", "list"])
    payload = json.loads(capsys.readouterr().out)

    assert "paused" in text
    assert payload["vms"][0]["guest"] == "paused"


def test_orphaned_and_panicked_reports_both_facts(cache, monkeypatch, capsys):
    """The cell that proves the two axes are independent."""
    inst = _panicked_instance(cache, "op")
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [])
    orphans = [{
        "pid": 999, "serial_log": inst.serial_log, "rootfs": None,
        "cmdline": "qemu",
    }]
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: orphans)
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: orphans)

    cli.main(["list"])
    listing = capsys.readouterr().out

    cli.main(["status", "--vm", "op"])
    described = capsys.readouterr().err

    # Neither fact may be dropped: reaping without pulling the crash first
    # loses the evidence the run existed to produce.
    assert "ORPHANED" in listing and "PANICKED" in listing
    assert "orphaned remnant" in described
    assert "PANICKED" in described
    assert "qmu crash --vm op" in described


# ---------------------------------------------------------------------------
# The guest axis must track USABILITY, not merely "is a crash retrievable".
#
# Under the default exploit-dev profile (deliberately no oops=panic) an Oops
# kills the faulting task and the guest keeps serving. Labelling that
# `panicked` attached "reap it" guidance to a working VM — the inverse of the
# failure this axis was added to prevent.
# ---------------------------------------------------------------------------


def _vm_with_log(cache, vm_id, body):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text(body)
    return VMInstance(
        vm_id=vm_id, pid=4242, qmp_socket=str(idir / f"{vm_id}.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None, serial_log=str(serial),
        kernel="/boot/bzImage", rootfs=None, memory="4G", cpus=2,
        cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=True,
    )


SURVIVED_OOPS = (
    "[ 1.6] BUG: kernel NULL pointer dereference, address: 0000000000000083\n"
    "[ 1.6] Oops: Oops: 0000 [#2] SMP NOPTI\n"
    "[ 1.6] RIP: 0010:perf_event__header_size+0x12/0x80\n"
    "[ 1.6] ---[ end trace 0000000000000000 ]---\n"
    "[ 1.7] === GPF HARNESS DONE ===\n"   # guest kept running
)

TERMINAL_PANIC = (
    "[ 1.6] Oops: general protection fault [#1] SMP\n"
    "[ 1.6] ---[ end trace 0000000000000000 ]---\n"
    "[ 1.6] Kernel panic - not syncing: Fatal exception\n"
    "[ 1.6] ---[ end Kernel panic - not syncing: Fatal exception ]---\n"
)


def _register_running(monkeypatch, inst):
    """Make BOTH authorities agree the VM is running.

    `classify_vm` lives in qmu.instance and consults its own `list_instances`;
    patching only lifecycle's copy leaves the classifier seeing a bare serial
    log and calling the VM a stopped remnant — the two-authority plumbing the
    matrix exists to keep honest.
    """
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    # Deliberately does NOT touch _qmp_ctx: each test's own _qmp() fake must
    # stand, or `crashed` would pass merely because QMP was unreachable rather
    # than because the guest was confirmed running.


def _qmp(monkeypatch, running):
    class FakeQMP:
        def execute(self, cmd):
            return {"running": running, "status": "running" if running else "paused"}

    class Ctx:
        def __enter__(self): return FakeQMP()
        def __exit__(self, *a): return False

    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda inst: Ctx())


def test_survived_oops_is_crashed_not_panicked(cache, monkeypatch):
    """The default-profile everyday case that the old predicate inverted."""
    inst = _vm_with_log(cache, "oops", SURVIVED_OOPS)
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "crashed"


def test_terminal_panic_is_panicked(cache, monkeypatch):
    inst = _vm_with_log(cache, "dead", TERMINAL_PANIC)
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "panicked"


def test_clean_guest_is_serving(cache, monkeypatch):
    inst = _vm_with_log(cache, "ok", "[ 0.0] Linux version 6.12.0\n")
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


def test_halted_guest_is_paused(cache, monkeypatch):
    inst = _vm_with_log(cache, "pz", "[ 0.0] Linux version 6.12.0\n")
    _qmp(monkeypatch, False)

    assert lifecycle._guest_state(inst) == "paused"


def test_crashed_vm_is_never_told_to_be_reaped(cache, monkeypatch, capsys):
    """The label drives a destructive decision; it must not say 'reap'."""
    inst = _vm_with_log(cache, "oops", SURVIVED_OOPS)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    cli.main(["list"])
    listing = capsys.readouterr().out
    cli.main(["status", "--vm", "oops"])
    detail = capsys.readouterr().out

    assert "PANICKED" not in listing
    assert "crash report waiting" in listing
    assert "STILL RUNNING" in detail
    assert "do not reap it" in detail


def test_status_reports_the_crash_on_the_running_path(cache, monkeypatch, capsys):
    """It warned only on the orphaned path — the rarer of the two."""
    inst = _vm_with_log(cache, "gp", TERMINAL_PANIC)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    cli.main(["status", "--vm", "gp"])
    out = capsys.readouterr().out

    assert "PANICKED" in out
    assert "qmu crash --vm gp" in out


def test_status_publishes_both_axes_in_json(cache, monkeypatch, capsys):
    """`list` carried both fields and `status` carried neither."""
    inst = _vm_with_log(cache, "gp", TERMINAL_PANIC)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    cli.main(["--format", "json", "status", "--vm", "gp"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "running"
    assert payload["guest"] == "panicked"


# ---------------------------------------------------------------------------
# Axis 4, kill vs status. `status` tells the reader to pull the report BEFORE
# reaping; `kill` then deleted it without a word. Both commands look at the
# same guest axis, so `kill` must keep what `status` just promised was there.
# ---------------------------------------------------------------------------


def _fake_kill(monkeypatch):
    """Terminate nothing; do the same cleanup `_kill_vm` does."""
    calls = []

    def kill(inst, force=False, clean=True):
        calls.append(clean)
        if clean:
            instance_mod.remove_instance(inst.vm_id)

    monkeypatch.setattr(lifecycle, "_kill_vm", kill)
    return calls


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("body, guest", [
    (TERMINAL_PANIC, "panicked"),
    (SURVIVED_OOPS, "crashed"),
])
def test_kill_keeps_the_report_status_told_the_reader_to_pull(
    body, guest, output_format, cache, monkeypatch, capsys
):
    inst = _vm_with_log(cache, "ev", body)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    calls = _fake_kill(monkeypatch)

    cli.main(["--format", "json", "status", "--vm", "ev"])
    assert json.loads(capsys.readouterr().out)["guest"] == guest

    rc = cli.main(["--format", output_format, "kill", "--vm", "ev"])
    out = capsys.readouterr().out

    assert rc == 0
    assert calls == [False]
    assert Path(inst.serial_log).exists()
    if output_format == "json":
        payload = json.loads(out)
        assert payload["guest"] == guest
        assert payload["cleaned"] is False
        assert payload["logs_preserved"] is True
        assert payload["serial_log"] == inst.serial_log
    else:
        assert "Crash report preserved: qmu crash --vm ev" in out
        assert "qmu prune --vm ev" in out


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_kill_of_a_healthy_guest_still_cleans_and_returns_no_dead_path(
    output_format, cache, monkeypatch, capsys
):
    inst = _vm_with_log(cache, "hv", "[ 0.0] Linux version 6.12.0\n")
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    calls = _fake_kill(monkeypatch)

    rc = cli.main(["--format", output_format, "kill", "--vm", "hv"])
    out = capsys.readouterr().out

    assert rc == 0
    assert calls == [True]
    assert not Path(inst.serial_log).exists()
    if output_format == "json":
        payload = json.loads(out)
        assert payload["guest"] == "serving"
        assert payload["cleaned"] is True
        assert payload["logs_preserved"] is False
        # The path was just unlinked; handing it back would send the reader
        # to a file that is not there.
        assert payload["serial_log"] is None
        assert payload["bridge_reaped"] is False
    else:
        assert out.strip() == "VM 'hv' stopped."


def test_kill_no_clean_on_a_panicked_guest_names_the_report(
    cache, monkeypatch, capsys
):
    """--no-clean and evidence preservation must not contradict each other."""
    inst = _vm_with_log(cache, "nc", TERMINAL_PANIC)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    _fake_kill(monkeypatch)

    cli.main(["--format", "json", "kill", "--vm", "nc", "--no-clean"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["cleaned"] is False
    assert payload["logs_preserved"] is True
    assert payload["serial_log"] == inst.serial_log
    assert Path(inst.serial_log).exists()


def test_orphan_guest_state_can_reach_serving(cache, monkeypatch):
    """An orphan's QMP socket sits at a derivable path; don't give up on it."""
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    (idir / "orphsrv.qmp.sock").write_text("")
    serial = idir / "orphsrv.serial.log"
    serial.write_text("[ 0.0] Linux version 6.12.0\n")
    inst = VMInstance(
        vm_id="orphsrv", pid=0, qmp_socket="", ssh_port=None, ssh_key=None,
        gdb_port=None, serial_log=str(serial), kernel="", rootfs=None,
        memory="", cpus=0, cmdline="", profile="",
        started_at="2026-08-17T00:00:00Z", harness=False,
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


# ---------------------------------------------------------------------------
# The guest epoch does not advance across a guest-initiated reboot.
#
# `guest_epoch_serial_offset` only moves when qmu observes a QMP RESET, which
# needs a live connection at the instant it fires. A reboot between two
# commands (panic=1, kexec, a harness calling reboot, a watchdog) is invisible,
# so a previous-boot panic would label a healthy guest as gone — and the label
# instructs a destructive action. The log holds the ground truth regardless.
# ---------------------------------------------------------------------------


REBOOTED_HEALTHY = (
    "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
    "[ 1.5] FIRST BOOT: triggering\n"
    "[ 1.6] Kernel panic - not syncing: Fatal exception\n"
    "[ 1.6] ---[ end Kernel panic - not syncing: Fatal exception ]---\n"
    "[ 1.7] Rebooting in 1 seconds..\n"
    "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
    "[ 1.4] HEALTHY_NOW\n"
)


def test_panic_before_a_reboot_does_not_mark_the_new_guest_dead(cache, monkeypatch):
    inst = _vm_with_log(cache, "reb", REBOOTED_HEALTHY)
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


def test_a_panic_after_the_last_boot_still_counts(cache, monkeypatch):
    """The scoping must not swallow a real panic in the current boot."""
    inst = _vm_with_log(
        cache, "dead2",
        REBOOTED_HEALTHY
        + "[ 2.0] Kernel panic - not syncing: Fatal exception\n"
        "[ 2.0] ---[ end Kernel panic - not syncing: Fatal exception ]---\n",
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "panicked"


def test_a_survived_oops_before_a_reboot_is_also_scoped_out(cache, monkeypatch):
    inst = _vm_with_log(
        cache, "reb2",
        "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
        + SURVIVED_OOPS
        + "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
        "[ 1.4] HEALTHY_NOW\n",
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


def test_single_boot_logs_are_unaffected(cache, monkeypatch):
    """The common case must not regress: one banner, one panic, still dead."""
    inst = _vm_with_log(
        cache, "one",
        "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
        + TERMINAL_PANIC,
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "panicked"


def test_a_log_with_no_banner_at_all_still_classifies(cache, monkeypatch):
    """Harness logs may start mid-stream; absence of a banner must not hide a panic."""
    inst = _vm_with_log(cache, "nobanner", TERMINAL_PANIC)
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "panicked"


def test_reachable_guest_is_never_labelled_panicked(cache, monkeypatch, capsys):
    """The free assertion: ssh_ready=True with guest=panicked is self-contradictory.

    Cheap to detect and it fired on the reboot fixture, so it is worth pinning
    rather than trusting the individual branches.
    """
    inst = _vm_with_log(cache, "reb3", REBOOTED_HEALTHY)
    inst = __import__("dataclasses").replace(inst, ssh_port=10022, harness=False)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    class ReadySSH:
        def is_ready(self):
            return True

    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: ReadySSH())

    cli.main(["--format", "json", "list"])
    entry = json.loads(capsys.readouterr().out)["vms"][0]

    assert not (entry["ssh_ready"] and entry["guest"] == "panicked")


# ---------------------------------------------------------------------------
# `list` cost. One serial ssh handshake per running VM made a ten-VM host
# take 15–60 s per call. The probes run concurrently and are skipped where
# the guest axis already fixes the answer; the OUTPUT for the same facts must
# not change — only the time it takes to produce it.
# ---------------------------------------------------------------------------


def _ssh_capable(inst, port):
    return __import__("dataclasses").replace(inst, ssh_port=port, harness=False)


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("body, qmp_running, guest", [
    (TERMINAL_PANIC, True, "panicked"),
    ("[ 0.0] Linux version 6.12.0\n", False, "paused"),
])
def test_list_does_not_probe_ssh_on_a_guest_that_cannot_answer(
    body, qmp_running, guest, output_format, cache, monkeypatch, capsys
):
    inst = _ssh_capable(_vm_with_log(cache, "np", body), 10022)
    _qmp(monkeypatch, qmp_running)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: pytest.fail(f"probed sshd on a {guest} guest"),
    )

    cli.main(["--format", output_format, "list"])
    out = capsys.readouterr().out

    if output_format == "json":
        entry = json.loads(out)["vms"][0]
        assert entry["guest"] == guest
        assert entry["ssh_ready"] is False
    else:
        # Byte-identical to what a timed-out probe reported before.
        assert "ssh=10022(down)" in out


def test_list_probes_running_vms_concurrently_and_keeps_their_order(
    cache, monkeypatch, capsys
):
    vms = [
        _ssh_capable(_vm_with_log(cache, f"c{i}", "[ 0.0] Linux version 6.12.0\n"), 10030 + i)
        for i in range(4)
    ]
    _qmp(monkeypatch, True)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: list(vms))
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)

    class SlowSSH:
        def __init__(self, port):
            self.port = port

        def is_ready(self, timeout=2):
            time.sleep(0.3)
            return self.port % 2 == 0

    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: SlowSSH(i.ssh_port))

    started = time.monotonic()
    cli.main(["--format", "json", "list"])
    elapsed = time.monotonic() - started
    rows = [
        r for r in json.loads(capsys.readouterr().out)["vms"]
        if r["status"] == "running"
    ]

    assert elapsed < 0.3 * len(vms), "probes ran in series"
    assert [r["vm_id"] for r in rows] == [v.vm_id for v in vms]
    assert [r["ssh_ready"] for r in rows] == [True, False, True, False]

    cli.main(["list"])
    text = capsys.readouterr().out
    assert "ssh=10030(ok)" in text and "ssh=10031(down)" in text


def test_list_never_presents_a_dead_pid_as_live(cache, monkeypatch, capsys):
    """A stopped record keeps the pid its process had; `list` showed it as
    if it were still a process to signal."""
    inst = _vm_with_log(cache, "dead", "boot\n")
    instance_mod.save_instance(inst)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [])
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    cli.main(["--format", "json", "list"])
    entry = [v for v in json.loads(capsys.readouterr().out)["vms"] if v["vm_id"] == "dead"][0]

    assert entry["status"] == "stopped"
    assert entry["pid"] is None


def test_profile_override_is_machine_readable_wherever_text_says_so(
    cache, monkeypatch, capsys
):
    """Axis 3. `status` text printed "(NOT applied — cmdline was overridden)"
    while every JSON row still carried the bare profile name."""
    inst = _vm_with_log(cache, "ov", "[ 0.0] Linux version 6.12.0\n")
    inst = __import__("dataclasses").replace(inst, cmdline_override=True, kvm=False)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    cli.main(["status", "--vm", "ov"])
    text = capsys.readouterr().out
    cli.main(["--format", "json", "status", "--vm", "ov"])
    status = json.loads(capsys.readouterr().out)
    cli.main(["--format", "json", "list"])
    row = json.loads(capsys.readouterr().out)["vms"][0]

    assert "NOT applied" in text
    assert status["profile_applied"] is False
    assert row["profile_applied"] is False
    # The facts an agent otherwise had to read from the instance file.
    assert status["kvm"] is False and row["kvm"] is False
    assert "Accel:     tcg" in text
    assert status["qmp_socket"] == inst.qmp_socket
    assert status["qemu_log"].endswith("ov.qemu.log")
    assert status["arch"] == row["arch"]


def test_a_forged_boot_banner_cannot_hide_a_crash(cache, monkeypatch):
    """The banner must be a printk, not anything the guest can echo.

    A guest that writes a banner-shaped line to the console after a survived
    crash would otherwise scope that crash out of the label — `echo` or
    `cat /proc/version` to the console does it without trying. The real banner
    carries a printk timestamp; those userspace echoes cannot. (A `dmesg` replay
    does reproduce the timestamp; that residual case is accepted and surfaced
    through `wait --pattern`'s `scan_scope`, not hidden.)
    """
    inst = _vm_with_log(
        cache, "forged",
        "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
        + SURVIVED_OOPS
        + "Linux version 7.1.0-rc5 (fake@fake) (gcc 13.3.0) #15 SMP\n",
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "crashed"


def test_a_quoted_banner_mid_line_does_not_count_as_a_boot(cache, monkeypatch):
    inst = _vm_with_log(
        cache, "quoted",
        "[ 0.0] Linux version 7.1.0-rc5 (builder@host) (gcc 13.3.0) #15 SMP\n"
        + SURVIVED_OOPS
        + "[ 9.0] harness: saw '[    0.000000] Linux version 7.1.0-rc5 (b@h) (gcc)' in dmesg\n",
    )
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "crashed"


def test_a_real_second_boot_still_scopes(cache, monkeypatch):
    """The hardening must not break the fix it protects."""
    inst = _vm_with_log(cache, "realreboot", REBOOTED_HEALTHY)
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


# ---------------------------------------------------------------------------
# Cache states. Three commands report on build residue -- `cache du`,
# `cache ls` and `prune --build-residue` -- so the matrix gains rows for the
# states they can disagree about. A fourth (`unmanaged subtree exists`) crosses
# every prune branch plus `doctor`.
# ---------------------------------------------------------------------------


def _residue_tree(cache, name="linux-7.0", *, files=3, age_seconds=None):
    """Build a post-build source tree. age_seconds backdates every mtime so the
    tree lands in `eligible` rather than `held_back` at the default cutoff."""
    src = cache / "kernels" / "src" / name
    (src / "kernel").mkdir(parents=True)
    (src / "Makefile").write_text("# kbuild\n")
    (src / "vmlinux").write_bytes(b"\x7fELF")
    (src / "System.map").write_text("ffffffff81000000 T _text\n")
    for i in range(files):
        (src / "kernel" / f"f{i}.o").write_bytes(b"o" * 512)
    if age_seconds is not None:
        stamp = time.time() - age_seconds
        for path in sorted(src.rglob("*"), reverse=True):
            os.utime(path, (stamp, stamp))
        os.utime(src, (stamp, stamp))
    return src


# Old enough to be eligible at _RESIDUE_AGE, so the rows below exercise the
# eligible path rather than passing vacuously on an all-held-back cache.
_OLD = 7200


_RESIDUE_AGE = "600"
_BUCKETS = ("total", "eligible", "held_back", "refused")


def test_cache_du_and_prune_agree_bucket_for_bucket(cache, capsys):
    """Axis 4: subcommand vs subcommand. Two commands, one dataset."""
    _residue_tree(cache, age_seconds=_OLD)

    cli.main(["--format", "json", "cache", "du", "--older-than", _RESIDUE_AGE])
    du = json.loads(capsys.readouterr().out)["build_residue"]

    cli.main(["--format", "json", "prune", "--build-residue",
              "--older-than", _RESIDUE_AGE, "--dry-run"])
    pr = json.loads(capsys.readouterr().out)["build_residue"]

    for bucket in _BUCKETS:
        assert du[bucket]["bytes"] == pr[bucket]["bytes"], bucket
        assert sorted(du[bucket]["groups"]) == sorted(pr[bucket]["groups"]), bucket


def test_residue_preview_and_real_agree(cache, capsys):
    """Axis 1: preview vs real. Classification -- not deletion -- decides."""
    _residue_tree(cache, age_seconds=_OLD)

    cli.main(["--format", "json", "prune", "--build-residue",
              "--older-than", _RESIDUE_AGE, "--dry-run"])
    preview = json.loads(capsys.readouterr().out)

    cli.main(["--format", "json", "prune", "--build-residue",
              "--older-than", _RESIDUE_AGE])
    real = json.loads(capsys.readouterr().out)

    assert {i["path"] for i in preview["build_residue"]["would_remove"]} == {
        i["path"] for i in real["build_residue"]["removed"]
    }
    assert preview["dry_run"] is True and real["dry_run"] is False


def test_held_back_by_age_appears_in_both_text_and_json(cache, capsys):
    """Axis 3. A freshly-touched tree is held back, and says so in both formats.

    Named for the age gate, not for "in use by a build": there is no build
    detection, and a row named for one would be read as proof it exists.
    """
    _residue_tree(cache)

    cli.main(["prune", "--build-residue", "--dry-run"])
    text = capsys.readouterr().out
    cli.main(["--format", "json", "prune", "--build-residue", "--dry-run"])
    data = json.loads(capsys.readouterr().out)

    assert "Held back" in text
    assert "linux-7.0" in text
    assert data["build_residue"]["held_back"]["groups"] == ["linux-7.0"]
    assert data["build_residue"]["eligible"]["files"] == 0
    # This mode must never prescribe the flag that disables its only guard.
    assert "--older-than 0" not in text


def test_empty_and_populated_residue_are_equally_disclosing(cache, capsys):
    """Axis 2: branch vs branch. 'Nothing eligible' must not read as 'clean'."""
    cli.main(["--format", "json", "prune", "--build-residue", "--dry-run"])
    empty = json.loads(capsys.readouterr().out)

    _residue_tree(cache, age_seconds=_OLD)
    cli.main(["--format", "json", "prune", "--build-residue", "--dry-run"])
    populated = json.loads(capsys.readouterr().out)

    for payload in (empty, populated):
        assert set(_BUCKETS) <= set(payload["build_residue"])
        assert "unmanaged_cache" in payload
        assert payload["dry_run"] is True


@pytest.mark.parametrize("dry_run", [True, False])
def test_residue_prune_refuses_a_root_that_is_not_a_qmu_cache(
    dry_run, cache, monkeypatch, capsys
):
    """#49: QMU_CACHE_DIR is taken on faith, so a typo pointing at $HOME must
    be refused before classification — in preview and real run alike. An
    absent or empty root is NOT that typo (nothing under it to reclaim)."""
    (cache / "Documents").mkdir()
    (cache / "notes.o").write_bytes(b"not residue")

    rc = cli.main(
        ["--format", "json", "prune", "--build-residue"]
        + (["--dry-run"] if dry_run else [])
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["ok"] is False
    assert str(cache) in payload["error"]
    assert "QMU_CACHE_DIR" in payload["error"]
    assert (cache / "notes.o").exists()

    monkeypatch.setenv("QMU_CACHE_DIR", str(cache / "fresh-cache"))
    assert cli.main(["prune", "--build-residue", "--dry-run"]) == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["prune", "--all", "--dry-run"],
        ["prune", "--all"],
        ["prune", "--runtime", "--older-than", "0"],
        ["prune", "--orphans", "--dry-run"],
        ["prune", "--build-residue", "--dry-run"],
    ],
)
def test_every_prune_branch_discloses_the_unmanaged_cache(argv, cache, monkeypatch, capsys):
    """Axis 2 + axis 3. prune reaches instances/ and runtime_root() only, so
    every branch must say what it did NOT cover -- machine-readably.

    Gating this on --all alone is the regression shape already recorded in
    lifecycle.py ('Round 5 fixed only the ... branch').
    """
    (cache / "kernels").mkdir(exist_ok=True)
    (cache / "targets").mkdir(exist_ok=True)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])

    cli.main(["--format", "json", *argv])
    data = json.loads(capsys.readouterr().out)

    assert "unmanaged_cache" in data, argv
    assert data["unmanaged_cache"]["subtrees"] == ["kernels", "targets"]
    assert data["unmanaged_cache"]["hint"] == "qmu cache du"


def test_doctor_reports_the_unmanaged_cache_without_going_unhealthy(cache, capsys):
    """doctor returns 1 exactly when a row is `fail`. An unmanaged cache is
    informational: a warn-or-worse here would exit 1 on every machine that
    ever built a kernel, with no way to clear it -- breaking the health signal
    SKILL.md teaches."""
    (cache / "kernels").mkdir(exist_ok=True)

    cli.main(["--format", "json", "doctor"])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}

    assert "cache" in checks
    assert checks["cache"]["status"] == "info"
    assert "qmu cache du" in checks["cache"]["detail"]


# ---------------------------------------------------------------------------
# doctor rows and ConfigError. Two surfaces each: the text glyph vs the JSON
# `status`/`blocking`, and the text error lines vs the JSON `errors[]`.
# `[!]` once covered both MISSING and "not configured" while `[+]` covered ok
# and info; the JSON vocabulary was `ok/info/warn/MISSING/not configured`.
# ---------------------------------------------------------------------------


_DOCTOR_GLYPH = {"ok": "+", "fail": "!", "warn": "~", "info": "i"}


def test_doctor_text_glyph_agrees_with_json_status_and_exit_code(
    cache, monkeypatch, capsys, tmp_path
):
    """Axis 3: text vs JSON. Every row's glyph is a function of its JSON
    status; `blocking` is exactly `status == fail`; the exit code is exactly
    "any row blocks", in both formats."""
    # A starter file whose kernel/rootfs/key are still placeholders: one of
    # each verdict appears (fail rows, warn rows, info rows, ok rows).
    monkeypatch.chdir(tmp_path)
    assert cli.main(["config", "init"]) == 0
    capsys.readouterr()

    rc_json = cli.main(["--format", "json", "doctor"])
    payload = json.loads(capsys.readouterr().out)
    rc_text = cli.main(["doctor"])
    text = capsys.readouterr().out

    assert rc_json == rc_text == 1
    assert payload["ok"] is False
    statuses = {c["status"] for c in payload["checks"]}
    assert statuses <= set(_DOCTOR_GLYPH)
    assert {"ok", "fail", "warn"} <= statuses or {"ok", "fail", "info"} <= statuses
    for c in payload["checks"]:
        assert c["blocking"] is (c["status"] == "fail"), c["check"]
        assert f"  [{_DOCTOR_GLYPH[c['status']]}] {c['check']}: " in text, c["check"]
    assert payload["ok"] is (not any(c["blocking"] for c in payload["checks"]))
    assert "[!] kernel: ./bzImage (CHANGE ME placeholder; not found)" in text


def test_config_error_text_and_json_report_the_same_problems(
    cache, monkeypatch, capsys, tmp_path
):
    """Axis 3: text vs JSON. The text error prints one `Invalid config` line
    per problem; the JSON envelope lists the same problems in `errors[]`, in
    the same order, and the leading line is the first entry."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text(
        'append = "nokaslr"\n[machine]\nmemroy = "8G"\ncpus = "two"\n'
    )

    assert cli.main(["config", "show"]) == 1
    err = capsys.readouterr().err
    assert cli.main(["--format", "json", "config", "show"]) == 1
    payload = json.loads(capsys.readouterr().out)

    prefix = f"Invalid config {(tmp_path / 'qmu.toml').resolve()}: "
    text_problems = [
        line.removeprefix("[qmu] Error: ").removeprefix(prefix)
        for line in err.splitlines() if "Invalid config" in line
    ]
    json_problems = [
        f"key '{e['key']}': {e['message']}" + (f"; {e['hint']}" if e["hint"] else "")
        for e in payload["errors"]
    ]
    assert text_problems == json_problems
    assert [e["key"] for e in payload["errors"]] == ["append", "machine.memroy", "machine.cpus"]
    assert payload["key"] == payload["errors"][0]["key"]
    assert payload["error"].splitlines()[0].endswith(json_problems[0])


def test_cache_ls_never_presents_a_truncated_list_as_complete(cache, capsys):
    """Axis 2. A partial result must be as honest as an empty one."""
    for n in range(3):
        _residue_tree(cache, f"linux-7.{n}", age_seconds=_OLD)

    cli.main(["--format", "json", "cache", "ls", "--older-than", _RESIDUE_AGE,
              "--top", "1"])
    data = json.loads(capsys.readouterr().out)["build_residue"]["eligible"]

    assert data["shown"] == 1
    assert data["truncated"]["groups"] == 2
    shown = sum(g["bytes"] for g in data["groups"])
    assert shown + data["truncated"]["bytes"] == data["bytes"]


# ---------------------------------------------------------------------------
# Axis 4 again: subcommand vs subcommand, for the SSH transport-loss state.
#
# "The guest died under my command" is an observable state, and four
# subcommands report on it. Three agreed; `dmesg` carried its own ending
# (`return 0 if rc == 0 else 1`) and reported a panicked guest as exit 1 with
# `[dmesg failed, exit 255]` — the "guest command non-zero" class an agent
# reads as "dmesg failed INSIDE the guest". Same defect shape as every other
# row here: a fix landed on one path and its siblings kept contradicting it.
# ---------------------------------------------------------------------------


_LOST_PANIC = (
    "[   12.501] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[   12.502] Kernel panic - not syncing: Fatal exception\n"
    "[   12.503] RIP: 0010:sysrq_handle_crash+0x16/0x20\n"
)


class _TransportLostSSH:
    """One transport, dropped the way each command observes it dropping.

    `ssh.run` returns 255 (often with only a banner-exchange timeout on
    stderr); `scp` raises with rc 255 plus a transport marker. Both are the
    ambiguous signal the liveness probe resolves, so `is_ready` stays False.
    """

    def __init__(self, serial_path, append):
        self._serial_path = serial_path
        self._append = append

    def _drop(self):
        if self._append:
            with open(self._serial_path, "a") as stream:
                stream.write(self._append)
            self._append = ""

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self._drop()
        return 255, "", "Connection timed out during banner exchange"

    def push(self, local, remote):
        self._drop()
        raise SSHError(
            "SCP push failed: mux failed: Broken pipe",
            returncode=255,
            stderr="mux failed: Broken pipe",
        )

    def pull(self, remote, local):
        self.push(local, remote)

    def is_ready(self, timeout=2):
        return False


_LOST_ARGV = {
    "exec": ["exec", "--vm", VM, "trigger"],
    "dmesg": ["dmesg", "--vm", VM, "--tail", "5"],
    "push": ["push", "--vm", VM, "/tmp/payload.bin", "/root/payload.bin"],
    "pull": ["pull", "--vm", VM, "/root/payload.bin", "/tmp/payload.bin"],
}


def _agreement_view(rc, payload):
    """The facts a caller branches on, independent of per-command wording."""
    hint = payload.get("hint", "")
    return {
        "rc": rc,
        "ok": payload.get("ok"),
        "ssh_error": payload.get("ssh_error"),
        "crash_detected": payload.get("crash_detected"),
        "crash_present": payload.get("crash") is not None,
        "names_qmu_crash": "qmu crash" in hint,
        "names_qmu_log": "qmu log --tail 100" in hint,
    }


def _ssh_capable_instance(cache, vm_id=VM):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    return VMInstance(
        vm_id=vm_id, pid=4242, qmp_socket=str(idir / f"{vm_id}.qmp.sock"),
        ssh_port=10099, ssh_key=str(idir / f"{vm_id}.key"), gdb_port=None,
        serial_log=str(idir / f"{vm_id}.serial.log"), kernel="/boot/bzImage",
        rootfs="/var/rootfs.img", memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-09-02T00:00:00Z", harness=False,
    )


@pytest.mark.parametrize("panicked", [True, False])
def test_every_ssh_command_agrees_on_a_lost_transport(
    panicked, cache, monkeypatch, capsys
):
    """exec / dmesg / push / pull must classify one condition identically.

    A fresh corroborating serial report is the only thing that promotes the
    transport-layer code (4) to the kernel-crash code (3) callers branch on.
    """
    inst = _ssh_capable_instance(cache)
    decoy = _decoy_running(monkeypatch)
    assert decoy.vm_id != VM, "the decoy must not be the subject"
    # Subject AND decoy are both running: the decoy is what keeps a handler
    # from answering out of "the sole running VM" (this file's own rule), and
    # the subject has to be running or `exec` refuses before any SSH happens.
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest_mod.time, "sleep", lambda _: None)

    views = {}
    for command, argv in _LOST_ARGV.items():
        # A second running VM stays in the roster for every cell: with only one
        # instance a handler can answer from "the sole running VM" and never
        # reach the branch the real CLI takes on a shared box.
        monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
        with open(inst.serial_log, "w") as stream:
            stream.write("boot ok\n")
        monkeypatch.setattr(
            guest_mod, "_make_ssh",
            lambda selected: _TransportLostSSH(
                inst.serial_log, _LOST_PANIC if panicked else ""
            ),
        )

        rc = cli.main(["--format", "json", *argv])
        views[command] = _agreement_view(rc, json.loads(capsys.readouterr().out))

    expected = {
        "rc": 3 if panicked else 4,
        "ok": False,
        "ssh_error": True,
        "crash_detected": panicked,
        "crash_present": panicked,
        "names_qmu_crash": panicked,
        "names_qmu_log": not panicked,
    }
    for command, view in views.items():
        assert view == expected, f"`qmu {command}` disagrees: {view}"


class _ServingSSH:
    """A guest that answers: fixed exec result, transfers succeed."""

    def __init__(self, rc=0, stdout="", stderr=""):
        self._result = (rc, stdout, stderr)

    def run(self, command, timeout=30.0, check=False, **kwargs):
        return self._result

    def push(self, local, remote):
        pass

    def pull(self, remote, local):
        pass

    def is_ready(self, timeout=2):
        return True


def _serving_subject(cache, monkeypatch, ssh):
    inst = _ssh_capable_instance(cache)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest_mod, "_make_ssh", lambda selected: ssh)
    monkeypatch.setattr(guest_mod.time, "sleep", lambda _: None)
    with open(inst.serial_log, "w") as stream:
        stream.write("boot ok\n")
    return inst


@pytest.mark.parametrize("lost", [False, True])
def test_every_ssh_command_envelope_names_the_vm(lost, cache, monkeypatch, capsys):
    """Axis 4 (subcommand vs subcommand) × axis 2 (branch vs branch): a caller
    correlating envelopes with VMs reads `vm_id` on every guest-command
    envelope, success or lost transport. `exec` carried it only on some
    paths, `dmesg`/`push`/`pull` on none, and `crash` spelled it `vm`."""
    inst = _ssh_capable_instance(cache)
    if lost:
        ssh = _TransportLostSSH(inst.serial_log, "")
    else:
        ssh = _ServingSSH(0, "ok\n", "")
    _serving_subject(cache, monkeypatch, ssh)
    (Path("/tmp") / "payload.bin").write_bytes(b"x")

    for command, argv in _LOST_ARGV.items():
        cli.main(["--format", "json", *argv])
        payload = json.loads(capsys.readouterr().out)
        assert payload.get("vm_id") == VM, f"`qmu {command}` envelope: {sorted(payload)}"


@pytest.mark.parametrize("command", ["exec", "dmesg"])
def test_text_stdout_is_the_guest_stdout_json_carries_the_rest(
    command, cache, monkeypatch, capsys
):
    """Axis 3 (text vs JSON): what JSON reports as `stdout`/`text` is exactly
    what text mode puts on stdout; guest stderr and the exit trailer are on
    stderr in text mode and in their own keys in JSON. Measured live before
    this row: `qmu exec 'echo out; echo err >&2; exit 5' > o 2> e` left
    `[stderr] err` and `[exit code: 5]` in `o` and `e` empty."""
    _serving_subject(cache, monkeypatch, _ServingSSH(5, "line 1\nline 2\n", "err\n"))

    rc_json = cli.main(["--format", "json", *_LOST_ARGV[command]])
    payload = json.loads(capsys.readouterr().out)
    rc_text = cli.main(["--format", "text", *_LOST_ARGV[command]])
    captured = capsys.readouterr()

    assert rc_json == rc_text == 1
    stdout_key = "stdout" if command == "exec" else "text"
    assert captured.out == payload[stdout_key] == "line 1\nline 2\n"
    assert payload["stderr"] == "err\n"
    assert "err" in captured.err
    assert "5" in captured.err  # the exit trailer, per-command wording aside
    assert "[exit code" not in captured.out and "[dmesg failed" not in captured.out


# ---------------------------------------------------------------------------
# A guest `status`/`list` call PANICKED must be refused by every SSH-facing
# command, in both formats, before any SSH attempt — and a panic the guest
# already rebooted past must NOT be. Measured live before this row: `exec`
# spent 15–45 s in ssh keepalive and said "No fresh crash detected" (exit 4)
# while `status` said panicked and `crash` printed the report.
# ---------------------------------------------------------------------------


_PANICKED_ARGV = {
    **_LOST_ARGV,
    "compile": ["compile", "--vm", VM, "/tmp/x.c"],
}


def _qmp_running_for_cliutil(monkeypatch):
    """Both authorities see a running vCPU: lifecycle's copy for `status`, the
    SSH preflight's copy for the guest commands."""
    from qmu import _cliutil

    class FakeQMP:
        def execute(self, cmd):
            return {"running": True, "status": "running"}

    class Ctx:
        def __enter__(self): return FakeQMP()
        def __exit__(self, *a): return False

    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda inst: Ctx())
    monkeypatch.setattr(_cliutil, "_qmp_ctx", lambda inst: Ctx())


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_every_ssh_command_agrees_with_status_that_the_guest_panicked(
    fmt, cache, monkeypatch, capsys
):
    inst = _ssh_capable_instance(cache)
    with open(inst.serial_log, "w") as stream:
        stream.write("[ 0.0] Linux version 6.12.0 (x) #1\n" + TERMINAL_PANIC)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    _qmp_running_for_cliutil(monkeypatch)
    monkeypatch.setattr(
        guest_mod, "_make_ssh",
        lambda selected: (_ for _ in ()).throw(AssertionError("SSH attempted")),
    )

    cli.main(["--format", "json", "status", "--vm", VM])
    assert json.loads(capsys.readouterr().out)["guest"] == "panicked"

    for command, argv in _PANICKED_ARGV.items():
        rc = cli.main(["--format", fmt, *argv])
        captured = capsys.readouterr()
        assert rc == 1, f"`qmu {command}` rc={rc}"
        if fmt == "json":
            payload = json.loads(captured.out)
            view = {
                "ok": payload["ok"],
                "guest_state": payload["guest_state"],
                "ssh_error": payload["ssh_error"],
                "crash_detected": payload["crash_detected"],
                "names_qmu_crash": f"qmu crash --vm {VM}" in payload["hint"],
            }
            assert view == {
                "ok": False,
                "guest_state": "panicked",
                "ssh_error": False,
                "crash_detected": False,
                "names_qmu_crash": True,
            }, f"`qmu {command}` disagrees: {view}"
        else:
            # Refusals are prose: stderr with the documented prefix, never
            # stdout, so `eval "$(qmu kbase ...)"` and pipes stay clean.
            assert captured.out == "", f"`qmu {command}` wrote a refusal to stdout"
            assert captured.err.startswith("[qmu] Error:"), f"`qmu {command}`"
            assert "PANICKED" in captured.err, f"`qmu {command}`"
            assert f"qmu crash --vm {VM}" in captured.err, f"`qmu {command}`"


def test_ssh_commands_and_status_agree_a_rebooted_guest_is_serving(
    cache, monkeypatch, capsys
):
    """Scope is the current boot on BOTH paths: a panic the guest already
    rebooted past (`panic=N`) refuses nothing and `status` says serving."""
    inst = _ssh_capable_instance(cache)
    with open(inst.serial_log, "w") as stream:
        stream.write(
            "[ 0.0] Linux version 6.12.0 (x) #1\n" + TERMINAL_PANIC
            + "[ 1.7] Rebooting in 3 seconds..\n"
            "[ 0.0] Linux version 6.12.0 (x) #1\n"
            "localhost login: \n"
        )
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    _qmp_running_for_cliutil(monkeypatch)

    class ServingSSH:
        def run(self, command, timeout=30.0, check=False, **kwargs):
            return 0, "ok\n", ""

        def is_ready(self, timeout=2):
            return True

    monkeypatch.setattr(guest_mod, "_make_ssh", lambda selected: ServingSSH())
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda selected: ServingSSH())

    cli.main(["--format", "json", "status", "--vm", VM])
    assert json.loads(capsys.readouterr().out)["guest"] == "serving"

    for command in ("exec", "dmesg"):
        rc = cli.main(["--format", "json", *_LOST_ARGV[command]])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0, f"`qmu {command}` refused a serving guest: {payload}"
        assert payload["ok"] is True


# ---------------------------------------------------------------------------
# A networked-looking VM with NO SSH endpoint: `launch --no-net` without
# `--ssh-port`. qmu emits `-nic none` and binds nothing, so there is no port
# to record — it used to record an auto-allocated one anyway, `status` said
# `ssh: ready` once another VM was handed that port, and `exec --vm A` ran
# the command on VM B (exit 0, wrong kernel). Every command that reports on
# or uses SSH must agree: no endpoint, no probe, refuse before any SSH
# attempt, and say why (`--ssh-port`), in both formats.
# ---------------------------------------------------------------------------


_NO_ENDPOINT_ARGV = {
    **_PANICKED_ARGV,
    "kbase": ["kbase", "--vm", VM, "--symbols", "/tmp/vmlinux"],
}


def _no_net_instance(cache, vm_id=VM):
    """What `launch --no-net` (no --ssh-port) now records: not harness, a key,
    and ssh_port None."""
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text("[ 0.0] Linux version 6.12.0 (x) #1\n")
    return VMInstance(
        vm_id=vm_id, pid=4242, qmp_socket=str(idir / f"{vm_id}.qmp.sock"),
        ssh_port=None, ssh_key=str(idir / f"{vm_id}.key"), gdb_port=None,
        serial_log=str(serial), kernel="/boot/bzImage",
        rootfs="/var/rootfs.img", memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-10-16T00:00:00Z", harness=False,
    )


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_every_ssh_command_and_status_agree_a_no_net_vm_has_no_endpoint(
    fmt, cache, monkeypatch, capsys
):
    inst = _no_net_instance(cache)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    from qmu.commands import qmp_cmds as qmp_cmds_mod
    monkeypatch.setattr(qmp_cmds_mod, "choose_instance", lambda vm=None: inst)
    _qmp_running_for_cliutil(monkeypatch)
    # No command may so much as build an SSH client: there is no port to probe,
    # and a bare TCP probe is exactly how the wrong VM answered before.
    for mod in (lifecycle, guest_mod, qmp_cmds_mod):
        monkeypatch.setattr(
            mod, "_make_ssh",
            lambda selected: (_ for _ in ()).throw(AssertionError("SSH attempted")),
            raising=False,
        )

    rc = cli.main(["--format", fmt, "status", "--vm", VM])
    captured = capsys.readouterr()
    assert rc == 0
    if fmt == "json":
        status = json.loads(captured.out)
        assert status["ssh_port"] is None
        assert status["harness"] is False
        assert status["ssh"] not in ("ready", "down")
    else:
        assert "ready" not in captured.out

    rc = cli.main(["--format", fmt, "list"])
    captured = capsys.readouterr()
    assert rc == 0
    if fmt == "json":
        row = next(r for r in json.loads(captured.out)["vms"] if r["vm_id"] == VM)
        assert row["ssh_port"] is None
        assert row["ssh_ready"] is None
        assert row["harness"] is False
    else:
        line = next(l for l in captured.out.splitlines() if VM in l)
        assert "ssh=" not in line or "ssh=none" in line

    for command, argv in _NO_ENDPOINT_ARGV.items():
        rc = cli.main(["--format", fmt, *argv])
        captured = capsys.readouterr()
        assert rc == 1, f"`qmu {command}` rc={rc}"
        if fmt == "json":
            payload = json.loads(captured.out)
            assert payload["ok"] is False, f"`qmu {command}`"
            assert payload["error_type"] == "QMUError", f"`qmu {command}`"
            message = payload["error"]
        else:
            assert captured.out == "", f"`qmu {command}` wrote a refusal to stdout"
            assert captured.err.startswith("[qmu] Error:"), f"`qmu {command}`"
            message = captured.err
        assert "--no-net" in message and "--ssh-port" in message, f"`qmu {command}`: {message}"
        assert "harness" not in message, f"`qmu {command}` misreports --no-net as harness"


# ---------------------------------------------------------------------------
# HMP-wrapping commands. HMP reports its own failures as result TEXT, so five
# commands can each decide "did it work" differently -- and did: `snapshot
# delete <missing>` and `snapshot save 'has space'` said ok:true, `monitor
# nonsense-cmd` exited 0, while `snapshot load <missing>` exited 1 with a
# `message` instead of `error` (snapshot audit D3/D4/D8, contract #5). Axis 4
# (subcommand vs subcommand) and axis 3 (text vs JSON) in one row.
# ---------------------------------------------------------------------------


class _HmpFailingQMP:
    """Every HMP verb answers with an HMP error form; `info snapshots` is
    empty so the dedicated handlers' listing cross-checks also say "no"."""

    def __init__(self, text):
        self._text = text

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            return {"running": True, "status": "running"}
        if command == "human-monitor-command":
            return self._text
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        if command_line == "info snapshots":
            return ""
        return self._text


_HMP_FAILURE_ARGV = {
    "snapshot save": ["snapshot", "save", "x", "--vm", VM],
    "snapshot load": ["snapshot", "load", "x", "--vm", VM],
    "snapshot delete": ["snapshot", "delete", "x", "--vm", VM],
    "monitor": ["monitor", "--vm", VM, "nonsense-cmd"],
    "qmp human-monitor-command": [
        "qmp", "--vm", VM, "human-monitor-command",
        "--args", '{"command-line": "nonsense-cmd"}',
    ],
}


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_every_hmp_route_agrees_an_hmp_error_form_is_a_failure(
    cache, monkeypatch, capsys, fmt
):
    from qmu.commands import qmp_cmds

    inst = _ssh_capable_instance(cache)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    import contextlib
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: contextlib.nullcontext(_HmpFailingQMP("unknown command: 'x'\r\n")),
    )

    for command, argv in _HMP_FAILURE_ARGV.items():
        rc = cli.main(["--format", fmt, *argv])
        captured = capsys.readouterr()
        assert rc == 1, f"`qmu {command}` exit {rc}"
        if fmt == "json":
            payload = json.loads(captured.out)
            assert payload["ok"] is False, f"`qmu {command}`"
            assert "error" in payload and "error_type" in payload, f"`qmu {command}`: {payload}"
            assert "message" not in payload, f"`qmu {command}` still uses `message`"
        else:
            assert captured.out == "", f"`qmu {command}` wrote a failure to stdout"
            assert captured.err.startswith("[qmu] Error:"), f"`qmu {command}`: {captured.err}"


# ---------------------------------------------------------------------------
# The guest epoch after a qmu-ISSUED reset. `snapshot load` advanced it; the
# three raw routes to `system_reset` did not, so `wait --pattern 'login:'`
# matched the previous boot in 0.00 s after `qmu qmp system_reset` (snapshot
# audit D5). Four commands, one observable state: all must persist the same
# boundary -- the log size captured BEFORE the mutation landed.
# ---------------------------------------------------------------------------


class _MutatingQMP:
    """Every mutation succeeds; the serial log grows as a side effect, the
    way a real reset prints a new boot banner."""

    def __init__(self, serial_log):
        self._serial = serial_log

    def _grow(self):
        with open(self._serial, "a") as stream:
            stream.write("[    0.000000] Linux version 7.0.0 (reboot)\n")

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            return {"running": True, "status": "running"}
        if command in ("system_reset", "human-monitor-command"):
            self._grow()
        return "" if command == "human-monitor-command" else {}

    def execute_hmp(self, command_line, timeout=30.0):
        if command_line == "info snapshots":
            return (
                "List of snapshots present on all disks:\n"
                "ID        TAG               VM SIZE                DATE       VM CLOCK\n"
                "--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992\n"
            )
        self._grow()
        return ""


_RESET_ARGV = {
    "qmp system_reset": ["qmp", "--vm", VM, "system_reset"],
    "monitor system_reset": ["monitor", "--vm", VM, "system_reset"],
    "qmp human-monitor-command system_reset": [
        "qmp", "--vm", VM, "human-monitor-command",
        "--args", '{"command-line": "system_reset"}',
    ],
    "snapshot load": ["snapshot", "load", "clean", "--vm", VM],
    "monitor loadvm": ["monitor", "--vm", VM, "loadvm", "clean"],
}


@pytest.mark.parametrize("command", sorted(_RESET_ARGV))
def test_every_qmu_issued_reset_advances_the_guest_epoch(
    command, cache, monkeypatch, capsys
):
    from qmu.commands import qmp_cmds
    import contextlib

    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 7.0.0\nlocalhost login:\n")
    before = Path(inst.serial_log).stat().st_size
    assert inst.guest_epoch_serial_offset == 0
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: contextlib.nullcontext(_MutatingQMP(inst.serial_log)),
    )

    rc = cli.main(["--format", "json", *_RESET_ARGV[command]])
    capsys.readouterr()
    assert rc == 0, f"`qmu {command}` exit {rc}"
    saved = instance_mod.load_instance(VM)
    assert saved.guest_epoch_serial_offset == before, (
        f"`qmu {command}` persisted epoch {saved.guest_epoch_serial_offset}, "
        f"expected the pre-mutation log size {before}"
    )
    # The boundary is the PRE-mutation size: the new boot's banner must still
    # be inside the current epoch, or `wait`/`crash` would skip it.
    assert Path(inst.serial_log).stat().st_size > before


# ---------------------------------------------------------------------------
# "A debugger client is attached" is an observable state (the gdb stub serves
# one client). `qmu gdb` must refuse to spawn a second bridge and say so the
# same way in text and JSON; it used to hang 15 s, exit 4 with a raw
# TimeoutExpired repr, and leak a bridge per attempt (debug audit D4).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_gdb_refuses_an_attached_stub_identically_in_text_and_json(
    cache, monkeypatch, capsys, fmt
):
    from qmu.commands import qmp_cmds

    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 7.0.0\n")
    inst.gdb_port = 1234
    inst.gdb_bridge_pid = 4242
    inst.gdb_bridge_pid_start = "1"
    instance_mod.save_instance(inst)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds.shutil, "which", lambda name: "/usr/bin/pry")
    monkeypatch.setattr(qmp_cmds, "gdb_client_attached", lambda inst: True)
    monkeypatch.setattr(qmp_cmds, "bridge_alive", lambda inst: True)
    spawned = []
    monkeypatch.setattr(
        qmp_cmds.subprocess, "run", lambda *a, **kw: spawned.append(a) or None
    )

    rc = cli.main(["--format", fmt, "gdb", "--vm", VM])
    captured = capsys.readouterr()

    assert rc == 1
    assert spawned == []
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "QMUError"
        message = payload["error"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("[qmu] Error:")
        message = captured.err
    assert "already attached to port 1234" in message
    assert "pry bridge pid 4242" in message
    assert "pry kill --instance 4242" in message
    assert "TimeoutExpired" not in message


# ---------------------------------------------------------------------------
# Launch-time facts: text vs JSON axis. Every warning `launch` prints on
# stderr (profile override casualties, dotted-param typo, arch/cmdline lint,
# replace note) must exist in the JSON envelope's `warnings`, and the
# `no-console-output` outcome must be the same state with the same cause in
# both formats — it used to be a bare SSH timeout with an empty log.
# ---------------------------------------------------------------------------


def _launch_subject(tmp_path, monkeypatch, *, serial_text, ready):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text(
        '[boot]\nkernel = "Image"\ncmdline = "console=ttyS0 root=/dev/sda nokaslr"\n'
    )
    serial = tmp_path / f"{VM}.serial.log"
    serial.write_text(serial_text)
    inst = VMInstance(
        vm_id=VM, pid=4242, qmp_socket=str(tmp_path / "s.qmp"), ssh_port=10021,
        ssh_key=str(tmp_path / "k"), gdb_port=None, serial_log=str(serial),
        kernel="Image", rootfs=None, memory="1G", cpus=1,
        cmdline="console=ttyS0 root=/dev/sda", profile="exploit-test",
        started_at="2026-10-16T00:00:00Z",
    )

    def launch(**kwargs):
        instance_mod.save_instance(inst)
        return inst

    class SSH:
        def is_ready(self, timeout=2):
            return ready

    monkeypatch.setattr(lifecycle, "launch_vm", launch)
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: SSH())
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda _: None)
    monkeypatch.setattr(lifecycle, "NO_CONSOLE_OUTPUT_SECONDS", 0.0)
    return inst


_LAUNCH_WARNING_MARKERS = (
    "--profile exploit-test overrides",   # config cmdline displaced
    "nokaslr",                            # the named casualty
    "kasan.faul",                         # dotted-param typo
    "ttyAMA0",                            # console= lint for aarch64
    "/dev/vda",                           # root= lint for aarch64
)


def test_launch_warnings_agree_between_stderr_and_json(tmp_path, monkeypatch, capsys):
    _launch_subject(tmp_path, monkeypatch, serial_text="[0.0] Linux\n", ready=True)
    argv = [
        "launch", "--name", VM, "--arch", "aarch64", "--profile", "exploit-test",
        "--append", "kasan.faul=panic",
    ]

    rc = cli.main(["--format", "text", *argv])
    text = capsys.readouterr()
    assert rc == 0
    for marker in _LAUNCH_WARNING_MARKERS:
        assert marker in text.err, marker
    assert not text.out.lstrip().startswith("{")  # text stays text

    rc = cli.main(["--format", "json", *argv])
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    joined = "\n".join(payload["warnings"])
    for marker in _LAUNCH_WARNING_MARKERS:
        assert marker in joined, marker
    assert payload["config_sources"] == [str(tmp_path.resolve() / "qmu.toml")]
    assert payload["replaced"] is None
    # The JSON run also warned on stderr: the mirror adds, it does not move.
    for marker in _LAUNCH_WARNING_MARKERS:
        assert marker in captured.err, marker


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_no_console_output_is_one_state_in_both_formats(
    fmt, tmp_path, monkeypatch, capsys
):
    inst = _launch_subject(tmp_path, monkeypatch, serial_text="", ready=False)

    rc = cli.main([
        "--format", fmt, "launch", "--name", VM, "--arch", "aarch64",
        "--ssh-timeout", "60",
    ])
    captured = capsys.readouterr()

    assert rc == 4
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["ssh_status"] == "no-console-output"
        assert payload["error_type"] == "SSHError"
        message = payload["error"]
    else:
        assert "no-console-output" in captured.out
        assert "[qmu] Error:" in captured.err
        message = captured.err
    assert "No console output" in message
    assert "console=ttyAMA0" in message
    assert "-M/-cpu" in message
    assert f"qmu status --vm {VM}" in message
    # Retained, like the SSH-timeout sibling: never "not found" afterwards.
    assert instance_mod.load_instance(VM) is not None
    assert "timeout (VM may still be booting)" not in message


# ---------------------------------------------------------------------------
# Guest axis honesty: `serving` needs positive evidence. A vCPU that merely
# runs is not evidence — an aarch64 guest booted with the x86 cmdline runs
# forever, writes nothing, answers nobody, and was reported `serving`.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_silent_unreachable_guest_is_unknown_not_serving_everywhere(
    fmt, cache, monkeypatch, capsys
):
    """Empty console + SSH down: `status` and `list` agree on `unknown` and
    both say what was checked, in both formats."""
    inst = _ssh_capable(_vm_with_log(cache, VM, ""), 10022)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)

    class DownSSH:
        def is_ready(self, timeout=2):
            return False

    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: DownSSH())

    rc = cli.main(["--format", fmt, "status", "--vm", VM])
    status_out = capsys.readouterr().out
    assert rc == 0
    rc = cli.main(["--format", fmt, "list"])
    list_out = capsys.readouterr().out
    assert rc == 0

    if fmt == "json":
        status = json.loads(status_out)
        row = next(v for v in json.loads(list_out)["vms"] if v["vm_id"] == VM)
        assert status["guest"] == "unknown"
        assert row["guest"] == "unknown"
        assert status["ssh"] == "down"
        assert row["ssh_ready"] is False
        for detail in (status["guest_detail"], row["guest_detail"]):
            assert "SSH down" in detail
            assert "0 bytes of console output" in detail
    else:
        assert "serving" not in status_out + list_out
        assert "Guest:     unknown (SSH down, 0 bytes of console output)" in status_out
        assert "[running — guest unknown (SSH down, 0 bytes of console output)]" in list_out


def test_no_endpoint_guest_with_no_console_output_is_unknown(cache, monkeypatch):
    """No SSH to ask and nothing written: there is no positive evidence."""
    inst = _vm_with_log(cache, "silent", "")
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "unknown"


def test_no_endpoint_guest_with_console_output_is_serving(cache, monkeypatch):
    """A harness VM has no sshd by design; its console output is the evidence."""
    inst = _vm_with_log(cache, "talks", "[ 0.0] Linux version 6.12.0\nharness up\n")
    _qmp(monkeypatch, True)

    assert lifecycle._guest_state(inst) == "serving"


def test_ssh_ready_outranks_console_silence(cache, monkeypatch):
    inst = _ssh_capable(_vm_with_log(cache, "quiet", ""), 10022)
    _qmp(monkeypatch, True)

    class ReadySSH:
        def is_ready(self, timeout=2):
            return True

    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: ReadySSH())

    assert lifecycle._observe_guest(inst, probe_ssh=True).guest == "serving"


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_status_does_not_probe_ssh_on_a_halted_vcpu(fmt, cache, monkeypatch, capsys):
    """A paused guest cannot answer sshd; the probe could only time out (5.2 s
    measured) to the `down` it would report anyway."""
    inst = _ssh_capable(_vm_with_log(cache, VM, "[ 0.0] Linux version 6.12.0\n"), 10022)
    _qmp(monkeypatch, False)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: (_ for _ in ()).throw(AssertionError("SSH probed on a paused guest")),
    )

    rc = cli.main(["--format", fmt, "status", "--vm", VM])
    out = capsys.readouterr().out

    assert rc == 0
    if fmt == "json":
        payload = json.loads(out)
        assert payload["guest"] == "paused"
        assert payload["ssh"] == "skipped"
    else:
        assert "Guest:     paused" in out
        assert "SSH:       port 10022 (not probed: guest paused)" in out


# ---------------------------------------------------------------------------
# status=panicked ⇒ bare `wait` agrees (#27). `wait` said "still running"
# (124, crash:null) where `status` said panicked on the same VM.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_bare_wait_agrees_with_status_that_the_guest_panicked(
    fmt, cache, monkeypatch, capsys
):
    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 6.12.0 (x) #1\n" + TERMINAL_PANIC)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_CRASH_SETTLE_MAX", 0.0)

    cli.main(["--format", "json", "status", "--vm", VM])
    assert json.loads(capsys.readouterr().out)["guest"] == "panicked"

    rc = cli.main(["--format", fmt, "wait", "--vm", VM, "--timeout", "5"])
    captured = capsys.readouterr()

    assert rc == 3
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["guest"] == "panicked"
        assert payload["reason"] == "terminal_panic"
        assert payload["stopped"] is False
        assert "Fatal exception" in payload["crash"]
        assert payload["cleaned"] is False
    else:
        assert "PANICKED" in captured.out
        assert f"qmu kill --vm {VM}" in captured.out
        assert "still running (" not in captured.out
    # The evidence `status` pointed at is still there.
    assert Path(inst.serial_log).exists()


# ---------------------------------------------------------------------------
# prune --orphans --dry-run names the VM, not just a pid
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_prune_orphans_preview_names_the_vm_it_would_kill(
    fmt, cache, monkeypatch, capsys
):
    pid = _make_state(VM_ORPHANED, cache, monkeypatch)

    rc = cli.main(["--format", fmt, "prune", "--orphans", "--dry-run"])
    out = capsys.readouterr().out

    assert rc == 0
    if fmt == "json":
        payload = json.loads(out)
        assert payload["would_kill"] == [{
            "vm_id": VM, "pid": pid,
            "serial_log": str(cache / "instances" / f"{VM}.serial.log"),
        }]
    else:
        assert f"{VM}  pid {pid}" in out
