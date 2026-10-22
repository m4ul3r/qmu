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
import re
import time
from pathlib import Path

import pytest

from qmu import cli
from qmu import instance as instance_mod
from qmu.commands import guest as guest_mod
from qmu.commands import lifecycle
from qmu.commands import qmp_cmds
from qmu.instance import (
    VM_ABSENT,
    VM_HELD_BACK,
    VM_ORPHANED,
    VM_RUNNING,
    VM_STOPPED,
    VMInstance,
    classify_vm,
    save_instance,
    save_ssh_severed,
)
from qmu.ssh import GuestText, SSHAborted, SSHError
from tests.test_daemon import FakeQMPServer, daemon_env  # noqa: F401 — fixture


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

    Without one the invariant assertion never exercises the "VM 'X' not
    found. Running: decoy" listing — the exact message the real CLI produced
    on a shared box. The zero-running branch has its own row
    (`test_absent_name_with_zero_running_vms_is_named_by_every_command`).
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
        # #217: a stopped VM has nothing to kill; its remnant goes with prune.
        assert f"qmu prune --vm {VM}" in payload["hint"]
        assert "qmu kill" not in payload["hint"]
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
    """A non-running VM `list` shows is a successful description (exit 0),
    not a failed lookup: after `kill` kept the logs, `status` is the very
    next command, and exit 1 there read as "gone" (r2-exploit finding 3)."""
    _make_state(state, cache, monkeypatch)

    rc = cli.main(["status", "--vm", VM])
    out = capsys.readouterr().out

    assert rc == 0
    assert VM in out
    # It must say what the thing IS, and name a command that acts on it.
    assert ("orphaned remnant" in out) or ("is stopped" in out)
    assert "qmu " in out


@pytest.mark.parametrize("state", [VM_ORPHANED, VM_HELD_BACK, VM_STOPPED])
def test_status_non_running_json_is_structured(state, cache, monkeypatch, capsys):
    pid = _make_state(state, cache, monkeypatch)

    rc = cli.main(["--format", "json", "status", "--vm", VM])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["vm_id"] == VM
    # `stopped` is held back from `prune --all` by the default age gate,
    # which is the only difference between the two; `status` reports the
    # same state word `prune` would.
    expected = VM_HELD_BACK if state == VM_STOPPED else state
    assert payload["status"] == expected
    assert payload["pid"] == pid
    assert payload["pid_alive"] is (state == VM_ORPHANED)
    assert payload["logs_retained"] is True
    assert payload["serial_log"].endswith(f"{VM}.serial.log")
    assert payload["qemu_log"].endswith(f"{VM}.qemu.log")
    assert payload["crash_detected"] is False
    if state == VM_ORPHANED:
        assert payload["guest"] in {"unknown", "serving", "panicked", "crashed", "paused"}
    else:
        assert payload["guest"] is None


def test_status_names_the_live_pid_for_an_orphan(cache, monkeypatch, capsys):
    """`list` shows a pid; `status` must not describe the same VM without one."""
    pid = _make_state(VM_ORPHANED, cache, monkeypatch)

    cli.main(["status", "--vm", VM])

    assert str(pid) in capsys.readouterr().out


# A `.qemu.log`-only remnant (#104): no .json, no .serial.log. `prune
# --older-than 0` removed it while `list` omitted it, `prune --dry-run` said
# `found: false`, and `status`/`kill` answered exit 1 "No running VMs" — the
# canonical matrix defect on the subcommand axis, for a state the classifier
# had never been taught.


def _qemu_log_only_remnant(cache, monkeypatch):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    qemu_log = idir / f"{VM}.qemu.log"
    qemu_log.write_text("Review-owned QEMU-only diagnostic\n")
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    return qemu_log


def test_qemu_log_only_remnant_is_held_back_not_absent(cache, monkeypatch):
    _qemu_log_only_remnant(cache, monkeypatch)
    assert classify_vm(VM)["state"] == VM_HELD_BACK
    assert classify_vm(VM, older_than_seconds=0)["state"] == VM_STOPPED


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_qemu_log_only_remnant_is_seen_by_list_status_kill_and_prune(
    fmt, cache, monkeypatch, capsys
):
    qemu_log = _qemu_log_only_remnant(cache, monkeypatch)
    _decoy_running(monkeypatch)

    assert cli.main(["--format", fmt, "list"]) == 0
    listing = capsys.readouterr().out
    assert cli.main(["--format", fmt, "status", "--vm", VM]) == 0
    detail = capsys.readouterr().out
    assert cli.main(["--format", fmt, "prune", "--vm", VM, "--dry-run"]) == 0
    preview = capsys.readouterr().out
    assert qemu_log.exists(), "--dry-run acted"
    assert cli.main(["--format", fmt, "kill", "--vm", VM]) == 0
    killed = capsys.readouterr().out
    assert qemu_log.exists(), "kill on a stopped remnant must preserve it"

    for name, out in (("list", listing), ("status", detail), ("prune", preview), ("kill", killed)):
        assert VM in out, f"`qmu {name}` omits a remnant on disk"
        assert "not found" not in out and "No running VMs" not in out, name

    if fmt == "json":
        row = next(r for r in json.loads(listing)["vms"] if r["vm_id"] == VM)
        status = json.loads(detail)
        view = {
            "list": (row["status"], row["logs_retained"], row["crash_detected"]),
            "status": (status["status"], status["logs_retained"], status["crash_detected"]),
            "status_qemu_log": status["qemu_log"],
            "preview": (json.loads(preview)["found"], json.loads(preview)["held_back"]),
            "kill": (json.loads(killed)["already_stopped"], json.loads(killed)["logs_retained"]),
        }
        assert view == {
            "list": ("stopped", False, False),
            "status": (VM_HELD_BACK, False, False),
            "status_qemu_log": str(qemu_log),
            "preview": (True, [VM]),
            "kill": (True, False),
        }, f"the commands disagree about the remnant: {view}"
    else:
        assert "Held back by the --older-than cutoff" in preview
        assert f"QEMU log: {qemu_log}" in detail

    # The real run with the gate lowered agrees with its own preview.
    assert cli.main(["--format", "json", "prune", "--vm", VM, "--dry-run", "--older-than", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["would_prune"] == [VM]
    assert cli.main(["--format", "json", "prune", "--vm", VM, "--older-than", "0"]) == 0
    assert json.loads(capsys.readouterr().out)["pruned"] == [VM]
    assert not qemu_log.exists()


def _stopped_with_report(cache, monkeypatch, vm_id=VM):
    """A VM `kill` stopped with its crash report kept, as every triggered
    exploit run ends."""
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text(
        "[ 0.0] Linux version 6.12.0 (b@h) (gcc) #1\n"
        "[ 1.6] Oops: general protection fault [#1] SMP\n"
        "[ 1.6] ---[ end trace 0000000000000000 ]---\n"
        "[ 1.6] Kernel panic - not syncing: Fatal exception\n"
    )
    (idir / f"{vm_id}.qemu.log").write_text("qemu\n")
    inst = VMInstance(
        vm_id=vm_id, pid=999_999, qmp_socket=str(idir / f"{vm_id}.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None, serial_log=str(serial),
        kernel="/boot/bzImage", rootfs=None, memory="4G", cpus=2,
        cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=False, pid_start="0",
    )
    instance_mod.save_instance(inst)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    return inst


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_stopped_vm_with_a_report_is_marked_everywhere(
    output_format, cache, monkeypatch, capsys
):
    """`kill` said "crash report preserved"; `list` then showed a bare
    [stopped] and `status` exit 1 — three answers about one fact."""
    _stopped_with_report(cache, monkeypatch)

    rc = cli.main(["--format", output_format, "list"])
    listing = capsys.readouterr().out
    assert rc == 0
    rc = cli.main(["--format", output_format, "status", "--vm", VM])
    detail = capsys.readouterr().out
    assert rc == 0

    if output_format == "json":
        row = json.loads(listing)["vms"][0]
        assert row["status"] == "stopped"
        assert row["crash_detected"] is True
        assert row["logs_retained"] is True
        assert row["guest"] is None
        # Never null: a null read as "probe failed".
        assert row["qmp"] == "skipped"
        payload = json.loads(detail)
        assert payload["status"] == "stopped"
        assert payload["crash_detected"] is True
        assert payload["logs_retained"] is True
    else:
        assert f"{VM}  profile=exploit-dev  kernel=bzImage  [stopped — crash report retained]" in listing
        assert f"VM '{VM}' is stopped (logs retained; crash report waiting: qmu crash --vm {VM})" in detail


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_kill_of_a_stopped_vm_is_a_clean_no_op(
    output_format, cache, monkeypatch, capsys
):
    """`kill` then `kill` again: the second is already what was asked for."""
    inst = _stopped_with_report(cache, monkeypatch)
    calls = _fake_kill(monkeypatch)

    rc = cli.main(["--format", output_format, "kill", "--vm", VM])
    out = capsys.readouterr().out

    assert rc == 0
    assert calls == []
    assert Path(inst.serial_log).exists()
    if output_format == "json":
        payload = json.loads(out)
        assert payload["ok"] is True
        assert payload["already_stopped"] is True
        assert payload["vm_id"] == VM
        assert payload["logs_retained"] is True
    else:
        assert out.strip() == (
            f"VM '{VM}' is already stopped; state retained "
            f"(remove with: qmu prune --vm {VM})"
        )
        assert "--older-than 0" not in out


def test_kill_of_an_absent_vm_still_says_not_found(cache, monkeypatch, capsys):
    """The no-op is for a VM `list` shows; a typo must stay a typo."""
    _stopped_with_report(cache, monkeypatch)
    _decoy_running(monkeypatch)
    _fake_kill(monkeypatch)

    rc = cli.main(["--format", "json", "kill", "--vm", "subjct"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert "not found" in payload["error"]
    assert VM in payload["error"]


# Every command that needs a live VM, asked about one `list` shows but no
# tracked QEMU serves, must give the SAME answer `exec` gives (one describer)
# and name it in `vm_id` — with or without another VM running. #144 made the
# zero-running branch reach the running-only lookup, where push/pull/snapshot
# /gdb/qmp/… said "not found … Stopped: X" while `exec` said "is stopped".
_RUNNING_ONLY_ARGV = {
    "exec": ["exec", "--vm", VM, "true"],
    "push": ["push", "--vm", VM, "/tmp/payload", "/root/"],
    "pull": ["pull", "--vm", VM, "/root/payload"],
    "compile": ["compile", "--vm", VM, "/tmp/payload.c"],
    "dmesg": ["dmesg", "--vm", VM],
    "snapshot list": ["snapshot", "list", "--vm", VM],
    "cont": ["cont", "--vm", VM],
    "gdb": ["gdb", "--vm", VM],
    "kbase": ["kbase", "--vm", VM, "--symbols", "/tmp/System.map"],
    "qmp": ["qmp", "--vm", VM, "query-status"],
    "monitor": ["monitor", "--vm", VM, "info", "status"],
}


@pytest.mark.parametrize("with_decoy", [False, True], ids=["zero-running", "decoy"])
@pytest.mark.parametrize("state", [VM_ORPHANED, VM_STOPPED])
@pytest.mark.parametrize("command", sorted(_RUNNING_ONLY_ARGV))
def test_running_only_commands_never_deny_a_listed_vm(
    command, state, with_decoy, cache, monkeypatch, capsys
):
    _make_state(state, cache, monkeypatch)
    if with_decoy:
        decoy = VMInstance(
            vm_id="decoy", pid=1, qmp_socket="/tmp/decoy.qmp.sock",
            ssh_port=None, ssh_key=None, gdb_port=None,
            serial_log="/tmp/decoy.serial.log", kernel="/boot/bzImage",
            rootfs=None, memory="4G", cpus=2, cmdline="console=ttyS0",
            profile="exploit-dev", started_at="2026-08-17T00:00:00Z", harness=True,
        )
        for mod in (lifecycle, instance_mod):
            monkeypatch.setattr(mod, "list_instances", lambda: [decoy], raising=False)

    cli.main(["list"])
    assert VM in capsys.readouterr().out, "fixture did not produce a listed VM"

    answers = {}
    for name in ("exec", command):
        rc = cli.main(["--format", "json", *_RUNNING_ONLY_ARGV[name]])
        answers[name] = json.loads(capsys.readouterr().out)
        assert rc == 1, name
    payload = answers[command]

    assert "not found" not in payload["error"], (
        f"`qmu {command}` denies a VM that `qmu list` displays"
    )
    assert payload["vm_id"] == answers["exec"]["vm_id"] == VM
    assert payload["hint"] == answers["exec"]["hint"]
    assert payload["error"].replace(f"`qmu {command}`", "`qmu exec`") == (
        answers["exec"]["error"]
    ), f"`qmu {command}` and `qmu exec` describe the same VM differently"


# The empty-running-set branch (#144): with no VM running — the normal state
# after an auto-cleaned harness `wait` — status/wait/kill answered "No running
# VMs. Start one with: qmu launch" without naming the VM, while crash/log
# answered the question asked. One answer for every command, both formats.
_ABSENT_NAME_ARGV = {
    "status": ["status", "--vm", "ghost"],
    "wait": ["wait", "--vm", "ghost", "--timeout", "0"],
    "wait --pattern": ["wait", "--vm", "ghost", "--pattern", "x", "--timeout", "0"],
    "kill": ["kill", "--vm", "ghost"],
    "crash": ["crash", "--vm", "ghost"],
    "log": ["log", "--vm", "ghost"],
    "exec": ["exec", "--vm", "ghost", "true"],
    "push": ["push", "--vm", "ghost", "/tmp/payload", "/root/"],
    "pull": ["pull", "--vm", "ghost", "/root/payload"],
    "dmesg": ["dmesg", "--vm", "ghost"],
}


@pytest.mark.parametrize("output_format", ["text", "json"])
@pytest.mark.parametrize("command", sorted(_ABSENT_NAME_ARGV))
def test_absent_name_with_zero_running_vms_is_named_by_every_command(
    command, output_format, cache, monkeypatch, capsys
):
    _stopped_with_report(cache, monkeypatch)
    expected = f"VM 'ghost' not found. Running: none; Stopped: {VM}."

    rc = cli.main(["--format", output_format, *_ABSENT_NAME_ARGV[command]])
    captured = capsys.readouterr()

    assert rc == 1, command
    if output_format == "json":
        payload = json.loads(captured.out)
        assert payload["error"] == expected, command
        assert payload["hint"] == "qmu list", command
    else:
        assert captured.out == ""
        assert f"[qmu] Error: {expected}" in captured.err, command
        assert "No running VMs" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["status", "--vm", VM],
        ["wait", "--vm", VM, "--timeout", "0"],
        ["kill", "--vm", VM],
        ["crash", "--vm", VM],
        ["log", "--vm", VM],
    ],
    ids=lambda argv: argv[0],
)
def test_every_envelope_about_a_vm_keys_it_vm_id(argv, cache, monkeypatch, capsys):
    """#160: `crash`/`log` keyed the VM `vm` while every other command used
    `vm_id` — and in harness mode those two plus `wait` are the only result
    channels, so `d["vm_id"]` on a crash envelope silently read None."""
    _stopped_with_report(cache, monkeypatch)

    cli.main(["--format", "json", *argv])
    payload = json.loads(capsys.readouterr().out)

    assert payload["vm_id"] == VM
    assert "vm" not in payload


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
    # Age out only "prunable" by making the cutoff match nothing else. The
    # eligibility and refusal views are one discovery; patch both halves.
    monkeypatch.setattr(
        lifecycle, "list_prunable_instance_ids",
        lambda **kw: ["prunable"],
    )
    monkeypatch.setattr(
        instance_mod, "prune_refusals",
        lambda **kw: {"held": (instance_mod.HELD_AGE, None)},
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
        instance_mod, "prune_refusals",
        lambda **kw: {VM: (instance_mod.HELD_AGE, None)},
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
    described = capsys.readouterr().out

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


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_paused_guest_with_a_retained_report_agrees_across_list_status_crash(
    fmt, cache, monkeypatch, capsys
):
    """#93 (receipts 129–133): a survived report, then `qmp stop`. `paused`
    wins the usability axis, but the report is a fact about the log: `list`
    and `status` said `crash_detected: false` while `crash` retrieved it, so
    automation skipped a report because a debugger had halted the vCPU."""
    inst = _vm_with_log(cache, "pzr", "[ 0.0] Linux version 6.12.0\n" + SURVIVED_OOPS)
    _qmp(monkeypatch, False)
    _register_running(monkeypatch, inst)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_stopped_instances", lambda: [], raising=False)

    assert cli.main(["--format", fmt, "list"]) == 0
    listing = capsys.readouterr().out
    assert cli.main(["--format", fmt, "status", "--vm", "pzr"]) == 0
    detail = capsys.readouterr().out
    assert cli.main(["--format", fmt, "crash", "--vm", "pzr"]) == 0
    report = capsys.readouterr().out

    if fmt == "json":
        row = json.loads(listing)["vms"][0]
        status = json.loads(detail)
        crash = json.loads(report)
        view = {
            "list": (row["guest"], row["crash_detected"]),
            "status": (status["guest"], status["crash_detected"]),
            "crash": crash["crash_detected"],
        }
        assert view == {
            "list": ("paused", True),
            "status": ("paused", True),
            "crash": True,
        }, f"the three disagree: {view}"
    else:
        assert "vCPU paused" in listing and "crash report waiting" in listing
        assert "Guest:     paused" in detail
        assert "qmu crash --vm pzr" in detail
        assert "NULL pointer dereference" in report


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


# ---------------------------------------------------------------------------
# Axis 4, list vs status on a held QMP slot. Another client (a `wait`, a
# debugger bridge) owns the one QMP connection: `status` called that `busy`
# while `list` called the same socket `unreachable`, which reads as a dead
# VM. Both must classify the same exception the same way.
# ---------------------------------------------------------------------------


def _held_qmp(monkeypatch):
    class HeldCtx:
        def __enter__(self):
            raise __import__("qmu.qmp", fromlist=["QMPBusyError"]).QMPBusyError(
                "accepted the connection but sent no greeting"
            )

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda inst: HeldCtx())


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_list_and_status_agree_a_held_qmp_slot_is_busy(
    output_format, cache, monkeypatch, capsys
):
    inst = _ssh_capable(_vm_with_log(cache, "held", "[ 0.0] Linux version 6.12.0\n"), 10022)
    _held_qmp(monkeypatch)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: type("S", (), {"is_ready": lambda self, timeout=2: True})(),
    )

    cli.main(["--format", output_format, "list"])
    listing = capsys.readouterr().out
    cli.main(["--format", output_format, "status", "--vm", "held"])
    detail = capsys.readouterr().out

    if output_format == "json":
        row = json.loads(listing)["vms"][0]
        payload = json.loads(detail)
        assert row["qmp"] == payload["qmp"] == "busy"
        assert row["guest"] == payload["guest"] == "serving"
        # #106: the running row carries the same QEMU run-state field `status`
        # does, and a busy probe reads "unknown" in both.
        assert row["qemu_status"] == payload["qemu_status"] == "unknown"
    else:
        assert "qmp=busy" in listing
        assert "unreachable" not in listing
        assert "QMP:       busy" in detail


def test_list_running_rows_carry_the_qemu_status_that_status_reports(
    cache, monkeypatch, capsys
):
    """#106: `status` exposes `qemu_status`; a running `list` row must too, with
    the same value, while a stopped row — no QEMU to ask — omits it."""
    inst = _ssh_capable(_vm_with_log(cache, "live", "[ 0.0] Linux version 6.12.0\n"), 10022)
    _qmp(monkeypatch, False)
    _register_running(monkeypatch, inst)
    _write_remnant(cache, "gone")

    cli.main(["--format", "json", "list"])
    rows = {
        (r["vm_id"], r["status"]): r
        for r in json.loads(capsys.readouterr().out)["vms"]
    }
    cli.main(["--format", "json", "status", "--vm", "live"])
    payload = json.loads(capsys.readouterr().out)

    live, gone = rows[("live", "running")], rows[("gone", "stopped")]
    assert live["qemu_status"] == payload["qemu_status"] == "paused"
    assert live["guest"] == payload["guest"] == "paused"
    assert "qemu_status" not in gone and "qmp_socket" not in gone


# ---------------------------------------------------------------------------
# Axis 4, list vs status when the daemon serves the VM (#70). Neither command
# opens QMP: both read the daemon's cached state, both say `qmp: daemon`, and
# both scope the guest on the daemon's observed epoch — so a panic from the
# boot BEFORE an observed RESET is out of scope for both, and the new
# `guest_epoch_source` key appears on both running rows (and on neither when
# the layer is off, which is every other row in this file).
# ---------------------------------------------------------------------------


def _daemon_served(monkeypatch, *, epoch_offset, epoch_source="observed"):
    state = {
        "watched": True, "running": True, "qemu_status": "running",
        "panicked": False, "exited": False, "last_event": "RESET",
        "event_data": {"source": "qmp"}, "boot_offset": epoch_offset,
        "epoch_offset": epoch_offset, "epoch_source": epoch_source,
    }
    monkeypatch.setattr(lifecycle, "_daemon_state", lambda inst, adopt=True: dict(state))
    monkeypatch.setattr(
        lifecycle, "_qmp_ctx",
        lambda inst: pytest.fail("opened QMP while the daemon serves the VM"),
    )
    return state


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_list_and_status_agree_when_the_daemon_serves_the_vm(
    output_format, cache, monkeypatch, capsys
):
    first_boot = "[ 0.0] Linux version 6.12.0\n[ 9.0] Kernel panic - not syncing: old\n"
    second_boot = "[ 0.0] Linux version 6.12.0\nsecond boot up\n"
    inst = _ssh_capable(_vm_with_log(cache, "sup", first_boot + second_boot), 10022)
    _daemon_served(monkeypatch, epoch_offset=len(first_boot))
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: type("S", (), {"is_ready": lambda self, timeout=2: True})(),
    )

    cli.main(["--format", output_format, "list"])
    listing = capsys.readouterr().out
    cli.main(["--format", output_format, "status", "--vm", "sup"])
    detail = capsys.readouterr().out

    if output_format == "json":
        row = json.loads(listing)["vms"][0]
        payload = json.loads(detail)
        assert row["qmp"] == payload["qmp"] == "daemon"
        assert row["guest"] == payload["guest"] == "serving"
        assert row["crash_detected"] is payload["crash_detected"] is False
        assert row["guest_epoch_source"] == payload["guest_epoch_source"] == "observed"
        assert payload["guest_epoch_serial_offset"] == len(first_boot)
        assert payload["boot_offset"] == len(first_boot)
    else:
        assert "qmp=" not in listing, listing  # quiet, like `connected`
        assert "PANICKED" not in listing
        assert "QMP:       daemon (boot scope: observed epoch" in detail
        assert "panicked" not in detail


def test_daemon_keys_are_absent_on_the_standalone_path(cache, monkeypatch, capsys):
    """`QMU_DAEMON=off` (the suite default) must yield exactly today's shape."""
    inst = _ssh_capable(_vm_with_log(cache, "solo", "[ 0.0] Linux version 6.12.0\n"), 10022)
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: type("S", (), {"is_ready": lambda self, timeout=2: True})(),
    )

    cli.main(["--format", "json", "list"])
    row = json.loads(capsys.readouterr().out)["vms"][0]
    cli.main(["--format", "json", "status", "--vm", "solo"])
    payload = json.loads(capsys.readouterr().out)

    assert row["qmp"] == payload["qmp"] == "connected"
    for key in ("guest_epoch_source", "boot_offset", "guest_epoch_serial_offset"):
        assert key not in row and key not in payload, key


# ---------------------------------------------------------------------------
# Axis 2, daemon vs standalone, after `snapshot load` rewound a panicked guest
# (#162, #163). `loadvm` emits STOP/RESUME but no RESET, so the daemon learns
# the new generation only from the epoch the command hands it. Daemon-backed
# `status`/`list` kept the cached `panicked` (skipping the SSH probe that
# disproves it) and bare `wait` exited 3 on the pre-load report, while
# `QMU_DAEMON=off` said serving / 124 and `crash` found nothing this epoch.
# The daemon here is the real one, in-process: the bug lived in its cache.
# ---------------------------------------------------------------------------


class _ReadySSH:
    def is_ready(self, timeout=2):
        return True

    def close_control_master(self):
        pass


_AFTER_LOAD_ARGV = {
    "status": ["status", "--vm", VM],
    "list": ["list"],
    "wait": ["wait", "--vm", VM, "--timeout", "1"],
    "crash": ["crash", "--vm", VM],
}


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_status_list_wait_and_crash_agree_after_a_snapshot_load_daemon_on_and_off(
    fmt, cache, daemon_env, monkeypatch, capsys
):
    from qmu import daemon_client
    from qmu.commands import qmp_cmds

    idir = cache / "instances"
    serial = idir / f"{VM}.serial.log"
    serial.write_text("[ 0.0] Linux version 6.12.0 (x) #1\n[ 1.0] serving\n")
    server = FakeQMPServer(cache / "q.sock")
    instance_mod.save_instance(VMInstance(
        vm_id=VM, pid=os.getpid(), qmp_socket=str(server.path), ssh_port=10022,
        ssh_key="/k", gdb_port=None, serial_log=str(serial), kernel="/boot/bzImage",
        rootfs=None, memory="1G", cpus=1, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-08-17T00:00:00Z", harness=False,
    ))
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    for mod in (lifecycle, qmp_cmds):
        monkeypatch.setattr(mod, "_make_ssh", lambda inst: _ReadySSH())
    monkeypatch.setattr(lifecycle, "_CRASH_SETTLE_MAX", 0.0)

    def hmp(req):
        line = req["arguments"]["command-line"]
        if line == "info snapshots":
            return (
                "List of snapshots present on all disks:\n"
                "ID        TAG               VM SIZE                DATE       VM CLOCK     ICOUNT\n"
                "--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992\n"
            )
        if line.startswith("loadvm"):
            server.emit("STOP")
            server.emit("RESUME")
        return ""

    server.replies["human-monitor-command"] = hmp
    try:
        daemon_client.watch(VM)
        with serial.open("a") as stream:
            stream.write(TERMINAL_PANIC)
        server.emit("GUEST_PANICKED", {"action": "pause"})
        deadline = time.monotonic() + 5
        while not daemon_client.vm_state(VM)["panicked"] and time.monotonic() < deadline:
            time.sleep(0.01)
        assert cli.main(["--format", "json", "status", "--vm", VM]) == 0
        assert json.loads(capsys.readouterr().out)["guest"] == "panicked"

        assert cli.main(["--format", "json", "snapshot", "load", "clean", "--vm", VM]) == 0
        capsys.readouterr()

        readings = {}
        for mode in ("daemon", "standalone"):
            if mode == "standalone":
                monkeypatch.setenv("QMU_DAEMON", "off")
                daemon_client.reset()
                _qmp(monkeypatch, True)  # the daemon still holds the fake's one slot
            readings[mode] = {}
            for name, argv in _AFTER_LOAD_ARGV.items():
                rc = cli.main(["--format", fmt, *argv])
                readings[mode][name] = (rc, capsys.readouterr().out)
    finally:
        server.close()

    for mode, got in readings.items():
        codes = {name: rc for name, (rc, _) in got.items()}
        assert codes == {"status": 0, "list": 0, "wait": 124, "crash": 1}, (mode, got)
        if fmt == "text":
            for name in ("status", "list", "wait"):
                assert "panicked" not in got[name][1].lower(), (mode, name, got[name][1])
    if fmt == "json":
        parsed = {
            mode: {name: json.loads(out) for name, (_, out) in got.items()}
            for mode, got in readings.items()
        }
        for mode, p in parsed.items():
            row = p["list"]["vms"][0]
            assert p["status"]["guest"] == row["guest"] == "serving", mode
            assert p["status"]["crash_detected"] is row["crash_detected"] is False, mode
            assert p["status"]["ssh"] == "ready", mode
            assert p["wait"]["reason"] == "timeout" and p["wait"]["crash"] is None, mode
            assert p["crash"]["crash_detected"] is False, mode
        on, off = parsed["daemon"], parsed["standalone"]
        assert on["wait"]["guest"] == off["wait"]["guest"]
        assert set(on["wait"]) == set(off["wait"])
        assert on["status"]["qmp"] == "daemon" and off["status"]["qmp"] == "connected"

# ---------------------------------------------------------------------------
# The SSH readiness probe logs in, and a login runs `uname`. With a gdb
# client attached that is a breakpoint on `__x64_sys_newuname` fired by qmu's
# own `status` — which then halted the guest it was asked to describe
# (r2-debug P1). `status` and `list` both withhold the probe and both say so.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_status_and_list_skip_the_ssh_probe_while_a_debugger_is_attached(
    output_format, cache, monkeypatch, capsys
):
    inst = __import__("dataclasses").replace(
        _ssh_capable(_vm_with_log(cache, "dbg", "[ 0.0] Linux version 6.12.0\n"), 10022),
        gdb_port=1234,
    )
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: True)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: pytest.fail("probed sshd with a debugger attached"),
    )

    cli.main(["--format", output_format, "status", "--vm", "dbg"])
    detail = capsys.readouterr().out
    cli.main(["--format", output_format, "list"])
    listing = capsys.readouterr().out

    if output_format == "json":
        payload = json.loads(detail)
        row = json.loads(listing)["vms"][0]
        assert payload["ssh"] == row["ssh"] == "skipped (debugger attached)"
        assert row["ssh_ready"] is None
        # Console bytes are the positive evidence, as for a guest with no endpoint.
        assert payload["guest"] == row["guest"] == "serving"
    else:
        assert "not probed: debugger attached" in detail
        assert "ssh=10022(not probed: debugger attached)" in listing


def test_ssh_probe_runs_when_no_debugger_is_attached(cache, monkeypatch, capsys):
    """The skip is keyed on an attached client, not on the gdb port existing:
    every `--gdb` launch has a port, and most of the time nobody is on it."""
    inst = __import__("dataclasses").replace(
        _ssh_capable(_vm_with_log(cache, "nodbg", "[ 0.0] Linux version 6.12.0\n"), 10022),
        gdb_port=1234,
    )
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: False)
    probed = []
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: type("S", (), {"is_ready": lambda self, timeout=2: probed.append(1) or True})(),
    )

    cli.main(["--format", "json", "status", "--vm", "nodbg"])
    payload = json.loads(capsys.readouterr().out)

    assert probed == [1]
    assert payload["ssh"] == "ready"


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

    def push(self, local, remote, **kwargs):
        self._drop()
        raise SSHError(
            "SCP push failed: mux failed: Broken pipe",
            returncode=255,
            stderr="mux failed: Broken pipe",
        )

    def pull(self, remote, local, **kwargs):
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
        "names_qmu_crash": f"qmu crash --vm {VM}" in hint,
        "names_qmu_log": f"qmu log --vm {VM} --tail 100" in hint,
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


class _ServingAfterCutSSH:
    """ssh exits 255 because the session was cut under it (or the guest
    command really exited 255); the guest then answers the liveness probe
    and reports its kernel's uptime — near 0 after a reboot (#221)."""

    def __init__(self, cut, uptime):
        self._cut = cut
        self._uptime = uptime

    def run(self, command, timeout=30.0, check=False, **kwargs):
        if command == "cat /proc/uptime":
            return 0, f"{self._uptime:.2f} 1.00\n", ""
        self._cut()
        return 255, "", ""

    def is_ready(self, timeout=2):
        return True


@pytest.mark.parametrize(
    "cause", ["snapshot load", "guest reboot", "standalone reboot", "banner replay"]
)
def test_every_ssh_command_agrees_on_a_session_cut_under_it(
    cause, cache, monkeypatch, capsys
):
    """A session another pane's `snapshot load` cut, or a guest reboot (QEMU's
    RESET stamped by the daemon, or — daemon off — a guest kernel younger
    than the command), is a transport loss qmu can name, on exec and dmesg
    alike — never the guest command exiting 255, which the answering probe
    used to make of it. A boot banner the guest replays to its console is
    not a reboot: the 255 stays the guest's on both."""
    inst = _ssh_capable_instance(cache)
    save_instance(inst)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest_mod.time, "sleep", lambda _: None)
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)

    def cut():
        if cause == "snapshot load":
            qmp_cmds._sever_sessions(inst, cause)
        elif cause == "guest reboot":
            save_ssh_severed(inst, cause)  # the daemon, on a guest-requested RESET
        elif cause == "banner replay":
            with open(inst.serial_log, "a") as stream:
                stream.write("[    0.000000] Linux version 7.0.0 (b@h) (gcc 13) #1 SMP\n")

    rebooted = cause in ("guest reboot", "standalone reboot")
    monkeypatch.setattr(
        guest_mod, "_make_ssh",
        lambda selected: _ServingAfterCutSSH(cut, 0.0 if rebooted else 3600.0),
    )

    views = {}
    for command in ("exec", "dmesg"):
        with open(inst.serial_log, "w") as stream:
            stream.write("boot ok\n")
        rc = cli.main(["--format", "json", *_LOST_ARGV[command]])
        payload = json.loads(capsys.readouterr().out)
        views[command] = {
            "rc": rc,
            "ok": payload.get("ok"),
            "ssh_error": payload.get("ssh_error") is True,
            "exit_code": payload.get("exit_code"),
            "severed_by": payload.get("severed_by"),
        }
    if cause == "banner replay":
        expected = {"rc": 1, "ok": False, "ssh_error": False, "exit_code": 255, "severed_by": None}
    else:
        expected = {
            "rc": 4, "ok": False, "ssh_error": True, "exit_code": None,
            "severed_by": "guest reboot" if rebooted else cause,
        }
    for command, view in views.items():
        assert view == expected, f"`qmu {command}` disagrees: {view}"


class _HaltedMidCommandSSH:
    """A session the watcher aborts: `abort_when` is honoured like the real
    client (one poll, then :class:`SSHAborted`) for commands and transfers."""

    def _abort(self, kwargs, what):
        abort_when = kwargs.get("abort_when")
        assert abort_when is not None, f"{what} is not watched"
        assert abort_when() is True
        raise SSHAborted(f"{what} aborted by qmu", stdout="", stderr="")

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self._abort(kwargs, "SSH command")

    def push(self, local, remote, **kwargs):
        self._abort(kwargs, "SCP push")

    def pull(self, remote, local, **kwargs):
        self._abort(kwargs, "SCP pull")

    def is_ready(self, timeout=2):
        raise AssertionError("SSH probed against a halted vCPU")


_HALTED_ARGV = {
    **_LOST_ARGV,
    "compile": ["compile", "--vm", VM, "--run", "/tmp/x.c"],
}


@pytest.mark.parametrize("holder", ["no debugger", "qmu bridge", "other client"])
@pytest.mark.parametrize("output_format", ["text", "json"])
def test_every_ssh_command_agrees_on_a_vcpu_halted_mid_command(
    output_format, holder, cache, monkeypatch, capsys, tmp_path
):
    """A breakpoint fires while exec / dmesg / push / pull / compile run: no
    serial output, no transport drop — only QMP knows. Every command aborts
    on the watcher's QMP poll and reports the preflight's paused envelope
    (exit 1, `guest_state: paused`, the resume hint), never the 20 s
    keepalive stall into the crash/transport class, in both renderings.

    #225: with a debugger attached the `debug` stop is the debugger's: every
    command leads with its resume (`qmu-<vm>` for the bridge `qmu gdb`
    spawned, `<id>` for another client) and none offers `qmu cont` as the
    resume, which would run the guest with every breakpoint lifted."""
    from dataclasses import replace

    from qmu import debug

    inst = _ssh_capable_instance(cache)
    if holder != "no debugger":
        inst = replace(inst, gdb_port=1234)
        monkeypatch.setattr(debug, "gdb_client_attached", lambda i: True)
        monkeypatch.setattr(debug, "bridge_holds_stub", lambda i: holder == "qmu bridge")
    resume = {
        "no debugger": f"qmu cont --vm {VM}",
        "qmu bridge": f"pry --instance qmu-{VM} continue --background",
        "other client": "pry --instance <id> continue --background",
    }[holder]
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest_mod, "_make_ssh", lambda selected: _HaltedMidCommandSSH())
    monkeypatch.setattr(guest_mod, "_qmp_stopped_status", lambda i: "debug")
    clock = [0.0]

    def monotonic():
        clock[0] += 2.0
        return clock[0]

    monkeypatch.setattr(guest_mod.time, "monotonic", monotonic)
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    argvs = {**_HALTED_ARGV, "compile": ["compile", "--vm", VM, "--run", str(tmp_path / "x.c")]}

    for command, argv in argvs.items():
        with open(inst.serial_log, "w") as stream:
            stream.write("boot ok\n")
        rc = cli.main(["--format", output_format, *argv])
        captured = capsys.readouterr()
        assert rc == 1, f"`qmu {command}`: rc {rc}"
        if output_format == "json":
            payload = json.loads(captured.out)
            assert payload["ok"] is False, command
            assert payload["guest_state"] == "paused", command
            assert payload["qemu_status"] == "debug", command
            assert payload["crash_detected"] is False, command
            assert payload["ssh_error"] is False, command
            assert payload["vm_id"] == VM, command
            assert f"Resume with: {resume}" in payload["hint"], command
        else:
            out = captured.out + captured.err
            assert f"VM '{VM}' is debug (vCPU halted" in out, command
            assert f"Resume with: {resume}" in out, command
            assert "crash" not in out.lower(), command


class _PanicMidCommandSSH:
    """A session the watcher aborts on a terminal panic: the serial log gains
    the report while the command runs, the predicate is honoured like the
    real client (one poll, then :class:`SSHAborted` carrying no returncode)
    for commands and transfers alike. `is_ready` is never consulted — the
    serial log already explains the loss."""

    def __init__(self, serial_path):
        self._serial_path = serial_path

    def _abort(self, kwargs, what, stdout=""):
        abort_when = kwargs.get("abort_when")
        assert abort_when is not None, f"{what} is not watched"
        with open(self._serial_path, "a") as stream:
            stream.write(_LOST_PANIC)
        assert abort_when() is True
        raise SSHAborted(f"{what} aborted by qmu", stdout=stdout, stderr="")

    def run(self, command, timeout=30.0, check=False, **kwargs):
        if command.startswith("gcc"):
            return 0, "", ""  # the compile step succeeds; the panic lands under the run
        self._abort(kwargs, "SSH command", stdout="pre\n")

    def push(self, local, remote, **kwargs):
        self._abort(kwargs, "SCP push")

    def pull(self, remote, local, **kwargs):
        self._abort(kwargs, "SCP pull")

    def is_ready(self, timeout=2):
        raise AssertionError("SSH probed when the serial log already explains the loss")


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_every_ssh_command_agrees_on_a_panic_mid_command(
    output_format, cache, monkeypatch, capsys, tmp_path
):
    """The watcher stops exec / dmesg / push / pull / compile the moment the
    serial log shows a terminal panic. Every one of them is the kernel-crash
    class (3) with the report, in both renderings. Measured live before this
    row (#89): a sysrq panic during a 2 GiB `push` was exit 4 `SSHAborted`
    with no report while the concurrent `exec` was 3 and `qmu crash` returned
    the same panic — the watcher's no-returncode exception bypassed the
    transfer handlers' rc-255-plus-marker discrimination."""
    inst = _ssh_capable_instance(cache)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(
        guest_mod, "_make_ssh", lambda selected: _PanicMidCommandSSH(inst.serial_log)
    )
    (Path("/tmp") / "payload.bin").write_bytes(b"x")
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    argvs = {**_HALTED_ARGV, "compile": ["compile", "--vm", VM, "--run", str(tmp_path / "x.c")]}

    for command, argv in argvs.items():
        with open(inst.serial_log, "w") as stream:
            stream.write("boot ok\n")
        rc = cli.main(["--format", output_format, *argv])
        captured = capsys.readouterr()
        assert rc == 3, f"`qmu {command}`: rc {rc}"
        if output_format == "json":
            payload = json.loads(captured.out)
            assert payload["ok"] is False, command
            assert payload["ssh_error"] is True, command
            assert payload["crash_detected"] is True, command
            assert "Kernel panic - not syncing" in payload["crash"], command
            assert payload["vm_id"] == VM, command
            assert "qmu crash" in payload["hint"], command
            assert "guest_state" not in payload, command
        else:
            # exec/dmesg/compile keep stdout for guest bytes, so the report is
            # a stderr note there (#172); push/pull print it as their result.
            assert "Kernel panic - not syncing" in captured.out + captured.err, command
            assert "vCPU halted" not in captured.out + captured.err, command


class _ServingSSH:
    """A guest that answers: fixed exec result, transfers succeed."""

    def __init__(self, rc=0, stdout="", stderr=""):
        self._result = (rc, stdout, stderr)

    def run(self, command, timeout=30.0, check=False, **kwargs):
        return self._result

    def push(self, local, remote, **kwargs):
        pass

    def pull(self, remote, local, **kwargs):
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


@pytest.mark.parametrize("command", ["exec", "dmesg"])
def test_out_artifact_agrees_with_the_exit_code_in_both_formats(
    command, cache, monkeypatch, capsys, tmp_path
):
    """Axis 3 (text vs JSON), the `--out` leg: a failed guest command exits 1
    in both formats, and the pointer each format prints says the guest
    failed with its exit code — JSON as the envelope, text as the one-line
    `[qmu] Output written to …` pointer (#71b: text mode used to print the
    JSON envelope). Measured live before this row (#108): text `--out` said
    `ok: true` for `printf nope; exit 7` while JSON `--out` said `ok: false`
    for the same command."""
    _serving_subject(cache, monkeypatch, _ServingSSH(7, "nope", "err\n"))
    text_out, json_out = tmp_path / "text.bin", tmp_path / "data.json"

    rc_text = cli.main(["--format", "text", *_LOST_ARGV[command], "--out", str(text_out)])
    text_pointer = capsys.readouterr().out
    rc_json = cli.main(["--format", "json", *_LOST_ARGV[command], "--out", str(json_out)])
    json_envelope = json.loads(capsys.readouterr().out)

    assert rc_text == rc_json == 1
    assert text_pointer == f"[qmu] Output written to {text_out} (4 bytes, exit 7)\n"
    assert json_envelope["ok"] is False
    assert json.loads(json_out.read_text())["exit_code"] == 7
    assert text_out.read_bytes() == b"nope"


class _StreamingServingSSH(_ServingSSH):
    """A guest whose output arrives in pieces (`on_chunk`), as the real
    client relays it, before the joined result is returned."""

    def __init__(self, rc, chunks):
        self._chunks = chunks
        out = b"".join(d for s, d in chunks if s == "stdout")
        err = b"".join(d for s, d in chunks if s == "stderr")
        super().__init__(rc, GuestText(out), GuestText(err))

    def run(self, command, timeout=30.0, check=False, **kwargs):
        on_chunk = kwargs.get("on_chunk")
        if on_chunk is not None:
            for stream, data in self._chunks:
                on_chunk(stream, data)
        return self._result


def test_streamed_text_ndjson_and_buffered_json_agree_on_the_guest_output(
    cache, monkeypatch, capsys
):
    """Axis 3 (text vs JSON) × the live relay (#71a): text mode writes guest
    stdout as it arrives, ndjson emits `chunk` events then the envelope, json
    buffers. All three must report the same bytes once, with guest stderr
    and the exit trailer kept off stdout — a stream that was also rendered
    at the end would print everything twice."""
    chunks = [("stdout", b"line 1\n"), ("stderr", b"err\n"), ("stdout", b"line 2\n")]
    _serving_subject(cache, monkeypatch, _StreamingServingSSH(5, chunks))

    rc_json = cli.main(["--format", "json", *_LOST_ARGV["exec"]])
    payload = json.loads(capsys.readouterr().out)
    rc_ndjson = cli.main(["--format", "ndjson", *_LOST_ARGV["exec"]])
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    rc_text = cli.main(["--format", "text", *_LOST_ARGV["exec"]])
    captured = capsys.readouterr()

    assert rc_json == rc_ndjson == rc_text == 1
    events, envelope = lines[:-1], lines[-1]
    assert [e["event"] for e in events] == ["chunk"] * 3
    assert "".join(e["data"] for e in events if e["stream"] == "stdout") == "line 1\nline 2\n"
    assert envelope["stdout"] == payload["stdout"] == captured.out == "line 1\nline 2\n"
    assert envelope["stderr"] == payload["stderr"] == "err\n"
    assert captured.err == "err\n[exit code: 5]\n"
    assert "[exit code" not in captured.out


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
    monkeypatch.setattr(qmp_cmds, "qmu_bridge_attached", lambda inst: True)
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


_RAW_RESET_ARGV = {k: v for k, v in _RESET_ARGV.items() if "system_reset" in k}


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory modes")
@pytest.mark.parametrize("fmt", ["json", "ndjson", "text"])
@pytest.mark.parametrize("command", sorted(_RAW_RESET_ARGV))
def test_raw_reset_with_unwritable_metadata_emits_exactly_one_envelope(
    command, fmt, cache, monkeypatch, capsys
):
    """Axis 2 (branch vs branch) x the cross-product the reviewer named:
    metadata persistence failure + raw reset (#88). The reset reaches the
    guest; only the epoch persist fails. That is ONE outcome and must be ONE
    envelope -- `ok:false`, the QMP result still inside it, exit 4 -- not a
    success object followed by a failure object, which a consumer reading
    the first document accepted as the result."""
    from qmu.commands import qmp_cmds
    import contextlib

    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 7.0.0\nlocalhost login:\n")
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    qmp = _MutatingQMP(inst.serial_log)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(qmp))
    idir = cache / "instances"
    before = Path(inst.serial_log).stat().st_size

    idir.chmod(0o500)
    try:
        rc = cli.main(["--format", fmt, *_RAW_RESET_ARGV[command]])
        captured = capsys.readouterr()
    finally:
        idir.chmod(0o755)

    assert rc == 4, f"`qmu {command}` exit {rc}: {captured.out}{captured.err}"
    # The mutation itself landed (the fake grew the log, as a real reset
    # prints a new banner) and nothing was persisted.
    assert Path(inst.serial_log).stat().st_size > before
    assert instance_mod.load_instance(VM) is None
    if fmt == "text":
        assert captured.out == "", f"`qmu {command}` wrote a failure to stdout"
        assert captured.err.startswith("[qmu] Error:"), captured.err
        return
    documents = [line for line in captured.out.splitlines() if line.strip()]
    if fmt == "ndjson":
        assert len(documents) == 1, captured.out
        payload = json.loads(documents[0])
    else:
        payload = json.loads(captured.out)  # exactly one object or this raises
    assert payload["ok"] is False
    assert payload["error_type"] == "PermissionError"
    assert payload["guest_mutated"] is True
    assert str(idir) in payload["error"]
    # The QMP result the reset produced is still in the envelope.
    assert ("result" in payload) or ("output" in payload), payload
    assert f"qmu status --vm {VM}" in payload["hint"]


# ---------------------------------------------------------------------------
# A `snapshot load` that failed AFTER restoration began (#87). QEMU reverts
# the disks before it loads the vmstate, so when the vmstate load fails
# (a snapshot saved under one NIC model loaded into a boot with another --
# receipt 165, QEMU 8.2.2) the paused machine is pre-snapshot devices over
# post-snapshot disks. qmu used to `cont` it and report `resumed: true`;
# `status` then said `unknown`/SSH down on a machine `exec` happily tried.
# Now the load leaves it paused and says so, and `status` + every SSH
# command agree it is paused. The sibling cell -- a refusal QEMU made before
# touching the machine -- keeps the guest running and `exec` serving.
# ---------------------------------------------------------------------------


_INCOMPATIBLE_DEVICE_LOAD = (
    'Unknown ramblock "0000:00:03.0/e1000.rom", cannot accept migration\r\n'
    "error while loading state for instance 0x0 of device 'ram'\r\n"
    "Error: Error -22 while loading VM state"
)


class _LoadvmQMP:
    """One QEMU for every authority: `loadvm` answers `failure` and, like
    `hmp_loadvm`, stops the guest first (`restore-vm`); `cont` is recorded
    and honoured so a blind resume shows up as a wrong `status`."""

    def __init__(self, failure):
        self._failure = failure
        self.running = True
        self.status = "running"
        self.cont_sent = 0

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            return {"running": self.running, "status": self.status}
        if command == "cont":
            self.cont_sent += 1
            self.running, self.status = True, "running"
        if command == "human-monitor-command":
            return self.execute_hmp(arguments["command-line"])
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        if command_line == "info snapshots":
            return (
                "List of snapshots present on all disks:\n"
                "ID        TAG               VM SIZE                DATE       VM CLOCK\n"
                "--        clean             486 MiB 2026-05-28 23:11:52 0000:01:01.992\n"
                "--        good              486 MiB 2026-05-28 23:20:00 0000:01:30.000\n"
            )
        if command_line == "loadvm good":
            # A compatible tag: QEMU loads it and, as `hmp_loadvm` does,
            # restarts the guest only if it was running before.
            return ""
        if command_line.startswith("loadvm "):
            self.running, self.status = False, "restore-vm"
            return self._failure
        return ""


def _loadvm_subject(cache, monkeypatch, failure):
    from qmu import _cliutil
    from qmu.commands import qmp_cmds
    import contextlib

    inst = _ssh_capable_instance(cache)
    with open(inst.serial_log, "w") as stream:
        stream.write("[ 0.0] Linux version 6.12.0 (x) #1\nlocalhost login:\n")
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    for mod in (lifecycle, guest_mod, qmp_cmds):
        monkeypatch.setattr(mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    qmp = _LoadvmQMP(failure)
    for mod in (lifecycle, _cliutil, qmp_cmds):
        monkeypatch.setattr(mod, "_qmp_ctx", lambda inst: contextlib.nullcontext(qmp))
    monkeypatch.setattr(guest_mod.time, "sleep", lambda _: None)
    return inst, qmp


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_status_and_ssh_commands_agree_a_partially_restored_guest_is_paused(
    fmt, cache, monkeypatch, capsys
):
    inst, qmp = _loadvm_subject(cache, monkeypatch, _INCOMPATIBLE_DEVICE_LOAD)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: (_ for _ in ()).throw(AssertionError("SSH probed on a paused guest")),
    )
    monkeypatch.setattr(
        guest_mod, "_make_ssh",
        lambda selected: (_ for _ in ()).throw(AssertionError("SSH attempted")),
    )

    rc = cli.main(["--format", "json", "snapshot", "load", "clean", "--vm", VM])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert {
        "ok": payload["ok"],
        "resumed": payload["resumed"],
        "guest_paused": payload["guest_paused"],
        "restore_state": payload["restore_state"],
    } == {"ok": False, "resumed": False, "guest_paused": True, "restore_state": "partial"}
    assert qmp.cont_sent == 0
    assert qmp.running is False
    assert f"qmu kill --vm {VM}" in payload["hint"]
    assert "Resume with" not in payload["hint"]

    rc = cli.main(["--format", fmt, "status", "--vm", VM])
    out = capsys.readouterr().out
    assert rc == 0
    if fmt == "json":
        status = json.loads(out)
        assert status["guest"] == "paused"
        assert status["qemu_status"] == "restore-vm"
    else:
        assert "Guest:     paused" in out

    for command, argv in _PANICKED_ARGV.items():
        rc = cli.main(["--format", fmt, *argv])
        captured = capsys.readouterr()
        assert rc == 1, f"`qmu {command}` rc={rc}"
        if fmt == "json":
            refusal = json.loads(captured.out)
            assert refusal["ok"] is False, command
            assert refusal["guest_state"] == "paused", command
            assert refusal["qemu_status"] == "restore-vm", command
            assert refusal["ssh_error"] is False, command
            assert refusal["crash_detected"] is False, command
        else:
            assert captured.out == "", f"`qmu {command}` wrote a refusal to stdout"
            assert captured.err.startswith("[qmu] Error:"), f"`qmu {command}`"
            assert "restore-vm" in captured.err, f"`qmu {command}`"
    assert qmp.cont_sent == 0

    # `cont` is the one command whose whole job is the resume the hint
    # forbids (#110): it must refuse like `exec` does, name the same
    # recovery, and send nothing — unless the caller overrides.
    rc = cli.main(["--format", fmt, "cont", "--vm", VM])
    captured = capsys.readouterr()
    assert rc == 1
    assert qmp.cont_sent == 0, "`qmu cont` resumed a partially restored guest"
    if fmt == "json":
        refusal = json.loads(captured.out)
        assert refusal["ok"] is False
        assert refusal["qemu_status"] == "restore-vm"
        assert f"qmu kill --vm {VM}" in refusal["hint"]
        assert "--force" in refusal["hint"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("[qmu] Error:")
        assert "restore-vm" in captured.err
    rc = cli.main(["--format", "json", "status", "--vm", VM])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["qemu_status"] == "restore-vm"

    # The recovery the hint names: a known-good load succeeds AND resumes
    # the guest (QEMU alone restarts only a guest that was running before),
    # so `status` and `exec` go straight back to serving.
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: _ServingSSH())
    monkeypatch.setattr(guest_mod, "_make_ssh", lambda selected: _ServingSSH(0, "up\n"))
    rc = cli.main(["--format", "json", "snapshot", "load", "good", "--vm", VM])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["resumed"] is True
    assert qmp.cont_sent == 1
    assert qmp.running is True
    rc = cli.main(["--format", "json", "status", "--vm", VM])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["guest"] == "serving"
    rc = cli.main(["--format", "json", "exec", "--vm", VM, "true"])
    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert result["stdout"] == "up\n"


_LOAD_CLEAN_ARGV = {
    "snapshot load": ["snapshot", "load", "clean", "--vm", VM],
    "monitor loadvm": ["monitor", "loadvm", "clean", "--vm", VM],
    "qmp human-monitor-command loadvm": [
        "qmp", "human-monitor-command", "--args", '{"command-line": "loadvm clean"}',
        "--vm", VM,
    ],
}


@pytest.mark.parametrize("route", sorted(_LOAD_CLEAN_ARGV))
def test_pre_restore_refusal_keeps_the_guest_serving(route, cache, monkeypatch, capsys):
    """The sibling cell: QEMU said no before restoring anything (the tag is
    listed -- a partial snapshot passes the listing pre-check -- but loadvm
    refuses it), so the guest is exactly what it was and is resumed; `status`
    says serving and `exec` runs. The raw routes reach the same `hmp_loadvm`,
    which stops the guest before it looks for the tag, and used to leave it
    in `restore-vm` with a `qmu cont` hint that `cont` refused (#206): one
    answer on every route."""
    inst, qmp = _loadvm_subject(
        cache, monkeypatch, "Error: Snapshot 'clean' does not exist in one or more devices"
    )
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: _ServingSSH())
    monkeypatch.setattr(guest_mod, "_make_ssh", lambda selected: _ServingSSH(0, "up\n"))

    rc = cli.main(["--format", "json", *_LOAD_CLEAN_ARGV[route]])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert {
        "ok": payload["ok"],
        "resumed": payload["resumed"],
        "guest_paused": payload["guest_paused"],
        "restore_state": payload["restore_state"],
    } == {"ok": False, "resumed": True, "guest_paused": False, "restore_state": "none"}
    assert qmp.cont_sent == 1
    assert qmp.running is True
    assert f"qmu snapshot list --vm {VM}" in payload["hint"]

    rc = cli.main(["--format", "json", "status", "--vm", VM])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["guest"] == "serving"

    rc = cli.main(["--format", "json", "exec", "--vm", VM, "true"])
    result = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert result["ok"] is True
    assert result["stdout"] == "up\n"


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


@pytest.mark.parametrize("fmt", ["json", "ndjson", "text"])
def test_launch_ssh_timeout_is_the_timeout_class_in_every_format(
    fmt, tmp_path, monkeypatch, capsys
):
    """Axis 3/4 (text vs JSON, subcommand vs subcommand): an expired
    `--ssh-timeout` is exit 124 in every format — the code `run` exits for the
    same condition — with the VM retained, never the transport class (4) one
    verb used while its sibling said 124 (#72). The envelope shape is the one
    `tests/test_run_command.py::SSH_TIMEOUT_ENVELOPE_KEYS` pins for `run`."""
    SSH_TIMEOUT_ENVELOPE_KEYS = {
        "ok", "error", "error_type", "timed_out", "ssh_error", "hint",
    }

    _launch_subject(tmp_path, monkeypatch, serial_text="[0.0] Linux\n", ready=False)

    rc = cli.main(["--format", fmt, "launch", "--name", VM, "--ssh-timeout", "0"])
    captured = capsys.readouterr()

    assert rc == 124
    if fmt == "text":
        assert "timeout" in captured.out
        assert "[qmu] Error: SSH did not become ready" in captured.err
        assert f"qmu log --vm {VM} --tail 50" in captured.err
    else:
        payload = json.loads(captured.out)
        assert SSH_TIMEOUT_ENVELOPE_KEYS <= set(payload)
        assert payload["ok"] is False
        assert payload["timed_out"] is True
        assert payload["ssh_error"] is True
        assert payload["error_type"] == "TimeoutError"
        assert payload["ssh_status"] == "timeout"
        assert f"qmu log --vm {VM} --tail 50" in payload["hint"]
    # Retained: `status` answers afterwards, never "not found".
    assert instance_mod.load_instance(VM) is not None


# ---------------------------------------------------------------------------
# Every `ok: false` envelope carries a `hint` (#74), whichever exception class
# produced it and whichever JSON format was asked for. Measured live before
# this row: `qmu status --vm nope --format json` was `{ok, error, error_type}`
# and an agent had to guess the recovery from prose.
# ---------------------------------------------------------------------------


def _raise(exc):
    def handler(args):
        raise exc
    return handler


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
@pytest.mark.parametrize(
    "exc,rc,expected",
    [
        (
            instance_mod.QMUError("boom"),
            1,
            f"qmu status --vm {VM} for VM state; qmu doctor for the host environment",
        ),
        (
            instance_mod.QMUError("boom", hint="relaunch with --ssh-port 10022"),
            1,
            "relaunch with --ssh-port 10022",
        ),
        (SSHError("ssh died"), 4, f"qmu status --vm {VM}; qmu log --vm {VM} --tail 50"),
        (
            RuntimeError("unexpected"),
            4,
            f"qmu status --vm {VM} for VM state; qmu doctor for the host environment",
        ),
    ],
    ids=["qmu-default", "qmu-specific", "ssh-default", "catch-all"],
)
def test_every_error_envelope_carries_a_hint(fmt, exc, rc, expected, monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "_handle_status", _raise(exc))

    assert cli.main(["--format", fmt, "status", "--vm", VM]) == rc
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["ok"] is False
    assert payload["error_type"] == type(exc).__name__
    assert expected in payload["hint"]
    if fmt == "ndjson":
        assert captured.out.count("\n") == 1


def test_text_mode_prints_only_a_specific_hint(monkeypatch, capsys):
    """Axis 3: text stays quiet on the type default and prints `[qmu] Hint:`
    only when the raise site named a recovery."""
    monkeypatch.setattr(lifecycle, "_handle_status", _raise(instance_mod.QMUError("boom")))
    assert cli.main(["status", "--vm", VM]) == 1
    assert "Hint" not in capsys.readouterr().err

    monkeypatch.setattr(
        lifecycle, "_handle_status",
        _raise(instance_mod.QMUError("boom", hint="pass --ssh-port N")),
    )
    assert cli.main(["status", "--vm", VM]) == 1
    err = capsys.readouterr().err
    assert "[qmu] Error: boom\n[qmu] Hint: pass --ssh-port N\n" in err


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_result_warnings_reach_stderr_and_the_envelope(fmt, monkeypatch, capsys):
    """Axis 3: a `Result.warn(...)` line goes to stderr in every mode AND to the
    envelope's `warnings[]` (#74), prefix-stripped, merged with any
    `warnings` the handler already put in its data, without duplicates."""
    from qmu._cliutil import Result

    def handler(args):
        return Result(
            data={"ok": True, "warnings": ["already here"]},
            text="fine",
        ).warn("[qmu] WARNING: VM 'x' has a GDB stub\n", "[qmu] Warning: already here\n")

    monkeypatch.setattr(lifecycle, "_handle_status", handler)

    assert cli.main(["--format", fmt, "status", "--vm", VM]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert payload["warnings"] == ["already here", "VM 'x' has a GDB stub"]
    assert "[qmu] WARNING: VM 'x' has a GDB stub\n" in captured.err


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
# A VM killed under an in-flight `wait` (#118): bare and `--pattern` waits
# must agree the process EXITED — 0/process_exited and 1/process_exited —
# whoever owned their liveness: the standalone loop, the daemon's watch, or
# a daemon that released them mid-wait (explicit `unwatch`, its own
# shutdown). The daemon-backed pair used to burn their whole timeout
# (124, `stopped: false`, `last_event: SHUTDOWN`) after a kill that had
# released the watch first.
# ---------------------------------------------------------------------------


def _wait_owner(monkeypatch, owner):
    """Who owns the wait's liveness, and the terminal transition it delivers."""
    if owner == "standalone":
        _qmp(monkeypatch, True)
        return
    state = {
        "watched": True, "running": True, "qemu_status": "running", "panicked": False,
        "exited": False, "last_event": None, "epoch_offset": 0,
        "epoch_source": "banner", "boot_offset": 0,
    }
    monkeypatch.setattr(lifecycle, "_daemon_state", lambda inst, adopt=True: dict(state))
    if owner == "released":
        _qmp(monkeypatch, True)
        monkeypatch.setattr(lifecycle.daemon_client, "mark_released", lambda vm_id: None)

        def released(args, inst, *, pattern=None, start_offset=None, warnings=None):
            raise lifecycle._WaitReleased(
                f"[qmu] Note: the daemon released VM '{inst.vm_id}' mid-wait (an "
                "explicit unwatch or a daemon shutdown); the wait finished "
                "standalone on PID liveness.\n"
            )

        monkeypatch.setattr(lifecycle, "_daemon_wait_request", released)
        return
    monkeypatch.setattr(
        lifecycle, "_qmp_ctx",
        lambda inst: pytest.fail("opened QMP while the daemon serves the VM"),
    )

    def exited(args, inst, *, pattern=None, start_offset=None, warnings=None):
        if pattern is None:
            return {
                "stopped": True, "reason": "process_exited", "elapsed": 0.7,
                "running": False, "qemu_status": "shutdown", "last_event": "SHUTDOWN",
                "event_data": {"source": "qmp", "guest": False}, "boot_offset": 0,
                "panicked": False, "exited": True,
            }
        return {
            "matched_line": None, "reason": "process_exited", "terminal_panic_seen": False,
            "elapsed": 0.7, "scan_offset": start_offset or 0, "exited": True,
        }

    monkeypatch.setattr(lifecycle, "_daemon_wait_request", exited)


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("owner", ["standalone", "daemon", "released"])
def test_bare_and_pattern_wait_agree_that_a_killed_vm_exited(
    fmt, owner, cache, monkeypatch, capsys
):
    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 6.12.0 (x) #1\n[ 1.0] serving\n")
    _register_running(monkeypatch, inst)
    _wait_owner(monkeypatch, owner)
    # The kill lands after the wait began: the recorded identity is gone on
    # the first liveness check either loop makes.
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: False)
    monkeypatch.setattr(lifecycle, "remove_instance", lambda vm_id: None)

    bare_rc = cli.main(["--format", fmt, "wait", "--vm", VM, "--timeout", "5", "--no-clean"])
    bare = capsys.readouterr()
    pattern_rc = cli.main([
        "--format", fmt, "wait", "--vm", VM, "--pattern", "^NEVER_UNIQUE$", "--timeout", "5",
    ])
    pattern = capsys.readouterr()

    assert (bare_rc, pattern_rc) == (0, 1), (owner, bare.out, pattern.out)
    for captured in (bare, pattern):
        assert "not found" not in captured.out + captured.err
        assert "still running" not in captured.out and "Timed out" not in captured.out
    if fmt == "json":
        bare_payload, pattern_payload = json.loads(bare.out), json.loads(pattern.out)
        assert bare_payload["stopped"] is True and bare_payload["reason"] == "process_exited"
        assert bare_payload["guest"] is None and "hint" not in bare_payload
        assert pattern_payload["matched"] is False
        assert pattern_payload["reason"] == "process_exited"
        assert "qmu log --vm" in pattern_payload["hint"]
        released = [
            w for p in (bare_payload, pattern_payload)
            for w in p.get("warnings", []) if "released VM" in w
        ]
        assert len(released) == (2 if owner == "released" else 0), released
    else:
        assert f"VM '{VM}' stopped (process_exited" in bare.out
        assert f"VM '{VM}' exited after" in pattern.out and "without matching" in pattern.out
        notes = (bare.err + pattern.err).count("released VM")
        assert notes == (2 if owner == "released" else 0), (bare.err, pattern.err)


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


# ---------------------------------------------------------------------------
# A malformed `.json` plus a `.qemu.log` (#109): held back at ANY age. Every
# reporter must name the real refusal — unreadable metadata — and none may
# prescribe `--older-than 0`, which can never clear it.
# ---------------------------------------------------------------------------


def _malformed_metadata_remnant(cache, monkeypatch):
    idir = cache / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    json_path = idir / f"{VM}.json"
    json_path.write_text("{not json")
    (idir / f"{VM}.qemu.log").write_text("qemu\n")
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [])
    return json_path


def test_malformed_metadata_is_held_back_for_its_own_reason(cache, monkeypatch):
    json_path = _malformed_metadata_remnant(cache, monkeypatch)
    for older in (86400.0, 0.0):
        info = classify_vm(VM, older_than_seconds=older)
        assert (info["state"], info["held_reason"], info["held_path"]) == (
            VM_HELD_BACK, "malformed-metadata", str(json_path)
        )
    _write_remnant(cache, "young")
    assert classify_vm("young")["held_reason"] == "age"
    assert classify_vm("young", older_than_seconds=0.0)["held_reason"] is None


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_malformed_metadata_reason_agrees_across_status_list_kill_and_prune(
    fmt, cache, monkeypatch, capsys
):
    json_path = _malformed_metadata_remnant(cache, monkeypatch)
    _decoy_running(monkeypatch)

    outputs = {}
    for name, argv in {
        "list": ["list"],
        "status": ["status", "--vm", VM],
        "kill": ["kill", "--vm", VM],
        "prune --vm --dry-run": ["prune", "--vm", VM, "--older-than", "0", "--dry-run"],
        "prune --vm": ["prune", "--vm", VM, "--older-than", "0"],
        "prune --all --dry-run": ["prune", "--all", "--older-than", "0", "--dry-run"],
        "prune --all": ["prune", "--all", "--older-than", "0"],
    }.items():
        assert cli.main(["--format", fmt, *argv]) == 0, name
        outputs[name] = capsys.readouterr().out
        assert json_path.exists(), f"`qmu {name}` deleted metadata it cannot read"

    for name, out in outputs.items():
        assert VM in out, f"`qmu {name}` omits the remnant"
        assert "not found" not in out and "No running VMs" not in out, name
        # The age gate is not why it stayed; prescribing the flag the caller
        # just used sends them around the loop forever.
        assert "--older-than 0" not in out, f"`qmu {name}` advertises the age gate"
        assert "Held back by the --older-than" not in out, name
        assert str(json_path) in out, f"`qmu {name}` does not name the unreadable file"

    if fmt == "json":
        row = next(r for r in json.loads(outputs["list"])["vms"] if r["vm_id"] == VM)
        status = json.loads(outputs["status"])
        killed = json.loads(outputs["kill"])
        prunes = {k: json.loads(v) for k, v in outputs.items() if k.startswith("prune")}
        assert (row["status"], row["held_back"], row["held_reason"]) == (
            "stopped", True, "malformed-metadata"
        )
        assert (status["status"], status["held_reason"]) == (VM_HELD_BACK, "malformed-metadata")
        assert killed["held_reason"] == "malformed-metadata"
        expected = [{"vm_id": VM, "reason": "malformed-metadata", "path": str(json_path)}]
        for name, payload in prunes.items():
            assert payload["held_back"] == [VM], name
            assert payload["refused"] == expected, name
            assert payload["pruned"] == [] and payload.get("would_prune", []) == [], name
        assert prunes["prune --vm"]["found"] is True

    # Still there after every command, and `status` has not changed its mind.
    assert cli.main(["--format", "json", "status", "--vm", VM]) == 0
    assert json.loads(capsys.readouterr().out)["held_reason"] == "malformed-metadata"


# ---------------------------------------------------------------------------
# `cont --force` is the explicit opt-out of the restore-vm refusal (#110).
# ---------------------------------------------------------------------------


def test_cont_force_resumes_a_partially_restored_guest(cache, monkeypatch, capsys):
    inst, qmp = _loadvm_subject(cache, monkeypatch, _INCOMPATIBLE_DEVICE_LOAD)
    assert cli.main(["--format", "json", "snapshot", "load", "clean", "--vm", VM]) == 1
    capsys.readouterr()
    assert qmp.running is False

    assert cli.main(["--format", "json", "cont", "--vm", VM]) == 1
    capsys.readouterr()
    assert qmp.cont_sent == 0

    rc = cli.main(["--format", "json", "cont", "--vm", VM, "--force"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert qmp.cont_sent == 1 and qmp.running is True
    assert payload == {"ok": True, "vm_id": VM, "status": "running", "forced": True}

    # And `status` now agrees the guest is no longer halted.
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: _ServingSSH())
    assert cli.main(["--format", "json", "status", "--vm", VM]) == 0
    assert json.loads(capsys.readouterr().out)["qemu_status"] == "running"


# ---------------------------------------------------------------------------
# `snapshot save` whose budget expired (#73). HMP `savevm` keeps running on
# QEMU's main loop after the client gives up, and usually lands; the window
# closed, the result is UNKNOWN. Exit 124 (the `wait` timeout code, not 4 —
# the transport did not break), `may_have_landed: true`, and the hint names
# the one command that settles it with a budget that outlasts the save. Text
# and JSON say the same; a proven HMP failure says `may_have_landed: false`.
# ---------------------------------------------------------------------------


class _WedgedSavevmQMP:
    """QEMU whose `savevm` outlives every budget; `info snapshots` answers."""

    def __init__(self):
        self.closed = False

    def execute(self, command, arguments=None, timeout=30.0):
        return {"running": True, "status": "running"}

    def execute_hmp(self, command_line, timeout=30.0):
        from qmu.qmp import QMPTimeoutError

        if command_line.startswith("savevm "):
            self.closed = True
            raise QMPTimeoutError(f"human-monitor-command '{command_line}'", timeout)
        if command_line == "info snapshots":
            return (
                "List of snapshots present on all disks:\r\n"
                "ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT\r\n"
                "--        clean             325 MiB 2026-10-16 23:24:01 00:00:29.574\r\n"
            )
        return ""


def _savevm_subject(cache, monkeypatch):
    from qmu.commands import qmp_cmds
    import contextlib

    inst = _ssh_capable_instance(cache)
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [decoy, inst])
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    qmp = _WedgedSavevmQMP()
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(qmp))
    return inst, qmp


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_snapshot_save_timeout_is_an_unknown_result_in_text_and_json(
    fmt, cache, monkeypatch, capsys
):
    inst, qmp = _savevm_subject(cache, monkeypatch)
    rc = cli.main(["--format", fmt, "snapshot", "save", "clean", "--vm", VM, "--timeout", "7"])
    captured = capsys.readouterr()
    assert rc == 124, captured.err
    follow_up = f"qmu snapshot list --vm {VM} --timeout 300"
    if fmt == "text":
        assert captured.out == ""
        assert captured.err.startswith("[qmu] Error: snapshot save 'clean'"), captured.err
        assert "did not finish within 7s" in captured.err
        assert "may_have_landed: true" in captured.err
        assert follow_up in captured.err
        assert "snapshot save failed" not in captured.err
    else:
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error_type"] == "SnapshotError"
        assert payload["name"] == "clean"
        assert payload["timeout"] == 7.0
        assert payload["may_have_landed"] is True
        assert "did not finish within 7s" in payload["error"]
        assert follow_up in payload["hint"]
        assert "message" not in payload
    # No "temporary overlay" lecture: the save did not fail, it is unknown.
    assert "snapshot=on" not in captured.err

    # The follow-up the hint names works and honours its own budget.
    rc = cli.main(["--format", "json", "snapshot", "list", "--vm", VM, "--timeout", "300"])
    listed = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert [s["tag"] for s in listed["snapshots"]] == ["clean"]


def test_snapshot_save_default_budget_scales_with_guest_memory(cache, monkeypatch, capsys):
    from qmu.commands import qmp_cmds
    from qmu.snapshot import savevm_timeout

    inst, qmp = _savevm_subject(cache, monkeypatch)
    seen = {}

    def save(qmp, name, timeout):
        seen["timeout"] = timeout
        raise __import__("qmu.qmp", fromlist=["QMPTimeoutError"]).QMPTimeoutError("x", timeout)

    monkeypatch.setattr(qmp_cmds, "save_snapshot", save)
    assert cli.main(["--format", "json", "snapshot", "save", "clean", "--vm", VM]) == 124
    payload = json.loads(capsys.readouterr().out)
    assert seen["timeout"] == savevm_timeout("4G") == 140.0
    assert payload["timeout"] == 140.0
    # Twice the budget is the follow-up's budget once it exceeds the 300 s floor.
    assert f"--timeout 300" in payload["hint"]


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_snapshot_save_hmp_failure_is_a_proven_non_landing(fmt, cache, monkeypatch, capsys):
    from qmu.commands import qmp_cmds
    from qmu.snapshot import SnapshotResult

    inst, qmp = _savevm_subject(cache, monkeypatch)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot",
        lambda qmp, name, timeout: SnapshotResult(False, "Error: boom", reason="hmp"),
    )
    rc = cli.main(["--format", fmt, "snapshot", "save", "clean", "--vm", VM])
    captured = capsys.readouterr()
    assert rc == 1
    if fmt == "json":
        payload = json.loads(captured.out)
        assert payload["may_have_landed"] is False
        assert "timeout" not in payload
    else:
        assert captured.err.startswith("[qmu] Error: snapshot save failed")
        assert "may_have_landed" not in captured.err


# ---------------------------------------------------------------------------
# The SSH probe's cost is an observable (#77): `status` and `list` report the
# same `ssh_probe_ms` for the same probe, null whenever no probe was sent, and
# the status text carries the same number.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ready", [True, False])
def test_status_and_list_agree_on_the_ssh_probe_duration(ready, cache, monkeypatch, capsys):
    inst = _ssh_capable_instance(cache)
    with open(inst.serial_log, "w") as stream:
        stream.write("[ 0.0] Linux version 6.12.0 (x) #1\nlocalhost login:\n")
    decoy = _decoy_running(monkeypatch)
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "list_stopped_instances", lambda: [])
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_query_qmp", lambda i: lifecycle._QMPProbe(
        lifecycle.QMP_CONNECTED, status="running", running=True
    ))

    class SlowSSH:
        def is_ready(self, timeout=2):
            time.sleep(0.05)
            return ready

    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: SlowSSH())

    assert cli.main(["--format", "json", "status", "--vm", VM]) == 0
    status = json.loads(capsys.readouterr().out)
    assert cli.main(["--format", "json", "list"]) == 0
    row = next(r for r in json.loads(capsys.readouterr().out)["vms"] if r["vm_id"] == VM)
    assert cli.main(["status", "--vm", VM]) == 0
    text = capsys.readouterr().out

    for payload in (status, row):
        assert isinstance(payload["ssh_probe_ms"], int)
        assert payload["ssh_probe_ms"] >= 50
        assert payload["ssh"] == ("ready" if ready else "down")
    # The text run sends its own probe, so its duration is its own (two real
    # sleeps differ by a millisecond under load); it must carry a number of
    # the same kind next to the same SSH word.
    m = re.search(r"SSH:       port 10099 \((\w+), probe (\d+) ms\)", text)
    assert m is not None, text
    assert m.group(1) == status["ssh"] and int(m.group(2)) >= 50


def test_ssh_probe_duration_is_null_when_no_probe_was_sent(cache, monkeypatch, capsys):
    inst = _ssh_capable_instance(cache)
    with open(inst.serial_log, "w") as stream:
        stream.write("[ 0.0] Linux version 6.12.0 (x) #1\nKernel panic - not syncing: boom\n")
    for mod in (lifecycle, instance_mod):
        monkeypatch.setattr(mod, "list_instances", lambda: [inst])
        monkeypatch.setattr(mod, "find_orphan_qemus", lambda: [], raising=False)
    monkeypatch.setattr(lifecycle, "list_stopped_instances", lambda: [])
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        lifecycle, "_make_ssh",
        lambda i: (_ for _ in ()).throw(AssertionError("SSH probed on a panicked guest")),
    )
    assert cli.main(["--format", "json", "status", "--vm", VM]) == 0
    status = json.loads(capsys.readouterr().out)
    assert cli.main(["--format", "json", "list"]) == 0
    row = next(r for r in json.loads(capsys.readouterr().out)["vms"] if r["vm_id"] == VM)
    assert status["guest"] == row["guest"] == "panicked"
    assert status["ssh_probe_ms"] is None and row["ssh_probe_ms"] is None
    assert status["ssh"] == row["ssh"] == "skipped"


# ---------------------------------------------------------------------------
# Every failed *Result* carries a result-specific `hint` (#120, reopened #74).
# The #74 row above covers exception envelopes; wave 6 shipped it for those
# only, and the ordinary domain outcomes — `wait` timing out, `crash` finding
# nothing, `doctor` unhealthy, a guest command exiting 7 — were `ok: false`
# with no recovery at all. `render` now backstops any `ok: false` without a
# hint with a neutral generic; this row pins that the known producers do NOT
# lean on it (the generic is the one string every case must NOT equal) and
# that the hint never sends the reader to `qmu doctor` for a guest/caller
# condition.
# ---------------------------------------------------------------------------


class _TimeoutSSH(_ServingSSH):
    """A guest that answers the liveness probe but whose command outlives
    --timeout: `ssh.run` raises the SSHError the client raises on expiry."""

    def run(self, command, timeout=30.0, check=False, **kwargs):
        raise SSHError(f"SSH command timed out after {timeout}s: {command}", stdout="", stderr="")


def _wait_timeout_case(cache, monkeypatch):
    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 6.12.0 (x) #1\nbooted\n")
    _qmp(monkeypatch, True)
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)
    return ["wait", "--vm", VM, "--pattern", "^NEVER$", "--timeout", "0"], 124, ("--timeout",)


def _crash_none_case(cache, monkeypatch):
    inst = _vm_with_log(cache, VM, "[ 0.0] Linux version 6.12.0 (x) #1\nbooted\n")
    _register_running(monkeypatch, inst)
    monkeypatch.setattr(guest_mod, "find_instance", lambda vm=None: inst)
    return (
        ["crash", "--vm", VM], 1,
        (f"qmu log --vm {VM} --tail 200", f"qmu crash --vm {VM} --full-history"),
    )


def _doctor_unhealthy_case(cache, monkeypatch):
    from qmu.config import QMUConfig

    config = QMUConfig(
        arch="x86_64", net_backend="user", kernel=str(cache / "missing-bzImage"),
        rootfs=None, ssh_key=None, _sources=["config: fixture"],
    )
    monkeypatch.setattr(lifecycle, "resolve_config", lambda **kwargs: config)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [])
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    monkeypatch.setattr(lifecycle, "all_skill_source_dirs", lambda: [])
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: [])
    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: None)
    return ["doctor"], 1, ("Fix the [!] row(s)", "checks[]")


def _guest_exit_case(cache, monkeypatch):
    _serving_subject(cache, monkeypatch, _ServingSSH(7, "", "boom\n"))
    return ["exec", "--vm", VM, "false"], 1, ("exited 7", "stderr")


def _guest_timeout_case(cache, monkeypatch):
    _serving_subject(cache, monkeypatch, _TimeoutSSH())
    return ["exec", "--vm", VM, "--timeout", "2", "sleep 10"], 124, ("--timeout",)


def _compile_failure_case(cache, monkeypatch, tmp_path):
    _serving_subject(cache, monkeypatch, _ServingSSH(1, "", "x.c:1: error\n"))
    source = tmp_path / "x.c"
    source.write_text("int main(){}")
    return ["compile", "--vm", VM, str(source)], 1, ("compile_stderr", "--cflags")


def _dmesg_failure_case(cache, monkeypatch):
    _serving_subject(cache, monkeypatch, _ServingSSH(1, "", "dmesg: read kernel buffer failed\n"))
    return ["dmesg", "--vm", VM], 1, ("dmesg exited 1", f"qmu log --vm {VM} --tail 100")


def _snapshot_refusal_case(cache, monkeypatch):
    from qmu.commands import qmp_cmds
    from qmu.snapshot import SnapshotResult

    _savevm_subject(cache, monkeypatch)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot",
        lambda qmp, name, timeout: SnapshotResult(False, "Error: boom", reason="hmp"),
    )
    return ["snapshot", "save", "clean", "--vm", VM], 1, ("snapshot",)


def _prune_refusal_case(cache, monkeypatch):
    serial = _write_remnant(cache)
    orphan = {"pid": 4242, "serial_log": str(serial), "cmdline": "qemu"}
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [orphan])
    monkeypatch.setattr(instance_mod, "find_orphan_qemus", lambda: [orphan])

    def refuse(pid, sig):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(lifecycle.os, "kill", refuse)
    return ["prune", "--orphans"], 1, ("4242", "ps -o user,pid,cmd")


_FAILED_RESULT_CASES = {
    "wait-timeout": _wait_timeout_case,
    "crash-none": _crash_none_case,
    "doctor-unhealthy": _doctor_unhealthy_case,
    "guest-exit-7": _guest_exit_case,
    "guest-timeout": _guest_timeout_case,
    "compile-failure": _compile_failure_case,
    "dmesg-failure": _dmesg_failure_case,
    "snapshot-refusal": _snapshot_refusal_case,
    "prune-refusal": _prune_refusal_case,
}


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
@pytest.mark.parametrize("case", list(_FAILED_RESULT_CASES))
def test_every_failed_result_carries_a_specific_hint(case, fmt, cache, monkeypatch, capsys, tmp_path):
    from qmu import _cliutil

    build = _FAILED_RESULT_CASES[case]
    argv, rc, expected = (
        build(cache, monkeypatch, tmp_path) if case == "compile-failure"
        else build(cache, monkeypatch)
    )
    generic = _cliutil._BACKSTOP_HINT.format(vm=VM)

    assert cli.main(["--format", fmt, *argv]) == rc
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["ok"] is False
    hint = payload.get("hint")
    assert isinstance(hint, str) and hint, f"{case}: no hint in {sorted(payload)}"
    assert hint != generic, f"{case} relies on the render backstop"
    for fragment in expected:
        assert fragment in hint, f"{case}: {hint!r} lacks {fragment!r}"
    assert "qmu doctor" not in hint or case == "doctor-unhealthy", case
    if fmt == "ndjson":
        assert out.count("\n") == 1


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_render_backstops_a_failed_result_without_a_hint(fmt, monkeypatch, capsys):
    """The safety net, in isolation: a handler that forgot the hint still
    produces an envelope with one (neutral, no `qmu doctor`); a successful
    Result is left alone."""
    from qmu._cliutil import Result

    monkeypatch.setattr(
        lifecycle, "_handle_status",
        lambda args: Result(data={"ok": False, "vm_id": VM}, text="nope", stem="status", exit_code=1),
    )
    assert cli.main(["--format", fmt, "status", "--vm", VM]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["hint"] == f"qmu status --vm {VM}; qmu log --vm {VM} --tail 50"

    monkeypatch.setattr(
        lifecycle, "_handle_status",
        lambda args: Result(data={"ok": True, "vm_id": VM}, text="fine", stem="status"),
    )
    assert cli.main(["--format", fmt, "status", "--vm", VM]) == 0
    assert "hint" not in json.loads(capsys.readouterr().out)
