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

import pytest

from qmu import cli
from qmu import instance as instance_mod
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


def test_a_forged_boot_banner_cannot_hide_a_crash(cache, monkeypatch):
    """The banner must be a printk, not anything the guest can echo.

    A guest that writes a banner-shaped line to the console after a survived
    crash would otherwise scope that crash out of the label — reachable without
    trying via `dmesg` or `cat /proc/version`. The real banner carries a printk
    timestamp; a userspace echo cannot.
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
    """doctor treats only ok/info as healthy and returns 1 otherwise. A warn
    here would exit 1 on every machine that ever built a kernel, with no way to
    clear it -- breaking the health signal SKILL.md teaches."""
    (cache / "kernels").mkdir(exist_ok=True)

    cli.main(["--format", "json", "doctor"])
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}

    assert "cache" in checks
    assert checks["cache"]["status"] == "info"
    assert "qmu cache du" in checks["cache"]["detail"]


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
