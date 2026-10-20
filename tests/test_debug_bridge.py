"""pry bridge ownership (#40): `qmu gdb` records the bridge it spawns and
`debug.reap_bridge` terminates exactly that process.

The identity rule mirrors `instance_alive`: pid + /proc start-time, so a
recycled pid is never reaped. Live processes here are throwaway `sleep`s; the
pry path is exercised through a fake `pry` on PATH so no real GDB is started.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess

import pytest

from qmu import cli, debug
from qmu.instance import VMInstance, proc_pid_start, save_instance, load_instance


def _inst(tmp_path, **over):
    base = dict(
        vm_id="bridge-vm", pid=1, qmp_socket=str(tmp_path / "x.sock"),
        ssh_port=None, ssh_key=None, gdb_port=1234,
        serial_log=str(tmp_path / "x.log"), kernel="/k", rootfs=None,
        memory="1G", cpus=1, cmdline="", profile="exploit-dev",
        started_at="2026-01-01T00:00:00+00:00",
    )
    base.update(over)
    return VMInstance(**base)


@pytest.fixture
def sleeper():
    proc = subprocess.Popen(["sleep", "60"])
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def _wait_gone(proc, timeout=5.0):
    """The sleeper is OUR child, so after SIGTERM it is a zombie until waited
    on; `wait` both confirms the exit and reaps it."""
    try:
        return proc.wait(timeout=timeout) is not None
    except subprocess.TimeoutExpired:
        return False


# --- bridge_alive ------------------------------------------------------------


def test_bridge_alive_requires_a_recorded_pid(tmp_path):
    assert debug.bridge_alive(_inst(tmp_path)) is False


def test_bridge_alive_true_for_live_pid_with_matching_start(tmp_path, sleeper):
    inst = _inst(
        tmp_path, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )
    assert debug.bridge_alive(inst) is True


def test_bridge_alive_false_on_start_time_mismatch(tmp_path, sleeper):
    """A recycled pid must not pass for the bridge."""
    inst = _inst(tmp_path, gdb_bridge_pid=sleeper.pid, gdb_bridge_pid_start="1")
    assert debug.bridge_alive(inst) is False


def test_bridge_alive_false_for_dead_pid(tmp_path, sleeper):
    start = proc_pid_start(sleeper.pid)
    sleeper.kill()
    sleeper.wait()
    inst = _inst(tmp_path, gdb_bridge_pid=sleeper.pid, gdb_bridge_pid_start=start)
    assert debug.bridge_alive(inst) is False


# --- reap_bridge -------------------------------------------------------------


def test_reap_bridge_false_when_nothing_recorded(tmp_path):
    assert debug.reap_bridge(_inst(tmp_path)) is False


def test_reap_bridge_sigterm_fallback_kills_and_clears(tmp_path, sleeper, monkeypatch):
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    inst = _inst(
        tmp_path, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )
    save_instance(inst)

    assert debug.reap_bridge(inst) is True
    assert _wait_gone(sleeper)
    assert inst.gdb_bridge_pid is None
    assert inst.gdb_bridge_pid_start is None
    saved = load_instance("bridge-vm")
    assert saved.gdb_bridge_pid is None


def test_reap_bridge_prefers_pry_kill(tmp_path, sleeper, monkeypatch):
    """`pry kill --instance <pid>` is a clean gdb detach (QEMU resumes the
    vCPU); SIGTERM is only the fallback."""
    fake_pry = tmp_path / "pry"
    log = tmp_path / "pry.log"
    fake_pry.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log}"\n'
        'kill -TERM "$4"\n'
        'echo \'{"killed": true}\'\n'
    )
    fake_pry.chmod(0o755)
    monkeypatch.setattr(debug.shutil, "which", lambda name: str(fake_pry))
    inst = _inst(
        tmp_path, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )

    assert debug.reap_bridge(inst) is True
    assert log.read_text().strip() == f"kill --instance {sleeper.pid}"
    assert _wait_gone(sleeper)


def test_reap_bridge_falls_back_when_pry_kill_fails(tmp_path, sleeper, monkeypatch):
    fake_pry = tmp_path / "pry"
    fake_pry.write_text("#!/bin/sh\necho 'error: no such instance' >&2\nexit 1\n")
    fake_pry.chmod(0o755)
    monkeypatch.setattr(debug.shutil, "which", lambda name: str(fake_pry))
    inst = _inst(
        tmp_path, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )
    assert debug.reap_bridge(inst) is True
    assert _wait_gone(sleeper)


def test_reap_bridge_never_touches_a_recycled_pid(tmp_path, sleeper, monkeypatch):
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    inst = _inst(tmp_path, gdb_bridge_pid=sleeper.pid, gdb_bridge_pid_start="1")
    assert debug.reap_bridge(inst) is False
    assert sleeper.poll() is None  # still alive
    # The stale record is left as-is: nothing was reaped.
    assert inst.gdb_bridge_pid == sleeper.pid


def test_reap_bridge_never_raises_on_a_broken_record(tmp_path, monkeypatch):
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    inst = _inst(tmp_path, gdb_bridge_pid=-5, gdb_bridge_pid_start="x")
    assert debug.reap_bridge(inst) is False


def test_reap_bridge_without_instance_json_does_not_create_one(tmp_path, sleeper, monkeypatch):
    """`kill` may already have cleaned the record; reaping must not resurrect it."""
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    inst = _inst(
        tmp_path, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )
    assert debug.reap_bridge(inst) is True
    assert load_instance("bridge-vm") is None


# --- `kill` on an already-stopped VM still reaps its recorded bridge (#78) ---


def _stopped_record_with_bridge(tmp_path, sleeper, *, start):
    """A stopped instance record (dead pid, logs retained) whose `qmu gdb`
    bridge is the live sleeper."""
    serial = tmp_path / "bridge-vm.serial.log"
    serial.write_text("[    0.000000] Linux version 7.0.0 (b@h) (gcc) #1 SMP\nlogin: \n")
    inst = _inst(
        tmp_path, pid=999_999_999, pid_start="dead", serial_log=str(serial),
        gdb_bridge_pid=sleeper.pid, gdb_bridge_pid_start=start,
    )
    save_instance(inst)
    return inst, serial


def test_kill_on_a_stopped_vm_reaps_its_recorded_bridge(tmp_path, sleeper, monkeypatch, capsys):
    """Guest poweroff / external `qmp quit`, then the idempotent `kill`: QEMU
    is gone but the gdb bridge parked on its dead stub is not. The stopped
    success path must finish the same cleanup the live path does, without
    touching the retained logs."""
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    inst, serial = _stopped_record_with_bridge(
        tmp_path, sleeper, start=proc_pid_start(sleeper.pid),
    )

    rc = cli.main(["kill", "--vm", "bridge-vm", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["already_stopped"] is True
    assert payload["bridge_reaped"] is True
    assert _wait_gone(sleeper)
    assert serial.exists() and payload["logs_retained"] is True
    record = load_instance("bridge-vm")
    assert record is not None and record.gdb_bridge_pid is None


def test_kill_on_a_stopped_vm_never_signals_a_recycled_bridge_pid(
    tmp_path, sleeper, monkeypatch, capsys
):
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)
    _stopped_record_with_bridge(tmp_path, sleeper, start="1")

    rc = cli.main(["kill", "--vm", "bridge-vm", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["already_stopped"] is True
    assert payload["bridge_reaped"] is False
    assert sleeper.poll() is None, "an unrelated process wearing the pid is untouched"
    assert load_instance("bridge-vm").gdb_bridge_pid == sleeper.pid


# --- the reset warning names the KASLR re-slide (debug audit F9, #183) ------


def test_kaslr_reset_recovery_rebases_then_resyncs_with_or_without_ssh(tmp_path):
    """Run as written against live pry (#193, #203): `pry kbase` finds the
    re-slid base with no SSH and rebases the loaded vmlinux, `pry resync`
    re-arms; or `qmu kbase` over SSH feeds `resync --base`. Both stop a
    running target themselves, so no separate interrupt."""
    w = debug.reset_dropped_breakpoints_warning(_inst(tmp_path, vm_id="vm"))
    steps = (
        "pry --instance <id> kbase`", "pry --instance <id> resync`",
        "qmu kbase --vm vm", "pry --instance <id> resync --base $KBASE`",
    )
    positions = [w.index(step) for step in steps]
    assert positions == sorted(positions)
    assert "interrupt`" not in w and "<PENDING>" not in w


def test_kaslr_reset_of_a_halted_guest_resumes_after_the_rebase(tmp_path):
    """After `qmu cont` the debugger still believes the guest stopped, so
    `pry kbase`/`pry resync` halt it again: the recovery ends resuming it."""
    w = debug.reset_dropped_breakpoints_warning(
        _inst(tmp_path, vm_id="vm"), qemu_status="prelaunch"
    )
    assert w.index("qmu cont --vm vm") < w.index("kbase`") < w.index("continue --background")


def test_reset_recovery_skips_the_rebase_on_a_nokaslr_guest(tmp_path):
    """Addresses did not move: interrupt + continue re-inserts in place."""
    inst = _inst(tmp_path, vm_id="vm", cmdline="console=ttyS0 nokaslr")
    w = debug.reset_dropped_breakpoints_warning(inst, guest_initiated=True)
    assert "kbase" not in w and "--base" not in w
    assert w.index("interrupt`") < w.index("continue --background")


# --- the load warning: an image from another boot (#200) ---------------------


@pytest.mark.parametrize("kvm", [True, False])
def test_kaslr_load_recovery_rebases_instead_of_assuming_nothing_moved(tmp_path, kvm):
    """Live (#200): an image saved before a reset or reboot restores the
    kernel at that boot's base, so re-arming in place left the canary dead;
    `pry kbase` + `pry resync` made it fire. Under TCG too."""
    w = debug.loadvm_stale_session_warning(_inst(tmp_path, vm_id="vm", kvm=kvm))
    assert "did not move" not in w and "no re-arm" not in w
    assert w.index("pry --instance <id> kbase`") < w.index("pry --instance <id> resync`")
    assert "pry --instance <id> resync --base $KBASE`" in w


@pytest.mark.parametrize("kvm", [True, False])
def test_nokaslr_load_recovery_keeps_the_addresses(tmp_path, kvm):
    inst = _inst(tmp_path, vm_id="vm", kvm=kvm, cmdline="console=ttyS0 nokaslr")
    w = debug.loadvm_stale_session_warning(inst)
    assert "kbase" not in w and "--base" not in w


@pytest.fixture
def stub_client():
    """A listening "stub" on loopback with one client end held by THIS
    process — what a bridge's GDB holds while attached."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname())
    accepted, _ = server.accept()
    yield server.getsockname()[1]
    for s in (client, accepted, server):
        s.close()


def test_recoveries_name_qmu_bridge_only_while_it_holds_the_stub(
    tmp_path, sleeper, stub_client
):
    """#186: `qmu-<vm>` reaches the attached client only when it is the
    bridge `qmu gdb` recorded. Neither a hand-started client with no qmu
    bridge alive, nor one that took the stub after qmu's bridge disconnected
    (alive, holding nothing), may be offered that name."""
    me = os.getpid()
    ours = _inst(
        tmp_path, gdb_port=stub_client, gdb_bridge_pid=me,
        gdb_bridge_pid_start=proc_pid_start(me),
    )
    no_bridge = _inst(tmp_path, gdb_port=stub_client)
    disconnected = _inst(
        tmp_path, gdb_port=stub_client, gdb_bridge_pid=sleeper.pid,
        gdb_bridge_pid_start=proc_pid_start(sleeper.pid),
    )
    assert debug.bridge_holds_stub(ours) is True
    assert debug.bridge_holds_stub(disconnected) is False
    for build in (
        debug.reset_dropped_breakpoints_warning,
        debug.loadvm_stale_session_warning,
        lambda inst: debug.savevm_breakpoint_warning(inst, "running"),
    ):
        assert "`pry --instance qmu-bridge-vm " in build(ours)
        for foreign in (no_bridge, disconnected):
            assert "qmu-bridge-vm" not in build(foreign)
            assert "pry doctor" in build(foreign)


def test_tcg_warnings_do_not_claim_breakpoints_died(tmp_path):
    """Measured under --no-kvm: breakpoints live in QEMU, not guest RAM, so
    they keep firing after a snapshot load and after a nokaslr reset; only
    a KASLR re-slide strands them (and the rebase recovery applies)."""
    tcg = _inst(tmp_path, kvm=False)
    tcg_nokaslr = _inst(tmp_path, kvm=False, cmdline="console=ttyS0 nokaslr")
    load = debug.loadvm_stale_session_warning(tcg)
    assert "never fire" not in load and "interrupt" not in load
    reset = debug.reset_dropped_breakpoints_warning(tcg_nokaslr)
    assert "do not fire" not in reset and "Nothing to re-arm" in reset
    # At a debugger stop GDB had lifted them: booting needs `qmu cont`, and
    # its resume puts them back.
    halted = debug.reset_dropped_breakpoints_warning(tcg_nokaslr, qemu_status="prelaunch")
    assert "qmu cont --vm bridge-vm" in halted and "continue --background" in halted
    moved = debug.reset_dropped_breakpoints_warning(tcg)
    assert moved.index("qmu kbase") < moved.index("--base $KBASE")
