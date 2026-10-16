"""Round-6 regressions. Finding 1 is the one that matters: --dry-run deleted.

A flag whose entire contract is "do not do the destructive thing" did the
destructive thing, and destroyed the .serial.log files `kill --no-clean` exists
to preserve. Everything else here is the same false-statement class the earlier
rounds kept surfacing, relocated to commands that had not been fixed yet.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance
from qmu.ssh import SSHError


def _instance(**over) -> VMInstance:
    base = dict(
        vm_id="r6-vm", pid=4242, qmp_socket="/tmp/r6.qmp.sock",
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log="/tmp/r6.serial.log", kernel="/boot/bzImage",
        rootfs=None, memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-08-17T00:00:00Z", harness=True,
    )
    base.update(over)
    return VMInstance(**base)


def _remnant(tmp_path, monkeypatch, vm_id="dr1"):
    """A stopped VM whose logs were deliberately kept (kill --no-clean)."""
    idir = tmp_path / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    serial = idir / f"{vm_id}.serial.log"
    serial.write_text("BUG: KASAN: slab-use-after-free\n")
    (idir / f"{vm_id}.qemu.log").write_text("qemu\n")
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    return serial


# ---------------------------------------------------------------------------
# 1. --dry-run must never delete
# ---------------------------------------------------------------------------


def test_prune_all_dry_run_does_not_delete(tmp_path, monkeypatch, capsys):
    """The reported bug: it deleted and printed "Pruned 1 VM(s) (removed)"."""
    serial = _remnant(tmp_path, monkeypatch)

    rc = cli.main(["prune", "--all", "--dry-run", "--older-than", "0"])

    assert rc == 0
    assert serial.exists(), "--dry-run destroyed preserved crash evidence"
    assert "Would remove" in capsys.readouterr().out


def test_prune_vm_dry_run_does_not_delete(tmp_path, monkeypatch):
    serial = _remnant(tmp_path, monkeypatch, "dr2")

    rc = cli.main(["prune", "--vm", "dr2", "--dry-run", "--older-than", "0"])

    assert rc == 0
    assert serial.exists()


def test_dry_run_is_detectable_in_json(tmp_path, monkeypatch, capsys):
    """`dry_run: None` with `pruned` populated gave a script no way to tell."""
    _remnant(tmp_path, monkeypatch, "dr3")

    cli.main(
        ["--format", "json", "prune", "--all", "--dry-run", "--older-than", "0"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert payload["dry_run"] is True
    assert payload["pruned"] == []
    assert payload["would_prune"] == ["dr3"]


def test_a_real_prune_reports_dry_run_false(tmp_path, monkeypatch, capsys):
    _remnant(tmp_path, monkeypatch, "dr4")

    cli.main(["--format", "json", "prune", "--all", "--older-than", "0"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["dry_run"] is False
    assert payload["pruned"] == ["dr4"]


def test_real_prune_still_deletes(tmp_path, monkeypatch):
    serial = _remnant(tmp_path, monkeypatch, "dr5")

    rc = cli.main(["prune", "--all", "--older-than", "0"])

    assert rc == 0
    assert not serial.exists()


def test_dry_run_with_keep_logs_previews_without_acting(tmp_path, monkeypatch, capsys):
    serial = _remnant(tmp_path, monkeypatch, "dr6")

    rc = cli.main(
        ["prune", "--vm", "dr6", "--dry-run", "--keep-logs", "--older-than", "0"]
    )

    assert rc == 0
    assert serial.exists()
    assert "Would keep logs for" in capsys.readouterr().out


def test_runtime_dry_run_refuses_rather_than_acting(tmp_path, monkeypatch, capsys):
    """No preview pass exists there; refusing beats acting under the flag."""
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))

    rc = cli.main(["prune", "--runtime", "--dry-run"])

    assert rc == 1
    assert "not supported with --runtime" in capsys.readouterr().err


def test_dry_run_on_nothing_says_nothing_would_be_removed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))

    rc = cli.main(["prune", "--all", "--dry-run"])

    assert rc == 0
    assert "Nothing would be removed" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 2. kill called an orphan nonexistent
# ---------------------------------------------------------------------------


def test_kill_reaps_an_orphaned_remnant(tmp_path, monkeypatch, capsys):
    """`list` shows it with a live pid; `kill` said "not found"."""
    serial = _remnant(tmp_path, monkeypatch, "ob")
    monkeypatch.setattr(
        lifecycle, "find_orphan_qemus",
        lambda: [{"pid": 777, "serial_log": str(serial), "cmdline": "qemu"}],
    )
    signalled: list[int] = []
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: signalled.append(pid))
    monkeypatch.setattr(lifecycle, "is_pid_alive", lambda pid: False)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)

    rc = cli.main(["kill", "--vm", "ob"])

    out = capsys.readouterr().out
    assert rc == 0
    assert signalled == [777]
    assert "orphaned remnant" in out
    assert "777" in out


def test_kill_orphan_preserves_the_serial_log(tmp_path, monkeypatch, capsys):
    serial = _remnant(tmp_path, monkeypatch, "ob2")
    monkeypatch.setattr(
        lifecycle, "find_orphan_qemus",
        lambda: [{"pid": 778, "serial_log": str(serial), "cmdline": "qemu"}],
    )
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: None)
    monkeypatch.setattr(lifecycle, "is_pid_alive", lambda pid: False)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)

    cli.main(["--format", "json", "kill", "--vm", "ob2"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["orphaned"] is True
    assert payload["cleaned"] is False
    assert serial.exists()


def test_kill_of_a_dead_remnant_describes_it(tmp_path, monkeypatch, capsys):
    """The orphan branch engages only when a process is alive — but a dead
    remnant must still be described, not denied.

    Round 6 taught `kill` the orphan case only, so it went on reporting
    "not found" for a stopped remnant `qmu list` was displaying.
    """
    _remnant(tmp_path, monkeypatch, "dead")
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    rc = cli.main(["kill", "--vm", "dead"])

    captured = capsys.readouterr()
    # Wave 3: already stopped is what the caller asked for — a no-op, exit 0.
    assert rc == 0
    assert "not found" not in captured.out + captured.err
    assert "already stopped" in captured.out
    assert "qmu prune --vm dead" in captured.out


# ---------------------------------------------------------------------------
# 3. prune --all still made the false statement --vm no longer makes
# ---------------------------------------------------------------------------


def test_prune_all_names_the_age_gated_remnant(tmp_path, monkeypatch, capsys):
    """"No stopped VMs to prune." while `list` shows one is simply false."""
    _remnant(tmp_path, monkeypatch, "rem2")

    rc = cli.main(["prune", "--all"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "No stopped VMs to prune." not in out
    assert "rem2" in out
    assert "--older-than 0" in out


def test_prune_all_on_a_truly_empty_cache_keeps_the_plain_message(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))

    rc = cli.main(["prune", "--all"])

    assert rc == 0
    assert "No stopped VMs to prune." in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 4. dropped `rw` had no consequence note
# ---------------------------------------------------------------------------


def test_dropped_rw_explains_the_read_only_root(tmp_path, monkeypatch, capsys):
    """Measured: root mounts ro and writes fail EROFS — same class as init=."""
    cfg = tmp_path / "qmu.toml"
    cfg.write_text(
        '[boot]\nkernel = "./bzImage"\n'
        'cmdline = "console=ttyS0 root=/dev/sda rw"\n'
    )
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(lifecycle, "launch_vm", lambda **kw: _instance())

    cli.main(["launch", "--config", str(cfg), "--harness",
              "--profile", "exploit-test"])

    err = capsys.readouterr().err
    assert "'rw' is gone" in err
    assert "EROFS" in err


# ---------------------------------------------------------------------------
# exec vs push/pull: the same condition must get the same exit class
# ---------------------------------------------------------------------------


class _DroppedSSH:
    """One lost transport as `exec` and `push` each observe it: `run` returns
    ssh's 255 with the liveness probe failing; `scp` raises rc 255 plus a
    transport marker. `serial_text` lands in the log while the command runs,
    which is the only placement that counts as fresh for the command."""

    def __init__(self, serial, serial_text):
        self._serial, self._text = serial, serial_text

    def _drop(self):
        with open(self._serial, "a") as stream:
            stream.write(self._text)

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self._drop()
        return 255, "", ""

    def push(self, local, remote, **kwargs):
        self._drop()
        raise SSHError(
            "SCP push failed: mux failed: Broken pipe",
            returncode=255,
            stderr="mux failed: Broken pipe",
        )

    def is_ready(self, timeout=2):
        return False


def _lost_transport_rcs(tmp_path, monkeypatch, capsys, *, serial_text):
    from qmu.commands import guest as guest_mod

    serial = tmp_path / "vm.serial.log"
    inst = _instance(serial_log=str(serial), ssh_port=10022, ssh_key="/tmp/k", harness=False)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"x")
    monkeypatch.setattr(guest_mod, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        guest_mod, "_make_ssh", lambda selected: _DroppedSSH(serial, serial_text)
    )
    monkeypatch.setattr(guest_mod, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest_mod, "_require_running_vm", lambda vm, command: None)
    monkeypatch.setattr(guest_mod.time, "sleep", lambda _: None)

    rcs = {}
    for command, argv in (
        ("exec", ["exec", "--vm", "r6-vm", "true"]),
        ("push", ["push", "--vm", "r6-vm", str(payload), "/root/payload.bin"]),
    ):
        serial.write_text("ordinary boot log\n")
        rcs[command] = cli.main(["--format", "json", *argv])
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["ssh_error"] is True, command
        assert envelope["crash_detected"] is (envelope["crash"] is not None), command
    return rcs


def test_exec_and_scp_agree_on_transport_loss_without_a_crash(tmp_path, monkeypatch, capsys):
    """Sibling commands disagreeing about one condition is the recurring class.

    scp returned 4 for "connection dropped, no crash in the log" while exec
    returned 3, so a guest with no sshd reported a kernel panic on every exec.
    """
    rcs = _lost_transport_rcs(tmp_path, monkeypatch, capsys, serial_text="")

    assert rcs == {"exec": 4, "push": 4}


def test_exec_and_scp_still_report_3_when_a_crash_corroborates(tmp_path, monkeypatch, capsys):
    rcs = _lost_transport_rcs(
        tmp_path, monkeypatch, capsys,
        serial_text=(
            "[ 1.1] Kernel panic - not syncing: Fatal exception\n"
            "[ 1.1] ---[ end Kernel panic - not syncing: Fatal exception ]---\n"
        ),
    )

    assert rcs == {"exec": 3, "push": 3}
