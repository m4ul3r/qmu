"""Debugger↔VM coherence contract (#39/#44/#45/#46, umbrella #48).

qmu mutates VM reality (reset, loadvm, savevm) and attaches debuggers while the
gdbstub protocol says nothing to the client, so the debugger silently diverges:
stale registers after loadvm, breakpoints listed [enabled] that never fire after
a reset, int3 trap bytes baked into a saved image, hardware watchpoints that
no-op under KVM. This suite pins the "invalidate loudly" half of the contract —
qmu warns, naming what diverged and how to recover — plus the KVM opt-out that
makes the watchpoint workaround reachable.

These are seam tests: the underlying failures live in live QMP/gdbstub/KVM state
that unit doubles cannot see (see CLAUDE.md). They verify qmu emits the right
warning on the right event for a debugged VM and stays silent otherwise; the
divergence itself still needs real-VM verification.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess

import pytest

from qmu import cli, debug
from qmu.commands import qmp_cmds
from qmu.config import ConfigError, QMUConfig, load_config_file
from qmu.instance import VMInstance
from qmu.vm import build_qemu_command


# --- /proc/net/tcp parsing + attach probe ----------------------------------

# One real-shaped ESTABLISHED line: local 127.0.0.1:1234 (0100007F:04D2),
# state 01. The header row is deliberately included — the parser skips it.
_PROC_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode"
)


def _proc_line(local_port_hex: str, state: str) -> str:
    return (
        f"   0: 0100007F:{local_port_hex} 0100007F:AABB {state} "
        "00000000:00000000 00:00000000 00000000     0        0 0"
    )


# A non-loopback (10.0.0.5) ESTABLISHED socket that reuses port 1234 — must be
# excluded, so an unrelated connection can't masquerade as an attached debugger.
_NONLOOPBACK_LINE = (
    "   0: 0500000A:04D2 0100007F:AABB 01 00000000:00000000 "
    "00:00000000 00000000     0        0 0"
)
# IPv6 loopback ::1:4321 (0x10E1) ESTABLISHED — the gdb stub may bind ::1.
_TCP6_LOOPBACK_LINE = (
    "   0: 00000000000000000000000001000000:10E1 "
    "00000000000000000000000000000000:0000 01 00000000:00000000 "
    "00:00000000 00000000     0        0 0"
)


def test_established_local_ports_extracts_only_established_loopback():
    text = "\n".join([
        _PROC_HEADER,
        _proc_line("04D2", "01"),  # 127.0.0.1:1234 ESTABLISHED  -> included
        _proc_line("04D3", "0A"),  # 127.0.0.1:1235 LISTEN       -> excluded
        _proc_line("1F90", "01"),  # 127.0.0.1:8080 ESTABLISHED  -> included
        _NONLOOPBACK_LINE,          # 10.0.0.5:1234 ESTABLISHED   -> excluded (not loopback)
        _TCP6_LOOPBACK_LINE,        # [::1]:4321 ESTABLISHED      -> included
        "garbage line with too few fields",
    ])
    assert debug.established_local_ports(text) == {1234, 8080, 0x10E1}


def test_established_local_ports_excludes_nonloopback_sharing_the_port():
    # The dangerous false-positive from review: an unrelated ESTABLISHED socket
    # on another interface reusing the gdb port number must NOT count.
    text = "\n".join([_PROC_HEADER, _NONLOOPBACK_LINE])
    assert debug.established_local_ports(text) == set()


def test_established_local_ports_empty_on_header_only():
    assert debug.established_local_ports(_PROC_HEADER) == set()


def _gdb_inst(gdb_port):
    return VMInstance(
        vm_id="dg", pid=1, qmp_socket="/tmp/x.sock", ssh_port=None,
        ssh_key=None, gdb_port=gdb_port, serial_log="/tmp/x.log",
        kernel="/k", rootfs=None, memory="4G", cpus=1, cmdline="",
        profile="exploit-dev", started_at="2026-01-01T00:00:00+00:00",
    )


def test_gdb_client_attached_none_without_gdb_port(monkeypatch, tmp_path):
    # No gdb stub -> "not applicable", never a divergence source.
    assert debug.gdb_client_attached(_gdb_inst(None)) is None


def test_gdb_client_attached_true_when_established_on_port(monkeypatch, tmp_path):
    proc = tmp_path / "tcp"
    proc.write_text("\n".join([_PROC_HEADER, _proc_line("04D2", "01")]))
    monkeypatch.setattr(debug, "_PROC_NET_TCP", (str(proc),))
    assert debug.gdb_client_attached(_gdb_inst(1234)) is True


def test_gdb_client_attached_false_when_readable_but_only_listening(monkeypatch, tmp_path):
    proc = tmp_path / "tcp"
    proc.write_text("\n".join([_PROC_HEADER, _proc_line("04D2", "0A")]))  # LISTEN only
    monkeypatch.setattr(debug, "_PROC_NET_TCP", (str(proc),))
    assert debug.gdb_client_attached(_gdb_inst(1234)) is False


def test_gdb_client_attached_none_when_proc_unreadable(monkeypatch, tmp_path):
    monkeypatch.setattr(debug, "_PROC_NET_TCP", (str(tmp_path / "does-not-exist"),))
    assert debug.gdb_client_attached(_gdb_inst(1234)) is None


@pytest.mark.parametrize(
    "gdb_port,probe,expected",
    [
        (None, None, False),   # no stub -> never warn
        (1234, True, True),    # attached -> warn
        (1234, False, False),  # positively not attached -> silent
        (1234, None, True),    # cannot tell -> warn (fail-safe)
    ],
)
def test_debug_session_present_gate(monkeypatch, gdb_port, probe, expected):
    monkeypatch.setattr(debug, "gdb_client_attached", lambda inst: probe)
    assert debug.debug_session_present(_gdb_inst(gdb_port)) is expected


# --- snapshot save / load coherence warnings (#45 / #44) --------------------


class _FakeQMP:
    def execute(self, command, arguments=None, timeout=30.0):
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        return ""


class _HmpQMP:
    """QMP double whose execute_hmp returns a fixed string (for monitor tests)."""

    def __init__(self, hmp_result):
        self._hmp_result = hmp_result

    def execute(self, command, arguments=None, timeout=30.0):
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        return self._hmp_result


def _install_qmp_seams(monkeypatch, inst, *, present):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_FakeQMP())
    )
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: present)


def _snap_args():
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_save_warns_int3_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name: "Snapshot 'clean' saved.")
    rc = qmp_cmds._handle_snapshot_save(_snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err
    assert "0xCC" in err
    assert "debugger artifact" in err


def test_snapshot_save_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name: "Snapshot 'clean' saved.")
    rc = qmp_cmds._handle_snapshot_save(_snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" not in err
    assert err == ""


def test_snapshot_save_warns_even_when_client_detached(monkeypatch, capsys):
    # #45 / review finding: int3 bytes are baked into the image and survive an
    # uncleanly-detached bridge, so a save must warn whenever a stub EVER existed
    # (gdb_port set) — not only when a live client is probed. Force the live-view
    # gate to say "no client" to prove savevm does not depend on it.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=False)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: False)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name: "Snapshot 'clean' saved.")
    rc = qmp_cmds._handle_snapshot_save(_snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err


def test_snapshot_save_failure_does_not_add_int3_warning(monkeypatch, capsys):
    # A failed save wrote no image, so the int3-baking warning is moot and must
    # not appear — only the existing failure hint.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot", lambda qmp, name: "Error: Could not open 'savevm' section"
    )
    rc = qmp_cmds._handle_snapshot_save(_snap_args())
    err = capsys.readouterr().err
    assert rc == 1
    assert "int3" not in err
    assert "snapshot save failed" in err


def test_snapshot_load_warns_stale_session_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name: "Snapshot 'clean' loaded.")
    # save_guest_epoch_serial_offset writes instance JSON; stub it to a no-op
    # that returns the instance so the handler proceeds offline.
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = qmp_cmds._handle_snapshot_load(_snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "does NOT re-sync" in err
    # Reworded per review: must steer away from the #40 double-bridge trap.
    assert "Tear the stale pry bridge down first" in err
    assert "#40" in err


def test_snapshot_load_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name: "Snapshot 'clean' loaded.")
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = qmp_cmds._handle_snapshot_load(_snap_args())
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_snapshot_load_failure_does_not_warn_stale(monkeypatch, capsys):
    # A failed load did not rewind, so there is no stale-session divergence to
    # warn about — only the existing failure hint.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot", lambda qmp, name: "Error: Snapshot 'clean' does not exist"
    )
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = qmp_cmds._handle_snapshot_load(_snap_args())
    err = capsys.readouterr().err
    assert rc == 1
    assert "does NOT re-sync" not in err
    assert "snapshot load failed" in err


# --- reset drops breakpoints (#46) -----------------------------------------


def _qmp_args(command, cmd_args=None):
    return argparse.Namespace(vm=None, command=command, args=cmd_args, format="text", out=None)


def test_qmp_system_reset_warns_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_qmp(_qmp_args("system_reset"))
    err = capsys.readouterr().err
    assert rc == 0
    assert "drops the gdbstub's breakpoint" in err
    assert "hits stay 0" in err


def test_qmp_non_reset_command_never_warns(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_qmp(_qmp_args("query-status"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_qmp_system_reset_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    rc = qmp_cmds._handle_qmp(_qmp_args("system_reset"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def _monitor_args(tokens):
    return argparse.Namespace(vm=None, command=tokens, format="text", out=None)


def test_monitor_system_reset_warns_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_monitor(_monitor_args(["system_reset"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "drops the gdbstub's breakpoint" in err


def test_monitor_unrelated_command_does_not_warn(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_monitor(_monitor_args(["info", "registers"]))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_monitor_help_system_reset_does_not_warn(monkeypatch, capsys):
    # The verb is the FIRST token; `help system_reset` shows help and resets
    # nothing, so the reset warning must not fire (the superstring case).
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_monitor(_monitor_args(["help", "system_reset"]))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_monitor_savevm_warns_int3_when_stub_present(monkeypatch, capsys):
    # The HMP escape hatch reaches the same mutation as `qmu snapshot save`, so
    # it must carry the #45 warning too. Gated on the stub, not a live client.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=False)  # no live client
    rc = qmp_cmds._handle_monitor(_monitor_args(["savevm", "clean"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err


def test_monitor_loadvm_warns_stale_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = qmp_cmds._handle_monitor(_monitor_args(["loadvm", "clean"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "does NOT re-sync" in err


def test_monitor_savevm_failure_suppresses_warning(monkeypatch, capsys):
    # A failed HMP savevm mutated nothing, so no int3 warning.
    inst = _gdb_inst(1234)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: contextlib.nullcontext(_HmpQMP("Error: Could not open 'savevm' section")),
    )
    rc = qmp_cmds._handle_monitor(_monitor_args(["savevm", "clean"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" not in err


# --- gdb attach: KVM hardware-watchpoint warning (#39) ---------------------


def _gdb_vm(tmp_path, *, kvm):
    return VMInstance(
        vm_id="debug-vm", pid=4242, qmp_socket=str(tmp_path / "s.sock"),
        ssh_port=10022, ssh_key=str(tmp_path / "id_rsa"), gdb_port=1234,
        serial_log=str(tmp_path / "serial.log"), kernel=str(tmp_path / "bzImage"),
        rootfs=str(tmp_path / "rootfs.img"), memory="4G", cpus=2,
        cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-07-09T00:00:00+00:00", harness=False, arch="x86_64",
        kvm=kvm,
    )


def _install_gdb_seams(monkeypatch, inst):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds.shutil, "which",
        lambda name: "/usr/bin/pry" if name == "pry" else None,
    )

    def run(argv, **kwargs):
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(qmp_cmds.subprocess, "run", run)


def test_gdb_attach_warns_about_kvm_watchpoints(monkeypatch, tmp_path, capsys):
    _install_gdb_seams(monkeypatch, _gdb_vm(tmp_path, kvm=True))
    rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
    payload = json.loads(capsys.readouterr().out)
    w = payload["kvm_watchpoint_warning"]
    assert rc == 0
    assert payload["kvm"] is True
    assert "watchpoint" in w.lower()
    assert "--no-kvm" in w
    # The reworded (evidence-backed) message must lead with the real cause — the
    # watched virtual address / alias — not assert KVM breaks watchpoints.
    assert "virtual address" in w.lower()
    assert "alias" in w.lower()
    assert "never deliver" not in w.lower()


def test_gdb_attach_no_kvm_warning_when_tcg_or_unknown(monkeypatch, tmp_path, capsys):
    # kvm=None (older instance JSON) and kvm=False must both omit the warning:
    # only a positively-KVM VM gets it.
    for kvm in (None, False):
        _install_gdb_seams(monkeypatch, _gdb_vm(tmp_path, kvm=kvm))
        rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert "kvm" not in payload
        assert "kvm_watchpoint_warning" not in payload


# --- KVM opt-out: config accel + --no-kvm (#39) ----------------------------


def test_accel_tcg_disables_kvm():
    cfg = QMUConfig()
    cfg.accel = "tcg"
    assert cfg.use_kvm() is False


def test_accel_kvm_forces_kvm_regardless_of_host():
    cfg = QMUConfig()
    cfg.accel = "kvm"
    assert cfg.use_kvm() is True


def test_build_qemu_command_omits_enable_kvm_under_tcg():
    cfg = QMUConfig()
    cfg.arch = "x86_64"
    cfg.accel = "tcg"
    cmd = build_qemu_command(
        config=cfg, kernel="/k", rootfs="/r", ssh_port=10022, gdb_port=None,
        qmp_socket="/s", serial_log="/l", cmdline="console=ttyS0",
    )
    assert "-enable-kvm" not in cmd


def test_build_qemu_command_adds_enable_kvm_when_forced():
    cfg = QMUConfig()
    cfg.arch = "x86_64"
    cfg.accel = "kvm"
    cmd = build_qemu_command(
        config=cfg, kernel="/k", rootfs="/r", ssh_port=10022, gdb_port=None,
        qmp_socket="/s", serial_log="/l", cmdline="console=ttyS0",
    )
    assert "-enable-kvm" in cmd


def test_no_kvm_flag_resolves_to_accel_tcg():
    from qmu._cliutil import _resolve_config_from_args
    args = argparse.Namespace(no_kvm=True, config=None)
    cfg = _resolve_config_from_args(args)
    assert cfg.accel == "tcg"
    assert cfg.use_kvm() is False


def test_accel_config_key_parses(tmp_path):
    p = tmp_path / "qmu.toml"
    p.write_text('[machine]\naccel = "tcg"\n')
    raw = load_config_file(p)
    assert raw["machine"]["accel"] == "tcg"


def test_invalid_accel_value_is_source_aware(tmp_path):
    p = tmp_path / "qmu.toml"
    p.write_text('[machine]\naccel = "hvf"\n')
    with pytest.raises(ConfigError) as excinfo:
        load_config_file(p)
    assert excinfo.value.key_path == "machine.accel"
    assert "auto, kvm, tcg" in str(excinfo.value)


# --- kill warns about the stranded pry bridge (#40 stopgap) -----------------


def _kill_args(**over):
    base = dict(vm=None, force=False, no_clean=False, format="text", out=None)
    base.update(over)
    return argparse.Namespace(**base)


def test_kill_warns_about_stranded_pry_bridge(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)  # gdb_port=1234
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda inst, force=False, clean=True: None)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda inst: True)
    rc = lifecycle._handle_kill(_kill_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "Multiple bridge instances" in err
    assert "1234" in err


def test_kill_no_bridge_note_when_no_client(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda inst, force=False, clean=True: None)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda inst: False)
    rc = lifecycle._handle_kill(_kill_args())
    assert rc == 0
    assert "Multiple bridge instances" not in capsys.readouterr().err


def test_kill_does_not_probe_for_non_gdb_vm(monkeypatch, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_inst(None)  # gdb_port None: a non-gdb VM never had a bridge
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda inst, force=False, clean=True: None)
    monkeypatch.setattr(
        lifecycle, "debug_session_present",
        lambda inst: pytest.fail("must not probe a non-gdb VM"),
    )
    rc = lifecycle._handle_kill(_kill_args())
    assert rc == 0
    assert "Multiple bridge instances" not in capsys.readouterr().err


# --- wait warns on an observed reset (#46, the non-command path) -------------


class _WaitQMP:
    def __init__(self, events):
        self._events = list(events)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command, arguments=None, timeout=30.0):
        return {"running": True, "status": "running"}

    def wait_event(self, event_names, timeout=None):
        return self._events.pop(0) if self._events else None


def test_wait_warns_on_observed_reset_when_debugged(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)  # gdb_port=1234, harness=False
    alive = [True, False]

    monkeypatch.setattr(lifecycle, "_require_running", lambda vm, cmd: None)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        lifecycle, "_qmp_ctx", lambda sel: _WaitQMP([{"event": "RESET", "data": {}}])
    )
    monkeypatch.setattr(
        lifecycle, "instance_alive",
        lambda sel: alive.pop(0) if len(alive) > 1 else alive[0],
    )
    monkeypatch.setattr(lifecycle, "serial_log_offset", lambda p: 0)
    monkeypatch.setattr(lifecycle, "save_guest_epoch_serial_offset", lambda i, off: i)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: True)
    monkeypatch.setattr(
        lifecycle, "_warn_unknown_kernel_params",
        lambda i: {"all": [], "operator": [], "profile": []},
    )
    monkeypatch.setattr(lifecycle, "extract_crash", lambda *a, **k: "")

    args = argparse.Namespace(
        vm="debug-vm", pattern=None, timeout=1.0, no_clean=True,
        format="json", out=None, ignore_crash=False,
    )
    rc = lifecycle._handle_wait(args)
    err = capsys.readouterr().err
    assert rc == 0
    assert "drops the gdbstub's breakpoint" in err


def test_wait_reset_no_warning_without_debugger(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)
    alive = [True, False]

    monkeypatch.setattr(lifecycle, "_require_running", lambda vm, cmd: None)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        lifecycle, "_qmp_ctx", lambda sel: _WaitQMP([{"event": "RESET", "data": {}}])
    )
    monkeypatch.setattr(
        lifecycle, "instance_alive",
        lambda sel: alive.pop(0) if len(alive) > 1 else alive[0],
    )
    monkeypatch.setattr(lifecycle, "serial_log_offset", lambda p: 0)
    monkeypatch.setattr(lifecycle, "save_guest_epoch_serial_offset", lambda i, off: i)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: False)
    monkeypatch.setattr(
        lifecycle, "_warn_unknown_kernel_params",
        lambda i: {"all": [], "operator": [], "profile": []},
    )
    monkeypatch.setattr(lifecycle, "extract_crash", lambda *a, **k: "")

    args = argparse.Namespace(
        vm="debug-vm", pattern=None, timeout=1.0, no_clean=True,
        format="json", out=None, ignore_crash=False,
    )
    rc = lifecycle._handle_wait(args)
    err = capsys.readouterr().err
    assert rc == 0
    assert "drops the gdbstub's breakpoint" not in err
