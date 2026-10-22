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
import os
import subprocess

import pytest

from qmu import cli, debug
from qmu.commands import qmp_cmds
from qmu.config import ConfigError, QMUConfig, load_config_file
from qmu.instance import QMUError, VMInstance
from qmu.snapshot import SnapshotResult
from qmu.vm import build_qemu_command
from qmu._cliutil import render


def _run(handler, args):
    """Call a handler as `cli.main` would: render its Result, return the exit code."""
    return render(args, handler(args))


def _ok(message):
    return SnapshotResult(True, message)


def _failed(message):
    return SnapshotResult(False, message)


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
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)


def _snap_args():
    return argparse.Namespace(vm=None, name="clean", format="text", out=None)


def test_snapshot_save_warns_int3_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    rc = _run(qmp_cmds._handle_snapshot_save, _snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err
    assert "0xCC" in err


def test_snapshot_save_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    rc = _run(qmp_cmds._handle_snapshot_save, _snap_args())
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
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    rc = _run(qmp_cmds._handle_snapshot_save, _snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err


def test_snapshot_save_failure_does_not_add_int3_warning(monkeypatch, capsys):
    # A failed save wrote no image, so the int3-baking warning is moot and must
    # not appear — only the existing failure hint.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot",
        lambda qmp, name, **kw: _failed("Error: Could not open 'savevm' section"),
    )
    rc = _run(qmp_cmds._handle_snapshot_save, _snap_args())
    err = capsys.readouterr().err
    assert rc == 1
    assert "int3" not in err
    assert "snapshot save failed" in err


def test_snapshot_load_warns_stale_session_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' loaded."))
    # save_guest_epoch_serial_offset writes instance JSON; stub it to a no-op
    # that returns the instance so the handler proceeds offline.
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = _run(qmp_cmds._handle_snapshot_load, _snap_args())
    err = capsys.readouterr().err
    assert rc == 0
    assert "does NOT re-sync" in err


def test_snapshot_load_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    monkeypatch.setattr(qmp_cmds, "load_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' loaded."))
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = _run(qmp_cmds._handle_snapshot_load, _snap_args())
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_snapshot_load_pre_restore_refusal_does_not_warn_stale(monkeypatch, capsys):
    # A load QEMU refused before restoring anything did not rewind, so there
    # is no stale-session divergence to warn about — only the failure hint.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name, **kw: SnapshotResult(
            False, "Error: Snapshot 'clean' does not exist", reason="missing",
            restore_state="none",
        ),
    )
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = _run(qmp_cmds._handle_snapshot_load, _snap_args())
    err = capsys.readouterr().err
    assert rc == 1
    assert "does NOT re-sync" not in err
    assert debug.loadvm_failed_restore_warning(inst) not in err
    assert "snapshot load failed" in err


@pytest.mark.parametrize("restore_state", ["partial", "unknown"])
def test_snapshot_load_failure_after_restoration_began_warns_stale(
    monkeypatch, capsys, restore_state
):
    # #87 x #44: a load that got past the tag check reverted the disks and
    # reset the machine before the vmstate load failed, so the attached
    # debugger's view diverged — and the recovery must not resume the
    # half-restored machine (no continue/re-sync/detach).
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name, **kw: SnapshotResult(
            False, "Error: Error -22 while loading VM state", reason="hmp",
            guest_paused=True, restore_state=restore_state,
        ),
    )
    monkeypatch.setattr(qmp_cmds, "serial_log_offset", lambda path: 0)
    rc = _run(qmp_cmds._handle_snapshot_load, _snap_args())
    err = capsys.readouterr().err
    assert rc == 1
    assert debug.loadvm_failed_restore_warning(inst) in err
    assert debug.loadvm_stale_session_warning(inst) not in err
    assert "snapshot load failed" in err


# --- reset drops breakpoints (#46) -----------------------------------------


def _qmp_args(command, cmd_args=None):
    return argparse.Namespace(vm=None, command=command, args=cmd_args, format="text", out=None)


def test_qmp_system_reset_warns_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_qmp, _qmp_args("system_reset"))
    err = capsys.readouterr().err
    assert rc == 0
    assert "has a GDB stub and was just reset" in err
    assert "hits stay 0" in err


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_qmp_system_reset_warning_rides_in_the_envelope(monkeypatch, capsys, fmt):
    """#74: the coherence warning is stderr in every mode AND `warnings[]` in
    the json/ndjson envelope, so an agent reading only stdout learns that
    its breakpoint set was dropped."""
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    args = _qmp_args("system_reset")
    args.format = fmt
    rc = _run(qmp_cmds._handle_qmp, args)
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    (warning,) = payload["warnings"]
    assert warning.startswith("VM 'dg' has a GDB stub and was just reset")
    assert "has a GDB stub and was just reset" in captured.err


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_snapshot_save_warning_rides_in_the_envelope(monkeypatch, capsys, fmt):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    args = _snap_args()
    args.format = fmt
    rc = _run(qmp_cmds._handle_snapshot_save, args)
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert any("int3" in w for w in payload["warnings"])
    assert "int3" in captured.err


def test_qmp_non_reset_command_never_warns(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_qmp, _qmp_args("query-status"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_qmp_system_reset_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_qmp_seams(monkeypatch, inst, present=False)
    rc = _run(qmp_cmds._handle_qmp, _qmp_args("system_reset"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def _monitor_args(tokens):
    return argparse.Namespace(vm=None, command=tokens, format="text", out=None)


def test_monitor_system_reset_warns_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_monitor, _monitor_args(["system_reset"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "has a GDB stub and was just reset" in err


def test_monitor_unrelated_command_does_not_warn(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_monitor, _monitor_args(["info", "registers"]))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_monitor_help_system_reset_does_not_warn(monkeypatch, capsys):
    # The verb is the FIRST token; `help system_reset` shows help and resets
    # nothing, so the reset warning must not fire (the superstring case).
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_monitor, _monitor_args(["help", "system_reset"]))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_monitor_savevm_warns_int3_when_stub_present(monkeypatch, capsys):
    # The HMP escape hatch reaches the same mutation as `qmu snapshot save`, so
    # it must carry the #45 warning too. Gated on the stub, not a live client.
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=False)  # no live client
    rc = _run(qmp_cmds._handle_monitor, _monitor_args(["savevm", "clean"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err


def test_monitor_loadvm_warns_stale_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_qmp_seams(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_monitor, _monitor_args(["loadvm", "clean"]))
    err = capsys.readouterr().err
    assert rc == 0
    assert "does NOT re-sync" in err


def test_monitor_savevm_failure_is_an_error_without_warning(monkeypatch, capsys):
    # A failed HMP savevm mutated nothing, so no int3 warning -- and HMP's own
    # error text is a failure (exit 1), not an ok:true payload (audit D8).
    inst = _gdb_inst(1234)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: contextlib.nullcontext(_HmpQMP("Error: Could not open 'savevm' section")),
    )
    with pytest.raises(QMUError, match="Could not open 'savevm' section"):
        _run(qmp_cmds._handle_monitor, _monitor_args(["savevm", "clean"]))
    assert "int3" not in capsys.readouterr().err


# --- the third route: `qmu qmp human-monitor-command` (dogfood F4) ----------
#
# Live, with a debugger attached, `qmu qmp '{"execute":"human-monitor-command",
# "arguments":{"command-line":"system_reset"}}'` reset the machine with rc 0
# and an EMPTY stderr, while `qmu monitor system_reset` warned. The HMP verb
# rides inside the arguments, so keying only on the QMP method name missed it —
# and the envelope normalization made this shape trivially typeable.


class _HmpViaQmp:
    """Double whose *execute* returns a string, the shape QEMU answers
    `human-monitor-command` with (the HMP console text)."""

    def __init__(self, result=""):
        self._result = result

    def execute(self, command, arguments=None, timeout=30.0):
        return self._result

    def execute_hmp(self, command_line, timeout=30.0):
        return self._result


def _install_hmp_via_qmp(monkeypatch, inst, *, present, result=""):
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_HmpViaQmp(result))
    )
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: present)


def _hmp_qmp_args(command_line):
    return _qmp_args("human-monitor-command", json.dumps({"command-line": command_line}))


def test_qmp_hmp_system_reset_warns_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("system_reset"))
    err = capsys.readouterr().err
    assert rc == 0
    assert "has a GDB stub and was just reset" in err


def test_qmp_hmp_help_system_reset_does_not_warn(monkeypatch, capsys):
    # Same first-token rule as `monitor`: `help system_reset` resets nothing.
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("help system_reset"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_qmp_hmp_unrelated_verb_does_not_warn(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(monkeypatch, inst, present=True, result="VM status: running")
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("info status"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_qmp_hmp_system_reset_silent_when_not_debugged(monkeypatch, capsys):
    inst = _gdb_inst(None)
    _install_hmp_via_qmp(monkeypatch, inst, present=False)
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("system_reset"))
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_qmp_hmp_savevm_warns_int3_when_stub_present(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(monkeypatch, inst, present=False)  # no live client
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("savevm clean"))
    err = capsys.readouterr().err
    assert rc == 0
    assert "int3" in err


def test_qmp_hmp_loadvm_warns_stale_when_debugged(monkeypatch, capsys):
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(monkeypatch, inst, present=True)
    rc = _run(qmp_cmds._handle_qmp, _hmp_qmp_args("loadvm clean"))
    err = capsys.readouterr().err
    assert rc == 0
    assert "does NOT re-sync" in err


def test_qmp_hmp_savevm_failure_is_an_error_without_warning(monkeypatch, capsys):
    # A failed HMP savevm mutated nothing, so no int3 warning — the suppression
    # must reach this route too, which means reading the returned HMP text;
    # and that text is a failure, so the command exits 1 rather than ok:true.
    inst = _gdb_inst(1234)
    _install_hmp_via_qmp(
        monkeypatch, inst, present=True,
        result="Error: Could not open 'savevm' section",
    )
    with pytest.raises(QMUError, match="Could not open 'savevm' section"):
        _run(qmp_cmds._handle_qmp, _hmp_qmp_args("savevm clean"))
    assert "int3" not in capsys.readouterr().err


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
    # The attach gate reads the real /proc/net/tcp; on a shared host another
    # VM's debugger may be attached to port 1234, so pin "no client".
    monkeypatch.setattr(qmp_cmds, "gdb_client_attached", lambda inst: False)

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
    # only a positively-KVM VM gets it. `kvm` itself is always present with the
    # recorded value, as launch/status/list report it (#134).
    for kvm in (None, False):
        _install_gdb_seams(monkeypatch, _gdb_vm(tmp_path, kvm=kvm))
        rc = cli.main(["--format", "json", "gdb", "--vm", "debug-vm"])
        payload = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert payload["kvm"] is kvm
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
    rc = _run(lifecycle._handle_kill, _kill_args())
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
    rc = _run(lifecycle._handle_kill, _kill_args())
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
    rc = _run(lifecycle._handle_kill, _kill_args())
    assert rc == 0
    assert "Multiple bridge instances" not in capsys.readouterr().err


# --- wait warns on an observed reset (#46, the non-command path) -------------
#
# Bare `wait` no longer holds a QMP connection (one `query-status` per poll),
# so it observes a reboot the way every other command scopes the guest: a new
# kernel boot banner in the serial log after the wait began.


class _WaitQMP:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command, arguments=None, timeout=30.0):
        return {"running": True, "status": "running"}


def _wire_wait_reset(monkeypatch, inst, *, debugged):
    from qmu.commands import lifecycle
    alive = [True, False]

    monkeypatch.setattr(lifecycle, "_require_running", lambda vm, cmd: None)
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "_qmp_ctx", lambda sel: _WaitQMP())
    monkeypatch.setattr(
        lifecycle, "instance_alive",
        lambda sel: alive.pop(0) if len(alive) > 1 else alive[0],
    )
    # The log is empty when the wait starts; the first poll finds a banner.
    monkeypatch.setattr(
        lifecycle, "scan_console_growth",
        lambda p, *, scanned, boot_offset: (100, 100, False),
    )
    monkeypatch.setattr(lifecycle, "last_boot_offset", lambda p, start_offset=0: 100)
    monkeypatch.setattr(lifecycle, "serial_log_offset", lambda p: 100)
    monkeypatch.setattr(lifecycle, "has_terminal_panic", lambda *a, **k: False)
    monkeypatch.setattr(lifecycle, "save_guest_epoch_serial_offset", lambda i, off: i)
    monkeypatch.setattr(lifecycle, "debug_session_present", lambda i: debugged)
    monkeypatch.setattr(
        lifecycle, "_warn_unknown_kernel_params",
        lambda i, **kw: {"all": [], "operator": [], "profile": []},
    )
    monkeypatch.setattr(lifecycle, "extract_crash", lambda *a, **k: "")
    return argparse.Namespace(
        vm="debug-vm", pattern=None, timeout=1.0, no_clean=True,
        format="json", out=None, ignore_crash=False,
    )


def test_wait_warns_on_observed_reset_when_debugged(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)  # gdb_port=1234, harness=False
    args = _wire_wait_reset(monkeypatch, inst, debugged=True)

    rc = _run(lifecycle._handle_wait, args)
    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["last_event"] == "RESET"
    assert "has a GDB stub and" in captured.err


def test_wait_reset_no_warning_without_debugger(monkeypatch, tmp_path, capsys):
    from qmu.commands import lifecycle
    inst = _gdb_vm(tmp_path, kvm=None)
    args = _wire_wait_reset(monkeypatch, inst, debugged=False)

    rc = _run(lifecycle._handle_wait, args)
    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["last_event"] == "RESET"
    assert "has a GDB stub and" not in captured.err


# --- what a save can hold of the debugger's breakpoints (#188) ---------------
#
# Measured on QEMU 8.2.2: under KVM a save taken while GDB had the target
# running carried 0xCC at the breakpoint; one taken at a breakpoint stop
# (`debug`) or after `pry interrupt` (`paused`, bridge stopped) held the
# original byte; under TCG the inserted breakpoint never reached guest RAM.


class _StatusQMP(_FakeQMP):
    def __init__(self, status):
        self.status = status

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            return {"running": self.status == "running", "status": self.status}
        return {}


@pytest.mark.parametrize(
    "kvm,status,bridge_stopped,expected",
    [
        (True, "running", True, "possible"),
        (True, "debug", None, "lifted"),
        (True, "paused", True, "lifted"),
        (True, "paused", False, "possible"),
        (True, "paused", None, "possible"),
        (None, "debug", None, "lifted"),
        (None, "running", None, "possible"),
        (False, "running", None, "never"),
    ],
)
def test_snapshot_save_reports_what_the_image_can_hold(
    monkeypatch, capsys, kvm, status, bridge_stopped, expected
):
    inst = _gdb_inst(1234)
    inst.kvm = kvm
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_StatusQMP(status))
    )
    asked: list[str] = []

    def fake_bridge_stopped(inst):
        asked.append(status)
        return bridge_stopped

    monkeypatch.setattr(debug, "bridge_stopped", fake_bridge_stopped)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    args = _snap_args()
    args.format = "json"
    rc = _run(qmp_cmds._handle_snapshot_save, args)
    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["breakpoints_in_image"] == expected
    if expected == "possible":
        assert "[qmu] WARNING:" in captured.err
    elif expected == "lifted":
        assert "WARNING" not in captured.err and captured.err
    else:
        assert captured.err == ""
    # A pry command against a target GDB believes stopped halts a running VM,
    # so the bridge is consulted only while QEMU is already paused.
    assert set(asked) <= {"paused"}


def test_raw_savevm_classifies_like_snapshot_save(monkeypatch, capsys):
    """#227: the raw routes reach the same HMP `savevm` and compute the same
    classification; their envelopes carry it too, or a JSON caller saving
    through them gets only free text, worst for a foreign client with int3s
    in RAM (`possible`)."""
    inst = _gdb_inst(1234)
    inst.kvm = True
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(debug, "bridge_stopped", lambda inst: None)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok(f"Snapshot '{name}' saved.")
    )

    class _Monitor(_StatusQMP):
        def execute(self, command, arguments=None, timeout=30.0):
            if command == "human-monitor-command":
                return self.execute_hmp(arguments["command-line"])
            return super().execute(command, arguments, timeout)

        def execute_hmp(self, command_line, timeout=30.0):
            return ""

    for status, expected in (("debug", "lifted"), ("running", "possible")):
        monkeypatch.setattr(
            qmp_cmds, "_qmp_ctx", lambda inst, s=status: contextlib.nullcontext(_Monitor(s))
        )
        dedicated = _snap_args()
        dedicated.format = "json"
        assert _run(qmp_cmds._handle_snapshot_save, dedicated) == 0
        saved = json.loads(capsys.readouterr().out)
        assert saved["breakpoints_in_image"] == expected
        for handler, args in (
            (qmp_cmds._handle_monitor, _monitor_args(["savevm", "t"])),
            (qmp_cmds._handle_qmp, _hmp_qmp_args("savevm t")),
        ):
            args.format = "json"
            assert _run(handler, args) == 0
            captured = capsys.readouterr()
            payload = json.loads(captured.out)
            assert payload["breakpoints_in_image"] == expected
            assert "breakpoints_lifted" not in payload, "qmu stopped no bridge"
            assert ("[qmu] WARNING:" in captured.err) is (expected == "possible")


class _SequenceQMP(_FakeQMP):
    """query-status answers in order: the run state before, then after."""

    def __init__(self, *statuses):
        self.statuses = list(statuses)

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            status = self.statuses.pop(0)
            return {"running": status == "running", "status": status}
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        return ""


def test_a_breakpoint_hit_after_savevm_resumes_does_not_clear_the_image(
    monkeypatch, capsys
):
    """Review of #188, reproduced through to an int3 panic: savevm resumes a
    running guest before it returns, so a breakpoint hit in that gap reads
    `debug` afterwards for an image taken with the int3s in RAM. Running
    before the save is what decides: `possible`, on both routes."""
    inst = _gdb_inst(1234)
    inst.kvm = True
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'r' saved."))
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: contextlib.nullcontext(_SequenceQMP("running", "debug")),
    )
    args = _snap_args()
    args.format = "json"
    assert _run(qmp_cmds._handle_snapshot_save, args) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["breakpoints_in_image"] == "possible"
    assert "[qmu] WARNING:" in captured.err

    assert _run(qmp_cmds._handle_monitor, _monitor_args(["savevm", "r"])) == 0
    err = capsys.readouterr().err
    assert "[qmu] WARNING:" in err and "Note:" not in err


def test_reset_at_a_debugger_stop_says_to_boot_it_with_qmu_cont(monkeypatch, capsys):
    """Live (#183): a reset that lands while the debugger is stopped leaves
    QEMU in `prelaunch` and `pry continue` does not start it (the vCPU stays
    at the reset vector, KVM and TCG alike); `qmu cont` boots it. A reset of
    a running guest needs no cont."""
    inst = _gdb_inst(1234)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)
    monkeypatch.setattr(qmp_cmds, "save_guest_epoch_serial_offset", lambda inst, off: inst)

    class _Monitor(_StatusQMP):
        def execute_hmp(self, command_line, timeout=30.0):
            return ""

    for status, told in (("prelaunch", True), ("running", False)):
        monkeypatch.setattr(
            qmp_cmds, "_qmp_ctx", lambda inst, s=status: contextlib.nullcontext(_Monitor(s))
        )
        assert _run(qmp_cmds._handle_monitor, _monitor_args(["system_reset"])) == 0
        assert ("qmu cont --vm dg" in capsys.readouterr().err) is told


class _ContQMP(_StatusQMP):
    """`cont` runs the vCPU; `rehalt` is the status it is back in at once —
    an int3 no debugger owns re-runs (#237) — or None for a real resume."""

    def __init__(self, status, rehalt=None):
        super().__init__(status)
        self.rehalt = rehalt

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "cont":
            self.status = self.rehalt or "running"
            return {}
        return super().execute(command, arguments, timeout)


@pytest.mark.parametrize(
    "status,client,ours,resume",
    [
        ("debug", True, False, "pry --instance <id> continue --background"),
        ("paused", True, True, "pry --instance qmu-dg continue --background"),
        ("paused", True, False, None),  # a pause nobody can attribute
        ("paused", False, False, None),  # no client: nobody holds the stop
    ],
)
def test_cont_of_a_debugger_stop_says_it_resumed_behind_the_debugger(
    monkeypatch, capsys, status, client, ours, resume
):
    """Live (#225): `qmu cont` at a stop a debugger holds runs the guest with
    every breakpoint lifted while GDB still believes it stopped, and the
    next pry command halts it again. The resume still happens (exit 0); the
    envelope says so and names the debugger's own resume."""
    inst = _gdb_inst(1234)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_ContQMP(status))
    )
    monkeypatch.setattr(debug, "gdb_client_attached", lambda inst: client)
    monkeypatch.setattr(debug, "bridge_holds_stub", lambda inst: ours)
    args = argparse.Namespace(vm="dg", force=False, format="json", out=None)
    assert _run(qmp_cmds._handle_cont, args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    if resume is None:
        assert "warnings" not in payload
    else:
        (warning,) = payload["warnings"]
        assert f"`{resume}`" in warning


@pytest.mark.parametrize("rehalt", ["debug", None], ids=["int3-re-runs", "runs-on"])
def test_cont_at_a_breakpoint_no_debugger_owns_never_says_resumed(
    monkeypatch, capsys, rehalt
):
    """Live (#237): a debugger that died without detaching leaves its int3
    in RAM and in QEMU's breakpoint list; the guest halts in `debug` with no
    client on the stub. `qmu cont` re-runs the int3 and QEMU is back in
    `debug` at once — it answered exit 0 "resumed (status: debug)" and
    every hint said `qmu cont`. A new client is what clears it (QEMU drops
    a gone client's breakpoints), so every answer names that."""
    inst = _gdb_inst(1234)
    qmp = _ContQMP("debug", rehalt=rehalt)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: inst)
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(qmp))
    monkeypatch.setattr(qmp_cmds, "_CONT_SETTLE_SECONDS", 0.0)
    monkeypatch.setattr(debug, "gdb_client_attached", lambda inst: False)
    args = argparse.Namespace(vm="dg", force=False, format="json", out=None)

    rc = _run(qmp_cmds._handle_cont, args)
    payload = json.loads(capsys.readouterr().out)

    clear = "qmu gdb --vm dg --symbols <vmlinux>"
    if rehalt:
        assert rc == 1 and payload["ok"] is False
        assert payload["resumed"] is False
        assert payload["guest_state"] == "paused" and payload["qemu_status"] == "debug"
        assert clear in payload["hint"] and "pry --instance qmu-dg continue" in payload["hint"]
        assert "Resume with: qmu cont" not in payload["hint"]
    else:
        assert rc == 0 and payload["ok"] is True
        (warning,) = payload["warnings"]
        assert clear in warning


def test_a_paused_save_no_debugger_confirmed_does_not_send_the_reader_to_save_again(
    monkeypatch, capsys
):
    """Live (#229): under a client qmu did not spawn, the `running` save's
    recovery is to save at that client's stop — which is QEMU `paused` held
    across the save, a stop qmu cannot attribute, so `possible` again. That
    warning must not hand out the same recovery, or the reader loops."""
    inst = _gdb_inst(1234)
    inst.kvm = True
    _install_qmp_seams(monkeypatch, inst, present=True)
    monkeypatch.setattr(debug, "bridge_stopped", lambda inst: None)
    monkeypatch.setattr(qmp_cmds, "save_snapshot", lambda qmp, name, **kw: _ok("Snapshot 'clean' saved."))
    warnings = {}
    for status in ("running", "paused"):
        monkeypatch.setattr(
            qmp_cmds, "_qmp_ctx", lambda inst, s=status: contextlib.nullcontext(_StatusQMP(s))
        )
        args = _snap_args()
        args.format = "json"
        assert _run(qmp_cmds._handle_snapshot_save, args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["breakpoints_in_image"] == "possible"
        (warnings[status],) = payload["warnings"]
    assert "qmu snapshot save --vm dg" in warnings["running"]
    assert "qmu snapshot save" not in warnings["paused"]
    assert warnings["paused"] != warnings["running"]


# --- a guest reboot nobody issued is announced by the next command (#184) ----


_BANNER = b"[    0.000000] Linux version 6.1.11 (qmu@kbuild) (gcc 11.4.0) #1 SMP\n"


def _rebooting_vm(tmp_path, monkeypatch, *, attached=True):
    from qmu.instance import save_instance

    log = tmp_path / "rb.serial.log"
    log.write_bytes(b"SeaBIOS\n" + _BANNER + b"localhost login: \n")
    inst = VMInstance(
        vm_id="rb", pid=os.getpid(), qmp_socket=str(tmp_path / "rb.sock"), ssh_port=None,
        ssh_key=None, gdb_port=1234, serial_log=str(log), kernel="/k",
        rootfs=None, memory="1G", cpus=1, cmdline="", profile="exploit-dev",
        started_at="2026-01-01T00:00:00+00:00",
    )
    save_instance(inst)
    monkeypatch.setattr(debug, "gdb_client_attached", lambda inst: attached)
    return inst, log


def _reboot(log):
    with log.open("ab") as f:
        f.write(b"reboot: Restarting system\nSeaBIOS\n" + _BANNER + b"localhost login: \n")


def _announce(vm_id="rb"):
    from qmu.instance import load_instance

    debug.reset_coherence_warnings()
    debug.check_unwarned_reboot(load_instance(vm_id))
    return debug.coherence_warnings()


def test_guest_reboot_is_announced_once_by_the_next_command(tmp_path, monkeypatch, capsys):
    inst, log = _rebooting_vm(tmp_path, monkeypatch)
    debug.mark_debugger_attached(inst)
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx", lambda inst: contextlib.nullcontext(_StatusQMP("running"))
    )
    argv = ["--format", "json", "qmp", "query-status", "--vm", "rb"]

    assert cli.main(argv) == 0
    assert "warnings" not in json.loads(capsys.readouterr().out)

    _reboot(log)
    assert cli.main(argv) == 0
    captured = capsys.readouterr()
    warnings = json.loads(captured.out)["warnings"]
    assert len(warnings) == 1 and "rebooted by itself" in warnings[0]
    assert captured.err.count("rebooted by itself") == 1

    assert cli.main(argv) == 0
    assert "warnings" not in json.loads(capsys.readouterr().out)


def test_a_reset_qmu_warned_about_is_not_announced_again(tmp_path, monkeypatch):
    """`system_reset` warns itself; the boot it starts is that same generation."""
    inst, log = _rebooting_vm(tmp_path, monkeypatch)
    debug.mark_debugger_epoch(inst, log.stat().st_size, banners=1)
    _reboot(log)
    assert _announce() == ()
    _reboot(log)
    assert len(_announce()) == 1


def test_a_reboot_after_snapshot_load_is_announced(tmp_path, monkeypatch):
    """A restored guest prints no banner, so the first one after it is news."""
    inst, log = _rebooting_vm(tmp_path, monkeypatch)
    debug.mark_debugger_epoch(inst, log.stat().st_size, banners=0)
    _reboot(log)
    assert len(_announce()) == 1


def test_reboot_with_no_client_attached_moves_the_epoch_silently(tmp_path, monkeypatch):
    """Nobody to warn; a debugger attaching later sees the new boot, so the
    reboot must not be announced to it afterwards."""
    inst, log = _rebooting_vm(tmp_path, monkeypatch, attached=False)
    debug.mark_debugger_attached(inst)
    _reboot(log)
    assert _announce() == ()
    monkeypatch.setattr(debug, "gdb_client_attached", lambda inst: True)
    assert _announce() == ()


def test_first_boot_is_not_a_reboot_without_a_qmu_attach(tmp_path, monkeypatch):
    """A hand-started bridge leaves no attach point; the first boot is the
    one it saw, a second banner is a reboot."""
    inst, log = _rebooting_vm(tmp_path, monkeypatch)
    assert _announce() == ()
    _reboot(log)
    assert len(_announce()) == 1
