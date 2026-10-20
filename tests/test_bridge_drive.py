"""Driving the pry bridge qmu owns after a rewind or reset (#187).

After a `snapshot load` (or a raw `loadvm`) or a qmu-issued `system_reset`,
the bridge `qmu gdb` spawned is re-synced with `pry resync` or torn down with
the reason and the breakpoints it lost; a client qmu did not spawn is only
warned about. The bridge here is a throwaway `sleep` (so `bridge_alive` runs
for real) and `pry` is a fake on PATH that answers from a scripted queue and
logs its argv; the `pry resync` report shape is the one pry ships (pry #61).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from qmu import cli, debug
from qmu.commands import qmp_cmds
from qmu.instance import VMInstance, load_instance, proc_pid_start, save_instance
from qmu.snapshot import SnapshotResult

VM = "drv"
BANNER = "[    0.000000] Linux version 6.1.11 (b@h) (gcc) #1 SMP\n"


def _entry(status, **over):
    entry = {
        "address": "0xffffffff810881d0", "function": "__x64_sys_newuname",
        "kind": "breakpoint", "location": "1.1", "number": 1, "status": status,
    }
    entry.update(over)
    return entry


def _report(*entries, state="running"):
    entries = list(entries)
    not_armed = {"pending", "unreadable", "insert-failed", "not-resident"}
    return {
        "resynced": True, "state": state, "status": state,
        "run_state": {"was_running": True, "interrupted": True, "resumed": state == "running"},
        "breakpoints": entries,
        "summary": {
            "breakpoints": len(entries),
            "armed": sum(e["status"] == "armed" for e in entries),
            "not_armed": sum(e["status"] in not_armed for e in entries),
            "baked_traps": 0, "repaired": 0,
            "elf_mismatch": sum(e.get("elf_match") is False for e in entries),
        },
    }


BREAK_LIST = [{
    "number": 1, "location": "__x64_sys_newuname", "enabled": True,
    "kind": "breakpoint", "hits": 2, "address": "0xffffffff810881d0",
}]

_FAKE_PRY = r'''
import json, os, signal, sys
spec = os.environ["FAKE_PRY_DIR"]
argv = sys.argv[1:]
with open(os.path.join(spec, "calls.jsonl"), "a") as log:
    log.write(json.dumps(argv) + "\n")
cmd = argv[0]
if cmd == "kill":
    os.kill(int(argv[2]), signal.SIGTERM)
    print(json.dumps({"killed": True}))
    sys.exit(0)
path = os.path.join(spec, cmd + ".json")
queue = json.load(open(path))
answer = queue.pop(0) if len(queue) > 1 else queue[0]
json.dump(queue, open(path, "w"))
if answer.get("rc", 0):
    print(json.dumps({"ok": False, "error": answer["error"]}), file=sys.stderr)
    sys.exit(answer["rc"])
print(json.dumps(answer["result"]))
'''


@pytest.fixture
def bridge():
    proc = subprocess.Popen(["sleep", "60"])
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait()


@pytest.fixture
def pry(tmp_path, monkeypatch):
    """Fake `pry`: `answers(resync=[...], break_=[...])` scripts its replies."""
    spec = tmp_path / "pry"
    spec.mkdir()
    exe = spec / "pry"
    exe.write_text(f"#!{sys.executable}\n{_FAKE_PRY}")
    exe.chmod(0o755)
    monkeypatch.setenv("FAKE_PRY_DIR", str(spec))
    monkeypatch.setattr(debug.shutil, "which", lambda name: str(exe))

    class Pry:
        def answers(self, *, resync=None, break_=None):
            if resync is not None:
                (spec / "resync.json").write_text(json.dumps(resync))
            if break_ is not None:
                (spec / "break.json").write_text(json.dumps(break_))

        def calls(self):
            log = spec / "calls.jsonl"
            if not log.exists():
                return []
            return [json.loads(line) for line in log.read_text().splitlines()]

        def ran(self, cmd):
            return [c for c in self.calls() if c[0] == cmd]

    fake = Pry()
    fake.answers(break_=[{"result": BREAK_LIST}])
    return fake


class _QMP:
    """QEMU double: a reset appends the new boot's banner to the console."""

    def __init__(self, inst, *, running=True):
        self.inst = inst
        self.running = running

    def _reset(self):
        with open(self.inst.serial_log, "a") as log:
            log.write(BANNER)

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            return {"running": self.running, "status": "running" if self.running else "prelaunch"}
        if command == "system_reset":
            self._reset()
            return {}
        if command == "human-monitor-command":
            return self.execute_hmp(arguments["command-line"])
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        if command_line.split()[0] == "system_reset":
            self._reset()
        return ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _vm(tmp_path, monkeypatch, bridge, *, cmdline="console=ttyS0 nokaslr", running=True):
    serial = tmp_path / f"{VM}.serial.log"
    serial.write_text(BANNER + "login: \n")
    inst = VMInstance(
        vm_id=VM, pid=os.getpid(), pid_start=proc_pid_start(os.getpid()),
        qmp_socket=str(tmp_path / "q.sock"), ssh_port=None, ssh_key=None,
        gdb_port=1234, serial_log=str(serial), kernel="/k", rootfs=None,
        memory="1G", cpus=1, cmdline=cmdline, profile="exploit-dev",
        started_at="2026-01-01T00:00:00+00:00", arch="x86_64", kvm=True,
        gdb_bridge_pid=bridge.pid if bridge else None,
        gdb_bridge_pid_start=proc_pid_start(bridge.pid) if bridge else None,
    )
    save_instance(inst)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: load_instance(VM))
    monkeypatch.setattr(qmp_cmds, "_qmp_ctx", lambda inst: _QMP(inst, running=running))
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name: SnapshotResult(True, f"Snapshot '{name}' loaded."),
    )
    monkeypatch.setattr(debug, "_RESYNC_RETRY_SECONDS", 0.0)
    return inst


_LOAD_ROUTES = {
    "snapshot load": ["snapshot", "load", "clean"],
    "monitor loadvm": ["monitor", "loadvm", "clean"],
    "qmp hmp loadvm": [
        "qmp", "human-monitor-command", "--args", '{"command-line": "loadvm clean"}',
    ],
}
_RESET_ROUTES = {
    "qmp system_reset": ["qmp", "system_reset"],
    "monitor system_reset": ["monitor", "system_reset"],
    "qmp hmp system_reset": [
        "qmp", "human-monitor-command", "--args", '{"command-line": "system_reset"}',
    ],
}


def _json(capsys, argv):
    rc = cli.main(["--format", "json", *argv, "--vm", VM])
    return rc, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("route", sorted(_LOAD_ROUTES))
def test_every_load_route_resyncs_the_owned_bridge_and_reports_prys_result(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    report = _report(_entry("armed", trap_resident=True, elf_match=True))
    pry.answers(resync=[{"result": report}])

    rc, payload = _json(capsys, _LOAD_ROUTES[route])

    assert rc == 0 and payload["ok"] is True
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["bridge_pid"] == bridge.pid
    assert drive["resync"] == report
    assert "warnings" not in payload, "a fully armed re-sync leaves nothing to act on"
    assert pry.ran("resync") == [[
        "resync", "--instance", str(bridge.pid), "--format", "json",
        "--timeout", str(debug.PRY_RESYNC_TIMEOUT),
    ]]
    assert bridge.poll() is None, "a re-synced bridge is kept"


def test_load_text_mode_keeps_stdout_and_puts_the_receipt_on_stderr(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    pry.answers(resync=[{"result": _report(_entry("armed", trap_resident=True))}])

    rc = cli.main(["snapshot", "load", "clean", "--vm", VM])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == "Snapshot 'clean' loaded.\n"
    assert f"qmu-{VM}" in captured.err and "__x64_sys_newuname" in captured.err


def test_a_resync_that_leaves_breakpoints_unarmed_keeps_the_bridge_and_warns(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    report = _report(
        _entry("armed", trap_resident=True),
        _entry("pending", location="2.1", number=2, function="do_sys_poll"),
    )
    pry.answers(resync=[{"result": report}])

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert payload["debugger"]["action"] == "resynced"
    (warning,) = payload["warnings"]
    assert "#2.1 pending" in warning and "do_sys_poll" in warning
    assert "#1.1" not in warning, "an armed location is not reported as a problem"
    assert bridge.poll() is None


def test_a_failed_resync_tears_the_bridge_down_and_lists_what_it_lost(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    pry.answers(resync=[{"rc": 1, "error": "RuntimeError: remote target lost"}])

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0, "the load itself succeeded"
    drive = payload["debugger"]
    assert drive["action"] == "torn_down"
    assert "remote target lost" in drive["reason"]
    assert drive["bridge_reaped"] is True
    assert drive["breakpoints_dropped"] == BREAK_LIST
    assert bridge.wait(timeout=5) is not None
    assert load_instance(VM).gdb_bridge_pid is None
    (warning,) = payload["warnings"]
    assert "#1 __x64_sys_newuname" in warning


def test_a_client_qmu_did_not_spawn_is_warned_about_never_driven(
    tmp_path, monkeypatch, capsys, pry
):
    _vm(tmp_path, monkeypatch, None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert "debugger" not in payload
    assert payload["warnings"] == [
        debug.loadvm_stale_session_warning(VM).removeprefix("[qmu] WARNING: ")
    ]
    assert pry.calls() == []


@pytest.mark.parametrize("restore_state", ["partial", "unknown"])
def test_a_load_that_failed_mid_restore_never_drives_the_bridge(
    restore_state, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Re-syncing or detaching can resume a half-restored machine (#87)."""
    _vm(tmp_path, monkeypatch, bridge)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name: SnapshotResult(
            False, "Error: Error -22 while loading VM state", reason="hmp",
            guest_paused=True, restore_state=restore_state,
        ),
    )

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 1
    assert "debugger" not in payload
    assert pry.calls() == []
    assert bridge.poll() is None


@pytest.mark.parametrize("route", sorted(_RESET_ROUTES))
def test_every_reset_route_resyncs_a_nokaslr_bridge_once_the_new_kernel_is_up(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    armed = _report(_entry("armed", trap_resident=True, reseated=True))
    pry.answers(resync=[{"result": _report(_entry("unreadable"))}, {"result": armed}])

    rc, payload = _json(capsys, _RESET_ROUTES[route])

    assert rc == 0
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["attempts"] == 2, "an unreadable site is retried until it maps"
    assert drive["resync"] == armed
    assert "warnings" not in payload
    assert bridge.poll() is None


def test_a_reset_whose_sites_never_map_keeps_the_bridge_and_says_so(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    monkeypatch.setattr(debug, "RESET_KERNEL_WAIT_SECONDS", 0.2)
    pry.answers(resync=[{"result": _report(_entry("unreadable"))}])

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    assert payload["debugger"]["action"] == "resynced"
    (warning,) = payload["warnings"]
    assert "#1.1 unreadable" in warning
    assert bridge.poll() is None


def test_a_kaslr_reset_tears_the_bridge_down_without_resyncing_it(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """Re-syncing against the previous boot's base would arm breakpoints at
    addresses the re-slid kernel uses for other code."""
    _vm(tmp_path, monkeypatch, bridge, cmdline="console=ttyS0 root=/dev/sda")

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    drive = payload["debugger"]
    assert drive["action"] == "torn_down"
    assert drive["breakpoints_dropped"] == BREAK_LIST
    assert pry.ran("resync") == []
    assert bridge.wait(timeout=5) is not None


def test_a_reset_of_a_halted_guest_tears_the_bridge_down(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """Halted at the reset vector no kernel address is readable and GDB
    cannot resume past breakpoints it cannot insert."""
    _vm(tmp_path, monkeypatch, bridge, running=False)

    rc, payload = _json(capsys, ["monitor", "system_reset"])

    assert rc == 0
    assert payload["debugger"]["action"] == "torn_down"
    assert pry.ran("resync") == []
    assert bridge.wait(timeout=5) is not None


def test_a_reset_with_no_owned_bridge_keeps_the_warning(tmp_path, monkeypatch, capsys, pry):
    _vm(tmp_path, monkeypatch, None)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    assert "debugger" not in payload
    assert payload["warnings"] == [
        debug.reset_dropped_breakpoints_warning(VM).removeprefix("[qmu] WARNING: ")
    ]
    assert pry.calls() == []


def test_a_spilled_resync_report_is_read_from_its_artifact(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """pry spills a large result and prints a pointer; qmu reads the file."""
    _vm(tmp_path, monkeypatch, bridge)
    report = _report(_entry("armed", trap_resident=True))
    artifact = tmp_path / "resync.json"
    artifact.write_text(json.dumps(report))
    pry.answers(resync=[{"result": {"artifact_path": str(artifact), "tokens": 12000}}])

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert payload["debugger"]["resync"] == report
