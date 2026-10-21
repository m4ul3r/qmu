"""Driving the pry bridge qmu owns after a rewind or reset (#187, #200) and
around a save (#201).

After a `snapshot load` (or a raw `loadvm`) or a qmu-issued `system_reset`,
the bridge `qmu gdb` spawned is re-synced with `pry resync` (on a KASLR guest
after `pry kbase` rebased it) or torn down with the reason and the
breakpoints it lost; a client qmu did not spawn is only warned about. A save
of a running KVM guest stops that bridge across the savevm. The bridge here
is a throwaway `sleep` (so `bridge_alive` runs for real) and `pry` is a fake
on PATH that answers from a scripted queue and logs its argv; the `pry
resync`/`pry kbase` report shapes are the ones pry ships (pry #61, #66).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

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

KBASE = {
    "base": "0xffffffff92000000", "slide": "0x11000000", "method": "idt",
    "apply": {"path": "/vmlinux", "applied": True, "previous_slide": "0x4e00000"},
}

_FAKE_PRY = r'''
import json, os, signal, sys
spec = os.environ["FAKE_PRY_DIR"]
argv = sys.argv[1:]
if argv[:1] == ["--instance"]:
    # `pry --instance ID status` → log it as `status --instance ID`.
    argv = argv[2:3] + argv[:2] + argv[3:]
with open(os.path.join(spec, "calls.jsonl"), "a") as log:
    log.write(json.dumps(argv) + "\n")
if argv[0] in ("resync", "kbase") and os.environ.get("FAKE_PRY_SERIAL"):
    # Was the new boot's end of kernel init on the console when qmu armed?
    with open(os.environ["FAKE_PRY_SERIAL"]) as serial:
        seen = "as init process" in serial.read()
    with open(os.path.join(spec, "init_seen.jsonl"), "a") as log:
        log.write(json.dumps(seen) + "\n")
cmd = argv[0]
if cmd == "kill":
    os.kill(int(argv[2]), signal.SIGTERM)
    print(json.dumps({"killed": True}))
    sys.exit(0)
# The debugger's stop: `interrupt` takes one (QEMU then reports `paused`, or
# `debug` for a breakpoint the target hit by itself), `continue` ends it,
# `status` reads it. The file holds QEMU's run state at that stop.
stopped = os.path.join(spec, "stopped")
if cmd == "status":
    print(json.dumps({"state": "stopped" if os.path.exists(stopped) else "running"}))
    sys.exit(0)
path = os.path.join(spec, cmd + ".json")
queue = json.load(open(path))
answer = queue.pop(0) if len(queue) > 1 else queue[0]
json.dump(queue, open(path, "w"))
if answer.get("rc", 0):
    print(json.dumps({"ok": False, "error": answer["error"]}), file=sys.stderr)
    sys.exit(answer["rc"])
if cmd == "interrupt" and answer["result"].get("stopped") and not os.path.exists(stopped):
    reason = answer["result"].get("reason") or {}
    with open(stopped, "w") as mark:
        mark.write("debug" if reason.get("kind") == "breakpoint-hit" else "paused")
elif cmd == "continue" and os.path.exists(stopped):
    os.remove(stopped)
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
        def answers(self, *, resync=None, break_=None, kbase=None, interrupt=None,
                    continue_=None):
            for cmd, queue in (
                ("resync", resync), ("break", break_), ("kbase", kbase),
                ("interrupt", interrupt), ("continue", continue_),
            ):
                if queue is not None:
                    (spec / f"{cmd}.json").write_text(json.dumps(queue))

        def stopped(self):
            """Whether the fake bridge is at a debugger stop now."""
            return (spec / "stopped").exists()

        def stop(self, qemu_status="paused"):
            """Put the target at a debugger stop before the command runs."""
            (spec / "stopped").write_text(qemu_status)

        def calls(self):
            log = spec / "calls.jsonl"
            if not log.exists():
                return []
            return [json.loads(line) for line in log.read_text().splitlines()]

        def ran(self, cmd):
            return [c for c in self.calls() if c[0] == cmd]

        def init_seen_at_resync(self):
            log = spec / "init_seen.jsonl"
            if not log.exists():
                return []
            return [json.loads(line) for line in log.read_text().splitlines()]

    fake = Pry()
    fake.answers(
        break_=[{"result": BREAK_LIST}],
        kbase=[{"result": KBASE}],
        interrupt=[{"result": {
            "interrupted": True, "stopped": True, "state": "stopped",
            "reason": {"kind": "signal", "signal": "SIGINT"},
        }}],
        continue_=[{"result": {"state": "running"}}],
    )
    return fake


INIT_DONE = "[    1.353989] Run /sbin/init as init process\n"


class _QMP:
    """QEMU double: a reset appends the new boot's banner to the console at
    once and, `init_after` seconds later, the end of kernel init (`None`: a
    `quiet` boot that never prints it). A running guest reads `paused` while
    the fake bridge is at a debugger stop; `saves` records the run state
    each savevm ran in."""

    saves: list[str] = []

    def __init__(self, inst, *, running=True, init_after=0.3, init_text=None):
        self.inst = inst
        self.running = running
        self.init_after = init_after
        self.init_text = init_text

    def _status(self):
        if not self.running:
            return "prelaunch"
        stopped = os.path.join(os.environ.get("FAKE_PRY_DIR", "/nonexistent"), "stopped")
        if not os.path.exists(stopped):
            return "running"
        with open(stopped) as mark:
            return mark.read() or "paused"

    def savevm(self):
        _QMP.saves.append(self._status())

    def _reset(self):
        with open(self.inst.serial_log, "a") as log:
            log.write(BANNER)
        if self.init_after is None:
            return

        def finish_init():
            time.sleep(self.init_after)
            with open(self.inst.serial_log, "a") as log:
                if self.init_text is not None:
                    log.write(self.init_text)
                    return
                log.write("[    0.216847] Freeing SMP alternatives memory: 44K\n")
                log.write(INIT_DONE)

        threading.Thread(target=finish_init, daemon=True).start()

    def execute(self, command, arguments=None, timeout=30.0):
        if command == "query-status":
            status = self._status()
            return {"running": status == "running", "status": status}
        if command == "system_reset":
            self._reset()
            return {}
        if command == "human-monitor-command":
            return self.execute_hmp(arguments["command-line"])
        return {}

    def execute_hmp(self, command_line, timeout=30.0):
        verb = command_line.split()[0]
        if verb == "system_reset":
            self._reset()
        elif verb == "savevm":
            self.savevm()
        return ""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _vm(
    tmp_path, monkeypatch, bridge, *, cmdline="console=ttyS0 nokaslr",
    running=True, init_after=0.3, kvm=True, init_text=None,
):
    serial = tmp_path / f"{VM}.serial.log"
    serial.write_text(BANNER + "login: \n")
    monkeypatch.setenv("FAKE_PRY_SERIAL", str(serial))
    inst = VMInstance(
        vm_id=VM, pid=os.getpid(), pid_start=proc_pid_start(os.getpid()),
        qmp_socket=str(tmp_path / "q.sock"), ssh_port=None, ssh_key=None,
        gdb_port=1234, serial_log=str(serial), kernel="/k", rootfs=None,
        memory="1G", cpus=1, cmdline=cmdline, profile="exploit-dev",
        started_at="2026-01-01T00:00:00+00:00", arch="x86_64", kvm=kvm,
        gdb_bridge_pid=bridge.pid if bridge else None,
        gdb_bridge_pid_start=proc_pid_start(bridge.pid) if bridge else None,
    )
    save_instance(inst)
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm=None: load_instance(VM))
    monkeypatch.setattr(
        qmp_cmds, "_qmp_ctx",
        lambda inst: _QMP(
            inst, running=running, init_after=init_after, init_text=init_text
        ),
    )
    monkeypatch.setattr(qmp_cmds, "_drop_ssh_master", lambda inst: None)
    monkeypatch.setattr(
        qmp_cmds, "load_snapshot",
        lambda qmp, name: SnapshotResult(True, f"Snapshot '{name}' loaded."),
    )
    monkeypatch.setattr(_QMP, "saves", [])

    def save_snapshot(qmp, name, timeout=None):
        qmp.savevm()
        return SnapshotResult(True, f"Snapshot '{name}' saved.")

    monkeypatch.setattr(qmp_cmds, "save_snapshot", save_snapshot)
    monkeypatch.setattr(debug, "RESET_KERNEL_WAIT_SECONDS", 5.0)
    # The sleeper owns no socket: model "the recorded bridge holds the stub"
    # as "it is alive" (the hand-started tests record no bridge at all).
    monkeypatch.setattr(debug, "bridge_holds_stub", debug.bridge_alive)
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
_SAVE_ROUTES = {
    "snapshot save": ["snapshot", "save", "clean"],
    "monitor savevm": ["monitor", "savevm", "clean"],
    "qmp hmp savevm": [
        "qmp", "human-monitor-command", "--args", '{"command-line": "savevm clean"}',
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
        debug.loadvm_stale_session_warning(load_instance(VM)).removeprefix("[qmu] WARNING: ")
    ]
    assert pry.calls() == []


def test_qmus_bridge_that_lost_the_stub_to_another_client_is_not_driven(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """A live recorded bridge proves nothing about who holds the stub (#186):
    re-syncing it would leave the client that does hold it unwarned."""
    _vm(tmp_path, monkeypatch, bridge)
    monkeypatch.setattr(debug, "bridge_holds_stub", lambda inst: False)
    monkeypatch.setattr(qmp_cmds, "debug_session_present", lambda inst: True)

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert "debugger" not in payload
    assert len(payload["warnings"]) == 1
    assert pry.calls() == []
    assert bridge.poll() is None


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
def test_every_reset_route_resyncs_a_nokaslr_bridge_only_after_kernel_init(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """The new kernel patches its own text at boot (alternatives, return
    thunks); a breakpoint armed before that trips the patcher, so the banner
    alone is not enough — qmu arms once the end of kernel init is on the
    console."""
    _vm(tmp_path, monkeypatch, bridge, init_after=0.4)
    armed = _report(_entry("armed", trap_resident=True))
    pry.answers(resync=[{"result": armed}])

    rc, payload = _json(capsys, _RESET_ROUTES[route])

    assert rc == 0
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["resync"] == armed
    assert pry.init_seen_at_resync() == [True], "armed once, after kernel init"
    assert "warnings" not in payload
    assert bridge.poll() is None


def test_a_reset_whose_kernel_never_shows_init_is_not_resynced_and_says_so(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """A boot that shows neither the end of init nor a `login:` prompt (a
    `quiet` console with no getty on it): qmu cannot prove the boot-time
    patching is over, so it arms nothing and keeps the bridge."""
    _vm(tmp_path, monkeypatch, bridge, init_after=None)
    monkeypatch.setattr(debug, "RESET_KERNEL_WAIT_SECONDS", 0.3)

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    assert payload["debugger"]["action"] == "not_resynced"
    assert pry.ran("resync") == []
    assert bridge.poll() is None
    assert len(payload["warnings"]) == 2, "why, then the manual recovery"


QUIET_LOGIN = "\r\nDebian GNU/Linux 12 drv ttyS0\r\n\r\ndrv login: "


def test_a_quiet_reset_is_resynced_once_the_getty_prompts(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """Live (#205): a `quiet` console never prints the end of kernel init,
    so every reset blocked the whole budget and armed nothing, while the
    guest served 5 s in. The getty's `login:` prompt, which `quiet` does
    not hide, comes after init and ends the wait."""
    _vm(
        tmp_path, monkeypatch, bridge, cmdline="console=ttyS0 nokaslr quiet",
        init_text=QUIET_LOGIN,
    )
    armed = _report(_entry("armed", trap_resident=True))
    pry.answers(resync=[{"result": armed}])

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["waited_seconds"] < debug.RESET_KERNEL_WAIT_SECONDS
    assert drive["resync"] == armed


@pytest.mark.parametrize("route", [["snapshot", "load", "clean"], ["qmp", "system_reset"]])
def test_pry_missing_from_qmus_path_leaves_a_healthy_bridge_alone(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Nothing is wrong with the bridge when qmu cannot find `pry`: tearing
    it down would lose its breakpoints for nothing."""
    _vm(tmp_path, monkeypatch, bridge)
    monkeypatch.setattr(debug.shutil, "which", lambda name: None)

    rc, payload = _json(capsys, route)

    assert rc == 0
    assert payload["debugger"]["action"] == "not_resynced"
    assert bridge.poll() is None
    assert load_instance(VM).gdb_bridge_pid == bridge.pid
    assert len(payload["warnings"]) == 2


@pytest.mark.parametrize("cmdline", ["console=ttyS0 nokaslr", "console=ttyS0"])
def test_boot_patched_code_under_a_breakpoint_is_no_warning_once_the_base_is_known(
    cmdline, tmp_path, monkeypatch, capsys, bridge, pry
):
    """`elf_match: false` where the symbols sit at the kernel's base — a
    nokaslr kernel, or the base `pry kbase` validated on a KASLR one — is the
    kernel's own boot-time patching: the breakpoint is where it was set."""
    _vm(tmp_path, monkeypatch, bridge, cmdline=cmdline)
    patched = _entry("armed", trap_resident=True, elf_match=False,
                     guest_bytes="c3", elf_bytes="e9")
    pry.answers(resync=[{"result": _report(patched)}])

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert payload["debugger"]["action"] == "resynced"
    assert "warnings" not in payload


@pytest.mark.parametrize("route", sorted(_LOAD_ROUTES))
def test_a_kaslr_load_rebases_the_bridge_before_it_resyncs(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Live (#200): an image saved before a reset or reboot restores the
    kernel at that boot's base; a re-sync at the bridge's base armed the
    breakpoint where nothing ran. `pry kbase` first rebases to the restored
    kernel, at a stop qmu holds, and qmu resumes only after the re-sync."""
    _vm(tmp_path, monkeypatch, bridge, cmdline="console=ttyS0")
    report = _report(_entry("armed", trap_resident=True, elf_match=True), state="stopped")
    pry.answers(resync=[{"result": report}])

    rc, payload = _json(capsys, _LOAD_ROUTES[route])

    assert rc == 0
    assert [c[0] for c in pry.calls()] == ["interrupt", "kbase", "resync", "continue"]
    assert not pry.stopped()
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["kbase"] == KBASE and drive["resync"] == report
    assert drive["interrupted"] is True and drive["resumed"] is True
    assert bridge.poll() is None


@pytest.mark.parametrize(
    ("cmdline", "drive"),
    [("console=ttyS0", ["interrupt", "kbase", "resync"]),
     ("console=ttyS0 nokaslr", ["interrupt", "resync"])],
    ids=["kaslr", "nokaslr"],
)
def test_a_load_into_a_debugger_stop_resyncs_there_and_resumes_nothing(
    cmdline, drive, tmp_path, monkeypatch, capsys, bridge, pry
):
    """A target the operator had stopped stays at that stop."""
    _vm(tmp_path, monkeypatch, bridge, cmdline=cmdline)
    pry.stop()
    pry.answers(
        interrupt=[{"result": {"interrupted": False, "stopped": True, "state": "stopped"}}],
        resync=[{"result": _report(_entry("armed", trap_resident=True), state="stopped")}],
    )

    rc, payload = _json(capsys, ["snapshot", "load", "clean"])

    assert rc == 0
    assert [c[0] for c in pry.calls()] == drive
    assert pry.stopped()
    assert payload["debugger"]["action"] == "resynced"
    assert "interrupted" not in payload["debugger"]


_STALE_INTERRUPT = [{"result": {
    "interrupted": False, "stopped": True, "state": "stopped",
    "reason": {"kind": "signal", "signal": "SIGINT"},
}}]


@pytest.mark.parametrize(
    "route", [
        ["snapshot", "save", "clean"], ["monitor", "savevm", "clean"],
        ["snapshot", "load", "clean"], ["monitor", "loadvm", "clean"],
        ["qmp", "system_reset"],
    ],
    ids=lambda argv: " ".join(argv[:2]),
)
@pytest.mark.parametrize("cmdline", ["console=ttyS0", "console=ttyS0 nokaslr"])
def test_a_guest_resumed_behind_the_bridges_back_is_running_after_qmu_drives_it(
    route, cmdline, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Live (#226): after `qmu gdb` → `qmu cont` GDB believes the target
    stopped while QEMU runs it. Its first packet halts the guest, and `pry
    interrupt` answers `interrupted: false` for that stop; trusting it left
    the running guest halted after a save, a load and a KASLR reset. QEMU
    said `running` before qmu touched the bridge and is at no breakpoint
    stop after, so the stop is qmu's and qmu resumes it."""
    _vm(tmp_path, monkeypatch, bridge, cmdline=cmdline)
    pry.answers(
        interrupt=_STALE_INTERRUPT,
        resync=[{"result": _report(_entry("armed", trap_resident=True), state="stopped")}],
    )

    rc, payload = _json(capsys, route)

    assert rc == 0
    assert pry.ran("continue"), "qmu resumes the stop it made"
    assert not pry.stopped(), "the guest runs again"
    drive = payload["debugger"]
    assert drive["interrupted"] is True and drive["resumed"] is True
    assert drive["stale_stop"] is True
    if route[1] in ("save", "savevm"):
        assert _QMP.saves == ["paused"], "saved at the stop, with GDB's breakpoints lifted"
        assert payload["breakpoints_in_image"] == "lifted"
        assert payload["breakpoints_lifted"] is True


@pytest.mark.parametrize("route", [["snapshot", "load", "clean"], ["qmp", "system_reset"]])
def test_a_kaslr_base_pry_cannot_validate_is_never_armed_at_the_old_one(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Review of #200, live: `pry kbase` on a running target stops it and
    resumes it even when it fails, and under KVM that resume re-inserted
    every breakpoint at the bridge's stale base while qmu said none was
    armed. `pry kbase` now runs at a stop qmu holds, and a failure keeps
    that stop: nothing is resumed, re-synced or torn down."""
    _vm(tmp_path, monkeypatch, bridge, cmdline="console=ttyS0")
    pry.answers(kbase=[{"rc": 1, "error": "no kernel symbol file is loaded"}])

    rc, payload = _json(capsys, route)

    assert rc == 0
    assert [c[0] for c in pry.calls()] == ["interrupt", "kbase"]
    assert pry.stopped(), "the target stays at qmu's stop: no breakpoint in RAM"
    drive = payload["debugger"]
    assert drive["action"] == "not_resynced"
    assert drive["interrupted"] is True and drive["resumed"] is False
    assert "no kernel symbol file is loaded" in drive["reason"]
    assert bridge.poll() is None
    assert any(
        f"pry --instance qmu-{VM} continue --background" in w for w in payload["warnings"]
    )


def test_a_kaslr_reset_rebases_and_resyncs_after_kernel_init(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """`pry kbase` reads the re-slid base with no SSH (pry #66), so the
    bridge is kept: rebased and re-armed once the new kernel finished
    patching its own text."""
    _vm(tmp_path, monkeypatch, bridge, cmdline="console=ttyS0 root=/dev/sda")
    report = _report(_entry("armed", trap_resident=True, elf_match=True), state="stopped")
    pry.answers(resync=[{"result": report}])

    rc, payload = _json(capsys, ["qmp", "system_reset"])

    assert rc == 0
    assert [c[0] for c in pry.calls()] == ["interrupt", "kbase", "resync", "continue"]
    assert pry.init_seen_at_resync() == [True, True]
    assert not pry.stopped()
    drive = payload["debugger"]
    assert drive["action"] == "resynced"
    assert drive["kbase"] == KBASE
    assert bridge.poll() is None


@pytest.mark.parametrize("route", sorted(_SAVE_ROUTES))
def test_a_save_of_a_running_guest_stops_the_owned_bridge_across_it(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """Live (#201): with qmu's bridge running the guest under KVM, a save
    baked its int3s into the image. qmu stops the bridge (GDB lifts them),
    saves at that stop and resumes it."""
    _vm(tmp_path, monkeypatch, bridge)

    rc, payload = _json(capsys, _SAVE_ROUTES[route])

    assert rc == 0
    assert _QMP.saves == ["paused"], "the savevm ran at the debugger's stop"
    assert [c[0] for c in pry.calls() if c[0] != "status"] == ["interrupt", "continue"]
    assert not pry.stopped(), "the bridge is resumed after the save"
    drive = payload["debugger"]
    assert drive["action"] == "stopped_for_save"
    assert drive["interrupted"] is True and drive["resumed"] is True
    assert payload["breakpoints_in_image"] == "lifted"
    assert payload["breakpoints_lifted"] is True


def test_a_save_that_found_the_bridge_stopped_by_itself_leaves_that_stop(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """A breakpoint hit between QEMU's `running` and qmu's interrupt (QEMU
    `debug` after it) is the operator's stop: the save is taken there and
    nothing resumes it. The guest the save found running is now halted, and
    a JSON caller is told so with the resume command (#226)."""
    _vm(tmp_path, monkeypatch, bridge)
    pry.answers(interrupt=[{"result": {
        "interrupted": False, "stopped": True, "state": "stopped",
        "reason": {"kind": "breakpoint-hit", "number": 1},
    }}])

    rc, payload = _json(capsys, ["snapshot", "save", "clean"])

    assert rc == 0
    assert pry.ran("continue") == []
    assert pry.stopped()
    assert payload["debugger"]["resumed"] is False
    assert payload["breakpoints_in_image"] == "lifted"
    assert any(f"pry --instance qmu-{VM} continue --background" in w for w in payload["warnings"])


def test_a_save_that_outran_its_budget_leaves_the_bridge_stopped_and_says_so(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    """QEMU may still be writing the image: resuming would put the
    breakpoints back into RAM being saved."""
    _vm(tmp_path, monkeypatch, bridge)

    def expired(qmp, name, timeout=None):
        raise qmp_cmds.QMPTimeoutError("human-monitor-command", timeout)

    monkeypatch.setattr(qmp_cmds, "save_snapshot", expired)

    rc, payload = _json(capsys, ["snapshot", "save", "clean"])

    assert rc == 124 and payload["may_have_landed"] is True
    assert pry.ran("continue") == []
    assert pry.stopped()
    assert any(f"pry --instance qmu-{VM} continue --background" in w for w in payload["warnings"])


@pytest.mark.parametrize("route", ["snapshot save", "monitor savevm"])
def test_a_save_that_dies_mid_flight_resumes_and_says_when_it_could_not(
    route, tmp_path, monkeypatch, capsys, bridge, pry
):
    """A transport failure that is not the save's timeout resumes the
    bridge; when that resume fails, the error envelope says the guest is
    halted in the debugger, on the dedicated route as on the raw one."""
    _vm(tmp_path, monkeypatch, bridge)
    pry.answers(continue_=[{"rc": 1, "error": "bridge not responding"}])

    def broken(*args, **kwargs):
        raise qmp_cmds.QMPError("connection reset by peer")

    monkeypatch.setattr(qmp_cmds, "save_snapshot", broken)
    monkeypatch.setattr(_QMP, "execute_hmp", broken)

    rc, payload = _json(capsys, _SAVE_ROUTES[route])

    assert rc == 4 and payload["ok"] is False
    assert pry.ran("continue"), "the bridge qmu stopped is resumed"
    assert any(
        "bridge not responding" in w and "halted in the debugger" in w
        for w in payload["warnings"]
    )


def test_a_failed_save_still_resumes_the_bridge(tmp_path, monkeypatch, capsys, bridge, pry):
    _vm(tmp_path, monkeypatch, bridge)
    monkeypatch.setattr(
        qmp_cmds, "save_snapshot",
        lambda qmp, name, timeout=None: SnapshotResult(
            False, "Error: no block device can store vmstate", reason="drive"
        ),
    )

    rc, payload = _json(capsys, ["snapshot", "save", "clean"])

    assert rc == 1
    assert not pry.stopped()
    assert payload["debugger"]["resumed"] is True


def test_a_bridge_that_cannot_be_stopped_saves_running_and_warns(
    tmp_path, monkeypatch, capsys, bridge, pry
):
    _vm(tmp_path, monkeypatch, bridge)
    pry.answers(interrupt=[{"rc": 1, "error": "bridge not responding"}])

    rc, payload = _json(capsys, ["snapshot", "save", "clean"])

    assert rc == 0
    assert _QMP.saves == ["running"]
    assert payload["breakpoints_in_image"] == "possible"
    assert "breakpoints_lifted" not in payload
    assert any("bridge not responding" in w for w in payload["warnings"])


@pytest.mark.parametrize(
    ("kvm", "owned"), [(False, True), (True, False)], ids=["tcg", "foreign-client"],
)
def test_a_save_drives_no_bridge_under_tcg_or_for_another_client(
    kvm, owned, tmp_path, monkeypatch, capsys, bridge, pry
):
    """TCG breakpoints never reach guest RAM; another client is never driven."""
    _vm(tmp_path, monkeypatch, bridge if owned else None, kvm=kvm)

    rc, payload = _json(capsys, ["snapshot", "save", "clean"])

    assert rc == 0
    assert pry.ran("interrupt") == []
    assert "debugger" not in payload and "breakpoints_lifted" not in payload


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
        debug.reset_dropped_breakpoints_warning(
            load_instance(VM), qemu_status="running"
        ).removeprefix("[qmu] WARNING: ")
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
