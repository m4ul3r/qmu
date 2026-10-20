"""Auto-selection agreement across log / crash / status.

SKILL.md promised "with one VM running, commands auto-select it". That was true
for every command using choose_instance (running-only) and FALSE for the only
two using find_instance -- `log` and `crash` -- which count stopped VMs as
candidates so a dead VM's log stays readable. One stopped remnant was enough to
break the two commands an agent reaches for during crash triage, with a 60-line
error that never named the remedy.
"""

from __future__ import annotations

import json
import os

import pytest

from qmu import cli
from qmu.instance import (
    VMInstance,
    proc_pid_start,
    save_instance,
    _AMBIGUITY_LIST_LIMIT,
)
from qmu.paths import instances_dir


def _mk(vm_id: str, *, alive: bool):
    d = instances_dir()
    d.mkdir(parents=True, exist_ok=True)
    pid = os.getpid() if alive else 999_999
    inst = VMInstance(
        vm_id=vm_id, pid=pid, qmp_socket=str(d / f"{vm_id}.qmp.sock"),
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log=str(d / f"{vm_id}.serial.log"), kernel="bzImage",
        rootfs="r.img", memory="1G", cpus=1, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="now",
        pid_start=proc_pid_start(pid) if alive else "0",
    )
    save_instance(inst)
    (d / f"{vm_id}.serial.log").write_text(
        f"serial-of-{vm_id}\nBUG: kernel NULL pointer dereference\n"
    )
    (d / f"{vm_id}.qemu.log").write_text("")
    return inst


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    return tmp_path


@pytest.mark.parametrize("cmd", ["log", "crash", "status"])
def test_one_running_many_stopped_auto_selects(cmd, cache, capsys):
    """The regression: log/crash used to fail here while status succeeded."""
    _mk("live", alive=True)
    for n in range(8):
        _mk(f"dead{n}", alive=False)

    rc = cli.main(["--format", "json", cmd])
    data = json.loads(capsys.readouterr().out)

    assert rc in (0, 1), f"{cmd} failed to auto-select"
    assert "Multiple VMs found" not in json.dumps(data)
    assert data.get("vm_id", "live") == "live"


NOTE = "[qmu] Auto-selected the only running VM 'live' (pass --vm to pin it)."


@pytest.mark.parametrize("cmd", ["log", "crash", "status", "wait", "exec"])
def test_auto_selection_is_disclosed_not_silent(cmd, cache, capsys):
    """A silent pick is how an agent reads the wrong VM's log after a kill.

    Every command that picks the single running VM says so on stderr — the
    disclosure lives in the lookup, not in each handler, so a new command
    cannot forget it — and the JSON envelope carries `autoselected: true`.
    """
    _mk("live", alive=True)
    _mk("dead", alive=False)

    extra = {"wait": ["--timeout", "0"], "exec": ["true"]}.get(cmd, [])
    cli.main(["--format", "json", cmd, *extra])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data.get("vm_id", "live") == "live"
    assert data["autoselected"] is True
    assert NOTE in captured.err

    cli.main([cmd, *extra])
    captured = capsys.readouterr()
    assert NOTE in captured.err
    assert "Auto-selected" not in captured.out, "the note must not pollute stdout"


@pytest.mark.parametrize("cmd", ["log", "crash"])
def test_explicit_vm_wins_and_is_not_annotated(cmd, cache, capsys):
    """A stopped VM stays readable by name -- f792840 must not regress."""
    _mk("live", alive=True)
    _mk("dead", alive=False)

    rc = cli.main(["--format", "json", cmd, "--vm", "dead"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vm_id"] == "dead"
    assert "autoselected" not in data
    assert "Auto-selected" not in captured.err
    if cmd == "log":
        assert "serial-of-dead" in data["log"]


def test_single_candidate_is_still_disclosed(cache, capsys):
    """One VM on disk is still a pick the caller did not make: on a shared
    host that one VM may be someone else's."""
    _mk("solo", alive=False)
    cli.main(["--format", "json", "log"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vm_id"] == "solo"
    assert data["autoselected"] is True
    assert "Auto-selected the only VM (stopped) 'solo'" in captured.err


@pytest.mark.parametrize("cmd", ["log", "status", "kill", "exec"])
def test_require_vm_env_refuses_auto_selection(cmd, cache, monkeypatch, capsys):
    """`QMU_REQUIRE_VM=1`: a forgotten --vm is a refusal, never an action on
    whatever VM happens to be alive."""
    _mk("live", alive=True)
    monkeypatch.setenv("QMU_REQUIRE_VM", "1")

    extra = ["true"] if cmd == "exec" else []
    rc = cli.main(["--format", "json", cmd, *extra])
    data = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert data["ok"] is False
    assert data["error"] == "--vm is required: QMU_REQUIRE_VM is set"
    assert "autoselected" not in data

    if cmd != "kill":  # an explicit --vm is never refused
        cli.main(["--format", "json", cmd, "--vm", "live", *extra])
        assert "QMU_REQUIRE_VM" not in capsys.readouterr().out


def test_require_vm_env_zero_is_unset(cache, monkeypatch, capsys):
    _mk("live", alive=True)
    monkeypatch.setenv("QMU_REQUIRE_VM", "0")
    cli.main(["--format", "json", "status"])
    assert json.loads(capsys.readouterr().out)["autoselected"] is True


def test_genuine_ambiguity_is_bounded_and_names_the_remedy(cache, capsys):
    """No running VM + many stopped: still ambiguous, but the error must be
    short and actionable. It used to list all of them and mention neither
    `qmu list` nor `qmu prune`."""
    for n in range(40):
        _mk(f"dead{n}", alive=False)

    rc = cli.main(["log"])
    captured = capsys.readouterr()
    text = captured.out + captured.err

    assert rc == 1
    assert "Multiple VMs found" in text
    listed = [ln for ln in text.splitlines() if ln.strip().startswith("dead")]
    assert len(listed) == _AMBIGUITY_LIST_LIMIT
    assert "and 35 more" in text
    assert "qmu list" in text
    # On a shared host the stopped VMs listed are other people's too; the
    # remedy names one VM, never the cache-wide sweep (r2-shared P1).
    assert "qmu prune --vm dead" in text
    assert "prune --all" not in text
    assert len(text.strip().splitlines()) <= 10


def test_two_running_vms_are_still_ambiguous(cache, capsys):
    """The tie-break is 'exactly one running', not 'prefer any running'."""
    _mk("a", alive=True)
    _mk("b", alive=True)
    rc = cli.main(["log"])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert rc == 1


@pytest.mark.parametrize("cmd", ["status", "kill", "exec"])
def test_near_miss_names_stopped_vms_too(cmd, cache, capsys):
    """A one-character typo on a STOPPED vm_id used to answer
    "not found. Running: live", hiding the very VM `qmu list` displays and the
    caller was aiming at. The running-only inventory is narrower than `list`,
    so the recovery hint has to carry both -- same shape find_instance already
    emitted, which is how the two lookups stopped disagreeing.
    """
    _mk("live", alive=True)
    _mk("c3-probe", alive=False)

    argv = [cmd, "--vm", "c3-prube"] + (["true"] if cmd == "exec" else [])
    rc = cli.main(argv)
    err = capsys.readouterr().err

    assert rc == 1
    assert "not found" in err
    assert "Running: live" in err
    assert "c3-probe" in err, f"`qmu {cmd}` hid the stopped VM `qmu list` shows"
    assert "Stopped:" in err
