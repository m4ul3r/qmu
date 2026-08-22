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
    assert data.get("vm", "live") == "live"


@pytest.mark.parametrize("cmd", ["log", "crash"])
def test_auto_selection_is_disclosed_not_silent(cmd, cache, capsys):
    """A silent pick is how an agent reads the wrong VM's log after a kill."""
    _mk("live", alive=True)
    _mk("dead", alive=False)

    cli.main(["--format", "json", cmd])
    data = json.loads(capsys.readouterr().out)
    assert data["vm"] == "live"
    assert "autoselected" in data
    assert "live" in data["autoselected"]

    cli.main([cmd])
    assert "Auto-selected" in capsys.readouterr().out


@pytest.mark.parametrize("cmd", ["log", "crash"])
def test_explicit_vm_wins_and_is_not_annotated(cmd, cache, capsys):
    """A stopped VM stays readable by name -- f792840 must not regress."""
    _mk("live", alive=True)
    _mk("dead", alive=False)

    rc = cli.main(["--format", "json", cmd, "--vm", "dead"])
    data = json.loads(capsys.readouterr().out)
    assert data["vm"] == "dead"
    assert "autoselected" not in data
    if cmd == "log":
        assert "serial-of-dead" in data["log"]


def test_single_candidate_is_not_annotated(cache, capsys):
    _mk("solo", alive=False)
    cli.main(["--format", "json", "log"])
    data = json.loads(capsys.readouterr().out)
    assert data["vm"] == "solo"
    assert "autoselected" not in data


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
    assert "qmu prune --all" in text
    assert len(text.strip().splitlines()) <= 10


def test_two_running_vms_are_still_ambiguous(cache, capsys):
    """The tie-break is 'exactly one running', not 'prefer any running'."""
    _mk("a", alive=True)
    _mk("b", alive=True)
    rc = cli.main(["log"])
    text = capsys.readouterr().out + capsys.readouterr().err
    assert rc == 1
