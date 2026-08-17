"""Round-5 regressions: the flip side of round-4's fixes, plus recovery gaps.

Finding A is the instructive one — fixing "--profile silently not applied"
created "--profile applied, your cmdline silently gone", with `nokaslr` as the
usual casualty. A fix that trades one silent failure for another is not a fix.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.instance import VMInstance


def _instance(**over) -> VMInstance:
    base = dict(
        vm_id="r5-vm", pid=4242, qmp_socket="/tmp/r5.qmp.sock",
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log="/tmp/r5.serial.log", kernel="/boot/bzImage",
        rootfs=None, memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-08-17T00:00:00Z", harness=True,
    )
    base.update(over)
    return VMInstance(**base)


# ---------------------------------------------------------------------------
# A. --profile must name what it discards
# ---------------------------------------------------------------------------


CONFIG_WITH_CMDLINE = (
    '[boot]\nkernel = "./bzImage"\n'
    'cmdline = "console=ttyS0 nokaslr root=/dev/sda rw slub_debug=- init=/init.sh"\n'
)


@pytest.fixture
def launched(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(
        lifecycle, "launch_vm", lambda **kw: calls.append(kw) or _instance()
    )
    return calls


def _cfg(tmp_path, body=CONFIG_WITH_CMDLINE):
    path = tmp_path / "qmu.toml"
    path.write_text(body)
    return str(path)


def test_override_lists_the_dropped_params(launched, tmp_path, capsys):
    cli.main(["launch", "--config", _cfg(tmp_path), "--harness",
              "--profile", "exploit-test"])

    err = capsys.readouterr().err
    assert "dropped:" in err
    for token in ("nokaslr", "slub_debug=-", "init=/init.sh"):
        assert token in err


def test_nokaslr_loss_is_called_out_by_consequence(launched, tmp_path, capsys):
    """The casualty that silently invalidates every hardcoded address."""
    cli.main(["launch", "--config", _cfg(tmp_path), "--harness",
              "--profile", "exploit-test"])

    err = capsys.readouterr().err
    assert "'nokaslr' is gone" in err
    assert "every kernel address changes" in err


def test_init_loss_is_called_out(launched, tmp_path, capsys):
    cli.main(["launch", "--config", _cfg(tmp_path), "--harness",
              "--profile", "exploit-test"])

    assert "runs its default init" in capsys.readouterr().err


def test_params_the_profile_also_supplies_are_not_listed_as_dropped(
    launched, tmp_path, capsys
):
    """`root=` survives via the profile, so reporting it as lost is noise."""
    cli.main(["launch", "--config", _cfg(tmp_path), "--harness",
              "--profile", "exploit-test"])

    dropped_line = [
        line for line in capsys.readouterr().err.splitlines()
        if "dropped:" in line
    ][0]
    assert "root=" not in dropped_line
    assert "console=ttyS0" not in dropped_line


def test_readding_via_append_suppresses_the_drop_notice(
    launched, tmp_path, capsys
):
    cli.main(["launch", "--config", _cfg(tmp_path), "--harness",
              "--profile", "exploit-test", "--append", "nokaslr"])

    err = capsys.readouterr().err
    assert "'nokaslr' is gone" not in err


def test_no_drop_notice_when_nothing_is_lost(launched, tmp_path, capsys):
    body = '[boot]\nkernel = "./b"\ncmdline = "console=ttyS0 root=/dev/sda"\n'
    cli.main(["launch", "--config", _cfg(tmp_path, body), "--harness",
              "--profile", "exploit-test"])

    assert "dropped:" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# B. A visible-but-age-gated VM must not be reported as nonexistent
# ---------------------------------------------------------------------------


def _log_only_remnant(tmp_path, monkeypatch, vm_id="orph4"):
    idir = tmp_path / "instances"
    idir.mkdir(parents=True, exist_ok=True)
    (idir / f"{vm_id}.serial.log").write_text("boot\n")
    (idir / f"{vm_id}.qemu.log").write_text("qemu\n")
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    return idir


def test_age_gated_remnant_is_not_reported_as_missing(tmp_path, monkeypatch, capsys):
    """`No stopped VM named X` sent the reader to rm in the cache directory."""
    _log_only_remnant(tmp_path, monkeypatch)

    rc = cli.main(["prune", "--vm", "orph4"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "No stopped VM named" not in err
    assert "--older-than 0" in err


def test_the_suggested_command_actually_removes_it(tmp_path, monkeypatch):
    _log_only_remnant(tmp_path, monkeypatch)

    assert cli.main(["prune", "--vm", "orph4", "--older-than", "0"]) == 0
    assert cli.main(["--format", "json", "prune", "--vm", "orph4"]) == 1


def test_genuinely_absent_vm_still_says_so(tmp_path, monkeypatch, capsys):
    _log_only_remnant(tmp_path, monkeypatch)

    rc = cli.main(["prune", "--vm", "never-existed"])

    assert rc == 1
    assert "No stopped VM named" in capsys.readouterr().err


def test_log_only_entry_with_a_live_qemu_is_not_shown_as_stopped(
    tmp_path, monkeypatch, capsys
):
    """The one display that would say 'nothing running' while an orphan holds
    your image."""
    _log_only_remnant(tmp_path, monkeypatch)
    serial = str(tmp_path / "instances" / "orph4.serial.log")
    monkeypatch.setattr(
        lifecycle, "find_orphan_qemus",
        lambda: [{"pid": 999, "serial_log": serial, "cmdline": "qemu"}],
    )

    rc = cli.main(["list"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "ORPHANED" in out
    assert "[stopped]" not in out


def test_orphaned_status_is_machine_readable(tmp_path, monkeypatch, capsys):
    _log_only_remnant(tmp_path, monkeypatch)
    serial = str(tmp_path / "instances" / "orph4.serial.log")
    monkeypatch.setattr(
        lifecycle, "find_orphan_qemus",
        lambda: [{"pid": 999, "serial_log": serial, "cmdline": "qemu"}],
    )

    cli.main(["--format", "json", "list"])
    payload = json.loads(capsys.readouterr().out)

    entry = payload["vms"][0]
    assert entry["status"] == "orphaned"
    assert entry["pid"] == 999


def test_log_only_entry_with_no_live_process_stays_stopped(
    tmp_path, monkeypatch, capsys
):
    _log_only_remnant(tmp_path, monkeypatch)
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    cli.main(["list"])

    assert "[stopped]" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# C. prune --orphans --dry-run
# ---------------------------------------------------------------------------


@pytest.fixture
def two_orphans(monkeypatch):
    orphans = [
        {"pid": 111, "serial_log": "/c/a.serial.log", "cmdline": "qemu a"},
        {"pid": 222, "serial_log": "/c/b.serial.log", "cmdline": "qemu b"},
    ]
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: orphans)
    return orphans


def test_dry_run_kills_nothing(two_orphans, monkeypatch, capsys):
    """This SIGKILLs by argv pattern; on a shared box you must be able to look
    first."""
    monkeypatch.setattr(
        lifecycle.os, "kill",
        lambda *a: pytest.fail("--dry-run must not signal anything"),
    )

    rc = cli.main(["prune", "--orphans", "--dry-run"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Would kill 2" in out
    assert "pid 111" in out and "pid 222" in out


def test_dry_run_reports_the_serial_log_for_identification(two_orphans, capsys):
    cli.main(["prune", "--orphans", "--dry-run"])

    assert "/c/a.serial.log" in capsys.readouterr().out


def test_dry_run_json_lists_candidates_without_killing(two_orphans, capsys):
    cli.main(["--format", "json", "prune", "--orphans", "--dry-run"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["dry_run"] is True
    assert payload["killed"] == []
    assert [c["pid"] for c in payload["would_kill"]] == [111, 222]


def test_dry_run_on_a_clean_box_says_nothing_would_be_killed(monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])

    rc = cli.main(["prune", "--orphans", "--dry-run"])

    assert rc == 0
    assert "Nothing would be killed" in capsys.readouterr().out


def test_without_dry_run_it_still_kills(two_orphans, monkeypatch, capsys):
    signalled: list[int] = []
    monkeypatch.setattr(lifecycle.os, "kill", lambda pid, sig: signalled.append(pid))
    monkeypatch.setattr(lifecycle, "is_pid_alive", lambda pid: False)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)

    rc = cli.main(["prune", "--orphans"])

    assert rc == 0
    assert signalled == [111, 222]


# ---------------------------------------------------------------------------
# Found while testing C: prune ignored a top-level --format
# ---------------------------------------------------------------------------


def test_top_level_format_reaches_prune(two_orphans, capsys):
    """`--format` is documented as valid before OR after the subcommand.

    prune declared its own --format with a plain "text" default, which
    overwrote the top-level value instead of deferring to it.
    """
    cli.main(["--format", "json", "prune", "--orphans", "--dry-run"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["dry_run"] is True


def test_format_after_the_subcommand_still_works(two_orphans, capsys):
    cli.main(["prune", "--orphans", "--dry-run", "--format", "json"])

    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_prune_still_defaults_to_text(two_orphans, capsys):
    cli.main(["prune", "--orphans", "--dry-run"])

    assert "Would kill 2" in capsys.readouterr().out
