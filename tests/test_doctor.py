from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.config import QMUConfig
from qmu.qemu import QEMUNetdevCapabilities, native_passt_problem


@pytest.fixture
def doctor_env(tmp_path, monkeypatch):
    rootfs = tmp_path / "rootfs.img"
    rootfs.write_bytes(b"")
    ssh_key = tmp_path / "id_ed25519"
    ssh_key.write_text("fixture key")
    ssh_key.chmod(0o600)

    config = QMUConfig(
        arch="aarch64",
        net_backend="passt",
        rootfs=str(rootfs),
        ssh_key=str(ssh_key),
        _sources=["config: fixture"],
    )
    monkeypatch.setattr(lifecycle, "resolve_config", lambda **kwargs: config)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [])

    skill_source = tmp_path / "skill-source" / "qmu"
    skill_source.mkdir(parents=True)
    claude_skills = tmp_path / "claude-skills"
    (claude_skills / "qmu").mkdir(parents=True)
    monkeypatch.setattr(lifecycle, "all_skill_source_dirs", lambda: [skill_source])
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: [claude_skills])

    executables = {
        "qemu-system-aarch64": "/usr/bin/qemu-system-aarch64",
        "passt": "/usr/bin/passt",
        "pry": "/usr/bin/pry",
    }
    monkeypatch.setattr(lifecycle.shutil, "which", executables.get)
    return SimpleNamespace(config=config, executables=executables)


def _check(payload, name):
    return next(item for item in payload["checks"] if item["check"] == name)


def _caps(
    *,
    path="/opt/qemu/qemu-system-aarch64",
    backends=frozenset({"user", "passt"}),
    error=None,
):
    return QEMUNetdevCapabilities(
        binary="qemu-system-aarch64",
        path=path,
        backends=backends,
        error=error,
    )


def _run_json_doctor(capsys):
    rc = cli.main(["--format", "json", "doctor"])
    return rc, json.loads(capsys.readouterr().out)


def test_doctor_supported_configured_passt_is_healthy_and_uses_selected_arch(
    doctor_env, monkeypatch, capsys
):
    caps = _caps()
    probe = Mock(return_value=caps)
    monkeypatch.setattr(lifecycle, "probe_qemu_netdevs", probe, raising=False)

    rc, payload = _run_json_doctor(capsys)

    qemu_check = _check(payload, "qemu-system-aarch64")
    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    assert rc == 0
    assert payload["ok"] is True
    assert qemu_check == {
        "check": "qemu-system-aarch64",
        "status": "ok",
        "detail": "/opt/qemu/qemu-system-aarch64",
    }
    assert native_check["status"] == "ok"
    assert native_check["detail"] == (
        "/opt/qemu/qemu-system-aarch64 advertises native '-netdev passt'"
    )
    assert "qemu-system-aarch64" in native_check["detail"]
    assert _check(payload, "passt (net_backend=passt)")["status"] == "ok"
    probe.assert_called_once_with("qemu-system-aarch64")


def test_doctor_unsupported_native_passt_is_unhealthy_even_when_passt_exists(
    doctor_env, monkeypatch, capsys
):
    caps = _caps(backends=frozenset({"user", "stream"}))
    probe = Mock(return_value=caps)
    monkeypatch.setattr(lifecycle, "probe_qemu_netdevs", probe, raising=False)

    rc, payload = _run_json_doctor(capsys)

    native = _check(payload, "QEMU native passt (-netdev passt)")
    assert rc == 1
    assert payload["ok"] is False
    assert native["status"] == "MISSING"
    assert native["detail"] == native_passt_problem(caps)
    assert "does not advertise" in native["detail"]
    assert "QEMU 10.1" in native["detail"]
    assert "build-optional" in native["detail"]
    assert _check(payload, "passt (net_backend=passt)")["status"] == "ok"


def test_doctor_supported_native_passt_is_unhealthy_when_external_passt_missing(
    doctor_env, monkeypatch, capsys
):
    doctor_env.executables["passt"] = None
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    external_check = _check(payload, "passt (net_backend=passt)")
    assert native_check["status"] == "ok"
    assert external_check["status"] == "MISSING"
    assert rc == 1
    assert payload["ok"] is False


def test_doctor_reports_both_failures_when_capability_and_executable_are_missing(
    doctor_env, monkeypatch, capsys
):
    doctor_env.executables["passt"] = None
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps(backends=frozenset({"user", "stream"}))),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    external_check = _check(payload, "passt (net_backend=passt)")
    assert native_check["status"] == "MISSING"
    assert external_check["status"] == "MISSING"
    assert rc == 1


def test_doctor_missing_selected_qemu_cannot_claim_unsupported_capability(
    doctor_env, monkeypatch, capsys
):
    doctor_env.executables["qemu-system-aarch64"] = None
    caps = _caps(
        path=None,
        backends=frozenset(),
        error="Selected QEMU binary 'qemu-system-aarch64' was not found in PATH",
    )
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=caps),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    qemu_check = _check(payload, "qemu-system-aarch64")
    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    assert rc == 1
    assert qemu_check["status"] == "MISSING"
    assert native_check["status"] == "MISSING"
    assert native_check["detail"] == native_passt_problem(caps)
    assert "Cannot verify" in native_check["detail"]
    assert "not found in PATH" in native_check["detail"]
    assert "does not advertise" not in native_check["detail"]


def test_doctor_probe_failure_is_unhealthy_not_a_traceback(
    doctor_env, monkeypatch, capsys
):
    caps = _caps(
        backends=frozenset(),
        error="Capability probe 'qemu-system-aarch64 -netdev help' timed out after 5.0 seconds",
    )
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=caps),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    qemu_check = _check(payload, "qemu-system-aarch64")
    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    assert qemu_check["status"] == "ok"
    assert native_check["status"] == "MISSING"
    assert native_check["detail"] == native_passt_problem(caps)
    assert "timed out" in native_check["detail"]
    assert rc == 1


def test_doctor_user_backend_skips_native_passt_probe_and_external_requirement(
    doctor_env, monkeypatch, capsys
):
    doctor_env.config.net_backend = "user"
    doctor_env.executables["passt"] = None
    probe = Mock(side_effect=AssertionError("native passt probe must be skipped"))
    monkeypatch.setattr(lifecycle, "probe_qemu_netdevs", probe, raising=False)

    rc, payload = _run_json_doctor(capsys)

    native_check = _check(payload, "QEMU native passt (-netdev passt)")
    external_check = _check(payload, "passt (net_backend=passt)")
    assert rc == 0
    assert payload["ok"] is True
    assert native_check == {
        "check": "QEMU native passt (-netdev passt)",
        "status": "info",
        "detail": "Not required for configured net_backend=user.",
    }
    assert external_check == {
        "check": "passt (net_backend=passt)",
        "status": "info",
        "detail": "Not found — not required for configured net_backend=user.",
    }
    probe.assert_not_called()


def test_doctor_text_matches_structured_unsupported_passt_message(
    doctor_env, monkeypatch, capsys
):
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps(backends=frozenset({"user", "stream"}))),
        raising=False,
    )

    rc = cli.main(["doctor"])
    text = capsys.readouterr().out

    assert rc == 1
    assert text.startswith("qmu doctor:")
    assert "[!] QEMU native passt (-netdev passt):" in text
    assert "qemu-system-aarch64" in text
    assert "does not advertise" in text
    assert "QEMU 10.1" in text
    assert "makes snapshots work" not in text


def test_doctor_rejects_launch_only_net_backend_override(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["doctor", "--net-backend", "user"])

    assert excinfo.value.code == 2
    error = capsys.readouterr().err
    assert "unrecognized arguments" in error
    assert "--net-backend" in error


# ---------------------------------------------------------------------------
# An invalid global config is not an absent one (F7). Measured before this:
# `qmu doctor` printed "[~] config: No qmu.toml or ~/.config/qmu/config.toml
# found. Run: qmu config init" while its own stderr said
# "ignoring global config: Invalid config <path>: failed to parse TOML" — the
# body contradicted the warning, and the prescribed action writes a PROJECT
# file, so the broken global stays there re-warning forever. doctor is exempt
# from the #37 dispatch gate on the grounds that it diagnoses the fault itself;
# that only holds if it diagnoses the non-fatal layer too.
# ---------------------------------------------------------------------------


def test_doctor_names_a_rejected_global_config_instead_of_claiming_none(
    doctor_env, monkeypatch, capsys
):
    broken = "/home/agent/.config/qmu/config.toml"
    doctor_env.config._sources = ["built-in defaults"]
    doctor_env.config._skipped_sources = [
        {"kind": "global", "path": broken, "problem": "failed to parse TOML"}
    ]
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc = cli.main(["--format", "json", "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    row = _check(payload, "global config")
    assert row["status"] == "warn"
    assert broken in row["detail"]
    assert "failed to parse TOML" in row["detail"]
    assert "Fix or delete that file" in row["detail"]
    assert "will not clear this" in row["detail"]
    # The false claim is gone, and the config row no longer sends the reader
    # to `qmu config init` as the remedy for this fault.
    config_row = _check(payload, "config")
    assert "No qmu.toml" not in config_row["detail"]
    assert config_row["status"] == "warn"
    assert "built-in defaults only" in config_row["detail"]


def test_doctor_still_reports_a_genuinely_absent_config(
    doctor_env, monkeypatch, capsys
):
    """The not-found branch must survive: nothing was rejected here, so
    `qmu config init` really is the right advice."""
    doctor_env.config._sources = ["built-in defaults"]
    doctor_env.config._skipped_sources = []
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc = cli.main(["--format", "json", "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    config_row = _check(payload, "config")
    assert config_row["detail"] == (
        "No qmu.toml or ~/.config/qmu/config.toml found. Run: qmu config init"
    )
    assert not [c for c in payload["checks"] if c["check"] == "global config"]


def test_doctor_reports_a_rejected_global_alongside_a_loaded_project(
    doctor_env, monkeypatch, capsys
):
    """A valid project layer must not hide the broken global: the file is still
    there, still re-warning on every command."""
    broken = "/home/agent/.config/qmu/config.toml"
    doctor_env.config._sources = ["built-in defaults", "project: /work/qmu.toml"]
    doctor_env.config._skipped_sources = [
        {"kind": "global", "path": broken, "problem": "key 'rootfs': belongs in [drive]"}
    ]
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc = cli.main(["--format", "json", "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert _check(payload, "config") == {
        "check": "config",
        "status": "ok",
        "detail": "built-in defaults -> project: /work/qmu.toml",
    }
    assert broken in _check(payload, "global config")["detail"]


def test_doctor_text_shows_the_rejected_global_as_a_warn_row(
    doctor_env, monkeypatch, capsys
):
    broken = "/home/agent/.config/qmu/config.toml"
    doctor_env.config._sources = ["built-in defaults"]
    doctor_env.config._skipped_sources = [
        {"kind": "global", "path": broken, "problem": "failed to parse TOML"}
    ]
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc = cli.main(["doctor"])
    text = capsys.readouterr().out

    assert rc == 1
    assert f"[~] global config: {broken} EXISTS but is invalid" in text
    assert "No qmu.toml or ~/.config/qmu/config.toml found" not in text
