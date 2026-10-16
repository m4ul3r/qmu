from __future__ import annotations

import json
from pathlib import Path
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
        "blocking": False,
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
    assert native["status"] == "fail"
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
    assert external_check["status"] == "fail"
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
    assert native_check["status"] == "fail"
    assert external_check["status"] == "fail"
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
    assert qemu_check["status"] == "fail"
    assert native_check["status"] == "fail"
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
    assert native_check["status"] == "fail"
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
        "blocking": False,
    }
    assert external_check == {
        "check": "passt (net_backend=passt)",
        "status": "info",
        "detail": "Not found — not required for configured net_backend=user.",
        "blocking": False,
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
    # A file that exists and is rejected is a defect in the user's setup that
    # every command re-warns about: gating, not a hint.
    assert row["status"] == "fail"
    assert row["blocking"] is True
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
    `qmu config init` really is the right advice. It names the REAL global
    path (QMU_CONFIG_DIR is honored by `config path`; doctor said
    `~/.config/qmu/config.toml` regardless), and it is a warning: launching
    with flags works without any config file."""
    doctor_env.config._sources = ["built-in defaults"]
    doctor_env.config._skipped_sources = []
    monkeypatch.setenv("QMU_CONFIG_DIR", "/custom/cfg")
    monkeypatch.setattr(
        lifecycle,
        "probe_qemu_netdevs",
        Mock(return_value=_caps()),
        raising=False,
    )

    rc = cli.main(["--format", "json", "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    config_row = _check(payload, "config")
    assert config_row["status"] == "warn"
    assert config_row["blocking"] is False
    assert config_row["detail"] == (
        "No qmu.toml or /custom/cfg/config.toml found. Run: qmu config init"
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
        "blocking": False,
    }
    assert broken in _check(payload, "global config")["detail"]


def test_doctor_text_shows_the_rejected_global_as_a_fail_row(
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
    assert f"[!] global config: {broken} EXISTS but is invalid" in text
    assert "No qmu.toml or" not in text


# ---------------------------------------------------------------------------
# The kernel row. doctor went green on a starter qmu.toml whose `kernel =`
# line was still commented out, and the very next `launch` failed on it.
# ---------------------------------------------------------------------------


def _passt_ok(monkeypatch):
    monkeypatch.setattr(
        lifecycle, "probe_qemu_netdevs", Mock(return_value=_caps()), raising=False
    )


def test_doctor_warns_but_does_not_block_on_an_unconfigured_kernel(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)

    rc, payload = _run_json_doctor(capsys)

    row = _check(payload, "kernel")
    assert rc == 0 and payload["ok"] is True
    assert row["status"] == "warn"
    assert row["blocking"] is False
    assert "not configured" in row["detail"]
    assert "--harness" in row["detail"]

    assert cli.main(["doctor"]) == 0
    assert "[~] kernel: not configured" in capsys.readouterr().out


def test_doctor_blocks_on_a_configured_kernel_that_is_missing(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    doctor_env.config.kernel = str(tmp_path / "nope" / "bzImage")

    rc, payload = _run_json_doctor(capsys)

    row = _check(payload, "kernel")
    assert rc == 1 and payload["ok"] is False
    assert row["status"] == "fail"
    assert row["blocking"] is True
    assert str(tmp_path / "nope" / "bzImage") in row["detail"]

    assert cli.main(["doctor"]) == 1
    assert "[!] kernel:" in capsys.readouterr().out


def test_doctor_passes_a_configured_kernel_that_exists(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    kernel = tmp_path / "bzImage"
    kernel.write_bytes(b"\x00")
    doctor_env.config.kernel = str(kernel)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 0
    assert _check(payload, "kernel") == {
        "check": "kernel", "status": "ok", "detail": str(kernel),
        "blocking": False,
    }
    cli.main(["doctor"])
    assert f"[+] kernel: {kernel}" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# libguestfs is optional tooling: its failure is a warning, never the reason
# a host where launch/exec/crash all work is reported unhealthy.
# ---------------------------------------------------------------------------


def test_doctor_stays_healthy_when_only_libguestfs_cannot_build(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    doctor_env.executables["guestfish"] = "/usr/bin/guestfish"
    monkeypatch.setenv("SUPERMIN_KERNEL", str(tmp_path / "unreadable-vmlinuz"))

    rc, payload = _run_json_doctor(capsys)

    row = _check(payload, "libguestfs (rootfs inject / launch --inject)")
    assert rc == 0 and payload["ok"] is True
    assert row["status"] == "warn"
    assert row["blocking"] is False
    assert "NOT readable" in row["detail"]

    cli.main(["doctor"])
    assert "[~] libguestfs" in capsys.readouterr().out


def test_every_doctor_check_carries_a_boolean_blocking_verdict(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    doctor_env.executables["qemu-system-aarch64"] = None
    monkeypatch.setattr(
        lifecycle, "probe_qemu_netdevs",
        Mock(return_value=_caps(path=None, backends=frozenset())),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    assert all(isinstance(c["blocking"], bool) for c in payload["checks"])
    # `ok` is exactly "nothing blocks" — not a re-reading of status strings.
    assert payload["ok"] is (not any(c["blocking"] for c in payload["checks"]))
    assert _check(payload, "qemu-system-aarch64")["blocking"] is True


# ---------------------------------------------------------------------------
# One glyph per meaning. `[!]` used to cover both MISSING and "not configured",
# `[+]` covered ok and info, and JSON statuses mixed case (`MISSING`, `not
# configured`, `warn`). Now status ∈ {ok, fail, warn, info}, blocking is
# exactly `status == "fail"`, and the text glyph is a function of status.
# ---------------------------------------------------------------------------


def test_every_doctor_row_uses_the_four_status_vocabulary(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    doctor_env.executables["qemu-system-aarch64"] = None
    monkeypatch.setattr(
        lifecycle, "probe_qemu_netdevs",
        Mock(return_value=_caps(path=None, backends=frozenset())),
        raising=False,
    )

    rc, payload = _run_json_doctor(capsys)

    statuses = {c["status"] for c in payload["checks"]}
    assert statuses <= {"ok", "fail", "warn", "info"}
    assert all(c["blocking"] is (c["status"] == "fail") for c in payload["checks"])
    assert rc == 1

    cli.main(["doctor"])
    text = capsys.readouterr().out
    glyph = {"ok": "+", "fail": "!", "warn": "~", "info": "i"}
    for c in payload["checks"]:
        assert f"[{glyph[c['status']]}] {c['check']}:" in text, c["check"]


def test_doctor_informational_rows_render_as_i_not_plus(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    doctor_env.executables["pry"] = None

    rc, payload = _run_json_doctor(capsys)
    assert rc == 0
    assert _check(payload, "pry (GDB integration)")["status"] == "info"
    assert _check(payload, "running VMs")["status"] == "info"

    cli.main(["doctor"])
    text = capsys.readouterr().out
    assert "[i] pry (GDB integration):" in text
    assert "[i] running VMs:" in text
    assert "[+] pry" not in text


def test_doctor_missing_skills_are_informational_not_gating(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: [tmp_path / "none"])

    rc, payload = _run_json_doctor(capsys)

    assert rc == 0
    row = _check(payload, "skills")
    assert row["status"] == "info" and row["blocking"] is False
    assert "qmu skill install" in row["detail"]


def test_doctor_key_permissions_warning_does_not_fail_the_check(
    doctor_env, monkeypatch, capsys, tmp_path
):
    """launch works with a 0644 key (the rootfs decides), so the row is a
    non-blocking warning — it used to flip exit 1."""
    _passt_ok(monkeypatch)
    Path(doctor_env.config.ssh_key).chmod(0o644)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 0
    row = _check(payload, "SSH key permissions")
    assert row["status"] == "warn" and row["blocking"] is False
    cli.main(["doctor"])
    assert "[~] SSH key permissions: mode=644" in capsys.readouterr().out


def test_doctor_forced_kvm_without_dev_kvm_is_gating(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    doctor_env.config.accel = "kvm"
    monkeypatch.setattr(lifecycle.Path, "exists", lambda self: False)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    assert _check(payload, "KVM")["status"] == "fail"


# ---------------------------------------------------------------------------
# Cross toolchain: with a foreign guest arch, `compile --host` and `qmu gdb`
# need a cross compiler and gdb-multiarch. Both are warnings naming the apt
# package; neither blocks launch/exec.
# ---------------------------------------------------------------------------


def test_doctor_adds_cross_toolchain_rows_for_a_foreign_arch(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    monkeypatch.setattr(lifecycle, "host_arch", lambda: "x86_64")

    rc, payload = _run_json_doctor(capsys)

    assert rc == 0
    cc = _check(payload, "cross compiler for aarch64 (compile --host)")
    assert cc["status"] == "warn" and cc["blocking"] is False
    assert "aarch64-linux-gnu-gcc" in cc["detail"]
    assert "apt install gcc-aarch64-linux-gnu" in cc["detail"]
    gdb = _check(payload, "gdb-multiarch (qmu gdb / pry on a foreign arch)")
    assert gdb["status"] == "warn"
    assert "apt install gdb-multiarch" in gdb["detail"]

    doctor_env.executables["aarch64-linux-gnu-gcc"] = "/usr/bin/aarch64-linux-gnu-gcc"
    doctor_env.executables["gdb-multiarch"] = "/usr/bin/gdb-multiarch"
    rc, payload = _run_json_doctor(capsys)
    assert _check(payload, "cross compiler for aarch64 (compile --host)") == {
        "check": "cross compiler for aarch64 (compile --host)",
        "status": "ok", "detail": "/usr/bin/aarch64-linux-gnu-gcc",
        "blocking": False,
    }
    assert _check(payload, "gdb-multiarch (qmu gdb / pry on a foreign arch)")["status"] == "ok"


def test_doctor_has_no_cross_toolchain_rows_for_the_host_arch(
    doctor_env, monkeypatch, capsys
):
    _passt_ok(monkeypatch)
    monkeypatch.setattr(lifecycle, "host_arch", lambda: "aarch64")

    _, payload = _run_json_doctor(capsys)

    assert not [c for c in payload["checks"] if c["check"].startswith("cross compiler")]
    assert not [c for c in payload["checks"] if c["check"].startswith("gdb-multiarch")]


# ---------------------------------------------------------------------------
# The starter file's `kernel = "./bzImage"  # CHANGE ME` line is live now, so
# an unedited starter lands on the kernel row — and the row says why.
# ---------------------------------------------------------------------------


def test_doctor_names_the_starter_placeholder_as_written(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    cfg = doctor_env.config
    cfg.kernel = str(tmp_path / "bzImage")
    cfg._written_paths["kernel"] = "./bzImage"
    cfg._field_sources["kernel"] = f"project: {tmp_path / 'qmu.toml'}"

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    row = _check(payload, "kernel")
    assert row["status"] == "fail"
    assert row["detail"].startswith("./bzImage (CHANGE ME placeholder; not found)")
    assert f"resolves to {tmp_path / 'bzImage'}" in row["detail"]
    assert f"[project {tmp_path / 'qmu.toml'}]" in row["detail"]

    cli.main(["doctor"])
    assert "[!] kernel: ./bzImage (CHANGE ME placeholder; not found)" in capsys.readouterr().out


def test_doctor_missing_rootfs_and_key_say_not_found_with_their_layer(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    cfg = doctor_env.config
    cfg.rootfs = str(tmp_path / "gone.img")
    cfg.ssh_key = str(tmp_path / "gone_key")
    cfg._field_sources["rootfs"] = "global: /home/me/.config/qmu/config.toml"
    cfg._field_sources["ssh_key"] = "CLI flags"

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    rootfs = _check(payload, "rootfs image")
    assert rootfs["status"] == "fail"
    assert rootfs["detail"] == (
        f"{tmp_path / 'gone.img'} (not found) [global /home/me/.config/qmu/config.toml]"
    )
    key = _check(payload, "SSH key")
    assert key["status"] == "fail"
    assert key["detail"] == f"{tmp_path / 'gone_key'} (not found) [flag]"


# ---------------------------------------------------------------------------
# "Not configured" gates only when a flagless launch would fail on it: a
# [boot] kernel is set and the boot is not harness-shaped (initrd, no rootfs).
# ---------------------------------------------------------------------------


def test_doctor_unconfigured_rootfs_and_key_gate_only_with_a_kernel(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    cfg = doctor_env.config
    cfg.rootfs = None
    cfg.ssh_key = None

    # No kernel: launch needs flags anyway — hints only.
    rc, payload = _run_json_doctor(capsys)
    assert rc == 0
    assert _check(payload, "rootfs image")["status"] == "warn"
    assert _check(payload, "SSH key")["status"] == "warn"
    assert "--harness" in _check(payload, "SSH key")["detail"]

    # Kernel set, no initrd: a flagless `qmu launch` fails on these.
    kernel = tmp_path / "bzImage"
    kernel.write_bytes(b"\x00")
    cfg.kernel = str(kernel)
    rc, payload = _run_json_doctor(capsys)
    assert rc == 1
    assert _check(payload, "rootfs image")["status"] == "fail"
    assert "flagless launch will fail" in _check(payload, "rootfs image")["detail"]
    assert _check(payload, "SSH key")["status"] == "fail"

    # Kernel + initrd, no rootfs: the kernelCTF/syzkaller harness shape.
    cfg.initrd = str(kernel)
    rc, payload = _run_json_doctor(capsys)
    assert rc == 0
    assert _check(payload, "rootfs image")["status"] == "warn"
    assert _check(payload, "SSH key")["status"] == "warn"


# ---------------------------------------------------------------------------
# The `qmu config init` tip is for a directory with no project config: with
# one loaded, `config init` would only say "already exists".
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sources", "expect_tip"),
    [
        (["built-in defaults"], True),
        (["built-in defaults", "global: /home/me/.config/qmu/config.toml"], True),
        (["built-in defaults", "project: /work/qmu.toml"], False),
        (["built-in defaults", "config: /work/explicit.toml"], False),
    ],
)
def test_doctor_config_init_tip_only_without_a_project_layer(
    doctor_env, monkeypatch, capsys, sources, expect_tip
):
    _passt_ok(monkeypatch)
    doctor_env.config._sources = sources

    cli.main(["doctor"])
    text = capsys.readouterr().out

    assert ("Tip: run `qmu config init`" in text) is expect_tip
