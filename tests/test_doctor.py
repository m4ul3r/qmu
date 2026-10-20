from __future__ import annotations

import json
import os
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
    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    # The sshd-policy row reads the image through guestfish; the fixture's
    # image is an empty file, so stub the read (tests override it). The
    # appliance probe would start a real guestfish: stub it as running.
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "read_sshd_evidence",
        lambda image, partition=0: _evidence(rootfs_stamp='{"sshd_policy": "key-only"}'),
    )
    monkeypatch.setattr(lifecycle.rootfs_mod, "probe_appliance", lambda fish: (True, ""))

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


_KEY_ONLY_SHADOW = "root:!*:20664:0:99999:7:::"
_LEGACY_SHADOW = "root::20627:0:99999:7:::"
_LEGACY_SSHD = (
    "Include /etc/ssh/sshd_config.d/*.conf\n"
    "PermitRootLogin yes\nPermitEmptyPasswords yes\nUsePAM yes\n"
)
_STOCK_SSHD = "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"


def _evidence(
    *, rootfs_stamp=None, target_stamp=None, root_shadow=_KEY_ONLY_SHADOW,
    sshd_config=_STOCK_SSHD, sshd_config_d=(),
):
    return lifecycle.rootfs_mod.SshdEvidence(
        rootfs_stamp=rootfs_stamp, target_stamp=target_stamp,
        root_shadow=root_shadow, sshd_config=sshd_config, sshd_config_d=sshd_config_d,
    )


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
        "hint": "",
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
        "hint": "",
    }
    assert external_check == {
        "check": "passt (net_backend=passt)",
        "status": "info",
        "detail": "Not found — not required for configured net_backend=user.",
        "blocking": False,
        "hint": "",
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
        "hint": "",
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
        "blocking": False, "hint": "",
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
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "probe_appliance",
        lambda fish: (False, "libguestfs: error: /usr/bin/supermin exited with error status 1."),
    )
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "read_sshd_evidence",
        lambda image, partition=0: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    rc, payload = _run_json_doctor(capsys)

    row = _check(payload, "libguestfs (rootfs inject / launch --inject)")
    assert rc == 0 and payload["ok"] is True
    assert row["status"] == "warn"
    assert row["blocking"] is False
    assert "NOT readable" in row["detail"]
    policy = _check(payload, "rootfs sshd policy")
    assert policy["status"] == "info" and policy["sshd_policy"] is None
    assert "ANY key" not in policy["detail"]

    cli.main(["doctor"])
    assert "[~] libguestfs" in capsys.readouterr().out


def test_doctor_unreadable_boot_kernels_with_a_cached_appliance_still_reads_the_rootfs(
    doctor_env, monkeypatch, capsys
):
    """#146: the appliance cache made inject work while the row said every
    inject would fail, and the sshd-policy row went dark with it."""
    _passt_ok(monkeypatch)
    doctor_env.executables["guestfish"] = "/usr/bin/guestfish"
    monkeypatch.delenv("SUPERMIN_KERNEL", raising=False)
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "appliance_kernel_problem",
        lambda: "no /boot/vmlinuz-* is readable (they are mode 0600)",
    )
    probed = []
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "probe_appliance", lambda fish: probed.append(fish) or (True, ""),
    )

    rc, payload = _run_json_doctor(capsys)

    row = _check(payload, "libguestfs (rootfs inject / launch --inject)")
    assert probed == ["/usr/bin/guestfish"]
    assert rc == 0 and row["status"] == "warn" and row["blocking"] is False
    assert "will fail" not in row["detail"]
    # The unprivileged remedy leads; the system-wide chmod is the alternative.
    assert row["hint"].startswith("export SUPERMIN_KERNEL=")
    assert _check(payload, "rootfs sshd policy")["sshd_policy"] == "key-only"


# ---------------------------------------------------------------------------
# #75/#145: a cached mkrootfs image built before key-only sshd accepts root
# with ANY key. doctor measures that (root's shadow entry + sshd config) and
# reads both qmu stamps; a missing stamp alone is no evidence either way.
# ---------------------------------------------------------------------------


def _libguestfs_ok(doctor_env, monkeypatch, tmp_path):
    doctor_env.executables["guestfish"] = "/usr/bin/guestfish"
    kernel = tmp_path / "vmlinuz"
    kernel.write_bytes(b"")
    monkeypatch.setenv("SUPERMIN_KERNEL", str(kernel))


def _use_evidence(monkeypatch, evidence, seen=None):
    def read(image, partition=0):
        if seen is not None:
            seen["image"] = image
        return evidence

    monkeypatch.setattr(lifecycle.rootfs_mod, "read_sshd_evidence", read)


def test_doctor_sshd_policy_key_only_is_ok(doctor_env, monkeypatch, capsys, tmp_path):
    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)
    seen = {}
    _use_evidence(
        monkeypatch, _evidence(rootfs_stamp='{"schema": 1, "sshd_policy": "key-only"}'), seen,
    )
    rc, payload = _run_json_doctor(capsys)
    assert rc == 0
    assert _check(payload, "rootfs sshd policy") == {
        "check": "rootfs sshd policy", "status": "ok", "detail": "key-only",
        "blocking": False, "hint": "", "sshd_policy": "key-only",
    }
    assert seen["image"] == doctor_env.config.rootfs
    cli.main(["doctor"])
    assert "[+] rootfs sshd policy: key-only" in capsys.readouterr().out


def test_doctor_sshd_policy_mktarget_target_is_key_only(
    doctor_env, monkeypatch, capsys, tmp_path
):
    """#145: every mktarget.sh target was reported permissive with a hint to
    rebuild it with mkrootfs.sh, which cannot build an Ubuntu target."""
    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)
    _use_evidence(monkeypatch, _evidence(
        target_stamp='{"mktarget_version": "2", "distro": "ubuntu"}',
        sshd_config_d=("PermitRootLogin prohibit-password\nPasswordAuthentication no\n"
                       "PermitEmptyPasswords no\n",),
    ))
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "rootfs sshd policy")
    assert rc == 0
    assert row["status"] == "ok" and row["sshd_policy"] == "key-only"
    assert "mkrootfs" not in row["detail"] + row["hint"]


@pytest.mark.parametrize("stamps", [
    {},
    {"rootfs_stamp": '{"sshd_policy": "key-only"}'},
    {"target_stamp": '{"mktarget_version": "2"}'},
    {"target_stamp": '{"mktarget_version": "2", "hardening": "relaxed"}'},
])
def test_doctor_sshd_policy_measured_empty_root_password_warns_not_blocks(
    doctor_env, monkeypatch, capsys, tmp_path, stamps
):
    """The legacy mkrootfs setup is permissive whatever a stamp says."""
    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)
    _use_evidence(monkeypatch, _evidence(
        root_shadow=_LEGACY_SHADOW, sshd_config=_LEGACY_SSHD, **stamps,
    ))
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "rootfs sshd policy")
    assert rc == 0 and payload["ok"] is True
    assert row["status"] == "warn" and row["blocking"] is False
    assert row["sshd_policy"] == "permissive"
    assert ("mktarget" in row["hint"]) == ("target_stamp" in stamps)
    # a relaxed target lives in its own -relaxed directory: only the same
    # flag rebuilds the image doctor is looking at
    assert ("--relax-hardening" in row["hint"]) == ("relaxed" in stamps.get("target_stamp", ""))
    cli.main(["doctor"])
    assert "[~] rootfs sshd policy: permissive" in capsys.readouterr().out


@pytest.mark.parametrize("rootfs_stamp", [None, "{}", '{"sshd_policy": "any-key"}', "not json"])
def test_doctor_sshd_policy_without_stamp_or_open_path_claims_nothing(
    doctor_env, monkeypatch, capsys, tmp_path, rootfs_stamp
):
    """#145: a missing stamp is evidence the image was not built by a qmu
    tool, not that its sshd is permissive."""
    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)
    _use_evidence(monkeypatch, _evidence(rootfs_stamp=rootfs_stamp))
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "rootfs sshd policy")
    assert rc == 0
    assert row["status"] == "info" and row["sshd_policy"] == "unknown"
    assert row["hint"] == ""
    assert "ANY key" not in row["detail"]


def test_doctor_sshd_policy_is_not_checked_without_guestfish(
    doctor_env, monkeypatch, capsys
):
    """guestfish absent: the row says so instead of guessing either way."""
    _passt_ok(monkeypatch)
    monkeypatch.setattr(
        lifecycle.rootfs_mod, "read_sshd_evidence",
        lambda image, partition=0: (_ for _ in ()).throw(AssertionError("must not run")),
    )
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "rootfs sshd policy")
    assert rc == 0
    assert row["status"] == "info" and row["sshd_policy"] is None
    assert "ANY key" not in row["detail"]
    cli.main(["doctor"])
    assert "[i] rootfs sshd policy: not checked (" in capsys.readouterr().out


def test_doctor_sshd_policy_guestfish_failure_is_not_checked(
    doctor_env, monkeypatch, capsys, tmp_path
):
    """A partitioned or foreign image the whole-disk mount cannot open."""
    from qmu.instance import QMUError

    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)

    def boom(image, partition=0):
        raise QMUError("guestfish sshd failed (exit 1).\nTry `qmu rootfs shell`")

    monkeypatch.setattr(lifecycle.rootfs_mod, "read_sshd_evidence", boom)
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "rootfs sshd policy")
    assert rc == 0
    assert row["status"] == "info"
    assert row["detail"] == "not checked (guestfish sshd failed (exit 1).)"


def test_doctor_sshd_policy_row_absent_without_a_usable_rootfs(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    _libguestfs_ok(doctor_env, monkeypatch, tmp_path)
    for rootfs in (None, str(tmp_path / "missing.img")):
        doctor_env.config.rootfs = rootfs
        _, payload = _run_json_doctor(capsys)
        assert not [c for c in payload["checks"] if c["check"] == "rootfs sshd policy"]


# ---------------------------------------------------------------------------
# #75: the initrd row, shaped like the kernel row.
# ---------------------------------------------------------------------------


def test_doctor_initrd_not_configured_is_informational(doctor_env, monkeypatch, capsys):
    _passt_ok(monkeypatch)
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "initrd")
    assert rc == 0
    assert row["status"] == "info" and row["blocking"] is False and row["hint"] == ""
    cli.main(["doctor"])
    assert "[i] initrd: not configured" in capsys.readouterr().out


def test_doctor_blocks_on_a_configured_initrd_that_is_missing(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    cfg = doctor_env.config
    cfg.initrd = str(tmp_path / "initramfs.cpio.gz")
    cfg._written_paths["initrd"] = "./initramfs.cpio.gz"
    cfg._field_sources["initrd"] = f"project: {tmp_path / 'qmu.toml'}"

    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "initrd")
    assert rc == 1 and payload["ok"] is False
    assert row["status"] == "fail" and row["blocking"] is True
    assert row["detail"].startswith("./initramfs.cpio.gz (not found) — resolves to ")
    assert "launch will fail with `Initrd not found`" in row["detail"]
    assert row["hint"] == "set [boot] initrd in qmu.toml or pass --initrd"
    # #120: the unhealthy envelope itself carries a hint that names the
    # failing row(s) and their fixes — not a bare "run qmu doctor".
    assert payload["hint"].startswith("Fix the [!] row(s): initrd — initrd: set [boot] initrd")
    assert "checks[]" in payload["hint"]
    cli.main(["doctor"])
    assert "[!] initrd: ./initramfs.cpio.gz (not found)" in capsys.readouterr().out


def test_doctor_healthy_envelope_carries_no_hint(doctor_env, monkeypatch, capsys):
    _passt_ok(monkeypatch)
    rc, payload = _run_json_doctor(capsys)
    assert rc == 0 and payload["ok"] is True
    assert "hint" not in payload


def test_doctor_passes_a_configured_initrd_that_exists(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    initrd = tmp_path / "initramfs.cpio.gz"
    initrd.write_bytes(b"\x00")
    doctor_env.config.initrd = str(initrd)
    rc, payload = _run_json_doctor(capsys)
    assert rc == 0
    assert _check(payload, "initrd") == {
        "check": "initrd", "status": "ok", "detail": str(initrd),
        "blocking": False, "hint": "",
    }
    cli.main(["doctor"])
    assert f"[+] initrd: {initrd}" in capsys.readouterr().out


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


def test_every_doctor_row_carries_a_machine_readable_hint(
    doctor_env, monkeypatch, capsys
):
    """The fix lives in `hint`, not only inside the prose `detail`."""
    _passt_ok(monkeypatch)
    doctor_env.config.kernel = "./bzImage"  # not found -> fail
    doctor_env.executables["pry"] = None
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: [Path("/nonexistent")])

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    for row in payload["checks"]:
        assert isinstance(row["hint"], str), row["check"]
        if row["status"] == "ok":
            assert row["hint"] == "", row["check"]
        if row["status"] == "fail":
            assert row["hint"], row["check"]
    assert _check(payload, "kernel")["hint"] == "set [boot] kernel in qmu.toml or pass --kernel"
    assert _check(payload, "skills")["hint"] == "qmu skill install"
    assert _check(payload, "pry (GDB integration)")["hint"]


def test_doctor_skills_row_is_a_count_with_paths_in_json(
    doctor_env, monkeypatch, capsys, tmp_path
):
    """Fifteen absolute paths on one line dominated every doctor run."""
    _passt_ok(monkeypatch)
    sources = []
    roots = [tmp_path / r for r in ("claude", "codex", "agents")]
    for name in ("qmu", "qmu-linux-kbuild", "qmu-linux-rootfs", "qmu-ubuntu-target", "firmware-over-qmu"):
        src = tmp_path / "repo-skills" / name
        src.mkdir(parents=True)
        sources.append(src)
        for root in roots:
            root.mkdir(exist_ok=True)
            (root / name).symlink_to(src)
    monkeypatch.setattr(lifecycle, "all_skill_source_dirs", lambda: sources)
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: roots)

    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "skills")
    assert row["status"] == "ok"
    assert row["summary"] == "5 skills × 3 roots installed"
    assert row["detail"] == ", ".join(row["detail_paths"]["installed"])
    assert len(row["detail_paths"]["installed"]) == 15
    assert row["detail_paths"]["missing"] == []
    assert row["detail_paths"]["stale"] == []

    cli.main(["doctor"])
    text = capsys.readouterr().out
    skills_line = next(l for l in text.splitlines() if "] skills:" in l)
    assert len(skills_line) <= 120
    assert str(tmp_path) not in skills_line


def test_doctor_skills_row_counts_missing_and_stale_links(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    src = tmp_path / "repo-skills" / "qmu"
    src.mkdir(parents=True)
    other = tmp_path / "old-checkout" / "qmu"
    other.mkdir(parents=True)
    roots = [tmp_path / "claude", tmp_path / "codex", tmp_path / "agents"]
    for root in roots:
        root.mkdir()
    (roots[0] / "qmu").symlink_to(src)
    (roots[1] / "qmu").symlink_to(other)
    monkeypatch.setattr(lifecycle, "all_skill_source_dirs", lambda: [src])
    monkeypatch.setattr(lifecycle, "skill_install_roots", lambda: roots)

    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "skills")
    assert row["status"] == "warn"
    assert row["detail"] == (
        "partial: 2 installed, 1 missing, 1 stale (linked to another checkout) "
        "(run: qmu skill install)"
    )
    assert row["summary"] == (
        "1 skills × 3 roots: 2 installed, 1 missing, 1 stale (linked to "
        "another checkout) (run: qmu skill install)"
    )
    assert row["hint"] == "qmu skill install"
    assert row["detail_paths"]["missing"] == [str(roots[2] / "qmu")]
    assert row["detail_paths"]["stale"] == [str(roots[1] / "qmu")]


def test_doctor_running_vms_counts_records_and_orphans_like_list(
    doctor_env, monkeypatch, capsys
):
    """`doctor` said 0 while `list` showed a VM: orphaned QEMUs are running too."""
    _passt_ok(monkeypatch)
    monkeypatch.setattr(lifecycle, "list_instances", lambda: [object()])
    monkeypatch.setattr(
        lifecycle, "find_orphan_qemus", lambda: [{"pid": 4242, "serial_log": "/x"}],
    )

    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "running VMs")
    assert row["running"] == 1 and row["orphaned"] == 1
    assert row["detail"].startswith("1 running + 1 orphaned (no instance record) under ")
    assert row["hint"] == "qmu prune --orphans --dry-run"

    monkeypatch.setattr(lifecycle, "find_orphan_qemus", lambda: [])
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "running VMs")
    assert row["detail"].startswith("1 running under ")
    assert row["hint"] == ""


def test_doctor_libguestfs_honours_a_readable_supermin_kernel(
    doctor_env, monkeypatch, capsys, tmp_path
):
    _passt_ok(monkeypatch)
    doctor_env.executables["guestfish"] = "/usr/bin/guestfish"
    kernel = tmp_path / "vmlinuz"
    kernel.write_bytes(b"")
    monkeypatch.setenv("SUPERMIN_KERNEL", str(kernel))

    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "libguestfs (rootfs inject / launch --inject)")
    assert row["status"] == "ok"
    assert row["detail"] == f"/usr/bin/guestfish; SUPERMIN_KERNEL={kernel}"
    assert row["hint"] == ""

    monkeypatch.setenv("SUPERMIN_KERNEL", str(tmp_path / "absent"))
    rc, payload = _run_json_doctor(capsys)
    row = _check(payload, "libguestfs (rootfs inject / launch --inject)")
    assert row["status"] == "warn"
    assert "is NOT readable" in row["detail"]
    assert row["hint"] == "export SUPERMIN_KERNEL=<readable kernel image>"


def test_doctor_group_readable_key_is_gating_like_openssh(
    doctor_env, monkeypatch, capsys
):
    """OpenSSH refuses an owner's key with group/other bits (UNPROTECTED
    PRIVATE KEY FILE) deterministically, so no rootfs can make it usable:
    the row must gate, with the chmod fix (#94)."""
    _passt_ok(monkeypatch)
    key = Path(doctor_env.config.ssh_key)
    key.chmod(0o644)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    assert payload["ok"] is False
    row = _check(payload, "SSH key permissions")
    assert row["status"] == "fail" and row["blocking"] is True
    assert row["hint"] == f"chmod 600 {doctor_env.config.ssh_key}"
    assert cli.main(["doctor"]) == 1
    assert "[!] SSH key permissions:" in capsys.readouterr().out


@pytest.mark.parametrize("mode", [0o400, 0o600, 0o700])
def test_doctor_key_modes_openssh_accepts_are_ok(
    doctor_env, monkeypatch, capsys, mode
):
    """Stricter-than-0600 modes load fine; only group/other bits are refused."""
    _passt_ok(monkeypatch)
    Path(doctor_env.config.ssh_key).chmod(mode)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 0
    assert _check(payload, "SSH key permissions")["status"] == "ok"


def test_doctor_unreadable_key_is_gating(doctor_env, monkeypatch, capsys):
    if os.geteuid() == 0:
        pytest.skip("root reads every mode")
    _passt_ok(monkeypatch)
    Path(doctor_env.config.ssh_key).chmod(0o200)

    rc, payload = _run_json_doctor(capsys)

    assert rc == 1
    row = _check(payload, "SSH key permissions")
    assert row["status"] == "fail" and row["blocking"] is True


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
        "blocking": False, "hint": "",
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
