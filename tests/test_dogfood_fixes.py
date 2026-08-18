"""Regressions found by dogfooding the ergonomics work over ~20 real boots.

Each test here corresponds to a defect that survived the unit suite because it
only appeared against a live VM or a real rootfs image.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qmu import cli, rootfs as rootfs_mod
from qmu.commands import lifecycle
from qmu.config import DEFAULT_PROFILES, QMUConfig, ConfigError, load_config_file
from qmu.instance import QMUError, VMInstance
from qmu.rootfs import _diagnose_guestfish_failure
from qmu.serial import SerialTail, extract_unknown_params
from qmu.vm import suspect_dotted_params


def _instance(serial_log: str) -> VMInstance:
    return VMInstance(
        vm_id="dog-vm",
        pid=4242,
        qmp_socket="/tmp/dog-vm.qmp.sock",
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z",
        harness=True,
    )


# ---------------------------------------------------------------------------
# --inject must run after the previous VM is killed
# ---------------------------------------------------------------------------


def test_inject_runs_after_the_old_vm_is_killed(monkeypatch, tmp_path):
    """Iteration 2 of the boot loop failed: libguestfs cannot open a live image."""
    order: list[str] = []

    existing = _instance(str(tmp_path / "old.serial.log"))
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: existing)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(
        lifecycle, "_kill_vm", lambda inst, **kw: order.append("kill")
    )
    monkeypatch.setattr(
        lifecycle,
        "_inject_into_rootfs",
        lambda config, specs, partition=1, mkdir=False: order.append("inject"),
    )

    def fake_launch_vm(**kwargs):
        order.append("launch")
        return _instance(str(tmp_path / "new.serial.log"))

    monkeypatch.setattr(lifecycle, "launch_vm", fake_launch_vm)

    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[boot]\nkernel = "./bzImage"\n\n[drive]\nrootfs = "./rootfs.img"\n')

    rc = cli.main(
        ["launch", "--config", str(cfg), "--harness", "--name", "probe",
         "--inject", "./a.txt:/root/"]
    )

    assert rc == 0
    assert order == ["kill", "inject", "launch"]


def test_inject_partition_reaches_the_injector(monkeypatch, tmp_path):
    """A whole-disk image needs --partition 0; launch had no way to say so."""
    seen: dict = {}

    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(
        lifecycle,
        "_inject_into_rootfs",
        lambda config, specs, partition=1, mkdir=False: seen.update(partition=partition),
    )
    monkeypatch.setattr(
        lifecycle, "launch_vm",
        lambda **kw: _instance(str(tmp_path / "vm.serial.log")),
    )

    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[boot]\nkernel = "./bzImage"\n\n[drive]\nrootfs = "./rootfs.img"\n')

    rc = cli.main(
        ["launch", "--config", str(cfg), "--harness",
         "--inject", "./a.txt:/root/", "--partition", "0"]
    )

    assert rc == 0
    assert seen["partition"] == 0


# ---------------------------------------------------------------------------
# guestfish failure diagnosis
# ---------------------------------------------------------------------------


def test_appliance_failure_points_at_the_untracked_holder():
    """The tracked-holder pre-check already ran, so name the orphan reaper."""
    out = "libguestfs: error: appliance closed the connection unexpectedly"

    diagnosis = _diagnose_guestfish_failure(out, "./rootfs.img", 1)

    assert diagnosis is not None
    assert "qmu prune --orphans" in diagnosis
    assert "qmu doctor" in diagnosis


def test_unreadable_boot_kernel_is_diagnosed_as_a_permissions_problem():
    out = (
        "supermin: kernel: picked vmlinuz /boot/vmlinuz-6.8.0-137-generic\n"
        "cp: cannot open '/boot/vmlinuz-6.8.0-137-generic': Permission denied\n"
        "supermin: cp -p command failed"
    )

    diagnosis = _diagnose_guestfish_failure(out, "./rootfs.img", 1)

    assert diagnosis is not None
    assert "SUPERMIN_KERNEL" in diagnosis
    assert "chmod" in diagnosis


def test_wrong_partition_is_diagnosed_from_guestfish_own_output():
    out = (
        "libguestfs: error: mount_options: /dev/sda1: No such file or directory\n"
        "guestfish: Did you mean to mount one of these filesystems?\n"
        "guestfish:       /dev/sda (ext4)"
    )

    diagnosis = _diagnose_guestfish_failure(out, "./trixie.img", 1)

    assert diagnosis is not None
    assert "--partition 0" in diagnosis


def test_unknown_failure_returns_no_false_diagnosis():
    assert _diagnose_guestfish_failure("something else entirely", "./i.img", 1) is None


# ---------------------------------------------------------------------------
# exploit-test profile was a no-op
# ---------------------------------------------------------------------------


def test_exploit_test_profile_uses_the_real_boot_parameter():
    """`panic_on_oops` is sysctl-only (kernel/panic.c); the boot form is `oops=panic`.

    With the wrong spelling the kernel passed it to userspace and an exploit
    that corrupted the kernel and kept running read as a clean run.
    """
    cmdline = DEFAULT_PROFILES["exploit-test"]

    assert "oops=panic" in cmdline
    assert "panic_on_oops" not in cmdline


def test_trigger_test_profile_keeps_panic_on_warn():
    """panic_on_warn IS a core_param boot parameter — it was never broken."""
    assert "panic_on_warn=1" in DEFAULT_PROFILES["trigger-test"]


# ---------------------------------------------------------------------------
# unknown kernel command line parameters
# ---------------------------------------------------------------------------


def test_unknown_kernel_params_are_extracted(tmp_path):
    log = tmp_path / "s.log"
    log.write_text(
        '[    0.133588] Unknown kernel command line parameters '
        '"apparmor=0 panic_on_oops=1", will be passed to user space.\n'
    )

    assert extract_unknown_params(log) == ["apparmor=0", "panic_on_oops=1"]


def test_init_consumed_params_are_not_reported_as_unknown(tmp_path):
    """root=/init= always appear here; warning about them trains the reader to ignore."""
    log = tmp_path / "s.log"
    log.write_text(
        '[    0.1] Unknown kernel command line parameters '
        '"root=/dev/sda init=/init.sh nonsense=1", will be passed to user space.\n'
    )

    assert extract_unknown_params(log) == ["nonsense=1"]


def test_no_unknown_params_line_yields_nothing(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("[    0.0] Linux version 6.12.0\n")

    assert extract_unknown_params(log) == []


def test_wait_reports_unknown_params_in_its_envelope(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    serial.write_text(
        '[    0.1] Unknown kernel command line parameters "panic_on_oops=1", '
        'will be passed to user space.\n=== results ===\n'
    )
    inst = _instance(str(serial))
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)

    rc = cli.main(
        ["--format", "json", "wait", "--pattern", "=== results ===", "--timeout", "5"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["unknown_kernel_params"] == ["panic_on_oops=1"]


# ---------------------------------------------------------------------------
# CRLF leaking into matched_line
# ---------------------------------------------------------------------------


def test_serial_tail_strips_the_carriage_return(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("=== HARNESS DONE ===\r\n")

    assert SerialTail(log).read_lines() == ["=== HARNESS DONE ==="]


def test_flush_also_strips_the_carriage_return(tmp_path):
    log = tmp_path / "s.log"
    log.write_text("partial line\r")
    tail = SerialTail(log)
    tail.read_lines()

    assert tail.flush() == ["partial line"]


def test_dollar_anchored_pattern_matches_a_crlf_line(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    serial.write_text("=== results ===\r\n")
    inst = _instance(str(serial))
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)

    rc = cli.main(
        ["--format", "json", "wait", "--pattern", "results ===$", "--timeout", "5"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["matched_line"] == "=== results ==="
    assert "\r" not in payload["matched_line"]


# ---------------------------------------------------------------------------
# config error wording
# ---------------------------------------------------------------------------


def test_misplaced_table_hint_reads_as_a_table_not_a_key(tmp_path):
    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[vm]\nkernel = "./bzImage"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    message = str(exc.value)
    assert "the keys of '[vm]' belong in" in message
    assert "move 'vm' to" not in message


def test_typo_in_a_key_gets_a_did_you_mean(tmp_path):
    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[boot]\nkernal = "./bzImage"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    assert "did you mean 'kernel'?" in str(exc.value)


def test_typo_in_a_table_gets_a_did_you_mean(tmp_path):
    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[machin]\narch = "x86_64"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    assert "did you mean '[machine]'?" in str(exc.value)


def test_unrecognizable_key_lists_the_valid_ones(tmp_path):
    cfg = tmp_path / "qmu.toml"
    cfg.write_text('[boot]\nzzzzzz = "x"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    message = str(exc.value)
    assert "valid keys for [boot]" in message
    assert "kernel" in message


# ---------------------------------------------------------------------------
# doctor libguestfs check
# ---------------------------------------------------------------------------


def test_doctor_flags_an_unreadable_appliance_kernel(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: "/usr/bin/guestfish")
    monkeypatch.delenv("SUPERMIN_KERNEL", raising=False)

    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "vmlinuz-6.8.0-137-generic").write_text("kernel")
    monkeypatch.setattr(lifecycle, "Path", lambda p="": _FakePath(p, boot))
    # Mode 0600 on the real host; patched rather than chmod'd so the result
    # does not depend on the uid running the suite.
    monkeypatch.setattr(lifecycle.os, "access", lambda path, mode: False)

    result = lifecycle._check_libguestfs()

    assert result["status"] == "MISSING"
    assert "SUPERMIN_KERNEL" in result["detail"]


def test_doctor_passes_when_a_boot_kernel_is_readable(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: "/usr/bin/guestfish")
    monkeypatch.delenv("SUPERMIN_KERNEL", raising=False)

    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "vmlinuz-6.8.0-137-generic").write_text("kernel")
    monkeypatch.setattr(lifecycle, "Path", lambda p="": _FakePath(p, boot))

    assert lifecycle._check_libguestfs()["status"] == "ok"


class _FakePath:
    """Minimal Path stand-in that redirects /boot and reports it unreadable."""

    def __init__(self, raw, boot_dir):
        self._raw = str(raw)
        self._boot = boot_dir

    def is_dir(self):
        return self._raw == "/boot"

    def glob(self, pattern):
        return list(self._boot.glob(pattern))


def test_doctor_accepts_an_explicit_readable_supermin_kernel(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: "/usr/bin/guestfish")
    kernel = tmp_path / "vmlinuz"
    kernel.write_text("kernel")
    monkeypatch.setenv("SUPERMIN_KERNEL", str(kernel))

    result = lifecycle._check_libguestfs()

    assert result["status"] == "ok"
    assert str(kernel) in result["detail"]


def test_doctor_reports_missing_guestfish_as_optional(monkeypatch):
    monkeypatch.setattr(lifecycle.shutil, "which", lambda name: None)

    result = lifecycle._check_libguestfs()

    # Informational, not a failure: libguestfs is only needed for inject.
    assert result["status"] == "info"
    assert "libguestfs-tools" in result["detail"]


# ---------------------------------------------------------------------------
# Round 3: nokaslr false-flagged, dotted params invisible
# ---------------------------------------------------------------------------


def test_nokaslr_is_not_reported_as_ineffective(tmp_path):
    """Regression: nokaslr works but the kernel lists it as unknown.

    On x86 it is consumed by the decompressor (arch/x86/boot/compressed/
    kaslr.c) with no __setup entry to claim it, so the later accounting cannot
    know it was honored. Telling an exploit developer that nokaslr had no
    effect invites them to remove it and break every hardcoded-address exploit.
    """
    log = tmp_path / "s.log"
    log.write_text(
        '[    0.1] Unknown kernel command line parameters '
        '"nokaslr apparmor=0 zzz_bogus=1", will be passed to user space.\n'
    )

    unknown = extract_unknown_params(log, arch="x86_64")

    assert "nokaslr" not in unknown
    assert unknown == ["apparmor=0", "zzz_bogus=1"]


@pytest.mark.parametrize("param", ["no5lvl", "acpi_rsdp=0x123", "earlyprintk=serial"])
def test_other_pre_parse_params_are_not_flagged(tmp_path, param):
    log = tmp_path / "s.log"
    log.write_text(
        f'[    0.1] Unknown kernel command line parameters "{param} real_typo=1", '
        'will be passed to user space.\n'
    )

    assert extract_unknown_params(log, arch="x86_64") == ["real_typo=1"]


def test_dotted_param_typo_is_caught_by_the_spell_check():
    """The kernel never lists dotted params as unknown, so nothing else sees this."""
    suspects = suspect_dotted_params("console=ttyS0 kasan.faul=panic")

    assert suspects == [("kasan.faul", "kasan.fault")]


def test_correct_dotted_param_is_not_flagged():
    assert suspect_dotted_params("kasan.fault=panic net.ifnames=0") == []


def test_unrelated_dotted_param_is_left_alone():
    """A legitimate param qmu has never heard of must not be second-guessed."""
    assert suspect_dotted_params("nvme.io_queue_depth=4 xhci_hcd.quirks=1") == []


def test_operator_params_and_profile_params_are_reported_separately(
    monkeypatch, tmp_path, capsys
):
    """A warning that is always present is a warning nobody reads."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text(
        '[    0.1] Unknown kernel command line parameters '
        '"apparmor=0 totally_bogus=7", will be passed to user space.\n'
    )
    inst = _instance(str(serial))
    # apparmor=0 ships in qmu's own exploit-dev profile; totally_bogus=7 does not.
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)

    lifecycle._warn_unknown_kernel_params(inst)
    err = capsys.readouterr().err

    warning, note = err.split("[qmu] Note:")
    assert "totally_bogus=7" in warning
    assert "apparmor=0" not in warning
    assert "apparmor=0" in note


def test_no_operator_params_means_no_loud_warning(monkeypatch, tmp_path, capsys):
    serial = tmp_path / "vm.serial.log"
    serial.write_text(
        '[    0.1] Unknown kernel command line parameters "apparmor=0", '
        'will be passed to user space.\n'
    )
    inst = _instance(str(serial))

    lifecycle._warn_unknown_kernel_params(inst)
    err = capsys.readouterr().err

    assert "Warning" not in err
    assert "apparmor=0" in err


# ---------------------------------------------------------------------------
# Round 3: inject silently created a typo'd directory
# ---------------------------------------------------------------------------


def test_inject_errors_on_a_missing_guest_dir(tmp_path, monkeypatch):
    local = tmp_path / "exploit"
    local.write_text("payload")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")

    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "_missing_dirs", lambda fish, img, part, dirs: ["/rooot"]
    )

    with pytest.raises(QMUError) as exc:
        rootfs_mod.inject(str(image), [(str(local), "/rooot")], partition=0)

    message = str(exc.value)
    assert "/rooot" in message
    assert "--mkdir" in message


def test_missing_dirs_reads_guestfish_is_dir_answers(tmp_path, monkeypatch):
    calls: dict = {}

    def fake_run(cmd, input=None, text=None, capture_output=None):
        calls["input"] = input
        return SimpleNamespace(returncode=0, stdout="true\nfalse\n", stderr="")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    # _missing_dirs sorts its input, so use names whose order is unambiguous.
    missing = rootfs_mod._missing_dirs(
        "guestfish", str(tmp_path / "i.img"), 0, ["/aaa", "/zzz"]
    )

    assert missing == ["/zzz"]
    assert "is-dir" in calls["input"]


def test_missing_dirs_is_inconclusive_on_a_short_read(tmp_path, monkeypatch):
    """Never invent a verdict about paths guestfish did not report on."""
    monkeypatch.setattr(
        rootfs_mod.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="true\n", stderr=""),
    )

    assert rootfs_mod._missing_dirs(
        "guestfish", str(tmp_path / "i.img"), 0, ["/a", "/b"]
    ) == []


# ---------------------------------------------------------------------------
# Round 3: rootfs rm was backwards
# ---------------------------------------------------------------------------


def test_rm_errors_on_a_missing_path(tmp_path, monkeypatch):
    """`rm-f` semantics report success for a typo — wrong for a verification tool."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "_run_script", lambda *a, **k: "false\n"
    )

    with pytest.raises(QMUError) as exc:
        rootfs_mod.remove(str(image), ["/root/nope.txt"], partition=0)

    assert "/root/nope.txt" in str(exc.value)
    assert "--force" in str(exc.value)


def test_rm_force_ignores_a_missing_path(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    scripts: list[str] = []
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "_run_script",
        lambda img, part, script, action: scripts.append(script) or "",
    )

    rootfs_mod.remove(str(image), ["/root/nope.txt"], partition=0, force=True)

    # No existence probe, and `rm-f` so ENOENT is genuinely tolerated —
    # plain `rm` errors on a missing path even with the probe skipped.
    assert len(scripts) == 1
    assert scripts[0].startswith("rm-f ")


def test_rm_recursive_uses_rm_rf(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    scripts: list[str] = []
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "_run_script",
        lambda img, part, script, action: scripts.append(script) or "true\n",
    )

    rootfs_mod.remove(str(image), ["/rooot"], partition=0, recursive=True)

    assert "rm-rf /rooot" in scripts[-1]


# ---------------------------------------------------------------------------
# Round 3: wrong-path vs wrong-partition attribution
# ---------------------------------------------------------------------------


def test_missing_path_is_not_blamed_on_the_partition():
    out = "libguestfs: error: cat: /root/nope.txt: No such file or directory"

    diagnosis = _diagnose_guestfish_failure(out, "./i.img", 0)

    assert diagnosis is not None
    # The fix is to check the path, not to change the partition. (The suggested
    # `ls` command still carries --partition because it has to be correct.)
    assert "needs --partition" not in diagnosis
    assert "was not found in" not in diagnosis
    assert "path does not exist" in diagnosis
    assert "rootfs ls" in diagnosis


def test_directory_target_is_named_as_such():
    out = "libguestfs: error: cat: /root: Is a directory"

    diagnosis = _diagnose_guestfish_failure(out, "./i.img", 0)

    assert diagnosis is not None
    assert "--recursive" in diagnosis


def test_busy_image_is_refused_before_guestfish_runs(monkeypatch, tmp_path):
    """qmu owns the instance metadata, so it can name the blocking VM."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    holder = _instance(str(tmp_path / "h.serial.log"))
    holder.rootfs = str(image)
    monkeypatch.setattr(rootfs_mod, "list_instances", lambda: [holder], raising=False)
    monkeypatch.setattr(
        "qmu.instance.list_instances", lambda: [holder]
    )
    monkeypatch.setattr("qmu.instance.instance_alive", lambda i: True)

    with pytest.raises(QMUError) as exc:
        rootfs_mod.require_image_free(str(image))

    message = str(exc.value)
    assert "dog-vm" in message
    assert "qmu kill --vm dog-vm" in message


def test_image_lock_failure_names_an_untracked_qemu():
    """The metadata pre-check cannot see a QEMU qmu no longer tracks."""
    out = 'qemu-system-x86_64: -device scsi-hd,drive=hd0: Failed to get "write" lock'

    diagnosis = _diagnose_guestfish_failure(out, "./rootfs.img", 0)

    assert diagnosis is not None
    assert "pgrep -af qemu-system" in diagnosis
    assert "qmu kill" in diagnosis
