"""Round-4 regressions, all found by dogfooding round-3 code against real VMs.

Two of these (1 and 2) are silent-wrong-answer bugs: the tool reported success
or printed an attribute that did not describe the boot that actually happened.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qmu import cli, rootfs as rootfs_mod
from qmu.commands import lifecycle
from qmu.config import QMUConfig
from qmu import instance as instance_mod
from qmu.instance import QMUError, VMInstance
from qmu.rootfs import _diagnose_guestfish_failure
from qmu.serial import extract_crash, extract_unknown_params
from qmu.vm import suspect_dotted_params


def _instance(**over) -> VMInstance:
    base = dict(
        vm_id="r4-vm", pid=4242, qmp_socket="/tmp/r4.qmp.sock",
        ssh_port=None, ssh_key=None, gdb_port=None,
        serial_log="/tmp/r4.serial.log", kernel="/boot/bzImage",
        rootfs="/var/rootfs.img", memory="4G", cpus=2,
        cmdline="console=ttyS0", profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z", harness=True,
    )
    base.update(over)
    return VMInstance(**base)


# ---------------------------------------------------------------------------
# 1. CLI --profile silently lost to [boot] cmdline
# ---------------------------------------------------------------------------


@pytest.fixture
def captured(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)

    def fake_launch_vm(**kwargs):
        calls.append(kwargs)
        return _instance(cmdline=kwargs.get("cmdline") or "",
                         profile=kwargs.get("profile") or "exploit-dev")

    monkeypatch.setattr(lifecycle, "launch_vm", fake_launch_vm)
    return calls


def _cfg(tmp_path, body: str):
    path = tmp_path / "qmu.toml"
    path.write_text(body)
    return str(path)


BOOT_WITH_CMDLINE = (
    '[boot]\nkernel = "./bzImage"\n'
    'cmdline = "console=ttyS0 root=/dev/sda rw init=/init.sh"\n'
)


def test_cli_profile_beats_a_project_boot_cmdline(captured, tmp_path):
    """--profile exploit-test must not become a silent no-op."""
    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, BOOT_WITH_CMDLINE), "--harness",
         "--profile", "exploit-test"]
    )

    assert rc == 0
    assert captured[0]["profile"] == "exploit-test"
    # cmdline=None means resolve_cmdline falls through to the profile.
    assert captured[0]["cmdline"] is None


def test_cli_profile_override_is_announced(captured, tmp_path, capsys):
    cli.main(
        ["launch", "--config", _cfg(tmp_path, BOOT_WITH_CMDLINE), "--harness",
         "--profile", "exploit-test"]
    )

    assert "overrides the [boot] cmdline" in capsys.readouterr().err


def test_explicit_cli_cmdline_still_wins_over_profile(captured, tmp_path):
    """The caller overriding themselves is not the bug being fixed."""
    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, BOOT_WITH_CMDLINE), "--harness",
         "--profile", "exploit-test", "--cmdline", "console=ttyS0 mine=1"]
    )

    assert rc == 0
    assert captured[0]["cmdline"] == "console=ttyS0 mine=1"


def test_boot_cmdline_still_applies_without_a_cli_profile(captured, tmp_path):
    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, BOOT_WITH_CMDLINE), "--harness"]
    )

    assert rc == 0
    assert captured[0]["cmdline"] == "console=ttyS0 root=/dev/sda rw init=/init.sh"


def test_status_marks_a_profile_that_did_not_apply():
    inst = _instance(profile="exploit-test", cmdline_override=True)

    assert "NOT applied" in lifecycle._profile_label(inst)


def test_status_shows_a_plain_profile_when_it_did_apply():
    inst = _instance(profile="exploit-test", cmdline_override=False)

    assert lifecycle._profile_label(inst) == "exploit-test"


def test_overridden_profile_is_not_credited_for_unknown_params(monkeypatch):
    """Attribution must not blame a profile that contributed nothing."""
    inst = _instance(cmdline_override=True)

    assert lifecycle._profile_params(inst) == set()


# ---------------------------------------------------------------------------
# 2. --no-replace was ignored, orphaning a QEMU
# ---------------------------------------------------------------------------


def test_no_replace_fails_instead_of_orphaning(monkeypatch, tmp_path, capsys):
    """Launching anyway overwrote the metadata and stranded the running QEMU."""
    existing = _instance(pid=1111)
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: existing)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    launched: list = []
    monkeypatch.setattr(
        lifecycle, "launch_vm", lambda **kw: launched.append(kw) or _instance()
    )

    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, '[boot]\nkernel = "./b"\n'),
         "--harness", "--name", "orph", "--no-replace"]
    )

    assert rc == 1
    assert launched == []
    err = capsys.readouterr().err
    assert "already running" in err
    assert "qmu kill --vm orph" in err


def test_no_replace_is_fine_when_nothing_is_running(monkeypatch, tmp_path):
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    monkeypatch.setattr(lifecycle, "launch_vm", lambda **kw: _instance())

    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, '[boot]\nkernel = "./b"\n'),
         "--harness", "--name", "fresh", "--no-replace"]
    )

    assert rc == 0


def test_replace_still_kills_the_old_vm(monkeypatch, tmp_path):
    existing = _instance(pid=1111)
    killed: list = []
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: existing)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_kill_vm", lambda i, **kw: killed.append(i))
    monkeypatch.setattr(lifecycle, "launch_vm", lambda **kw: _instance())

    rc = cli.main(
        ["launch", "--config", _cfg(tmp_path, '[boot]\nkernel = "./b"\n'),
         "--harness", "--name", "orph"]
    )

    assert rc == 0
    assert killed == [existing]


def test_orphan_scan_matches_only_qmu_launched_qemus(monkeypatch, tmp_path):
    """A user's own QEMU must never be a reaping candidate.

    find_orphan_qemus lives in qmu.instance (bottom of the DAG, so rootfs.py
    can reach it too), which is the module whose seams this patches.
    """
    inst_dir = tmp_path / "instances"
    inst_dir.mkdir()
    monkeypatch.setattr(instance_mod, "instances_dir", lambda: inst_dir)
    monkeypatch.setattr(instance_mod, "list_instances", lambda: [])

    procs = {
        "100": f"qemu-system-x86_64\0-qmp\0unix:{inst_dir}/a.qmp.sock,server\0",
        "200": "qemu-system-x86_64\0-qmp\0unix:/somewhere/else.sock\0",
        "300": "sshd\0-D\0",
    }

    class FakeEntry:
        def __init__(self, name):
            self.name = name

        def __truediv__(self, _child):
            return SimpleNamespace(
                read_bytes=lambda: procs[self.name].encode()
            )

    monkeypatch.setattr(
        instance_mod, "Path",
        lambda p: SimpleNamespace(iterdir=lambda: [FakeEntry(n) for n in procs]),
    )

    found = [o["pid"] for o in instance_mod.find_orphan_qemus()]

    assert found == [100]


# ---------------------------------------------------------------------------
# 3. Pre-parse allowlist must be arch-gated
# ---------------------------------------------------------------------------


def _unknown_log(tmp_path, params: str):
    log = tmp_path / "s.log"
    log.write_text(
        f'[ 0.1] Unknown kernel command line parameters "{params}", '
        'will be passed to user space.\n'
    )
    return log


def test_nokaslr_is_reported_on_arm32_where_it_does_nothing(tmp_path):
    """arch/arm/ has no KASLR at all — the kernel's report is correct there."""
    log = _unknown_log(tmp_path, "nokaslr zzz_bogus=1")

    assert extract_unknown_params(log, arch="arm") == ["nokaslr", "zzz_bogus=1"]


def test_nokaslr_is_suppressed_on_x86_where_it_works(tmp_path):
    log = _unknown_log(tmp_path, "nokaslr zzz_bogus=1")

    assert extract_unknown_params(log, arch="x86_64") == ["zzz_bogus=1"]


@pytest.mark.parametrize("param", ["edd", "forcepae", "no5lvl", "acpi_rsdp=0x1"])
def test_x86_only_params_are_reported_on_arm(tmp_path, param):
    """Suppressing an x86 name off-x86 hides a parameter that really is inert."""
    log = _unknown_log(tmp_path, f"{param} zzz=1")

    assert param.split("=")[0] in " ".join(
        extract_unknown_params(log, arch="aarch64")
    )


def test_unknown_arch_suppresses_only_universally_inert_names(tmp_path):
    """Old instance JSON has no arch; never hide a real dud on a guess."""
    log = _unknown_log(tmp_path, "nokaslr quiet zzz=1")

    assert extract_unknown_params(log, arch=None) == ["nokaslr", "zzz=1"]


# ---------------------------------------------------------------------------
# 4. Crash extraction truncated to the panic epilogue
# ---------------------------------------------------------------------------


GPF_WITH_EPILOGUE = """[ 1.50] general protection fault, probably for non-canonical address 0x5252525252525252: 0000 [#1] SMP
[ 1.50] RIP: 0010:perf_event__header_size+0x12/0x80
[ 1.50] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 5252525252525252
[ 1.50]  perf_event_release_kernel+0x1a0/0x3c0
[ 1.50] Modules linked in:
[ 1.50] ---[ end trace 0000000000000000 ]---
[ 1.50] RIP: 0010:perf_event__header_size+0x12/0x80
[ 1.50] CR2: 0000000000000000 CR3: 0000000012345000 CR4: 00000000000006f0
[ 1.50] note: exploit[142] exited with irqs disabled
[ 1.50] Kernel panic - not syncing: Fatal exception
[ 1.50] ---[ end Kernel panic - not syncing: Fatal exception ]---
"""


def test_crash_keeps_the_registers_across_the_die_epilogue(tmp_path):
    """The load-bearing evidence is RIP/RDI, not the three-line panic tail."""
    log = tmp_path / "gpf.log"
    log.write_text(GPF_WITH_EPILOGUE)

    report = extract_crash(log)

    assert "general protection fault" in report
    assert "RDI: 5252525252525252" in report
    assert "perf_event_release_kernel" in report
    assert "Kernel panic - not syncing" in report


def test_resumed_warning_is_not_bridged_into_a_later_panic(tmp_path):
    """Ordinary output between the two proves the first event really ended."""
    log = tmp_path / "resumed.log"
    log.write_text(
        "[ 1.0] WARNING: CPU: 0 at old_root_cause\n"
        "[ 1.2] ---[ end trace 111 ]---\n"
        "[ 1.3] service resumed normally\n"
        "[ 2.0] sysrq: Trigger a crash\n"
        "[ 2.1] Kernel panic - not syncing: sysrq triggered crash\n"
    )

    report = extract_crash(log)

    assert "sysrq triggered crash" in report
    assert "old_root_cause" not in report


# ---------------------------------------------------------------------------
# 5. rm --force did not force
# ---------------------------------------------------------------------------


def test_rm_force_uses_rm_f_so_enoent_is_tolerated(tmp_path, monkeypatch):
    """Skipping the probe was not enough: plain `rm` errors on ENOENT too."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    scripts: list[str] = []
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "_run_script",
        lambda img, part, script, action: scripts.append(script) or "",
    )

    rootfs_mod.remove(str(image), ["/root/nope"], partition=0, force=True)

    assert scripts == ["rm-f /root/nope\n"]


# ---------------------------------------------------------------------------
# 6. Dotted spell-check knew 1 of 9 kasan.* params
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "typo,expected",
    [
        ("kasan.mod=off", "kasan.mode"),
        ("kasan.vmaloc=off", "kasan.vmalloc"),
        ("kasan.stacktrce=off", "kasan.stacktrace"),
        ("kasan.write_ony=1", "kasan.write_only"),
    ],
)
def test_kasan_family_typos_are_caught(typo, expected):
    suspects = suspect_dotted_params(f"console=ttyS0 {typo}")

    assert suspects and suspects[0][1] == expected


@pytest.mark.parametrize(
    "param",
    [
        "kasan.mode=off", "kasan.vmalloc=off", "kasan.stacktrace=off",
        "kasan.write_only=1", "kasan.stack_ring_size=1024",
        "arm64.nomte", "id_aa64pfr1.mte=0", "nvme.io_queue_depth=4",
        "xhci_hcd.quirks=1", "usbcore.autosuspend=-1", "ctf.root_shell=1",
        "iommu.passthrough=1", "random.trust_cpu=on",
    ],
)
def test_legitimate_dotted_params_are_never_flagged(param):
    assert suspect_dotted_params(f"console=ttyS0 {param}") == []


# ---------------------------------------------------------------------------
# 7. Busy-image guard blocked read-only inspection
# ---------------------------------------------------------------------------


def test_ls_opens_read_only_and_skips_the_busy_guard(tmp_path, monkeypatch):
    """Checking whether an inject landed is exactly a while-running question."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    guarded: list = []
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "require_image_free", lambda img: guarded.append(img)
    )
    seen: dict = {}

    def fake_run(cmd, input=None, text=None, capture_output=None):
        seen["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="total 0\n", stderr="")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    rootfs_mod.listdir(str(image), "/root", partition=0)

    assert guarded == []
    assert "--ro" in seen["cmd"]


def test_cat_also_opens_read_only(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "require_image_free",
        lambda img: pytest.fail("read-only command must not take the write guard"),
    )
    seen: dict = {}

    def fake_run(cmd, input=None, text=None, capture_output=None):
        seen["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="hi\n", stderr="")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    assert rootfs_mod.read_file(str(image), "/init.sh", partition=0) == "hi\n"
    assert "--ro" in seen["cmd"]


def test_writers_still_take_the_guard(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    guarded: list = []
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "require_image_free", lambda img: guarded.append(img)
    )
    monkeypatch.setattr(
        rootfs_mod.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="true\n", stderr=""),
    )

    rootfs_mod.remove(str(image), ["/root/x"], partition=0)

    assert guarded


def test_guard_message_says_write_not_modify(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    holder = _instance(rootfs=str(image), vm_id="rep")
    monkeypatch.setattr("qmu.instance.list_instances", lambda: [holder])
    monkeypatch.setattr("qmu.instance.instance_alive", lambda i: True)

    with pytest.raises(QMUError) as exc:
        rootfs_mod.require_image_free(str(image))

    assert "Cannot write to" in str(exc.value)


# ---------------------------------------------------------------------------
# 8. JSON merged the operator/profile split
# ---------------------------------------------------------------------------


def test_json_keeps_the_operator_profile_split(monkeypatch, tmp_path, capsys):
    """A script gating on 'did I pass a bogus param' must not trip forever."""
    serial = tmp_path / "vm.serial.log"
    serial.write_text(
        '[ 0.1] Unknown kernel command line parameters "apparmor=0 my_bogus=1", '
        'will be passed to user space.\n=== results ===\n'
    )
    inst = _instance(serial_log=str(serial), arch="x86_64")
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(lifecycle, "instance_alive", lambda i: True)
    monkeypatch.setattr(lifecycle, "_PATTERN_POLL_INTERVAL", 0.001)

    rc = cli.main(
        ["--format", "json", "wait", "--pattern", "=== results ===", "--timeout", "5"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    by_source = payload["unknown_kernel_params_by_source"]
    assert by_source["operator"] == ["my_bogus=1"]
    assert by_source["profile"] == ["apparmor=0"]
    # The flat key stays for back-compat.
    assert payload["unknown_kernel_params"] == ["apparmor=0", "my_bogus=1"]
