"""Launch ergonomics: [boot] config, --append, --vm alias, and the root= guard.

Each case here corresponds to a round trip an agent otherwise spends
rediscovering: that --kernel must be retyped on every launch, that --cmdline
silently replaces the profile (dropping root=), and that --vm means "instance"
everywhere except launch.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle
from qmu.config import QMUConfig, load_config_file, ConfigError
from qmu.instance import QMUError, VMInstance
from qmu.vm import resolve_cmdline


@pytest.fixture
def captured_launch(monkeypatch):
    """Replace launch_vm with a recorder so no QEMU process is started."""
    calls: list[dict] = []

    def fake_launch_vm(**kwargs):
        calls.append(kwargs)
        config: QMUConfig = kwargs["config"]
        return VMInstance(
            vm_id=kwargs.get("name") or "auto-vm",
            pid=1234,
            qmp_socket="/tmp/auto-vm.qmp.sock",
            ssh_port=None,
            ssh_key=None,
            gdb_port=None,
            serial_log="/tmp/auto-vm.serial.log",
            kernel=kwargs["kernel"],
            rootfs=config.rootfs,
            memory=config.memory,
            cpus=config.cpus,
            cmdline=kwargs.get("cmdline") or "",
            profile=kwargs.get("profile") or "exploit-dev",
            started_at="2026-08-17T00:00:00Z",
            harness=True,
        )

    monkeypatch.setattr(lifecycle, "launch_vm", fake_launch_vm)
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: None)
    return calls


def _write_config(tmp_path, body: str):
    path = tmp_path / "qmu.toml"
    path.write_text(body)
    return path


# ---------------------------------------------------------------------------
# [boot] table
# ---------------------------------------------------------------------------


def test_kernel_can_come_from_config(captured_launch, tmp_path):
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./bzImage"\n')

    rc = cli.main(["launch", "--config", str(cfg), "--harness"])

    assert rc == 0
    assert captured_launch[0]["kernel"] == "./bzImage"


def test_launch_flag_beats_config_kernel(captured_launch, tmp_path):
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./from-config"\n')

    rc = cli.main(
        ["launch", "--config", str(cfg), "--harness", "--kernel", "./from-flag"]
    )

    assert rc == 0
    assert captured_launch[0]["kernel"] == "./from-flag"


def test_initrd_profile_and_cmdline_come_from_config(captured_launch, tmp_path):
    cfg = _write_config(
        tmp_path,
        '[boot]\n'
        'kernel = "./bzImage"\n'
        'initrd = "./initramfs.cpio.gz"\n'
        'profile = "trigger-test"\n',
    )

    rc = cli.main(["launch", "--config", str(cfg), "--harness"])

    assert rc == 0
    assert captured_launch[0]["initrd"] == "./initramfs.cpio.gz"
    assert captured_launch[0]["profile"] == "trigger-test"


def test_missing_kernel_names_both_ways_to_supply_it(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    rc = cli.main(["launch", "--harness"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "--kernel" in err
    assert "[boot] kernel" in err


def test_vm_table_migration_hint_names_the_real_tables(tmp_path):
    cfg = _write_config(tmp_path, '[vm]\nkernel = "./bzImage"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    message = str(exc.value)
    assert "[boot]" in message and "[machine]" in message and "[drive]" in message


@pytest.mark.parametrize(
    "key,destination",
    [
        ("kernel", "[boot] kernel"),
        ("initrd", "[boot] initrd"),
        ("append", "[boot] cmdline"),
        ("profile", "[boot] profile"),
    ],
)
def test_misplaced_boot_keys_get_a_destination_hint(tmp_path, key, destination):
    cfg = _write_config(tmp_path, f'[machine]\n{key} = "x"\n')

    with pytest.raises(ConfigError) as exc:
        load_config_file(cfg)

    assert destination in str(exc.value)


# ---------------------------------------------------------------------------
# --append
# ---------------------------------------------------------------------------


def test_append_extends_the_profile_cmdline(captured_launch, tmp_path):
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./bzImage"\n')

    rc = cli.main(
        ["launch", "--config", str(cfg), "--harness", "--append", "slub_debug=- nokaslr"]
    )

    assert rc == 0
    assert captured_launch[0]["append"] == "slub_debug=- nokaslr"
    # --append must not be conflated with a full cmdline override.
    assert captured_launch[0]["cmdline"] is None


def test_append_extends_the_profile_and_keeps_root():
    """The point of --append: adding a param must not cost you root=."""
    config = QMUConfig()

    resolved = resolve_cmdline(config, profile="exploit-dev", append="slub_debug=-")

    assert "root=/dev/sda" in resolved
    assert resolved.endswith("slub_debug=-")


def test_append_also_extends_an_explicit_cmdline():
    config = QMUConfig()

    resolved = resolve_cmdline(
        config, cmdline="console=ttyS0 root=/dev/sda", append="nokaslr"
    )

    assert resolved == "console=ttyS0 root=/dev/sda nokaslr"


def test_cmdline_alone_still_replaces_the_profile():
    config = QMUConfig()

    resolved = resolve_cmdline(config, profile="exploit-dev", cmdline="console=ttyS0")

    assert resolved == "console=ttyS0"


def test_unknown_profile_lists_the_valid_ones():
    config = QMUConfig()

    with pytest.raises(QMUError) as exc:
        resolve_cmdline(config, profile="nope")

    assert "exploit-dev" in str(exc.value)


# ---------------------------------------------------------------------------
# --vm alias and the root= guard
# ---------------------------------------------------------------------------


def test_vm_is_accepted_as_an_alias_for_name(captured_launch, tmp_path):
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./bzImage"\n')

    rc = cli.main(["launch", "--config", str(cfg), "--harness", "--vm", "poc64556"])

    assert rc == 0
    assert captured_launch[0]["name"] == "poc64556"


def test_name_wins_when_both_are_given(captured_launch, tmp_path):
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./bzImage"\n')

    rc = cli.main(
        [
            "launch", "--config", str(cfg), "--harness",
            "--vm", "from-vm", "--name", "from-name",
        ]
    )

    assert rc == 0
    assert captured_launch[0]["name"] == "from-name"


def test_cmdline_without_root_warns_when_a_rootfs_is_attached(
    captured_launch, tmp_path, capsys
):
    cfg = _write_config(
        tmp_path,
        '[boot]\nkernel = "./bzImage"\n\n[drive]\nrootfs = "./rootfs.img"\n'
        '\n[ssh]\nkey = "./key"\n',
    )

    rc = cli.main(
        ["launch", "--config", str(cfg), "--no-wait-ssh",
         "--cmdline", "console=ttyS0 nokaslr"]
    )

    assert rc == 0
    assert "root=" in capsys.readouterr().err


def test_no_root_warning_when_the_cmdline_has_one(captured_launch, tmp_path, capsys):
    cfg = _write_config(
        tmp_path,
        '[boot]\nkernel = "./bzImage"\n\n[drive]\nrootfs = "./rootfs.img"\n'
        '\n[ssh]\nkey = "./key"\n',
    )

    rc = cli.main(
        ["launch", "--config", str(cfg), "--no-wait-ssh",
         "--cmdline", "console=ttyS0 root=/dev/sda rw"]
    )

    assert rc == 0
    assert "Warning" not in capsys.readouterr().err


def test_no_root_warning_in_harness_mode(captured_launch, tmp_path, capsys):
    """Harness VMs boot from an initramfs; a missing root= is correct there."""
    cfg = _write_config(tmp_path, '[boot]\nkernel = "./bzImage"\n')

    rc = cli.main(
        ["launch", "--config", str(cfg), "--harness", "--cmdline", "console=ttyS0"]
    )

    assert rc == 0
    assert "Warning" not in capsys.readouterr().err
