"""Unit tests for build_qemu_command — pure function, no qemu execution."""

from __future__ import annotations

from qmu.config import QMUConfig
from qmu.vm import build_qemu_command


def _base_config() -> QMUConfig:
    cfg = QMUConfig()
    cfg.arch = "x86_64"
    cfg.memory = "4G"
    cfg.cpus = 2
    return cfg


def _kwargs(**over):
    base = dict(
        config=_base_config(),
        kernel="/k/bzImage",
        rootfs="/r/rootfs.img",
        ssh_port=10022,
        gdb_port=None,
        qmp_socket="/sock/qmp",
        serial_log="/log/serial.log",
        cmdline="console=ttyS0",
    )
    base.update(over)
    return base


def test_default_invocation_unchanged():
    cmd = build_qemu_command(**_kwargs())
    # Hostfwd present
    assert any("hostfwd=tcp:127.0.0.1:10022-:22" in a for a in cmd)
    # Implicit rootfs drive present
    assert any("file=/r/rootfs.img" in a for a in cmd)
    # NIC model defaults to virtio-net-pci
    assert any(a == "nic,model=virtio-net-pci" for a in cmd)
    # No initrd
    assert "-initrd" not in cmd


def test_initrd_added():
    cmd = build_qemu_command(**_kwargs(initrd="/boot/initrd.img"))
    assert "-initrd" in cmd
    i = cmd.index("-initrd")
    assert cmd[i + 1] == "/boot/initrd.img"


def test_drive_overrides_implicit_rootfs():
    cmd = build_qemu_command(
        **_kwargs(
            drives=[
                "file=/a.img,if=virtio,readonly,format=raw",
                "file=/b.img,if=virtio,readonly,format=raw",
            ]
        )
    )
    drive_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-drive"]
    # Two custom drives, implicit rootfs not present.
    assert drive_args == [
        "file=/a.img,if=virtio,readonly,format=raw",
        "file=/b.img,if=virtio,readonly,format=raw",
    ]
    # The implicit "file=/r/rootfs.img,..." line must be absent.
    assert not any("/r/rootfs.img" in a for a in cmd)


def test_no_net_emits_nic_none():
    cmd = build_qemu_command(**_kwargs(no_net=True, ssh_port=None))
    assert "-nic" in cmd
    i = cmd.index("-nic")
    assert cmd[i + 1] == "none"
    # No -net flags, no hostfwd
    assert "-net" not in cmd
    assert not any("hostfwd" in a for a in cmd)


def test_harness_style_no_ssh_no_net():
    """Harness-mode equivalent: no rootfs, no ssh_port, no_net=True, with initrd + drives."""
    cmd = build_qemu_command(
        **_kwargs(
            rootfs=None,
            ssh_port=None,
            initrd="/boot/initramfs.img",
            drives=["file=/r.img,if=virtio,readonly,format=raw"],
            no_net=True,
        )
    )
    assert "-initrd" in cmd
    assert "-nic" in cmd and cmd[cmd.index("-nic") + 1] == "none"
    assert not any("hostfwd" in a for a in cmd)
    drive_args = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-drive"]
    assert drive_args == ["file=/r.img,if=virtio,readonly,format=raw"]


def test_nic_model_override_propagates():
    cmd = build_qemu_command(**_kwargs(nic_model="e1000"))
    assert any(a == "nic,model=e1000" for a in cmd)
    assert not any(a == "nic,model=virtio-net-pci" for a in cmd)


def test_nic_model_from_config():
    cfg = _base_config()
    cfg.nic_model = "rtl8139"
    cmd = build_qemu_command(**_kwargs(config=cfg))
    assert any(a == "nic,model=rtl8139" for a in cmd)


def test_ssh_port_none_without_no_net_uses_nic_user():
    """Edge case: --no-wait-ssh without --no-net (harness=False, ssh_port=None)."""
    cmd = build_qemu_command(**_kwargs(ssh_port=None, no_net=False))
    assert "-nic" in cmd
    i = cmd.index("-nic")
    assert cmd[i + 1].startswith("user,model=")
    assert not any("hostfwd" in a for a in cmd)
