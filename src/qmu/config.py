from __future__ import annotations

import platform
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .paths import global_config_path


CONFIG_FILENAME = "qmu.toml"


# Built-in boot profiles — used when no profiles defined in config
DEFAULT_PROFILES: dict[str, str] = {
    "exploit-dev": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 kasan.fault=panic"
    ),
    "trigger-test": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"
    ),
    "exploit-test": (
        "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
        " selinux=0 apparmor=0 panic_on_oops=1 kasan.fault=panic"
    ),
}


@dataclass
class QMUConfig:
    # machine
    arch: str = "x86_64"
    memory: str = "4G"
    cpus: int = 2
    extra_args: list[str] = field(default_factory=list)

    # drive
    rootfs: str | None = None
    drive_format: str = "raw"

    # ssh
    ssh_key: str | None = None
    ssh_user: str = "root"
    ssh_port_start: int = 10021

    # gdb
    gdb_port_start: int = 1234

    # profiles (name -> cmdline)
    profiles: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PROFILES))

    # tracking: which config files contributed
    _sources: list[str] = field(default_factory=list, repr=False)

    def qemu_binary(self) -> str:
        return f"qemu-system-{self.arch}"

    def use_kvm(self) -> bool:
        """Enable KVM only when guest arch matches host."""
        host = platform.machine()
        mapping = {"x86_64": "x86_64", "aarch64": "aarch64"}
        return mapping.get(self.arch) == host and Path("/dev/kvm").exists()


def find_project_config(start: Path | None = None) -> Path | None:
    """Walk up from `start` (default: CWD) looking for qmu.toml."""
    current = (start or Path.cwd()).resolve()
    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            return None
        current = parent


def load_config_file(path: Path) -> dict[str, Any]:
    """Parse a TOML config file into a flat dict."""
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    return raw


def _apply_toml(cfg: QMUConfig, raw: dict[str, Any], source: str) -> None:
    """Apply a parsed TOML dict onto a QMUConfig, recording the source."""
    machine = raw.get("machine", {})
    if "arch" in machine:
        cfg.arch = machine["arch"]
    if "memory" in machine:
        cfg.memory = machine["memory"]
    if "cpus" in machine:
        cfg.cpus = int(machine["cpus"])
    if "extra_args" in machine:
        cfg.extra_args = list(machine["extra_args"])

    drive = raw.get("drive", {})
    if "rootfs" in drive:
        cfg.rootfs = drive["rootfs"]
    if "format" in drive:
        cfg.drive_format = drive["format"]

    ssh = raw.get("ssh", {})
    if "key" in ssh:
        cfg.ssh_key = ssh["key"]
    if "user" in ssh:
        cfg.ssh_user = ssh["user"]
    if "port_start" in ssh:
        cfg.ssh_port_start = int(ssh["port_start"])

    gdb = raw.get("gdb", {})
    if "port_start" in gdb:
        cfg.gdb_port_start = int(gdb["port_start"])

    profiles = raw.get("profiles", {})
    if profiles:
        # Config profiles extend/override defaults
        for name, prof in profiles.items():
            if isinstance(prof, dict) and "cmdline" in prof:
                cfg.profiles[name] = prof["cmdline"]
            elif isinstance(prof, str):
                cfg.profiles[name] = prof

    cfg._sources.append(source)


def _apply_cli(cfg: QMUConfig, overrides: dict[str, Any]) -> None:
    """Apply CLI flag overrides onto a QMUConfig. Only non-None values override."""
    for key, value in overrides.items():
        if value is None:
            continue
        if hasattr(cfg, key):
            setattr(cfg, key, value)


def resolve_config(
    cli_overrides: dict[str, Any] | None = None,
    config_path_override: Path | None = None,
) -> QMUConfig:
    """Build a QMUConfig by layering: defaults < global < project < CLI.

    Args:
        cli_overrides: Dict of CLI flag values (None means "use config default").
        config_path_override: Explicit config file path (--config flag).
    """
    cfg = QMUConfig()
    cfg._sources.append("built-in defaults")

    # Layer 1: global config
    gpath = global_config_path()
    if gpath.is_file():
        try:
            raw = load_config_file(gpath)
            _apply_toml(cfg, raw, f"global: {gpath}")
        except Exception:
            pass  # Skip broken global config

    # Layer 2: project config (or explicit --config)
    if config_path_override is not None:
        ppath = Path(config_path_override).resolve()
        if ppath.is_file():
            raw = load_config_file(ppath)
            _apply_toml(cfg, raw, f"config: {ppath}")
    else:
        ppath = find_project_config()
        if ppath is not None:
            raw = load_config_file(ppath)
            _apply_toml(cfg, raw, f"project: {ppath}")

    # Layer 3: CLI overrides
    if cli_overrides:
        _apply_cli(cfg, cli_overrides)
        cfg._sources.append("CLI flags")

    return cfg


STARTER_CONFIG = """\
# qmu.toml — QEMU VM configuration for qmu CLI
# See: qmu config show

[machine]
arch = "x86_64"
memory = "4G"
cpus = 2
# extra_args = ["-M", "virt", "-cpu", "cortex-a57"]  # e.g. for aarch64

[drive]
# rootfs = "/path/to/rootfs.img"
# format = "raw"

[ssh]
# key = "/path/to/ssh.id_rsa"
# user = "root"
# port_start = 10021

[gdb]
# port_start = 1234

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"

[profiles.trigger-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"

[profiles.exploit-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_oops=1 kasan.fault=panic"
"""
