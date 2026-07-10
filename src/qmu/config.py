from __future__ import annotations

import platform
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .instance import QMUError
from .paths import global_config_path


CONFIG_FILENAME = "qmu.toml"

class ConfigError(QMUError):
    """A source-aware TOML parse or schema error."""

    def __init__(
        self,
        source: Path,
        problem: str,
        *,
        key_path: str | None = None,
        hint: str | None = None,
    ) -> None:
        self.source = Path(source).resolve()
        self.key_path = key_path
        self.problem = problem
        self.hint = hint
        message = f"Invalid config {self.source}"
        if key_path is not None:
            message += f": key '{key_path}'"
        message += f": {problem}"
        if hint is not None:
            message += f"; {hint}"
        super().__init__(message)


_FIXED_SCHEMA: dict[str, dict[str, str]] = {
    "machine": {
        "arch": "string",
        "memory": "string",
        "cpus": "integer",
        "cpu": "string",
        "nic_model": "string",
        "net_backend": "net_backend",
        "extra_args": "string_array",
    },
    "drive": {
        "rootfs": "string",
        "format": "string",
    },
    "ssh": {
        "key": "string",
        "user": "string",
        "port_start": "integer",
    },
    "gdb": {
        "port_start": "integer",
    },
}

_MIGRATION_DESTINATIONS: dict[str, tuple[str, ...]] = {
    "arch": ("[machine] arch",),
    "memory": ("[machine] memory",),
    "cpus": ("[machine] cpus",),
    "cpu": ("[machine] cpu",),
    "cpu_model": ("[machine] cpu",),
    "nic_model": ("[machine] nic_model",),
    "net_backend": ("[machine] net_backend",),
    "extra_args": ("[machine] extra_args",),
    "rootfs": ("[drive] rootfs",),
    "format": ("[drive] format",),
    "drive_format": ("[drive] format",),
    "key": ("[ssh] key",),
    "ssh_key": ("[ssh] key",),
    "user": ("[ssh] user",),
    "ssh_user": ("[ssh] user",),
    "port_start": ("[ssh] port_start", "[gdb] port_start"),
    "ssh_port_start": ("[ssh] port_start",),
    "gdb_port_start": ("[gdb] port_start",),
}


def _value_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if type(value) is int:
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "table"
    if isinstance(value, float):
        return "float"
    return type(value).__name__


def _migration_hint(key: str) -> str | None:
    destinations = _MIGRATION_DESTINATIONS.get(key)
    if destinations is None:
        return None
    quoted = [f"'{destination}'" for destination in destinations]
    if len(quoted) == 1:
        target = quoted[0]
    else:
        target = " or ".join(quoted)
    return f"move '{key}' to {target}"
def _validate_value(value: Any, kind: str, source: Path, key_path: str) -> None:
    if kind == "string":
        valid = isinstance(value, str)
        expected = "string"
    elif kind == "integer":
        valid = type(value) is int
        expected = "integer"
    elif kind == "string_array":
        if not isinstance(value, list):
            raise ConfigError(
                source,
                f"expected array of strings, got {_value_type_name(value)}",
                key_path=key_path,
            )
        for index, item in enumerate(value):
            if not isinstance(item, str):
                raise ConfigError(
                    source,
                    f"expected string, got {_value_type_name(item)}",
                    key_path=f"{key_path}[{index}]",
                )
        return
    elif kind == "net_backend":
        if not isinstance(value, str):
            raise ConfigError(
                source,
                f"expected string, got {_value_type_name(value)}",
                key_path=key_path,
            )
        if value not in ("user", "passt"):
            raise ConfigError(
                source,
                "expected one of: user, passt",
                key_path=key_path,
            )
        return
    else:
        raise AssertionError(f"unknown config schema kind: {kind}")

    if not valid:
        raise ConfigError(
            source,
            f"expected {expected}, got {_value_type_name(value)}",
            key_path=key_path,
        )


def _validate_profiles(profiles: dict[str, Any], source: Path) -> None:
    for name, profile in profiles.items():
        profile_path = f"profiles.{name}"
        if isinstance(profile, str):
            continue
        if not isinstance(profile, dict):
            raise ConfigError(
                source,
                f"expected string or table, got {_value_type_name(profile)}",
                key_path=profile_path,
            )
        for key, value in profile.items():
            key_path = f"{profile_path}.{key}"
            if key != "cmdline":
                raise ConfigError(source, "unknown key", key_path=key_path)
            _validate_value(value, "string", source, key_path)


def _validate_toml(raw: dict[str, Any], source: Path) -> None:
    for section, section_value in raw.items():
        if section not in (*_FIXED_SCHEMA, "profiles"):
            raise ConfigError(
                source,
                "unknown top-level key",
                key_path=section,
                hint=_migration_hint(section),
            )
        if not isinstance(section_value, dict):
            raise ConfigError(
                source,
                f"expected table, got {_value_type_name(section_value)}",
                key_path=section,
            )
        if section == "profiles":
            _validate_profiles(section_value, source)
            continue

        section_schema = _FIXED_SCHEMA[section]
        for key, value in section_value.items():
            key_path = f"{section}.{key}"
            kind = section_schema.get(key)
            if kind is None:
                raise ConfigError(
                    source,
                    "unknown key",
                    key_path=key_path,
                    hint=_migration_hint(key),
                )
            _validate_value(value, kind, source, key_path)


def load_config_file(path: Path) -> dict[str, Any]:
    """Parse and validate one TOML source before it can affect QMUConfig."""
    source = Path(path).resolve()
    try:
        with source.open("rb") as file:
            raw = tomllib.load(file)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(source, f"failed to parse TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(source, f"failed to read TOML: {exc}") from exc
    _validate_toml(raw, source)
    return raw


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
    cpu_model: str | None = None
    nic_model: str = "virtio-net-pci"
    net_backend: str = "user"  # "user" (slirp) or native "passt" when advertised by QEMU
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




def _apply_toml(cfg: QMUConfig, raw: dict[str, Any], source: str) -> None:
    """Apply a parsed TOML dict onto a QMUConfig, recording the source."""
    machine = raw.get("machine", {})
    if "arch" in machine:
        cfg.arch = machine["arch"]
    if "memory" in machine:
        cfg.memory = machine["memory"]
    if "cpus" in machine:
        cfg.cpus = int(machine["cpus"])
    if "cpu" in machine:
        cfg.cpu_model = machine["cpu"]
    if "nic_model" in machine:
        cfg.nic_model = machine["nic_model"]
    if "net_backend" in machine:
        backend = str(machine["net_backend"])
        if backend not in ("user", "passt"):
            raise QMUError(
                f"Invalid net_backend '{backend}': must be 'user' or 'passt'"
            )
        cfg.net_backend = backend
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


def _apply_config_file(
    cfg: QMUConfig,
    path: Path,
    source_kind: str,
) -> None:
    source = Path(path).resolve()
    raw = load_config_file(source)
    _apply_toml(cfg, raw, f"{source_kind}: {source}")


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

    # Layer 1: global config — non-fatal, but never silently ignored.
    # A broken global config warns and is skipped so a single stale
    # `~/.config/qmu/config.toml` never bricks every command (including
    # `doctor`, whose job is to diagnose it). Validation happens inside
    # load_config_file before any mutation, so a rejected layer leaves cfg
    # untouched. Project/explicit configs below stay fatal.
    gpath = global_config_path().resolve()
    if gpath.is_file():
        try:
            _apply_config_file(cfg, gpath, "global")
        except ConfigError as exc:
            sys.stderr.write(f"[qmu] Warning: ignoring global config: {exc}\n")

    # Layer 2: project config (or explicit --config)
    if config_path_override is not None:
        ppath = Path(config_path_override).resolve()
        if ppath.is_file():
            _apply_config_file(cfg, ppath, "config")
    else:
        ppath = find_project_config()
        if ppath is not None:
            _apply_config_file(cfg, ppath, "project")

    # Layer 3: CLI overrides
    if cli_overrides:
        _apply_cli(cfg, cli_overrides)
        cfg._sources.append("CLI flags")

    return cfg


def render_starter_config(arch: str | None = None) -> str:
    """Build a starter qmu.toml tailored to the host arch."""
    host_arch = arch or platform.machine()
    if host_arch == "aarch64":
        machine_extras = '\nextra_args = ["-M", "virt", "-cpu", "cortex-a57"]'
        alt_arch_hint = '# arch = "x86_64"  # set this if cross-emulating'
    else:
        host_arch = "x86_64"
        machine_extras = '# extra_args = ["-M", "virt", "-cpu", "cortex-a57"]  # for aarch64'
        alt_arch_hint = '# arch = "aarch64"  # set this if cross-emulating'

    return f"""\
# qmu.toml — QEMU VM configuration for qmu CLI
#
# Quick start:
#   1. Edit the two `# CHANGE ME` lines below to point at your rootfs image
#      and SSH private key.
#   2. Run `qmu doctor` to verify everything resolves.
#   3. Run `qmu launch --kernel /path/to/bzImage`.
#
# For boot-and-die kernels (kernelCTF, syzkaller reproducers) you do not need
# a rootfs or SSH key — see the harness-mode block at the bottom of this file.
#
# See `qmu config show` for the full resolved config.

[machine]
arch = "{host_arch}"
{alt_arch_hint}
memory = "4G"
cpus = 2
# cpu = "host"                   # passes -cpu to QEMU; "host" is recommended with KVM
# nic_model = "virtio-net-pci"   # or "e1000", "rtl8139", ...
# net_backend = "passt"          # Optional migration-compatible backend. The selected
#                                #   QEMU must advertise native passt; qmu probes whether it
#                                #   advertises native passt (documented since QEMU 10.1 but
#                                #   build-optional), and `passt` must be on PATH. Default
#                                #   user/slirp often restores successfully.
#                                #   Switch only if loadvm reports slirp/footer errors.
#                                #   A manually managed external passt + QEMU stream setup
#                                #   is outside qmu process management; qmu does not manage
#                                #   that external process.
{machine_extras}

[drive]
rootfs = "./rootfs.img"          # CHANGE ME — path to a kernel rootfs image
format = "raw"                   # "raw" or "qcow2" base. qmu attaches this configured
                                 #   rootfs through a temporary snapshot=on overlay, so
                                 #   raw or qcow2 can support in-session savevm/loadvm;
                                 #   checkpoints disappear when QEMU exits. For durable
                                 #   internal snapshots, attach a writable qcow2 drive
                                 #   without snapshot=on, e.g. launch with:
                                 #   --drive 'file=./rootfs.qcow2,format=qcow2'
                                 #   Changing [drive] format alone remains temporary.

[ssh]
key = "~/.ssh/qmu_id_rsa"        # CHANGE ME — private key matching the rootfs
user = "root"
# port_start = 10021

[gdb]
# port_start = 1234

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"

[profiles.trigger-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"

[profiles.exploit-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_oops=1 kasan.fault=panic"

# ---------------------------------------------------------------------------
# Harness mode (boot-and-die kernels)
# ---------------------------------------------------------------------------
# If your kernel boots from a kernel + initramfs + read-only rootfs, runs a
# one-shot init script, and halts (kernelCTF judge envs, syzkaller repros),
# you don't need [drive] or [ssh] above. Delete those sections and launch with:
#
#   qmu launch --harness \\
#     --kernel ./bzImage --initrd ./ramdisk.img \\
#     --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \\
#     --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'
"""
