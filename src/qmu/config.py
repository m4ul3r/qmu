from __future__ import annotations

import platform
import tomllib
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass, field
from difflib import get_close_matches
from pathlib import Path
from typing import Any

from .instance import QMUError
from .paths import global_config_path


CONFIG_FILENAME = "qmu.toml"

class ConfigError(QMUError):
    """A source-aware TOML parse or schema error.

    One validation pass collects every problem in a file; the first is the
    error's own `key_path`/`problem`/`hint` (so the leading message line is
    the same as it always was) and the rest ride in `more`. The rendered
    message is one `Invalid config <path>: ...` line per problem, then the
    recovery paragraph; `envelope_fields()` is the JSON counterpart.
    """

    def __init__(
        self,
        source: Path,
        problem: str,
        *,
        key_path: str | None = None,
        hint: str | None = None,
        recovery: str | None = None,
        more: Iterable[ConfigError] = (),
    ) -> None:
        self.source = Path(source).resolve()
        self.key_path = key_path
        self.problem = problem
        self.hint = hint
        self.recovery = recovery
        self.more = tuple(more)
        lines = [self._render_line(self)]
        lines.extend(self._render_line(extra) for extra in self.more)
        if recovery is not None:
            lines.append(recovery)
        super().__init__("\n".join(lines))

    @staticmethod
    def _render_line(err: ConfigError) -> str:
        return f"Invalid config {err.source}: {err._own_problem()}"

    def _own_problem(self) -> str:
        text = f"key '{self.key_path}': {self.problem}" if self.key_path else self.problem
        if self.hint is not None:
            text += f"; {self.hint}"
        return text

    def describe_problem(self) -> str:
        """The fault without the `Invalid config <path>` prefix.

        For renderers that already name the file themselves — `doctor`'s
        skipped-global row — so the path is not printed twice. Additional
        problems from the same pass are appended, ` | `-separated.
        """
        return " | ".join(err._own_problem() for err in self.problems())

    def problems(self) -> list[ConfigError]:
        """Every problem of the pass, this one first."""
        return [self, *self.more]

    def envelope_fields(self) -> dict[str, Any]:
        """Structured fields merged into the `{"ok": false, ...}` envelope.

        `source`/`key`/`hint` describe the first problem (mirroring the
        leading message line); `errors` lists every problem of the pass so a
        caller fixes a file in one round trip instead of one key per run.
        """
        return {
            "source": str(self.source),
            "key": self.key_path,
            "hint": self.hint,
            "errors": [
                {
                    "source": str(err.source),
                    "key": err.key_path,
                    "message": err.problem,
                    "hint": err.hint,
                }
                for err in self.problems()
            ],
        }


_FIXED_SCHEMA: dict[str, dict[str, str]] = {
    "boot": {
        "kernel": "string",
        "initrd": "string",
        "cmdline": "string",
        "profile": "string",
    },
    "machine": {
        "arch": "string",
        "memory": "string",
        "cpus": "integer",
        "cpu": "string",
        "nic_model": "string",
        "net_backend": "net_backend",
        "accel": "accel",
        "no_reboot": "boolean",
        "forwards": "forward_array",
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
    "daemon": {
        "autostart": "boolean",
        "idle_exit": "integer",
    },
}

# QMUConfig path fields -> the TOML key that sets them, for provenance text.
_PATH_FIELD_KEYS: dict[str, str] = {
    "kernel": "[boot] kernel",
    "initrd": "[boot] initrd",
    "rootfs": "[drive] rootfs",
    "ssh_key": "[ssh] key",
}

# QMUConfig field -> dotted TOML key, for per-key provenance (`config show`).
# Order is the display order of the resolved config.
_FIELD_TOML_KEYS: dict[str, str] = {
    "kernel": "boot.kernel",
    "initrd": "boot.initrd",
    "cmdline": "boot.cmdline",
    "profile": "boot.profile",
    "arch": "machine.arch",
    "memory": "machine.memory",
    "cpus": "machine.cpus",
    "cpu_model": "machine.cpu",
    "nic_model": "machine.nic_model",
    "net_backend": "machine.net_backend",
    "accel": "machine.accel",
    "no_reboot": "machine.no_reboot",
    "forwards": "machine.forwards",
    "extra_args": "machine.extra_args",
    "rootfs": "drive.rootfs",
    "drive_format": "drive.format",
    "ssh_key": "ssh.key",
    "ssh_user": "ssh.user",
    "ssh_port_start": "ssh.port_start",
    "gdb_port_start": "gdb.port_start",
    "daemon_autostart": "daemon.autostart",
    "daemon_idle_exit": "daemon.idle_exit",
}


def _layer_label(source: str) -> str:
    """`_sources` entry -> short layer label (`global <path>`, `project
    <path>`, `--config <path>`, `flag`, `built-in`)."""
    kind, sep, path = source.partition(": ")
    if not sep:
        return "flag" if source == "CLI flags" else "built-in"
    if kind == "config":
        return f"--config {path}"
    return f"{kind} {path}"


_MIGRATION_DESTINATIONS: dict[str, tuple[str, ...]] = {
    # A `[vm]` table is the most common wrong guess: it reads like the obvious
    # name for "the machine I am booting", but qmu splits those keys across
    # three tables. Name all three so the fix needs no second lookup.
    "vm": ("[boot]", "[machine]", "[drive]"),
    "kernel": ("[boot] kernel",),
    "initrd": ("[boot] initrd",),
    "cmdline": ("[boot] cmdline",),
    "append": ("[boot] cmdline",),
    "profile": ("[boot] profile",),
    "arch": ("[machine] arch",),
    "memory": ("[machine] memory",),
    "cpus": ("[machine] cpus",),
    "cpu": ("[machine] cpu",),
    "cpu_model": ("[machine] cpu",),
    "nic_model": ("[machine] nic_model",),
    "net_backend": ("[machine] net_backend",),
    "accel": ("[machine] accel",),
    "no_kvm": ("[machine] accel",),
    "no_reboot": ("[machine] no_reboot",),
    "no-reboot": ("[machine] no_reboot",),
    "noreboot": ("[machine] no_reboot",),
    "forward": ("[machine] forwards",),
    "forwards": ("[machine] forwards",),
    "hostfwd": ("[machine] forwards",),
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


def _did_you_mean(key: str, candidates: Iterable[str]) -> str | None:
    """Suggest the closest schema key for a probable typo."""
    matches = get_close_matches(key, list(candidates), n=1, cutoff=0.7)
    return matches[0] if matches else None


def _migration_hint(key: str, *, is_table: bool = False) -> str | None:
    destinations = _MIGRATION_DESTINATIONS.get(key)
    if destinations is None:
        return None
    quoted = [f"'{destination}'" for destination in destinations]
    if len(quoted) == 1:
        target = quoted[0]
    else:
        target = " or ".join(quoted)
    if is_table:
        # A misplaced *table* has no single home — its keys scatter across the
        # named tables — so "move 'vm' to '[boot]'" would misdescribe the fix.
        return f"the keys of '[{key}]' belong in {target}"
    return f"move '{key}' to {target}"


FORWARD_SPEC_HINT = (
    "use [HOST:]HPORT:GPORT (e.g. '2345:2345', '0.0.0.0:8080:80'), or a bare "
    "GPORT to auto-allocate the host port"
)


def parse_forward_spec(spec: str) -> dict[str, Any]:
    """`[HOST:]HPORT:GPORT` or `GPORT` -> {host, host_port, guest_port}.

    `host_port` is None for a bare GPORT: `launch` allocates one. HOST
    defaults to 127.0.0.1, the address qmu binds its SSH forward on, so a
    forward is not exposed beyond the host unless the caller names an
    address. Raises ValueError naming what is wrong with `spec`.
    """
    parts = spec.strip().split(":")
    if len(parts) == 1:
        host, hport, gport = "127.0.0.1", None, parts[0]
    elif len(parts) == 2:
        host, (hport, gport) = "127.0.0.1", parts
    elif len(parts) == 3:
        host, hport, gport = parts
        if not host:
            raise ValueError(f"forward {spec!r}: empty HOST")
    else:
        raise ValueError(f"forward {spec!r}: expected [HOST:]HPORT:GPORT or GPORT")

    def port(text: str, what: str) -> int:
        if not text.isdigit() or not 1 <= int(text) <= 65535:
            raise ValueError(f"forward {spec!r}: {what} {text!r} is not a port (1-65535)")
        return int(text)

    return {
        "host": host,
        "host_port": None if hport is None else port(hport, "HPORT"),
        "guest_port": port(gport, "GPORT"),
    }


def _validate_value(
    value: Any, kind: str, source: Path, key_path: str, problems: list[ConfigError]
) -> None:
    """Append a ConfigError to `problems` when `value` is not of `kind`."""
    if kind == "string":
        valid = isinstance(value, str)
        expected = "string"
    elif kind == "integer":
        valid = type(value) is int
        expected = "integer"
    elif kind == "boolean":
        valid = isinstance(value, bool)
        expected = "boolean (true/false)"
    elif kind == "string_array":
        if not isinstance(value, list):
            problems.append(ConfigError(
                source,
                f"expected array of strings, got {_value_type_name(value)}",
                key_path=key_path,
            ))
            return
        for index, item in enumerate(value):
            if not isinstance(item, str):
                problems.append(ConfigError(
                    source,
                    f"expected string, got {_value_type_name(item)}",
                    key_path=f"{key_path}[{index}]",
                ))
        return
    elif kind == "forward_array":
        if not isinstance(value, list):
            problems.append(ConfigError(
                source,
                f"expected array of strings, got {_value_type_name(value)}",
                key_path=key_path,
            ))
            return
        for index, item in enumerate(value):
            if not isinstance(item, str):
                problems.append(ConfigError(
                    source,
                    f"expected string, got {_value_type_name(item)}",
                    key_path=f"{key_path}[{index}]",
                ))
                continue
            try:
                parse_forward_spec(item)
            except ValueError as exc:
                problems.append(ConfigError(
                    source,
                    str(exc),
                    key_path=f"{key_path}[{index}]",
                    hint=FORWARD_SPEC_HINT,
                ))
        return
    elif kind == "net_backend":
        if not isinstance(value, str):
            problems.append(ConfigError(
                source,
                f"expected string, got {_value_type_name(value)}",
                key_path=key_path,
            ))
        elif value not in ("user", "passt"):
            problems.append(ConfigError(
                source,
                "expected one of: user, passt",
                key_path=key_path,
            ))
        return
    elif kind == "accel":
        if not isinstance(value, str):
            problems.append(ConfigError(
                source,
                f"expected string, got {_value_type_name(value)}",
                key_path=key_path,
            ))
        elif value not in ("auto", "kvm", "tcg"):
            problems.append(ConfigError(
                source,
                "expected one of: auto, kvm, tcg",
                key_path=key_path,
            ))
        return
    else:
        raise AssertionError(f"unknown config schema kind: {kind}")

    if not valid:
        problems.append(ConfigError(
            source,
            f"expected {expected}, got {_value_type_name(value)}",
            key_path=key_path,
        ))


def _validate_profiles(
    profiles: dict[str, Any], source: Path, problems: list[ConfigError]
) -> None:
    for name, profile in profiles.items():
        profile_path = f"profiles.{name}"
        if isinstance(profile, str):
            continue
        if not isinstance(profile, dict):
            problems.append(ConfigError(
                source,
                f"expected string or table, got {_value_type_name(profile)}",
                key_path=profile_path,
            ))
            continue
        for key, value in profile.items():
            key_path = f"{profile_path}.{key}"
            if key != "cmdline":
                problems.append(ConfigError(source, "unknown key", key_path=key_path))
                continue
            _validate_value(value, "string", source, key_path, problems)


def _validate_toml(raw: dict[str, Any], source: Path) -> None:
    """Check `raw` against the schema; raise ONE ConfigError carrying every
    problem found. Stopping at the first key sent a three-typo file through
    three fix-and-rerun round trips, each reporting the next key."""
    problems: list[ConfigError] = []
    for section, section_value in raw.items():
        if section not in (*_FIXED_SCHEMA, "profiles"):
            hint = _migration_hint(section, is_table=True)
            if hint is None:
                near = _did_you_mean(section, (*_FIXED_SCHEMA, "profiles"))
                if near is not None:
                    hint = f"did you mean '[{near}]'?"
            problems.append(ConfigError(
                source,
                "unknown top-level key",
                key_path=section,
                hint=hint,
            ))
            continue
        if not isinstance(section_value, dict):
            problems.append(ConfigError(
                source,
                f"expected table, got {_value_type_name(section_value)}",
                key_path=section,
            ))
            continue
        if section == "profiles":
            _validate_profiles(section_value, source, problems)
            continue

        section_schema = _FIXED_SCHEMA[section]
        for key, value in section_value.items():
            key_path = f"{section}.{key}"
            kind = section_schema.get(key)
            if kind is None:
                hint = _migration_hint(key)
                if hint is None:
                    near = _did_you_mean(key, section_schema)
                    if near is not None:
                        hint = f"did you mean '{near}'?"
                    else:
                        valid = ", ".join(sorted(section_schema))
                        hint = f"valid keys for [{section}]: {valid}"
                problems.append(ConfigError(
                    source,
                    "unknown key",
                    key_path=key_path,
                    hint=hint,
                ))
                continue
            _validate_value(value, kind, source, key_path, problems)

    if problems:
        first, *rest = problems
        raise ConfigError(
            source,
            first.problem,
            key_path=first.key_path,
            hint=first.hint,
            more=rest,
        )


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
        " selinux=0 apparmor=0 oops=panic kasan.fault=panic"
    ),
    # --- distro-target profiles (tools/mktarget.sh) -----------------------
    #
    # These deliberately do NOT carry `selinux=0 apparmor=0`. On a distro
    # target AppArmor *is* part of what is being measured — Ubuntu builds with
    # CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor" and ships an
    # `unprivileged_userns` profile in enforce mode that decides whether an
    # unprivileged user namespace can be created at all. Disabling the LSM
    # stack silently flips that primitive, and most modern LPEs open with it.
    # They also omit `kasan.fault=panic`, which is inert and misleading on a
    # distro kernel (no KASAN).
    #
    # `ubuntu-target` is the only one of these under which a claim like "this
    # PoC works on Ubuntu 24.04" is valid: KASLR on, LSMs on, sysctls at the
    # distro defaults.
    "ubuntu-target": (
        "console=ttyS0 root=/dev/sda rw earlyprintk=serial net.ifnames=0"
    ),
    # Reversing/GDB only. nokaslr makes symbols stable; an exploit that works
    # here is NOT an exploit on Ubuntu, since KASLR bypass is a separate proof
    # obligation.
    "ubuntu-debug": (
        "console=ttyS0 root=/dev/sda rw earlyprintk=serial net.ifnames=0 nokaslr"
    ),
    # Triage: KASLR and the LSM stack left alone, but panic on the first
    # oops/warn so `qmu crash` yields one clean report.
    "ubuntu-trigger": (
        "console=ttyS0 root=/dev/sda rw earlyprintk=serial net.ifnames=0"
        " panic_on_oops=1 panic_on_warn=1"
    ),
}


@dataclass
class QMUConfig:
    # boot — the launch recipe. Configurable so a project's qmu.toml can
    # describe a whole boot and `qmu launch` needs no repeated flags.
    kernel: str | None = None
    initrd: str | None = None
    cmdline: str | None = None
    profile: str = "exploit-dev"

    # machine
    arch: str = "x86_64"
    memory: str = "4G"
    cpus: int = 2
    cpu_model: str | None = None
    nic_model: str = "virtio-net-pci"
    net_backend: str = "user"  # "user" (slirp) or native "passt" when advertised by QEMU
    # Acceleration selection: "auto" (KVM when guest arch == host arch and
    # /dev/kvm exists), "kvm" (force -enable-kvm — the operator's explicit
    # choice; QEMU errors if unavailable), or "tcg" (pure emulation, no
    # -enable-kvm). The TCG escape hatch is a retest lever for hardware-
    # watchpoint issues under KVM (#39): a watchpoint that "misses" is usually
    # watching the wrong VA (a heap/physmap alias), but some QEMU/KVM builds do
    # drop gdbstub watchpoints and --no-kvm isolates that. (Live-tested: on
    # qemu 8.2.2 + KVM a jiffies watchpoint fired fine — KVM alone is not the
    # cause.)
    accel: str = "auto"
    # -no-reboot: a panic under `panic=N` exits QEMU instead of rebooting into
    # a fresh boot that buries the report. The one launch flag that had no
    # config key (#76); boot-and-die projects set it once here.
    no_reboot: bool = False
    # Extra host->guest TCP forwards on qmu's own NIC (#149), as written:
    # `[HOST:]HPORT:GPORT`, or a bare `GPORT` for an auto-allocated host port.
    # `--forward` (repeatable) replaces the list, like every launch flag.
    forwards: list[str] = field(default_factory=list)
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

    # daemon (#70): the per-user supervisor that owns QMP connections. The
    # client spawns it on demand unless `autostart` is false (QMU_DAEMON=off
    # disables the whole layer per process); it exits after `idle_exit`
    # seconds with no running VM and no client (0 = never).
    daemon_autostart: bool = True
    daemon_idle_exit: int = 600

    # profiles (name -> cmdline)
    profiles: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PROFILES))

    # tracking: which config files contributed
    _sources: list[str] = field(default_factory=list, repr=False)

    # tracking: which config files EXISTED and were rejected. A layer that was
    # found and skipped is not an absent layer, and only `_sources` recorded
    # the difference before — so `doctor` reported "No qmu.toml or
    # ~/.config/qmu/config.toml found. Run: qmu config init" for a broken
    # global its own stderr warning had just named, prescribing an action
    # (write a PROJECT file) that leaves the broken global in place forever.
    # Kept out of `_sources` so its consumers (`config show`'s source chain,
    # doctor's loaded-file check) keep meaning "contributed values".
    _skipped_sources: list[dict[str, str]] = field(default_factory=list, repr=False)

    # tracking: which layer set each path-typed field (`kernel`, `initrd`,
    # `rootfs`, `ssh_key`) — the TOML key and file for a config layer, absent
    # for a CLI flag. Config files are discovered by walking UP from CWD, so a
    # relative value is anchored at the file that set it (see `_anchor_path`)
    # and a not-found error names both the resolved path and that file; the
    # bare relative string the user never typed in this directory was the
    # whole of `Kernel not found: ./bzImage` before.
    _path_sources: dict[str, str] = field(default_factory=dict, repr=False)

    # tracking: the path string as WRITTEN in the config file, before
    # anchoring, so a report can say `./bzImage` (what the user must edit)
    # alongside the absolute file it resolved to.
    _written_paths: dict[str, str] = field(default_factory=dict, repr=False)

    def written_path(self, field_name: str) -> str | None:
        """The path as typed in its config file, or the value itself for a
        flag / unset field."""
        return self._written_paths.get(field_name, getattr(self, field_name))

    def describe_path_source(self, field_name: str) -> str:
        """Suffix naming where a path field came from, or '' for a CLI flag."""
        source = self._path_sources.get(field_name)
        if source is None:
            return ""
        return f" (from {_PATH_FIELD_KEYS[field_name]} in {source})"

    # tracking: which layer set EVERY field, keyed by QMUConfig field name
    # (`profiles.<name>` for a profile cmdline). Values are the same source
    # strings as `_sources` ("global: <path>", "project: <path>",
    # "config: <path>", "CLI flags"); a field nobody set is absent and means
    # built-in. `_path_sources` above is the path-only subset vm.py's
    # not-found errors read; this is the superset `config show` renders, so a
    # starter `[ssh] key` shadowing a global one is visible per key.
    _field_sources: dict[str, str] = field(default_factory=dict, repr=False)

    def source_layer(self, field_name: str) -> str:
        """Short layer label for a field: `built-in`, `global <path>`,
        `project <path>`, `--config <path>` or `flag`."""
        source = self._field_sources.get(field_name)
        if source is None:
            return "built-in"
        return _layer_label(source)

    def source_layers(self) -> dict[str, str]:
        """TOML dotted key -> layer label, for every configurable key."""
        layers = {
            toml_key: self.source_layer(field_name)
            for field_name, toml_key in _FIELD_TOML_KEYS.items()
        }
        for name in self.profiles:
            layers[f"profiles.{name}"] = self.source_layer(f"profiles.{name}")
        return layers

    def qemu_binary(self) -> str:
        return f"qemu-system-{self.arch}"

    def use_kvm(self) -> bool:
        """Whether QEMU should be launched with -enable-kvm.

        `accel` gates the automatic decision:
        - "tcg": never — the operator asked for pure emulation (e.g. to make
          gdbstub hardware watchpoints deliver, see #39).
        - "kvm": always — the operator's explicit choice; if /dev/kvm is
          missing or the arch does not match, QEMU itself will refuse, which
          is the correct place for that failure to surface.
        - "auto" (default): only when the guest arch matches the host and
          /dev/kvm exists — the historical behavior.
        """
        if self.accel == "tcg":
            return False
        if self.accel == "kvm":
            return True
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




def _anchor_path(value: str, base_dir: Path | None) -> str:
    """Resolve a relative config path against the directory of its file.

    `~` expands first so a home-relative value stays absolute. Only the
    anchoring is done here — no `resolve()` — so symlinks and non-existent
    files are reported as written, just rooted where the file lives.
    """
    expanded = Path(value).expanduser()
    if base_dir is None or expanded.is_absolute():
        return str(expanded)
    return str(base_dir / expanded)


_PATH_FIELDS = frozenset(_PATH_FIELD_KEYS)


def _set_field(cfg: QMUConfig, field_name: str, value: Any, source: str) -> None:
    """Set one field and record the layer that set it."""
    setattr(cfg, field_name, value)
    cfg._field_sources[field_name] = source
    if field_name in _PATH_FIELDS:
        cfg._path_sources[field_name] = source


def _apply_toml(
    cfg: QMUConfig,
    raw: dict[str, Any],
    source: str,
    *,
    base_dir: Path | None = None,
) -> None:
    """Apply a parsed TOML dict onto a QMUConfig, recording the source.

    `base_dir` is the directory of the file `raw` came from: path-typed
    values are anchored there, because the file is found by walking up from
    CWD and `./bzImage` next to it must mean the same file from any subdir.
    `raw` has already passed `_validate_toml`, so values are type-correct.
    """
    for field_name, toml_key in _FIELD_TOML_KEYS.items():
        section, key = toml_key.split(".", 1)
        table = raw.get(section, {})
        if key not in table:
            continue
        value = table[key]
        if field_name in _PATH_FIELDS:
            cfg._written_paths[field_name] = str(value)
            value = _anchor_path(value, base_dir)
        elif field_name in ("extra_args", "forwards"):
            value = list(value)
        _set_field(cfg, field_name, value, source)

    profiles = raw.get("profiles", {})
    if profiles:
        # Config profiles extend/override defaults
        for name, prof in profiles.items():
            if isinstance(prof, dict) and "cmdline" in prof:
                cfg.profiles[name] = prof["cmdline"]
            elif isinstance(prof, str):
                cfg.profiles[name] = prof
            else:
                continue
            cfg._field_sources[f"profiles.{name}"] = source

    cfg._sources.append(source)


def _apply_cli(cfg: QMUConfig, overrides: dict[str, Any]) -> None:
    """Apply CLI flag overrides onto a QMUConfig. Only non-None values override."""
    for key, value in overrides.items():
        if value is None:
            continue
        if hasattr(cfg, key):
            setattr(cfg, key, value)
            cfg._field_sources[key] = "CLI flags"
            # A flag is typed in this shell, so it stays CWD-relative and
            # carries no file provenance.
            cfg._path_sources.pop(key, None)
            cfg._written_paths.pop(key, None)


def _apply_config_file(
    cfg: QMUConfig,
    path: Path,
    source_kind: str,
) -> None:
    source = Path(path).resolve()
    raw = load_config_file(source)
    _apply_toml(cfg, raw, f"{source_kind}: {source}", base_dir=source.parent)


# Recovery guidance for the FATAL layer. The project/explicit config is
# validated at the cli.main dispatch choke point before every non-exempt
# subcommand, so one unknown key in a qmu.toml refuses `kill`, `prune` and
# `wait` as well — and the bare "Invalid config <path>: ..." line says nothing
# about that, nor about the way out. Measured next move for an agent holding a
# VM it cannot reap: `qmu kill --vm X --config good.toml`, which is exit 2
# `unrecognized arguments` (only status/list/log/crash register --config, and
# _add_common_opts cannot carry it without colliding with _add_launch_opts).
# So the guidance never prescribes --config: it names the escape hatch that
# works on every verb, grounded in find_project_config walking up from CWD only.
#
# It rides on the ConfigError itself, not on the gate in cli.main, because
# `config show` and `doctor` reach the same fault through their own
# resolve_config call — and the #37 contract is that every surface reports a
# broken project config with one byte-identical message.
_PROJECT_CONFIG_RECOVERY = (
    "This file is validated before every non-exempt subcommand — `kill`, "
    "`prune` and `wait` included — so VM cleanup is blocked until it parses. "
    "Fix it, or re-run from a directory outside the project: the qmu.toml "
    "search only walks up from the current directory."
)
_EXPLICIT_CONFIG_RECOVERY = (
    "This file is validated before every non-exempt subcommand — `kill`, "
    "`prune` and `wait` included — so VM cleanup is blocked until it parses. "
    "Fix it, or drop `--config` to fall back to the project and global layers."
)


def _with_recovery(exc: ConfigError, recovery: str) -> ConfigError:
    """Re-render a ConfigError with recovery guidance appended.

    Rebuilt rather than mutated so the class (and therefore the JSON
    `error_type`) and the leading message line stay byte-identical.
    """
    return ConfigError(
        exc.source,
        exc.problem,
        key_path=exc.key_path,
        hint=exc.hint,
        recovery=recovery,
        more=exc.more,
    )


# One command may resolve config twice (the dispatch-level project-config gate in
# cli.main plus a handler that needs the QMUConfig object), and this warning is a
# per-COMMAND diagnostic, not a per-process one: cli._parse clears the list via
# reset_global_config_warnings() before dispatching, so repeated resolve_config()
# calls within one command still dedupe, but the next command warns again. Keyed
# on the rendered message so a different file or a different error still warns.
# Nothing is written here: the warning fires in the config gate BEFORE the
# handler runs, and the renderer attaches it to the command's Result so it
# reaches stderr in every mode AND the JSON envelope's `warnings[]` (#74).
# A ContextVar holding a tuple, not a module-level list: the MCP façade
# dispatches concurrent commands in separate contexts, and a shared list would
# hand one command's warning to another's envelope.
_global_config_warnings: ContextVar[tuple[str, ...]] = ContextVar(
    "qmu_global_config_warnings", default=()
)


def reset_global_config_warnings() -> None:
    """Clear the warn-once list. Called once per CLI invocation by
    cli._parse (so the dedup is per-command, not per-process) and by the test
    suite's isolate_qmu_env fixture (so a warning from one test cannot mask
    the same message in the next)."""
    _global_config_warnings.set(())


def global_config_warnings() -> tuple[str, ...]:
    """The `[qmu] Warning: …` lines recorded by resolve_config() since the last
    reset, in order, newline-terminated — the shape `Result.warnings` takes."""
    return _global_config_warnings.get()


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
            # Record the skip before warning: the file EXISTS and was rejected,
            # which `doctor` must be able to tell apart from "no global config
            # at all" — the branch that used to fire here and send the reader
            # to `qmu config init` (a PROJECT file) while the broken global sat
            # there re-warning on every command.
            cfg._skipped_sources.append({
                "kind": "global",
                "path": str(gpath),
                "problem": exc.describe_problem(),
            })
            warning = f"[qmu] Warning: ignoring global config: {exc}\n"
            if warning not in _global_config_warnings.get():
                _global_config_warnings.set(_global_config_warnings.get() + (warning,))

    # Layer 2: project config (or explicit --config). Unlike the project
    # search (which simply finds nothing when no qmu.toml exists upward from
    # CWD), an explicit --config naming a path that isn't there is a caller
    # mistake, not "no project config": silently falling through used to both
    # drop every layer above CLI flags AND defeat the #37 dispatch gate (a
    # typo'd --config made `list` report "No VMs." instead of refusing).
    if config_path_override is not None:
        ppath = Path(config_path_override).resolve()
        if not ppath.is_file():
            raise ConfigError(
                ppath, "file not found", recovery=_EXPLICIT_CONFIG_RECOVERY
            )
        try:
            _apply_config_file(cfg, ppath, "config")
        except ConfigError as exc:
            # `from exc.__cause__`, not `from exc`: the re-render replaces the
            # error rather than wrapping it, and callers (and tests) pin the
            # ORIGINAL cause — e.g. the tomllib.TOMLDecodeError behind a
            # malformed file — as __cause__.
            raise _with_recovery(exc, _EXPLICIT_CONFIG_RECOVERY) from exc.__cause__
    else:
        ppath = find_project_config()
        if ppath is not None:
            try:
                _apply_config_file(cfg, ppath, "project")
            except ConfigError as exc:
                raise _with_recovery(exc, _PROJECT_CONFIG_RECOVERY) from exc.__cause__

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
#   1. Edit the `# CHANGE ME` lines below to point at your kernel, rootfs
#      image, and SSH private key.
#   2. Run `qmu doctor` to verify everything resolves.
#   3. Run `qmu launch` — with [boot] kernel set you need no flags at all.
#
# For boot-and-die kernels (kernelCTF, syzkaller reproducers) you do not need
# a rootfs or SSH key — see the harness-mode block at the bottom of this file.
#
# See `qmu config show` for the full resolved config.

[boot]
kernel = "./bzImage"             # CHANGE ME — every launch flag has a config key,
                                 #   so setting this makes `qmu launch` self-contained.
                                 #   --kernel still overrides it for one-off boots.
# initrd = "./initramfs.cpio.gz"
# profile = "exploit-dev"        # named cmdline from [profiles.*] below
# cmdline = "console=ttyS0 ..."  # full override; REPLACES the profile cmdline.
#                                #   To add params on top of a profile instead, launch
#                                #   with --append 'slub_debug=- nokaslr'.

[machine]
arch = "{host_arch}"
{alt_arch_hint}
memory = "4G"
cpus = 2
# cpu = "host"                   # passes -cpu to QEMU; "host" is recommended with KVM
# accel = "auto"                 # "auto" (KVM when guest arch == host arch and
#                                #   /dev/kvm exists), "kvm" (force), or "tcg" (pure
#                                #   emulation). "tcg" / --no-kvm is a retest lever
#                                #   if a gdbstub hardware watchpoint misses under
#                                #   KVM (usually a VA-alias issue — see #39).
# no_reboot = true               # pass -no-reboot: a panic under `panic=N` exits QEMU
#                                #   instead of rebooting over its own report (boot-and-die
#                                #   harnesses). Same as the --no-reboot flag on every launch;
#                                #   --reboot clears it for one launch.
# nic_model = "virtio-net-pci"   # or "e1000", "rtl8139", ...
# forwards = ["2345:2345"]       # extra host->guest TCP forwards on qmu's NIC (gdbserver, a
#                                #   service under test): [HOST:]HPORT:GPORT, or a bare GPORT
#                                #   for an auto-allocated host port. Same as --forward.
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

[daemon]
# autostart = true               # spawn the per-user supervisor on demand (it owns each
#                                #   VM's QMP connection; QMU_DAEMON=off disables per process)
# idle_exit = 600                # seconds with no running VM and no client before it exits

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"

[profiles.trigger-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"

[profiles.exploit-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 oops=panic kasan.fault=panic"

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
