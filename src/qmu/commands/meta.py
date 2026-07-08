"""Meta / housekeeping commands: config (show/init/path), rootfs (inject/shell),
skill (install), version.

These talk to config files, rootfs images via libguestfs, and the skill install
roots — none touch a running VM. Shared helpers come from :mod:`.._cliutil`;
this module imports no other ``commands.*`` module and never imports ``cli``.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from ..config import find_project_config, render_starter_config, resolve_config
from ..instance import QMUError
from ..paths import (
    all_skill_source_dirs,
    claude_skills_dir,
    codex_home,
    codex_skills_dir,
    global_config_path,
)
from .. import rootfs as rootfs_mod
from ..version import VERSION
from .._cliutil import (
    _add_common_opts,
    _add_format_opts,
    _emit,
    _make_group_help_handler,
)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _add_config(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("config", help="Manage qmu configuration")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="config_cmd")

    s = sp.add_parser("show", help="Show resolved configuration")
    s.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_config_show)

    s = sp.add_parser("init", help="Create a starter qmu.toml in current directory")
    _add_format_opts(s)
    s.set_defaults(handler=_handle_config_init)

    s = sp.add_parser("path", help="Show config file search paths")
    _add_format_opts(s)
    s.set_defaults(handler=_handle_config_path)


def _handle_config_show(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )

    data = {
        "ok": True,
        "sources": config._sources,
        "machine": {
            "arch": config.arch,
            "memory": config.memory,
            "cpus": config.cpus,
            "cpu_model": config.cpu_model,
            "qemu_binary": config.qemu_binary(),
            "kvm": config.use_kvm(),
            "extra_args": config.extra_args,
        },
        "drive": {
            "rootfs": config.rootfs,
            "format": config.drive_format,
        },
        "ssh": {
            "key": config.ssh_key,
            "user": config.ssh_user,
            "port_start": config.ssh_port_start,
        },
        "gdb": {
            "port_start": config.gdb_port_start,
        },
        "profiles": config.profiles,
    }

    lines = ["Resolved qmu config:"]
    lines.append(f"  Sources: {' -> '.join(config._sources)}")
    lines.append(f"  Arch:        {config.arch} ({config.qemu_binary()})")
    lines.append(f"  KVM:         {config.use_kvm()}")
    lines.append(f"  Memory:      {config.memory}")
    lines.append(f"  CPUs:        {config.cpus}")
    lines.append(f"  CPU model:   {config.cpu_model or '(qemu default)'}")
    lines.append(f"  Rootfs:      {config.rootfs or '(not set)'}")
    lines.append(f"  Drive fmt:   {config.drive_format}")
    lines.append(f"  SSH key:     {config.ssh_key or '(not set)'}")
    lines.append(f"  SSH user:    {config.ssh_user}")
    lines.append(f"  SSH port:    {config.ssh_port_start}+")
    lines.append(f"  GDB port:    {config.gdb_port_start}+")
    if config.extra_args:
        lines.append(f"  Extra args:  {' '.join(config.extra_args)}")
    lines.append(f"  Profiles:    {', '.join(config.profiles.keys())}")
    _emit(args, data=data, text=lines, stem="config-show")
    return 0


def _handle_config_init(args: argparse.Namespace) -> int:
    target = Path.cwd() / "qmu.toml"
    # ERG-7: `config init` is idempotent — an existing file is a benign no-op
    # (exit 0), not a failure. The file is never overwritten.
    if target.exists():
        msg = f"{target} already exists, not overwritten"
        _emit(
            args,
            data={"ok": True, "path": str(target), "created": False, "message": msg},
            text=msg,
            stem="config-init",
        )
        return 0
    target.write_text(render_starter_config())
    _emit(
        args,
        data={"ok": True, "path": str(target), "created": True},
        text=f"Created {target}",
        stem="config-init",
    )
    return 0


def _handle_config_path(args: argparse.Namespace) -> int:
    gpath = global_config_path()
    ppath = find_project_config()
    lines = [
        f"Global config:  {gpath} ({'exists' if gpath.is_file() else 'not found'})",
        f"Project config: {ppath or '(none found — searched up from CWD)'}",
    ]
    _emit(
        args,
        data={
            "ok": True,
            "global_config": str(gpath),
            "global_config_exists": gpath.is_file(),
            "project_config": str(ppath) if ppath else None,
        },
        text=lines,
        stem="config-path",
    )
    return 0


# ---------------------------------------------------------------------------
# rootfs (libguestfs)
# ---------------------------------------------------------------------------


def _add_rootfs(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("rootfs", help="Manipulate rootfs images via libguestfs")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="rootfs_cmd")

    s = sp.add_parser("inject", help="Copy local files into a rootfs image")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("mappings", nargs="+", metavar="LOCAL:GUEST",
                   help="One or more LOCAL:GUEST pairs (GUEST is a directory)")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number (default: 1; use 0 for whole-disk image)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_inject)

    s = sp.add_parser("shell", help="Drop into a guestfish interactive shell")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("--partition", type=int, default=1)
    s.set_defaults(handler=_handle_rootfs_shell)


def _handle_rootfs_inject(args: argparse.Namespace) -> int:
    parsed = [rootfs_mod.parse_mapping(m) for m in args.mappings]
    rootfs_mod.inject(args.image, parsed, partition=args.partition)

    summary = {
        "ok": True,
        "image": args.image,
        "partition": args.partition,
        "injected": [{"local": l, "guest": g} for l, g in parsed],
    }
    lines = [f"Injected into {args.image} (partition {args.partition}):"]
    for local, guest in parsed:
        lines.append(f"  {local} -> {guest}")
    _emit(args, data=summary, text=lines, stem="rootfs-inject")
    return 0


def _handle_rootfs_shell(args: argparse.Namespace) -> int:
    return rootfs_mod.shell(args.image, partition=args.partition)


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------


def _add_skill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("skill", help="Manage Claude Code / Codex skill")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="skill_cmd")
    s = sp.add_parser("install", help="Install skill into ~/.claude (and ~/.codex if present)")
    s.set_defaults(handler=_handle_skill_install)


def _skill_install_roots() -> list[Path]:
    """Return the destination dirs for `qmu skill install`.

    Always installs into ~/.claude/skills/. Additionally installs into
    ~/.codex/skills/ when ~/.codex/ exists.
    """
    roots = [claude_skills_dir()]
    if codex_home().is_dir():
        roots.append(codex_skills_dir())
    return roots


def _handle_skill_install(args: argparse.Namespace) -> int:
    skill_dirs = all_skill_source_dirs()
    if not skill_dirs:
        raise QMUError("No skill sources found under skills/")

    for src in skill_dirs:
        name = src.name
        for root in _skill_install_roots():
            dst = root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.is_symlink() or dst.exists():
                if dst.is_symlink():
                    dst.unlink()
                else:
                    shutil.rmtree(dst)
            dst.symlink_to(src)
            print(f"Skill installed: {dst} -> {src}")
    return 0


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


def _add_version(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("version", help="Print version")
    _add_format_opts(p)
    p.set_defaults(handler=_handle_version)


def _handle_version(args: argparse.Namespace) -> int:
    _emit(args, data={"ok": True, "version": VERSION}, text=f"qmu {VERSION}", stem="version")
    return 0
