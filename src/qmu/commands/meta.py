"""Meta / housekeeping commands: cache (du/ls), config (show/init/path),
rootfs (inject/shell), skill (install), version.

These talk to config files, rootfs images via libguestfs, and the skill install
roots — none touch a running VM. Shared helpers come from :mod:`.._cliutil`;
this module imports no other ``commands.*`` module and never imports ``cli``.
"""

from __future__ import annotations

import argparse
import base64
import shutil
from pathlib import Path
from typing import Any

from ..cache import (
    MIN_BUILD_RESIDUE_AGE,
    human_bytes,
    scan_cache,
    source_tree_names,
)
from ..config import find_project_config, render_starter_config, resolve_config
from ..instance import QMUError
from ..paths import (
    agents_home,
    agents_skills_dir,
    all_skill_source_dirs,
    global_config_path,
    omp_agent_dir,
    skill_install_roots,
)
from .. import rootfs as rootfs_mod
from ..version import VERSION
from .._cliutil import (
    Result,
    _add_common_opts,
    _add_format_opts,
    _make_group_help_handler,
)


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------
#
# READ-ONLY, deliberately. `qmu prune` stays the one and only verb that deletes;
# splitting inspection from destruction is what keeps a second cleanup verb from
# existing at all. `--older-than` here is a *predicate* parameter, not an action:
# bucket membership is a function of it, so all three commands (cache du, cache
# ls, prune --build-residue) must compute buckets at the same age or they report
# different answers about the same cache.


_BUCKETS = ("eligible", "held_back", "refused")


def _add_cache(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "cache",
        help="Inspect the qmu cache on disk (read-only)",
        description=(
            "Report what is in ~/.cache/qmu and how much of it is reclaimable. "
            "Nothing here deletes; reclaim build residue with "
            "`qmu prune --build-residue`."
        ),
    )
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="cache_cmd")

    s = sp.add_parser("du", help="Show cache size per subtree, and reclaimable totals")
    _add_cache_age_opt(s)
    _add_format_opts(s)
    s.set_defaults(handler=_handle_cache_du)

    s = sp.add_parser("ls", help="List reclaimable build-residue entries, largest first")
    _add_cache_age_opt(s)
    s.add_argument(
        "--bucket", choices=("all", *_BUCKETS), default="eligible",
        help="Which bucket to list (default: eligible — what can actually be reclaimed)",
    )
    s.add_argument(
        "--top", type=int, default=20,
        help="Show at most N groups per bucket (default: 20; 0 means no limit). "
             "Withheld groups are always disclosed, never silently dropped.",
    )
    _add_format_opts(s)
    s.set_defaults(handler=_handle_cache_ls)


def _add_cache_age_opt(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tree", action="append", default=None, metavar="NAME",
        help="Restrict to this kernel source tree (e.g. linux-7.0.12). "
             "Repeatable. A narrowing filter only. Matches the same flag on "
             "`qmu prune --build-residue`, so both report the same buckets.",
    )
    parser.add_argument(
        "--older-than",
        type=_nonnegative_float,
        default=86400.0,
        help="Age threshold in seconds used to bucket residue (default: 86400). "
             "Matches `qmu prune --older-than` so both commands report the same "
             "buckets. Read-only commands accept any non-negative value.",
    )


def _validate_trees(names: list[str] | None) -> list[str] | None:
    """Reject an unknown --tree by naming the trees that DO exist.

    "Never report 'not found' for something another command displays" -- an
    unknown name here must not send the reader to `rm` for a tree `qmu cache ls`
    is showing them.
    """
    if not names:
        return None
    available = source_tree_names()
    unknown = [n for n in names if n not in available]
    if unknown:
        listed = ", ".join(available) if available else "(none)"
        raise QMUError(
            f"No kernel source tree named {', '.join(unknown)}. "
            f"Present: {listed}."
        )
    return names


def _nonnegative_float(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number of seconds") from exc
    if seconds < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return seconds


def _age_annotation(older_than: float) -> str | None:
    """Disclose when an inspected age is below what prune will act on.

    A read-only command has no reason to refuse a predicate — showing what an
    aggressive value would select is the point of inspection. But then
    `cache du --older-than 60` succeeds where the same prune invocation errors,
    so the difference is stated rather than left latent.
    """
    if older_than >= MIN_BUILD_RESIDUE_AGE:
        return None
    return (
        f"Note: --older-than {older_than:g}s is below the "
        f"{MIN_BUILD_RESIDUE_AGE:g}s floor `qmu prune --build-residue` enforces, "
        f"so it would refuse this value. Shown here for inspection only."
    )


def _handle_cache_du(args: argparse.Namespace) -> Result:
    older_than = getattr(args, "older_than", 86400.0)
    trees = _validate_trees(getattr(args, "tree", None))
    report = scan_cache(older_than_seconds=older_than, trees=trees)
    residue = report.residue

    data = {
        "ok": True,
        "cache_dir": str(report.root),
        "total_bytes": report.total_bytes,
        "total_apparent_bytes": report.total_apparent_bytes,
        "total_files": report.total_files,
        "subtrees": [s.as_dict() for s in report.subtrees],
        "build_residue": residue.as_dict(),
    }
    note = _age_annotation(older_than)
    if note:
        data["note"] = note

    lines = [f"qmu cache: {report.root}"]
    if not report.subtrees:
        lines.append("  (empty — nothing cached yet)")
    for s in report.subtrees:
        managed = s.managed_by or "NOT reclaimable by any qmu command"
        flag = "" if s.known else "  [unknown to qmu]"
        lines.append(
            f"  {s.name:<12} {human_bytes(s.bytes):>8}  "
            f"({s.files:,} files, {human_bytes(s.apparent_bytes)} apparent){flag}"
        )
        lines.append(f"  {'':<12}   {managed}")
    lines.append(
        f"  {'TOTAL':<12} {human_bytes(report.total_bytes):>8}  "
        f"({report.total_files:,} files)"
    )
    lines.append("")
    lines.append(f"Build residue (--older-than {older_than:g}s):")
    lines.append(
        f"  total      {human_bytes(residue.total.bytes):>8}  "
        f"{residue.total.files:,} files in {len(residue.total.groups)} source tree(s)"
    )
    for name in _BUCKETS:
        bucket = getattr(residue, name)
        lines.append(
            f"  {name:<10} {human_bytes(bucket.bytes):>8}  {bucket.files:,} files"
        )
        for reason in bucket.reasons[:3]:
            lines.append(f"  {'':<10}   {reason}")
    if residue.eligible.bytes:
        lines.append("")
        lines.append(
            f"Reclaim with: qmu prune --build-residue "
            f"--older-than {max(older_than, MIN_BUILD_RESIDUE_AGE):g} --dry-run"
        )
    if note:
        lines.append(note)

    return Result(data=data, text=lines, stem="cache-du")


def _group_rows(report, bucket_name: str) -> list[dict]:
    """Aggregate residue items into per-source-tree rows for one bucket."""
    rows: dict[str, dict] = {}
    for item in report.items:
        if item.bucket != bucket_name:
            continue
        row = rows.setdefault(
            item.group,
            {"group": item.group, "bucket": bucket_name, "bytes": 0, "files": 0,
             "reason": item.reason},
        )
        row["bytes"] += item.bytes
        row["files"] += 1
    return sorted(rows.values(), key=lambda r: -r["bytes"])


def _handle_cache_ls(args: argparse.Namespace) -> Result:
    older_than = getattr(args, "older_than", 86400.0)
    top = getattr(args, "top", 20)
    if top < 0:
        raise QMUError("--top must be non-negative (0 means no limit).")
    if top == 0:
        top = None
    wanted = getattr(args, "bucket", "eligible")
    trees = _validate_trees(getattr(args, "tree", None))
    buckets = _BUCKETS if wanted == "all" else (wanted,)

    report = scan_cache(older_than_seconds=older_than, trees=trees)
    residue = report.residue

    payload: dict[str, dict] = {}
    lines = [f"Build residue in {report.root}/kernels/src (--older-than {older_than:g}s)"]
    any_rows = False
    for name in buckets:
        rows = _group_rows(residue, name)
        shown = rows if top is None else rows[:top]
        withheld = [] if top is None else rows[top:]
        # A truncated listing that does not say so silently contradicts
        # `cache du`'s totals for the same bucket.
        payload[name] = {
            "groups": shown,
            "shown": len(shown),
            "truncated": {
                "groups": len(withheld),
                "bytes": sum(r["bytes"] for r in withheld),
                "files": sum(r["files"] for r in withheld),
            },
            "bytes": getattr(residue, name).bytes,
            "files": getattr(residue, name).files,
        }
        lines.append("")
        bucket = getattr(residue, name)
        lines.append(
            f"{name} — {human_bytes(bucket.bytes)} in {bucket.files:,} files"
        )
        if not rows:
            lines.append("  (none)")
            continue
        any_rows = True
        for row in shown:
            suffix = f"  [{row['reason']}]" if row["reason"] else ""
            lines.append(
                f"  {human_bytes(row['bytes']):>8}  {row['files']:>7,} files  "
                f"{row['group']}{suffix}"
            )
        if withheld:
            lines.append(
                f"  ... {len(withheld)} more group(s) withheld by --top {top}: "
                f"{human_bytes(sum(r['bytes'] for r in withheld))} in "
                f"{sum(r['files'] for r in withheld):,} files. "
                f"Re-run with --top 0 to see them all."
            )

    data = {
        "ok": True,
        "cache_dir": str(report.root),
        "older_than_seconds": float(older_than),
        "bucket": wanted,
        "top": top,
        "build_residue": payload,
    }
    note = _age_annotation(older_than)
    if note:
        data["note"] = note
        lines.append(note)
    if not any_rows:
        lines.append("")
        lines.append("Nothing to reclaim in this bucket.")

    return Result(data=data, text=lines, stem="cache-ls")


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


def _resolved_path(config: Any, field_name: str) -> dict[str, Any] | None:
    """As-written value, absolute form and existence of a configured path."""
    value = getattr(config, field_name)
    if value is None:
        return None
    resolved = Path(value).expanduser().resolve()
    return {
        "written": config.written_path(field_name),
        "resolved": str(resolved),
        "exists": resolved.exists(),
    }


def _handle_config_show(args: argparse.Namespace) -> Result:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )
    sources = config.source_layers()
    paths = {
        "boot.kernel": _resolved_path(config, "kernel"),
        "boot.initrd": _resolved_path(config, "initrd"),
        "drive.rootfs": _resolved_path(config, "rootfs"),
        "ssh.key": _resolved_path(config, "ssh_key"),
    }

    data = {
        "ok": True,
        # The ordered layer chain, and per TOML key which layer set it — a
        # starter qmu.toml's uncommented `[ssh] key` silently shadowing a
        # global one was invisible with the chain alone.
        "layers": config._sources,
        "sources": sources,
        "paths": paths,
        "boot": {
            "kernel": config.kernel,
            "initrd": config.initrd,
            "cmdline": config.cmdline,
            "profile": config.profile,
            "resolved_cmdline": config.cmdline or config.profiles.get(config.profile),
        },
        "machine": {
            "arch": config.arch,
            "memory": config.memory,
            "cpus": config.cpus,
            "cpu_model": config.cpu_model,
            "nic_model": config.nic_model,
            "net_backend": config.net_backend,
            "accel": config.accel,
            "no_reboot": config.no_reboot,
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

    def row(label: str, value: str, key: str) -> str:
        return f"  {label:<12} {value}  [{sources[key]}]"

    def path_row(label: str, field_name: str, key: str, unset: str) -> str:
        info = paths[key]
        if info is None:
            return row(label, unset, key)
        shown = config.written_path(field_name)
        if info["resolved"] != shown:
            shown += f" -> {info['resolved']}"
        if not info["exists"]:
            shown += " (not found)"
        return row(label, shown, key)

    lines = ["Resolved qmu config:"]
    lines.append(f"  Layers:      {' -> '.join(config._sources)}")
    lines.append(path_row("Kernel:", "kernel", "boot.kernel", "(not set — pass --kernel)"))
    if config.initrd:
        lines.append(path_row("Initrd:", "initrd", "boot.initrd", "(not set)"))
    lines.append(row("Profile:", config.profile, "boot.profile"))
    if config.cmdline:
        lines.append(row("Cmdline:", config.cmdline, "boot.cmdline"))
    else:
        lines.append(row(
            "Cmdline:",
            f"{config.profiles.get(config.profile, '')}  (from profile '{config.profile}')",
            f"profiles.{config.profile}" if config.profile in config.profiles else "boot.profile",
        ))
    lines.append(row("Arch:", f"{config.arch} ({config.qemu_binary()})", "machine.arch"))
    lines.append(row("Accel:", f"{config.accel} (kvm={config.use_kvm()})", "machine.accel"))
    lines.append(row("No-reboot:", str(config.no_reboot).lower(), "machine.no_reboot"))
    lines.append(row("Memory:", config.memory, "machine.memory"))
    lines.append(row("CPUs:", str(config.cpus), "machine.cpus"))
    lines.append(row("CPU model:", config.cpu_model or "(qemu default)", "machine.cpu"))
    lines.append(row("NIC model:", config.nic_model, "machine.nic_model"))
    lines.append(row("Net backend:", config.net_backend, "machine.net_backend"))
    lines.append(row(
        "Extra args:", " ".join(config.extra_args) or "(none)", "machine.extra_args",
    ))
    lines.append(path_row("Rootfs:", "rootfs", "drive.rootfs", "(not set)"))
    lines.append(row("Drive fmt:", config.drive_format, "drive.format"))
    lines.append(path_row("SSH key:", "ssh_key", "ssh.key", "(not set)"))
    lines.append(row("SSH user:", config.ssh_user, "ssh.user"))
    lines.append(row("SSH port:", f"{config.ssh_port_start}+", "ssh.port_start"))
    lines.append(row("GDB port:", f"{config.gdb_port_start}+", "gdb.port_start"))
    lines.append("  Profiles:")
    for name in config.profiles:
        lines.append(f"    {name}  [{sources[f'profiles.{name}']}]")
    return Result(data=data, text=lines, stem="config-show")


def _handle_config_init(args: argparse.Namespace) -> Result:
    target = Path.cwd() / "qmu.toml"
    # ERG-7: `config init` is idempotent — an existing file is a benign no-op
    # (exit 0), not a failure. The file is never overwritten.
    if target.exists():
        msg = f"{target} already exists, not overwritten"
        return Result(
            data={"ok": True, "path": str(target), "created": False, "message": msg},
            text=msg,
            stem="config-init",
        )
    target.write_text(render_starter_config())
    return Result(
        data={"ok": True, "path": str(target), "created": True},
        text=f"Created {target}",
        stem="config-init",
    )


def _handle_config_path(args: argparse.Namespace) -> Result:
    gpath = global_config_path()
    ppath = find_project_config()
    lines = [
        f"Global config:  {gpath} ({'exists' if gpath.is_file() else 'not found'})",
        f"Project config: {ppath or '(none found — searched up from CWD)'}",
    ]
    return Result(
        data={
            "ok": True,
            "global_config": str(gpath),
            "global_config_exists": gpath.is_file(),
            "project_config": str(ppath) if ppath else None,
        },
        text=lines,
        stem="config-path",
    )


# ---------------------------------------------------------------------------
# rootfs (libguestfs)
# ---------------------------------------------------------------------------


def _add_rootfs(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("rootfs", help="Manipulate rootfs images via libguestfs")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="rootfs_cmd")

    s = sp.add_parser(
        "inject",
        help="Copy local files into a rootfs image",
        description=(
            "Copy local files or directories into a rootfs image (offline, via "
            "guestfish). GUEST is always a DIRECTORY inside the image, with or "
            "without a trailing slash; the local filename is kept, so "
            "./exploit:/root lands at /root/exploit. Injected paths are chowned "
            "to root (0:0); mode bits are preserved, so an executable stays "
            "executable. Exit 1 when the image, a LOCAL file, or (without "
            "--mkdir) a GUEST directory does not exist, or when a running VM "
            "still holds the image — nothing is written in any of those cases."
        ),
    )
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("mappings", nargs="+", metavar="LOCAL:GUEST",
                   help="One or more LOCAL:GUEST pairs (GUEST is a directory, "
                        "e.g. ./run.sh:/root or ./exploit:/root/)")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number to mount (default: 1 = /dev/sda1). Use "
                        "0 for a whole-disk image with no partition table, such "
                        "as the one tools/mkrootfs.sh produces")
    s.add_argument("--mkdir", action="store_true",
                   help="Create GUEST if it does not exist (default: a missing "
                        "directory is an error, so a typo cannot report success)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_inject)

    s = sp.add_parser(
        "ls",
        help="List a directory inside a rootfs image",
        description=(
            "List a directory inside a rootfs image. Text output is one "
            "ls -l-style line per entry (mode uid gid size mtime name); JSON "
            "carries entries[] of {name, type, mode, uid, gid, size, mtime, "
            "target}. Exit 1 when the image or the directory does not exist."
        ),
    )
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("path", nargs="?", default="/", help="Guest directory (default: /)")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number to mount (default: 1 = /dev/sda1; use "
                        "0 for a whole-disk image with no partition table)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_ls)

    s = sp.add_parser(
        "cat",
        help="Print a file from inside a rootfs image",
        description=(
            "Print a file from inside a rootfs image, byte-exact (no trailing "
            "newline is added, so the output checksums equal to the file). JSON "
            "carries content, size and encoding ('utf-8', or 'base64' when the "
            "bytes are not valid UTF-8). Exit 1 when the image or the file "
            "does not exist."
        ),
    )
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("path", help="Guest file path")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number to mount (default: 1 = /dev/sda1; use "
                        "0 for a whole-disk image with no partition table)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_cat)

    s = sp.add_parser(
        "rm",
        help="Delete files inside a rootfs image",
        description=(
            "Delete files (or, with --recursive, directories) inside a rootfs "
            "image. GUEST_PATH is the full path of the file itself, not its "
            "directory. Exit 1 when the image does not exist, when a GUEST_PATH "
            "is missing (unless --force, which reports it under 'missing' and "
            "removes the rest), when a path is a directory and --recursive was "
            "not given, or when a running VM still holds the image."
        ),
    )
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("paths", nargs="+", metavar="GUEST_PATH",
                   help="One or more guest file paths to remove")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number to mount (default: 1 = /dev/sda1). Use "
                        "0 for a whole-disk image with no partition table, such "
                        "as the one tools/mkrootfs.sh produces")
    s.add_argument("--recursive", "-r", action="store_true",
                   help="Remove directories and their contents")
    s.add_argument("--force", "-f", action="store_true",
                   help="Ignore paths that do not exist (default: a missing path "
                        "is an error, so a typo cannot report success)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_rm)

    s = sp.add_parser("shell", help="Drop into a guestfish interactive shell")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("--partition", type=int, default=1)
    s.set_defaults(handler=_handle_rootfs_shell)


def _handle_rootfs_inject(args: argparse.Namespace) -> Result:
    parsed = [rootfs_mod.parse_mapping(m) for m in args.mappings]
    rootfs_mod.inject(
        args.image, parsed, partition=args.partition, mkdir=args.mkdir
    )

    guest_dirs = rootfs_mod._inject_guest_dirs(parsed)
    injected = []
    for (local, guest), guest_dir in zip(parsed, guest_dirs):
        name = Path(local).resolve().name
        injected.append({
            "local": local,
            "guest": guest,
            "path": guest_dir.rstrip("/") + "/" + name,
            "owner": "0:0",
        })
    summary = {
        "ok": True,
        "image": args.image,
        "partition": args.partition,
        "injected": injected,
    }
    lines = [f"Injected into {args.image} (partition {args.partition}):"]
    for item in injected:
        lines.append(f"  {item['local']} -> {item['path']} (owner 0:0)")
    return Result(data=summary, text=lines, stem="rootfs-inject")


def _handle_rootfs_ls(args: argparse.Namespace) -> Result:
    entries = rootfs_mod.listdir(args.image, args.path, partition=args.partition)
    return Result(
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "path": args.path,
            "entries": entries,
        },
        text=[rootfs_mod.format_entry(e) for e in entries] if entries else f"{args.path} is empty.",
        stem="rootfs-ls",
    )


def _handle_rootfs_cat(args: argparse.Namespace) -> Result:
    raw = rootfs_mod.read_file(args.image, args.path, partition=args.partition)
    try:
        content, encoding = raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        content, encoding = base64.b64encode(raw).decode("ascii"), "base64"

    # Text mode is the file's bytes, verbatim (`raw`): rendering `text` would
    # append a newline (and decode), so a checksum of the output never matched
    # the source.
    return Result(
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "path": args.path,
            "size": len(raw),
            "encoding": encoding,
            "content": content,
        },
        stem="rootfs-cat",
        raw=raw,
    )


def _handle_rootfs_rm(args: argparse.Namespace) -> Result:
    result = rootfs_mod.remove(
        args.image,
        args.paths,
        partition=args.partition,
        recursive=args.recursive,
        force=args.force,
    )
    if result["removed"]:
        lines = [f"Removed from {args.image} (partition {args.partition}):"]
        lines.extend(f"  {p}" for p in result["removed"])
        lines.extend(
            f"  (not present, ignored by --force) {p}" for p in result["missing"]
        )
    else:
        lines = [
            f"Nothing to remove: {', '.join(result['missing'])} does not exist "
            "(--force)."
        ]
    return Result(
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "removed": result["removed"],
            "missing": result["missing"],
        },
        text=lines,
        stem="rootfs-rm",
    )


def _handle_rootfs_shell(args: argparse.Namespace) -> Result:
    return Result.silent_exit(rootfs_mod.shell(args.image, partition=args.partition))


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------


def _add_skill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("skill", help="Manage Claude Code / Codex / OMP skills")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="skill_cmd")
    s = sp.add_parser("install", help="Install skills into ~/.claude (and ~/.codex / ~/.agents when present)")
    _add_format_opts(s)
    s.set_defaults(handler=_handle_skill_install)


def _prepare_install_roots(roots: list[Path]) -> None:
    """Create every install root before the first symlink is written.

    Linking is skill-outer/root-inner, so a root that cannot be created (e.g.
    ~/.agents exists as a regular file) would otherwise abort mid-loop with
    ~/.claude holding only the first skill — an auto-detected root breaking the
    two that already worked.

    mkdir() is the probe as well as the creation: with exist_ok=True it succeeds
    on a real dir (and on a symlink to one, which is a legitimate dotfiles
    layout) and raises on every unusable shape — NotADirectoryError when a
    parent is a file, FileExistsError when the root itself is a file or a
    dangling symlink, PermissionError when the home is not writable. Those are
    all the caller's own filesystem state, i.e. operational, so they become
    QMUError (exit 1, with the remedy) instead of reaching cli's catch-all as a
    bare errno string on exit 4, which the contract reserves for infra and
    internal faults.
    """
    for root in roots:
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            blocker = next(
                (p for p in (root, *root.parents) if p.is_symlink() or p.exists()),
                None,
            )
            if blocker is not None and not blocker.is_dir():
                raise QMUError(
                    f"Cannot install skills into {root}: {blocker} exists but is "
                    f"not a directory. Remove or move it — or point "
                    f"CLAUDE_HOME/CODEX_HOME/AGENTS_HOME at another location — "
                    f"then re-run `qmu skill install`."
                ) from exc
            raise QMUError(
                f"Cannot create skill install root {root}: "
                f"{exc.strerror or exc}"
            ) from exc


_LINK_STATUSES = ("installed", "relinked", "replaced", "current")


def _link_skill(src: Path, dst: Path) -> tuple[str, str | None]:
    """Point `dst` at `src`, reporting what was there before.

    Four outcomes, because "installed" is a different fact from each of the
    others and anyone re-running this needs to know which one they got:

    * ``current``  — already a link to this source. NOTHING is written; the
      link is left byte-identical (mtime included) instead of being removed
      and recreated, so a re-run is a true no-op rather than N rewrites of
      links a live agent session may be reading through.
    * ``relinked`` — a link to a DIFFERENT source, whose old target comes back
      so the caller can be told. This is the outcome that matters: an install
      run from a stale checkout leaves every link pointing at a tree that no
      longer matches the repo, and calling that "installed" is exactly how
      such a swap goes unnoticed.
    * ``replaced`` — a real directory or file, which is deleted. Destructive,
      so it has to be visible in the output.
    * ``installed`` — nothing was there.
    """
    previous: str | None = None
    if dst.is_symlink():
        previous = str(dst.readlink())
        if dst.resolve() == src.resolve():
            return "current", previous
        dst.unlink()
        status = "relinked"
    elif dst.exists():
        if dst.is_dir():
            shutil.rmtree(dst)
        else:
            # A plain file here used to reach shutil.rmtree() and raise
            # NotADirectoryError into cli's catch-all as exit 4, which the
            # contract reserves for infra faults; it is the caller's own
            # filesystem state and is simply replaceable.
            dst.unlink()
        status = "replaced"
    else:
        status = "installed"
    dst.symlink_to(src)
    return status, previous


def _handle_skill_install(args: argparse.Namespace) -> Result:
    skill_dirs = all_skill_source_dirs()
    if not skill_dirs:
        raise QMUError("No skill sources found under skills/")

    roots = skill_install_roots()
    _prepare_install_roots(roots)

    links: list[dict[str, object]] = []
    counts = dict.fromkeys(_LINK_STATUSES, 0)
    changed: list[str] = []
    for src in skill_dirs:
        for root in roots:
            dst = root / src.name
            status, previous = _link_skill(src, dst)
            counts[status] += 1
            links.append({
                "skill": src.name,
                "root": str(root),
                "path": str(dst),
                "target": str(src),
                "status": status,
                "previous_target": previous if status == "relinked" else None,
            })
            if status == "current":
                # Tallied instead of listed: one line per unchanged link is
                # what buried the changed ones, and every re-run is all-
                # unchanged. The JSON payload still carries each link.
                continue
            if status == "relinked":
                detail = f"  (was {previous})"
            elif status == "replaced":
                detail = "  (removed what was there)"
            else:
                detail = ""
            changed.append(f"{status:<9} {dst} -> {src}{detail}")

    skipped: list[dict[str, str]] = []
    if agents_skills_dir() not in roots:
        skipped.append({
            "path": str(agents_skills_dir()),
            "reason": (
                f"OMP not detected: no directory at {agents_home()} or "
                f"{omp_agent_dir()}"
            ),
        })

    total = len(links)
    link_s = "" if total == 1 else "s"
    root_s = "" if len(roots) == 1 else "s"
    if counts["current"] == total:
        summary = (
            f"All {total} link{link_s} in {len(roots)} root{root_s} already "
            f"current — nothing to do."
        )
    else:
        tally = ", ".join(f"{counts[s]} {s}" for s in _LINK_STATUSES if counts[s])
        summary = f"{total} link{link_s} in {len(roots)} root{root_s}: {tally}."
    lines = [*changed, summary]
    lines.extend(f"Skipped {e['path']} ({e['reason']})" for e in skipped)

    return Result(
        data={
            "ok": True,
            "roots": [str(r) for r in roots],
            "skills": [d.name for d in skill_dirs],
            "links": links,
            "counts": counts,
            "skipped_roots": skipped,
        },
        text=lines,
        stem="skill-install",
    )


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


def _add_version(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("version", help="Print version")
    _add_format_opts(p)
    p.set_defaults(handler=_handle_version)


def _handle_version(args: argparse.Namespace) -> Result:
    return Result(data={"ok": True, "version": VERSION}, text=f"qmu {VERSION}", stem="version")
