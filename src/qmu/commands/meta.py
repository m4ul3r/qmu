"""Meta / housekeeping commands: cache (du/ls), config (show/init/path),
rootfs (inject/shell), skill (install), version.

These talk to config files, rootfs images via libguestfs, and the skill install
roots — none touch a running VM. Shared helpers come from :mod:`.._cliutil`;
this module imports no other ``commands.*`` module and never imports ``cli``.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

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
    _add_common_opts,
    _add_format_opts,
    _emit,
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


def _handle_cache_du(args: argparse.Namespace) -> int:
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

    _emit(args, data=data, text=lines, stem="cache-du")
    return 0


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


def _handle_cache_ls(args: argparse.Namespace) -> int:
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

    _emit(args, data=data, text=lines, stem="cache-ls")
    return 0


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
    lines.append(f"  Kernel:      {config.kernel or '(not set — pass --kernel)'}")
    if config.initrd:
        lines.append(f"  Initrd:      {config.initrd}")
    lines.append(f"  Profile:     {config.profile}")
    lines.append(
        f"  Cmdline:     {config.cmdline or config.profiles.get(config.profile, '')}"
        + ("" if config.cmdline else f"  (from profile '{config.profile}')")
    )
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
    s.add_argument("--mkdir", action="store_true",
                   help="Create GUEST if it does not exist (default: a missing "
                        "directory is an error, so a typo cannot report success)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_inject)

    s = sp.add_parser("ls", help="List a directory inside a rootfs image")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("path", nargs="?", default="/", help="Guest directory (default: /)")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number (default: 1; use 0 for whole-disk image)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_ls)

    s = sp.add_parser("cat", help="Print a file from inside a rootfs image")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("path", help="Guest file path")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number (default: 1; use 0 for whole-disk image)")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_rootfs_cat)

    s = sp.add_parser("rm", help="Delete files inside a rootfs image")
    s.add_argument("image", help="Path to rootfs image")
    s.add_argument("paths", nargs="+", metavar="GUEST_PATH",
                   help="One or more guest file paths to remove")
    s.add_argument("--partition", type=int, default=1,
                   help="Partition number (default: 1; use 0 for whole-disk image)")
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


def _handle_rootfs_inject(args: argparse.Namespace) -> int:
    parsed = [rootfs_mod.parse_mapping(m) for m in args.mappings]
    rootfs_mod.inject(
        args.image, parsed, partition=args.partition, mkdir=args.mkdir
    )

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


def _handle_rootfs_ls(args: argparse.Namespace) -> int:
    entries = rootfs_mod.listdir(args.image, args.path, partition=args.partition)
    _emit(
        args,
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "path": args.path,
            "entries": entries,
        },
        text=entries if entries else f"{args.path} is empty.",
        stem="rootfs-ls",
    )
    return 0


def _handle_rootfs_cat(args: argparse.Namespace) -> int:
    content = rootfs_mod.read_file(args.image, args.path, partition=args.partition)
    _emit(
        args,
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "path": args.path,
            "content": content,
        },
        text=content,
        stem="rootfs-cat",
    )
    return 0


def _handle_rootfs_rm(args: argparse.Namespace) -> int:
    rootfs_mod.remove(
        args.image,
        args.paths,
        partition=args.partition,
        recursive=args.recursive,
        force=args.force,
    )
    lines = [f"Removed from {args.image} (partition {args.partition}):"]
    lines.extend(f"  {p}" for p in args.paths)
    _emit(
        args,
        data={
            "ok": True,
            "image": args.image,
            "partition": args.partition,
            "removed": args.paths,
        },
        text=lines,
        stem="rootfs-rm",
    )
    return 0


def _handle_rootfs_shell(args: argparse.Namespace) -> int:
    return rootfs_mod.shell(args.image, partition=args.partition)


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------


def _add_skill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("skill", help="Manage Claude Code / Codex / OMP skills")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="skill_cmd")
    s = sp.add_parser("install", help="Install skills into ~/.claude (and ~/.codex / ~/.agents when present)")
    s.set_defaults(handler=_handle_skill_install)


def _handle_skill_install(args: argparse.Namespace) -> int:
    skill_dirs = all_skill_source_dirs()
    if not skill_dirs:
        raise QMUError("No skill sources found under skills/")

    roots = skill_install_roots()
    for src in skill_dirs:
        name = src.name
        for root in roots:
            dst = root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.is_symlink() or dst.exists():
                if dst.is_symlink():
                    dst.unlink()
                else:
                    shutil.rmtree(dst)
            dst.symlink_to(src)
            print(f"Skill installed: {dst} -> {src}")
    if agents_skills_dir() not in roots:
        print(
            f"Skipped {agents_skills_dir()} (OMP not detected: neither "
            f"{agents_home()} nor {omp_agent_dir()} exists)"
        )
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
