"""Cache inventory and build-residue classification.

qmu owns the ``~/.cache/qmu`` namespace (:func:`qmu.paths.cache_home`), but three
sibling shell tools write into it through the same ``QMU_CACHE_DIR``:
``tools/kbuild.sh`` (``kernels/``), ``tools/mkrootfs.sh`` (``rootfs/``) and
``tools/mktarget.sh`` (``targets/``). Until this module existed no qmu command
could *see* any of it — ``prune`` reaches ``instances/`` and ``runtime_root()``
only, which on a real research box is ~0.01% of the bytes on disk.

This is the single authority on "what is in the cache and what is reclaimable".
It sits at the domain layer beside :mod:`qmu.instance` / :mod:`qmu.runtime` and
imports nothing from ``commands.*`` or ``cli``.

Two invariants drive the whole design:

**Allocated bytes, never apparent.** ``targets/`` and ``rootfs/`` hold sparse
ext4 images: a single ``rootfs.img`` measures 4.29 GB by ``st_size`` and 0.65 GB
by ``st_blocks * 512``. Summing ``st_size`` overstates a real cache by ~70%,
concentrated in exactly the subtrees a reader would then wrongly delete. Both
numbers are reported; ``bytes`` is always allocated.

**The residue classifier is an allowlist of build intermediates.** It never
selects ``vmlinux``, ``vmlinux.unstripped``, ``System.map``, ``Makefile``,
``.config``, anything under ``arch/*/boot/``, or any symlink. This is not
defensive coding — those files are frequently the *only* copy. ``kbuild.sh``'s
``make $GDB_TARGET`` step fails on 4.x kernels and, under ``pipefail``, aborts
before the artifact copy, so the source tree keeps the only ``vmlinux`` /
``System.map`` / ``Image`` for that build. ``skills/firmware-over-qmu/SKILL.md``
documents recovering from exactly there.
"""

from __future__ import annotations

import math
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .paths import cache_home, instances_dir


# Subtrees qmu knows about. Anything else found at the cache root is still
# reported (``known=False``) — a cache that hides bytes from its own inventory
# is the defect this module exists to fix.
KNOWN_SUBTREES: tuple[str, ...] = ("instances", "kernels", "rootfs", "targets")

# Only ``instances/`` has a lifecycle today; the rest are written by the shell
# tools and reclaimed (for kernels/) by ``qmu prune --build-residue``.
_MANAGED_BY = {
    "instances": "qmu prune --vm/--all",
    "kernels": "qmu prune --build-residue (build residue only)",
}

# Build intermediates, matched by name inside ``kernels/src/linux-*/`` only.
_RESIDUE_SUFFIXES: tuple[str, ...] = (
    ".o", ".a", ".ko", ".mod", ".mod.c", ".symtypes",
)
_RESIDUE_CMD = re.compile(r"^\..+\.cmd$")
_RESIDUE_TMP_VMLINUX = re.compile(r"^\.tmp_vmlinux")

# NEVER classified as residue, at any depth, under any predicate.
#
# ``vmlinux.unstripped`` is listed explicitly rather than merely omitted from
# the allowlist so a later suffix addition cannot pick it up. On linux-7.0.12 it
# is 1109.5 MB against a copied-out ``vmlinux`` of 518.6 MB (2.14x) — it holds
# strictly more debug information and is not derivable from what survives.
_NEVER_NAMES = frozenset({
    "vmlinux",
    "vmlinux.unstripped",
    "System.map",
    "Makefile",
    ".config",
})

_SOURCE_DIR_RE = re.compile(r"^linux-.+")

# Below this many seconds, ``prune --build-residue`` refuses rather than acting:
# ``kbuild.sh`` bind-mounts the source tree read-write for the whole build, so
# reclaiming residue from a build that may still be running corrupts it. There
# is deliberately no override flag — see the module docstring of the handler.
MIN_BUILD_RESIDUE_AGE = 600.0

# Bucket precedence. ``refused`` is a hard block (an unwritable parent dir, or an
# instance record pointing at the path); ``held_back`` is a timer that expires.
# An item that is both lands in ``refused``. Without a stated precedence the
# three buckets do not partition and the pinned
# ``total == eligible + held_back + refused`` equality fails.
BUCKET_REFUSED = "refused"
BUCKET_HELD_BACK = "held_back"
BUCKET_ELIGIBLE = "eligible"


@dataclass(frozen=True)
class SubtreeUsage:
    """One directory at the cache root."""

    name: str
    path: Path
    bytes: int              # allocated: st_blocks * 512
    apparent_bytes: int     # st_size sum, reported alongside
    files: int
    managed_by: str         # "" when no qmu command reclaims it
    known: bool

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "path": str(self.path),
            "bytes": self.bytes,
            "apparent_bytes": self.apparent_bytes,
            "files": self.files,
            "managed_by": self.managed_by,
            "known": self.known,
        }


@dataclass(frozen=True)
class ReclaimItem:
    """One reclaimable file, already assigned to a bucket."""

    path: Path
    bytes: int
    group: str              # source-tree dir name, e.g. "linux-7.0.12"
    bucket: str
    reason: str             # why it is in that bucket ("" for eligible)

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "bytes": self.bytes,
            "group": self.group,
            "bucket": self.bucket,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Bucket:
    """Aggregate of one bucket. Shape is identical in every command that emits it."""

    groups: tuple[str, ...] = ()
    bytes: int = 0
    files: int = 0
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "groups": list(self.groups),
            "bytes": self.bytes,
            "files": self.files,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class ResidueReport:
    older_than_seconds: float
    items: tuple[ReclaimItem, ...] = ()
    total: Bucket = field(default_factory=Bucket)
    eligible: Bucket = field(default_factory=Bucket)
    held_back: Bucket = field(default_factory=Bucket)
    refused: Bucket = field(default_factory=Bucket)

    def as_dict(self) -> dict:
        return {
            "older_than_seconds": self.older_than_seconds,
            "total": self.total.as_dict(),
            "eligible": self.eligible.as_dict(),
            "held_back": self.held_back.as_dict(),
            "refused": self.refused.as_dict(),
        }

    def bucket_items(self, bucket: str) -> list[ReclaimItem]:
        return [item for item in self.items if item.bucket == bucket]


@dataclass(frozen=True)
class CacheReport:
    root: Path
    subtrees: tuple[SubtreeUsage, ...]
    total_bytes: int
    total_apparent_bytes: int
    total_files: int
    residue: ResidueReport

    def unmanaged(self) -> tuple[SubtreeUsage, ...]:
        return tuple(s for s in self.subtrees if not s.managed_by)


def _iter_files(root: Path):
    """Yield (path, lstat) for regular files under root. Symlinks are never followed."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # os.walk already does not follow symlinked dirs with followlinks=False,
        # but it still *lists* them; drop them so they are never descended or counted.
        dirnames[:] = [
            d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                st = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            yield path, st


def _subtree_usage(path: Path, name: str) -> SubtreeUsage:
    allocated = apparent = files = 0
    seen: set[tuple[int, int]] = set()
    for _fp, st in _iter_files(path):
        key = (st.st_dev, st.st_ino)
        if key in seen:
            continue
        seen.add(key)
        allocated += st.st_blocks * 512
        apparent += st.st_size
        files += 1
    return SubtreeUsage(
        name=name,
        path=path,
        bytes=allocated,
        apparent_bytes=apparent,
        files=files,
        managed_by=_MANAGED_BY.get(name, ""),
        known=name in KNOWN_SUBTREES,
    )


def is_residue_name(name: str) -> bool:
    """True when a bare filename is a build intermediate.

    Name-only, deliberately: the caller is responsible for confirming the file
    lives inside ``kernels/src/linux-*/`` and is a regular file.
    """
    if name in _NEVER_NAMES:
        return False
    if name.endswith(_RESIDUE_SUFFIXES):
        return True
    if _RESIDUE_CMD.match(name):
        return True
    return False


def _is_tmp_vmlinux(name: str) -> bool:
    return bool(_RESIDUE_TMP_VMLINUX.match(name))


def _under_arch_boot(rel: Path) -> bool:
    parts = rel.parts
    return len(parts) >= 3 and parts[0] == "arch" and parts[2] == "boot"


def _parent_writable(path: Path) -> bool:
    """Unlink permission lives on the *parent directory*, never on the file.

    Demonstrated on a real cache: ``os.access(file, W_OK)`` returns True for a
    0664 file whose ``os.unlink`` raises ``PermissionError``, because the parent
    directory is root-owned 0755. Checking the file would report 789 root-owned
    directories as writable and make preview disagree with the real run.
    """
    return os.access(path.parent, os.W_OK | os.X_OK)


def _instance_referenced_paths() -> set[Path]:
    """Absolute paths any instance record points at (kernel / rootfs / ssh_key).

    Imported lazily so this module stays importable when instance state is
    unreadable, and so a cache scan never fails because of a malformed record.
    """
    referenced: set[Path] = set()
    try:
        from .instance import list_instances, list_stopped_instances
    except Exception:  # pragma: no cover - defensive
        return referenced
    records = []
    for loader in (list_instances, list_stopped_instances):
        try:
            records.extend(loader())
        except Exception:  # pragma: no cover - defensive
            continue
    for inst in records:
        for attr in ("kernel", "rootfs", "ssh_key"):
            value = getattr(inst, attr, None)
            if not value:
                continue
            try:
                referenced.add(Path(str(value)).resolve())
            except OSError:
                continue
    return referenced


def _group_buckets(items: Iterable[ReclaimItem], bucket: str) -> Bucket:
    groups: list[str] = []
    reasons: list[str] = []
    total = files = 0
    for item in items:
        if item.bucket != bucket:
            continue
        if item.group not in groups:
            groups.append(item.group)
        if item.reason and item.reason not in reasons:
            reasons.append(item.reason)
        total += item.bytes
        files += 1
    return Bucket(tuple(groups), total, files, tuple(reasons))


def _all_bucket(items: Iterable[ReclaimItem]) -> Bucket:
    groups: list[str] = []
    total = files = 0
    for item in items:
        if item.group not in groups:
            groups.append(item.group)
        total += item.bytes
        files += 1
    return Bucket(tuple(groups), total, files, ())


def classify_residue(
    *,
    older_than_seconds: float,
    now: float | None = None,
    root: Path | None = None,
    trees: Iterable[str] | None = None,
) -> ResidueReport:
    """Classify build residue into eligible / held_back / refused.

    Every consumer — ``cache du``, ``cache ls``, ``prune --build-residue``
    preview and ``prune --build-residue`` real — calls this one function, so on a
    fixed cache state they agree by construction. Putting the writability check
    in the deleting path instead would make preview systematically over-promise:
    on a real cache one source tree has 789 root-owned directories, none of them
    unlinkable, and the dry run would have advertised 1.47 GB it could not remove.
    """
    if not math.isfinite(older_than_seconds) or older_than_seconds < 0:
        raise ValueError("older_than_seconds must be finite and non-negative")
    current = time.time() if now is None else now
    if not math.isfinite(current):
        raise ValueError("now must be finite")
    cutoff = current - older_than_seconds

    cache_root = (root or cache_home())
    # A narrowing filter, never a widening one: it can only reduce what is
    # considered, so it cannot make any invocation delete more than the
    # unfiltered one would. Applied here rather than in a caller so that
    # `cache du`, `cache ls` and `prune --build-residue` keep agreeing bucket
    # for bucket at the same (--older-than, --tree) pair.
    wanted = set(trees) if trees else None
    src_root = cache_root / "kernels" / "src"
    items: list[ReclaimItem] = []
    if not src_root.is_dir():
        empty = Bucket()
        return ResidueReport(float(older_than_seconds), (), empty, empty, empty, empty)

    referenced = _instance_referenced_paths()

    try:
        entries = sorted(src_root.iterdir())
    except OSError:
        entries = []

    for tree in entries:
        if not _SOURCE_DIR_RE.match(tree.name):
            continue
        if wanted is not None and tree.name not in wanted:
            continue
        try:
            tree_st = tree.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(tree_st.st_mode) or stat.S_ISLNK(tree_st.st_mode):
            continue

        candidates: list[tuple[Path, os.stat_result]] = []
        newest = 0.0
        seen: set[tuple[int, int]] = set()
        has_vmlinux = (tree / "vmlinux").is_file()

        for path, st in _iter_files(tree):
            newest = max(newest, st.st_mtime)
            name = path.name
            if name in _NEVER_NAMES:
                continue
            try:
                rel = path.relative_to(tree)
            except ValueError:  # pragma: no cover - defensive
                continue
            if _under_arch_boot(rel):
                continue
            if _is_tmp_vmlinux(name):
                # A .tmp_vmlinux1 is a complete pre-kallsyms ELF. If a build died
                # between the tmp link and the final link it is the only
                # near-complete one, so gate it on a real vmlinux existing.
                if not has_vmlinux:
                    continue
            elif not is_residue_name(name):
                continue
            key = (st.st_dev, st.st_ino)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((path, st))

        if not candidates:
            continue

        # Age is per-tree: a live build touches its tree continuously, so the
        # newest mtime anywhere in it is the signal. tar preserves tarball
        # mtimes on extract, so a pristine tree reads as ancient — and a pristine
        # tree contains zero candidates, so there is nothing to gate until the
        # first object lands with a current mtime.
        tree_is_fresh = newest > cutoff

        for path, st in candidates:
            resolved_parent = path.parent
            reason = ""
            bucket = BUCKET_ELIGIBLE
            if not _parent_writable(path):
                bucket = BUCKET_REFUSED
                reason = f"{resolved_parent} is not writable"
            elif _is_referenced(path, referenced):
                bucket = BUCKET_REFUSED
                reason = "referenced by an instance record"
            elif tree_is_fresh:
                bucket = BUCKET_HELD_BACK
                reason = f"modified within {older_than_seconds:g}s"
            items.append(
                ReclaimItem(
                    path=path,
                    bytes=st.st_blocks * 512,
                    group=tree.name,
                    bucket=bucket,
                    reason=reason,
                )
            )

    frozen = tuple(items)
    return ResidueReport(
        older_than_seconds=float(older_than_seconds),
        items=frozen,
        total=_all_bucket(frozen),
        eligible=_group_buckets(frozen, BUCKET_ELIGIBLE),
        held_back=_group_buckets(frozen, BUCKET_HELD_BACK),
        refused=_group_buckets(frozen, BUCKET_REFUSED),
    )


def _is_referenced(path: Path, referenced: set[Path]) -> bool:
    if not referenced:
        return False
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved in referenced


def scan_cache(
    *,
    older_than_seconds: float = 86400.0,
    now: float | None = None,
    root: Path | None = None,
    trees: Iterable[str] | None = None,
) -> CacheReport:
    """One inventory pass over the cache root, plus residue classification."""
    cache_root = root or cache_home()
    subtrees: list[SubtreeUsage] = []
    if cache_root.is_dir():
        try:
            children = sorted(cache_root.iterdir())
        except OSError:
            children = []
        for child in children:
            try:
                st = child.lstat()
            except OSError:
                continue
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
                continue
            subtrees.append(_subtree_usage(child, child.name))

    residue = classify_residue(
        older_than_seconds=older_than_seconds, now=now, root=cache_root,
        trees=trees,
    )
    return CacheReport(
        root=cache_root,
        subtrees=tuple(subtrees),
        total_bytes=sum(s.bytes for s in subtrees),
        total_apparent_bytes=sum(s.apparent_bytes for s in subtrees),
        total_files=sum(s.files for s in subtrees),
        residue=residue,
    )


def unmanaged_subtree_names(root: Path | None = None) -> list[str]:
    """Names of existing cache subtrees no qmu command fully reclaims.

    Cheap: ``is_dir()`` per known name, no walk. ``prune`` calls this on every
    branch so it stops implying it cleaned a cache it cannot reach, without
    paying the ~2 s a real inventory costs on a 600k-file cache.
    """
    cache_root = root or cache_home()
    names: list[str] = []
    for name in KNOWN_SUBTREES:
        if name == "instances":
            continue
        try:
            if (cache_root / name).is_dir():
                names.append(name)
        except OSError:
            continue
    return names


def cache_root_is_sane(root: Path | None = None) -> bool:
    """True when the root looks like a qmu cache.

    ``QMU_CACHE_DIR`` is honoured with no validation (``paths.py``), so a typo
    pointing at ``$HOME`` must not be actionable. The residue classifier is
    already scoped to ``kernels/src/linux-*/``, so this is a second line rather
    than the load-bearing guard.
    """
    cache_root = root or cache_home()
    if not cache_root.is_dir():
        return False
    if cache_root == Path(cache_root.anchor):
        return False
    return any((cache_root / name).is_dir() for name in KNOWN_SUBTREES)


def remove_items(items: Iterable[ReclaimItem]) -> tuple[list[ReclaimItem], list[tuple[ReclaimItem, str]]]:
    """Unlink the given items. Returns (removed, failed).

    ``failed`` exists because classification cannot be the last word: permissions
    can change between the scan and the unlink, and the emitted result must be
    *what happened*, not what was planned. Folding a failure silently into
    ``removed`` would re-create preview-disagrees-with-real one layer up, at the
    reporting layer.

    The pre-unlink ``lstat`` re-check covers **file-identity** TOCTOU — the leaf
    replaced by a symlink, a directory, or a different inode. It does not cover
    permission TOCTOU: unlink permission lives on the parent directory and a
    leaf ``lstat`` says nothing about it.
    """
    removed: list[ReclaimItem] = []
    failed: list[tuple[ReclaimItem, str]] = []
    try:
        root = cache_home().resolve()
    except OSError as exc:
        return removed, [(item, str(exc)) for item in items]

    for item in items:
        path = item.path
        try:
            # Containment on the *parent*, resolved. Never resolve() the leaf:
            # kernels/src/linux-*/vmlinux-gdb.py are dangling absolute symlinks
            # to the container path /src/..., and resolving those lands outside
            # the cache. Prior art: runtime.py's spill containment check.
            parent = path.parent.resolve()
            if not parent.is_relative_to(root):
                failed.append((item, "outside the qmu cache"))
                continue
        except OSError as exc:
            failed.append((item, str(exc)))
            continue

        try:
            st = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            failed.append((item, str(exc)))
            continue
        if not stat.S_ISREG(st.st_mode):
            failed.append((item, "no longer a regular file"))
            continue

        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            failed.append((item, exc.strerror or str(exc)))
            continue
        removed.append(item)

    return removed, failed


def human_bytes(value: int) -> str:
    """Render a byte count the way `du -h` does, for text output."""
    step = 1024.0
    size = float(value)
    for unit in ("B", "K", "M", "G", "T"):
        if abs(size) < step or unit == "T":
            if unit == "B":
                return f"{int(size)}B"
            return f"{size:.1f}{unit}"
        size /= step
    return f"{size:.1f}T"  # pragma: no cover


def instances_subtree_path() -> Path:
    return instances_dir()


def source_tree_names(root: Path | None = None) -> list[str]:
    """Names of the kernel source trees present, for --tree validation.

    Exists so an unknown --tree names what does exist rather than reporting
    "not found" for something `qmu cache ls` is displaying.
    """
    src_root = (root or cache_home()) / "kernels" / "src"
    if not src_root.is_dir():
        return []
    try:
        return sorted(
            d.name for d in src_root.iterdir()
            if d.is_dir() and not d.is_symlink() and _SOURCE_DIR_RE.match(d.name)
        )
    except OSError:
        return []
