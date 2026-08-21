"""Domain tests for cache inventory and build-residue classification.

The regression these guard against is not hypothetical. An earlier revision of
this feature classified residue by filename glob and located built kernels by
looking for an image directly under ``kernels/<version>/``. Both were wrong:
``kbuild.sh`` writes the image to ``kernels/<version>/<arch>/``, and four source
trees on the developer's own machine hold the ONLY copy of their ``vmlinux`` /
``System.map`` / ``arch/*/boot/Image`` because kbuild's ``make scripts_gdb`` step
fails on 4.x under ``pipefail`` and aborts before the artifact copy. The
combination would have deleted every source tree in the cache.
"""

from __future__ import annotations

import os
import stat

import pytest

from qmu import cache


def _tree(root, name, *, with_vmlinux=True):
    """Build a source tree shaped like a real post-build kbuild tree."""
    src = root / "kernels" / "src" / name
    (src / "kernel").mkdir(parents=True)
    (src / "arch" / "arm64" / "boot").mkdir(parents=True)
    (src / "include" / "generated").mkdir(parents=True)

    # Protected: must survive every predicate.
    (src / "Makefile").write_text("# kbuild\n")
    (src / ".config").write_text("CONFIG_X=y\n")
    (src / "System.map").write_text("ffffffff81000000 T _text\n")
    (src / "arch" / "arm64" / "boot" / "Image").write_bytes(b"\x00" * 512)
    (src / "arch" / "arm64" / "boot" / "Image.gz").write_bytes(b"\x00" * 128)
    if with_vmlinux:
        (src / "vmlinux").write_bytes(b"\x7fELF" + b"\x00" * 256)
        (src / "vmlinux.unstripped").write_bytes(b"\x7fELF" + b"\x00" * 1024)

    # Residue: must be selected.
    (src / "kernel" / "fork.o").write_bytes(b"o" * 100)
    (src / "kernel" / ".fork.o.cmd").write_text("savedcmd_x := gcc\n")
    (src / "built-in.a").write_bytes(b"a" * 100)
    (src / "kernel" / "mod.ko").write_bytes(b"k" * 100)
    (src / "kernel" / "x.mod").write_text("x\n")
    (src / "kernel" / "x.mod.c").write_text("x\n")
    (src / "kernel" / "x.symtypes").write_text("x\n")
    if with_vmlinux:
        (src / ".tmp_vmlinux1").write_bytes(b"t" * 100)
    return src


PROTECTED = (
    "Makefile", ".config", "System.map", "vmlinux", "vmlinux.unstripped",
)


@pytest.fixture
def cache_root(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    (tmp_path / "instances").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# classification safety — the data-loss regressions
# ---------------------------------------------------------------------------


def test_classifier_never_selects_a_protected_artifact(cache_root):
    _tree(cache_root, "linux-6.6.75")
    report = cache.classify_residue(older_than_seconds=0.0)

    names = {item.path.name for item in report.items}
    for protected in PROTECTED:
        assert protected not in names, f"{protected} must never be residue"
    assert not any("/boot/" in str(item.path) for item in report.items)
    assert report.total.files > 0, "fixture produced no residue at all"


def test_regression_source_tree_holding_the_only_kernel_copy_is_preserved(cache_root):
    """kbuild's scripts_gdb failure on 4.x leaves the tree as the only copy.

    ``kernels/<ver>/<arch>/`` holds just a build.log; the built ``vmlinux``,
    ``System.map`` and ``Image`` live only in the source tree. An earlier design
    flagged exactly this shape for whole-tree deletion.
    """
    src = _tree(cache_root, "linux-4.14.336")
    outdir = cache_root / "kernels" / "4.14.336" / "arm64"
    outdir.mkdir(parents=True)
    (outdir / "build.log").write_text(
        "make: *** No rule to make target 'scripts_gdb'.  Stop.\n"
    )

    before = {p.name: p.read_bytes() for p in src.iterdir() if p.is_file()}
    report = cache.classify_residue(older_than_seconds=0.0)
    removed, failed = cache.remove_items(report.bucket_items(cache.BUCKET_ELIGIBLE))

    assert removed and not failed
    assert src.is_dir(), "the source tree itself must never be removed"
    for name in PROTECTED:
        assert (src / name).is_file(), f"{name} was destroyed"
        assert (src / name).read_bytes() == before[name]
    assert (src / "arch" / "arm64" / "boot" / "Image").is_file()


def test_kbuild_cache_validity_survives_a_clean(cache_root):
    """After reclaiming residue, build_cache_complete()'s source requirement holds."""
    src = _tree(cache_root, "linux-7.0")
    report = cache.classify_residue(older_than_seconds=0.0)
    cache.remove_items(report.bucket_items(cache.BUCKET_ELIGIBLE))
    # kbuild.sh:229 -- the only thing it needs from the source tree.
    assert (src / "Makefile").is_file()
    assert (src / ".config").is_file()


def test_symlinks_are_never_selected_and_do_not_abort_the_scan(cache_root):
    """kernels/src/linux-*/vmlinux-gdb.py is a dangling absolute container path."""
    src = _tree(cache_root, "linux-7.0.12")
    (src / "vmlinux-gdb.py").symlink_to("/src/scripts/gdb/vmlinux-gdb.py")
    (src / "kernel" / "alias.o").symlink_to("/src/kernel/fork.o")
    outside = cache_root.parent / "outside.o"
    outside.write_bytes(b"x" * 64)
    (src / "kernel" / "escape.o").symlink_to(outside)

    report = cache.classify_residue(older_than_seconds=0.0)
    for item in report.items:
        assert not item.path.is_symlink()
    assert report.total.files > 0
    cache.remove_items(report.bucket_items(cache.BUCKET_ELIGIBLE))
    assert outside.is_file(), "a symlink target outside the cache was followed"


def test_vmlinux_unstripped_is_never_selected_even_alone(cache_root):
    src = cache_root / "kernels" / "src" / "linux-9.9"
    src.mkdir(parents=True)
    (src / "Makefile").write_text("x\n")
    (src / "vmlinux.unstripped").write_bytes(b"\x7fELF")
    report = cache.classify_residue(older_than_seconds=0.0)
    assert report.total.files == 0


def test_tmp_vmlinux_is_gated_on_a_real_vmlinux_existing(cache_root):
    """A .tmp_vmlinux1 is a complete pre-kallsyms ELF; without a vmlinux it is
    the only near-complete one, so it must not be reclaimed."""
    src = cache_root / "kernels" / "src" / "linux-8.8"
    (src / "kernel").mkdir(parents=True)
    (src / "Makefile").write_text("x\n")
    (src / ".tmp_vmlinux1").write_bytes(b"t" * 100)
    (src / "kernel" / "a.o").write_bytes(b"o" * 10)

    report = cache.classify_residue(older_than_seconds=0.0)
    names = {i.path.name for i in report.items}
    assert ".tmp_vmlinux1" not in names
    assert "a.o" in names


# ---------------------------------------------------------------------------
# buckets
# ---------------------------------------------------------------------------


def test_buckets_partition_the_total(cache_root):
    _tree(cache_root, "linux-6.6.75")
    _tree(cache_root, "linux-7.0")
    report = cache.classify_residue(older_than_seconds=0.0)
    assert report.total.bytes == (
        report.eligible.bytes + report.held_back.bytes + report.refused.bytes
    )
    assert report.total.files == (
        report.eligible.files + report.held_back.files + report.refused.files
    )


def test_age_gate_holds_back_a_freshly_touched_tree(cache_root):
    _tree(cache_root, "linux-7.0")
    held = cache.classify_residue(older_than_seconds=86400.0)
    assert held.held_back.files > 0
    assert held.eligible.files == 0
    assert "linux-7.0" in held.held_back.groups

    now_open = cache.classify_residue(older_than_seconds=0.0)
    assert now_open.eligible.files > 0
    assert now_open.held_back.files == 0


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory write bits")
def test_unwritable_parent_refuses_per_file_not_per_tree(cache_root):
    """Refusal is per-file. Whole-group refusal would forfeit a whole tree to
    protect a handful of files -- on the developer's cache, 1.47 GB to protect
    27 files."""
    src = _tree(cache_root, "linux-4.14.75")
    locked = src / "include" / "generated"
    (locked / "trapped.o").write_bytes(b"o" * 50)
    os.chmod(locked, 0o555)
    try:
        report = cache.classify_residue(older_than_seconds=0.0)
        refused_names = {i.path.name for i in report.bucket_items(cache.BUCKET_REFUSED)}
        eligible_names = {i.path.name for i in report.bucket_items(cache.BUCKET_ELIGIBLE)}
        assert "trapped.o" in refused_names
        assert "fork.o" in eligible_names, "per-file refusal, not per-tree"
        assert report.refused.reasons
    finally:
        os.chmod(locked, 0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory write bits")
def test_refused_beats_held_back_so_buckets_stay_disjoint(cache_root):
    """A tree that is both fresh AND partly unwritable must still partition."""
    src = _tree(cache_root, "linux-7.0")
    locked = src / "include" / "generated"
    (locked / "trapped.o").write_bytes(b"o" * 50)
    os.chmod(locked, 0o555)
    try:
        report = cache.classify_residue(older_than_seconds=86400.0)
        buckets = {i.path: i.bucket for i in report.items}
        assert buckets[locked / "trapped.o"] == cache.BUCKET_REFUSED
        assert report.total.bytes == (
            report.eligible.bytes + report.held_back.bytes + report.refused.bytes
        )
    finally:
        os.chmod(locked, 0o755)


def test_instance_referenced_paths_are_refused(cache_root, monkeypatch):
    src = _tree(cache_root, "linux-7.0")
    target = src / "kernel" / "fork.o"

    class _Rec:
        kernel = str(target)
        rootfs = None
        ssh_key = None

    monkeypatch.setattr(cache, "_instance_referenced_paths",
                        lambda: {target.resolve()})
    report = cache.classify_residue(older_than_seconds=0.0)
    by_path = {i.path: i for i in report.items}
    assert by_path[target].bucket == cache.BUCKET_REFUSED
    assert "instance record" in by_path[target].reason


# ---------------------------------------------------------------------------
# accounting
# ---------------------------------------------------------------------------


def test_sizes_are_allocated_not_apparent_for_sparse_files(cache_root):
    """targets/ and rootfs/ hold sparse ext4 images. Summing st_size overstates
    a real cache by ~70%, concentrated in exactly the subtrees a reader would
    then wrongly delete."""
    d = cache_root / "targets" / "ubuntu" / "noble" / "x86_64" / "6.8.0-31"
    d.mkdir(parents=True)
    img = d / "rootfs.img"
    with open(img, "wb") as fh:
        fh.truncate(512 * 1024 * 1024)   # 512 MiB apparent, ~0 allocated

    st = os.stat(img)
    if st.st_blocks * 512 >= st.st_size:
        pytest.skip("filesystem does not support sparse files")

    report = cache.scan_cache(older_than_seconds=0.0)
    targets = next(s for s in report.subtrees if s.name == "targets")
    assert targets.apparent_bytes >= 512 * 1024 * 1024
    assert targets.bytes < targets.apparent_bytes / 2
    assert targets.bytes == st.st_blocks * 512


def test_unknown_subtrees_are_reported_never_hidden(cache_root):
    (cache_root / "mystery").mkdir()
    (cache_root / "mystery" / "big.bin").write_bytes(b"x" * 4096)
    report = cache.scan_cache(older_than_seconds=0.0)
    names = {s.name: s for s in report.subtrees}
    assert "mystery" in names
    assert names["mystery"].known is False
    assert names["mystery"].managed_by == ""
    assert report.total_bytes >= names["mystery"].bytes


def test_instances_is_marked_managed_and_others_are_not(cache_root):
    (cache_root / "rootfs").mkdir()
    report = cache.scan_cache(older_than_seconds=0.0)
    by = {s.name: s for s in report.subtrees}
    assert by["instances"].managed_by
    assert by["rootfs"].managed_by == ""
    assert "rootfs" in cache.unmanaged_subtree_names()
    assert "instances" not in cache.unmanaged_subtree_names()


def test_empty_and_absent_cache_do_not_raise(cache_root):
    report = cache.scan_cache(older_than_seconds=0.0)
    assert report.residue.total.files == 0
    assert report.total_bytes >= 0


def test_negative_age_is_rejected(cache_root):
    with pytest.raises(ValueError):
        cache.classify_residue(older_than_seconds=-1.0)


# ---------------------------------------------------------------------------
# deletion safety
# ---------------------------------------------------------------------------


def test_remove_items_reports_what_happened_not_what_was_planned(cache_root):
    src = _tree(cache_root, "linux-7.0")
    report = cache.classify_residue(older_than_seconds=0.0)
    planned = report.bucket_items(cache.BUCKET_ELIGIBLE)
    # Vanish one file between classification and deletion.
    (src / "kernel" / "fork.o").unlink()
    removed, failed = cache.remove_items(planned)
    assert len(removed) == len(planned) - 1
    assert all(not i.path.exists() for i in removed)


def test_remove_items_refuses_paths_outside_the_cache(cache_root, tmp_path):
    outside = tmp_path.parent / "not-the-cache.o"
    outside.write_bytes(b"x" * 10)
    item = cache.ReclaimItem(
        path=outside, bytes=10, group="x", bucket=cache.BUCKET_ELIGIBLE, reason=""
    )
    removed, failed = cache.remove_items([item])
    assert removed == []
    assert failed and "outside" in failed[0][1]
    assert outside.is_file()


def test_remove_items_skips_a_leaf_swapped_for_a_directory(cache_root):
    src = _tree(cache_root, "linux-7.0")
    report = cache.classify_residue(older_than_seconds=0.0)
    victim = next(i for i in report.bucket_items(cache.BUCKET_ELIGIBLE)
                  if i.path.name == "fork.o")
    victim.path.unlink()
    victim.path.mkdir()
    removed, failed = cache.remove_items([victim])
    assert removed == []
    assert failed and "regular file" in failed[0][1]
    assert victim.path.is_dir()


def test_cache_root_sanity_gate(cache_root, tmp_path):
    assert cache.cache_root_is_sane(cache_root)
    bare = tmp_path / "empty-elsewhere"
    bare.mkdir()
    assert not cache.cache_root_is_sane(bare)
