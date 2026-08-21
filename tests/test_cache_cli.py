"""CLI tests for `qmu cache du|ls` and `qmu prune --build-residue`.

The invariant these exist to hold is cross-command: `cache du`, `cache ls` and
`prune --build-residue` all classify through one function, so at the same
``--older-than`` they must report the same buckets. An earlier revision pinned
``du``'s single total equal to the dry-run total, which was unsatisfiable in the
field (the prune side filters by age, in-use and writability) while passing in
CI on a fixture that happened to trigger none of them.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from qmu import cache as cache_mod
from qmu import cli


def _tree(root, name):
    src = root / "kernels" / "src" / name
    (src / "kernel").mkdir(parents=True)
    (src / "arch" / "x86" / "boot").mkdir(parents=True)
    (src / "Makefile").write_text("# kbuild\n")
    (src / ".config").write_text("CONFIG_X=y\n")
    (src / "vmlinux").write_bytes(b"\x7fELF" + b"\x00" * 512)
    (src / "System.map").write_text("ffffffff81000000 T _text\n")
    (src / "arch" / "x86" / "boot" / "bzImage").write_bytes(b"\x00" * 256)
    for i in range(4):
        (src / "kernel" / f"f{i}.o").write_bytes(b"o" * 1000)
        (src / "kernel" / f".f{i}.o.cmd").write_text("savedcmd := gcc\n")
    return src


@pytest.fixture
def cache_root(tmp_path, monkeypatch):
    monkeypatch.setenv("QMU_CACHE_DIR", str(tmp_path))
    (tmp_path / "instances").mkdir()
    return tmp_path


def _json(capsys):
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# cache du / ls
# ---------------------------------------------------------------------------


def test_bare_cache_prints_group_help_and_exits_2(cache_root, capsys):
    assert cli.main(["cache"]) == 2
    assert "du" in capsys.readouterr().err


def test_cache_du_json_envelope(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    assert cli.main(["cache", "du", "--older-than", "0", "--format", "json"]) == 0
    data = _json(capsys)
    assert data["ok"] is True
    assert data["cache_dir"] == str(cache_root)
    assert {"total_bytes", "total_apparent_bytes", "total_files", "subtrees",
            "build_residue"} <= set(data)
    residue = data["build_residue"]
    for bucket in ("total", "eligible", "held_back", "refused"):
        assert {"groups", "bytes", "files", "reasons"} <= set(residue[bucket])
    assert residue["total"]["bytes"] == (
        residue["eligible"]["bytes"] + residue["held_back"]["bytes"]
        + residue["refused"]["bytes"]
    )


def test_cache_du_marks_unmanaged_subtrees(cache_root, capsys):
    (cache_root / "targets").mkdir()
    cli.main(["cache", "du", "--format", "json"])
    subtrees = {s["name"]: s for s in _json(capsys)["subtrees"]}
    assert subtrees["instances"]["managed_by"]
    assert subtrees["targets"]["managed_by"] == ""


def test_cache_du_text_names_the_reclaim_command(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    cli.main(["cache", "du", "--older-than", "0"])
    out = capsys.readouterr().out
    assert "prune --build-residue" in out
    assert "NOT reclaimable by any qmu command" not in out or "targets" in out


def test_cache_du_and_prune_dry_run_agree_bucket_for_bucket(cache_root, capsys):
    """The cross-command invariant. Same --older-than -> same buckets."""
    _tree(cache_root, "linux-7.0")
    _tree(cache_root, "linux-6.6.75")
    age = str(cache_mod.MIN_BUILD_RESIDUE_AGE)

    cli.main(["cache", "du", "--older-than", age, "--format", "json"])
    du = _json(capsys)["build_residue"]

    cli.main(["prune", "--build-residue", "--older-than", age,
              "--dry-run", "--format", "json"])
    pr = _json(capsys)["build_residue"]

    for bucket in ("total", "eligible", "held_back", "refused"):
        assert du[bucket]["bytes"] == pr[bucket]["bytes"], bucket
        assert du[bucket]["files"] == pr[bucket]["files"], bucket
        assert sorted(du[bucket]["groups"]) == sorted(pr[bucket]["groups"]), bucket


def test_cache_ls_discloses_truncation(cache_root, capsys):
    for n in range(4):
        _tree(cache_root, f"linux-7.{n}")
    cli.main(["cache", "ls", "--older-than", "0", "--top", "2", "--format", "json"])
    payload = _json(capsys)["build_residue"]["eligible"]
    assert payload["shown"] == 2
    assert payload["truncated"]["groups"] == 2
    assert payload["truncated"]["bytes"] > 0
    # A truncated listing must not appear to disagree with du's total.
    shown = sum(g["bytes"] for g in payload["groups"])
    assert shown + payload["truncated"]["bytes"] == payload["bytes"]


def test_cache_ls_text_discloses_truncation(cache_root, capsys):
    for n in range(4):
        _tree(cache_root, f"linux-7.{n}")
    cli.main(["cache", "ls", "--older-than", "0", "--top", "1"])
    out = capsys.readouterr().out
    assert "withheld by --top 1" in out
    assert "--top 0 to see them all" in out


def test_cache_ls_untruncated_sums_match_du(cache_root, capsys):
    for n in range(3):
        _tree(cache_root, f"linux-7.{n}")
    cli.main(["cache", "ls", "--older-than", "0", "--top", "99",
              "--bucket", "all", "--format", "json"])
    ls = _json(capsys)["build_residue"]
    cli.main(["cache", "du", "--older-than", "0", "--format", "json"])
    du = _json(capsys)["build_residue"]
    for bucket in ("eligible", "held_back", "refused"):
        assert sum(g["bytes"] for g in ls[bucket]["groups"]) == du[bucket]["bytes"]
        assert ls[bucket]["truncated"]["groups"] == 0


def test_cache_read_only_commands_accept_an_age_below_prunes_floor(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    assert cli.main(["cache", "du", "--older-than", "0", "--format", "json"]) == 0
    data = _json(capsys)
    assert "note" in data and "floor" in data["note"]
    # ...while prune refuses the same value.
    assert cli.main(["prune", "--build-residue", "--older-than", "0"]) == 1


def test_cache_format_json_honored_before_and_after_subcommand(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    cli.main(["--format", "json", "cache", "du"])
    assert _json(capsys)["ok"] is True
    cli.main(["cache", "du", "--format", "json"])
    assert _json(capsys)["ok"] is True


def test_cache_ls_rejects_negative_top(cache_root):
    assert cli.main(["cache", "ls", "--top", "-1"]) == 1


def test_cache_ls_top_zero_means_no_limit(cache_root, capsys):
    for n in range(3):
        _tree(cache_root, f"linux-7.{n}")
    cli.main(["cache", "ls", "--older-than", "0", "--top", "0", "--format", "json"])
    payload = _json(capsys)["build_residue"]["eligible"]
    assert payload["shown"] == 3
    assert payload["truncated"]["groups"] == 0


# ---------------------------------------------------------------------------
# prune --build-residue
# ---------------------------------------------------------------------------


def test_dry_run_removes_nothing_and_predicts_the_real_run_exactly(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    _tree(cache_root, "linux-6.6.75")
    age = str(cache_mod.MIN_BUILD_RESIDUE_AGE)

    before = sorted(str(p) for p in cache_root.rglob("*") if p.is_file())
    assert cli.main(["prune", "--build-residue", "--older-than", age,
                     "--dry-run", "--format", "json"]) == 0
    preview = _json(capsys)
    assert preview["dry_run"] is True
    assert sorted(str(p) for p in cache_root.rglob("*") if p.is_file()) == before

    assert cli.main(["prune", "--build-residue", "--older-than", age,
                     "--format", "json"]) == 0
    real = _json(capsys)
    assert real["dry_run"] is False

    predicted = {i["path"] for i in preview["build_residue"]["would_remove"]}
    removed = {i["path"] for i in real["build_residue"]["removed"]}
    assert predicted == removed
    assert real["build_residue"]["bytes_removed"] == (
        preview["build_residue"]["eligible"]["bytes"]
    )
    assert real["build_residue"]["files_removed"] == (
        preview["build_residue"]["eligible"]["files"]
    )


def test_removed_reflects_what_was_unlinked_not_what_was_planned(cache_root, capsys):
    """A failure after classification must not be reported as a removal."""
    src = _tree(cache_root, "linux-7.0")
    age = str(cache_mod.MIN_BUILD_RESIDUE_AGE)
    cli.main(["prune", "--build-residue", "--older-than", age, "--format", "json"])
    real = _json(capsys)
    for entry in real["build_residue"]["removed"]:
        assert not os.path.exists(entry["path"])
    assert (src / "vmlinux").is_file()
    assert (src / "System.map").is_file()
    assert (src / "Makefile").is_file()


def test_build_residue_envelope_nests_and_does_not_reuse_top_level_held_back(
    cache_root, capsys
):
    """`prune --all` puts VM ids in top-level held_back; this mode puts source
    tree names in a nested one. Sharing the key would make them unparseable."""
    _tree(cache_root, "linux-7.0")
    cli.main(["prune", "--build-residue", "--dry-run", "--format", "json"])
    data = _json(capsys)
    assert "held_back" not in data, "must not collide with the instance-prune key"
    assert "build_residue" in data
    assert "held_back" in data["build_residue"]
    assert {"ok", "dry_run", "build_residue", "unmanaged_cache"} <= set(data)


def test_age_floor_is_refused_not_clamped(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    assert cli.main(["prune", "--build-residue", "--older-than", "0"]) == 1
    capsys.readouterr()
    assert cli.main(["prune", "--build-residue", "--older-than", "599",
                     "--format", "json"]) == 1
    payload = _json(capsys)
    assert payload["ok"] is False
    assert "floor" in payload["error"]
    # Nothing was removed by the refused invocation.
    assert list((cache_root / "kernels" / "src" / "linux-7.0" / "kernel").glob("*.o"))


def test_held_back_message_never_prescribes_older_than_zero(cache_root, capsys):
    """Instance pruning tells you to re-run with --older-than 0. For build
    residue that flag disables the only guard against a live build."""
    _tree(cache_root, "linux-7.0")
    cli.main(["prune", "--build-residue", "--dry-run"])
    out = capsys.readouterr().out
    assert "Held back" in out
    assert "--older-than 0" not in out


def test_keep_logs_is_rejected(cache_root):
    assert cli.main(["prune", "--build-residue", "--keep-logs"]) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory write bits")
def test_refused_group_still_exits_zero(cache_root, capsys):
    """A partial refusal is a reported outcome, not a failure -- otherwise
    scripted use breaks on any cache holding one root-owned tree."""
    src = _tree(cache_root, "linux-7.0")
    locked = src / "kernel" / "locked"
    locked.mkdir()
    (locked / "trapped.o").write_bytes(b"o" * 100)
    os.chmod(locked, 0o555)
    try:
        rc = cli.main(["prune", "--build-residue", "--older-than",
                       str(cache_mod.MIN_BUILD_RESIDUE_AGE), "--format", "json"])
        data = _json(capsys)
        assert rc == 0
        assert data["ok"] is True
        assert data["build_residue"]["refused"]["files"] >= 1
        assert (locked / "trapped.o").is_file()
    finally:
        os.chmod(locked, 0o755)


def test_nothing_to_do_is_honest(cache_root, capsys):
    assert cli.main(["prune", "--build-residue", "--dry-run"]) == 0
    assert "No build residue is eligible" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# mode enumeration must not drift
# ---------------------------------------------------------------------------


def test_previewable_mode_enumeration_matches_reality(cache_root, capsys):
    """Five strings used to enumerate prune's modes by hand. They are now
    generated from one table; this pins that the generated text names every
    mode that actually supports --dry-run."""
    from qmu.commands import lifecycle

    phrase = lifecycle._previewable_modes_phrase()
    for flag, previewable in lifecycle._PRUNE_MODES:
        bare = flag.split()[0]
        if previewable:
            assert bare in phrase, f"{bare} supports --dry-run but is not named"
        else:
            assert f"not {bare}" in phrase or bare in phrase

    # The --runtime refusal must hand the caller the real list.
    assert cli.main(["prune", "--runtime", "--dry-run"]) == 1
    captured = capsys.readouterr()
    assert "--build-residue" in captured.out + captured.err


def test_specify_a_mode_names_every_mode(cache_root, capsys):
    from qmu.commands import lifecycle

    assert cli.main(["prune"]) == 1
    captured = capsys.readouterr()
    text = captured.out + captured.err
    for flag, _ in lifecycle._PRUNE_MODES:
        assert flag.split()[0] in text


def test_per_file_detail_is_capped_and_disclosed(cache_root, capsys):
    """Dogfooding finding: on the real cache the eligible set is ~56k files,
    which rendered a 12.7 MB / ~3.2M-token envelope -- 317x the spill limit --
    so `--dry-run --format json` spilled and was unusable inline. The totals are
    what a caller branches on; the path list is detail."""
    from qmu.commands import lifecycle

    src = cache_root / "kernels" / "src" / "linux-7.0"
    (src / "kernel").mkdir(parents=True)
    (src / "Makefile").write_text("x\n")
    (src / "vmlinux").write_bytes(b"\x7fELF")
    n = lifecycle._MAX_ITEM_DETAIL + 25
    for i in range(n):
        (src / "kernel" / f"f{i}.o").write_bytes(b"o" * 64)
    # Backdate so the tree is eligible rather than held back by the age gate.
    stamp = time.time() - 7200
    for path in sorted(src.rglob("*"), reverse=True):
        os.utime(path, (stamp, stamp))
    os.utime(src, (stamp, stamp))

    cli.main(["prune", "--build-residue",
              "--older-than", str(cache_mod.MIN_BUILD_RESIDUE_AGE),
              "--dry-run", "--format", "json"])
    residue = _json(capsys)["build_residue"]

    assert len(residue["would_remove"]) == lifecycle._MAX_ITEM_DETAIL
    assert residue["would_remove_truncated"]["files"] == 25
    assert residue["would_remove_truncated"]["bytes"] > 0
    assert "capped" in residue["would_remove_truncated"]["hint"]
    # The totals stay complete -- that is the point of capping detail, not totals.
    assert residue["eligible"]["files"] == n


# ---------------------------------------------------------------------------
# --tree: a narrowing filter, added because dogfooding wanted one tree at a time
# ---------------------------------------------------------------------------


def test_tree_filter_narrows_and_never_widens(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    _tree(cache_root, "linux-6.6.75")

    cli.main(["cache", "du", "--older-than", "0", "--format", "json"])
    everything = _json(capsys)["build_residue"]["total"]

    cli.main(["cache", "du", "--older-than", "0", "--tree", "linux-7.0",
              "--format", "json"])
    one = _json(capsys)["build_residue"]["total"]

    assert one["groups"] == ["linux-7.0"]
    assert 0 < one["bytes"] < everything["bytes"]


def test_tree_filter_keeps_du_and_prune_in_agreement(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    _tree(cache_root, "linux-6.6.75")
    age = str(cache_mod.MIN_BUILD_RESIDUE_AGE)

    cli.main(["cache", "du", "--older-than", age, "--tree", "linux-7.0",
              "--format", "json"])
    du = _json(capsys)["build_residue"]
    cli.main(["prune", "--build-residue", "--older-than", age,
              "--tree", "linux-7.0", "--dry-run", "--format", "json"])
    pr = _json(capsys)["build_residue"]

    for bucket in ("total", "eligible", "held_back", "refused"):
        assert du[bucket]["bytes"] == pr[bucket]["bytes"], bucket
        assert sorted(du[bucket]["groups"]) == sorted(pr[bucket]["groups"]), bucket


def test_tree_filter_leaves_other_trees_untouched(cache_root):
    keep = _tree(cache_root, "linux-6.6.75")
    drop = _tree(cache_root, "linux-7.0")
    stamp = time.time() - 7200
    for src in (keep, drop):
        for path in sorted(src.rglob("*"), reverse=True):
            os.utime(path, (stamp, stamp))
        os.utime(src, (stamp, stamp))

    assert cli.main(["prune", "--build-residue", "--older-than",
                     str(cache_mod.MIN_BUILD_RESIDUE_AGE),
                     "--tree", "linux-7.0"]) == 0

    assert not list((drop / "kernel").glob("*.o"))
    assert list((keep / "kernel").glob("*.o")), "an unfiltered tree was touched"


def test_unknown_tree_names_the_trees_that_exist(cache_root, capsys):
    _tree(cache_root, "linux-7.0")
    assert cli.main(["prune", "--build-residue", "--tree", "linux-9.9"]) == 1
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "linux-7.0" in text, "must name what does exist"


def test_tree_is_rejected_on_modes_it_does_not_apply_to(cache_root):
    assert cli.main(["prune", "--all", "--tree", "linux-7.0"]) == 1
    assert cli.main(["prune", "--runtime", "--tree", "linux-7.0"]) == 1
