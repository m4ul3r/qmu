from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

MKROOTFS = Path(__file__).resolve().parents[1] / "tools" / "mkrootfs.sh"


class MkrootfsEnv:
    def __init__(self, tmp_path: Path):
        self.tmp_path = tmp_path
        self.fake_bin = tmp_path / "fake-bin"
        self.fake_bin.mkdir()
        self.scratch = tmp_path / "scratch-tmp"
        self.scratch.mkdir()
        self.outdir = tmp_path / "outdir"
        self.outdir.mkdir()
        self.calls = tmp_path / "call.log"
        self.calls.write_text("")
        self.private_key = tmp_path / "id_ed25519"
        self.private_key.write_text("PRIVATE\n")
        self.private_key.with_suffix(".pub").write_text(
            "ssh-ed25519 AAAA test@qmu\n"
        )
        self.cache = tmp_path / "cache"
        self.rootfs_cache = self.cache / "rootfs" / "bookworm"
        self.failing_stage: str | None = None
        self._write_docker_shim()
        self._write_sudo_shim()
        self._write_sshkeygen_shim()

    def _write_sshkeygen_shim(self) -> None:
        """A default-shaped run generates its own key, so the script calls
        ssh-keygen. Shim it: the tests must not depend on openssh being present,
        and the generated key never feeds the build digest anyway (only an
        explicit --ssh-key's public half is hashed, mkrootfs.sh:138-140)."""
        script = self.fake_bin / "ssh-keygen"
        script.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                out=""
                while [[ $# -gt 0 ]]; do
                  case "$1" in
                    -f) out="$2"; shift 2 ;;
                    *)  shift ;;
                  esac
                done
                [[ -n "$out" ]] || exit 9
                printf 'FAKE PRIVATE\\n' >"$out"
                printf 'ssh-ed25519 AAAAFAKE qmu-generated\\n' >"$out.pub"
                """
            )
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _write_docker_shim(self) -> None:
        script = self.fake_bin / "docker"
        script.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                CALL_LOG={self.calls!s}
                FAIL_STAGE=${{MKROOTFS_FAIL_STAGE:-}}
                STATE={self.tmp_path / "docker-state"!s}
                mkdir -p "$STATE"
                echo "docker $*" >>"$CALL_LOG"
                case "${{1:-}}" in
                  build)
                    exit 0
                    ;;
                  create)
                    echo "cid-test"
                    exit 0
                    ;;
                  export)
                    count_file="$STATE/export_count"
                    count=0
                    if [[ -f "$count_file" ]]; then
                      count="$(cat "$count_file")"
                    fi
                    count=$((count + 1))
                    echo "$count" >"$count_file"
                    if [[ "$FAIL_STAGE" == "export" && "$count" -ge 2 ]]; then
                      echo "docker export failed" >&2
                      exit 31
                    fi
                    # Minimal tar stream with one empty directory entry.
                    printf ''
                    # Produce a tiny empty tar (two 512-byte zero blocks).
                    dd if=/dev/zero bs=512 count=2 status=none 2>/dev/null || \\
                      python3 -c 'import sys; sys.stdout.buffer.write(b"\\\\x00"*1024)'
                    exit 0
                    ;;
                  run)
                    # Helper pipeline: docker run --rm -i ...
                    if [[ " $* " == *" --rm "* ]]; then
                      echo "helper mke2fs failed" >&2
                      exit 23
                    fi
                    exit 0
                    ;;
                  rm)
                    echo "docker rm $*" >>"$CALL_LOG"
                    exit 0
                    ;;
                  *)
                    exit 0
                    ;;
                esac
                """
            )
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _write_sudo_shim(self) -> None:
        script = self.fake_bin / "sudo"
        outdir = self.outdir
        script.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                CALL_LOG={self.calls!s}
                FAIL_STAGE=${{MKROOTFS_FAIL_STAGE:-}}
                echo "sudo $*" >>"$CALL_LOG"
                case "${{1:-}}" in
                  tar)
                    if [[ "$FAIL_STAGE" == "tar" ]]; then
                      # Consume stdin then fail so pipefail trips.
                      cat >/dev/null || true
                      exit 41
                    fi
                    # Consume stdin successfully.
                    cat >/dev/null || true
                    exit 0
                    ;;
                  mke2fs)
                    if [[ "$FAIL_STAGE" == "mke2fs" ]]; then
                      exit 42
                    fi
                    # Last non-size arg before size is the image path.
                    img=""
                    for arg in "$@"; do
                      case "$arg" in
                        *.img*) img="$arg" ;;
                      esac
                    done
                    if [[ -n "$img" ]]; then
                      : >"$img"
                    else
                      : >"{outdir}/rootfs.img"
                    fi
                    exit 0
                    ;;
                  chown)
                    if [[ "$FAIL_STAGE" == "chown" ]]; then
                      exit 43
                    fi
                    exit 0
                    ;;
                  rm)
                    # sudo rm -rf -- <root>  (drop the leading "rm" from "$@")
                    shift
                    exec rm "$@"
                    ;;
                  *)
                    exit 0
                    ;;
                esac
                """
            )
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run(self, *, failing_stage: str | None = None) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env.get('PATH', '')}"
        env["TMPDIR"] = str(self.scratch)
        env["QMU_CACHE_DIR"] = str(self.tmp_path / "cache")
        if failing_stage is not None:
            env["MKROOTFS_FAIL_STAGE"] = failing_stage
        else:
            env.pop("MKROOTFS_FAIL_STAGE", None)
        # Reset docker export counter between runs.
        state = self.tmp_path / "docker-state"
        if state.exists():
            for child in state.iterdir():
                child.unlink()
        self.calls.write_text("")
        # Clear any prior rootfs image for clean assertions.
        img = self.outdir / "rootfs.img"
        if img.exists():
            img.unlink()
        result = subprocess.run(
            [
                "bash",
                str(MKROOTFS),
                "--outdir",
                str(self.outdir),
                "--ssh-key",
                str(self.private_key),
            ],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, self.scratch, self.calls

    def run_args(
        self,
        *args: str,
        failing_stage: str | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run mkrootfs.sh with arbitrary argv, in the fake-bin sandbox.

        Unlike run(), this passes no --outdir/--ssh-key of its own (so the
        cache-directory routing under QMU_CACHE_DIR is what is exercised) and
        deletes NO image, so a second call sees the first call's cache.
        `env_overrides` layers extra environment (e.g. QMU_ROOTFS_SIZE) on
        top of the sandboxed PATH/TMPDIR/QMU_CACHE_DIR.
        """
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env.get('PATH', '')}"
        env["TMPDIR"] = str(self.scratch)
        env["QMU_CACHE_DIR"] = str(self.cache)
        if failing_stage is not None:
            env["MKROOTFS_FAIL_STAGE"] = failing_stage
        else:
            env.pop("MKROOTFS_FAIL_STAGE", None)
        if env_overrides:
            env.update(env_overrides)
        state = self.tmp_path / "docker-state"
        if state.exists():
            for child in state.iterdir():
                child.unlink()
        self.calls.write_text("")
        return subprocess.run(
            ["bash", str(MKROOTFS), *args],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )


@pytest.fixture
def mkrootfs_env(tmp_path: Path) -> MkrootfsEnv:
    return MkrootfsEnv(tmp_path)


def test_mkrootfs_uses_sudo_fallback_when_helper_pipeline_fails(mkrootfs_env: MkrootfsEnv):
    result, scratch, calls = mkrootfs_env.run()

    assert result.returncode == 0, result.stderr
    assert "ext4 image creation failed (exit 23)" in result.stderr
    assert "fallback: trying sudo mke2fs..." in result.stderr
    assert f"ROOTFS={mkrootfs_env.outdir}/rootfs.img" in result.stdout.splitlines()
    assert f"SSH_KEY={mkrootfs_env.private_key}" in result.stdout.splitlines()
    log = calls.read_text()
    assert "sudo tar" in log
    assert "sudo mke2fs" in log
    assert "sudo chown" in log
    assert "docker rm cid-test" in log or "docker rm cid-test" in log.replace("  ", " ")
    assert "docker rm" in log and "cid-test" in log
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("failing_stage", ["export", "tar", "mke2fs", "chown"])
def test_mkrootfs_cleans_fallback_tempdir_when_fallback_stage_fails(
    failing_stage: str, mkrootfs_env: MkrootfsEnv
):
    result, scratch, calls = mkrootfs_env.run(failing_stage=failing_stage)
    assert result.returncode != 0
    log = calls.read_text()
    # Stage-specific evidence that the failing command was reached.
    if failing_stage == "export":
        assert "docker export" in log
    elif failing_stage == "tar":
        assert "sudo tar" in log
    elif failing_stage == "mke2fs":
        assert "sudo mke2fs" in log
    elif failing_stage == "chown":
        assert "sudo chown" in log
    assert "docker rm" in log and "cid-test" in log
    assert list(scratch.iterdir()) == []


# ---------------------------------------------------------------------------
# Cache-key contract (#51). Before this, EVERY build landed in
# <release>/<arch>/rootfs.img regardless of --packages/--size/--ssh-key, so the
# second request was served the first request's image with no warning. These
# pin the six behaviors that replaced it: keyed variant dirs, order-insensitive
# package normalization, a stamp-checked hit, a named mismatch rebuild, the
# legacy-image UNVERIFIED note, and .part atomicity.
# ---------------------------------------------------------------------------

VARIANT_DIR_RE = re.compile(r"/x86_64-[0-9a-f]{8}/rootfs\.img$")


def _rootfs_path(result: subprocess.CompletedProcess[str]) -> str:
    lines = [ln for ln in result.stdout.splitlines() if ln.startswith("ROOTFS=")]
    assert len(lines) == 1, f"expected one ROOTFS= line, got {result.stdout!r}"
    return lines[0].split("=", 1)[1]


def _built(env: MkrootfsEnv) -> bool:
    """The docker shim logs every invocation; `docker export` only happens on a
    real build, so its absence proves the run was served from cache."""
    return "docker export" in env.calls.read_text()


def test_default_and_packages_builds_use_distinct_dirs(mkrootfs_env: MkrootfsEnv):
    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    default_img = mkrootfs_env.rootfs_cache / "x86_64" / "rootfs.img"
    assert _rootfs_path(result) == str(default_img)
    assert default_img.is_file()
    stamp = (mkrootfs_env.rootfs_cache / "x86_64" / ".mkrootfs-stamp").read_text()
    assert "build_key=" in stamp

    keyed = mkrootfs_env.run_args("--packages", "strace,htop")
    assert keyed.returncode == 0, keyed.stderr
    keyed_path = _rootfs_path(keyed)
    assert VARIANT_DIR_RE.search(keyed_path), keyed_path
    assert keyed_path != str(default_img)
    assert _built(mkrootfs_env), "a new option shape must not be served from cache"
    assert "packages=strace,htop" in Path(keyed_path).with_name(".mkrootfs-stamp").read_text()


def test_package_order_does_not_change_cache_dir(mkrootfs_env: MkrootfsEnv):
    first = mkrootfs_env.run_args("--packages", "strace,htop")
    assert first.returncode == 0, first.stderr
    assert VARIANT_DIR_RE.search(_rootfs_path(first)), _rootfs_path(first)
    second = mkrootfs_env.run_args("--packages", "htop,strace")
    assert second.returncode == 0, second.stderr
    assert _rootfs_path(second) == _rootfs_path(first)
    assert "cached rootfs found" in second.stderr
    assert not _built(mkrootfs_env), "reordered packages must be a cache HIT"


def test_size_change_routes_to_keyed_dir(mkrootfs_env: MkrootfsEnv):
    result = mkrootfs_env.run_args("--size", "3G")
    assert result.returncode == 0, result.stderr
    path = _rootfs_path(result)
    assert VARIANT_DIR_RE.search(path), path
    assert "size=3G" in Path(path).with_name(".mkrootfs-stamp").read_text()


def test_stamped_hit_with_wrong_key_rebuilds_and_names_options(mkrootfs_env: MkrootfsEnv):
    first = mkrootfs_env.run_args("--packages", "strace")
    assert first.returncode == 0, first.stderr
    stamp = Path(_rootfs_path(first)).with_name(".mkrootfs-stamp")
    stamp.write_text(
        re.sub(r"^build_key=.*$", "build_key=deadbeef", stamp.read_text(), flags=re.M)
    )

    again = mkrootfs_env.run_args("--packages", "strace")
    assert again.returncode == 0, again.stderr
    assert "was built with different options than requested" in again.stderr
    assert "rebuilding with the requested options" in again.stderr
    assert _built(mkrootfs_env), "a key mismatch must rebuild, not serve"
    assert "build_key=deadbeef" not in stamp.read_text()


def test_legacy_unstamped_default_image_is_served_with_unverified_note(
    mkrootfs_env: MkrootfsEnv,
):
    legacy = mkrootfs_env.rootfs_cache / "x86_64"
    legacy.mkdir(parents=True)
    (legacy / "rootfs.img").write_bytes(b"")

    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    assert _rootfs_path(result) == str(legacy / "rootfs.img")
    assert "no completion stamp" in result.stderr
    assert "UNVERIFIED" in result.stderr
    assert not _built(mkrootfs_env), "a legacy default image stays valid"


def test_partial_image_is_never_served_and_interrupted_build_leaves_nothing(
    mkrootfs_env: MkrootfsEnv,
):
    target = mkrootfs_env.rootfs_cache / "x86_64"
    target.mkdir(parents=True)
    (target / "rootfs.img.part").write_bytes(b"truncated")

    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    assert _built(mkrootfs_env), "a .part image must never satisfy the cache gate"
    assert (target / "rootfs.img").is_file()
    assert not (target / "rootfs.img.part").exists()

    shutil.rmtree(mkrootfs_env.cache)
    failed = mkrootfs_env.run_args(failing_stage="mke2fs")
    assert failed.returncode != 0
    assert not (target / "rootfs.img").exists()
    assert not (target / ".mkrootfs-stamp").exists()


# ---------------------------------------------------------------------------
# #59-review findings: stamp/image publish coherence (P1), auto-generated
# ssh-key pinning, and the four previously-unpinned single-line clauses.
# ---------------------------------------------------------------------------


def test_failed_rebuild_after_mismatch_does_not_masquerade_as_legacy(
    mkrootfs_env: MkrootfsEnv,
):
    """P1: the completion stamp used to be deleted before a rebuild even
    started, so a mismatch-triggered rebuild that then failed left a GOOD
    but mismatched image with NO stamp -- which the legacy default-shape
    exception then served at exit 0 as merely 'UNVERIFIED', not what was
    actually requested. The (image, stamp) pair must stay coherent until a
    replacement build actually succeeds."""
    outdir = mkrootfs_env.tmp_path / "shared-outdir"
    built = mkrootfs_env.run_args("--outdir", str(outdir), "--packages", "strace")
    assert built.returncode == 0, built.stderr
    stamp = outdir / ".mkrootfs-stamp"
    assert "packages=strace" in stamp.read_text()

    failed = mkrootfs_env.run_args("--outdir", str(outdir), failing_stage="mke2fs")
    assert failed.returncode != 0
    # The old (mismatched) image is still on disk; its stamp must be too, so
    # the next request can still tell the two disagree.
    assert (outdir / "rootfs.img").is_file()
    assert stamp.is_file(), "a failed rebuild must not destroy the previous stamp"
    assert "packages=strace" in stamp.read_text()

    retried = mkrootfs_env.run_args("--outdir", str(outdir))
    assert retried.returncode == 0, retried.stderr
    assert "no completion stamp" not in retried.stderr, (
        "a mismatched-but-stamped image must never be served through the "
        "unstamped-legacy exception"
    )
    assert "was built with different options than requested" in retried.stderr
    assert _built(mkrootfs_env), "the mismatch must trigger a real rebuild"
    new_stamp_text = stamp.read_text()
    assert "packages=strace" not in new_stamp_text
    assert "packages=" in new_stamp_text


def test_stamp_part_is_renamed_into_place_after_build(mkrootfs_env: MkrootfsEnv):
    """The stamp's publish-time replacement (the final `mv` into
    `.mkrootfs-stamp`) is what now provides the P1 coherence guarantee;
    a fresh build must leave the final name, never a stray `.part`."""
    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    target = mkrootfs_env.rootfs_cache / "x86_64"
    assert (target / "rootfs.img").is_file()
    assert (target / ".mkrootfs-stamp").is_file()
    assert not (target / ".mkrootfs-stamp.part").exists()
    assert "build_key=" in (target / ".mkrootfs-stamp").read_text()


def test_swapped_generated_ssh_key_triggers_rebuild_not_silent_serve(
    mkrootfs_env: MkrootfsEnv,
):
    """The auto-generated key's pubkey cannot be part of BUILD_KEY (it does
    not exist until this directory's first build creates it), so a swapped
    key in a generating-mode cache dir must be caught by the stamp's
    recorded hash instead -- otherwise the stale image boots with a key the
    caller no longer has, and every push/pull/exec fails auth silently."""
    first = mkrootfs_env.run_args()
    assert first.returncode == 0, first.stderr
    keydir = Path(_rootfs_path(first)).parent
    assert (keydir / "id_ed25519.pub").is_file()

    replaced_pub = "ssh-ed25519 REPLACED swapped@qmu\n"
    (keydir / "id_ed25519.pub").write_text(replaced_pub)
    (keydir / "id_ed25519").write_text("REPLACED PRIVATE\n")

    again = mkrootfs_env.run_args()
    assert again.returncode == 0, again.stderr
    assert "different SSH key" in again.stderr
    assert _built(mkrootfs_env), "a swapped auto-generated key must never be served silently"
    expected = hashlib.sha256(replaced_pub.encode()).hexdigest()
    stamp_text = (keydir / ".mkrootfs-stamp").read_text()
    assert f"ssh_pubkey_sha256={expected}" in stamp_text


def test_distinct_ssh_keys_route_to_distinct_dirs_and_rebuild(mkrootfs_env: MkrootfsEnv):
    key_a = mkrootfs_env.tmp_path / "key_a"
    key_a.write_text("PRIVATE-A\n")
    key_a.with_suffix(".pub").write_text("ssh-ed25519 AAAAA a@qmu\n")
    key_b = mkrootfs_env.tmp_path / "key_b"
    key_b.write_text("PRIVATE-B\n")
    key_b.with_suffix(".pub").write_text("ssh-ed25519 BBBBB b@qmu\n")

    first = mkrootfs_env.run_args("--ssh-key", str(key_a))
    assert first.returncode == 0, first.stderr
    path_a = _rootfs_path(first)
    assert VARIANT_DIR_RE.search(path_a), path_a

    second = mkrootfs_env.run_args("--ssh-key", str(key_b))
    assert second.returncode == 0, second.stderr
    path_b = _rootfs_path(second)
    assert VARIANT_DIR_RE.search(path_b), path_b
    assert path_b != path_a
    assert _built(mkrootfs_env), "a different --ssh-key must not be served from key A's cache"


def test_env_default_size_override_routes_to_keyed_dir(mkrootfs_env: MkrootfsEnv):
    result = mkrootfs_env.run_args(env_overrides={"QMU_ROOTFS_SIZE": "5G"})
    assert result.returncode == 0, result.stderr
    path = _rootfs_path(result)
    assert VARIANT_DIR_RE.search(path), path
    assert "size=5G" in Path(path).with_name(".mkrootfs-stamp").read_text()


def test_unstamped_image_in_keyed_dir_is_never_served(mkrootfs_env: MkrootfsEnv):
    first = mkrootfs_env.run_args("--packages", "strace")
    assert first.returncode == 0, first.stderr
    path = Path(_rootfs_path(first))
    assert VARIANT_DIR_RE.search(str(path)), path
    (path.with_name(".mkrootfs-stamp")).unlink()

    again = mkrootfs_env.run_args("--packages", "strace")
    assert again.returncode == 0, again.stderr
    assert _built(mkrootfs_env), (
        "an unstamped image outside the legacy default dir must never be served"
    )


def test_mismatch_note_placeholder_values_are_plain_text(mkrootfs_env: MkrootfsEnv):
    """#59 followup: %q-quoting the option placeholders rendered
    `packages=\\<none\\>` / `ssh-key=\\<generated\\>`; only the image path
    needs shell-quoting (SKILL.md documents it as such)."""
    outdir = mkrootfs_env.tmp_path / "note-outdir"
    first = mkrootfs_env.run_args("--outdir", str(outdir), "--packages", "strace")
    assert first.returncode == 0, first.stderr

    again = mkrootfs_env.run_args("--outdir", str(outdir))
    assert again.returncode == 0, again.stderr
    assert "packages=<none>" in again.stderr
    assert "ssh-key=<generated>" in again.stderr
    assert "\\<" not in again.stderr
    assert "\\>" not in again.stderr
