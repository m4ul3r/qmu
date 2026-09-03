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

# The shims below deliberately write to STDOUT. Real `docker build -q` prints
# the image id there and real `mke2fs` prints "Creating regular file <path>"
# there even with -q (both measured), so a *silent* double cannot see stdout
# pollution -- which is exactly how a cache MISS shipped with a stdout that
# `eval $(tools/mkrootfs.sh)` could not consume. Every one of these markers
# must come out on stderr instead.
SHIM_STDOUT_MARKERS = ("sha256:", "Creating regular file", "mkrootfs-shim:")


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
                    # Real `docker build -q` writes the image id to stdout.
                    echo "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
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
                      # The container's mke2fs writes to the container's
                      # stdout, which is this process's stdout.
                      echo "Creating regular file /output/rootfs.img.part"
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
                    echo "mkrootfs-shim: sudo tar stdout"
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
                    # Real mke2fs prints this on stdout even with -q.
                    echo "Creating regular file ${{img:-{outdir}/rootfs.img}}"
                    exit 0
                    ;;
                  chown)
                    if [[ "$FAIL_STAGE" == "chown" ]]; then
                      exit 43
                    fi
                    echo "mkrootfs-shim: sudo chown stdout"
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


def _eval_assignments(stdout: str) -> tuple[int, dict[str, str]]:
    """Consume the script's stdout the way the documented workflow does --
    `eval $(tools/mkrootfs.sh)` -- and report what the caller ends up holding.
    An unquoted path with a space word-splits here (the eval fails, rc 91)
    instead of landing in the variable."""
    probe = subprocess.run(
        [
            "bash",
            "-c",
            'eval "$1" || exit 91\n'
            'printf "ROOTFS=%s\\nSSH_KEY=%s\\n" "${ROOTFS-}" "${SSH_KEY-}"',
            "_",
            stdout,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    values: dict[str, str] = {}
    for line in probe.stdout.splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return probe.returncode, values


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
    # The note must not claim provenance the script cannot know: an unstamped
    # image may equally be a cache dir whose stamp was removed, or one left by
    # a build killed mid-publish. It names the possibilities instead.
    assert "or one whose stamp was removed" in result.stderr
    assert "it was built before option tracking existed" not in result.stderr
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


@pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores the read-only predecessor this pins"
)
def test_stamp_part_is_renamed_into_place_after_build(mkrootfs_env: MkrootfsEnv):
    """The publish-window poison and the image itself must be published by
    rename, never by writing through the previous file. Asserting only the
    final filenames passed against a non-atomic write (measured), so this pins
    the property that makes rename load-bearing: a read-only predecessor
    cannot be written or copied over, but can be renamed over, because rename
    needs only the directory. A `cp` in place of either `mv` fails here, and
    it must fail LOUDLY -- a silent copy failure republishes the stamp over
    the OLD image, which is the incoherence this whole publish sequence
    exists to prevent. (The completion stamp's own rename is pinned by
    test_every_stamp_publish_is_a_temp_file_rename: by the time it runs, the
    poison publish has already replaced the read-only predecessor.)"""
    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    target = mkrootfs_env.rootfs_cache / "x86_64"
    stamp = target / ".mkrootfs-stamp"
    image = target / "rootfs.img"
    assert image.is_file()
    assert stamp.is_file()
    assert not (target / ".mkrootfs-stamp.part").exists()
    assert not (target / ".mkrootfs-stamp.publishing").exists()
    key_match = re.search(r"^build_key=(\S+)$", stamp.read_text(), re.M)
    assert key_match, stamp.read_text()
    image.write_bytes(b"first-generation image")

    image.chmod(0o400)
    stamp.chmod(0o400)
    rebuilt = mkrootfs_env.run_args("--no-cache")
    assert rebuilt.returncode == 0, rebuilt.stderr
    assert _built(mkrootfs_env)
    assert not (target / ".mkrootfs-stamp.part").exists()
    assert not (target / ".mkrootfs-stamp.publishing").exists()
    assert not (target / "rootfs.img.part").exists()
    assert image.read_bytes() != b"first-generation image", (
        "the rebuild's image must actually replace the read-only predecessor"
    )
    republished = stamp.read_text()
    assert f"build_key={key_match.group(1)}" in republished
    assert "publishing-" not in republished, "the poison must not survive a build"


def test_every_stamp_publish_is_a_temp_file_rename():
    """The completion stamp's atomicity has no observable seam: the poison
    publish immediately before it already replaced whatever was at the stamp
    path, so a direct `} > "$STAMP_OUT"` behaves identically through the CLI
    (measured -- the whole file stayed green). Pin it at the source instead,
    which is what the coherence guarantee actually rests on: nothing may write
    to the stamp path directly, and every temp stamp written must be renamed
    onto it."""
    text = MKROOTFS.read_text()
    assert not re.search(r'>\s*"\$STAMP_OUT"', text), (
        "a stamp must never be written in place; assemble it beside the final "
        "name and rename it on"
    )
    temps = set(re.findall(r'>\s*"\$STAMP_OUT\.([A-Za-z]+)"', text))
    assert temps == {"publishing", "part"}, temps
    for temp in temps:
        assert f'mv -f -- "$STAMP_OUT.{temp}" "$STAMP_OUT"' in text, temp


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


# ---------------------------------------------------------------------------
# Round-2 review + dogfood findings: the publish window opened by moving the
# stamp replacement after the image rename, and the two stdout-contract
# defects (build chatter, unquoted paths) that a silent fake-docker harness
# structurally could not see.
# ---------------------------------------------------------------------------


def test_interrupted_publish_is_never_served_as_a_matching_image(
    mkrootfs_env: MkrootfsEnv,
):
    """The image is renamed into place before the stamp is replaced, so the
    directory briefly holds the NEW image with the OLD stamp. A death in that
    window (signal, ENOSPC/EIO on the stamp write right after a multi-GB
    image, unclean shutdown) used to leave a stamp certifying an image it does
    not describe, and the next request for the shape that stamp named was
    served at exit 0 with no note at all -- worse than the legacy path, which
    at least says UNVERIFIED. Poisoning the stamp before the image rename
    turns that into a named mismatch and a rebuild."""
    outdir = mkrootfs_env.tmp_path / "publish-window"
    built = mkrootfs_env.run_args("--outdir", str(outdir), "--packages", "strace")
    assert built.returncode == 0, built.stderr
    stamp = outdir / ".mkrootfs-stamp"
    assert "packages=strace" in stamp.read_text()

    # Fail the FINAL stamp write, after the image rename: a directory at its
    # temp name makes the redirect fail, which under `set -e` aborts the run
    # exactly inside the publish window.
    obstacle = outdir / ".mkrootfs-stamp.part"
    obstacle.mkdir()
    interrupted = mkrootfs_env.run_args("--outdir", str(outdir))
    assert interrupted.returncode != 0
    assert (outdir / "rootfs.img").is_file(), "the default-shaped image was published"
    assert "build_key=publishing-" in stamp.read_text(), (
        "the stamp must be poisoned BEFORE the image is published, so an "
        "interrupted publish cannot leave a stamp describing the old image"
    )
    obstacle.rmdir()

    again = mkrootfs_env.run_args("--outdir", str(outdir), "--packages", "strace")
    assert again.returncode == 0, again.stderr
    assert "died while publishing" in again.stderr
    assert "rebuilding with the requested options" in again.stderr
    assert _built(mkrootfs_env), "an interrupted publish must rebuild, never serve"
    # The poison names no build, so it is never rendered as an option set.
    assert re.search(r"publishing-\d+", again.stderr) is None, again.stderr
    republished = stamp.read_text()
    assert "packages=strace" in republished
    assert "publishing-" not in republished


def test_build_path_stdout_carries_only_assignments(mkrootfs_env: MkrootfsEnv):
    """`eval $(tools/mkrootfs.sh)` is the documented workflow (SKILL.md
    'Output format', and the script header), but on a cache MISS stdout also
    carried `docker build -q`'s image id and mke2fs's `Creating regular file`,
    so the eval died with rc 127. Every build command's stdout belongs on
    stderr; the shims here speak on stdout precisely so this is observable."""
    result = mkrootfs_env.run_args()
    assert result.returncode == 0, result.stderr
    assert _built(mkrootfs_env), "this must exercise the BUILD path, not a hit"
    keys = [line.split("=", 1)[0] for line in result.stdout.splitlines()]
    assert keys == ["ROOTFS", "SSH_KEY"], result.stdout
    for marker in SHIM_STDOUT_MARKERS:
        assert marker not in result.stdout, (marker, result.stdout)
        assert marker in result.stderr, f"{marker}: the shim never spoke at all"
    rc, _values = _eval_assignments(result.stdout)
    assert rc == 0, result.stdout


def test_emitted_paths_are_shell_quoted_so_eval_survives_a_space(
    mkrootfs_env: MkrootfsEnv,
):
    """`--outdir` is documented, and with a space in it the unquoted
    `echo "ROOTFS=$OUTDIR/rootfs.img"` word-split under eval: the caller got
    empty variables and a bare rc-127 shell error, no qmu-prefixed
    diagnostic. kbuild.sh already emitted `printf '%q'`; both of mkrootfs's
    emission sites -- build path and cache-hit path -- must match it."""
    outdir = mkrootfs_env.tmp_path / "space dir"
    built = mkrootfs_env.run_args("--outdir", str(outdir))
    assert built.returncode == 0, built.stderr
    assert _built(mkrootfs_env)
    rc, values = _eval_assignments(built.stdout)
    assert rc == 0, f"build-path stdout is not eval-able: {built.stdout!r}"
    assert values["ROOTFS"] == str(outdir / "rootfs.img")
    assert values["SSH_KEY"] == str(outdir / "id_ed25519")

    hit = mkrootfs_env.run_args("--outdir", str(outdir))
    assert hit.returncode == 0, hit.stderr
    assert not _built(mkrootfs_env), "second identical run must be a cache hit"
    rc, values = _eval_assignments(hit.stdout)
    assert rc == 0, f"cache-hit stdout is not eval-able: {hit.stdout!r}"
    assert values["ROOTFS"] == str(outdir / "rootfs.img")
    assert values["SSH_KEY"] == str(outdir / "id_ed25519")


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
def test_unreadable_generated_pubkey_is_a_permission_error_not_a_changed_key(
    mkrootfs_env: MkrootfsEnv,
):
    """The generating-mode key re-check compared an unconditionally captured
    digest, so an existing-but-unreadable id_ed25519.pub produced an empty
    digest, announced a CHANGED SSH KEY, and then died inside `cat` with a raw
    `Permission denied` and no `mkrootfs: error:` line. Nothing about the key
    changed; the fault is the permissions, and the message must say so."""
    first = mkrootfs_env.run_args()
    assert first.returncode == 0, first.stderr
    pub = Path(_rootfs_path(first)).with_name("id_ed25519.pub")
    assert pub.is_file()
    pub.chmod(0o000)
    try:
        again = mkrootfs_env.run_args()
    finally:
        pub.chmod(0o644)
    assert again.returncode == 2, again.stderr
    assert "mkrootfs: error:" in again.stderr
    assert "cannot read" in again.stderr and "id_ed25519.pub" in again.stderr
    assert "check its permissions" in again.stderr
    assert "different SSH key" not in again.stderr, (
        "an unreadable public half is a permission fault, not a changed key"
    )
    assert "Permission denied" not in again.stderr, "no raw cat error"
    assert again.stdout == "", "a fatal permission fault emits no assignments"
    assert not _built(mkrootfs_env)


def test_missing_generated_pubkey_beside_an_existing_private_key_is_fatal(
    mkrootfs_env: MkrootfsEnv,
):
    """Same class as the unreadable case: with the private half present the
    pair is not regenerated, so a missing .pub used to reach the build's `cat`
    and abort with a raw `No such file or directory` and no `mkrootfs: error:`
    line. The message must name the file and how to restore it."""
    first = mkrootfs_env.run_args()
    assert first.returncode == 0, first.stderr
    pub = Path(_rootfs_path(first)).with_name("id_ed25519.pub")
    pub.unlink()

    again = mkrootfs_env.run_args()
    assert again.returncode == 2, again.stderr
    assert "mkrootfs: error: SSH public key missing" in again.stderr
    assert "ssh-keygen -y -f" in again.stderr
    assert "different SSH key" not in again.stderr
    assert again.stdout == ""
    assert not _built(mkrootfs_env)
