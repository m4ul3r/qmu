from __future__ import annotations

import os
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
        self.failing_stage: str | None = None
        self._write_docker_shim()
        self._write_sudo_shim()

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
                        *.img) img="$arg" ;;
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
