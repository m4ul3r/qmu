"""Per-version source-tree serialization in tools/kbuild.sh.

Every invocation for one kernel version mutates the single shared extracted
tree under $CACHE/kernels/src/linux-$VERSION, so kbuild.sh takes an exclusive
flock keyed per version before touching the cache. These tests pin that
contract offline via the fake docker/tar environment from test_kbuild.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from tests.test_kbuild import KBUILD, _parse_assignments, kbuild_env

# How long the blocked phase waits for a fast-failure to show up. A waiting
# invocation is still alive after this window; a crashing one is long gone.
BLOCKED_WINDOW_SECONDS = 2.0
POLL_INTERVAL_SECONDS = 0.05


def _hold_version_lock(lock_path: Path) -> subprocess.Popen[str]:
    """Acquire the version lock externally (shared, like flock -s) and hold it."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch()
    # "-o"/--no-fork makes flock exec the sleeper in-place. Default behavior
    # forks, and the forked child inherits the locked fd, keeping the lock
    # alive after flock itself is terminated.
    holder = subprocess.Popen(
        ["flock", "-s", "-o", str(lock_path), "sleep", "120"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Confirm the holder actually owns the lock before starting kbuild: an
    # exclusive probe must fail while the shared lock is held.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        probe = subprocess.run(
            ["flock", "-n", str(lock_path), "true"], check=False
        )
        if probe.returncode != 0:
            return holder
        time.sleep(POLL_INTERVAL_SECONDS)
    holder.kill()
    holder.wait()
    pytest.fail("external lock holder never acquired the version lock")


def _release(holder: subprocess.Popen[str]) -> None:
    holder.terminate()
    holder.wait(timeout=10)


def _spawn_kbuild(kbuild_env, *extra: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [str(KBUILD), "--version", "7.0", "--arch", "x86_64", *extra],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=kbuild_env.env,
    )


def _assert_blocked(proc: subprocess.Popen[str]) -> None:
    """Assert the invocation neither exits nor completes while the lock is held.

    Discriminates waiting from fast-failure: a failing invocation would have
    exited well within BLOCKED_WINDOW_SECONDS.
    """
    deadline = time.monotonic() + BLOCKED_WINDOW_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(POLL_INTERVAL_SECONDS)
    assert (
        proc.poll() is None
    ), f"kbuild exited during held lock (rc={proc.returncode}, stderr={proc.stderr.read() if proc.stderr else ''})"


def test_second_invocation_blocks_while_version_lock_held(kbuild_env):
    lock_path = kbuild_env.cache / "kernels" / ".src-linux-7.0.lock"
    holder = _hold_version_lock(lock_path)
    try:
        proc = _spawn_kbuild(kbuild_env)
        try:
            _assert_blocked(proc)
        finally:
            _release(holder)
        stdout, stderr = proc.communicate(timeout=60)
        assert proc.returncode == 0, stderr
        # A blocked invocation must SAY it is waiting: silence for the length of
        # a full build is indistinguishable from a hang.
        assert "waiting for another kbuild invocation" in stderr
        assert "acquired linux-7.0 source-tree lock" in stderr
        values = _parse_assignments(stdout)
        assert Path(values["KERNEL"]).is_file()
        assert Path(values["VMLINUX"]).is_file()
    finally:
        if holder.poll() is None:
            _release(holder)


def test_config_only_serializes_against_running_build(kbuild_env, tmp_path):
    outdir = tmp_path / "config-only-under-lock"
    lock_path = kbuild_env.cache / "kernels" / ".src-linux-7.0.lock"
    holder = _hold_version_lock(lock_path)
    try:
        proc = _spawn_kbuild(kbuild_env, "--config-only", "--outdir", str(outdir))
        try:
            _assert_blocked(proc)
        finally:
            _release(holder)
        stdout, stderr = proc.communicate(timeout=60)
        assert proc.returncode == 0, stderr
        assert stdout == f"CONFIG={outdir}/.config\n"
        assert (outdir / ".config").is_file()
    finally:
        if holder.poll() is None:
            _release(holder)
