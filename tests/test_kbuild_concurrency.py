"""Per-version source-tree serialization in tools/kbuild.sh.

Every invocation for one kernel version mutates the single shared extracted
tree under $CACHE/kernels/src/linux-$VERSION, so kbuild.sh takes an exclusive
flock keyed per version before touching the cache. These tests pin that
contract offline via the fake docker/tar environment from test_kbuild.
"""

from __future__ import annotations

import os
import signal
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
    # "-o"/--close closes flock's OWN fd in the forked child right before it
    # execs `sleep`, so the lock is tied to the flock process itself, not to
    # `sleep` (which shares flock's process group but never gets a copy of
    # its locked fd). start_new_session gives that process group a pgid we
    # can reap as a unit in _release -- reaping only the flock PID leaves
    # `sleep` behind, orphaned to init for the rest of its 120s.
    # (--no-fork/-F would exec `sleep` in flock's own place instead of
    # forking, and `man flock` documents -F as incompatible with --close --
    # combining them here would hang both tests past the 60s communicate
    # timeout, not keep the lock alive any better.)
    holder = subprocess.Popen(
        ["flock", "-s", "-o", str(lock_path), "sleep", "120"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
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
    # holder.terminate() only signals the flock parent. Because it holds the
    # lock via --close (see _hold_version_lock), `sleep` does not share that
    # fd and survives -- reparented to init -- for up to its full 120s.
    # Signal the whole process group instead so both processes die together.
    try:
        pgid = os.getpgid(holder.pid)
    except ProcessLookupError:
        pgid = None
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
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


def _fake_bin_dir(kbuild_env) -> Path:
    return Path(kbuild_env.env["PATH"].split(os.pathsep)[0])


@pytest.fixture
def slow_kbuild_env(kbuild_env):
    """Extends the fake docker shim owned by tests/test_kbuild.py so its
    `run` step can be made to block on KBUILD_TEST_HOLD_SECONDS.

    Needed because both tests above only ever observe the version lock from
    OUTSIDE kbuild's critical section -- before kbuild starts, or after it
    has already exited. Neither would notice the lock being released early
    (e.g. by an accidental `flock -u 9` right after acquisition), because by
    the time either test looks, kbuild is done either way.
    """
    docker_path = _fake_bin_dir(kbuild_env) / "docker"
    original = docker_path.read_text()
    marker = 'if os.environ.get("KBUILD_FAIL_IF_DOCKER_RUNS") == "1":'
    assert original.count(marker) == 1, (
        "fake docker shim shape changed; update the hold-injection in "
        "test_kbuild_concurrency.slow_kbuild_env"
    )
    hold_snippet = (
        'hold = os.environ.get("KBUILD_TEST_HOLD_SECONDS")\n'
        "if hold:\n"
        "    import time\n"
        "    time.sleep(float(hold))\n"
        + marker
    )
    docker_path.write_text(original.replace(marker, hold_snippet, 1))
    return kbuild_env


def test_lock_is_held_for_the_full_critical_section_not_released_early(
    slow_kbuild_env,
):
    """The version lock must stay held for kbuild's ENTIRE critical section,
    not just around acquisition. This probes the lock from outside WHILE the
    (fake) build is still running -- it must fail if the lock were dropped
    right after it was acquired.
    """
    lock_path = slow_kbuild_env.cache / "kernels" / ".src-linux-7.0.lock"
    env = slow_kbuild_env.env.copy()
    env["KBUILD_TEST_HOLD_SECONDS"] = "2"
    proc = subprocess.Popen(
        [str(KBUILD), "--version", "7.0", "--arch", "x86_64"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        deadline = time.monotonic() + 10.0
        acquired = False
        while time.monotonic() < deadline:
            if lock_path.exists():
                probe = subprocess.run(
                    ["flock", "-n", str(lock_path), "true"], check=False
                )
                if probe.returncode != 0:
                    acquired = True
                    break
            time.sleep(POLL_INTERVAL_SECONDS)
        assert acquired, "kbuild never appeared to hold its own version lock"

        # Still mid-build (the fake docker is inside its
        # KBUILD_TEST_HOLD_SECONDS sleep): the lock must still be refused
        # from outside.
        probe = subprocess.run(["flock", "-n", str(lock_path), "true"], check=False)
        assert probe.returncode != 0, (
            "external flock succeeded while kbuild should still be inside "
            "its critical section -- the lock was released too early"
        )

        stdout, stderr = proc.communicate(timeout=30)
        assert proc.returncode == 0, stderr
        values = _parse_assignments(stdout)
        assert Path(values["KERNEL"]).is_file()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


@pytest.fixture
def broken_flock_kbuild_env(kbuild_env):
    """A `flock` shim that fails for a reason OTHER than lock contention --
    e.g. ENOLCK, a filesystem that can't flock(2), or a broken binary -- with
    an exit code that is deliberately not kbuild.sh's own conflict code.
    """
    flock_shim = _fake_bin_dir(kbuild_env) / "flock"
    flock_shim.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('fake flock: simulated non-conflict failure\\n')\n"
        "raise SystemExit(37)\n"
    )
    flock_shim.chmod(0o755)
    return kbuild_env


def test_flock_non_conflict_failure_is_fatal_not_a_bogus_wait(
    broken_flock_kbuild_env,
):
    """kbuild.sh used to treat every non-zero flock exit as lock contention,
    so a real failure (ENOLCK, EBADF, a broken flock binary...) printed the
    bogus "waiting for another kbuild invocation" line, then failed the
    identical way on the blocking retry and aborted under `set -e` with no
    `kbuild:`-prefixed diagnostic at all.
    """
    result = broken_flock_kbuild_env.run()
    assert result.returncode == 2, result.stderr
    assert "kbuild: error:" in result.stderr
    assert "waiting for another kbuild invocation" not in result.stderr


def test_uncreatable_kernels_dir_is_a_fatal_error_not_a_raw_traceback(tmp_path):
    """#60 follow-up: `mkdir -p "$CACHE/kernels"` was unguarded, so a
    permission failure there surfaced as a raw bash line-number traceback
    and exit 1 instead of kbuild.sh's usual `kbuild: error: ...` / exit 2.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    os.chmod(cache, 0o500)  # read+execute only: mkdir "kernels" under it fails
    env = os.environ.copy()
    env["QMU_CACHE_DIR"] = str(cache)
    try:
        result = subprocess.run(
            [str(KBUILD), "--version", "7.0", "--arch", "x86_64"],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
    finally:
        os.chmod(cache, 0o700)
    assert result.returncode == 2, result.stderr
    assert "kbuild: error:" in result.stderr


def test_unwritable_kernels_dir_lock_file_is_a_fatal_error_not_a_raw_traceback(
    kbuild_env,
):
    """#60 follow-up: `exec 9>".../.src-linux-$VERSION.lock"` was unguarded
    too. Here "kernels" already exists (from the fixture) but is read-only,
    so `mkdir -p` no-ops and the `exec` redirection itself fails.
    """
    kernels_dir = kbuild_env.cache / "kernels"
    os.chmod(kernels_dir, 0o500)
    try:
        result = kbuild_env.run()
    finally:
        os.chmod(kernels_dir, 0o700)
    assert result.returncode == 2, result.stderr
    assert "kbuild: error:" in result.stderr


@pytest.fixture
def reap_logging_kbuild_env(kbuild_env):
    """Extends the fake docker shim to log EVERY invocation, not just `run`.

    Without this, `docker rm -f <container>` calls -- issued by kbuild.sh's
    defensive pre-clean and by reap_container's EXIT trap -- silently hit the
    shim's "unexpected invocation" fallback and are invisible to
    kbuild_env.docker_runs().
    """
    docker_path = _fake_bin_dir(kbuild_env) / "docker"
    original = docker_path.read_text()
    marker = (
        'if not args or args[0] != "run":\n'
        '    print(f"unexpected fake docker invocation: {args!r}", file=sys.stderr)\n'
        '    raise SystemExit(96)\n'
    )
    assert original.count(marker) == 1, (
        "fake docker shim shape changed; update reap_logging_kbuild_env"
    )
    replacement = (
        'if not args or args[0] != "run":\n'
        '    _log = Path(os.environ["KBUILD_DOCKER_LOG"])\n'
        '    with _log.open("a") as _stream:\n'
        '        _stream.write(json.dumps(args) + "\\n")\n'
        '    raise SystemExit(0 if args[:1] == ["rm"] else 96)\n'
    )
    docker_path.write_text(original.replace(marker, replacement, 1))
    return kbuild_env


def test_build_container_is_named_and_reaped_on_exit(reap_logging_kbuild_env):
    """#60 follow-up: the container is named uniquely per invocation and
    force-removed both defensively before `docker run` and by
    reap_container's EXIT trap after -- the comment above the lock says the
    guarded mutation cannot outlive the lock; this proves `docker rm -f` is
    actually issued for it, not just claimed in a comment.
    """
    proc = subprocess.Popen(
        [str(KBUILD), "--version", "7.0", "--arch", "x86_64"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=reap_logging_kbuild_env.env,
    )
    stdout, stderr = proc.communicate(timeout=60)
    assert proc.returncode == 0, stderr
    expected_name = f"qmu-kbuild-7.0-x86_64-{proc.pid}"
    kinds = [call[0] for call in reap_logging_kbuild_env.docker_runs()]
    assert kinds == ["rm", "run", "rm"], kinds
    for call in reap_logging_kbuild_env.docker_runs():
        if call[0] == "rm":
            assert call == ["rm", "-f", expected_name], call
    run_argv = next(c for c in reap_logging_kbuild_env.docker_runs() if c[0] == "run")
    assert "--name" in run_argv, run_argv
    assert run_argv[run_argv.index("--name") + 1] == expected_name


def test_release_reaps_the_lock_holders_entire_process_group(tmp_path):
    """#60 follow-up: holder.terminate() only signals the flock parent.
    Because it holds the lock via --close (see _hold_version_lock), the
    `sleep` it forks does not share that fd and survived, reparented to
    init, for up to the rest of its 120s -- two such strays were observed
    after a run. _release must reap the whole process group.
    """
    lock_path = tmp_path / "standalone.lock"
    holder = _hold_version_lock(lock_path)
    children = subprocess.run(
        ["pgrep", "-P", str(holder.pid)], capture_output=True, text=True
    ).stdout.split()
    assert children, "expected flock to have forked a sleep child"
    sleep_pid = int(children[0])
    _release(holder)
    time.sleep(0.3)
    alive = subprocess.run(["kill", "-0", sleep_pid.__str__()]).returncode == 0
    assert not alive, "sleep child survived _release -- process group was not reaped"
