"""Exercise PID 1 marker contracts and the helper fetcher's pure functions.

Never host mounts, networking, Docker, or real daemons.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1] / "skills/firmware-over-qmu"
TEMPLATES = SKILL / "templates"
FETCHER = SKILL / "fetch-hosttools.sh"
ADDRESS = "2: eth0 inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0"


@pytest.fixture
def run_template(tmp_path):
    # PATH shims cannot protect these scripts: each overwrites PATH. BASH_ENV
    # functions intercept every host-facing command. Successful shutdown exits
    # before sysrq; sleep exits before a resident loop can hang the test runner.
    # `dropbear` is a function that execs the fixture daemon inside the
    # template's background child, so the template's own supervision (`&`,
    # `wait`) is what runs, not a stand-in for it.
    bash_env = tmp_path / "isolate.bash"
    bash_env.write_text(r"""
mount() { :; }
mkdir() { :; }
chmod() { :; }
uname() { printf 'fixture kernel\n'; }
sed() { :; }
ls() { :; }
sync() { :; }
ldd() {
    printf '%s' "$FIXTURE_LDD_OUTPUT"
    printf '%s' "$FIXTURE_LDD_ERROR" >&2
    return "$FIXTURE_LDD_STATUS"
}
ip() {
    local stage
    case "$*" in
        'link set lo up') stage=link-lo ;;
        'link set eth0 up') stage=link-eth0 ;;
        'addr add 10.0.2.15/24 dev eth0') stage=address ;;
        'route add default via 10.0.2.10') stage=route ;;
        '-4 -o addr show '*)
            printf '%s\n' "$FIXTURE_ADDRESS"
            stage=address-query ;;
        *) printf 'unexpected ip operation\n' >&2; return 98 ;;
    esac
    if [[ "$stage" == "$FIXTURE_IP_FAIL" ]]; then
        printf '%s\n' "$FIXTURE_IP_ERROR" >&2
        return 23
    fi
}
poweroff() { printf 'FIXTURE-SHUTDOWN\n'; exit 0; }
halt() { printf 'FIXTURE-SHUTDOWN\n'; exit 0; }
sleep() { printf 'FIXTURE-RESIDENT\n' >&2; exit 73; }
dropbear() { exec "$FIXTURE_DAEMON" "$@"; }
""")
    # The daemon is /bin/sh (not bash) so BASH_ENV's sleep shim does not apply
    # to it. It announces itself, optionally blocks until a release file
    # appears (a resident daemon), then exits with the requested status.
    daemon = tmp_path / "daemon"
    daemon.write_text(
        "#!/bin/sh\n"
        "printf 'FIXTURE-DAEMON-STARTED\\n'\n"
        ": > \"$FIXTURE_DAEMON_STARTED\"\n"
        "while [ -n \"$FIXTURE_DAEMON_HOLD\" ] && [ ! -e \"$FIXTURE_DAEMON_HOLD\" ]; do\n"
        "    sleep 0.05\n"
        "done\n"
        "exit \"$FIXTURE_DAEMON_EXIT\"\n"
    )
    daemon.chmod(0o700)

    def run(name, *, ldd_output="libexample.so => /usr/lib/libexample.so\n",
            ldd_status=0, ldd_error="", ip_fail="", ip_error="network operation failed",
            address=ADDRESS, exec_failure=False, daemon_exit=0, daemon_hold=None,
            background=False):
        env = os.environ.copy()
        env.update(
            BASH_ENV=str(bash_env),
            FIXTURE_LDD_OUTPUT=ldd_output,
            FIXTURE_LDD_STATUS=str(ldd_status),
            FIXTURE_LDD_ERROR=ldd_error,
            FIXTURE_IP_FAIL=ip_fail,
            FIXTURE_IP_ERROR=ip_error,
            FIXTURE_ADDRESS=address,
            FIXTURE_DAEMON=str(tmp_path / "absent-daemon" if exec_failure else daemon),
            FIXTURE_DAEMON_STARTED=str(tmp_path / "daemon.started"),
            FIXTURE_DAEMON_HOLD=str(daemon_hold) if daemon_hold else "",
            FIXTURE_DAEMON_EXIT=str(daemon_exit),
        )
        argv = ["bash", str(TEMPLATES / f"qmu-{name}-init.sh")]
        if background:
            return subprocess.Popen(
                argv, cwd=tmp_path, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        return subprocess.run(
            argv, cwd=tmp_path, env=env, text=True, capture_output=True,
            check=False, timeout=5,
        )

    run.started = tmp_path / "daemon.started"
    return run


def assert_parked(result, marker):
    """PID 1 printed the failure marker and is resident: no shutdown, no exit."""
    assert marker in result.stderr
    assert result.returncode == 73
    assert "FIXTURE-RESIDENT" in result.stderr
    assert "FIXTURE-SHUTDOWN" not in result.stdout


def assert_resident_failure(result, marker):
    """A failure before the daemon stage: parked, and the daemon never ran."""
    assert_parked(result, marker)
    assert "FIXTURE-DAEMON-STARTED" not in result.stdout


def test_probe_success(run_template):
    result = run_template("probe")
    assert result.returncode == 0
    assert "QMU-BOOT-OK" in result.stdout
    assert "QMU-BOOT-DONE" in result.stdout
    assert "QMU-PROBE-FAILED" not in result.stderr
    assert "FIXTURE-SHUTDOWN" in result.stdout


def test_probe_command_failure(run_template):
    result = run_template("probe", ldd_status=17, ldd_error="ldd: target unavailable\n")
    assert "QMU-BOOT-DONE" not in result.stdout
    assert "ldd: target unavailable" in result.stdout + result.stderr
    assert_resident_failure(result, "QMU-PROBE-FAILED: ldd exited 17")


def test_probe_unresolved_dependency_beyond_twenty_lines(run_template):
    output = "libresolved.so => /usr/lib/libresolved.so\n" * 25
    output += "libexample.so => not found\n"
    result = run_template("probe", ldd_output=output)
    assert "QMU-BOOT-DONE" not in result.stdout
    assert "libexample.so => not found" in result.stdout
    assert_resident_failure(result, "QMU-PROBE-FAILED: unresolved dependencies")


@pytest.mark.parametrize("output", ["", " \t\n"])
def test_probe_empty_evidence(run_template, output):
    result = run_template("probe", ldd_output=output)
    assert "QMU-BOOT-DONE" not in result.stdout
    assert_resident_failure(result, "QMU-PROBE-FAILED: empty dependency evidence")


@pytest.mark.parametrize("stage", ["link-lo", "link-eth0", "address", "route"])
def test_network_operation_failure(run_template, stage):
    diagnostic = "RTNETLINK answers: File exists" if stage == "address" else "device unavailable"
    result = run_template("net", ip_fail=stage, ip_error=diagnostic)
    assert "QMU-NET-READY" not in result.stdout
    assert "QMU-NET-CONFIGURED" not in result.stdout
    assert diagnostic in result.stderr
    assert_resident_failure(result, f"QMU-NET-FAILED: {stage}")


@pytest.mark.parametrize("address,query_failure,stage", [
    (ADDRESS, "address-query", "address-query"),
    ("", "", "address-observation"),
    ("2: eth0 inet 192.0.2.9/24 scope global eth0", "", "address-observation"),
    ("2: eth0 inet 10.0.2.15/240 scope global eth0", "", "address-observation"),
    ("2: eth0 notinet 10.0.2.15/24 scope global eth0", "", "address-observation"),
])
def test_network_address_evidence(run_template, address, query_failure, stage):
    result = run_template("net", address=address, ip_fail=query_failure)
    assert "QMU-NET-READY" not in result.stdout
    assert "QMU-NET-CONFIGURED" not in result.stdout
    if address:
        assert address in result.stdout + result.stderr
    if query_failure:
        assert "network operation failed" in result.stderr
    assert_resident_failure(result, f"QMU-NET-FAILED: {stage}")


def test_network_pid1_outlives_running_daemon(run_template, tmp_path):
    """A resident daemon is the success shape: PID 1 stays alive behind it and
    reports nothing. Only once the daemon exits does the marker appear."""
    release = tmp_path / "release"
    proc = run_template("net", daemon_hold=release, background=True)
    try:
        deadline = time.monotonic() + 5
        while not run_template.started.exists():
            assert time.monotonic() < deadline, "daemon never started"
            assert proc.poll() is None, "PID 1 exited before the daemon started"
            time.sleep(0.02)
        time.sleep(0.2)
        assert proc.poll() is None, "PID 1 did not stay resident behind its daemon"
        release.touch()
        stdout, stderr = proc.communicate(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
    result = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    assert f"QMU-NET-CONFIGURED {ADDRESS}" in result.stdout
    assert "FIXTURE-DAEMON-STARTED" in result.stdout
    assert "=== QMU-HELPER-EXITED code=0 ===" in result.stdout
    assert_parked(result, "QMU-NET-FAILED: dropbear-exited 0")


@pytest.mark.parametrize("code", [0, 23])
def test_network_daemon_exit_is_failure(run_template, code):
    """An exec that succeeded and then returned (exit 0 included) must not take
    PID 1 with it: the marker names the status and PID 1 parks."""
    result = run_template("net", daemon_exit=code)
    assert f"QMU-NET-CONFIGURED {ADDRESS}" in result.stdout
    assert "FIXTURE-DAEMON-STARTED" in result.stdout
    assert f"=== QMU-HELPER-EXITED code={code} ===" in result.stdout
    assert_parked(result, f"QMU-NET-FAILED: dropbear-exited {code}")


def test_network_exec_failure(run_template):
    result = run_template("net", exec_failure=True)
    assert "QMU-NET-CONFIGURED" in result.stdout
    assert "=== QMU-HELPER-EXITED code=127 ===" in result.stdout
    assert_resident_failure(result, "QMU-NET-FAILED: dropbear-exited 127")


# --- fetch-hosttools.sh: sourceable functions, no Docker -------------------


def fetcher_call(snippet, *argv, env=None, stdin=None):
    """Source the fetcher (its main() is guarded on $0) and run one function."""
    full_env = os.environ.copy()
    full_env.update(env or {})
    return subprocess.run(
        ["bash", "-c", f'source "$1"; shift; {snippet}', "qmu-test", str(FETCHER), *argv],
        input=stdin, text=True, capture_output=True, check=False, timeout=10,
        env=full_env,
    )


def test_fetcher_eol_rewrite_targets_single_archive_tree(tmp_path):
    sources = tmp_path / "sources.list"
    sources.write_text(
        "deb http://ports.ubuntu.com/ubuntu-ports eoan main universe\n"
        "deb http://ports.ubuntu.com/ eoan-updates main\n"
        "deb http://archive.ubuntu.com/ubuntu eoan main\n"
        "deb http://us.archive.ubuntu.com/ubuntu eoan-updates main\n"
        "deb http://security.ubuntu.com/ubuntu eoan-security main\n"
        "URIs: http://ports.ubuntu.com/ubuntu-ports/\n"
    )
    result = fetcher_call('rewrite_eol_sources "$@"', str(sources), str(tmp_path / "absent"))
    assert result.returncode == 0, result.stderr
    assert sources.read_text().splitlines() == [
        "deb http://old-releases.ubuntu.com/ubuntu eoan main universe",
        "deb http://old-releases.ubuntu.com/ubuntu/ eoan-updates main",
        "deb http://old-releases.ubuntu.com/ubuntu eoan main",
        "deb http://old-releases.ubuntu.com/ubuntu eoan-updates main",
        "deb http://old-releases.ubuntu.com/ubuntu eoan-security main",
        "URIs: http://old-releases.ubuntu.com/ubuntu/",
    ]


LDD_SFTP = (
    "\tlinux-vdso.so.1 (0x00007ffd)\n"
    "\tlibcrypto.so.3 => /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (0x1)\n"
    "\tlibcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x2)\n"
    "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x3)\n"
    "\tlibm-2.27.so => /lib/libm-2.27.so (0x4)\n"
    "\tlibz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x5)\n"
    "\tlibutil.so.1 => /lib/x86_64-linux-gnu/libutil.so.1 (0x6)\n"
    "\t/lib64/ld-linux-x86-64.so.2 (0x7)\n"
)


def test_fetcher_copies_libcrypto_but_not_glibc_base():
    result = fetcher_call("nonbase_library_paths", stdin=LDD_SFTP)
    assert result.returncode == 0, result.stderr
    assert sorted(result.stdout.split()) == [
        "/lib/x86_64-linux-gnu/libz.so.1",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    ]


@pytest.fixture
def fake_output(tmp_path):
    """A fetched output tree plus an `ldd` on PATH that answers from
    <ldd-dir>/<basename>.ldd (default: libc only)."""
    out = tmp_path / "out"
    (out / "libs").mkdir(parents=True)
    for name in ("dropbear", "dropbearkey", "gdbserver", "sftp-server"):
        (out / name).write_text("elf")
    ldd_dir = tmp_path / "ldd"
    ldd_dir.mkdir()
    shim_bin = tmp_path / "bin"
    shim_bin.mkdir()
    shim = shim_bin / "ldd"
    shim.write_text(
        "#!/bin/sh\n"
        f'f="{ldd_dir}/${{1##*/}}.ldd"\n'
        'if [ -e "$f" ]; then cat "$f"; else printf "\\tlibc.so.6 => /lib/libc.so.6 (0x1)\\n"; fi\n'
    )
    shim.chmod(0o700)
    env = {"PATH": f"{shim_bin}:{os.environ['PATH']}"}

    def check():
        return fetcher_call('check_dependency_completeness "$1"', str(out), env=env)

    return out, ldd_dir, check


def test_fetcher_completeness_accepts_shipped_and_base_libs(fake_output):
    out, ldd_dir, check = fake_output
    (ldd_dir / "sftp-server.ldd").write_text(LDD_SFTP)
    (out / "libs/libcrypto.so.3").write_text("elf")
    (out / "libs/libz.so.1").write_text("elf")
    result = check()
    assert result.returncode == 0, result.stderr


def test_fetcher_completeness_reports_omitted_binary_dependency(fake_output):
    out, ldd_dir, check = fake_output
    (ldd_dir / "sftp-server.ldd").write_text(LDD_SFTP)
    (out / "libs/libz.so.1").write_text("elf")
    result = check()
    assert result.returncode != 0
    assert "sftp-server: libcrypto.so.3" in result.stderr
    assert "libz.so.1" not in result.stderr
    assert "libcrypt.so.1" not in result.stderr


def test_fetcher_completeness_walks_shipped_libraries(fake_output):
    out, ldd_dir, check = fake_output
    (out / "libs/libcrypto.so.3").write_text("elf")
    (ldd_dir / "libcrypto.so.3.ldd").write_text(
        "\tlibc.so.6 => /lib/libc.so.6 (0x1)\n"
        "\tlibatomic.so.1 => not found\n"
    )
    result = check()
    assert result.returncode != 0
    assert "libcrypto.so.3: libatomic.so.1" in result.stderr
