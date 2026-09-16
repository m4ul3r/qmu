"""Exercise PID 1 marker contracts, never host mounts, networking, or daemons."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

TEMPLATES = Path(__file__).resolve().parents[1] / "skills/firmware-over-qmu/templates"
ADDRESS = "2: eth0 inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0"


@pytest.fixture
def run_template(tmp_path):
    # PATH shims cannot protect these scripts: each overwrites PATH. BASH_ENV
    # functions intercept every host-facing command. Successful shutdown exits
    # before sysrq; sleep exits before a resident loop can hang the test runner.
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
exec() {
    shift
    builtin exec "$FIXTURE_DAEMON" "$@"
}
""")
    daemon = tmp_path / "daemon"
    daemon.write_text("#!/bin/sh\nprintf 'FIXTURE-DAEMON-HANDOFF\\n'\n")
    daemon.chmod(0o700)

    def run(name, *, ldd_output="libexample.so => /usr/lib/libexample.so\n",
            ldd_status=0, ldd_error="", ip_fail="", ip_error="network operation failed",
            address=ADDRESS, exec_failure=False):
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
        )
        return subprocess.run(
            ["bash", str(TEMPLATES / f"qmu-{name}-init.sh")],
            cwd=tmp_path, env=env, text=True, capture_output=True,
            check=False, timeout=5,
        )

    return run


def assert_resident_failure(result, marker):
    assert marker in result.stderr
    assert result.returncode == 73
    assert "FIXTURE-RESIDENT" in result.stderr
    assert "FIXTURE-SHUTDOWN" not in result.stdout
    assert "FIXTURE-DAEMON-HANDOFF" not in result.stdout


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


def test_network_success(run_template):
    result = run_template("net")
    assert result.returncode == 0
    assert f"QMU-NET-CONFIGURED {ADDRESS}" in result.stdout
    assert "QMU-NET-READY" not in result.stdout
    assert "QMU-NET-FAILED" not in result.stderr
    assert "FIXTURE-DAEMON-HANDOFF" in result.stdout


def test_network_exec_failure(run_template):
    result = run_template("net", exec_failure=True)
    assert "QMU-NET-CONFIGURED" in result.stdout
    assert "QMU-NET-READY" not in result.stdout
    assert_resident_failure(result, "QMU-NET-FAILED: dropbear-exec")
