"""instance_alive() must survive PID recycling — the guard fix #3 relies on.

A recorded pid can be reused by an unrelated process after a reboot (the
instance JSON outlives the kernel's pid namespace). launch-replace and the
list/status paths therefore key liveness off instance_alive(), which compares
the /proc start-time (field 22) against the value captured at launch. These
tests drive that comparison with a REAL live process so the recycling branch
is exercised deterministically, not mocked.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from qmu.instance import VMInstance, instance_alive, proc_pid_start

pytestmark = pytest.mark.skipif(
    not os.path.isdir("/proc"), reason="pid_start recycling guard needs /proc"
)


def _inst(pid: int, pid_start: str | None) -> VMInstance:
    return VMInstance(
        vm_id="vm-recycle",
        pid=pid,
        qmp_socket="/tmp/qmp.sock",
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log="/tmp/serial.log",
        kernel="/boot/bzImage",
        rootfs=None,
        memory="1G",
        cpus=1,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-05T00:00:00Z",
        pid_start=pid_start,
    )


@pytest.fixture
def sleeper():
    proc = subprocess.Popen(["sleep", "30"])
    try:
        yield proc
    finally:
        if proc.returncode is None:
            proc.terminate()
            proc.wait()


def test_matching_pid_start_is_alive(sleeper):
    real = proc_pid_start(sleeper.pid)
    assert real is not None
    assert instance_alive(_inst(sleeper.pid, real)) is True


def test_recycled_pid_with_wrong_start_is_dead(sleeper):
    # Same pid, different start-time: an unrelated process reusing the pid.
    real = proc_pid_start(sleeper.pid)
    stale = str(int(real) + 100000)
    assert instance_alive(_inst(sleeper.pid, stale)) is False


def test_missing_pid_start_falls_back_to_pid_liveness(sleeper):
    # Old instance JSON with no recorded start-time: pid-only liveness applies.
    assert instance_alive(_inst(sleeper.pid, None)) is True


def test_dead_pid_is_not_alive(sleeper):
    real = proc_pid_start(sleeper.pid)
    sleeper.terminate()
    sleeper.wait()  # reap: an unreaped zombie would still answer kill(0)
    assert instance_alive(_inst(sleeper.pid, real)) is False
    assert instance_alive(_inst(sleeper.pid, None)) is False
