from __future__ import annotations

import shutil
import subprocess
from unittest.mock import Mock

import pytest

from qmu import qemu
from qmu.qemu import (
    QEMUNetdevCapabilities,
    native_passt_problem,
    probe_qemu_netdevs,
)


def _result(*, stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["/opt/qemu/bin/qemu-system-aarch64", "-netdev", "help"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_probe_reads_exact_netdev_names_from_selected_qemu(monkeypatch, stream):
    monkeypatch.setattr(qemu.shutil, "which", lambda name: "/opt/qemu/bin/" + name)
    output = "Available netdev backend types:\nuser\nstream\npasst\nvhost-user\n"
    run = Mock(return_value=_result(**{stream: output}))
    monkeypatch.setattr(qemu.subprocess, "run", run)

    caps = probe_qemu_netdevs("qemu-system-aarch64")

    assert caps == QEMUNetdevCapabilities(
        binary="qemu-system-aarch64",
        path="/opt/qemu/bin/qemu-system-aarch64",
        backends=frozenset({"user", "stream", "passt", "vhost-user"}),
    )
    assert caps.available is True
    assert caps.supports("passt") is True
    run.assert_called_once_with(
        ["/opt/qemu/bin/qemu-system-aarch64", "-machine", "none", "-netdev", "help"],
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )


def test_probe_forces_machine_none_for_arches_without_a_default(monkeypatch):
    # Regression: aarch64/arm/riscv abort with "No machine specified" before
    # enumerating netdev backends unless a machine is selected, which produced
    # a false-negative native-passt result. `-machine none` must always be
    # passed so the probe reaches backend enumeration on every arch.
    monkeypatch.setattr(qemu.shutil, "which", lambda name: "/opt/qemu/bin/" + name)
    run = Mock(
        return_value=_result(
            stdout="Available netdev backend types:\nuser\npasst\n"
        )
    )
    monkeypatch.setattr(qemu.subprocess, "run", run)

    probe_qemu_netdevs("qemu-system-aarch64")

    argv = run.call_args.args[0]
    assert argv[1:3] == ["-machine", "none"]


def test_probe_does_not_accept_passt_as_a_substring(monkeypatch):
    monkeypatch.setattr(qemu.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(
        qemu.subprocess,
        "run",
        lambda *args, **kwargs: _result(
            stdout="Available netdev backend types:\nuser\npassthrough-helper\nstream\n"
        ),
    )
    caps = probe_qemu_netdevs("qemu-system-x86_64")
    assert caps.supports("passt") is False
    assert native_passt_problem(caps) is not None


def test_missing_selected_qemu_is_a_structured_result_and_does_not_run(monkeypatch):
    monkeypatch.setattr(qemu.shutil, "which", lambda name: None)
    run = Mock()
    monkeypatch.setattr(qemu.subprocess, "run", run)

    caps = probe_qemu_netdevs("qemu-system-aarch64")

    assert caps.path is None
    assert caps.backends == frozenset()
    assert "not found in PATH" in caps.error
    assert "qemu-system-aarch64" in native_passt_problem(caps)
    run.assert_not_called()


@pytest.mark.parametrize(
    ("effect", "expected"),
    [
        ("nonzero", "exited with status 1"),
        ("timeout", "timed out after 5.0 seconds"),
        ("oserror", "could not run"),
    ],
)
def test_probe_failures_are_distinct_from_unsupported(monkeypatch, effect, expected):
    monkeypatch.setattr(qemu.shutil, "which", lambda name: "/usr/bin/" + name)
    if effect == "nonzero":
        behavior = Mock(return_value=_result(stderr="bad option", returncode=1))
    elif effect == "timeout":
        behavior = Mock(side_effect=subprocess.TimeoutExpired(["qemu"], 5.0))
    else:
        behavior = Mock(side_effect=OSError("exec format error"))
    monkeypatch.setattr(qemu.subprocess, "run", behavior)

    caps = probe_qemu_netdevs("qemu-system-x86_64")

    assert caps.path == "/usr/bin/qemu-system-x86_64"
    assert caps.backends == frozenset()
    assert expected in caps.error
    assert "does not advertise" not in native_passt_problem(caps)


def test_unsupported_message_is_capability_based_with_qemu_10_1_context():
    caps = QEMUNetdevCapabilities(
        binary="qemu-system-x86_64",
        path="/usr/bin/qemu-system-x86_64",
        backends=frozenset({"user", "stream"}),
    )
    message = native_passt_problem(caps)
    assert "does not advertise the native '-netdev passt' backend" in message
    assert "QEMU 10.1" in message
    assert "build-optional" in message
    assert "10.1+" not in message
    assert ">=" not in message
    assert "version" not in message.lower()


# --- real-binary cross-arch coverage -------------------------------------
# The mocked tests above stub subprocess.run, so they cannot catch a probe
# invocation that a real qemu binary rejects. The original bug was exactly
# that: `-netdev help` with no `-machine` exits 1 on arches without a default
# machine (aarch64, arm, riscv...), so the probe reported a false error on a
# passt-capable QEMU. These tests run the ACTUAL binary when installed and
# skip cleanly when it is not (e.g. CI without cross-arch qemu packages).

_CROSS_ARCH_BINARIES = [
    "qemu-system-x86_64",
    "qemu-system-i386",
    "qemu-system-aarch64",
    "qemu-system-arm",
    "qemu-system-riscv64",
]


@pytest.mark.parametrize("binary", _CROSS_ARCH_BINARIES)
def test_real_probe_reaches_backend_enumeration_on_every_installed_arch(binary):
    """Regression guard for the missing `-machine none`: on every installed
    arch — not just x86_64 — the real probe must reach netdev enumeration
    (no error) and report backends, including the always-present `user`."""
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed on this host")

    caps = probe_qemu_netdevs(binary)

    assert caps.error is None, (
        f"{binary}: probe failed to reach netdev enumeration: {caps.error}"
    )
    assert caps.available is True
    assert "user" in caps.backends, f"{binary}: backends={sorted(caps.backends)}"
