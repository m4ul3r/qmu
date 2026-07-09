from __future__ import annotations

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
        ["/opt/qemu/bin/qemu-system-aarch64", "-netdev", "help"],
        capture_output=True,
        text=True,
        timeout=5.0,
        check=False,
    )


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
