from __future__ import annotations

from unittest.mock import Mock

import pytest

from qmu import vm
from qmu.config import QMUConfig
from qmu.instance import QMUError
from qmu.qemu import QEMUNetdevCapabilities


def _launch_fixture(tmp_path, *, arch="x86_64", backend="passt"):
    kernel = tmp_path / "bzImage"
    rootfs = tmp_path / "rootfs.img"
    key = tmp_path / "id_ed25519"
    for path in (kernel, rootfs, key):
        path.write_bytes(b"")
    cfg = QMUConfig(
        arch=arch,
        net_backend=backend,
        rootfs=str(rootfs),
        ssh_key=str(key),
    )
    return cfg, kernel


def _caps(binary, *, path=True, passt=True, error=None):
    return QEMUNetdevCapabilities(
        binary=binary,
        path=f"/opt/qemu/bin/{binary}" if path else None,
        backends=frozenset({"user", "passt"} if passt else {"user", "stream"}),
        error=error,
    )


def _exited_popen():
    proc = Mock(pid=4242, returncode=1)
    proc.poll.return_value = 1
    return Mock(return_value=proc)


def _watch_launch_side_effects(monkeypatch):
    port_allocator = Mock(return_value=10022)
    popen = _exited_popen()
    monkeypatch.setattr(vm, "find_free_port", port_allocator)
    monkeypatch.setattr(vm.subprocess, "Popen", popen)
    return port_allocator, popen


def _assert_no_launch_side_effects(port_allocator, popen):
    port_allocator.assert_not_called()
    popen.assert_not_called()
    assert not vm.instances_dir().exists()


def test_unsupported_native_passt_fails_before_spawn_or_artifacts(monkeypatch, tmp_path):
    cfg, kernel = _launch_fixture(tmp_path)
    probe = Mock(return_value=_caps("qemu-system-x86_64", passt=False))
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    passt_lookup = Mock(return_value="/usr/bin/passt")
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)
    port_allocator, popen = _watch_launch_side_effects(monkeypatch)

    with pytest.raises(QMUError, match="does not advertise.*-netdev passt") as exc:
        vm.launch_vm(config=cfg, kernel=str(kernel), name="unsupported")

    assert "QEMU 10.1" in str(exc.value)
    assert "build-optional" in str(exc.value)
    probe.assert_called_once_with("qemu-system-x86_64")
    passt_lookup.assert_not_called()
    _assert_no_launch_side_effects(port_allocator, popen)


def test_missing_selected_qemu_fails_without_probe_subprocess_or_spawn(monkeypatch, tmp_path):
    cfg, kernel = _launch_fixture(tmp_path, arch="aarch64")
    probe = Mock(
        return_value=_caps(
            "qemu-system-aarch64",
            path=False,
            passt=False,
            error="Selected QEMU binary 'qemu-system-aarch64' was not found in PATH",
        )
    )
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    passt_lookup = Mock(return_value="/usr/bin/passt")
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)
    port_allocator, popen = _watch_launch_side_effects(monkeypatch)

    with pytest.raises(QMUError, match="qemu-system-aarch64.*not found in PATH"):
        vm.launch_vm(config=cfg, kernel=str(kernel), name="missing")

    probe.assert_called_once_with("qemu-system-aarch64")
    passt_lookup.assert_not_called()
    _assert_no_launch_side_effects(port_allocator, popen)


def test_native_capability_failure_precedes_missing_external_passt(monkeypatch, tmp_path):
    cfg, kernel = _launch_fixture(tmp_path)
    probe = Mock(return_value=_caps("qemu-system-x86_64", passt=False))
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    passt_lookup = Mock(return_value=None)
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)
    port_allocator, popen = _watch_launch_side_effects(monkeypatch)

    with pytest.raises(QMUError, match="does not advertise"):
        vm.launch_vm(config=cfg, kernel=str(kernel))

    probe.assert_called_once_with("qemu-system-x86_64")
    passt_lookup.assert_not_called()
    _assert_no_launch_side_effects(port_allocator, popen)


def test_supported_native_passt_still_requires_external_passt(monkeypatch, tmp_path):
    cfg, kernel = _launch_fixture(tmp_path)
    probe = Mock(return_value=_caps("qemu-system-x86_64"))
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    passt_lookup = Mock(return_value=None)
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)
    port_allocator, popen = _watch_launch_side_effects(monkeypatch)

    with pytest.raises(QMUError, match="requires the 'passt' binary on PATH"):
        vm.launch_vm(config=cfg, kernel=str(kernel))

    probe.assert_called_once_with("qemu-system-x86_64")
    passt_lookup.assert_called_once_with("passt")
    _assert_no_launch_side_effects(port_allocator, popen)


def test_preflight_probes_only_selected_architecture_binary(monkeypatch):
    cfg = QMUConfig(arch="aarch64", net_backend="passt")
    seen = []
    monkeypatch.setattr(
        vm,
        "probe_qemu_netdevs",
        lambda binary: seen.append(binary) or _caps(binary),
        raising=False,
    )
    monkeypatch.setattr(vm.shutil, "which", lambda name: "/usr/bin/passt")

    path = vm._preflight_native_passt(
        config=cfg,
        net_backend=None,
        no_net=False,
        harness=False,
    )

    assert seen == ["qemu-system-aarch64"]
    assert path == "/opt/qemu/bin/qemu-system-aarch64"


@pytest.mark.parametrize(
    ("configured", "override", "no_net", "harness"),
    [
        ("user", None, False, False),
        ("passt", "user", False, False),
        ("passt", None, True, False),
        ("passt", None, False, True),
    ],
)
def test_non_passt_launch_modes_skip_capability_and_external_passt(
    monkeypatch, configured, override, no_net, harness
):
    cfg = QMUConfig(net_backend=configured)
    probe = Mock(side_effect=AssertionError("probe must be skipped"))
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    monkeypatch.setattr(
        vm.shutil,
        "which",
        Mock(side_effect=AssertionError("external passt lookup must be skipped")),
    )

    assert vm._preflight_native_passt(
        config=cfg,
        net_backend=override,
        no_net=no_net,
        harness=harness,
    ) is None
    probe.assert_not_called()


def test_passt_override_probes_and_checks_external_passt(monkeypatch):
    cfg = QMUConfig(net_backend="user")
    probe = Mock(return_value=_caps("qemu-system-x86_64"))
    passt_lookup = Mock(return_value="/usr/bin/passt")
    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)

    path = vm._preflight_native_passt(
        config=cfg,
        net_backend="passt",
        no_net=False,
        harness=False,
    )

    assert path == "/opt/qemu/bin/qemu-system-x86_64"
    probe.assert_called_once_with("qemu-system-x86_64")
    passt_lookup.assert_called_once_with("passt")


def test_launch_probes_once_and_reuses_resolved_qemu_across_port_retry(
    monkeypatch, tmp_path
):
    cfg, kernel = _launch_fixture(tmp_path)
    resolved = "/opt/qemu/bin/qemu-system-x86_64"
    probe = Mock(return_value=_caps("qemu-system-x86_64"))
    passt_lookup = Mock(return_value="/usr/bin/passt")
    port_allocator = Mock(side_effect=[10022, 10023])
    commands = []
    process_specs = iter([
        (4242, "Address already in use"),
        (4243, "intentional test stop"),
    ])

    def fake_popen(cmd, *, stdout, **kwargs):
        pid, output = next(process_specs)
        stdout.write(output)
        stdout.flush()
        proc = Mock(pid=pid, returncode=1)
        proc.poll.return_value = 1
        commands.append(cmd)
        return proc

    monkeypatch.setattr(vm, "probe_qemu_netdevs", probe, raising=False)
    monkeypatch.setattr(vm.shutil, "which", passt_lookup)
    monkeypatch.setattr(vm, "find_free_port", port_allocator)
    monkeypatch.setattr(vm.subprocess, "Popen", fake_popen)

    with pytest.raises(QMUError, match="QEMU exited immediately"):
        vm.launch_vm(config=cfg, kernel=str(kernel), name="resolved-binary")

    probe.assert_called_once_with("qemu-system-x86_64")
    passt_lookup.assert_called_once_with("passt")
    assert [cmd[0] for cmd in commands] == [resolved, resolved]
