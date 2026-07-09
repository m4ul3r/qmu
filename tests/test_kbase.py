from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from qmu import _cliutil, cli
from qmu.commands import qmp_cmds
from qmu.instance import QMUError, VMInstance
from qmu.qmp import QMPError
from qmu.ssh import SSHError


def test_parse_nm_posix_text_symbol():
    assert qmp_cmds._parse_nm_text(
        "startup_64 T ffffffff81000000\n"
        "_text T ffffffff81000000\n"
        "_stext T ffffffff81000100\n"
    ) == 0xFFFFFFFF81000000


def test_parse_nm_ignores_nearby_symbol_names():
    assert qmp_cmds._parse_nm_text(
        "_stext T 1000\n_text T 2000\n_text_end T 3000\n"
    ) == 0x2000


@pytest.mark.parametrize(
    ("output", "fragment"),
    [
        ("_stext T 1000\n", "missing _text"),
        ("_text T 1000\n_text T 2000\n", "multiple _text"),
        ("_text T not-hex\n", "invalid _text address"),
        ("_text T 0\n", "zero _text address"),
    ],
)
def test_parse_nm_rejects_unusable_text(output, fragment):
    with pytest.raises(QMUError, match=fragment):
        qmp_cmds._parse_nm_text(output)


def test_parse_kallsyms_text_symbol():
    assert qmp_cmds._parse_kallsyms_text(
        "ffffffff95200000 T _text\n"
    ) == 0xFFFFFFFF95200000


@pytest.mark.parametrize(
    ("output", "fragment"),
    [
        ("ffffffff95200000 T _stext\n", "missing _text"),
        (
            "ffffffff95200000 T _text\nffffffff95400000 T _text\n",
            "multiple _text",
        ),
        ("not-hex T _text\n", "invalid _text address"),
        ("0000000000000000 T _text\n", "restricted /proc/kallsyms"),
    ],
)
def test_parse_kallsyms_rejects_unusable_text(output, fragment):
    with pytest.raises(QMUError, match=fragment):
        qmp_cmds._parse_kallsyms_text(output)


def test_format_hex_supports_zero_positive_and_negative_values():
    assert qmp_cmds._format_hex(0) == "0x0"
    assert qmp_cmds._format_hex(0x14000000) == "0x14000000"
    assert qmp_cmds._format_hex(-0x200000) == "-0x200000"


class FakeSSH:
    def __init__(self, result=(0, "ffffffff95200000 T _text\n", "")):
        self.result = result
        self.calls: list[tuple[str, float]] = []

    def run(self, command, timeout=30.0, check=False):
        self.calls.append((command, timeout))
        return self.result


class FakeQMP:
    def __init__(self, *, status="running", enter_error=None):
        self.status = status
        self.enter_error = enter_error
        self.calls: list[str] = []

    def __enter__(self):
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def __exit__(self, *args):
        return False

    def execute(self, command):
        self.calls.append(command)
        assert command == "query-status"
        return {"status": self.status}


@pytest.fixture
def kbase_vm(tmp_path):
    return VMInstance(
        vm_id="debug-vm",
        pid=4242,
        qmp_socket=str(tmp_path / "debug-vm.qmp.sock"),
        ssh_port=10022,
        ssh_key=str(tmp_path / "id_rsa"),
        gdb_port=1234,
        serial_log=str(tmp_path / "serial.log"),
        kernel=str(tmp_path / "bzImage"),
        rootfs=str(tmp_path / "rootfs.img"),
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-07-09T00:00:00+00:00",
        harness=False,
        arch="x86_64",
    )


def _fail_if_called(label):
    def fail(*args, **kwargs):
        raise AssertionError(f"{label} was called")

    return fail


def _json_payload(capsys):
    return json.loads(capsys.readouterr().out)


def _assert_operational_error(rc, payload, *fragments):
    assert rc == 1
    assert payload["ok"] is False
    assert payload["error_type"] == "QMUError"
    assert payload["error"]
    for fragment in fragments:
        assert fragment in payload["error"]


def test_read_link_text_prefers_nm(monkeypatch, tmp_path):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    seen = []
    monkeypatch.setattr(
        qmp_cmds.shutil,
        "which",
        lambda name: "/usr/bin/nm" if name == "nm" else None,
    )
    monkeypatch.setattr(
        qmp_cmds.subprocess,
        "run",
        lambda cmd, **kwargs: (
            seen.append((cmd, kwargs))
            or subprocess.CompletedProcess(
                cmd, 0, "_text T ffffffff81000000\n", ""
            )
        ),
    )

    resolved, address = qmp_cmds._read_link_text(str(symbols))

    assert resolved == symbols.resolve()
    assert address == 0xFFFFFFFF81000000
    assert seen[0][0] == [
        "/usr/bin/nm", "-P", "--defined-only", str(symbols.resolve())
    ]
    assert seen[0][1] == {
        "capture_output": True,
        "text": True,
        "timeout": 15,
    }


def test_read_link_text_falls_back_to_llvm_nm(monkeypatch, tmp_path):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    monkeypatch.setattr(
        qmp_cmds.shutil,
        "which",
        lambda name: "/usr/bin/llvm-nm" if name == "llvm-nm" else None,
    )
    completed = subprocess.CompletedProcess(
        [], 0, "_text T ffffffff81000000\n", ""
    )
    run = pytest.MonkeyPatch.context()
    with run as patch:
        called = []
        patch.setattr(
            qmp_cmds.subprocess,
            "run",
            lambda cmd, **kwargs: called.append(cmd) or completed,
        )
        qmp_cmds._read_link_text(str(symbols))
    assert called[0][0] == "/usr/bin/llvm-nm"


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_kbase_nonzero_slide_structured(
    monkeypatch, tmp_path, kbase_vm, fmt, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    fake = FakeSSH()
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", fmt, "kbase", "--vm", "debug-vm",
        "--symbols", str(symbols),
    ])
    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    payload = json.loads("\n".join(lines)) if fmt == "json" else json.loads(lines[0])

    assert rc == 0
    assert payload == {
        "ok": True,
        "vm_id": "debug-vm",
        "arch": "x86_64",
        "symbols": str(symbols.resolve()),
        "kbase": "0xffffffff95200000",
        "link_base": "0xffffffff81000000",
        "slide": "0x14200000",
    }
    if fmt == "ndjson":
        assert len(lines) == 1
    assert fake.calls == [(
        "awk '$3 == \"_text\" { print $1, $2, $3 }' /proc/kallsyms",
        10.0,
    )]


def test_kbase_zero_slide_text(monkeypatch, tmp_path, kbase_vm, capsys):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    fake = FakeSSH((0, "ffffffff81000000 T _text\n", ""))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main(["kbase", "--symbols", str(symbols)])

    assert rc == 0
    assert capsys.readouterr().out == (
        "KBASE=0xffffffff81000000\n"
        "LINK_BASE=0xffffffff81000000\n"
        "SLIDE=0x0\n"
    )


def test_kbase_missing_symbols_file_is_exit_1(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    missing = tmp_path / "missing-vmlinux"
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(qmp_cmds.shutil, "which", _fail_if_called("symbol lookup"))
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(missing)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(rc, payload, "symbols file not found", str(missing))


def test_kbase_missing_nm_and_llvm_nm_is_exit_1(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    lookups = []
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds.shutil,
        "which",
        lambda name: lookups.append(name) or None,
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(rc, payload, "no local symbol tool", "llvm-nm")
    assert lookups == ["nm", "llvm-nm"]


def test_kbase_nm_failure_is_exit_1_and_includes_tool_diagnostic(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(qmp_cmds.shutil, "which", lambda name: "/usr/bin/nm")
    monkeypatch.setattr(
        qmp_cmds.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 2, "", "file format not recognized"
        ),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(
        rc, payload, "nm failed", "exit 2", "file format not recognized"
    )


def test_kbase_guest_command_failure_is_exit_1(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH((2, "", "permission denied"))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(
        rc, payload, "/proc/kallsyms", "exit 2", "permission denied"
    )


def test_kbase_missing_runtime_text_is_exit_1(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH((0, "ffffffff95200000 T _stext\n", ""))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(rc, payload, "/proc/kallsyms", "missing _text")


def test_kbase_restricted_kallsyms_is_exit_1_json(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH((0, "0000000000000000 T _text\n", ""))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(
        rc, payload, "restricted /proc/kallsyms", "kptr_restrict"
    )


def test_kbase_harness_fails_before_preflight_and_ssh(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    kbase_vm.harness = True
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(
        qmp_cmds, "_preflight_ssh_guest", _fail_if_called("preflight")
    )
    monkeypatch.setattr(qmp_cmds, "_read_link_text", _fail_if_called("local tool"))
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))
    monkeypatch.setattr(qmp_cmds.subprocess, "run", _fail_if_called("subprocess"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(tmp_path / "vmlinux")
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(rc, payload, "harness-mode", "no SSH")


def test_kbase_unknown_legacy_arch_fails_with_relaunch_guidance(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    kbase_vm.arch = None
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(qmp_cmds, "_read_link_text", _fail_if_called("local tool"))
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(tmp_path / "vmlinux")
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(
        rc, payload, "predates architecture metadata", "relaunch"
    )


def test_kbase_unsupported_arch_fails_before_local_tool_and_ssh(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    kbase_vm.arch = "riscv64"
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(qmp_cmds, "_read_link_text", _fail_if_called("local tool"))
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(tmp_path / "vmlinux")
    ])
    payload = _json_payload(capsys)

    _assert_operational_error(rc, payload, "riscv64", "does not support")


def test_kbase_paused_uses_pr1_preflight_and_never_constructs_ssh(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    qmp = FakeQMP(status="paused")
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(_cliutil, "_qmp_ctx", lambda inst: qmp)
    monkeypatch.setattr(qmp_cmds, "_read_link_text", _fail_if_called("local tool"))
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))
    monkeypatch.setattr(qmp_cmds.subprocess, "run", _fail_if_called("subprocess"))

    rc = cli.main([
        "--format", "json", "kbase", "--vm", "debug-vm",
        "--symbols", str(tmp_path / "vmlinux"),
    ])
    payload = _json_payload(capsys)

    assert rc == 1
    assert qmp.calls == ["query-status"]
    assert payload["ok"] is False
    assert payload["qemu_status"] == "paused"
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False
    assert "crash" not in payload
    assert "qmu cont --vm debug-vm" in payload["hint"]
    assert "pry continue" in payload["hint"]


def test_kbase_qmp_unavailable_preflight_falls_through_to_ssh(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH()
    qmp = FakeQMP(enter_error=QMPError("unavailable"))
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(_cliutil, "_qmp_ctx", lambda inst: qmp)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    assert rc == 0
    assert payload["ok"] is True
    assert fake.calls == [(
        "awk '$3 == \"_text\" { print $1, $2, $3 }' /proc/kallsyms",
        10.0,
    )]


def test_kbase_nm_timeout_is_infrastructure_exit_4(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    symbols.write_bytes(b"ELF")
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(qmp_cmds.shutil, "which", lambda name: "/usr/bin/nm")
    monkeypatch.setattr(
        qmp_cmds.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(a[0], 15)
        ),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", _fail_if_called("SSH"))

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "TimeoutExpired"


def test_kbase_ssh_error_is_infrastructure_exit_4(
    monkeypatch, tmp_path, kbase_vm, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH()

    def fail_run(command, timeout=30.0, check=False):
        raise SSHError("guest transport unavailable")

    fake.run = fail_run
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert "guest transport unavailable" in payload["error"]


@pytest.mark.parametrize("arch", ["x86_64", "i386", "aarch64", "arm"])
def test_kbase_accepts_each_supported_guest_architecture(
    monkeypatch, tmp_path, kbase_vm, arch, capsys
):
    symbols = tmp_path / "vmlinux"
    fake = FakeSSH()
    kbase_vm.arch = arch
    monkeypatch.setattr(qmp_cmds, "choose_instance", lambda vm: kbase_vm)
    monkeypatch.setattr(qmp_cmds, "_preflight_ssh_guest", lambda *a, **k: None)
    monkeypatch.setattr(
        qmp_cmds,
        "_read_link_text",
        lambda path: (symbols.resolve(), 0xFFFFFFFF81000000),
    )
    monkeypatch.setattr(qmp_cmds, "_make_ssh", lambda inst: fake)

    rc = cli.main([
        "--format", "json", "kbase", "--symbols", str(symbols)
    ])
    payload = _json_payload(capsys)

    assert rc == 0
    assert payload["ok"] is True
    assert payload["arch"] == arch
    assert payload["kbase"] == "0xffffffff95200000"
