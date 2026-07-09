"""Push/pull transport classification and crash-attribution contracts.

Drives `cli.main` for push/pull with a fake SSH transfer seam that can append
serial bytes during the operation and raise structured `SSHError` evidence.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import guest
from qmu.instance import VMInstance
from qmu.ssh import SSHError


PANIC_LOG = (
    "[    3.111] general protection fault: 0000 [#1] PREEMPT SMP\n"
    "[    3.112] Kernel panic - not syncing: Fatal exception\n"
    "[    3.113] RIP: 0010:do_the_bad_thing+0x40/0x80\n"
)


def _fake_instance(serial_log: str) -> VMInstance:
    return VMInstance(
        vm_id="xfer-vm",
        pid=4242,
        qmp_socket="/tmp/xfer-vm.qmp.sock",
        ssh_port=10099,
        ssh_key="/tmp/xfer-vm.key",
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-05-29T00:00:00Z",
        harness=False,
    )


class FakeTransferSSH:
    def __init__(self, serial_path, *, append_text="", failure=None):
        self.serial_path = serial_path
        self.append_text = append_text
        self.failure = failure
        self.calls = []

    def _perform(self, operation, first, second):
        self.calls.append((operation, first, second))
        if self.append_text:
            with open(self.serial_path, "a", encoding="utf-8") as stream:
                stream.write(self.append_text)
        if self.failure is not None:
            raise self.failure

    def push(self, local, remote):
        self._perform("push", local, remote)

    def pull(self, remote, local):
        self._perform("pull", remote, local)


def _install_transfer(
    monkeypatch,
    tmp_path,
    *,
    operation: str,
    initial_serial: str = "boot ok\n",
    append_text: str = "",
    failure: SSHError | None = None,
    forbid_extract: bool = False,
):
    serial = tmp_path / "xfer-vm.serial.log"
    serial.write_text(initial_serial)
    inst = _fake_instance(str(serial))
    fake = FakeTransferSSH(str(serial), append_text=append_text, failure=failure)
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest, "_make_ssh", lambda i: fake)
    monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
    if forbid_extract:
        monkeypatch.setattr(
            guest,
            "extract_crash",
            lambda *a, **kw: (_ for _ in ()).throw(
                AssertionError("extract_crash must not be called")
            ),
        )
    return fake, inst, serial


def _run_transfer(operation: str, fmt: str, local: str, remote: str) -> int:
    if operation == "push":
        argv = ["--format", fmt, "push", local, remote]
    else:
        argv = ["--format", fmt, "pull", remote, local]
    return cli.main(argv)


@pytest.mark.parametrize("operation", ["push", "pull"])
@pytest.mark.parametrize("fmt", ["text", "json", "ndjson"])
def test_transfer_success_preserves_paths_and_status(
    monkeypatch, tmp_path, capsys, operation, fmt
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    _install_transfer(monkeypatch, tmp_path, operation=operation)

    rc = _run_transfer(operation, fmt, local, remote)
    out = capsys.readouterr().out

    assert rc == 0
    if fmt == "text":
        if operation == "push":
            assert out.strip() == f"Pushed {local} -> guest:{remote}"
        else:
            assert out.strip() == f"Pulled guest:{remote} -> {local}"
    else:
        if fmt == "ndjson":
            assert len(out.splitlines()) == 1
        payload = json.loads(out)
        assert payload == {"ok": True, "local": local, "remote": remote}


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_transfer_local_validation_is_exit4_without_crash_claim(
    monkeypatch, tmp_path, capsys, fmt
):
    missing = tmp_path / "missing.bin"
    failure = SSHError(f"Local file not found: {missing}")
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation="push",
        failure=failure,
        forbid_extract=True,
    )

    rc = cli.main(["--format", fmt, "push", str(missing), "/root/"])
    out = capsys.readouterr().out
    if fmt == "ndjson":
        assert len(out.splitlines()) == 1
    payload = json.loads(out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert payload["error"] == f"Local file not found: {missing}"
    assert "crash" not in payload
    assert "crash_detected" not in payload
    assert "ssh_error" not in payload


@pytest.mark.parametrize("operation", ["push", "pull"])
@pytest.mark.parametrize(
    "stderr",
    ["No such file or directory", "Permission denied"],
)
@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_transfer_remote_filesystem_failure_is_ordinary_exit4(
    monkeypatch, tmp_path, capsys, operation, stderr, fmt
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    message = (
        f"SCP {operation} failed: {stderr}"
    )
    failure = SSHError(message, returncode=1, stderr=stderr)
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        initial_serial=PANIC_LOG,
        failure=failure,
        forbid_extract=True,
    )

    rc = _run_transfer(operation, fmt, local, remote)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert rc == 4
    assert payload == {
        "ok": False,
        "error": message,
        "error_type": "SSHError",
    }


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_transfer_protocol_failure_stays_exit4_even_when_fresh_crash_exists(
    monkeypatch, tmp_path, capsys, operation
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    failure = SSHError(
        f"SCP {operation} failed: protocol error",
        returncode=1,
        stderr="protocol error",
    )
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        append_text=PANIC_LOG,
        failure=failure,
        forbid_extract=True,
    )

    rc = _run_transfer(operation, "json", local, remote)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert "crash" not in payload
    assert "crash_detected" not in payload


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_transfer_rc255_without_marker_is_ordinary_exit4(
    monkeypatch, tmp_path, capsys, operation
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    stderr = "scp: Connection closed"
    failure = SSHError(
        f"SCP {operation} failed: {stderr}",
        returncode=255,
        stderr=stderr,
    )
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        append_text=PANIC_LOG,
        failure=failure,
        forbid_extract=True,
    )

    rc = _run_transfer(operation, "json", local, remote)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert "crash" not in payload
    assert "crash_detected" not in payload


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_transfer_timeout_is_exit4_without_crash_claim(
    monkeypatch, tmp_path, capsys, operation
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    if operation == "push":
        message = f"SCP push timed out after 30s: {local} -> {remote}"
    else:
        message = f"SCP pull timed out after 30s: {remote} -> {local}"
    failure = SSHError(message)
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        failure=failure,
        forbid_extract=True,
    )

    rc = _run_transfer(operation, "json", local, remote)
    payload = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["error_type"] == "SSHError"
    assert "crash" not in payload
    assert "crash_detected" not in payload


@pytest.mark.parametrize("operation", ["push", "pull"])
@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_transfer_transport_loss_with_fresh_crash_is_exit3(
    monkeypatch, tmp_path, capsys, operation, fmt
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    failure = SSHError(
        f"SCP {operation} failed: mux failed: Broken pipe",
        returncode=255,
        stderr="mux failed: Broken pipe",
    )
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        initial_serial="boot ok\n",
        append_text=PANIC_LOG,
        failure=failure,
    )

    rc = _run_transfer(operation, fmt, local, remote)
    out = capsys.readouterr().out
    if fmt == "ndjson":
        assert len(out.splitlines()) == 1
    payload = json.loads(out)

    assert rc == 3
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert payload["operation"] == operation
    assert payload["local"] == local
    assert payload["remote"] == remote
    assert "panic" in payload["crash"].lower()
    assert "qmu crash" in payload["hint"]


@pytest.mark.parametrize("operation", ["push", "pull"])
@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_transfer_transport_loss_without_fresh_crash_is_exit4(
    monkeypatch, tmp_path, capsys, operation, fmt
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    failure = SSHError(
        f"SCP {operation} failed: mux failed: Broken pipe",
        returncode=255,
        stderr="mux failed: Broken pipe",
    )
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        initial_serial="boot ok\n",
        append_text="",
        failure=failure,
    )

    rc = _run_transfer(operation, fmt, local, remote)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None
    assert "qmu log --tail 100" in payload["hint"]


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_transfer_transport_loss_ignores_stale_precommand_crash(
    monkeypatch, tmp_path, capsys, operation
):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")
    failure = SSHError(
        f"SCP {operation} failed: mux failed: Broken pipe",
        returncode=255,
        stderr="mux failed: Broken pipe",
    )
    _install_transfer(
        monkeypatch,
        tmp_path,
        operation=operation,
        initial_serial=PANIC_LOG,
        append_text="",
        failure=failure,
    )

    rc = _run_transfer(operation, "json", local, remote)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert rc == 4
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is False
    assert payload["crash"] is None
    assert "panic" not in out.lower()
    assert "Fatal exception" not in out


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_transfer_json_ndjson_semantic_parity(monkeypatch, tmp_path, capsys, operation):
    local = str(tmp_path / "payload.bin")
    remote = "/root/payload.bin"
    (tmp_path / "payload.bin").write_bytes(b"data")

    cases = [
        ("success", "", None),
        (
            "ordinary",
            "",
            SSHError(
                f"SCP {operation} failed: No such file or directory",
                returncode=1,
                stderr="No such file or directory",
            ),
        ),
        (
            "transport_crash",
            PANIC_LOG,
            SSHError(
                f"SCP {operation} failed: Broken pipe",
                returncode=255,
                stderr="Broken pipe",
            ),
        ),
        (
            "transport_no_crash",
            "",
            SSHError(
                f"SCP {operation} failed: Broken pipe",
                returncode=255,
                stderr="Broken pipe",
            ),
        ),
    ]

    for name, append_text, failure in cases:
        payloads = {}
        rcs = {}
        for fmt in ("json", "ndjson"):
            # Fresh fixture per format
            sub = tmp_path / f"{operation}-{name}-{fmt}"
            sub.mkdir()
            local_fmt = str(sub / "payload.bin")
            (sub / "payload.bin").write_bytes(b"data")
            _install_transfer(
                monkeypatch,
                sub,
                operation=operation,
                append_text=append_text,
                failure=failure,
            )
            rcs[fmt] = _run_transfer(operation, fmt, local_fmt, remote)
            out = capsys.readouterr().out
            if fmt == "ndjson":
                assert len(out.splitlines()) == 1
            payloads[fmt] = json.loads(out)
            assert (rcs[fmt] == 0) is payloads[fmt]["ok"]

        # Normalize local paths which differ per format fixture
        for fmt in ("json", "ndjson"):
            if "local" in payloads[fmt]:
                payloads[fmt] = {**payloads[fmt], "local": "<local>"}
        assert payloads["json"] == payloads["ndjson"]
        assert rcs["json"] == rcs["ndjson"]
