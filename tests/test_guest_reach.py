"""Guest reach: a refused SSH login (#158), SFTP-less guests (#148), extra
guest ports (#149) and unprivileged guest commands (#150).

Doubles are installed on the command module that owns each handler
(`qmu.commands.guest` / `qmu.commands.lifecycle`), per CLAUDE.md.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest

from qmu import cli
from qmu._cliutil import _resolve_config_from_args
from qmu.commands import guest, lifecycle
from qmu.commands.lifecycle import QMP_CONNECTED, _QMPProbe
from qmu.config import parse_forward_spec, resolve_config
from qmu.config import ConfigError, QMUConfig
from qmu.instance import QMUError, VMInstance
from qmu.ssh import (
    PROBE_AUTH_FAILED,
    PROBE_DOWN,
    PROBE_READY,
    SCPFileError,
    SSHClient,
    SSHError,
    GuestText,
)
from qmu.vm import _bind_forward_ports, build_qemu_command, launch_vm


def _instance(serial_log: str, *, ssh_user: str = "root") -> VMInstance:
    return VMInstance(
        vm_id="reach-vm", pid=4242, qmp_socket="/tmp/reach-vm.qmp.sock",
        ssh_port=10099, ssh_key="/tmp/reach-vm.key", ssh_user=ssh_user,
        gdb_port=None, serial_log=serial_log, kernel="/boot/bzImage",
        rootfs="/var/rootfs.img", memory="4G", cpus=2, cmdline="console=ttyS0",
        profile="exploit-dev", started_at="2026-10-19T00:00:00Z",
    )


def _executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# ---------------------------------------------------------------------------
# #158 — sshd answering "Permission denied" is not "down" and not "booting"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rc,stderr,expected",
    [
        (255, b"lowpriv@localhost: Permission denied (publickey,password).\r\n", PROBE_AUTH_FAILED),
        (255, b"ssh: connect to host localhost port 2222: Connection refused\r\n", PROBE_DOWN),
        (255, b"Connection timed out during banner exchange\r\n", PROBE_DOWN),
        (0, b"", PROBE_READY),
    ],
)
def test_probe_tells_a_refused_login_from_a_dead_port(monkeypatch, rc, stderr, expected):
    client = SSHClient(port=2222, key_path="k", user="lowpriv")
    monkeypatch.setattr(
        "qmu.ssh.subprocess.run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, rc, b"", stderr),
    )

    assert client.probe() == expected
    assert client.is_ready() is (expected == PROBE_READY)
    assert client.last_probe == expected


class _RefusingSSH(SSHClient):
    """Real classification and error building; sshd refuses every login."""

    def probe(self, timeout=2):
        self.last_probe = PROBE_AUTH_FAILED
        self.last_probe_stderr = f"{self.user}@localhost: Permission denied (publickey)."
        return PROBE_AUTH_FAILED

    def run(self, command, timeout=30.0, check=False, **kwargs):
        return 255, GuestText(b""), GuestText(
            f"{self.user}@localhost: Permission denied (publickey).\n".encode()
        )


def test_exec_names_the_refused_user_instead_of_calling_the_guest_unreachable(
    monkeypatch, tmp_path, capsys
):
    """ssh's 255 for a refused login used to take the transport-loss path:
    "VM may be unreachable", with no word of which account was tried."""
    serial = tmp_path / "reach-vm.serial.log"
    serial.write_text("boot ok\n")
    inst = _instance(str(serial), ssh_user="lowpriv")
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest, "_make_ssh", lambda i: _RefusingSSH(i.ssh_port, i.ssh_key, user=i.ssh_user))
    monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest, "_require_running_vm", lambda vm, command: None)
    monkeypatch.setattr(guest, "_qmp_stopped_status", lambda inst: None)

    rc = cli.main(["exec", "--vm", "reach-vm", "--format", "json", "id"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 4
    assert payload["error_type"] == "SSHAuthError"
    assert payload["ssh_status"] == "auth-failed"
    assert payload["ssh_user"] == "lowpriv"
    assert "unreachable" not in payload["error"]


def test_status_reports_a_refused_login_as_serving_with_the_user(
    monkeypatch, tmp_path, capsys
):
    """`status` used to say `ssh: "down"`, `guest: "unknown"` (SSH down) for a
    guest whose sshd was answering, and nothing named the user."""
    serial = tmp_path / "reach-vm.serial.log"
    serial.write_text("Linux version 6.1.0\nlocalhost login:\n")
    inst = _instance(str(serial), ssh_user="lowpriv")
    monkeypatch.setattr(lifecycle, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(
        lifecycle, "_query_qmp",
        lambda i: _QMPProbe(QMP_CONNECTED, status="running", running=True),
    )
    monkeypatch.setattr(lifecycle, "_make_ssh", lambda i: _RefusingSSH(i.ssh_port, i.ssh_key, user=i.ssh_user))

    assert cli.main(["status", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["ssh"] == "auth-failed"
    assert payload["guest"] == "serving"
    assert payload["ssh_user"] == "lowpriv"


# ---------------------------------------------------------------------------
# #148 — a guest without an SFTP server gets the legacy protocol (scp -O)
# ---------------------------------------------------------------------------


def _fake_scp(tmp_path: Path, monkeypatch, *, legacy: str) -> Path:
    """An `scp` on PATH that speaks like a Dropbear guest's other end: SFTP
    mode dies on the missing sftp-server; `-O` does whatever `legacy` says."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "scp-calls"
    _executable(bindir / "scp", f"""#!/bin/sh
echo "$*" >> {calls}
for a in "$@"; do [ "$a" = -O ] && {{ {legacy}; }}; done
echo "sh: /usr/libexec/sftp-server: No such file or directory" >&2
echo "scp: Connection closed" >&2
exit 255
""")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return calls


def _called_with_legacy(calls: Path) -> list[bool]:
    return ["-O" in line.split() for line in calls.read_text().splitlines()]


def test_transfers_fall_back_to_legacy_scp_on_a_guest_without_sftp(tmp_path, monkeypatch):
    calls = _fake_scp(tmp_path, monkeypatch, legacy="exit 0")
    client = SSHClient(port=2222, key_path="k")
    source = tmp_path / "blob.bin"
    source.write_bytes(b"x")

    client.push(str(source), "/tmp/blob.bin")
    assert _called_with_legacy(calls) == [False, True]

    # The client stays on the protocol the guest speaks.
    client.pull("/tmp/blob.bin", str(tmp_path / "back.bin"))
    assert _called_with_legacy(calls) == [False, True, True]


def test_a_guest_with_neither_sftp_nor_scp_is_a_guest_condition(tmp_path, monkeypatch):
    calls = _fake_scp(
        tmp_path, monkeypatch,
        legacy='echo "sh: scp: not found" >&2; exit 1',
    )
    client = SSHClient(port=2222, key_path="k")
    source = tmp_path / "blob.bin"
    source.write_bytes(b"x")

    with pytest.raises(SCPFileError) as exc:
        client.push(str(source), "/tmp/blob.bin")

    assert "sftp-server" in str(exc.value) and "scp: not found" in str(exc.value)
    assert exc.value.hint is not None
    assert _called_with_legacy(calls) == [False, True]


def test_a_dead_transport_is_not_retried_as_legacy(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "scp-calls"
    _executable(bindir / "scp", f"""#!/bin/sh
echo "$*" >> {calls}
echo "ssh: connect to host localhost port 2222: Connection refused" >&2
exit 255
""")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    source = tmp_path / "blob.bin"
    source.write_bytes(b"x")

    with pytest.raises(SSHError):
        SSHClient(port=2222, key_path="k").push(str(source), "/tmp/blob.bin")

    assert _called_with_legacy(calls) == [False]


# ---------------------------------------------------------------------------
# #149 — --forward / [machine] forwards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("2345", {"host": "127.0.0.1", "host_port": None, "guest_port": 2345}),
        ("12345:2345", {"host": "127.0.0.1", "host_port": 12345, "guest_port": 2345}),
        ("0.0.0.0:8080:80", {"host": "0.0.0.0", "host_port": 8080, "guest_port": 80}),
    ],
)
def test_forward_spec_forms(spec, expected):
    assert parse_forward_spec(spec) == expected


@pytest.mark.parametrize("spec", ["0:80", "8080:70000", "a:1:2:3", "http:80", ":8080:80", ""])
def test_malformed_forward_specs_are_refused(spec):
    with pytest.raises(ValueError):
        parse_forward_spec(spec)


def test_forward_flag_replaces_the_config_list(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text('[machine]\nforwards = ["2345", "8080:80"]\n')
    assert resolve_config().forwards == ["2345", "8080:80"]

    args = cli.build_parser().parse_args(["launch", "--forward", "9000:90"])
    config = _resolve_config_from_args(args)
    assert config.forwards == ["9000:90"]
    assert config.source_layer("forwards") == "flag"


def test_a_bad_config_forward_names_its_index(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "qmu.toml").write_text('[machine]\nforwards = ["2345", "nope"]\n')

    with pytest.raises(ConfigError) as exc:
        resolve_config()

    assert exc.value.key_path == "machine.forwards[1]"


def test_a_malformed_forward_flag_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main(["launch", "--forward", "80:", "--format", "json"])
    assert exc.value.code == 2


def test_forwards_ride_qmus_own_netdev():
    config = QMUConfig()
    cmd = build_qemu_command(
        config=config, kernel="bzImage", rootfs=None, ssh_port=10021,
        gdb_port=None, qmp_socket="q.sock", serial_log="s.log", cmdline="",
        forwards=[
            {"host": "127.0.0.1", "host_port": 10022, "guest_port": 2345},
            {"host": "0.0.0.0", "host_port": 8080, "guest_port": 80},
        ],
    )
    netdev = cmd[cmd.index("-netdev") + 1]
    assert "hostfwd=tcp:127.0.0.1:10021-:22" in netdev
    assert "hostfwd=tcp:127.0.0.1:10022-:2345" in netdev
    assert "hostfwd=tcp:0.0.0.0:8080-:80" in netdev


@pytest.mark.parametrize(
    "kwargs,needle",
    [({"no_net": True}, "--no-net"), ({"net_backend": "passt"}, "passt")],
)
def test_forwards_without_qmus_nic_are_refused_not_dropped(tmp_path, kwargs, needle):
    for name in ("bzImage", "rootfs.img", "key"):
        (tmp_path / name).write_bytes(b"x")
    config = QMUConfig(
        kernel=str(tmp_path / "bzImage"), rootfs=str(tmp_path / "rootfs.img"),
        ssh_key=str(tmp_path / "key"), forwards=["2345"],
    )

    with pytest.raises(QMUError) as exc:
        launch_vm(config=config, kernel=config.kernel, **kwargs)

    assert needle in str(exc.value)


def test_auto_forward_ports_skip_the_ports_this_launch_picked():
    taken = {10021}
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        start = probe.getsockname()[1]
    taken.add(start)

    resolved = _bind_forward_ports(
        [{"host": "127.0.0.1", "host_port": None, "guest_port": 2345}],
        start=start, taken=taken,
    )

    assert resolved[0]["host_port"] not in {10021, start}


def test_a_pinned_forward_port_in_use_is_named():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        busy = listener.getsockname()[1]

        with pytest.raises(QMUError) as exc:
            _bind_forward_ports(
                [{"host": "127.0.0.1", "host_port": busy, "guest_port": 80}],
                start=10021, taken=set(),
            )

    assert str(busy) in str(exc.value)


# ---------------------------------------------------------------------------
# #150 — --user NAME
# ---------------------------------------------------------------------------


_TRICKY = """printf '%s|%s\\n' "it's $1" "$(pwd)"; exit 7"""


@pytest.mark.parametrize("drop", ["runuser", "su"])
def test_privilege_drop_keeps_quoting_cwd_and_exit_status(tmp_path, drop):
    """The wrapper must hand the command to the guest shell unchanged (single
    quotes, `$`), start in the account's home, and forward its exit status —
    through `runuser`, or `su` on a BusyBox guest without it."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if drop == "runuser":
        # runuser -u NAME -- sh -c CMD  ->  sh -c CMD
        _executable(bindir / "runuser", '#!/bin/sh\nshift 3\nexec "$@"\n')
    else:
        # su -s /bin/sh NAME -c CMD  ->  /bin/sh -c CMD
        _executable(bindir / "su", '#!/bin/sh\nexec "$2" -c "$5"\n')
    home = tmp_path / "home"
    home.mkdir()
    path = f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin"
    if drop == "su" and any(Path(d, "runuser").exists() for d in ("/usr/bin", "/bin")):
        pytest.skip("host has runuser on the restricted PATH")

    wire = guest._as_user(_TRICKY, "nobody")
    result = subprocess.run(
        ["sh", "-c", wire], capture_output=True, text=True, cwd=tmp_path,
        env={"PATH": path, "HOME": str(home)},
    )

    assert result.returncode == 7
    assert result.stdout == f"it's |{home}\n"


class _RecordingSSH:
    def __init__(self):
        self.runs: list[str] = []

    def run(self, command, timeout=30.0, check=False, **kwargs):
        self.runs.append(command)
        return 0, GuestText(b"uid=65534(nobody)\n"), GuestText(b"")

    def is_ready(self, timeout=2):
        return True


@pytest.mark.parametrize("user,wrapped", [("nobody", True), ("root", False)])
def test_exec_user_wraps_only_a_foreign_account_and_reports_run_as(
    monkeypatch, tmp_path, capsys, user, wrapped
):
    serial = tmp_path / "reach-vm.serial.log"
    serial.write_text("boot ok\n")
    inst = _instance(str(serial))
    fake = _RecordingSSH()
    monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
    monkeypatch.setattr(guest, "_make_ssh", lambda i: fake)
    monkeypatch.setattr(guest, "_preflight_ssh_guest", lambda *a, **kw: None)
    monkeypatch.setattr(guest, "_require_running_vm", lambda vm, command: None)

    rc = cli.main(["exec", "--vm", "reach-vm", "--user", user, "--format", "json", "--", "id", "-u"])
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["run_as"] == user
    assert ("runuser -u nobody" in fake.runs[0]) is wrapped
    if not wrapped:
        assert fake.runs == ["id -u"]


def test_compile_user_without_run_is_refused(tmp_path, capsys):
    source = tmp_path / "poc.c"
    source.write_text("int main(void){return 0;}\n")

    rc = cli.main(["compile", str(source), "--user", "nobody", "--format", "json"])

    assert rc == 1
    assert "--run" in json.loads(capsys.readouterr().out)["error"]
