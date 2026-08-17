"""`qmu compile --host` — build on the host, push the artifact, run it.

The point of the flag is that the GUEST needs no toolchain: a minimal rootfs
(kernelCTF's, most vendor images, the one qmu-linux-rootfs builds) ships no gcc,
and an emulated cross-arch guest compiles orders of magnitude slower than the
host cross-compiler. So the contract these tests pin is:

  * no `gcc` is ever invoked in the guest on the --host path;
  * the pushed binary is made executable (scp does not preserve the mode, and a
    non-executable artifact would fail --run with a bare "Permission denied"
    that reads like a guest problem);
  * the JSON keys are the SAME as the in-guest path, with `compiled_on`
    recording which one ran, so a consumer need not branch;
  * a host compile failure renders as the ordinary "Compilation failed"
    envelope and exit 1, not as an infrastructure error.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import guest
from qmu.instance import QMUError, VMInstance


def _fake_instance(serial_log: str, arch: str | None = None) -> VMInstance:
    return VMInstance(
        vm_id="hostcc-vm",
        pid=5150,
        qmp_socket="/tmp/hostcc-vm.qmp.sock",
        ssh_port=10111,
        ssh_key="/tmp/hostcc-vm.key",
        gdb_port=None,
        serial_log=serial_log,
        kernel="/boot/bzImage",
        arch=arch,
        rootfs="/var/rootfs.img",
        memory="4G",
        cpus=2,
        cmdline="console=ttyS0",
        profile="exploit-dev",
        started_at="2026-08-17T00:00:00Z",
        harness=False,
    )


class FakeSSH:
    """Records guest-side traffic. `run_results` is consumed per run() call."""

    def __init__(self, run_results=None):
        self.pushes: list[tuple[str, str]] = []
        self.runs: list[str] = []
        self._run_results = list(run_results or [])

    def push(self, local, remote):
        self.pushes.append((local, remote))

    def run(self, command, timeout=None):
        self.runs.append(command)
        if self._run_results:
            return self._run_results.pop(0)
        return 0, "", ""


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Wire choose_instance/_make_ssh/preflight; return (install, state)."""
    serial = tmp_path / "hostcc-vm.serial.log"
    serial.write_text("[    0.000] Linux version 6.9.0\n")
    state: dict = {"serial": serial}

    def _install(*, arch=None, run_results=None):
        inst = _fake_instance(str(serial), arch=arch)
        ssh = FakeSSH(run_results=run_results)
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda instance: ssh)
        monkeypatch.setattr(
            guest, "_preflight_ssh_guest", lambda args, instance, stem: None
        )
        state["inst"] = inst
        state["ssh"] = ssh
        return ssh

    return _install, state


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "exploit.c"
    path.write_text("int main(void) { return 0; }\n")
    return path


# --- the host path ---------------------------------------------------------

def test_host_build_never_invokes_gcc_in_the_guest(wired, source, capsys):
    install, _state = wired
    ssh = install()

    rc = cli.main(["compile", "--host", str(source)])

    assert rc == 0, capsys.readouterr().out
    assert not any(cmd.startswith("gcc") for cmd in ssh.runs), ssh.runs


def test_host_build_pushes_the_binary_and_makes_it_executable(wired, source):
    """scp has no -p, so the artifact lands 0644 and --run would fail with a
    bare 'Permission denied'. chmod is part of delivering a runnable binary."""
    install, _state = wired
    ssh = install()

    rc = cli.main(["compile", "--host", str(source)])

    assert rc == 0
    assert len(ssh.pushes) == 1
    local, remote = ssh.pushes[0]
    assert local.endswith("/exploit")        # the built binary, not the .c
    assert remote == "/root/exploit"
    assert ssh.runs == ["chmod +x /root/exploit"]


def test_guest_path_still_pushes_source_and_compiles_in_guest(wired, source):
    """The default path is unchanged: --host is opt-in."""
    install, _state = wired
    ssh = install()

    rc = cli.main(["compile", str(source)])

    assert rc == 0
    assert ssh.pushes == [(str(source), "/root/exploit.c")]
    assert ssh.runs[0].startswith("gcc ")


@pytest.mark.parametrize(
    "argv,expected",
    [(["compile", "--host"], "host"), (["compile"], "guest")],
)
def test_compiled_on_records_which_path_ran(wired, source, capsys, argv, expected):
    install, _state = wired
    install()

    rc = cli.main([*argv, "--format", "json", str(source)])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["compiled_on"] == expected
    # Same key names on both paths so a consumer need not branch.
    for key in ("source", "compile_cmd", "compile_exit", "compile_stderr", "ok"):
        assert key in payload


def test_compiler_is_selected_from_the_guest_arch(monkeypatch, wired, source, capsys):
    """The instance's arch drives selection — not the host's. A host-arch binary
    on a cross-arch guest fails to exec with a much worse error."""
    install, _state = wired
    install(arch="aarch64")
    seen: dict = {}

    def _fake_resolve(arch, override):
        seen["arch"] = arch
        seen["override"] = override
        return ["aarch64-linux-gnu-gcc"]

    def _fake_compile(src, out, cflags, cc, timeout=120.0):
        out.write_bytes(b"\x7fELF fake")
        return 0, "", "", [*cc, "-o", str(out), str(src)]

    monkeypatch.setattr(guest, "resolve_host_cc", _fake_resolve)
    monkeypatch.setattr(guest, "host_compile", _fake_compile)

    rc = cli.main(["compile", "--host", "--format", "json", str(source)])

    assert rc == 0
    assert seen == {"arch": "aarch64", "override": None}
    payload = json.loads(capsys.readouterr().out)
    assert payload["compiler"] == "aarch64-linux-gnu-gcc"
    assert payload["guest_arch"] == "aarch64"


def test_cc_flag_reaches_the_resolver(monkeypatch, wired, source):
    install, _state = wired
    install()
    seen: dict = {}

    def _fake_resolve(arch, override):
        seen["override"] = override
        return ["cc"]

    monkeypatch.setattr(guest, "resolve_host_cc", _fake_resolve)
    cli.main(["compile", "--host", "--cc", "clang -target x", str(source)])

    assert seen["override"] == "clang -target x"


# --- failure paths ---------------------------------------------------------

def test_host_compile_failure_is_exit_1_with_the_ordinary_envelope(
    monkeypatch, wired, source, capsys
):
    install, _state = wired
    ssh = install()
    monkeypatch.setattr(guest, "resolve_host_cc", lambda arch, override: ["cc"])
    monkeypatch.setattr(
        guest,
        "host_compile",
        lambda src, out, cflags, cc, timeout=120.0: (
            1, "", "exploit.c:1:1: error: nope", ["cc"]
        ),
    )

    rc = cli.main(["compile", "--host", str(source)])

    assert rc == 1
    out = capsys.readouterr().out
    assert "Compilation failed on the host" in out
    assert "error: nope" in out
    # Nothing was delivered to the guest.
    assert ssh.pushes == []


def test_missing_toolchain_is_an_operational_error_not_a_traceback(
    monkeypatch, wired, source, capsys
):
    install, _state = wired
    install(arch="aarch64")

    def _boom(arch, override):
        raise QMUError("No host compiler found for guest arch 'aarch64'.")

    monkeypatch.setattr(guest, "resolve_host_cc", _boom)

    rc = cli.main(["compile", "--host", str(source)])

    assert rc == 1
    assert "No host compiler found" in capsys.readouterr().err


def test_chmod_failure_is_reported_as_a_compile_failure(
    monkeypatch, wired, source, capsys
):
    """A pushed-but-unrunnable binary is not a success: --run would fail later
    with an error that points at the guest instead of at the transfer."""
    install, _state = wired
    install(run_results=[(1, "", "chmod: Read-only file system")])

    rc = cli.main(["compile", "--host", "--format", "json", str(source)])

    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["compile_exit"] == 1
    assert "could not make it executable" in payload["compile_stderr"]


# --- --run composition -----------------------------------------------------

def test_host_build_then_run_executes_the_pushed_binary(wired, source, capsys):
    install, _state = wired
    ssh = install(run_results=[(0, "", ""), (0, "pwned\n", "")])

    rc = cli.main(["compile", "--host", "--run", str(source)])

    assert rc == 0
    assert ssh.runs == ["chmod +x /root/exploit", "/root/exploit"]
    assert "pwned" in capsys.readouterr().out


def test_host_build_then_run_propagates_a_non_zero_guest_exit(wired, source):
    install, _state = wired
    install(run_results=[(0, "", ""), (42, "", "boom")])

    assert cli.main(["compile", "--host", "--run", str(source)]) == 1
