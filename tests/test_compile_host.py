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
from qmu.ssh import SSHAborted, SSHError


def _fake_instance(serial_log: str, arch: str | None = "x86_64") -> VMInstance:
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

    def __init__(
        self,
        run_results=None,
        *,
        ready=True,
        serial_path=None,
        append_on_run="",
        push_raises=None,
    ):
        self.pushes: list[tuple[str, str]] = []
        self.runs: list[str] = []
        self._run_results = list(run_results or [])
        self.ready = ready
        self.serial_path = serial_path
        self.append_on_run = append_on_run
        self.push_raises = push_raises

    def _panic(self):
        if self.append_on_run and self.serial_path is not None:
            with open(self.serial_path, "a", encoding="utf-8") as stream:
                stream.write(self.append_on_run)

    def is_ready(self, timeout=2):
        return self.ready

    def push(self, local, remote, **kwargs):
        self.pushes.append((local, remote))
        if self.push_raises is not None:
            self._panic()
            raise self.push_raises

    def run(self, command, timeout=None, **kwargs):
        self.runs.append(command)
        self._panic()
        if self._run_results:
            return self._run_results.pop(0)
        return 0, "", ""


@pytest.fixture
def wired(monkeypatch, tmp_path):
    """Wire choose_instance/_make_ssh/preflight; return (install, state)."""
    serial = tmp_path / "hostcc-vm.serial.log"
    serial.write_text("[    0.000] Linux version 6.9.0\n")
    state: dict = {"serial": serial}

    def _install(*, arch="x86_64", run_results=None, **ssh_kw):
        inst = _fake_instance(str(serial), arch=arch)
        ssh = FakeSSH(run_results=run_results, serial_path=serial, **ssh_kw)
        monkeypatch.setattr(guest, "choose_instance", lambda vm=None: inst)
        monkeypatch.setattr(guest, "_make_ssh", lambda instance: ssh)
        monkeypatch.setattr(
            guest, "_preflight_ssh_guest", lambda instance, *, stem: None
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


def test_cc_flag_is_honored_by_the_guest_compile_too(wired, source, capsys):
    """`--cc` without `--host` was accepted and silently ignored (measured:
    `compile_cmd` showed plain `gcc`). It now names the guest compiler."""
    install, _state = wired
    ssh = install()

    rc = cli.main(["compile", "--format", "json", "--cc", "gcc -O2", str(source)])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["compiled_on"] == "guest"
    assert payload["compile_cmd"].startswith("gcc -O2 -static -lpthread -o ")
    assert ssh.runs == [payload["compile_cmd"]]


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


PANIC = (
    "[    4.100] BUG: unable to handle page fault for address: ffffffff81000000\n"
    "[    4.101] Kernel panic - not syncing: Fatal exception\n"
)


def test_panic_during_delivery_chmod_is_a_crash_not_a_compile_failure(
    wired, source, capsys
):
    """rc=255 from chmod is both a legal exit code and what ssh returns when a
    panic drops the transport. Reporting the panic as 'compilation failed' with
    ssh_error:false would bury the very thing the caller is looking for."""
    install, _state = wired
    install(
        run_results=[(255, "", "")],
        ready=False,              # liveness probe confirms the guest is gone
        append_on_run=PANIC,
    )

    rc = cli.main(["compile", "--host", "--format", "json", str(source)])

    assert rc == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "Kernel panic" in payload["crash"]


def test_transport_loss_delivering_the_binary_without_a_crash_is_exit_4(
    wired, source, capsys
):
    """Same discrimination push/pull use: no fresh crash report means the guest
    is merely unreachable (4), never the kernel-crash class (3)."""
    install, _state = wired
    install(run_results=[(255, "", "")], ready=False)

    rc = cli.main(["compile", "--host", "--format", "json", str(source)])

    assert rc == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is False


def test_scp_transport_failure_during_delivery_is_classified(wired, source, capsys):
    install, _state = wired
    install(
        push_raises=SSHError(
            "SCP push failed: Connection reset by peer",
            returncode=255,
            stderr="Connection reset by peer",
        ),
        append_on_run=PANIC,
    )

    rc = cli.main(["compile", "--host", "--format", "json", str(source)])

    assert rc == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True


def test_non_transport_scp_failure_still_surfaces_as_infra(wired, source):
    """A plain scp error (not a transport marker) must not be dressed up as a
    guest crash — it stays the infrastructure class."""
    install, _state = wired
    install(
        push_raises=SSHError(
            "SCP push failed: No such file or directory",
            returncode=1,
            stderr="No such file or directory",
        )
    )

    assert cli.main(["compile", "--host", str(source)]) == 4


def test_quoted_cflags_survive_on_the_host_path(wired, source, capsys):
    """The in-guest path interpolates --cflags into a guest shell, so a quoted
    flag works there; splitting on bare whitespace would break it on --host only."""
    install, _state = wired
    install()

    rc = cli.main([
        "compile", "--host", "--format", "json",
        "--cflags", "-O0 -DMSG='hello world'", str(source),
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    # One argv entry, not two: the shell's quoting work done by shlex.
    assert "-DMSG=hello world" in payload["compile_cmd"]


# --- --run composition -----------------------------------------------------

def test_host_build_then_run_executes_the_pushed_binary(wired, source, capsys):
    install, _state = wired
    ssh = install(run_results=[(0, "", ""), (0, "pwned\n", "")])

    rc = cli.main(["compile", "--host", "--run", str(source)])

    assert rc == 0
    assert ssh.runs == ["chmod +x /root/exploit", "/root/exploit"]
    assert "pwned" in capsys.readouterr().out


def test_run_text_mode_stdout_is_the_program_output_only(wired, source, capsys):
    """`compile --run ... > out.txt` must hold only what the program printed:
    the banner, the program's stderr and the `[exit code]` trailer are stderr,
    with the banner FIRST (it used to trail the output as a stderr note, so a
    terminal showed the header after the body)."""
    install, _state = wired
    install(run_results=[(0, "", ""), (3, "sizeof(void*)=8\n", "warn\n")])

    rc = cli.main(["compile", "--host", "--run", str(source)])

    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out == "sizeof(void*)=8\n"
    assert captured.err == "Compiled and ran exploit.c:\nwarn\n[exit code: 3]\n"


def test_compile_without_run_keeps_stdout_empty_in_text_mode(wired, source, capsys):
    """Same split without --run: the `Compiled ...` banner is a stderr note, so a
    redirect of `compile` collects nothing but program output on every path."""
    install, _state = wired
    install(run_results=[(0, "", "")])

    rc = cli.main(["compile", "--host", str(source)])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
    assert captured.err.startswith("Compiled exploit.c -> /root/exploit")


def test_compile_json_envelope_is_unchanged_by_the_stream_split(wired, source, capsys):
    install, _state = wired
    install(run_results=[(0, "", ""), (0, "pwned\n", "")])

    rc = cli.main(["--format", "json", "compile", "--host", "--run", str(source)])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["run_stdout"] == "pwned\n"
    assert payload["run_exit"] == 0


def test_host_build_then_run_propagates_a_non_zero_guest_exit(wired, source):
    install, _state = wired
    install(run_results=[(0, "", ""), (42, "", "boom")])

    assert cli.main(["compile", "--host", "--run", str(source)]) == 1


def test_scp_timeout_during_delivery_with_a_live_guest_stays_infra(wired, source, capsys):
    """An scp subprocess timeout carries no returncode and no transport marker:
    with nothing in the serial log it is an infra failure (4), never a guest
    crash, exactly as push/pull classify it."""
    install, _state = wired
    install(push_raises=SSHError("SCP push timed out after 30s: /tmp/x -> /root/x"))

    rc = cli.main(["--format", "json", "compile", "--host", str(source)])

    assert rc == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["error_type"] == "SSHError"
    assert "crash_detected" not in payload


@pytest.mark.parametrize("failure", [
    SSHAborted("SCP push aborted by qmu: /tmp/x -> /root/x"),
    SSHError("SCP push timed out after 30s: /tmp/x -> /root/x"),
])
def test_panic_appended_during_delivery_is_the_crash_class(wired, source, capsys, failure):
    """The watcher stops scp when the serial log shows a terminal panic
    (`SSHAborted`, no returncode); a timeout that coincides with the panic is
    the same outcome. Both are the kernel-crash class with the report — the
    bare `SSHAborted` used to escape as exit 4 with no report while the
    concurrent `exec` and the next `qmu crash` both returned the panic."""
    install, _state = wired
    install(push_raises=failure, append_on_run=PANIC)

    rc = cli.main(["--format", "json", "compile", "--host", str(source)])

    assert rc == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["ssh_error"] is True
    assert payload["crash_detected"] is True
    assert "Kernel panic - not syncing" in payload["crash"]
    assert payload["operation"] == "push"
    assert "qmu crash" in payload["hint"]


def test_compile_cmd_is_rendered_as_a_reusable_command(wired, source, capsys):
    """A quoted flag that shlex.split correctly kept as ONE argv entry must not
    be rendered back as two: the reported command should be runnable as shown."""
    install, _state = wired
    install()

    rc = cli.main([
        "compile", "--host", "--format", "json",
        "--cflags", "-O0 -DMSG='hello world'", str(source),
    ])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "'-DMSG=hello world'" in payload["compile_cmd"]
    # Round-trips: splitting the rendered command recovers the exact argv.
    import shlex
    assert "-DMSG=hello world" in shlex.split(payload["compile_cmd"])
