"""`qmu run` — boot, run one guest command, reap, report once.

`run` collapses launch → exec → kill into a single call, so the two things that
must not drift are:

  * the exit code is the GUEST command's outcome, mapped onto the existing
    contract with no new codes (0/1/3/124), using the same crash-vs-transport
    discrimination `qmu exec` uses — it calls `guest._run_guest_command`, not a
    second copy of it;
  * reaping is conditional. A VM is fully removed only when nothing is left to
    look at. If the run crashed the kernel, never reached a guest, or died on
    boot, the QEMU process is stopped but the instance metadata and .serial.log
    survive — reaping the evidence of the crash the agent just triggered would
    make `run` strictly worse than the three commands it replaces.

The QEMU/SSH seams are faked; `tests/live-transcript.md` is where the real-VM
verification lives.
"""

from __future__ import annotations

import json

import pytest

from qmu import cli
from qmu.commands import lifecycle, run
from qmu.instance import VMInstance
from qmu.ssh import GuestText, SSHError

# Captured before any test stubs it: the fixture replaces this seam with a
# no-op, and the --no-replace test needs the real guard back.
_REAL_REPLACE_EXISTING = lifecycle._replace_existing_named_vm


PANIC = (
    "[    4.100] BUG: unable to handle page fault for address: ffffffff81000000\n"
    "[    4.101] Kernel panic - not syncing: Fatal exception\n"
    "[    4.102] RIP: 0010:evil+0x10/0x20\n"
)


class FakeSSH:
    def __init__(
        self,
        *,
        ready=True,
        run_result=(0, "", ""),
        run_raises=None,
        serial_path=None,
        append_on_run="",
        ready_after_run=None,
    ):
        self.ready = ready
        self.run_result = run_result
        self.run_raises = run_raises
        self.serial_path = serial_path
        self.append_on_run = append_on_run
        # A guest that panics DURING the command answered SSH a moment earlier —
        # that is how `run` got as far as running anything. Modelling the panic
        # as ready=False from the start instead makes the VM merely unreachable
        # at boot, which is a different code path entirely.
        self.ready_after_run = ready_after_run
        self.runs: list[str] = []
        self.probes = 0
        self.master_closes = 0

    def is_ready(self, timeout=2):
        self.probes += 1
        return self.ready

    def close_control_master(self, timeout=5.0):
        self.master_closes += 1
        return True

    def run(self, command, timeout=None, **kwargs):
        self.runs.append(command)
        # Crash detection is command-scoped: `_run_guest_command` records the
        # serial offset BEFORE the command, so a panic only counts if it lands
        # while the command runs. Appending here is what makes the fake honest.
        if self.append_on_run and self.serial_path is not None:
            with open(self.serial_path, "a", encoding="utf-8") as stream:
                stream.write(self.append_on_run)
        if self.ready_after_run is not None:
            self.ready = self.ready_after_run
        if self.run_raises is not None:
            raise self.run_raises
        return self.run_result


@pytest.fixture
def harness(monkeypatch, tmp_path):
    """Fake the launch/SSH/kill seams. Returns an `install(...)` callable."""
    serial = tmp_path / "run-vm.serial.log"
    state: dict = {"kills": [], "serial": serial, "launched": False}

    def _install(*, serial_text="[    0.000] Linux version 6.9.0\n", alive=True, **ssh_kw):
        serial.write_text(serial_text)
        inst = VMInstance(
            vm_id="run-vm",
            pid=6001,
            qmp_socket=str(tmp_path / "run-vm.qmp.sock"),
            ssh_port=10222,
            ssh_key=str(tmp_path / "run-vm.key"),
            gdb_port=None,
            serial_log=str(serial),
            kernel="/boot/bzImage",
            arch="x86_64",
            rootfs="/var/rootfs.img",
            memory="4G",
            cpus=2,
            cmdline="console=ttyS0 nokaslr",
            profile="exploit-dev",
            started_at="2026-08-17T00:00:00Z",
            harness=False,
        )
        ssh = FakeSSH(serial_path=serial, **ssh_kw)

        def _launch(**kwargs):
            state["launched"] = True
            state["launch_kwargs"] = kwargs
            return inst

        monkeypatch.setattr(run, "launch_vm", _launch)
        monkeypatch.setattr(run, "_make_ssh", lambda instance: ssh)
        monkeypatch.setattr(run, "instance_alive", lambda instance: alive)
        # `run` boots through lifecycle._prepare_boot, which reads this name
        # from lifecycle's namespace — so that is where the seam lives.
        monkeypatch.setattr(
            lifecycle, "_replace_existing_named_vm", lambda name, no_replace: None
        )
        monkeypatch.setattr(
            run,
            "_kill_vm",
            lambda instance, force=False, clean=True: state["kills"].append(clean),
        )
        state["inst"] = inst
        state["ssh"] = ssh
        return ssh

    return _install, state


def _argv(*extra):
    return ["run", "--kernel", "/boot/bzImage", *extra]


# --- exit-code matrix ------------------------------------------------------

def test_successful_command_exits_0_and_reaps_the_vm(harness, capsys):
    install, state = harness
    ssh = install(run_result=(0, "uid=0(root)\n", ""))

    rc = cli.main(_argv("id"))

    assert rc == 0
    assert ssh.runs == ["id"]
    assert state["kills"] == [True]          # clean=True -> fully reaped
    out = capsys.readouterr().out
    assert "uid=0(root)" in out
    # Clean path stays byte-comparable with `qmu exec`: no VM chatter on stdout,
    # so `qmu run ... | grep` behaves the same way.
    assert "Serial log" not in out
    assert "qmu prune" not in out


def test_non_zero_guest_command_exits_1_and_still_reaps(harness):
    """An ordinary failure is not evidence: keeping a VM per failed run would
    leak instances across a normal edit-run loop."""
    install, state = harness
    install(run_result=(3, "", "no such file"))

    rc = cli.main(_argv("./exploit"))

    assert rc == 1
    assert state["kills"] == [True]


def test_crash_during_the_command_exits_3_and_preserves_state(harness, capsys):
    install, state = harness
    install(
        append_on_run=PANIC,
        # Boots fine, then the command kills it: the post-command liveness probe
        # is what separates this from a healthy command that outran --timeout.
        ready_after_run=False,
        run_raises=SSHError("SSH command timed out after 60s: ./exploit"),
    )

    rc = cli.main(_argv("./exploit"))

    assert rc == 3
    assert state["kills"] == [False]         # clean=False -> serial log kept
    captured = capsys.readouterr()
    assert "Kernel panic - not syncing" in captured.out
    # Follow-up hints are stderr notes: stdout is what `qmu exec` would print.
    assert "qmu crash --vm run-vm" in captured.err
    assert "state preserved" in captured.err
    assert "state preserved" not in captured.out


def test_boot_panic_exits_3_with_the_report(harness, capsys):
    """A kernel that panics before sshd is the single most valuable outcome to
    get right: it must be exit 3 WITH the report, not a bare boot timeout."""
    install, state = harness
    install(serial_text=PANIC, ready=False, alive=False)

    rc = cli.main(_argv("./exploit"))

    assert rc == 3
    assert state["kills"] == [False]
    out = capsys.readouterr().out
    assert "crashed before the guest became reachable" in out
    assert "Kernel panic - not syncing" in out


def test_vm_dies_on_boot_without_a_crash_exits_1(harness, capsys):
    install, state = harness
    install(serial_text="early boot noise\n", ready=False, alive=False)

    rc = cli.main(_argv("./exploit"))

    assert rc == 1
    assert state["kills"] == [False]
    out = capsys.readouterr().out
    assert "exited before the guest became reachable" in out
    assert "No crash report" in out


def test_unreachable_guest_exits_124(harness, capsys):
    """VM alive, no crash, guest never answers -> the wait-timeout code, so an
    agent can tell 'never came up' from 'command failed'."""
    install, state = harness
    install(serial_text="booting...\n", ready=False, alive=True)

    rc = cli.main(_argv("--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    assert state["kills"] == [False]
    out = capsys.readouterr().out
    assert "did not become reachable" in out


# The keys `launch --ssh-timeout` and `run --ssh-timeout` share when the window
# closes with the guest still booting (#72): one shape, one exit code (124).
SSH_TIMEOUT_ENVELOPE_KEYS = {"ok", "error", "error_type", "timed_out", "ssh_error", "hint"}


def test_unreachable_guest_envelope_matches_launch_timeout_shape(harness, capsys):
    """#72: `run` and `launch` exit 124 for an expired --ssh-timeout and
    describe it identically: `timed_out: true`, `ssh_error: true`,
    `error_type: TimeoutError`, an `error` and a `hint`."""
    install, _ = harness
    install(serial_text="[0.0] Linux\n", ready=False, alive=True)

    rc = cli.main(_argv("--format", "json", "--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert SSH_TIMEOUT_ENVELOPE_KEYS <= set(payload)
    assert payload["ok"] is False
    assert payload["timed_out"] is True
    assert payload["ssh_error"] is True
    assert payload["error_type"] == "TimeoutError"
    assert "SSH did not become ready" in payload["error"]
    assert "--ssh-timeout" in payload["hint"]


WARNING = (
    "[    1.500] ------------[ cut here ]------------\n"
    "[    1.501] WARNING: CPU: 0 PID: 1 at drivers/thing.c:42 thing_init+0x10/0x20\n"
    "[    1.502] ---[ end trace 0000000000000000 ]---\n"
)


def test_boot_warning_without_a_panic_is_not_promoted_to_a_crash(harness, capsys):
    """extract_crash also matches SURVIVED reports (WARNING/KASAN). A guest that
    merely never started sshd must stay 124 — claiming exit 3 would tell the
    caller a healthy kernel died."""
    install, state = harness
    install(serial_text=WARNING, ready=False, alive=True)

    rc = cli.main(_argv("--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    out = capsys.readouterr().out
    # The warning is still SHOWN and the state preserved — it is usually the
    # reason the boot went wrong — it just does not change the exit code.
    assert "Non-fatal kernel report" in out
    assert "WARNING: CPU: 0" in out
    assert state["kills"] == [False]


def test_boot_report_is_reported_as_a_survived_crash_without_exit_3(harness, capsys):
    """A survived boot-time report is `crash_detected` (what `status` and
    `crash` call it, #136) but, with no terminal panic, never the exit-3
    class: the guest that printed it is still alive."""
    install, state = harness
    install(serial_text=WARNING, ready=False, alive=True)

    rc = cli.main(_argv("--format", "json", "--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert "WARNING: CPU: 0" in payload["crash"]


def test_survived_kernel_warning_during_a_clean_run_is_not_reaped(harness, capsys):
    """Under the default exploit-dev profile an Oops kills only the faulting
    task, so a command can trigger a splat and still exit 0. Reaping there would
    delete the splat the run just produced."""
    install, state = harness
    install(run_result=(0, "done\n", ""), append_on_run=WARNING)

    rc = cli.main(_argv("--format", "json", "./exploit"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert payload["state_preserved"] is True
    assert state["kills"] == [False]          # clean=False -> serial log kept


def test_keep_does_not_claim_a_dead_vm_is_running(harness, capsys):
    install, state = harness
    install(ready=False, alive=False, serial_text="early boot noise\n")

    rc = cli.main(_argv("--format", "json", "--keep", "./exploit"))

    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert state["kills"] == []               # --keep still means "do not kill"
    assert payload["vm_state"] != "running"
    assert "exited" in payload["vm_state"]


def test_ssh_timeout_zero_still_probes_once(harness):
    """--ssh-timeout 0 means 'probe once', not 'never try'."""
    install, state = harness
    ssh = install(ready=False, alive=True)

    cli.main(_argv("--ssh-timeout", "0", "id"))

    assert ssh.probes >= 1


# --- reaping policy --------------------------------------------------------

def test_keep_leaves_the_vm_running(harness, capsys):
    install, state = harness
    install(run_result=(0, "ok\n", ""))

    rc = cli.main(_argv("--keep", "id"))

    assert rc == 0
    assert state["kills"] == []              # never killed
    assert state["ssh"].master_closes == 0   # the VM stays up; so does its mux
    captured = capsys.readouterr()
    assert captured.out == "ok\n"
    assert "run-vm" in captured.err and "running" in captured.err


def test_text_stdout_is_the_guest_bytes_with_no_added_newline(harness, capsysbinary):
    """`qmu run -- 'printf x' | od -An -tx1` measured `78 0a` (#80): the
    text renderer line-terminated the guest's stdout. `run` shares exec's
    emitter, so it is byte-exact too, with the follow-up notes on stderr."""
    install, state = harness
    install(run_result=(0, GuestText(b"x"), GuestText(b"")))

    rc = cli.main(_argv("printf x"))

    assert rc == 0
    assert capsysbinary.readouterr().out == b"x"


def test_unexpected_error_after_launch_still_stops_the_vm(monkeypatch, harness):
    """An exception between launch and reap must not orphan a QEMU process
    holding the rootfs — and must keep the serial log for the post-mortem."""
    install, state = harness
    install()

    def _boom(ssh, inst, timeout):
        raise RuntimeError("internal failure")

    monkeypatch.setattr(run, "_wait_for_guest", _boom)

    rc = cli.main(_argv("id"))

    assert rc == 4                            # main() catch-all, not 3
    assert state["kills"] == [False]          # stopped, state preserved


# --- envelope --------------------------------------------------------------

def test_json_envelope_identifies_the_vm_and_its_fate(harness, capsys):
    install, state = harness
    install(run_result=(0, "hi\n", ""))

    rc = cli.main(_argv("--format", "json", "echo", "hi"))

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["vm_id"] == "run-vm"
    assert payload["command"] == "echo hi"
    assert payload["exit_code"] == 0
    assert payload["arch"] == "x86_64"
    assert payload["serial_log"].endswith("run-vm.serial.log")
    assert payload["vm_state"] == "reaped"
    assert payload["state_preserved"] is False
    assert payload["vm_kept"] is False
    # L1 booleans present on every path.
    assert payload["ssh_error"] is False
    assert payload["crash_detected"] is False


def test_json_envelope_on_a_crash_reports_preserved_state(harness, capsys):
    install, state = harness
    install(
        append_on_run=PANIC,
        ready_after_run=False,
        run_raises=SSHError("transport lost"),
    )

    rc = cli.main(_argv("--format", "json", "./exploit"))

    assert rc == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["crash_detected"] is True
    assert "Kernel panic" in payload["crash"]
    assert payload["state_preserved"] is True
    assert payload["vm_state"] == "stopped (state preserved)"


# --- parser surface --------------------------------------------------------

def test_boot_flags_are_forwarded_to_launch(harness):
    install, state = harness
    install(run_result=(0, "", ""))

    cli.main(_argv("--profile", "exploit-test", "--cmdline", "console=ttyS0 nokaslr",
                   "--name", "one-shot", "--gdb", "id"))

    kwargs = state["launch_kwargs"]
    assert kwargs["profile"] == "exploit-test"
    assert kwargs["cmdline"] == "console=ttyS0 nokaslr"
    assert kwargs["name"] == "one-shot"
    assert kwargs["gdb"] is True
    assert kwargs["harness"] is False


def test_append_extends_the_profile_cmdline_on_run(harness):
    """`run` and `launch` register one flag set, so they must APPLY it alike.

    A flag that parses on `run` but is only honored by `launch` is the
    subcommand-divergence the shared registrar exists to close: it presents as
    a boot that silently ignores the parameter the caller asked for.
    """
    install, state = harness
    install(run_result=(0, "", ""))

    cli.main(_argv("--append", "slub_debug=- nokaslr", "id"))

    # append is resolved by launch_vm, so it must arrive there rather than
    # being folded into (or dropped from) the cmdline here.
    assert state["launch_kwargs"]["append"] == "slub_debug=- nokaslr"
    # ...and it must NOT have replaced the profile.
    assert state["launch_kwargs"]["cmdline"] is None


def test_inject_runs_before_boot_on_run(monkeypatch, harness):
    """--inject must land before the guest boots, on `run` as on `launch`.

    A one-shot boot is exactly when the binary needs to be in the image
    already, so registering the flag without honoring it would be worse than
    not offering it: the run would report success against stale contents.
    """
    install, state = harness
    install(run_result=(0, "", ""))

    calls: list[tuple] = []
    monkeypatch.setattr(
        lifecycle, "_preflight_injects",
        lambda config, specs, partition=1, mkdir=False: None,
    )
    monkeypatch.setattr(
        lifecycle, "_inject_into_rootfs",
        lambda config, specs, partition=1, mkdir=False: calls.append(
            (specs, partition, mkdir)
        ),
    )

    cli.main(_argv("--inject", "./exploit:/root", "--mkdir", "id"))

    assert calls == [(["./exploit:/root"], 1, True)]
    assert state["launched"] is True


def test_qemu_args_are_flag_carried(harness):
    """`run` spends its positional on the guest command, so QEMU passthrough has
    to be a flag — and it is not decoration: an aarch64/arm guest does not boot
    without `-M virt`, which is exactly the case --host compiles target."""
    install, state = harness
    install(run_result=(0, "", ""))

    cli.main(_argv("--arch", "aarch64", "--qemu-arg=-M", "--qemu-arg=virt", "uname -m"))

    assert state["launch_kwargs"]["extra_args"] == ["-M", "virt"]


def test_no_qemu_args_passes_none(harness):
    install, state = harness
    install(run_result=(0, "", ""))

    cli.main(_argv("id"))

    assert state["launch_kwargs"]["extra_args"] is None


@pytest.mark.parametrize("flag", ["--harness", "--no-wait-ssh"])
def test_ssh_less_modes_are_a_usage_error_that_names_the_alternative(
    harness, flag, capsys
):
    """`run` executes a guest command over SSH, so a mode that guarantees no SSH
    cannot run one. Rejected as a usage error (exit 2) rather than booting a VM
    that then reports a confusing SSH failure — and the message says what to
    do instead; the bare "unrecognized arguments" pointed nowhere."""
    install, state = harness
    install()

    with pytest.raises(SystemExit) as exc:
        cli.main(_argv(flag, "id"))

    assert exc.value.code == 2
    assert state["launched"] is False
    err = capsys.readouterr().err
    assert (
        f"{flag} is not accepted: run executes a guest command over SSH; "
        "for boot-and-die kernels use launch --harness + wait + crash"
    ) in err


def test_ssh_less_mode_refusal_is_an_envelope_under_json(harness, capsys):
    install, state = harness
    install()

    with pytest.raises(SystemExit) as exc:
        cli.main(_argv("--format", "json", "--harness", "id"))

    assert exc.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["error_type"] == "UsageError"
    assert "launch --harness + wait + crash" in payload["error"]


def test_double_dash_hands_dash_words_to_the_guest(harness):
    """`qmu run -- uname -a`: after `--` the command's dash-words are the
    command's, not qmu's."""
    install, state = harness
    ssh = install(run_result=(0, "", ""))

    rc = cli.main(_argv("--", "uname", "-a"))

    assert rc == 0
    assert ssh.runs == ["uname -a"]


def test_qmu_flags_after_the_command_are_qmus(harness):
    install, state = harness
    ssh = install(run_result=(0, "", ""))

    rc = cli.main(_argv("./exploit", "--keep"))

    assert rc == 0
    assert ssh.runs == ["./exploit"]
    assert state["kills"] == []


def test_unquoted_dash_words_are_a_usage_error_with_a_hint(harness, capsys):
    install, state = harness
    install()

    with pytest.raises(SystemExit) as exc:
        cli.main(_argv("uname", "-a"))

    assert exc.value.code == 2
    assert state["launched"] is False
    err = capsys.readouterr().err
    assert "unrecognized arguments: -a" in err
    assert "Hint: quote the guest command ('uname -a') or put -- before it" in err


def test_quoted_single_argument_is_passed_to_the_guest_shell_verbatim(harness):
    install, state = harness
    ssh = install(run_result=(0, "", ""))

    rc = cli.main(_argv("cat /proc/slabinfo | grep kmalloc-192"))

    assert rc == 0
    assert ssh.runs == ["cat /proc/slabinfo | grep kmalloc-192"]


def test_clean_run_closes_the_ssh_control_master_before_reaping(harness):
    """The mux master (`ControlPersist=60`) would otherwise outlive the VM it
    was opened to; `--keep` leaves it, since the VM stays up."""
    install, state = harness
    ssh = install(run_result=(0, "", ""))

    cli.main(_argv("id"))

    assert ssh.master_closes == 1
    assert state["kills"] == [True]


def test_command_is_required(harness):
    install, state = harness
    install()

    with pytest.raises(SystemExit) as exc:
        cli.main(_argv())

    assert exc.value.code == 2


# --- second-round review regressions ---------------------------------------

KASAN_BOOT_BANNER = (
    "[    0.000] Linux version 6.9.0\n"
    "[    0.101] kasan: KernelAddressSanitizer initialized\n"
    "[    0.102] Memory: 4096K/8192K available\n"
    "[    1.500] systemd 252 running in system mode\n"
)


def test_kasan_boot_banner_is_not_a_kernel_warning(harness, capsys):
    """The former bare, case-insensitive `KASAN:` matcher classified the normal
    initialization banner as a warning. The shared classifier must leave this
    informational boot output unclassified; genuine `BUG: KASAN:` reports are
    checked separately."""
    install, state = harness
    install(serial_text=KASAN_BOOT_BANNER, ready=False, alive=True)

    rc = cli.main(_argv("--format", "json", "--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is False
    assert payload["crash"] is None


def test_genuine_report_after_a_kasan_banner_is_still_reported(harness, capsys):
    """The narrowing must not swallow a real splat that follows the banner."""
    install, state = harness
    install(
        serial_text=KASAN_BOOT_BANNER + (
            "[    2.000] BUG: KASAN: slab-use-after-free in evil+0x10/0x20\n"
            "[    2.001] ---[ end trace 0000000000000000 ]---\n"
        ),
        ready=False,
        alive=True,
    )

    rc = cli.main(_argv("--format", "json", "--ssh-timeout", "0", "./exploit"))

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert payload["crash_detected"] is True
    assert "slab-use-after-free" in payload["crash"]


def test_healthy_command_timeout_is_124_not_a_crash(harness, capsys):
    """`qmu run --timeout 1 -- 'sleep 10'` against a healthy guest. Reproduced
    live as exit 3 before the fix — a phantom panic for a slow command."""
    install, state = harness
    install(run_raises=SSHError(
        "SSH command timed out after 1s: sleep 10",
        stdout="partial\n",
        stderr="progress\n",
    ))

    rc = cli.main(_argv("--format", "json", "--timeout", "1", "sleep 10"))

    assert rc == 124
    payload = json.loads(capsys.readouterr().out)
    assert payload["timed_out"] is True
    assert payload["crash_detected"] is False
    # What the command printed before the deadline is still reported.
    assert payload["exit_code"] is None
    assert payload["stdout"] == "partial\n"
    assert payload["stderr"] == "progress\n"
    # Nothing crashed, but the run did not succeed either: the VM is preserved
    # so the caller can look at what the command was stuck on.
    assert state["kills"] == [False]


def test_no_net_is_accepted_and_forwarded(harness):
    """--no-net is NOT an SSH-less mode: it suppresses qmu's own NIC so a
    manually supplied one can take over, which is the documented arm32/MMIO
    topology (--no-net + --qemu-arg=-netdev ...hostfwd + a matching --ssh-port).
    Rejecting it would make that valid configuration unreachable from `run`."""
    install, state = harness
    install(run_result=(0, "", ""))

    rc = cli.main(_argv(
        "--no-net", "--ssh-port", "10099",
        "--qemu-arg=-netdev", "--qemu-arg=user,id=n0,hostfwd=tcp::10099-:22",
        "id",
    ))

    assert rc == 0
    kwargs = state["launch_kwargs"]
    assert kwargs["no_net"] is True
    assert kwargs["ssh_port"] == 10099
    assert kwargs["extra_args"] == ["-netdev", "user,id=n0,hostfwd=tcp::10099-:22"]


def test_no_replace_refuses_to_launch_over_a_live_namesake(monkeypatch, harness, capsys):
    """--no-replace promised not to replace; it must not silently ORPHAN either.

    Launching over a live namesake reuses its vm_id and overwrites its instance
    JSON, QMP socket and serial log, leaving the original QEMU running untracked
    and still holding the rootfs."""
    install, state = harness
    install(run_result=(0, "", ""))
    # Undo the fixture's no-op stub so the real guard runs.
    monkeypatch.setattr(
        lifecycle, "_replace_existing_named_vm", _REAL_REPLACE_EXISTING
    )
    monkeypatch.setattr(lifecycle, "load_instance", lambda name: state["inst"])
    monkeypatch.setattr(lifecycle, "instance_alive", lambda instance: True)

    rc = cli.main(_argv("--name", "run-vm", "--no-replace", "id"))

    assert rc == 1
    assert state["launched"] is False          # nothing was booted over it
    err = capsys.readouterr().err
    assert "already running" in err
    assert "qmu kill --vm run-vm" in err
