"""``qmu run`` — boot a VM, run one guest command, reap it, report once.

The three-command sequence ``launch`` → ``exec`` → ``kill`` is the most common
thing an agent does with qmu, and spending three turns (and three envelopes) on
it is pure overhead when the VM is disposable. ``run`` collapses it into one
call whose exit code is the *guest command's* outcome, mapped onto the existing
contract with no new codes:

    0    guest command exited 0
    1    guest command exited non-zero, or the VM died before SSH came up
    3    kernel crash / SSH transport loss (same discrimination as ``exec``)
    4    QMP/SSH infrastructure failure (raised, mapped by ``cli.main``)
    124  the guest never became reachable within ``--ssh-timeout``, or the
         command outlived ``--timeout`` on a guest that still answers

**Dependency direction.** This module is a leaf: ``cli`` imports it, and nothing
imports it. It is the one place that imports sibling command modules, and it does
so deliberately — the alternative is a second copy of the crash-vs-transport-loss
discrimination (``guest._run_guest_command``) and of the named-VM replacement
(``lifecycle._replace_existing_named_vm``), and divergent copies of exactly those
decisions are the defect class the state-agreement matrix exists to catch. The
DAG stays one-way: ``cli -> run -> {guest, lifecycle} -> _cliutil -> domain``.

**Reaping is conditional on purpose.** A VM is fully removed only when there is
nothing left to look at. If the run produced a crash, timed out waiting for the
guest, or died mid-boot, the QEMU process is stopped but the instance metadata
and ``.serial.log`` are preserved, and the envelope names the follow-up command.
Reaping the evidence of the crash the agent just triggered would make ``run``
strictly worse than the three-command sequence it replaces.
"""

from __future__ import annotations

import argparse
import time
from typing import Any

# `extract_crash` deliberately also matches SURVIVED reports (a WARNING, a KASAN
# splat), because those are worth showing. They are not evidence that the boot
# failed, so the boot-failure classifier needs the stricter, terminal marker —
# `serial.has_terminal_panic`, using the same serial-text discriminator as
# `lifecycle._guest_state` and `wait --pattern`.

from ..instance import VMInstance, instance_alive
from ..serial import extract_crash, has_terminal_panic
from ..ssh import SSHClient
from ..vm import launch_vm
from .._cliutil import (
    _add_common_opts,
    _add_launch_opts,
    _kill_vm,
    _make_ssh,
)
from .guest import (
    GUEST_COMMAND_HELP,
    _emit_guest_result,
    _join_exec_command,
    _run_guest_command,
)
from .lifecycle import _prepare_boot


class _NoHarnessAction(argparse.Action):
    """Reject `--harness` / `--no-wait-ssh` with the reason, not "unrecognized".

    `run` executes a guest command over SSH, so a mode that guarantees no SSH
    cannot run one. Leaving the flags unregistered made the attempt a generic
    top-level usage error that pointed nowhere; this is still exit 2 (a usage
    error, rendered by the same `_UsageError` path), but it names the
    sequence that does what the caller wanted.
    """

    def __init__(self, option_strings, dest, **kwargs):
        kwargs["nargs"] = 0
        kwargs["help"] = argparse.SUPPRESS
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.error(
            f"{option_string} is not accepted: run executes a guest command "
            "over SSH; for boot-and-die kernels use launch --harness + wait + crash"
        )


def _add_run(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "run",
        help="Boot a VM, run one command in the guest, then reap the VM",
        description=(
            "Boot a throwaway VM, run COMMAND in the guest, and stop the VM. "
            "The exit code is the guest command's (0/1), or 3 on a kernel "
            "crash, or 124 if the guest never became reachable (or COMMAND "
            "outlived --timeout). State is preserved (not reaped) whenever "
            "there is something left to inspect. qmu flags may appear before "
            "or after COMMAND; quote the guest command, or put -- before it, "
            "when it has its own dash-words (`qmu run --name x -- uname -a`). "
            "Text-mode stdout is the guest's stdout only, exactly as "
            "`qmu exec` prints it. Boot-and-die kernels have no SSH: use "
            "launch --harness + wait + crash instead."
        ),
    )
    _add_launch_opts(p, run_mode=True)
    p.add_argument("--harness", action=_NoHarnessAction)
    p.add_argument("--no-wait-ssh", action=_NoHarnessAction)
    p.add_argument("command", nargs="+", help=GUEST_COMMAND_HELP)
    p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Guest command timeout in seconds (default: 60); on expiry the "
             "output produced so far is still reported (exit 124)",
    )
    p.add_argument(
        "--keep",
        action="store_true",
        help="Leave the VM running afterwards instead of stopping it",
    )
    _add_common_opts(p)
    p.set_defaults(handler=_handle_run)


def _wait_for_guest(ssh: SSHClient, inst: VMInstance, timeout: float) -> str:
    """Block until the guest answers SSH. Returns 'ready' / 'died' / 'timeout'.

    This is ``SSHClient.wait_ready`` plus a liveness check, because the two
    failures need different exit codes and a VM that died on boot must not burn
    the whole ``--ssh-timeout`` before saying so: a kernel that panics three
    seconds in would otherwise cost a full minute of wall clock per attempt.
    """
    deadline = time.monotonic() + timeout
    while True:
        if ssh.is_ready(timeout=2):
            return "ready"
        if not instance_alive(inst):
            # One last probe: the guest can answer and the VM exit between the
            # two checks, and reporting 'died' for a VM that did come up would
            # send the agent chasing a boot failure that did not happen.
            return "ready" if ssh.is_ready(timeout=2) else "died"
        # Deadline is checked AFTER a probe, so the guest is always given at
        # least one chance to answer (`--ssh-timeout 0` means "probe once").
        if time.monotonic() >= deadline:
            return "timeout"
        time.sleep(1.0)


def _boot_failure_payload(
    inst: VMInstance,
    outcome: str,
    timeout: float,
) -> tuple[int, dict[str, Any], list[str]]:
    """Classify a VM that never reached a usable guest.

    A **terminal panic** in the serial log is the discriminator, not merely the
    presence of a report: a kernel that panicked on boot is a crash (3) and the
    agent wants the report, while a guest that merely never started sshd is an
    operational failure (124/1) and must not be dressed up as a panic. A
    survived WARNING or KASAN splat sits between the two — it is reported in the
    envelope and preserved on disk, but it does not by itself promote a boot
    timeout to a crash, because the guest that emitted it is still alive.

    ``start_offset=0`` is the whole log because the VM was launched by this
    command — every byte belongs to this boot.
    """
    report = extract_crash(inst.serial_log, start_offset=0)
    crash = (
        report
        if report and has_terminal_panic(inst.serial_log, start_offset=0)
        else None
    )
    if crash is not None:
        return (
            3,
            {
                "ok": False,
                "ssh_error": True,
                "crash_detected": True,
                "crash": crash,
                "hint": "Kernel crashed before the guest was reachable. "
                        f"Full log: qmu log --vm {inst.vm_id} --tail 200",
            },
            [
                f"VM '{inst.vm_id}' crashed before the guest became reachable.",
                f"\nCrash from serial log:\n{crash}",
            ],
        )
    # A non-terminal report (survived WARNING / KASAN splat) is still shown and
    # still preserved on disk — it is usually the reason the boot went wrong —
    # but it does not change the exit code, because the guest that printed it
    # did not die of it.
    warned = report is not None
    warning_line = (
        f"\nNon-fatal kernel report from serial log:\n{report}"
        if warned
        else "No crash report in the serial log"
    )
    if outcome == "died":
        return (
            1,
            {
                "ok": False,
                "ssh_error": True,
                "crash_detected": False,
                "crash": None,
                "kernel_warning_detected": warned,
                "kernel_warning": report,
                "hint": "QEMU exited before the guest was reachable. Check: "
                        f"qmu log --vm {inst.vm_id} --tail 200",
            },
            [
                f"VM '{inst.vm_id}' exited before the guest became reachable.",
                f"{warning_line} — the kernel may have failed to boot, or the "
                "command line may be wrong.",
            ],
        )
    return (
        124,
        {
            "ok": False,
            "ssh_error": True,
            "crash_detected": False,
            "crash": None,
            "kernel_warning_detected": warned,
            "kernel_warning": report,
            "hint": f"Guest did not answer SSH within {timeout:g}s and did not "
                    "panic. Raise --ssh-timeout, or check that the rootfs "
                    f"starts sshd: qmu log --vm {inst.vm_id} --tail 200",
        },
        [
            f"VM '{inst.vm_id}' did not become reachable within {timeout:g}s.",
            f"{warning_line}; the guest may still be booting or may not start sshd.",
        ],
    )


def _handle_run(args: argparse.Namespace) -> int:
    # Same preparation `launch` runs: config layering, the [boot] kernel
    # fallback, the profile-vs-cmdline warnings, namesake replacement and
    # --inject. `run` registers the same flags, so it must apply them the same
    # way or a flag would parse here and be silently ignored.
    config, name = _prepare_boot(args)

    inst = launch_vm(
        config=config,
        kernel=config.kernel,
        profile=config.profile,
        cmdline=config.cmdline,
        append=args.append,
        gdb=args.gdb,
        name=name,
        ssh_port=args.ssh_port,
        gdb_port=args.gdb_port,
        extra_args=args.extra or None,
        ssh_timeout=args.ssh_timeout,
        initrd=config.initrd,
        drives=args.drives,
        no_net=args.no_net,
        nic_model=args.nic_model,
        net_backend=args.net_backend,
        harness=False,
        no_reboot=args.no_reboot,
    )

    # Everything after a successful launch runs under this guard: an exception
    # between here and the reap would otherwise leave an untracked QEMU process
    # holding the rootfs, which is the failure `launch --no-replace` was fixed
    # for. State is preserved rather than cleaned, because an unexpected error is
    # exactly when the serial log is worth keeping.
    try:
        ssh = _make_ssh(inst)
        outcome = _wait_for_guest(ssh, inst, float(args.ssh_timeout))
        command = _join_exec_command(args.command)
        if outcome != "ready":
            status, data, text = _boot_failure_payload(
                inst, outcome, float(args.ssh_timeout)
            )
            notes: list[str] = []
        else:
            status, data, text, notes = _run_guest_command(
                ssh, command, inst, timeout=args.timeout
            )
            # The ssh ControlMaster (`ControlPersist=60`) outlives the command;
            # the VM is about to be stopped under it, so close it now rather
            # than leaving a master that times out on its own.
            if not args.keep:
                ssh.close_control_master()
    except BaseException:
        _kill_vm(inst, clean=False)
        raise

    # Preserve whenever something is still worth reading. An ordinary non-zero
    # guest command (1) is NOT that: the guest already reported it in stdout/
    # stderr, and keeping a VM per failed run would leak instances across a
    # normal edit-run loop.
    # A survived kernel report counts: under the default exploit-dev profile an
    # Oops kills only the faulting task, so a command can trigger a KASAN splat
    # and still exit 0. Reaping there would delete the splat the run just
    # produced, which is the whole reason the caller ran it.
    preserve = (
        outcome != "ready"
        or status not in (0, 1)
        or data.get("crash_detected") is True
        or data.get("kernel_warning_detected") is True
    )
    if args.keep:
        # --keep means "do not kill it", which is not the same as "it is up":
        # a VM that died on boot is kept in the sense that qmu did not stop it.
        vm_state = "running" if instance_alive(inst) else "exited on its own"
    else:
        _kill_vm(inst, clean=not preserve)
        vm_state = "stopped (state preserved)" if preserve else "reaped"

    data = {
        **data,
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "arch": config.arch,
        "kernel": inst.kernel,
        "profile": inst.profile,
        "serial_log": inst.serial_log,
        "command": command,
        "vm_state": vm_state,
        "vm_kept": bool(args.keep),
        "state_preserved": bool(args.keep or preserve),
    }

    if data["state_preserved"]:
        # Follow-up hints are stderr notes, like the `[exit code: N]` trailer:
        # text-mode stdout is the guest's stdout (plus the crash report on a
        # lost transport) exactly as `qmu exec` prints it, so an agent can pipe
        # `qmu run` the same way on every path.
        notes = [
            *notes,
            f"VM '{inst.vm_id}' {vm_state}. Serial log: {inst.serial_log}",
            f"Inspect: qmu log --vm {inst.vm_id} --tail 200, or "
            f"qmu crash --vm {inst.vm_id}",
        ]
        if not args.keep:
            notes.append(f"Clean up: qmu prune --vm {inst.vm_id}")

    _emit_guest_result(args, data=data, text=text, notes=notes, stem="run")
    return status
