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
    124  the guest never became reachable within ``--ssh-timeout``

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

from ..instance import VMInstance, instance_alive
from ..serial import extract_crash
from ..ssh import SSHClient
from ..vm import launch_vm
from .._cliutil import (
    _add_common_opts,
    _add_launch_opts,
    _emit,
    _kill_vm,
    _make_ssh,
    _resolve_config_from_args,
)
from .guest import _join_exec_command, _run_guest_command
from .lifecycle import _replace_existing_named_vm


def _add_run(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "run",
        help="Boot a VM, run one command in the guest, then reap the VM",
        description=(
            "Boot a throwaway VM, run COMMAND in the guest, and stop the VM. "
            "The exit code is the guest command's (0/1), or 3 on a kernel "
            "crash, or 124 if the guest never became reachable. State is "
            "preserved (not reaped) whenever there is something left to inspect."
        ),
    )
    _add_launch_opts(p, run_mode=True)
    p.add_argument("command", nargs="+", help="Command to run in the guest")
    p.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Guest command timeout in seconds (default: 60)",
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

    A fresh crash report in the serial log is the discriminator: a kernel that
    panicked on boot is a crash (3) and the agent wants the report, while a guest
    that merely never started sshd is an operational failure (124/1) and must not
    be dressed up as a panic. ``start_offset=0`` is the whole log because the VM
    was launched by this command — every byte belongs to this boot.
    """
    crash = extract_crash(inst.serial_log, start_offset=0)
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
    if outcome == "died":
        return (
            1,
            {
                "ok": False,
                "ssh_error": True,
                "crash_detected": False,
                "crash": None,
                "hint": "QEMU exited before the guest was reachable, with no "
                        f"crash report. Check: qmu log --vm {inst.vm_id} --tail 200",
            },
            [
                f"VM '{inst.vm_id}' exited before the guest became reachable.",
                "No crash report in the serial log — the kernel may have failed "
                "to boot, or the command line may be wrong.",
            ],
        )
    return (
        124,
        {
            "ok": False,
            "ssh_error": True,
            "crash_detected": False,
            "crash": None,
            "hint": f"Guest did not answer SSH within {timeout:g}s and no crash "
                    "was reported. Raise --ssh-timeout, or check that the rootfs "
                    f"starts sshd: qmu log --vm {inst.vm_id} --tail 200",
        },
        [
            f"VM '{inst.vm_id}' did not become reachable within {timeout:g}s.",
            "No crash report in the serial log; the guest may still be booting "
            "or may not start sshd.",
        ],
    )


def _handle_run(args: argparse.Namespace) -> int:
    config = _resolve_config_from_args(args)
    _replace_existing_named_vm(args.name, args.no_replace)

    inst = launch_vm(
        config=config,
        kernel=args.kernel,
        profile=args.profile,
        cmdline=args.cmdline,
        gdb=args.gdb,
        name=args.name,
        ssh_port=args.ssh_port,
        gdb_port=args.gdb_port,
        extra_args=args.extra or None,
        ssh_timeout=args.ssh_timeout,
        initrd=args.initrd,
        drives=args.drives,
        no_net=args.no_net,
        nic_model=args.nic_model,
        net_backend=args.net_backend,
        harness=False,
    )

    # Everything after a successful launch runs under this guard: an exception
    # between here and the reap would otherwise leave an untracked QEMU process
    # holding the rootfs, which is the failure `launch --no-replace` was fixed
    # for. State is preserved rather than cleaned, because an unexpected error is
    # exactly when the serial log is worth keeping.
    try:
        ssh = _make_ssh(inst)
        outcome = _wait_for_guest(ssh, inst, float(args.ssh_timeout))
        if outcome != "ready":
            status, data, text = _boot_failure_payload(
                inst, outcome, float(args.ssh_timeout)
            )
            command = _join_exec_command(args.command)
        else:
            command = _join_exec_command(args.command)
            status, data, text = _run_guest_command(
                ssh, command, inst, timeout=args.timeout
            )
    except BaseException:
        _kill_vm(inst, clean=False)
        raise

    # Preserve whenever something is still worth reading. An ordinary non-zero
    # guest command (1) is NOT that: the guest already reported it in stdout/
    # stderr, and keeping a VM per failed run would leak instances across a
    # normal edit-run loop.
    preserve = (
        outcome != "ready"
        or status not in (0, 1)
        or data.get("crash_detected") is True
    )
    if args.keep:
        vm_state = "running"
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

    lines = [text] if isinstance(text, str) else list(text)
    if data["state_preserved"]:
        # Only annotate when there is a follow-up to make: on the clean path the
        # text output stays byte-identical to what `qmu exec` would have printed,
        # so an agent can pipe `qmu run` the same way.
        lines.append(f"\nVM '{inst.vm_id}' {vm_state}. Serial log: {inst.serial_log}")
        lines.append(
            f"Inspect: qmu log --vm {inst.vm_id} --tail 200 | "
            f"qmu crash --vm {inst.vm_id}"
        )
        if not args.keep:
            lines.append(f"Clean up:  qmu prune --vm {inst.vm_id}")

    _emit(args, data=data, text=lines, stem="run")
    return status
