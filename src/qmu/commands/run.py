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
import re
import time
from typing import Any

# `extract_crash` deliberately also matches SURVIVED reports (a WARNING, a KASAN
# splat), because those are worth showing. They are not evidence that the boot
# failed, so the boot-failure classifier needs the stricter, terminal marker.
# (The qmu-agent-ergonomics branch grows a shared `serial.has_terminal_panic()`;
# consolidate onto it when that lands rather than keeping two spellings.)
_TERMINAL_PANIC = re.compile(r"Kernel panic - not syncing", re.IGNORECASE)

# This is the ONLY code path that scans a whole boot from byte 0, which exposes a
# sharp edge in the shared patterns: `CRASH_START_PATTERNS` carries a bare,
# case-insensitive `KASAN:` that also matches the ordinary boot banner
# "kasan: KernelAddressSanitizer initialized". With no end marker after it, the
# extract runs to the end of the log, so every KASAN kernel would report a
# multi-thousand-token "warning" that is really just its boot. Require a genuine
# report header before believing the extract. Narrowing the shared pattern would
# change `qmu crash` for every caller, so the check lives at this call site.
_REAL_REPORT_HEADER = re.compile(
    r"(BUG:|WARNING: CPU:|Oops:|general protection fault|UBSAN:|"
    r"Kernel panic|slab-use-after-free|slab-out-of-bounds|stack-out-of-bounds|"
    r"use-after-free in|double-free or invalid-free)"
)

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
    extracted = extract_crash(inst.serial_log, start_offset=0)
    report = (
        extracted
        if extracted and _REAL_REPORT_HEADER.search(extracted)
        else None
    )
    crash = report if report and _TERMINAL_PANIC.search(report) else None
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
