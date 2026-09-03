"""VM lifecycle commands: launch, kill, prune, wait, list, status, doctor.

These manage the QEMU process and its instance metadata. Shared helpers come
from :mod:`.._cliutil`.

The patchable collaborators (``choose_instance``, ``_qmp_ctx``,
``instance_alive``, ``extract_crash``, ``serial_log_offset``, and
``save_guest_epoch_serial_offset``) are imported directly into this module's
namespace. The test suite drives the production seams via
``monkeypatch.setattr(lifecycle, ...)`` (e.g. ``lifecycle.choose_instance`` /
``lifecycle._qmp_ctx`` / ``lifecycle.instance_alive``); the patches take effect
because the handlers read these names from this module at call time.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any

from dataclasses import replace

from ..config import resolve_config
from ..debug import debug_session_present, reset_dropped_breakpoints_warning
from ..instance import (
    QMUError,
    VM_ABSENT,
    VM_HELD_BACK,
    VM_ORPHANED,
    VM_RUNNING,
    VM_STOPPED,
    choose_instance,
    classify_vm,
    find_orphan_qemus,
    held_back_vm_ids,
    instance_alive,
    is_pid_alive,
    list_instances,
    list_prunable_instance_ids,
    list_stopped_instances,
    load_instance,
    remove_instance,
    save_guest_epoch_serial_offset,
)
from .. import rootfs as rootfs_mod
from ..cache import (
    MIN_BUILD_RESIDUE_AGE,
    classify_residue,
    source_tree_names,
    human_bytes,
    remove_items,
    unmanaged_subtree_names,
)
from ..runtime import prune_runtime_artifacts
from ..paths import (
    all_skill_source_dirs,
    instances_dir,
    qmp_socket_path,
    claude_skills_dir,
    codex_home,
    codex_skills_dir,
)
from ..qemu import native_passt_problem, probe_qemu_netdevs
from ..qmp import QMPError
from ..serial import (
    SerialTail,
    extract_crash,
    has_terminal_panic,
    extract_unknown_params,
    last_boot_offset,
    serial_log_offset,
)
from ..vm import launch_vm, suspect_dotted_params
from .._cliutil import (
    _add_common_opts,
    _add_launch_opts,
    _emit,
    _kill_vm,
    _make_ssh,
    _output,
    _qmp_ctx,
    _resolve_config_from_args,
)


# ---------------------------------------------------------------------------
# launch
# ---------------------------------------------------------------------------


def _add_launch(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("launch", help="Start a QEMU VM")
    _add_launch_opts(p)
    _add_common_opts(p)
    p.set_defaults(handler=_handle_launch)


def _replace_existing_named_vm(name: str | None, no_replace: bool) -> None:
    """Clear the way for a named launch: kill a live namesake, reap a stale one.

    Shared with ``qmu run`` (``commands.run``) so both boot paths treat a
    same-named VM identically; a second copy would let one of them orphan a QEMU
    process still holding the rootfs. The collaborators are read from this
    module's namespace, so ``monkeypatch.setattr(lifecycle, "load_instance", ...)``
    keeps working for both callers.
    """
    if not name:
        return
    if no_replace:
        # --no-replace promised not to replace; it must not silently ORPHAN
        # either. Launching over a live namesake reuses its vm_id and overwrites
        # its instance JSON, QMP socket and serial log, leaving the original
        # QEMU running untracked and still holding the rootfs. Refusing is the
        # only reading of the flag that is not a lie.
        existing = load_instance(name)
        if existing is not None and instance_alive(existing):
            raise QMUError(
                f"VM '{name}' is already running (pid={existing.pid}) and "
                "--no-replace was given, so it was left alone and nothing was "
                f"launched. Use a different --name, drop --no-replace to "
                f"replace it, or stop it first: qmu kill --vm {name}"
            )
        return
    existing = load_instance(name)
    if existing is not None and instance_alive(existing):
        sys.stderr.write(f"[qmu] Replacing existing VM '{name}' (pid={existing.pid})\n")
        _kill_vm(existing)
    elif existing is not None:
        # Stale metadata from dead process — just clean up
        remove_instance(existing.vm_id)

def _warn_if_cmdline_drops_root(args: argparse.Namespace, config: Any) -> None:
    """Flag the classic `--cmdline` footgun before the guest drops to initramfs.

    `--cmdline` REPLACES the profile, and every built-in profile carries
    ``root=``. Hand-written command lines routinely omit it, and the only
    symptom is an unexplained emergency shell several boots later.
    """
    # --harness is launch-only; `run` shares this warning but has no such flag.
    if config.cmdline is None or getattr(args, "harness", False) or args.drives:
        return
    if config.rootfs is None or "root=" in config.cmdline:
        return
    sys.stderr.write(
        "[qmu] Warning: --cmdline replaces the profile command line and this one "
        "has no 'root=', but a rootfs is attached. The guest will likely stall in "
        "initramfs. Add 'root=/dev/sda' (check `qmu config show` for the profile "
        "cmdline), or use --append to extend the profile instead of replacing it.\n"
    )


# Boot params whose loss silently invalidates work rather than just changing
# behavior, so they are called out by name when an override drops them.
_CONSEQUENTIAL_DROPS = {
    "nokaslr": "every kernel address changes; hardcoded offsets will be wrong",
    "init": "the guest runs its default init, not your harness script",
    "root": "the guest may stall in initramfs",
    "rw": "the guest root mounts read-only; writes from your exploit or harness "
          "fail with EROFS",
    "ro": "the guest root mounts writable, so the image is no longer protected",
    "kasan.fault": "KASAN will no longer panic on first fault",
    "panic_on_warn": "a WARNING will no longer stop the run",
    "oops": "an Oops will no longer panic, so a corrupted kernel reads as a clean run",
    "slub_debug": "SLUB debug behavior changes and heap layout moves",
}


def _warn_profile_override_drops(config: Any, append: str | None) -> None:
    """Name the params a CLI --profile is about to discard.

    Saying only "an override happened" trades one silent failure for another:
    the previous bug was `--profile` not applying, and the fix makes it apply
    while the config's own cmdline vanishes. In this domain the usual casualty
    is `nokaslr`, so a final-validation run silently gets KASLR back and every
    hardcoded address moves with nothing pointing at the command line.
    """
    replacement = config.profiles.get(config.profile, "")
    kept = {token.split("=", 1)[0] for token in replacement.split()}
    kept.update(token.split("=", 1)[0] for token in (append or "").split())

    dropped = [
        token for token in config.cmdline.split()
        if token.split("=", 1)[0] not in kept
    ]

    sys.stderr.write(
        f"[qmu] --profile {config.profile} overrides the [boot] cmdline in "
        f"qmu.toml for this launch.\n"
    )
    if not dropped:
        return
    sys.stderr.write(f"[qmu]   dropped: {' '.join(dropped)}\n")
    for token in dropped:
        name = token.split("=", 1)[0]
        consequence = _CONSEQUENTIAL_DROPS.get(name)
        if consequence:
            sys.stderr.write(f"[qmu]   note: '{token}' is gone — {consequence}\n")
    sys.stderr.write("[qmu]   re-add any you still need with --append.\n")


def _warn_suspect_dotted_params(config: Any, append: str | None) -> None:
    """Flag a dotted param that near-misses a name qmu knows.

    A dotted param is invisible to the kernel's own "Unknown kernel command
    line parameters" report, so `kasan.faul=panic` would otherwise be ignored
    at boot AND undetectable afterwards — the one typo class nothing catches.
    """
    full = " ".join(
        part for part in (
            config.cmdline or config.profiles.get(config.profile, ""),
            append or "",
        ) if part
    )
    for typo, suggestion in suspect_dotted_params(full):
        sys.stderr.write(
            f"[qmu] Warning: boot parameter '{typo}' looks like a typo of "
            f"'{suggestion}'. Dotted params are NOT reported by the kernel's "
            f"unknown-parameter line, so this would be silently ignored.\n"
        )


def _profile_label(inst: Any) -> str:
    """Describe the profile honestly, including when it did not apply.

    Printing a bare `Profile: exploit-test` next to a command line that came
    from a full override states something false about the boot — the same class
    of silent misreport as a dead boot parameter.
    """
    name = inst.profile or "(none)"
    if getattr(inst, "cmdline_override", False):
        return f"{name} (NOT applied — cmdline was overridden)"
    return name


def _profile_params(inst: Any) -> set[str]:
    """Return the params qmu's own profile contributed to this boot."""
    # A full cmdline override means the profile contributed nothing, so
    # crediting it would misattribute the caller's own params to qmu.
    if getattr(inst, "cmdline_override", False):
        return set()
    try:
        config = resolve_config()
        profile_cmdline = config.profiles.get(inst.profile or "", "")
    except QMUError:
        return set()
    return {token for token in profile_cmdline.split()}


def _warn_unknown_kernel_params(inst: Any) -> dict[str, list[str]]:
    """Report boot params the kernel did not claim, ranked by who supplied them.

    Params that came from qmu's own profile are reported separately and more
    quietly. They are not actionable by the reader — `apparmor=0` is unclaimed
    precisely because AppArmor is not compiled in, which is the state the param
    was asking for — and mixing them in with a genuine typo renders both
    identically. A warning that is always present is a warning nobody reads,
    which is how a dead `panic_on_oops=1` survived in the first place.
    """
    unknown = extract_unknown_params(
        inst.serial_log,
        start_offset=inst.guest_epoch_serial_offset or 0,
        arch=getattr(inst, "arch", None),
    )
    if not unknown:
        return {"all": [], "operator": [], "profile": []}

    from_profile = _profile_params(inst)
    operator = [p for p in unknown if p not in from_profile]
    inherited = [p for p in unknown if p in from_profile]

    if operator:
        sys.stderr.write(
            "[qmu] Warning: the kernel did not claim these boot parameters, so "
            f"they had no kernel-side effect: {' '.join(operator)}\n"
            "[qmu]   Check spelling, and whether each is a boot parameter at all "
            "(many are sysctl-only — e.g. the boot form of panic_on_oops is "
            "'oops=panic').\n"
        )
    if inherited:
        sys.stderr.write(
            f"[qmu] Note: unclaimed by this kernel, from profile "
            f"'{inst.profile}': {' '.join(inherited)}\n"
        )
    # Machine-readable output keeps the same split the text output makes. A
    # script gating on "did I pass a bogus param" must not trip forever on a
    # profile param it cannot fix — that is the alarm fatigue this split exists
    # to end, and merging the halves here would just move it into the JSON.
    return {"all": unknown, "operator": operator, "profile": inherited}


def _inject_into_rootfs(
    config: Any, specs: list[str], partition: int = 1, mkdir: bool = False
) -> None:
    """Copy host files into the rootfs image before the VM boots."""
    if config.rootfs is None:
        raise QMUError(
            "--inject needs a rootfs image. Set [drive] rootfs in qmu.toml or pass --rootfs."
        )
    # The busy-image guard lives in rootfs.require_image_free so it covers the
    # standalone `qmu rootfs *` commands too, not just this path.
    mappings = [rootfs_mod.parse_mapping(spec) for spec in specs]
    rootfs_mod.inject(config.rootfs, mappings, partition=partition, mkdir=mkdir)
    for local, guest in mappings:
        sys.stderr.write(f"[qmu] Injected {local} -> {guest}\n")


def _prepare_boot(args: argparse.Namespace) -> tuple[Any, str | None]:
    """Resolve config and clear the way for a boot; returns (config, name).

    Shared by ``launch`` and ``run`` (``commands.run``). Both register the same
    boot-describing flags through ``_add_launch_opts``, so both must ALSO apply
    them the same way — a flag that parses on `run` but is only honored by
    `launch` is the subcommand-divergence the shared registrar exists to close,
    and it would present as a boot that silently ignores `--append` or
    `--inject`.

    ``--harness`` is launch-only (`run` needs SSH to run its command), so it is
    read defensively rather than assumed present.
    """
    config = _resolve_config_from_args(args)

    # Harness mode bundles --no-wait-ssh + --no-net
    if getattr(args, "harness", False):
        args.no_wait_ssh = True
        args.no_net = True

    if config.kernel is None:
        raise QMUError(
            "No kernel configured. Pass --kernel or set [boot] kernel in qmu.toml "
            "(run `qmu config init` for a starter file)."
        )

    # An explicit CLI --profile must beat a project `[boot] cmdline`. Layering
    # otherwise inverts: config.cmdline is a full override, so a qmu.toml
    # cmdline would silently discard the profile the caller just named on the
    # command line — `--profile exploit-test` becoming a no-op is exactly the
    # dead-parameter class this tool is supposed to catch. `--cmdline` on the
    # CLI still wins, because that is the caller overriding themselves.
    profile_from_cli = args.profile is not None and args.cmdline is None
    if profile_from_cli and config.cmdline is not None:
        _warn_profile_override_drops(config, args.append)
        config.cmdline = None

    # `--vm` is the instance selector on every other subcommand, so accept it
    # here as an alias for --name rather than silently ignoring it.
    name = args.name or getattr(args, "vm", None)

    _warn_if_cmdline_drops_root(args, config)
    _warn_suspect_dotted_params(config, args.append)

    # Replace existing VM with the same name (default behavior)
    _replace_existing_named_vm(name, args.no_replace)

    # Inject only AFTER the previous VM is gone. libguestfs cannot open an
    # image a live QEMU still holds, and it reports that as an opaque
    # "appliance closed the connection unexpectedly" — so injecting first
    # would break iteration 2 of the boot-and-check loop and blame the wrong
    # component.
    if args.injects:
        _inject_into_rootfs(
            config, args.injects, partition=args.partition, mkdir=args.mkdir
        )

    return config, name


def _handle_launch(args: argparse.Namespace) -> int:
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
        harness=args.harness,
    )

    if inst.harness or inst.ssh_port is None:
        ssh_status = "n/a (harness)"
    elif not args.no_wait_ssh:
        ssh = _make_ssh(inst)
        sys.stderr.write(f"[qmu] VM launched (pid={inst.pid}). Waiting for SSH on port {inst.ssh_port}...\n")
        if ssh.wait_ready(timeout=args.ssh_timeout):
            ssh_status = "ready"
        else:
            ssh_status = "timeout (VM may still be booting)"
    else:
        ssh_status = "skipped"

    # Only meaningful once the guest has booted far enough to have printed the
    # line; a --no-wait-ssh launch returns too early, so `wait` and `status`
    # re-check it later.
    unknown_params = (
        _warn_unknown_kernel_params(inst) if ssh_status == "ready"
        else {"all": [], "operator": [], "profile": []}
    )

    result = {
        "ok": True,
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "ssh_port": inst.ssh_port,
        "ssh_status": ssh_status,
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "profile": inst.profile,
        "serial_log": inst.serial_log,
        "arch": config.arch,
        "unknown_kernel_params": unknown_params["all"],
        "unknown_kernel_params_by_source": {
            "operator": unknown_params["operator"],
            "profile": unknown_params["profile"],
        },
    }

    lines = [
        f"VM '{inst.vm_id}' launched (pid={inst.pid})",
        f"  Arch:    {config.arch}",
    ]
    if inst.harness:
        lines.append(f"  Mode:    harness (no SSH)")
    elif inst.ssh_port is not None:
        lines.append(f"  SSH:     port {inst.ssh_port} ({ssh_status})")
    else:
        lines.append(f"  SSH:     {ssh_status}")
    if inst.gdb_port:
        lines.append(f"  GDB:     port {inst.gdb_port}")
    lines.append(f"  Kernel:  {inst.kernel}")
    lines.append(f"  Profile: {_profile_label(inst)}")
    lines.append(f"  Serial:  {inst.serial_log}")
    _emit(args, data=result, text=lines, stem="launch")
    return 0


def _orphan_serial_logs() -> dict[str, int]:
    """Map serial-log path -> pid, via this module's patchable seam."""
    mapping: dict[str, int] = {}
    for orphan in find_orphan_qemus():
        serial = orphan.get("serial_log")
        if serial:
            mapping[serial] = orphan["pid"]
    return mapping


# The guest-usability axis, independent of the existence axis above. A VM can
# be orphaned AND panicked, or running AND paused: those are two facts about
# two different things, so a single flat enum cannot express them. `list` used
# to report only the existence axis and silently flatten the rest, presenting a
# panicked VM identically to a healthy one.
GUEST_SERVING = "serving"
GUEST_PAUSED = "paused"
GUEST_CRASHED = "crashed"
GUEST_PANICKED = "panicked"
GUEST_UNKNOWN = "unknown"


def _qmp_running(inst: Any) -> bool | None:
    """True/False from QMP `query-status`, or None when it cannot be asked."""
    socket_path = inst.qmp_socket
    if not socket_path:
        # A synthesized orphan carries no recorded socket, but the file sits at
        # the conventional path — so `serving`/`paused` are computable for
        # orphans too rather than collapsing to `unknown`.
        candidate = qmp_socket_path(inst.vm_id)
        if not candidate.exists():
            return None
        inst = replace(inst, qmp_socket=str(candidate))
    try:
        with _qmp_ctx(inst) as qmp:
            status = qmp.execute("query-status")
    except (QMPError, OSError):
        return None
    if not isinstance(status, dict):
        return None
    running = status.get("running")
    return running if isinstance(running, bool) else None


def _guest_state(inst: Any) -> str:
    """Classify what the guest is DOING — is it usable — not whether a crash exists.

    The predicate is guest usability, so a retrievable crash report is not by
    itself `panicked`: under the default `exploit-dev` profile an Oops kills the
    faulting task and the guest keeps serving. Labelling that `panicked`
    attaches "reap it" guidance to a working VM — the exact inverse of the
    failure this axis was added to prevent.

    - `panicked`  — a terminal `Kernel panic - not syncing`; the guest is gone.
    - `crashed`   — a crash report is retrievable AND the guest still serves.
                    Neither `serving` (a report is waiting) nor `panicked`
                    (do NOT reap it).
    - `paused`    — vCPU halted, e.g. by `qmu gdb`.
    """
    if inst is None:
        return GUEST_UNKNOWN

    # Scope BOTH crash reads to the current boot. The recorded guest epoch only
    # advances on an observed QMP RESET, so a guest-initiated reboot between two
    # commands leaves it pointing at a guest that no longer exists — and a panic
    # from the previous boot would then label a demonstrably healthy VM as gone
    # and instruct the operator to reap it.
    start = inst.guest_epoch_serial_offset or 0
    start = max(start, last_boot_offset(inst.serial_log, start_offset=start))

    if has_terminal_panic(inst.serial_log, start_offset=start):
        return GUEST_PANICKED

    running = _qmp_running(inst)
    if running is False:
        return GUEST_PAUSED

    if extract_crash(inst.serial_log, start_offset=start):
        return GUEST_CRASHED

    return GUEST_SERVING if running is True else GUEST_UNKNOWN


def _classify(vm_id: str, older_than: float = 86400.0) -> dict[str, Any]:
    """Classify a vm_id on BOTH axes, through the shared authority.

    `state` answers "does a record and/or a process exist"; `guest` answers
    "is the guest usable". They are orthogonal — the cross product is real
    (orphaned+panicked is an everyday state after a triggered crash) — so they
    are two fields, never one enum.
    """
    info = classify_vm(
        vm_id, older_than_seconds=older_than, orphan_pids=_orphan_serial_logs()
    )
    if info["state"] in (VM_RUNNING, VM_ORPHANED):
        info["guest"] = _guest_state(info["instance"])
    else:
        info["guest"] = GUEST_UNKNOWN
    return info


# ---------------------------------------------------------------------------
# kill
# ---------------------------------------------------------------------------


def _add_kill(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("kill", help="Stop a running VM")
    p.add_argument("--force", action="store_true", help="Force kill (SIGKILL)")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata or serial log after kill")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_kill)


def _kill_orphan_if_named(args: argparse.Namespace) -> int | None:
    """Reap an orphaned remnant that `kill` would otherwise call nonexistent.

    `qmu list` shows these as [ORPHANED — process alive] with a live pid, and
    `kill` is the obvious command to reach for next. Reporting "not found" for
    a VM the tool just displayed is the same false statement corrected in
    `prune`, and it left the user with no route to the process at all.
    """
    vm = getattr(args, "vm", None)
    if not vm:
        return None

    orphan_pids = _orphan_serial_logs()
    if not orphan_pids:
        return None

    for inst in list_stopped_instances():
        if inst.vm_id != vm:
            continue
        pid = orphan_pids.get(inst.serial_log)
        if pid is None:
            return None

        # Identified by qmu's own instances dir in the process argv, so this is
        # always a qmu-launched QEMU — never an unrelated process.
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            raise QMUError(
                f"VM '{vm}' is an orphaned remnant (pid {pid}) and could not "
                f"be signalled: {exc}"
            ) from exc
        time.sleep(0.5)
        if is_pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        msg = (
            f"VM '{vm}' was an orphaned remnant (no metadata); killed its "
            f"QEMU process (pid {pid}). State preserved at {inst.serial_log}"
        )
        _emit(
            args,
            data={
                "ok": True,
                "vm_id": vm,
                "orphaned": True,
                "pid": pid,
                "cleaned": False,
                "serial_log": inst.serial_log,
            },
            text=msg,
            stem="kill",
        )
        return 0
    return None


def _handle_kill(args: argparse.Namespace) -> int:
    orphan_result = _kill_orphan_if_named(args)
    if orphan_result is not None:
        return orphan_result
    if args.vm:
        info = _classify(args.vm)
        if info["state"] in (VM_STOPPED, VM_HELD_BACK):
            raise QMUError(
                f"VM '{args.vm}' is already stopped; there is no process to "
                f"kill. Its logs remain — read them with `qmu log --vm "
                f"{args.vm}`, or remove them with `qmu prune --vm {args.vm} "
                f"--older-than 0`."
            )
    inst = choose_instance(args.vm)
    # #40: `qmu gdb` spawns a pry bridge that qmu does not track, so killing the
    # VM leaves that bridge pointing at a dead GDB stub — and the operator only
    # discovers it as a "Multiple bridge instances" error on the next `pry`
    # command. Probe for an attached client BEFORE the kill drops its
    # connection, and if one is present, say so on stderr so cleanup is not a
    # later surprise. qmu still does not manage the pry lifecycle.
    had_bridge = debug_session_present(inst) if inst.gdb_port is not None else False
    _kill_vm(inst, force=args.force, clean=not args.no_clean)
    if args.no_clean:
        msg = f"VM '{inst.vm_id}' stopped. State preserved at {inst.serial_log}"
    else:
        msg = f"VM '{inst.vm_id}' stopped."
    _emit(
        args,
        data={
            "ok": True,
            "vm_id": inst.vm_id,
            "cleaned": not args.no_clean,
            "serial_log": inst.serial_log,
        },
        text=msg,
        stem="kill",
    )
    if had_bridge:
        sys.stderr.write(
            f"[qmu] Note: VM '{inst.vm_id}' had an attached debugger on GDB port "
            f"{inst.gdb_port}. That pry bridge now points at a dead stub; qmu does "
            "not manage it. If a later `pry` command reports \"Multiple bridge "
            "instances\", this is the stale one — clean it up (`pry doctor`, then "
            "kill it).\n"
        )
    return 0


# ---------------------------------------------------------------------------
# prune
# ---------------------------------------------------------------------------


def _nonnegative_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number of seconds") from exc
    if seconds < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return seconds


def _add_prune(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "prune",
        help="Remove stopped-instance state or aged qmu runtime artifacts",
    )
    g = p.add_mutually_exclusive_group()
    # SUPPRESS (like _add_common_opts) so a top-level `--vm X` given before the
    # subcommand is not clobbered by this subparser's own default.
    g.add_argument("--vm", default=argparse.SUPPRESS, help="Prune a specific stopped VM")
    g.add_argument("--all", dest="prune_all", action="store_true",
                   help="Prune every stopped VM")
    g.add_argument(
        "--runtime",
        dest="prune_runtime",
        action="store_true",
        help="Prune aged qmu-owned runtime artifacts (spills and SSH controls)",
    )
    g.add_argument(
        "--orphans",
        dest="prune_orphans",
        action="store_true",
        help="Kill qmu-launched QEMU processes that no live instance record "
             "claims (untracked holders of a rootfs image)",
    )
    g.add_argument(
        "--build-residue",
        dest="prune_build_residue",
        action="store_true",
        help="Reclaim in-tree kernel build intermediates under "
             "kernels/src/linux-*/ (*.o, *.a, .*.cmd, ...). Never touches "
             "vmlinux, System.map, .config, Makefile or arch/*/boot/ — those "
             "are frequently the only copy. See `qmu cache du`.",
    )
    p.add_argument(
        "--tree", action="append", default=None, metavar="NAME",
        help="With --build-residue: restrict to this kernel source tree "
             "(e.g. linux-7.0.12). Repeatable. A narrowing filter only, so it "
             "can never remove more than the unfiltered run would.",
    )
    p.add_argument(
        "--older-than",
        type=_nonnegative_seconds,
        default=86400.0,
        help="Age threshold in seconds (default: 86400). Gates --runtime and "
             "--build-residue wholesale. With --vm/--all it gates ONLY "
             "metadata-free remnants (a leftover .qemu.log or .qmp.sock with "
             "no instance record): a VM that still has its record, and a "
             "serial-log-only remnant, prune at any age — which is why "
             "`--older-than 0` looks like a no-op on a stopped VM and is still "
             "the right flag once the record is gone.",
    )
    p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Preview only: list what would be removed or killed, and do "
             "nothing. Supported with " + _previewable_modes_phrase() + ".",
    )
    p.add_argument(
        "--keep-logs",
        action="store_true",
        help="preserve .serial.log and .qemu.log",
    )
    # _add_common_opts adds --vm too; we declared --vm above so add the rest
    # manually — with SUPPRESS defaults, matching _add_format_opts. A plain
    # default here silently overwrote a top-level `qmu --format json prune ...`
    # with "text", breaking the documented before-or-after-subcommand contract
    # for this one command.
    p.add_argument(
        "--format", choices=["text", "json", "ndjson"], default=argparse.SUPPRESS,
    )
    p.add_argument(
        "--out", default=argparse.SUPPRESS,
        help="Write output to file instead of stdout",
    )
    p.set_defaults(handler=_handle_prune)




# Single source of truth for prune's mode list. Five separate strings used to
# enumerate these by hand — argparse help for --dry-run, the --runtime refusal,
# the "Specify a mode" error, the --older-than help, and SKILL.md — and adding a
# mode meant remembering all of them. A mode that is previewable but missing
# from the refusal message actively withholds it from an agent that just hit
# that refusal.
_PRUNE_MODES: tuple[tuple[str, bool], ...] = (
    ("--vm <name>", True),
    ("--all", True),
    ("--runtime", False),
    ("--orphans", True),
    ("--build-residue", True),
)


def _join_modes(names: list[str]) -> str:
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + ", and " + names[-1]


def _previewable_modes_phrase() -> str:
    previewable = [name for name, ok in _PRUNE_MODES if ok]
    blocked = [name for name, ok in _PRUNE_MODES if not ok]
    phrase = _join_modes(previewable)
    if blocked:
        phrase += f" (not {_join_modes(blocked)}, which has no preview pass)"
    return phrase


def _all_modes_phrase() -> str:
    return _join_modes([name for name, _ok in _PRUNE_MODES])


def _unmanaged_cache() -> dict[str, Any]:
    """Disclose the cache subtrees prune cannot reclaim.

    Emitted on EVERY prune branch in JSON, from one helper, so a branch cannot
    be missed. Gating it on --all only would repeat the exact regression shape
    already recorded in this file ("Round 5 fixed only the ... branch"). Uses
    is_dir() probes only — a real inventory walks 600k files and costs ~2s,
    which does not belong on prune's path. The number lives in `qmu cache du`.
    """
    names = unmanaged_subtree_names()
    return {
        "subtrees": names,
        "hint": "qmu cache du",
        "reclaim_hint": "qmu prune --build-residue --dry-run",
    }


def _unmanaged_cache_note(payload: dict[str, Any]) -> str | None:
    names = payload.get("subtrees") or []
    if not names:
        return None
    listed = ", ".join(f"{n}/" for n in names)
    return (
        f"Not covered by this prune: {listed}. "
        f"Size them with `qmu cache du`; reclaim kernel build residue with "
        f"`qmu prune --build-residue --dry-run`."
    )


# Per-file detail cap. On a real cache the eligible set is ~56k files, which
# renders a 12.7 MB / ~3.2M-token JSON envelope -- 317x the spill limit -- so
# `--dry-run --format json` spilled to an artifact pointer and was unusable
# inline. The buckets already carry the totals and the per-tree groups, which is
# what a caller actually branches on; the path list is detail. Capped and
# disclosed, never silently truncated.
_MAX_ITEM_DETAIL = 100


def _capped(items: list[Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    shown = [i.as_dict() for i in items[:_MAX_ITEM_DETAIL]]
    withheld = items[_MAX_ITEM_DETAIL:]
    return shown, {
        "files": len(withheld),
        "bytes": sum(i.bytes for i in withheld),
        "hint": (
            f"per-file detail capped at {_MAX_ITEM_DETAIL}; totals above are "
            f"complete. Use `qmu cache ls --bucket eligible --top 0` for the "
            f"full per-tree breakdown."
        ) if withheld else "",
    }


def _handle_prune_build_residue(args: argparse.Namespace) -> int:
    """Reclaim in-tree kernel build intermediates.

    The age gate is the only thing standing between this and a live build:
    kbuild.sh bind-mounts the source tree read-write for the whole build, so
    residue from a build still running must not be reclaimed. It is a
    default-safe heuristic, not an invariant -- which is why values below
    MIN_BUILD_RESIDUE_AGE are refused outright rather than clamped, and why this
    mode never prescribes `--older-than 0` the way instance pruning does.
    """
    if args.keep_logs:
        raise QMUError("--keep-logs applies only to instance pruning.")

    older_than = float(args.older_than)
    if older_than < MIN_BUILD_RESIDUE_AGE:
        raise QMUError(
            f"--older-than {older_than:g} is below the "
            f"{MIN_BUILD_RESIDUE_AGE:g}s floor for --build-residue. kbuild "
            f"bind-mounts the kernel source tree read-write for the whole "
            f"build, so reclaiming residue from a build that may still be "
            f"running corrupts it. Use `--older-than "
            f"{MIN_BUILD_RESIDUE_AGE:g}` or higher, or inspect first with "
            f"`qmu cache du --older-than {older_than:g}`."
        )

    trees = getattr(args, "tree", None)
    if trees:
        available = source_tree_names()
        unknown = [t for t in trees if t not in available]
        if unknown:
            listed = ", ".join(available) if available else "(none)"
            raise QMUError(
                f"No kernel source tree named {', '.join(unknown)}. "
                f"Present: {listed}."
            )
    report = classify_residue(older_than_seconds=older_than, trees=trees)
    dry_run = getattr(args, "dry_run", False)
    unmanaged = _unmanaged_cache()

    # Classification -- not deletion -- decides membership, so preview and the
    # real run agree by construction on a fixed cache.
    payload: dict[str, Any] = report.as_dict()
    payload["removed"] = []
    payload["would_remove"] = []

    if dry_run:
        shown, withheld = _capped(report.bucket_items("eligible"))
        payload["would_remove"] = shown
        payload["would_remove_truncated"] = withheld
        data = {
            "ok": True,
            "dry_run": True,
            "build_residue": payload,
            "unmanaged_cache": unmanaged,
        }
        _emit(args, data=data, text=_residue_lines(report, dry_run=True, older_than=older_than),
              stem="prune-build-residue")
        return 0

    removed, failed = remove_items(report.bucket_items("eligible"))
    shown, withheld = _capped(removed)
    payload["removed"] = shown
    payload["removed_truncated"] = withheld
    payload["files_removed"] = len(removed)
    payload["bytes_removed"] = sum(i.bytes for i in removed)
    # A unlink that failed after classification is an outcome, not a prediction.
    # Folding it into `removed` would recreate preview != real at the reporting
    # layer, so it lands in `refused` with what actually happened.
    if failed:
        refused = dict(payload["refused"])
        refused["groups"] = sorted(
            set(refused["groups"]) | {item.group for item, _why in failed}
        )
        refused["bytes"] += sum(item.bytes for item, _why in failed)
        refused["files"] += len(failed)
        reasons = list(refused["reasons"])
        for _item, why in failed:
            if why not in reasons:
                reasons.append(why)
        refused["reasons"] = reasons
        payload["refused"] = refused
    data = {
        "ok": True,
        "dry_run": False,
        "build_residue": payload,
        "unmanaged_cache": unmanaged,
    }
    _emit(
        args,
        data=data,
        text=_residue_lines(
            report, dry_run=False, older_than=older_than,
            removed_bytes=sum(i.bytes for i in removed),
            removed_files=len(removed), failed=len(failed),
        ),
        stem="prune-build-residue",
    )
    # A refused group is a reported outcome, not a failure: exiting non-zero
    # would make scripted use fail on any cache holding one root-owned tree.
    return 0


def _residue_lines(
    report: Any,
    *,
    dry_run: bool,
    older_than: float,
    removed_bytes: int = 0,
    removed_files: int = 0,
    failed: int = 0,
) -> list[str]:
    eligible = report.eligible
    lines: list[str] = []
    if dry_run:
        if not eligible.files:
            lines.append("No build residue is eligible. Nothing would be removed.")
        else:
            lines.append(
                f"Would remove {human_bytes(eligible.bytes)} of build residue "
                f"({eligible.files:,} files) from "
                f"{len(eligible.groups)} source tree(s): "
                f"{', '.join(eligible.groups)}"
            )
            lines.append("Re-run without --dry-run to do it.")
    else:
        if not removed_files:
            lines.append("No build residue was eligible; nothing removed.")
        else:
            lines.append(
                f"Reclaimed {human_bytes(removed_bytes)} of build residue "
                f"({removed_files:,} files) from "
                f"{len(eligible.groups)} source tree(s): "
                f"{', '.join(eligible.groups)}"
            )
        if failed:
            lines.append(f"{failed} file(s) could not be removed; see `refused`.")

    # Held-back and refused are disclosed on BOTH branches, in both formats.
    if report.held_back.files:
        lines.append(
            f"Held back by the --older-than cutoff ({older_than:g}s): "
            f"{', '.join(report.held_back.groups)}. These trees were modified "
            f"recently and may be mid-build. Re-run later, or with a larger "
            f"--older-than once the build has finished."
        )
    if report.refused.files:
        lines.append(
            f"Refused {human_bytes(report.refused.bytes)} "
            f"({report.refused.files:,} files) in "
            f"{', '.join(report.refused.groups)}: "
            f"{report.refused.reasons[0] if report.refused.reasons else 'unavailable'}."
        )
        lines.append(
            "  These are left in place, not lost. If they are root-owned from "
            "an earlier build, `sudo chown -R $USER` the tree and re-run."
        )
    return lines


def _handle_prune_orphans(args: argparse.Namespace) -> int:
    orphans = find_orphan_qemus()

    if getattr(args, "dry_run", False):
        # This command SIGKILLs by argv pattern. On a shared box the only
        # responsible default is being able to see the list first, rather than
        # hand-reconstructing it from /proc to predict the outcome.
        data = {
            "ok": True,
            "dry_run": True,
            "unmanaged_cache": _unmanaged_cache(),
            "orphans_found": len(orphans),
            "would_kill": [
                {"pid": o["pid"], "serial_log": o.get("serial_log")}
                for o in orphans
            ],
            "killed": [],
        }
        if not orphans:
            text: Any = "No orphaned qmu QEMU processes. Nothing would be killed."
        else:
            text = [f"Would kill {len(orphans)} orphaned QEMU process(es):"]
            for o in orphans:
                text.append(f"  pid {o['pid']}  serial={o.get('serial_log') or '?'}")
            text.append("Re-run without --dry-run to kill them.")
        _emit(args, data=data, text=text, stem="prune-orphans")
        return 0

    killed: list[int] = []
    failed: list[dict[str, Any]] = []
    for orphan in orphans:
        try:
            os.kill(orphan["pid"], signal.SIGTERM)
            killed.append(orphan["pid"])
        except OSError as exc:
            failed.append({"pid": orphan["pid"], "error": str(exc)})

    if killed:
        # Give SIGTERM a moment, then escalate anything still alive.
        time.sleep(0.5)
        for pid in list(killed):
            if is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass

    data = {
        "ok": not failed,
        "unmanaged_cache": _unmanaged_cache(),
        "orphans_found": len(orphans),
        "killed": killed,
        "failed": failed,
    }
    if not orphans:
        text: Any = "No orphaned qmu QEMU processes."
    else:
        text = [f"Killed {len(killed)} orphaned QEMU process(es):"]
        text.extend(f"  pid {pid}" for pid in killed)
        text.extend(f"  pid {f['pid']}: FAILED — {f['error']}" for f in failed)
    _emit(args, data=data, text=text, stem="prune-orphans")
    return 1 if failed else 0


def _handle_prune(args: argparse.Namespace) -> int:
    if getattr(args, "prune_build_residue", False):
        return _handle_prune_build_residue(args)
    # A mode-scoped flag must be implemented for every mode the parser accepts
    # it on, or rejected explicitly -- never left to fall through silently.
    if getattr(args, "tree", None):
        raise QMUError("--tree applies only to --build-residue.")
    if getattr(args, "prune_orphans", False):
        if args.keep_logs:
            raise QMUError("--keep-logs applies only to instance pruning.")
        return _handle_prune_orphans(args)

    # SUPPRESS default (fix #2) means the attribute may be absent when --vm is
    # not given after the subcommand; the top-level parser default of None
    # guarantees it otherwise exists.
    vm = getattr(args, "vm", None)
    prune_runtime = getattr(args, "prune_runtime", False)
    prune_all = getattr(args, "prune_all", False)

    if prune_runtime:
        if args.keep_logs:
            raise QMUError("--keep-logs applies only to instance pruning.")
        if getattr(args, "dry_run", False):
            # prune_runtime_artifacts has no preview mode, and inventing one by
            # deleting first would defeat the flag entirely. Refuse rather than
            # act: a --dry-run that acts is worse than one that is unavailable.
            raise QMUError(
                "--dry-run is not supported with --runtime. Runtime artifacts "
                "are aged out in one pass with no preview; use `--older-than` "
                "to control what qualifies, or one of the previewable modes: "
                + _previewable_modes_phrase() + "."
            )
        result = prune_runtime_artifacts(older_than_seconds=args.older_than)

        def _art(item: Any) -> dict[str, str]:
            return {"kind": item.kind, "path": str(item.path)}

        data = {
            "ok": True,
            "unmanaged_cache": _unmanaged_cache(),
            "runtime": {
                "older_than_seconds": float(args.older_than),
                "removed": [_art(item) for item in result.removed],
                "skipped_live": [_art(item) for item in result.skipped_live],
                "skipped_indeterminate": [
                    _art(item) for item in result.skipped_indeterminate
                ],
            },
        }
        removed_n = len(result.removed)
        live_n = len(result.skipped_live)
        indet_n = len(result.skipped_indeterminate)
        if removed_n == 0:
            text = "No eligible qmu-owned runtime artifacts to prune."
        else:
            text = (
                f"Pruned {removed_n} qmu-owned runtime artifact(s); "
                f"skipped {live_n} live and {indet_n} indeterminate."
            )
        _emit(args, data=data, text=text, stem="prune")
        return 0

    running = list_instances()
    running_ids = {inst.vm_id for inst in running}
    prunable = list_prunable_instance_ids(older_than_seconds=args.older_than)

    if vm is not None:
        if vm in running_ids:
            raise QMUError(
                f"VM '{vm}' is running. Use 'qmu kill --vm {vm}' first."
            )
        if vm not in prunable:
            # Three different reasons a name can be unprunable, and naming the
            # wrong one is worse than saying nothing. A live orphan is NOT
            # age-gated — telling the caller to re-run with a smaller
            # --older-than prescribes the flag they just used, forever.
            info = _classify(vm, args.older_than)
            if info["state"] == VM_ORPHANED:
                raise QMUError(
                    f"VM '{vm}' is an orphaned remnant whose QEMU (pid "
                    f"{info['pid']}) is still running, so its serial log was "
                    f"not removed. Reap the process first with "
                    f"`qmu kill --vm {vm}` or `qmu prune --orphans`, then prune."
                )
            if info["state"] == VM_HELD_BACK:
                raise QMUError(
                    f"VM '{vm}' has leftover artifacts newer than the "
                    f"--older-than cutoff ({args.older_than:g}s), so it was not "
                    f"pruned. Re-run with `qmu prune --vm {vm} --older-than 0` "
                    f"to remove it now."
                )
            raise QMUError(f"No stopped VM named '{vm}'.")
        targets = [vm]
    elif prune_all:
        targets = prunable
    else:
        raise QMUError(
            "Specify a mode: " + _all_modes_phrase() + "."
        )

    # Disclosed unconditionally: on every branch, in both modes, and in JSON.
    # Round 5 fixed only the nothing-is-prunable branch of the real run, so a
    # mixed cache still reported "Pruned 1 VM(s) (removed)" with a remnant
    # holding megabytes of serial log left behind, and the preview — the thing
    # a cautious operator runs first — reintroduced the original false
    # statement outright.
    held_back = held_back_vm_ids(
        older_than_seconds=args.older_than, orphan_pids=_orphan_serial_logs()
    ) if prune_all else []
    held_note = (
        f"Held back by the --older-than cutoff ({args.older_than:g}s): "
        f"{', '.join(held_back)}. Re-run with `--older-than 0` to include them."
    ) if held_back else None

    unmanaged = _unmanaged_cache()
    # Text footer renders only where the branch implies "everything is now
    # clean" -- axis 3 is JSON superset-of text, not equality, so an agent still
    # gets the fact on every branch while a human running `prune --vm` in a loop
    # is not shown 58 identical footers.
    cache_note = _unmanaged_cache_note(unmanaged) if prune_all else None

    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        # --dry-run must never delete. It previously applied only to --orphans
        # and was silently ignored here, so `prune --all --dry-run` destroyed
        # the .serial.log files that `kill --no-clean` exists to preserve —
        # crash evidence lost under the one flag that promises not to act.
        data = {
            "ok": True,
            "dry_run": True,
            "unmanaged_cache": unmanaged,
            "pruned": [],
            "would_prune": targets,
            "held_back": held_back,
            "keep_logs": args.keep_logs,
        }
        if not targets:
            text: Any = ["Nothing to prune. Nothing would be removed."]
        else:
            verb = "keep logs for" if args.keep_logs else "remove"
            text = [f"Would {verb} {len(targets)} VM(s): {', '.join(targets)}"]
            text.append("Re-run without --dry-run to do it.")
        if held_note:
            text.append(held_note)
        if cache_note:
            text.append(cache_note)
        _emit(args, data=data, text=text, stem="prune")
        return 0

    pruned: list[str] = []
    for vm_id in targets:
        remove_instance(vm_id, keep_logs=args.keep_logs)
        pruned.append(vm_id)

    if not pruned:
        lines = ["No stopped VMs to prune."] if not held_back else [
            "No stopped VMs were old enough to prune."
        ]
    else:
        verb = "kept logs for" if args.keep_logs else "removed"
        lines = [f"Pruned {len(pruned)} VM(s) ({verb}): {', '.join(pruned)}"]
    if held_note:
        lines.append(held_note)
    if cache_note:
        lines.append(cache_note)
    _emit(
        args,
        data={
            "ok": True,
            "dry_run": False,
            "unmanaged_cache": unmanaged,
            "pruned": pruned,
            "held_back": held_back,
            "keep_logs": args.keep_logs,
        },
        text=lines,
        stem="prune",
    )
    return 0


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


_STOP_EVENTS = {"STOP", "SHUTDOWN", "POWERDOWN", "RESET"}


def _add_wait(sub: argparse._SubParsersAction) -> None:
    description = (
        "Block until the QEMU process exits, or until --pattern appears on the "
        "serial console"
    )
    p = sub.add_parser("wait", help=description, description=description)
    p.add_argument("--timeout", type=float, default=None,
                   help="Max seconds to wait (default: no timeout)")
    p.add_argument("--pattern", default=None,
                   help="Block until this regex matches a serial console line, instead of "
                        "waiting for the VM to exit. Exits 0 on match, 3 on kernel crash, "
                        "1 if the VM dies first, 124 on timeout.")
    p.add_argument("--ignore-crash", action="store_true",
                   help="With --pattern: keep waiting through a kernel crash instead of "
                        "aborting on it")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata after stop (harness VMs only)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_wait)


# How often the --pattern loop rescans the serial log. Short enough that an
# agent's next command starts promptly; long enough that a multi-minute wait
# is not thousands of syscalls.
_PATTERN_POLL_INTERVAL = 0.25


def _handle_wait(args: argparse.Namespace) -> int:
    _require_running(args.vm, "wait")
    if getattr(args, "pattern", None) is not None:
        return _wait_for_pattern(args)
    inst = choose_instance(args.vm)

    start = time.monotonic()
    deadline: float | None = (
        start + args.timeout if args.timeout is not None else None
    )
    reason = "unknown"
    qemu_status = "unknown"
    last_event: str | None = None
    event_data: Any = None
    stopped = False
    reset_persistence_in_progress = False
    warned_reset_debug = False

    try:
        with _qmp_ctx(inst) as qmp:
            try:
                status = qmp.execute("query-status")
                if isinstance(status, dict):
                    observed_status = status.get("status")
                    if isinstance(observed_status, str):
                        qemu_status = observed_status
            except (QMPError, OSError):
                pass

            while True:
                # The recorded process identity is the only terminal authority.
                # Checking before the deadline also preserves --timeout 0 as
                # “check once, then time out.”
                if not instance_alive(inst):
                    reason = "process_exited"
                    stopped = True
                    break

                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    tick = min(1.0, remaining)
                else:
                    tick = 1.0

                event = qmp.wait_event(_STOP_EVENTS, timeout=tick)
                if event is not None:
                    observed_event = event.get("event")
                    last_event = (
                        observed_event
                        if isinstance(observed_event, str)
                        else "unknown"
                    )
                    event_data = event.get("data")
                    if last_event == "RESET":
                        reset_persistence_in_progress = True
                        reset_offset = serial_log_offset(inst.serial_log)
                        inst = save_guest_epoch_serial_offset(inst, reset_offset)
                        reset_persistence_in_progress = False
                        # #46: an observed reset drops the gdbstub breakpoint set
                        # without telling the client. `wait` is the one place qmu
                        # sees a reset it did not itself issue, so warn here too
                        # (once per wait) when a debugger is attached.
                        if not warned_reset_debug and debug_session_present(inst):
                            warned_reset_debug = True
                            sys.stderr.write(
                                reset_dropped_breakpoints_warning(inst.vm_id) + "\n"
                            )
                    # Continue immediately so identity is checked after every
                    # observation; an event alone is never terminal.
                    continue
    except (QMPError, OSError) as exc:
        if reset_persistence_in_progress:
            raise
        if not instance_alive(inst):
            stopped = True
            reason = "process_exited"
        else:
            raise QMUError(f"QMP error during wait: {exc}") from exc

    elapsed = time.monotonic() - start
    _unknown_params = _warn_unknown_kernel_params(inst)
    crash = None
    if stopped:
        if inst.guest_epoch_serial_offset == 0:
            crash = extract_crash(inst.serial_log)
        else:
            crash = extract_crash(
                inst.serial_log,
                start_offset=inst.guest_epoch_serial_offset,
            )

    result = {
        "ok": stopped,
        "vm_id": inst.vm_id,
        "stopped": stopped,
        "reason": reason,
        "elapsed": round(elapsed, 3),
        "qemu_status": qemu_status,
        "last_event": last_event,
        "event_data": event_data,
        "crash": crash,
        "unknown_kernel_params": _unknown_params["all"],
        "unknown_kernel_params_by_source": {
            "operator": _unknown_params["operator"],
            "profile": _unknown_params["profile"],
        },
    }

    cleaned = False
    if stopped and inst.harness and not args.no_clean:
        # Identity death is already proven. Remove owned state directly; do not
        # pass a potentially recycled PID to _kill_vm's pid-only signaling.
        remove_instance(inst.vm_id)
        cleaned = True
    result["cleaned"] = cleaned

    lines = [
        f"VM '{inst.vm_id}' {'stopped' if stopped else 'still running'} "
        f"({reason}, elapsed={elapsed:.2f}s)"
    ]
    observation_suffix = "" if stopped else " (QEMU process still running)"
    if last_event is not None:
        lines.append(f"Observed QMP event {last_event}{observation_suffix}.")
    if qemu_status not in {"unknown", "running"}:
        lines.append(f"Observed QEMU status {qemu_status}{observation_suffix}.")
    if crash:
        lines.append("\nCrash from serial log:\n" + crash)
    if cleaned:
        lines.append("[qmu] Instance metadata cleaned up.")
    _emit(args, data=result, text=lines, stem="wait")

    return 0 if stopped else 124


# How long to let a detected crash finish printing before extracting it, and
# how long to keep waiting while the log is still growing.
_CRASH_SETTLE_INTERVAL = 0.2
_CRASH_SETTLE_MAX = 3.0


def _settled_crash(inst: Any, start_offset: int) -> str | None:
    """Re-extract a crash once the serial log stops growing.

    Bounded: a guest that keeps printing forever must not stall the wait.
    """
    deadline = time.monotonic() + _CRASH_SETTLE_MAX
    previous = serial_log_offset(inst.serial_log)
    while time.monotonic() < deadline:
        time.sleep(_CRASH_SETTLE_INTERVAL)
        current = serial_log_offset(inst.serial_log)
        if current == previous:
            break
        previous = current
    return extract_crash(inst.serial_log, start_offset=start_offset)


def _wait_for_pattern(args: argparse.Namespace) -> int:
    """Block until a regex matches a serial console line.

    This replaces the `until grep -q ... serial.log; do sleep 2; done` shell
    loop, and fixes its two failure modes: such a loop hangs forever when the
    guest panics before printing the expected marker, and it hangs forever
    when the VM dies. Both terminate here with a distinguishable exit code.
    """
    _require_running(args.vm, "wait")
    inst = choose_instance(args.vm)

    try:
        matcher = re.compile(args.pattern)
    except re.error as exc:
        raise QMUError(f"Invalid --pattern regex {args.pattern!r}: {exc}") from exc

    start = time.monotonic()
    deadline = start + args.timeout if args.timeout is not None else None
    # A RESET rebases the guest epoch; honor it so a pattern from the previous
    # boot cannot satisfy a wait against the current one.
    start_offset = inst.guest_epoch_serial_offset or 0
    tail = SerialTail(inst.serial_log, offset=start_offset)

    matched_line: str | None = None
    reason = "timeout"
    crash: str | None = None
    saw_dead = False

    while True:
        lines = tail.read_lines()
        if saw_dead:
            # The process is already gone, so nothing more will be appended.
            # Release the withheld fragment: the marker may be the final,
            # newline-less line QEMU wrote.
            lines.extend(tail.flush())
        for line in lines:
            if matcher.search(line):
                matched_line = line
                reason = "pattern_matched"
                break
        if matched_line is not None:
            break

        if saw_dead:
            reason = "process_exited"
            break

        if not args.ignore_crash and has_terminal_panic(
            inst.serial_log, start_offset=start_offset
        ):
            # Abort on a TERMINAL panic only. Aborting on any crash made the
            # wait unusable under the default `exploit-dev` profile, where a
            # survived Oops is the expected outcome of a trigger — so callers
            # pasted `--ignore-crash` onto every wait, and a reflexive
            # `--ignore-crash` is precisely how a real panic gets missed.
            # A survived crash leaves the guest running, so there is still a
            # marker to wait for; a terminal panic means there never will be.
            #
            # Detection also races the report still being written: an Oops is
            # visible several hundred ms before the panic epilogue that follows
            # it, so extracting immediately returns whichever half had landed.
            # Let the log settle first, or `crash` is a flake.
            crash = _settled_crash(inst, start_offset) or extract_crash(
                inst.serial_log, start_offset=start_offset
            )
            reason = "crash"
            break

        if not instance_alive(inst):
            # Do not conclude yet. The guest may have written the marker and
            # exited between the scan above and this liveness check, so take
            # one more pass over whatever landed before deciding.
            saw_dead = True
            continue

        if deadline is not None and time.monotonic() >= deadline:
            reason = "timeout"
            break

        time.sleep(_PATTERN_POLL_INTERVAL)

    if reason == "process_exited" and crash is None:
        crash = extract_crash(inst.serial_log, start_offset=start_offset)

    elapsed = time.monotonic() - start
    matched = matched_line is not None
    _unknown_params = _warn_unknown_kernel_params(inst)
    result = {
        "ok": matched,
        "vm_id": inst.vm_id,
        "matched": matched,
        "pattern": args.pattern,
        "matched_line": matched_line,
        "reason": reason,
        "elapsed": round(elapsed, 3),
        "crash": crash,
        "unknown_kernel_params": _unknown_params["all"],
        "unknown_kernel_params_by_source": {
            "operator": _unknown_params["operator"],
            "profile": _unknown_params["profile"],
        },
    }

    if matched:
        lines_out = [f"Matched /{args.pattern}/ after {elapsed:.2f}s:", matched_line or ""]
    elif reason == "crash":
        lines_out = [
            f"Kernel crash on '{inst.vm_id}' after {elapsed:.2f}s, "
            f"before /{args.pattern}/ matched.",
        ]
    elif reason == "process_exited":
        lines_out = [
            f"VM '{inst.vm_id}' exited after {elapsed:.2f}s without matching "
            f"/{args.pattern}/.",
        ]
    else:
        lines_out = [
            f"Timed out after {elapsed:.2f}s waiting for /{args.pattern}/ "
            f"on '{inst.vm_id}'.",
        ]
    if crash:
        lines_out.append("\nCrash from serial log:\n" + crash)
    _emit(args, data=result, text=lines_out, stem="wait")

    if matched:
        return 0
    if crash:
        return 3
    if reason == "process_exited":
        return 1
    return 124


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _add_list(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="List VMs (running and stopped)")
    _add_common_opts(p)
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.set_defaults(handler=_handle_list)


def _handle_list(args: argparse.Namespace) -> int:
    # The project-config gate lives at the cli.main dispatch choke point, so
    # this handler is already running under a validated project config.
    running = list_instances()
    stopped = list_stopped_instances()
    if not running and not stopped:
        _emit(args, data={"ok": True, "vms": []}, text="No VMs.", stem="list")
        return 0

    if args.format != "text":
        # Hoisted: _orphan_serial_logs() walks all of /proc, so calling it per
        # stopped VM made `list --format json` scan the process table N times.
        # The text branch below already does this once; both branches must also
        # read the SAME snapshot, or they can disagree about who is orphaned.
        orphan_logs = _orphan_serial_logs()
        data = []
        for inst in running:
            entry: dict[str, Any] = {
                "vm_id": inst.vm_id,
                "status": "running",
                "guest": _guest_state(inst),
                "pid": inst.pid,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel,
                "profile": inst.profile,
            }
            if inst.harness or inst.ssh_port is None:
                entry["ssh_ready"] = None
            else:
                entry["ssh_ready"] = _make_ssh(inst).is_ready()
            data.append(entry)
        for inst in stopped:
            orphan_pid = orphan_logs.get(inst.serial_log)
            data.append({
                "vm_id": inst.vm_id,
                "status": "orphaned" if orphan_pid else "stopped",
                "guest": _guest_state(inst) if orphan_pid else GUEST_UNKNOWN,
                "pid": orphan_pid or inst.pid or None,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel or None,
                "profile": inst.profile or None,
                "ssh_ready": None,
                "serial_log": inst.serial_log,
            })
        _output({"ok": True, "vms": data}, args, stem="list")
        return 0

    orphan_logs = _orphan_serial_logs()

    lines = []
    for inst in running:
        if inst.harness or inst.ssh_port is None:
            ssh_str = "harness"
        else:
            ssh_ok = _make_ssh(inst).is_ready()
            ssh_str = f"ssh={inst.ssh_port}({'ok' if ssh_ok else 'down'})"
        gdb_str = f" gdb={inst.gdb_port}" if inst.gdb_port else ""
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else ""
        # Report the guest axis alongside the existence axis. Presenting a
        # panicked or paused VM as a plain [running] is the same flattening
        # that made `list` and `status` contradict each other.
        guest = _guest_state(inst)
        state_str = {
            GUEST_PANICKED: "[running — GUEST PANICKED, run `qmu crash`]",
            GUEST_CRASHED: "[running — crash report waiting, run `qmu crash`]",
            GUEST_PAUSED: "[running — vCPU paused, `qmu cont` resumes]",
        }.get(guest, "[running]")
        lines.append(
            f"  {inst.vm_id}  pid={inst.pid}  {ssh_str}{gdb_str}  "
            f"profile={inst.profile}  {kernel_str}  {state_str}"
        )
    for inst in stopped:
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else "kernel=?"
        profile_str = f"profile={inst.profile}" if inst.profile else "profile=?"
        if inst.serial_log in orphan_logs:
            suffix = {
                GUEST_PANICKED: ", GUEST PANICKED, run `qmu crash`",
                GUEST_CRASHED: ", crash report waiting, run `qmu crash`",
            }.get(_guest_state(inst), "")
            state = f"[ORPHANED — process alive{suffix}]"
        else:
            state = "[stopped]"
        lines.append(f"  {inst.vm_id}  {profile_str}  {kernel_str}  {state}")
    _output("VMs:\n" + "\n".join(lines), args, stem="list")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _add_status(sub: argparse._SubParsersAction) -> None:
    # "show" is the common wrong guess for this verb; alias it rather than
    # making the caller spend a round trip discovering the right name.
    p = sub.add_parser("status", aliases=["show"], help="Detailed VM status")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_status)


def _require_running(vm_id: str | None, command: str) -> None:
    """Reject a non-running VM with a description, never with "not found"."""
    if not vm_id:
        return
    explanation = describe_non_running(vm_id, command=command)
    if explanation is not None:
        raise QMUError(explanation)


def _crash_warning(guest: str | None, vm_id: str) -> str:
    """The one sentence that tells the reader a report is waiting.

    Shared by `status` and `describe_non_running` so the tracked and orphaned
    paths cannot say different things about the same fact.
    """
    if guest == GUEST_PANICKED:
        return (
            " Its guest has PANICKED and the crash report is still "
            f"retrievable — run `qmu crash --vm {vm_id}` BEFORE reaping it."
        )
    if guest == GUEST_CRASHED:
        return (
            " Its guest reported a crash but is STILL RUNNING — pull the report "
            f"with `qmu crash --vm {vm_id}`; do not reap it."
        )
    return ""


def describe_non_running(
    vm_id: str, older_than: float = 86400.0, *, command: str | None = None
) -> str | None:
    """Explain a vm_id that `list` displays but a running-only lookup misses.

    `status` is the natural next command after spotting something odd in
    `list`, so answering "not found" — while helpfully listing what IS running,
    implying the entry is bogus — is the worst possible response. Shared with
    `prune` so the two cannot drift apart again.
    """
    info = _classify(vm_id, older_than)
    state = info["state"]
    if state == VM_ORPHANED:
        lead = (
            f"VM '{vm_id}' is an orphaned remnant: its metadata is gone but its "
            f"QEMU process (pid {info['pid']}) is still running."
        )
        if command in ("exec", "wait"):
            lead += f" `qmu {command}` needs a tracked VM, so it cannot act on it."
        lead += _crash_warning(info.get("guest"), vm_id)
        return (
            f"{lead} Reap it with `qmu kill --vm {vm_id}` or "
            f"`qmu prune --orphans`. Serial log: {info['serial_log']}"
        )
    if state in (VM_STOPPED, VM_HELD_BACK):
        verb = (
            f"`qmu {command}` needs a running VM"
            if command in ("exec", "wait")
            else "there is no live state to report"
        )
        return (
            f"VM '{vm_id}' is stopped; only its logs remain, so {verb}. "
            f"Read them with `qmu log --vm {vm_id}` or "
            f"`qmu crash --vm {vm_id}`, and remove them with "
            f"`qmu prune --vm {vm_id} --older-than 0`. "
            f"Serial log: {info['serial_log']}"
        )
    return None


def _handle_status(args: argparse.Namespace) -> int:
    # Validation of the project/explicit config happens once, at the cli.main
    # dispatch gate (#37), so every sibling verb gives one answer about whether
    # the project is valid. status reads no boot settings from qmu.toml.
    explanation = describe_non_running(args.vm) if args.vm else None
    if explanation is not None:
        raise QMUError(explanation)
    inst = choose_instance(args.vm)

    qmp_ok = False
    qemu_status = "unknown"
    try:
        with _qmp_ctx(inst) as qmp:
            status = qmp.execute("query-status")
            qmp_ok = True
            qemu_status = status.get("status", "unknown") if isinstance(status, dict) else str(status)
    except (QMPError, OSError):
        pass

    if inst.harness or inst.ssh_port is None:
        ssh_state = "n/a (harness)"
        ssh_ok = None
    else:
        ssh_ok = _make_ssh(inst).is_ready()
        ssh_state = "ready" if ssh_ok else "down"

    guest = _guest_state(inst)
    result = {
        "ok": True,
        "vm_id": inst.vm_id,
        # Both axes, matching `list`. status is the detailed per-VM command, so
        # it must not be the one that cannot answer what state the VM is in.
        "status": VM_RUNNING,
        "guest": guest,
        "pid": inst.pid,
        "harness": inst.harness,
        "qmp": "connected" if qmp_ok else "unreachable",
        "qemu_status": qemu_status,
        "ssh_port": inst.ssh_port,
        "ssh": ssh_state,
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "rootfs": inst.rootfs,
        "memory": inst.memory,
        "cpus": inst.cpus,
        "profile": inst.profile,
        "cmdline": inst.cmdline,
        "serial_log": inst.serial_log,
        "started_at": inst.started_at,
    }

    lines = [
        f"VM '{inst.vm_id}'",
        f"  PID:       {inst.pid}",
        f"  Guest:     {guest}",
        f"  QMP:       {'connected' if qmp_ok else 'unreachable'}",
        f"  QEMU:      {qemu_status}",
    ]
    if inst.harness or inst.ssh_port is None:
        lines.append(f"  Mode:      harness")
        lines.append(f"  SSH:       n/a")
    else:
        lines.append(f"  SSH:       port {inst.ssh_port} ({ssh_state})")
    if inst.gdb_port:
        lines.append(f"  GDB:       port {inst.gdb_port}")
    lines.extend([
        f"  Kernel:    {inst.kernel}",
        f"  Rootfs:    {inst.rootfs}",
        f"  Memory:    {inst.memory}",
        f"  CPUs:      {inst.cpus}",
        f"  Profile:   {_profile_label(inst)}",
        f"  Cmdline:   {inst.cmdline}",
        f"  Serial:    {inst.serial_log}",
        f"  Started:   {inst.started_at}",
    ])
    # The crash notice fired only on the orphaned path, which is the RARER of
    # the two — every successful trigger on a tracked VM lands here instead.
    notice = _crash_warning(guest, inst.vm_id)
    if notice:
        lines.append(notice.strip())
    _emit(args, data=result, text=lines, stem="status")
    return 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def _add_doctor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="Health check")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_doctor)


def _check_libguestfs() -> dict[str, Any]:
    """Report whether libguestfs can actually build its appliance."""
    check = "libguestfs (rootfs inject / launch --inject)"
    fish = shutil.which("guestfish")
    if fish is None:
        return {
            "check": check,
            "status": "info",
            "detail": "guestfish not found in PATH — required only for "
                      "`qmu rootfs *` and `qmu launch --inject`. "
                      "Install libguestfs-tools.",
        }

    # An explicit supermin kernel overrides the /boot lookup entirely.
    override = os.environ.get("SUPERMIN_KERNEL")
    if override:
        readable = os.access(override, os.R_OK)
        return {
            "check": check,
            "status": "ok" if readable else "MISSING",
            "detail": f"{fish}; SUPERMIN_KERNEL={override}"
                      + ("" if readable else " is NOT readable"),
        }

    kernels = sorted(Path("/boot").glob("vmlinuz-*")) if Path("/boot").is_dir() else []
    if not kernels:
        return {
            "check": check,
            "status": "warn",
            "detail": f"{fish}; no /boot/vmlinuz-* found for the supermin "
                      f"appliance. Set SUPERMIN_KERNEL to a readable kernel.",
        }
    if any(os.access(k, os.R_OK) for k in kernels):
        return {"check": check, "status": "ok", "detail": fish}

    return {
        "check": check,
        "status": "MISSING",
        "detail": f"{fish} is installed, but NO /boot/vmlinuz-* is readable "
                  f"(they are mode 0600), so the appliance cannot build and "
                  f"every inject will fail. Fix: sudo chmod 0644 /boot/vmlinuz-* "
                  f"— or leave system perms alone and export SUPERMIN_KERNEL / "
                  f"SUPERMIN_KERNEL_VERSION / SUPERMIN_MODULES pointing at a "
                  f"readable copy.",
    }


def _handle_doctor(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )
    checks: list[dict[str, Any]] = []

    # Config sources — distinguish "loaded a file" from "defaults only", and
    # both of those from "a file was found and REJECTED". resolve_config skips
    # an invalid global with a stderr warning; reporting "No qmu.toml or
    # ~/.config/qmu/config.toml found. Run: qmu config init" for it
    # contradicted that warning in the same breath and prescribed writing a
    # PROJECT file, which leaves the broken global in place forever. doctor is
    # exempt from the #37 dispatch gate because it diagnoses the project layer
    # itself — that justification only holds if it diagnoses the global layer
    # too, which is the layer that is deliberately non-fatal.
    file_sources = [s for s in config._sources if s.startswith(("global:", "project:", "config:"))]
    skipped_sources = config._skipped_sources
    if file_sources:
        checks.append({
            "check": "config",
            "status": "ok",
            "detail": " -> ".join(config._sources),
        })
    elif skipped_sources:
        checks.append({
            "check": "config",
            "status": "warn",
            "detail": "Running on built-in defaults only: every config file "
                      "found was rejected (see below).",
        })
    else:
        checks.append({
            "check": "config",
            "status": "warn",
            "detail": "No qmu.toml or ~/.config/qmu/config.toml found. Run: qmu config init",
        })
    for skipped in skipped_sources:
        checks.append({
            "check": f"{skipped['kind']} config",
            "status": "warn",
            "detail": (
                f"{skipped['path']} EXISTS but is invalid and was skipped: "
                f"{skipped['problem']}. Fix or delete that file — "
                f"`qmu config init` writes a project qmu.toml and will not "
                f"clear this."
            ),
        })

    # Cache subtrees no qmu command fully reclaims. Status is deliberately
    # "info", never "warn": _handle_doctor treats only ("ok", "info") as healthy
    # and returns 1 otherwise, so a warn here would exit 1 on every machine that
    # has ever built a kernel -- permanently red-lining the health signal
    # skills/qmu/SKILL.md teaches, with no way for the user to clear it (the
    # subtrees legitimately exist). Cheap is_dir() probes only; no walk.
    unmanaged_names = unmanaged_subtree_names()
    if unmanaged_names:
        checks.append({
            "check": "cache",
            "status": "info",
            "detail": (
                ", ".join(f"{n}/" for n in unmanaged_names)
                + " are not reclaimed by `qmu prune --vm/--all`. Size them with "
                  "`qmu cache du`; reclaim kernel build residue with "
                  "`qmu prune --build-residue --dry-run`."
            ),
        })

    # QEMU binary (arch-aware). For configured passt, derive the reported path
    # from the same result used for the native-backend capability check.
    binary = config.qemu_binary()
    passt_required = config.net_backend == "passt"
    qemu_caps = probe_qemu_netdevs(binary) if passt_required else None
    qemu = qemu_caps.path if qemu_caps is not None else shutil.which(binary)
    checks.append({
        "check": binary,
        "status": "ok" if qemu else "MISSING",
        "detail": qemu or "Not found in PATH",
    })

    if not passt_required:
        checks.append({
            "check": "QEMU native passt (-netdev passt)",
            "status": "info",
            "detail": "Not required for configured net_backend=user.",
        })
    else:
        assert qemu_caps is not None
        passt_problem = native_passt_problem(qemu_caps)
        checks.append({
            "check": "QEMU native passt (-netdev passt)",
            "status": "ok" if passt_problem is None else "MISSING",
            "detail": (
                f"{qemu_caps.path} advertises native '-netdev passt'"
                if passt_problem is None
                else passt_problem
            ),
        })

    # Rootfs
    if config.rootfs:
        rootfs_resolved = Path(config.rootfs).expanduser()
        rootfs_ok = rootfs_resolved.exists()
        checks.append({
            "check": "rootfs image",
            "status": "ok" if rootfs_ok else "MISSING",
            "detail": config.rootfs,
        })
    else:
        checks.append({
            "check": "rootfs image",
            "status": "not configured",
            "detail": "Set [drive] rootfs in qmu.toml or pass --rootfs (skip for --harness)",
        })

    # SSH key — split existence from permissions
    if config.ssh_key:
        key_path = Path(config.ssh_key).expanduser()
        key_ok = key_path.exists()
        checks.append({
            "check": "SSH key",
            "status": "ok" if key_ok else "MISSING",
            "detail": config.ssh_key,
        })
        if key_ok:
            mode = oct(key_path.stat().st_mode)[-3:]
            if mode in ("600", "400"):
                checks.append({
                    "check": "SSH key permissions",
                    "status": "ok",
                    "detail": f"mode={mode}",
                })
            else:
                checks.append({
                    "check": "SSH key permissions",
                    "status": "warn",
                    "detail": f"mode={mode} (should be 600 — `chmod 600 {config.ssh_key}`)",
                })
    else:
        checks.append({
            "check": "SSH key",
            "status": "not configured",
            "detail": "Set [ssh] key in qmu.toml or pass --ssh-key (skip for --harness)",
        })

    # KVM. Distinguish "explicitly disabled" (accel=tcg / --no-kvm) from
    # "unavailable" so a deliberate TCG choice — e.g. to make gdbstub hardware
    # watchpoints deliver (#39) — is not misreported as a missing capability.
    if config.use_kvm():
        if config.accel == "kvm" and not Path("/dev/kvm").exists():
            # accel=kvm forces -enable-kvm unconditionally; if /dev/kvm is
            # absent the launch will fail, so doctor must flag it rather than
            # report a green "forced" it cannot back up.
            checks.append({
                "check": "KVM",
                "status": "warn",
                "detail": "accel=kvm forces -enable-kvm but /dev/kvm is missing; "
                          "launch will fail. Use accel=auto/tcg or --no-kvm.",
            })
        else:
            checks.append({
                "check": "KVM",
                "status": "ok",
                "detail": (
                    "KVM acceleration forced (accel=kvm)"
                    if config.accel == "kvm"
                    else "KVM acceleration available"
                ),
            })
    elif config.accel == "tcg":
        checks.append({
            "check": "KVM",
            "status": "info",
            "detail": "Disabled by accel=tcg (--no-kvm); using TCG emulation",
        })
    else:
        checks.append({
            "check": "KVM",
            "status": "info",
            "detail": f"Not available for arch={config.arch} (will use TCG)",
        })

    # libguestfs (required by `rootfs *` and `launch --inject`). Both the
    # binary and its appliance kernel are checked: guestfish is routinely on
    # PATH while the appliance cannot build, because Debian/Ubuntu ship
    # /boot/vmlinuz-* mode 0600 and the build runs unprivileged. Reporting only
    # "guestfish: found" sends the reader off to debug an opaque
    # "appliance closed the connection unexpectedly" instead.
    checks.append(_check_libguestfs())

    # pry (optional — only needed for `qmu gdb`)
    pry = shutil.which("pry")
    checks.append({
        "check": "pry (GDB integration)",
        "status": "ok" if pry else "info",
        "detail": pry or "Not found in PATH — required only for `qmu gdb`. "
                         "Install pry and ensure it is on PATH.",
    })

    # External passt executable (required only when net_backend = "passt")
    passt = shutil.which("passt")
    checks.append({
        "check": "passt (net_backend=passt)",
        "status": ("ok" if passt else "MISSING") if passt_required else "info",
        "detail": passt or (
            "Not found in PATH — REQUIRED because net_backend=passt. "
            "Install passt (e.g. 'pacman -S passt' / 'apt install passt')."
            if passt_required else
            "Not found — not required for configured net_backend=user."
        ),
    })

    # Running instances
    instances = list_instances()
    checks.append({
        "check": "running VMs",
        "status": "ok",
        "detail": f"{len(instances)} instance(s)",
    })

    # Skills installed — check all skills in each install root
    skill_names = [d.name for d in all_skill_source_dirs()]
    if not skill_names:
        skill_names = ["qmu"]
    roots = [claude_skills_dir()]
    if codex_home().is_dir():
        roots.append(codex_skills_dir())
    installed: list[Path] = []
    missing: list[Path] = []
    for name in skill_names:
        for root in roots:
            p = root / name
            (installed if p.exists() else missing).append(p)
    if not missing:
        checks.append({
            "check": "skills",
            "status": "ok",
            "detail": ", ".join(str(p) for p in installed),
        })
    elif installed:
        checks.append({
            "check": "skills",
            "status": "warn",
            "detail": f"partial: {len(installed)} installed, {len(missing)} missing (run: qmu skill install)",
        })
    else:
        checks.append({
            "check": "skills",
            "status": "not installed",
            "detail": "Run: qmu skill install",
        })

    healthy = ("ok", "info")
    all_ok = all(c["status"] in healthy for c in checks)
    lines = ["qmu doctor:"]
    for c in checks:
        if c["status"] in healthy:
            mark = "+"
        elif c["status"] == "warn":
            mark = "~"
        else:
            mark = "!"
        lines.append(f"  [{mark}] {c['check']}: {c['detail']}")
    if not file_sources and config.rootfs is None and config.ssh_key is None:
        lines.append("")
        lines.append("Tip: run `qmu config init` to create a starter qmu.toml in this directory.")
    _emit(args, data={"ok": all_ok, "checks": checks}, text=lines, stem="doctor")

    return 0 if all_ok else 1
