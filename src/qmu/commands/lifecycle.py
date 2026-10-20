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
import json
import os
import re
import shutil
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Sequence

from dataclasses import dataclass, field, replace

from ..config import resolve_config
from .. import debug as debug_mod
from ..debug import debug_session_present, reset_dropped_breakpoints_warning
from ..instance import (
    HELD_AGE,
    HELD_MALFORMED_METADATA,
    HELD_QMP_BUSY,
    QMUError,
    VM_HELD_BACK,
    VM_ORPHANED,
    VM_RUNNING,
    VM_STOPPED,
    choose_instance,
    classify_vm,
    find_orphan_qemus,
    held_back_vms,
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
    cache_root_is_sane,
    classify_residue,
    source_tree_names,
    human_bytes,
    remove_items,
    unmanaged_subtree_names,
)
from ..runtime import prune_runtime_artifacts
from ..hostcc import candidate_compilers, cross_package, host_arch, normalize_arch
from ..paths import (
    all_skill_source_dirs,
    global_config_path,
    cache_home,
    instances_dir,
    qemu_log_path,
    qmp_socket_path,
    skill_install_roots,
)
from ..qemu import native_passt_problem, probe_qemu_netdevs
from ..qmp import QMPBusyError, QMPError
from .. import daemon_client
from ..serial import (
    SerialTail,
    current_boot_offset,
    scan_for_pattern,
    extract_crash,
    has_terminal_panic,
    extract_unknown_params,
    last_boot_offset,
    scan_console_growth,
    serial_log_offset,
)
from ..ssh import probe_refused_auth
from ..vm import launch_vm, suspect_dotted_params
from .._cliutil import (
    Result,
    _add_common_opts,
    _add_launch_opts,
    _auth_refused_error,
    _auth_refused_hint,
    _kill_vm,
    _make_ssh,
    _qmp_ctx,
    _resolve_config_from_args,
    _ssh_user,
    forward_label,
)


# ---------------------------------------------------------------------------
# launch
# ---------------------------------------------------------------------------


def _add_launch(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("launch", help="Start a QEMU VM")
    _add_launch_opts(p)
    _add_common_opts(p)
    p.set_defaults(handler=_handle_launch)


@dataclass
class _BootPrep:
    """What `_prepare_boot` learned that the launch envelope must carry.

    Every launch-time warning used to exist only on stderr, so an agent in
    `--format json` had to capture and regex the other stream to learn that
    `--profile` dropped `nokaslr` or that a dotted param was a typo. `warnings`
    is the JSON mirror of those lines; stderr keeps them for text readers.
    `config_sources` names the config files that applied, in precedence order,
    because a parent directory's qmu.toml silently contributed `extra_args`
    to a launch from a subdirectory and nothing in the output said so.
    """
    warnings: list[str] = field(default_factory=list)
    config_sources: list[str] = field(default_factory=list)
    replaced: dict[str, Any] | None = None


def _note(prep: _BootPrep | None, message: str) -> None:
    if prep is not None:
        prep.warnings.append(message)


def _replace_existing_named_vm(name: str | None, no_replace: bool) -> Any:
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
                f"replace it, or stop it first: qmu kill --vm {name}",
                hint=f"qmu kill --vm {name}; or relaunch with another --name",
            )
        return
    existing = load_instance(name)
    if existing is not None and instance_alive(existing):
        sys.stderr.write(f"[qmu] Replacing existing VM '{name}' (pid={existing.pid})\n")
        _release_from_daemon(existing)
        _kill_vm(existing)
        return existing
    elif existing is not None:
        # Stale metadata from dead process — just clean up
        remove_instance(existing.vm_id)
    return None


def _warn_if_cmdline_drops_root(
    args: argparse.Namespace, config: Any, prep: _BootPrep | None = None
) -> None:
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
    message = (
        "--cmdline replaces the profile command line and this one has no "
        "'root=', but a rootfs is attached. The guest will likely stall in "
        "initramfs. Add 'root=/dev/sda' (check `qmu config show` for the profile "
        "cmdline), or use --append to extend the profile instead of replacing it."
    )
    sys.stderr.write(f"[qmu] Warning: {message}\n")
    _note(prep, message)


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


def _warn_profile_override_drops(
    config: Any, append: str | None, prep: _BootPrep | None = None
) -> None:
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
    summary = (
        f"--profile {config.profile} overrides the [boot] cmdline in qmu.toml "
        "for this launch"
    )
    if not dropped:
        _note(prep, summary)
        return
    sys.stderr.write(f"[qmu]   dropped: {' '.join(dropped)}\n")
    summary += f"; dropped: {' '.join(dropped)}"
    for token in dropped:
        name = token.split("=", 1)[0]
        consequence = _CONSEQUENTIAL_DROPS.get(name)
        if consequence:
            sys.stderr.write(f"[qmu]   note: '{token}' is gone — {consequence}\n")
            summary += f"; '{token}' is gone — {consequence}"
    sys.stderr.write("[qmu]   re-add any you still need with --append.\n")
    _note(prep, summary + "; re-add any you still need with --append")


def _warn_suspect_dotted_params(
    config: Any, append: str | None, prep: _BootPrep | None = None
) -> None:
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
        message = (
            f"boot parameter '{typo}' looks like a typo of '{suggestion}'. "
            "Dotted params are NOT reported by the kernel's unknown-parameter "
            "line, so this would be silently ignored."
        )
        sys.stderr.write(f"[qmu] Warning: {message}\n")
        _note(prep, message)


# The console device and the implicit rootfs disk differ per machine type, and
# every built-in profile is written for x86 (`console=ttyS0 root=/dev/sda`).
# On QEMU's ARM `virt` machines those name devices that do not exist: the
# kernel boots, prints nothing to the serial log, and SSH never comes up — a
# full --ssh-timeout of silence with no explanation.
_ARM_ARCHES = frozenset({"aarch64", "arm"})


def _expected_console(arch: str | None) -> str | None:
    if arch in _ARM_ARCHES:
        return "ttyAMA0"
    if arch == "x86_64":
        return "ttyS0"
    return None


def _warn_arch_cmdline_mismatch(
    args: argparse.Namespace, config: Any, prep: _BootPrep | None = None
) -> None:
    """Lint `console=`/`root=` against the guest arch before a silent boot."""
    arch = config.arch
    resolved = " ".join(
        part for part in (
            config.cmdline or config.profiles.get(config.profile, ""),
            args.append or "",
        ) if part
    )
    consoles = [t for t in resolved.split() if t.startswith("console=")]
    roots = [t for t in resolved.split() if t.startswith("root=")]
    messages: list[str] = []
    if arch in _ARM_ARCHES:
        for token in consoles:
            if token[len("console="):].startswith("ttyS"):
                messages.append(
                    f"'{token}' names an x86 serial port; on {arch} QEMU's virt "
                    "console is ttyAMA0, so the kernel will print nothing to the "
                    "serial log and SSH will never come up. Pass "
                    "--cmdline 'console=ttyAMA0 root=/dev/vda rw ...' (every "
                    "built-in profile is written for x86)."
                )
        if not args.drives:
            for token in roots:
                if token[len("root="):].startswith("/dev/sd"):
                    messages.append(
                        f"'{token}' names a SCSI/SATA disk; qmu attaches the rootfs "
                        f"as virtio on {arch}, where it is /dev/vda. The guest will "
                        "panic with 'VFS: Unable to mount root fs'."
                    )
    elif arch == "x86_64":
        for token in consoles:
            if token[len("console="):].startswith("ttyAMA"):
                messages.append(
                    f"'{token}' names an ARM PL011 UART; on x86_64 the serial "
                    "console is ttyS0, so the kernel will print nothing to the "
                    "serial log."
                )
        # The mirror of the arm check (#152): the implicit x86 drive is a
        # plain -drive (IDE/SATA), so the guest sees /dev/sda, never a vd*.
        if not args.drives:
            for token in roots:
                if token[len("root="):].startswith("/dev/vd"):
                    messages.append(
                        f"'{token}' names a virtio disk; qmu attaches the rootfs "
                        "as a plain IDE/SATA drive on x86_64, where it is "
                        "/dev/sda. The guest will panic with 'VFS: Unable to "
                        "mount root fs'."
                    )
    for message in messages:
        sys.stderr.write(f"[qmu] Warning: {message}\n")
        _note(prep, message)


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

    Params that came from qmu's own profile are never printed. They are not
    actionable by the reader — `apparmor=0` is unclaimed precisely because
    AppArmor is not compiled in, which is the state the param was asking for —
    and a note that appears on every launch is a note nobody reads, which is
    how a dead `panic_on_oops=1` survived in the first place. They stay in the
    returned `profile` bucket so the JSON envelope keeps the split.
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
    # The profile bucket is deliberately silent on stderr; see the docstring.
    # Machine-readable output keeps the same split the text output makes. A
    # script gating on "did I pass a bogus param" must not trip forever on a
    # profile param it cannot fix — that is the alarm fatigue this split exists
    # to end, and merging the halves here would just move it into the JSON.
    return {"all": unknown, "operator": operator, "profile": inherited}


def _require_inject_rootfs(config: Any) -> str:
    if config.rootfs is None:
        raise QMUError(
            "--inject needs a rootfs image. Set [drive] rootfs in qmu.toml or pass --rootfs."
        )
    return config.rootfs


def _preflight_injects(
    config: Any, specs: list[str], partition: int = 1, mkdir: bool = False
) -> None:
    """Reject a bad --inject BEFORE the VM it replaces is killed.

    A typo'd guest directory used to surface only from the write pass, which
    runs after the namesake is gone: the healthy VM was killed and then the
    launch failed, leaving nothing. The checks here open the image read-only,
    which works while the old VM still holds it.
    """
    image = _require_inject_rootfs(config)
    mappings = [rootfs_mod.parse_mapping(spec) for spec in specs]
    rootfs_mod.preflight_inject(image, mappings, partition=partition, mkdir=mkdir)


def _inject_into_rootfs(
    config: Any, specs: list[str], partition: int = 1, mkdir: bool = False
) -> None:
    """Copy host files into the rootfs image before the VM boots."""
    image = _require_inject_rootfs(config)
    # The busy-image guard lives in rootfs.require_image_free so it covers the
    # standalone `qmu rootfs *` commands too, not just this path.
    mappings = [rootfs_mod.parse_mapping(spec) for spec in specs]
    rootfs_mod.inject(image, mappings, partition=partition, mkdir=mkdir)
    for local, guest in mappings:
        sys.stderr.write(f"[qmu] Injected {local} -> {guest}\n")


def _config_layers(config: Any) -> tuple[list[str], str | None]:
    """(config files that applied, in precedence order; the project/explicit one)."""
    applied: list[str] = []
    project: str | None = None
    for entry in getattr(config, "_sources", []):
        kind, sep, path = entry.partition(": ")
        if not sep or kind not in ("global", "project", "config"):
            continue
        applied.append(path)
        if kind in ("project", "config"):
            project = path
    return applied, project


def _prepare_boot(
    args: argparse.Namespace, prep: _BootPrep | None = None
) -> tuple[Any, str | None]:
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
    # `--vm` is the instance selector on every other subcommand, so it is
    # accepted here as an alias for --name. Two different names is a conflict
    # the caller must resolve: silently launching one of them put a VM on the
    # box under a name the caller never checked for and left the other name
    # unlaunched with no error.
    vm_alias = getattr(args, "vm", None)
    if args.name and vm_alias and args.name != vm_alias:
        raise QMUError(
            f"--name {args.name} and --vm {vm_alias} name different VMs; on "
            "launch, --vm is an alias for --name, so pass only one of them."
        )

    config = _resolve_config_from_args(args)

    # A broken global config already warned on stderr inside resolve_config;
    # the JSON mirror comes from the skip record it left behind.
    for skipped in getattr(config, "_skipped_sources", []):
        _note(prep, f"ignoring global config {skipped['path']}: {skipped['problem']}")

    # Name the layers that applied. A qmu.toml found by walking up from a
    # subdirectory contributes `extra_args` (`-M virt -cpu cortex-a57`) to a
    # launch that never mentioned it; without this line the only clue was
    # /proc/<pid>/cmdline.
    applied, project = _config_layers(config)
    if prep is not None:
        prep.config_sources = applied
    if project is not None:
        sys.stderr.write(f"[qmu] config: {project}\n")

    # `-no-reboot` from a config file is invisible on the command line, and
    # it inverts what a `panic=N` reboot test observes (#151): name the key
    # and the flag that clears it.
    reboot_layer = config.source_layer("no_reboot")
    if config.no_reboot and reboot_layer not in ("flag", "built-in"):
        message = (
            f"-no-reboot from [machine] no_reboot in {reboot_layer}: a panic "
            "exits QEMU instead of rebooting; pass --reboot to clear it"
        )
        sys.stderr.write(f"[qmu] {message}\n")
        _note(prep, message)

    # Harness mode bundles --no-wait-ssh + --no-net
    if getattr(args, "harness", False):
        args.no_wait_ssh = True
        args.no_net = True

    if config.kernel is None:
        raise QMUError(
            "No kernel configured. Pass --kernel or set [boot] kernel in qmu.toml "
            "(run `qmu config init` for a starter file).",
            hint="qmu launch --kernel <bzImage>; or qmu config init and set [boot] kernel",
        )

    # An explicit CLI --profile must beat a project `[boot] cmdline`. Layering
    # otherwise inverts: config.cmdline is a full override, so a qmu.toml
    # cmdline would silently discard the profile the caller just named on the
    # command line — `--profile exploit-test` becoming a no-op is exactly the
    # dead-parameter class this tool is supposed to catch. `--cmdline` on the
    # CLI still wins, because that is the caller overriding themselves.
    profile_from_cli = args.profile is not None and args.cmdline is None
    if profile_from_cli and config.cmdline is not None:
        _warn_profile_override_drops(config, args.append, prep)
        config.cmdline = None

    # `--vm` is the instance selector on every other subcommand, so accept it
    # here as an alias for --name rather than silently ignoring it.
    name = args.name or getattr(args, "vm", None)

    _warn_if_cmdline_drops_root(args, config, prep)
    _warn_suspect_dotted_params(config, args.append, prep)
    _warn_arch_cmdline_mismatch(args, config, prep)

    # Validate --inject targets BEFORE the namesake is killed: the write pass
    # below cannot run while the old VM holds the image, but the read-only
    # checks can, and a typo'd guest directory must not cost a healthy VM.
    if args.injects:
        _preflight_injects(
            config, args.injects, partition=args.partition, mkdir=args.mkdir
        )

    # Replace existing VM with the same name (default behavior)
    replaced = _replace_existing_named_vm(name, args.no_replace)
    if replaced is not None and prep is not None:
        prep.replaced = {"vm_id": replaced.vm_id, "pid": replaced.pid}
        prep.warnings.append(
            f"replaced existing VM '{replaced.vm_id}' (pid={replaced.pid})"
        )

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


# Seconds of SSH waiting after which a serial log that is still EMPTY means
# the boot is not going to happen: the kernel prints its banner within the
# first second on every supported machine, so silence this long means it is
# writing to a console device that does not exist (`console=ttyS0` on an ARM
# virt machine) or never started (wrong -M/-cpu). Waiting out the whole
# --ssh-timeout only adds a minute of nothing to the same answer.
NO_CONSOLE_OUTPUT_SECONDS = 10.0
_SSH_POLL_INTERVAL = 1.0
# How long sshd must keep refusing the login before the wait gives up on it.
# A refusal is positive evidence the guest is up, and the account comes from
# the image, so it does not change — but a first-boot script may still be
# installing authorized_keys when sshd starts. A few seconds covers that and
# costs nothing next to the full --ssh-timeout the refusal used to burn (#158).
AUTH_REFUSED_SETTLE_SECONDS = 5.0


def _serial_log_empty(path: str | None) -> bool:
    if not path:
        return True
    try:
        return os.path.getsize(path) == 0
    except OSError:
        return True


def _wait_for_ssh_or_console(ssh: Any, inst: Any, timeout: float) -> str:
    """Block for SSH; returns 'ready', 'timeout', 'no-console-output' or
    'auth-failed'.

    Polls `SSHClient.is_ready` alongside the empty-serial-log check, because
    the non-ready outcomes need different explanations: a slow boot may
    still answer, a silent console never will, and an sshd that refuses the
    recorded user/key has booted and will keep refusing (#158).
    """
    start = time.monotonic()
    deadline = start + timeout
    refused_since: float | None = None
    while True:
        if ssh.is_ready(timeout=2):
            return "ready"
        now = time.monotonic()
        if probe_refused_auth(ssh):
            if refused_since is None:
                refused_since = now
            if now - refused_since >= AUTH_REFUSED_SETTLE_SECONDS or now >= deadline:
                return "auth-failed"
        else:
            refused_since = None
        if (
            now - start >= NO_CONSOLE_OUTPUT_SECONDS
            and _serial_log_empty(inst.serial_log)
        ):
            return "no-console-output"
        # Deadline is checked AFTER a probe, so the guest is always given at
        # least one chance to answer (`--ssh-timeout 0` means "probe once").
        if now >= deadline:
            return "timeout"
        time.sleep(_SSH_POLL_INTERVAL)


def _no_console_output_error(inst: Any, arch: str | None) -> str:
    expected = _expected_console(arch)
    console_hint = (
        f"'console=' names a port this arch does not have ({arch} expects "
        f"console={expected})"
        if expected
        else "'console=' names a port this arch does not have"
    )
    return (
        f"No console output after {NO_CONSOLE_OUTPUT_SECONDS:g}s: the serial "
        f"log is still empty ({inst.serial_log}), so the kernel never wrote to "
        f"the console qmu records. Likely causes: {console_hint}, or the "
        "machine type/CPU (-M/-cpu) does not match this kernel. VM state "
        f"retained; inspect with `qmu status --vm {inst.vm_id}` or stop it "
        f"with `qmu kill --vm {inst.vm_id}`."
    )


def _handle_launch(args: argparse.Namespace) -> Result:
    prep = _BootPrep()
    config, name = _prepare_boot(args, prep)

    launch_notes: list[str] = []
    try:
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
            notes=launch_notes,
        )
    except QMUError as exc:
        # The lint already printed on stderr (`console=ttyS0` on aarch64) is
        # usually the explanation of a failed boot; a JSON reader must get it
        # in the failure envelope too, not only on success (#157).
        for note in launch_notes:
            sys.stderr.write(f"[qmu] {note}\n")
        exc.warnings = [*prep.warnings, *launch_notes, *exc.warnings]
        raise
    # The first-QMP-connect retry (#76): observable, not silently absorbed.
    for note in launch_notes:
        sys.stderr.write(f"[qmu] {note}\n")
        prep.warnings.append(note)
    # Hand the new VM to the daemon now that its first QMP connect succeeded
    # (inside `launch_vm`): from here on every RESET/STOP/SHUTDOWN is observed
    # rather than inferred, and sibling commands read cached state instead of
    # contending for the QMP slot. Best-effort — a VM nobody watches is
    # exactly today's standalone VM.
    _watch_in_daemon(inst)

    exit_code = 0
    error: str | None = None
    error_type = "SSHError"
    hint: str | None = None
    if inst.harness:
        ssh_status = "n/a (harness)"
    elif inst.ssh_port is None:
        # A non-harness VM without an SSH endpoint: launched with --no-net and
        # no --ssh-port, so there is no port to wait on or to report.
        ssh_status = "none (--no-net, no --ssh-port)"
    elif not args.no_wait_ssh:
        ssh = _make_ssh(inst)
        sys.stderr.write(f"[qmu] VM launched (pid={inst.pid}). Waiting for SSH on port {inst.ssh_port}...\n")
        outcome = _wait_for_ssh_or_console(ssh, inst, float(args.ssh_timeout))
        if outcome == "ready":
            ssh_status = "ready"
        elif outcome == "no-console-output":
            ssh_status = "no-console-output"
            exit_code = 4
            error = _no_console_output_error(inst, config.arch)
            expected = _expected_console(config.arch)
            hint = (
                f"qmu log --vm {inst.vm_id} --tail 50; then relaunch with "
                + (f"console={expected} " if expected else "the console= ")
                + "and -M/-cpu matching the kernel's arch"
            )
        elif outcome == "auth-failed":
            # sshd answered and refused the recorded user/key: the guest is
            # up, so neither "still booting" (124) nor a longer timeout
            # applies (#158). An SSH failure, exit 4, naming who was tried.
            ssh_status = "auth-failed"
            exit_code = 4
            error_type = "SSHAuthError"
            auth = _auth_refused_error(inst, ssh)
            error = f"{auth} VM state retained."
            hint = auth.hint
        else:
            # The window closed with the guest still booting: the timeout
            # code (124), the same `run` exits for the same condition, not
            # the transport class (4) — nothing broke, the VM is retained
            # and the SSH may still come up (#72).
            ssh_status = "timeout"
            exit_code = 124
            error_type = "TimeoutError"
            error = (
                f"SSH did not become ready within {args.ssh_timeout}s; the VM "
                "may still be booting. VM state retained."
            )
            hint = (
                f"qmu log --vm {inst.vm_id} --tail 50 shows how far the boot "
                f"got; qmu status --vm {inst.vm_id} re-probes SSH; or relaunch "
                "with a longer --ssh-timeout."
            )
    else:
        ssh_status = "skipped"

    if inst.harness and getattr(inst, "rootfs", None):
        # Name the layer that actually supplied the disk: an explicit --rootfs
        # used to be reported as "from config", sending the reader to edit a
        # qmu.toml key the flag had just overridden.
        layer = config.source_layer("rootfs")
        source = "--rootfs" if layer == "flag" else f"[drive] rootfs in {layer}"
        note = (
            f"Harness mode: attached rootfs {inst.rootfs} (from {source}; pass "
            "--drive to choose the disk)"
        )
        sys.stderr.write(f"[qmu] {note}\n")
        prep.warnings.append(note)

    # Only meaningful once the guest has booted far enough to have printed the
    # line; a --no-wait-ssh launch returns too early, so `wait` and `status`
    # re-check it later. When the check did not run, the JSON says so with
    # null — an empty list is indistinguishable from "checked, clean".
    if ssh_status == "ready":
        unknown_params = _warn_unknown_kernel_params(inst)
        unknown_all: list[str] | None = unknown_params["all"]
        unknown_by_source: dict[str, list[str]] | None = {
            "operator": unknown_params["operator"],
            "profile": unknown_params["profile"],
        }
    else:
        unknown_all = None
        unknown_by_source = None

    result = {
        "ok": exit_code == 0,
        "vm_id": inst.vm_id,
        "pid": inst.pid,
        "ssh_port": inst.ssh_port,
        "ssh_status": ssh_status,
        # Who the SSH commands log in as (#158): fixed here, at launch.
        "ssh_user": _ssh_user(inst),
        # Extra host->guest TCP forwards on qmu's own NIC (#149).
        "forwards": getattr(inst, "forwards", []),
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "profile": inst.profile,
        "profile_applied": not getattr(inst, "cmdline_override", False),
        "cmdline": getattr(inst, "cmdline", None),
        "rootfs": getattr(inst, "rootfs", None),
        "serial_log": inst.serial_log,
        "qemu_log": str(qemu_log_path(inst.vm_id)),
        "qmp_socket": getattr(inst, "qmp_socket", None),
        "arch": config.arch,
        "kvm": getattr(inst, "kvm", None),
        "unknown_kernel_params": unknown_all,
        "unknown_kernel_params_by_source": unknown_by_source,
        "warnings": prep.warnings,
        "config_sources": prep.config_sources,
        "replaced": prep.replaced,
    }

    lines = [
        f"VM '{inst.vm_id}' launched (pid={inst.pid})",
        f"  Arch:    {config.arch}",
    ]
    if inst.harness:
        lines.append(f"  Mode:    harness (no SSH)")
    elif inst.ssh_port is not None:
        lines.append(f"  SSH:     port {inst.ssh_port} ({ssh_status})")
        lines.append(f"  User:    {_ssh_user(inst)}")
    else:
        lines.append(f"  SSH:     {ssh_status}")
    for forward in getattr(inst, "forwards", []):
        lines.append(f"  Forward: {forward_label(forward)}")
    if inst.gdb_port:
        lines.append(f"  GDB:     port {inst.gdb_port}")
    lines.append(f"  Kernel:  {inst.kernel}")
    lines.append(f"  Profile: {_profile_label(inst)}")
    lines.append(f"  Serial:  {inst.serial_log}")
    notes: tuple[str, ...] = ()
    if error is not None:
        result["error_type"] = error_type
        result["error"] = error
        result["hint"] = hint
        if exit_code == 124:
            result["timed_out"] = True
            result["ssh_error"] = True
        elif ssh_status == "auth-failed":
            result["ssh_error"] = True
        # Text-mode stderr trailer, after the launch block it qualifies.
        notes = (f"[qmu] Error: {error}", f"[qmu] Hint: {hint}")
    return Result(
        data=result, text=lines, stem="launch", exit_code=exit_code, notes=notes
    )


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


# How a command's one QMP round trip went. `busy` is the single-client
# contention case: QEMU accepted the connection and never greeted it because
# another client (a `wait`, a debugger bridge) holds the socket. It is neither
# `connected` (nothing was learned) nor `unreachable` (the VM is fine).
# `daemon` means no round trip happened at all: the qmu daemon holds the
# VM's one connection and answered from the state its event stream keeps.
QMP_CONNECTED = "connected"
QMP_BUSY = "busy"
QMP_UNREACHABLE = "unreachable"
QMP_DAEMON = "daemon"


@dataclass
class _QMPProbe:
    state: str
    status: str = "unknown"
    running: bool | None = None
    error: str | None = None
    # The daemon's `vm_state` when `state == QMP_DAEMON`: carries the observed
    # epoch (`epoch_offset`/`epoch_source`) the guest scope is anchored on.
    daemon: dict[str, Any] | None = None


def _daemon_state(inst: Any, *, adopt: bool = True) -> dict[str, Any] | None:
    """The daemon's cached view of a running VM, adopting it on first sight.

    None whenever the standalone path must be taken: the layer is off
    (`QMU_DAEMON=off`), no daemon could be reached or spawned, the VM has no
    record to supervise (an orphan), or the daemon already saw it exit. The
    module-level name is the patch point; the tests run with the layer off.
    """
    if not daemon_client.enabled() or not getattr(inst, "qmp_socket", None):
        return None
    state = daemon_client.vm_state(inst.vm_id, adopt=adopt)
    if state is None or state.get("exited"):
        return None
    return state


def _probe_from_daemon(state: dict[str, Any]) -> _QMPProbe:
    """The daemon's cached view as one probe result.

    `qmp_busy` is the daemon's word for what the standalone path calls
    `busy`: QEMU stopped the vCPUs under a command a client proxied through
    the daemon (`savevm`) and answers nothing until it returns, so the run
    state is unknown — reported as the documented `qmp: "busy"` /
    `qemu_status: "unknown"`, never as the debugger halt (#137).
    """
    if state.get("qmp_busy") is True:
        inflight = state.get("qmp_inflight")
        return _QMPProbe(
            QMP_BUSY,
            error="QEMU is busy with "
            + (f"`{inflight}`" if isinstance(inflight, str) else "a command")
            + " a client sent through the qmu daemon",
            daemon=state,
        )
    running = state.get("running")
    status = state.get("qemu_status")
    return _QMPProbe(
        QMP_DAEMON,
        status=status if isinstance(status, str) else "unknown",
        running=running if isinstance(running, bool) else None,
        daemon=state,
    )


def _query_qmp(inst: Any) -> _QMPProbe:
    """One `query-status` — from the daemon's cache when it watches the VM,
    else one short-lived connection: connect, ask, disconnect.

    Never raises — a probe that cannot be answered is a reportable fact, not a
    failure of the command asking.
    """
    state = _daemon_state(inst)
    if state is not None:
        return _probe_from_daemon(state)
    socket_path = inst.qmp_socket
    if not socket_path:
        # A synthesized orphan carries no recorded socket, but the file sits at
        # the conventional path — so `serving`/`paused` are computable for
        # orphans too rather than collapsing to `unknown`.
        candidate = qmp_socket_path(inst.vm_id)
        if not candidate.exists():
            return _QMPProbe(QMP_UNREACHABLE, error="no QMP socket")
        inst = replace(inst, qmp_socket=str(candidate))
    try:
        with _qmp_ctx(inst) as qmp:
            status = qmp.execute("query-status")
    except QMPBusyError as exc:
        return _QMPProbe(QMP_BUSY, error=str(exc))
    except (QMPError, OSError) as exc:
        return _QMPProbe(QMP_UNREACHABLE, error=str(exc))
    if not isinstance(status, dict):
        return _QMPProbe(QMP_CONNECTED, status=str(status))
    name = status.get("status")
    running = status.get("running")
    return _QMPProbe(
        QMP_CONNECTED,
        status=name if isinstance(name, str) else "unknown",
        running=running if isinstance(running, bool) else None,
    )


@dataclass
class _GuestObservation:
    """Everything one look at a running VM's guest learned, for one renderer.

    `qmp` is None when the guest axis was decided without asking QEMU (a
    terminal panic in the log needs no second opinion). `ssh_ready` is None
    when there is no endpoint to probe or the probe was skipped; `ssh_probed`
    tells those apart.

    `crash_detected` is evidence, not usability: whether the current boot's
    console holds a retrievable report, exactly as `qmu crash` would answer.
    It is independent of `guest` — a paused guest with a report is `paused`
    on the usability axis and still has `crash_detected: True` — because
    deriving it from `guest in (panicked, crashed)` made `list`/`status`
    deny a report `crash` then retrieved, purely because a debugger had
    halted the vCPU (#93).
    """
    guest: str
    scan_offset: int
    console_bytes: int
    qmp: _QMPProbe | None = None
    has_endpoint: bool = False
    ssh_ready: bool | None = None
    ssh_probed: bool = False
    # Wall time of the SSH probe, None when none was sent. A port that accepts
    # TCP but never finishes the banner costs the whole probe budget, and that
    # cost was invisible until it was measured (#77).
    ssh_probe_ms: int | None = None
    # The SSH probe was withheld because a gdb client is attached: its login
    # runs `uname`, which fires a user breakpoint on `__x64_sys_newuname`.
    debugger_attached: bool = False
    # sshd answered the probe and refused the recorded user/key (#158): the
    # guest is up (positive evidence), but no SSH command can log in.
    ssh_auth_failed: bool = False
    crash_detected: bool = False
    # How the boot boundary `scan_offset` was learned when the daemon serves
    # the VM: "observed" (a RESET it witnessed) or "banner" (inferred from
    # the log). None on the standalone path, where only the banner exists.
    epoch_source: str | None = None

    @property
    def qmp_state(self) -> str | None:
        """`connected`/`busy`/`unreachable`/`daemon`, or None when QMP was not asked."""
        return self.qmp.state if self.qmp is not None else None

    def ssh_state(self) -> str:
        """The one SSH word `status` and `list` both report for this VM."""
        if not self.has_endpoint:
            return "none"
        if self.ssh_probed:
            if self.ssh_auth_failed:
                return "auth-failed"
            return "ready" if self.ssh_ready else "down"
        if self.debugger_attached:
            return "skipped (debugger attached)"
        return "skipped"

    def detail(self) -> str | None:
        """Why the axis says `unknown`, for the reader who has to act on it."""
        if self.guest != GUEST_UNKNOWN:
            return None
        reasons: list[str] = []
        if self.qmp is not None and self.qmp.state == QMP_BUSY:
            reasons.append("QMP busy")
        elif self.qmp is not None and self.qmp.state == QMP_UNREACHABLE:
            reasons.append("QMP unreachable")
        if self.ssh_probed:
            reasons.append("SSH ready" if self.ssh_ready else "SSH down")
        elif self.has_endpoint and self.debugger_attached:
            reasons.append("SSH not probed: debugger attached")
        elif self.has_endpoint:
            reasons.append("SSH not probed")
        else:
            reasons.append("no SSH")
        reasons.append(f"{self.console_bytes} bytes of console output")
        return ", ".join(reasons)


def _observe_guest(
    inst: Any, *, qmp: _QMPProbe | None = None, probe_ssh: bool = False
) -> _GuestObservation:
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
    - `serving`   — POSITIVE evidence only: sshd answered, or — for a guest
                    with no SSH endpoint and no probe — the current boot has
                    written to its console. A vCPU that merely runs is not
                    evidence: an aarch64 guest booted with the x86 cmdline
                    runs forever, writes nothing, and answers nobody, and it
                    was reported `serving` for exactly that reason.
    - `unknown`   — nothing positive: SSH probed and down, QMP busy or
                    unreachable with no SSH verdict, or no console output.

    `qmp` lets a caller that already paid for a `query-status` share it;
    `probe_ssh` asks sshd only when that could change the answer — never for
    a panicked or paused guest, which can only time out.
    """
    # Scope BOTH crash reads to the current boot. On the standalone path the
    # recorded guest epoch only advances on a RESET some qmu command happened
    # to witness, so a guest-initiated reboot between two commands leaves it
    # pointing at a guest that no longer exists — and a panic from the
    # previous boot would then label a demonstrably healthy VM as gone and
    # instruct the operator to reap it; the log's newest boot banner is the
    # fallback. When the daemon watches the VM, its event stream saw every
    # RESET: the epoch it persisted is the anchor and the banner can only
    # refine it forward within the same boot, never decide against it.
    if qmp is None:
        state = _daemon_state(inst)
        if state is not None:
            qmp = _probe_from_daemon(state)
    daemon = qmp.daemon if qmp is not None else None
    epoch_source: str | None = None
    if daemon is not None:
        epoch = daemon.get("epoch_offset")
        start = current_boot_offset(
            inst.serial_log, epoch if isinstance(epoch, int) else inst.guest_epoch_serial_offset
        )
        epoch_source = daemon.get("epoch_source") if isinstance(daemon.get("epoch_source"), str) else "banner"
    else:
        start = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    console_bytes = max(0, serial_log_offset(inst.serial_log) - start)
    has_endpoint = not inst.harness and inst.ssh_port is not None

    if has_terminal_panic(inst.serial_log, start_offset=start):
        return _GuestObservation(
            GUEST_PANICKED, start, console_bytes, qmp, has_endpoint,
            ssh_ready=False if has_endpoint else None, crash_detected=True,
            epoch_source=epoch_source,
        )

    # Read once, before the usability precedence decides anything: the report
    # is a fact about the log whichever branch below wins.
    crash_detected = extract_crash(inst.serial_log, start_offset=start) is not None

    if qmp is None:
        qmp = _query_qmp(inst)
    if qmp.running is False:
        return _GuestObservation(
            GUEST_PAUSED, start, console_bytes, qmp, has_endpoint,
            ssh_ready=False if has_endpoint else None,
            crash_detected=crash_detected, epoch_source=epoch_source,
        )

    # #39-adjacent: the readiness probe logs in, and a login runs `uname`.
    # With a client on the gdb stub that is a breakpoint on
    # `__x64_sys_newuname` fired by qmu itself, and a `status` that halts the
    # guest it was asked to describe. Console bytes stand in as the positive
    # evidence, exactly as for a guest with no endpoint.
    attached = (
        probe_ssh and has_endpoint and inst.gdb_port is not None
        and debug_session_present(inst)
    )
    ssh_ready: bool | None = None
    ssh_probed = False
    ssh_probe_ms: int | None = None
    ssh_auth_failed = False
    if probe_ssh and has_endpoint and not attached:
        probe_start = time.monotonic()
        ssh = _make_ssh(inst)
        ssh_ready = bool(ssh.is_ready())
        ssh_probe_ms = int((time.monotonic() - probe_start) * 1000)
        ssh_probed = True
        ssh_auth_failed = probe_refused_auth(ssh)

    if crash_detected:
        guest = GUEST_CRASHED
    elif ssh_probed:
        # An sshd that refuses the login answered: the guest serves, only
        # not to this user/key — `ssh: "auth-failed"` says which (#158).
        guest = GUEST_SERVING if ssh_ready or ssh_auth_failed else GUEST_UNKNOWN
    elif qmp.running is True and console_bytes > 0:
        guest = GUEST_SERVING
    else:
        guest = GUEST_UNKNOWN
    return _GuestObservation(
        guest, start, console_bytes, qmp, has_endpoint,
        ssh_ready=ssh_ready, ssh_probed=ssh_probed, ssh_probe_ms=ssh_probe_ms,
        debugger_attached=attached, ssh_auth_failed=ssh_auth_failed,
        crash_detected=crash_detected, epoch_source=epoch_source,
    )


def _guest_state(inst: Any) -> str:
    """The guest-usability axis alone; see `_observe_guest` for the rules."""
    if inst is None:
        return GUEST_UNKNOWN
    return _observe_guest(inst).guest


def _classify(vm_id: str, older_than: float = 86400.0) -> dict[str, Any]:
    """Classify a vm_id on BOTH axes, through the shared authority.

    `state` answers "does a record and/or a process exist"; `guest` answers
    "is the guest usable". They are orthogonal — the cross product is real
    (orphaned+panicked is an everyday state after a triggered crash) — so they
    are two fields, never one enum.

    The guest axis is read only for an orphan, the one state whose
    explanation uses it. Every caller with a *running* VM goes on to observe
    the guest itself with the SSH probe and the shared QMP round trip; doing
    it here too cost a second QMP connect per command — 2 s more behind a
    busy socket, for a value nobody read.
    """
    info = classify_vm(
        vm_id, older_than_seconds=older_than, orphan_pids=_orphan_serial_logs()
    )
    if info["state"] == VM_ORPHANED:
        info["guest"] = _guest_state(info["instance"])
    else:
        info["guest"] = GUEST_UNKNOWN
    return info


def _held_hint(
    vm_id: str, reason: str | None, path: str | None, *, older_than: float
) -> str:
    """The one sentence every command uses for a prune-withheld remnant.

    Keyed on the refusal reason, never on `held_back` alone: a malformed
    `.json` with no serial log is refused at any age, so prescribing
    `--older-than 0` for it sends the caller around the same loop forever
    (#109). qmu will not delete metadata it cannot read; the operator can.
    """
    if reason == HELD_MALFORMED_METADATA:
        return (
            f"metadata unreadable: {path} — repair or delete the .json by "
            f"hand, then prune"
        )
    if reason == HELD_QMP_BUSY:
        return (
            f"QMP socket still answers: {path} — something still serves it; "
            f"reap with `qmu kill --vm {vm_id}` or `qmu prune --orphans`, "
            f"then prune"
        )
    return (
        f"younger than the --older-than cutoff ({older_than:g}s); re-run with "
        f"`qmu prune --vm {vm_id} --older-than 0` to remove it"
    )



def _retained_logs(inst: Any) -> dict[str, Any]:
    """What a stopped VM left behind, in the words `status`/`kill`/`list` share.

    `crash_detected` is scoped to the last boot like every other reader, so
    a kill that preserved a report and a `list` that marks it agree.
    """
    serial = inst.serial_log if inst.serial_log and os.path.exists(inst.serial_log) else None
    qemu = qemu_log_path(inst.vm_id)
    qemu_log = str(qemu) if qemu.exists() else None
    crash_detected = False
    if serial is not None:
        scope = current_boot_offset(serial, inst.guest_epoch_serial_offset)
        crash_detected = extract_crash(serial, start_offset=scope) is not None
    return {
        "serial_log": serial,
        "qemu_log": qemu_log,
        "logs_retained": serial is not None,
        "crash_detected": crash_detected,
    }


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


def _kill_orphan_if_named(args: argparse.Namespace) -> Result | None:
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
        return Result(
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
    return None


def _close_ssh_master(inst: Any) -> bool:
    """Tear down the VM's multiplexed ssh master before QEMU goes away.

    `exec`/`push`/`pull` leave a `ControlPersist=60` master behind; after the
    guest is gone it lingers for its full minute as an `ssh [mux]` process
    under the runtime dir, which `prune --runtime` then reports as live.
    False when the VM never had an endpoint or no master was open.
    """
    if inst.harness or inst.ssh_port is None or not inst.ssh_key:
        return False
    return bool(_make_ssh(inst).close_control_master())


def _release_from_daemon(inst: Any) -> bool:
    """Ask the daemon to give `inst` up while its process lives: the watch
    and its QMP connection go, and every `wait` subscribed to it finishes
    standalone (`released`). For a caller that takes the VM over — a
    `--replace` launch — never for `kill`, which quits through the daemon so
    the watch itself sees the exit. Never spawns a daemon; False when none
    is running or the layer is off. Also the patch point for tests."""
    if not daemon_client.enabled():
        return False
    return daemon_client.unwatch(inst.vm_id)


def _watch_in_daemon(inst: Any) -> dict[str, Any] | None:
    """Hand a freshly launched VM to the daemon (spawning one if `[daemon]
    autostart` allows). None when the layer is off or no daemon came up;
    the launch is unaffected either way. Patch point for tests."""
    if not daemon_client.enabled():
        return None
    return daemon_client.watch(inst.vm_id)


def _handle_kill(args: argparse.Namespace) -> Result:
    orphan_result = _kill_orphan_if_named(args)
    if orphan_result is not None:
        return orphan_result
    if args.vm:
        info = _classify(args.vm)
        if info["state"] in (VM_STOPPED, VM_HELD_BACK):
            # Already what the caller asked for. An error here made every
            # "kill then kill again" cleanup script branch on exit codes for
            # a state it was happy with.
            inst = info["instance"]
            retained = _retained_logs(inst)
            # #78: QEMU being gone does not take the pry bridge `qmu gdb`
            # recorded with it — a guest poweroff or an external `qmp quit`
            # followed by the idempotent `kill` left a `gdb-multiarch` parked
            # on a dead stub. Same identity-checked reap as the live path;
            # the logs it preserves are untouched. The ssh master is closed
            # for the same reason: it is qmu's own, not the guest's.
            _close_ssh_master(inst)
            bridge_reaped = _reap_recorded_bridge(inst)
            if info["state"] == VM_HELD_BACK:
                remove = "not prunable as-is: " + _held_hint(
                    args.vm, info["held_reason"], info["held_path"],
                    older_than=86400.0,
                )
                remove_record = remove
            else:
                remove = f"remove with: qmu prune --vm {args.vm}"
                remove_record = f"remove its record with: qmu prune --vm {args.vm}"
            return Result(
                data={
                    "ok": True,
                    "vm_id": args.vm,
                    "already_stopped": True,
                    "logs_retained": retained["logs_retained"],
                    "serial_log": retained["serial_log"],
                    "bridge_reaped": bridge_reaped,
                    "held_reason": info["held_reason"],
                    "held_path": info["held_path"],
                },
                text=(
                    f"VM '{args.vm}' is already stopped; state retained ({remove})"
                    if retained["logs_retained"]
                    else f"VM '{args.vm}' is already stopped; no logs retained "
                    f"({remove_record})"
                )
                + (" Reaped its recorded debugger bridge." if bridge_reaped else ""),
                stem="kill",
            )
    inst = choose_instance(args.vm)
    # A panicked or crashed guest has a report in its serial log that `status`
    # just told the reader to pull. The default clean deleted it without a
    # word, so the evidence vanished under the one command every cleanup runs.
    # Keep the logs (exactly what --no-clean keeps) and say where they are.
    guest = _guest_state(inst)
    preserve_crash = guest in (GUEST_PANICKED, GUEST_CRASHED)
    clean = not args.no_clean and not preserve_crash
    # #40: `qmu gdb` spawns a pry bridge that qmu does not track, so killing the
    # VM leaves that bridge pointing at a dead GDB stub — and the operator only
    # discovers it as a "Multiple bridge instances" error on the next `pry`
    # command. Probe for an attached client BEFORE the kill drops its
    # connection, and if one is present, say so on stderr so cleanup is not a
    # later surprise. qmu still does not manage the pry lifecycle.
    had_bridge = debug_session_present(inst) if inst.gdb_port is not None else False
    _close_ssh_master(inst)
    # The daemon keeps its watch through the kill (#118). `_kill_vm`'s
    # graceful `quit` rides the daemon's own QMP connection (`_qmp_ctx`
    # proxies when the VM is watched), and the daemon marks the watch exited
    # once the EOF-then-PID check proves the process gone — which is the
    # terminal transition every in-flight `wait` on this VM is owed. Releasing
    # the watch first, as this used to, orphaned those waiters: they burned
    # their whole timeout on a VM that was already dead.
    _kill_vm(inst, force=args.force, clean=clean)
    bridge_reaped = _reap_recorded_bridge(inst)
    if preserve_crash:
        msg = (
            f"VM '{inst.vm_id}' stopped. Crash report preserved: "
            f"qmu crash --vm {inst.vm_id}; remove with: "
            f"qmu prune --vm {inst.vm_id}"
        )
    elif args.no_clean:
        msg = f"VM '{inst.vm_id}' stopped. State preserved at {inst.serial_log}"
    else:
        msg = f"VM '{inst.vm_id}' stopped."
    res = Result(
        data={
            "ok": True,
            "vm_id": inst.vm_id,
            "guest": guest,
            "cleaned": clean,
            "logs_preserved": not clean,
            # Never hand back a path the clean just unlinked.
            "serial_log": inst.serial_log if not clean else None,
            "bridge_reaped": bridge_reaped,
        },
        text=msg,
        stem="kill",
    )
    if had_bridge and not bridge_reaped:
        res = res.warn(
            f"[qmu] Note: VM '{inst.vm_id}' had an attached debugger on GDB port "
            f"{inst.gdb_port}. That pry bridge now points at a dead stub; qmu does "
            "not manage it. If a later `pry` command reports \"Multiple bridge "
            "instances\", this is the stale one — clean it up (`pry doctor`, then "
            "kill it).\n"
        )
    return res


def _reap_recorded_bridge(inst: Any) -> bool:
    """Reap the pry bridge `qmu gdb` recorded on this instance, if any.

    `debug.reap_bridge` owns the how; this only decides whether there is a
    recorded bridge to reap. A VM launched before the bridge was tracked, or
    one never attached, has nothing to reap and reports False.
    """
    if getattr(inst, "gdb_bridge_pid", None) is None:
        return False
    reap = getattr(debug_mod, "reap_bridge", None)
    if reap is None:
        return False
    return bool(reap(inst))


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


def _handle_prune_build_residue(args: argparse.Namespace) -> Result:
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
            f"`qmu cache du --older-than {older_than:g}`.",
            hint=(
                f"Use `qmu prune --build-residue --older-than "
                f"{MIN_BUILD_RESIDUE_AGE:g}` to include recently modified "
                f"trees, or inspect first with `qmu cache du --older-than "
                f"{older_than:g}`."
            ),
        )

    # QMU_CACHE_DIR is honoured with no validation, so a typo pointing at
    # $HOME must stop here — before anything is classified, let alone unlinked.
    # An absent or empty root is not that typo: there is nothing under it to
    # reclaim, and a fresh install must not be told its cache is broken.
    root = cache_home()
    if not cache_root_is_sane() and root.is_dir() and any(root.iterdir()):
        raise QMUError(
            f"Refusing to prune build residue: {root} does not look like a "
            "qmu cache (no instances/, kernels/, rootfs/ or targets/ subtree, "
            "but it is not empty). Check QMU_CACHE_DIR."
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
        return Result(data=data, text=_residue_lines(report, dry_run=True, older_than=older_than),
                      stem="prune-build-residue")

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
    # A refused group is a reported outcome, not a failure: exiting non-zero
    # would make scripted use fail on any cache holding one root-owned tree.
    return Result(
        data=data,
        text=_residue_lines(
            report, dry_run=False, older_than=older_than,
            removed_bytes=sum(i.bytes for i in removed),
            removed_files=len(removed), failed=len(failed),
        ),
        stem="prune-build-residue",
    )


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
            f"recently and may be mid-build. Re-run later, or with a smaller "
            f"--older-than, down to the {MIN_BUILD_RESIDUE_AGE:g}s floor "
            f"(`qmu prune --build-residue --older-than {MIN_BUILD_RESIDUE_AGE:g}`), "
            f"to reclaim trees from builds that have finished."
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


def _orphan_vm_id(orphan: dict[str, Any]) -> str | None:
    """The vm_id an orphan's own argv names, so `--dry-run` says which VM it
    would kill rather than just a pid the reader has to map back by hand."""
    for key, suffix in (("serial_log", ".serial.log"), ("qmp_socket", ".qmp.sock")):
        path = orphan.get(key)
        if path and str(path).endswith(suffix):
            return Path(path).name[: -len(suffix)]
    return None


def _handle_prune_orphans(args: argparse.Namespace) -> Result:
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
                {
                    "vm_id": _orphan_vm_id(o),
                    "pid": o["pid"],
                    "serial_log": o.get("serial_log"),
                }
                for o in orphans
            ],
            "killed": [],
        }
        if not orphans:
            text: Any = "No orphaned qmu QEMU processes. Nothing would be killed."
        else:
            text = [f"Would kill {len(orphans)} orphaned QEMU process(es):"]
            for o in orphans:
                text.append(
                    f"  {_orphan_vm_id(o) or '?'}  pid {o['pid']}  "
                    f"serial={o.get('serial_log') or '?'}"
                )
            text.append("Re-run without --dry-run to kill them.")
        return Result(data=data, text=text, stem="prune-orphans")

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
    if failed:
        pids = ", ".join(str(f["pid"]) for f in failed)
        data["hint"] = (
            f"SIGTERM to pid(s) {pids} failed (see `failed[].error`: usually "
            "another user's process, or one that exited meanwhile). Confirm "
            f"with `ps -o user,pid,cmd -p {pids}`; only a QEMU you own can be "
            "killed from this account"
        )
    if not orphans:
        text: Any = "No orphaned qmu QEMU processes."
    else:
        text = [f"Killed {len(killed)} orphaned QEMU process(es):"]
        text.extend(f"  pid {pid}" for pid in killed)
        text.extend(f"  pid {f['pid']}: FAILED — {f['error']}" for f in failed)
    return Result(
        data=data, text=text, stem="prune-orphans", exit_code=1 if failed else 0
    )


def _handle_prune(args: argparse.Namespace) -> Result:
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
        return Result(data=data, text=text, stem="prune")

    running = list_instances()
    running_ids = {inst.vm_id for inst in running}
    prunable = list_prunable_instance_ids(older_than_seconds=args.older_than)

    # `found` is the --vm answer to "was there anything on disk". Reported on
    # that path only; --all has no single subject.
    found: bool | None = None
    if vm is not None:
        if vm in running_ids:
            raise QMUError(
                f"VM '{vm}' is running. Use 'qmu kill --vm {vm}' first.",
                hint=f"qmu kill --vm {vm}; then qmu prune --vm {vm}",
            )
        found = True
        refused: list[dict[str, Any]] = []
        if vm in prunable:
            targets = [vm]
        else:
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
            if info["state"] == VM_STOPPED:
                targets = [vm]
            elif info["state"] == VM_HELD_BACK:
                # A refusal is an outcome, not an error: `prune --all`
                # reports the same remnant as `held_back` with exit 0, and
                # `--dry-run` must land in the preview envelope rather than
                # fail and prescribe the destructive run.
                targets = []
                refused = [{
                    "vm_id": vm,
                    "reason": info["held_reason"],
                    "path": info["held_path"],
                }]
            else:
                # Absent. A default `kill` already removed everything, so the
                # cleanup idiom `kill && prune --vm` must not fail on it.
                found = False
                targets = []
    elif prune_all:
        targets = prunable
        # Disclosed unconditionally: on every branch, in both modes, and in
        # JSON. Round 5 fixed only the nothing-is-prunable branch of the real
        # run, so a mixed cache still reported "Pruned 1 VM(s) (removed)" with
        # a remnant holding megabytes of serial log left behind, and the
        # preview — the thing a cautious operator runs first — reintroduced
        # the original false statement outright.
        refused = held_back_vms(
            older_than_seconds=args.older_than, orphan_pids=_orphan_serial_logs()
        )
    else:
        raise QMUError(
            "Specify a mode: " + _all_modes_phrase() + "."
        )

    # `held_back` keeps the id list; `refused` says WHY each one stayed, so a
    # malformed-metadata refusal is never dressed up as the age gate (#109).
    held_back = [entry["vm_id"] for entry in refused]
    aged = [e["vm_id"] for e in refused if e["reason"] == HELD_AGE]
    held_lines = [
        f"Held back by the --older-than cutoff ({args.older_than:g}s): "
        f"{', '.join(aged)}. Re-run with `--older-than 0` to include them."
    ] if aged else []
    held_lines += [
        f"Not pruned {entry['vm_id']}: "
        + _held_hint(
            entry["vm_id"], entry["reason"], entry["path"],
            older_than=args.older_than,
        )
        for entry in refused if entry["reason"] != HELD_AGE
    ]
    absent_note = (
        f"Nothing to prune for '{vm}': no state on disk (already removed by "
        "kill, or never existed)."
    ) if found is False else None

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
            "refused": refused,
            "keep_logs": args.keep_logs,
        }
        if found is not None:
            data["found"] = found
        if absent_note:
            text: Any = [absent_note]
        elif not targets:
            text = ["Nothing to prune. Nothing would be removed."]
        else:
            verb = "keep logs for" if args.keep_logs else "remove"
            text = [f"Would {verb} {len(targets)} VM(s): {', '.join(targets)}"]
            text.append("Re-run without --dry-run to do it.")
        text.extend(held_lines)
        if cache_note:
            text.append(cache_note)
        return Result(data=data, text=text, stem="prune")

    pruned: list[str] = []
    for vm_id in targets:
        remove_instance(vm_id, keep_logs=args.keep_logs)
        pruned.append(vm_id)

    if absent_note:
        lines = [absent_note]
    elif not pruned:
        lines = ["No stopped VMs to prune."] if not held_back else [
            "No stopped VMs could be pruned."
        ]
    else:
        verb = "kept logs for" if args.keep_logs else "removed"
        lines = [f"Pruned {len(pruned)} VM(s) ({verb}): {', '.join(pruned)}"]
    lines.extend(held_lines)
    if cache_note:
        lines.append(cache_note)
    data = {
        "ok": True,
        "dry_run": False,
        "unmanaged_cache": unmanaged,
        "pruned": pruned,
        "held_back": held_back,
        "refused": refused,
        "keep_logs": args.keep_logs,
    }
    if found is not None:
        data["found"] = found
    return Result(data=data, text=lines, stem="prune")


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


# Bare `wait` polls with short-lived QMP connections — one `query-status` per
# tick, connect to close — instead of holding the socket for its duration.
# QEMU serves ONE QMP client: a held connection made every sibling `status`
# stall 10 s per connect (then report `qmp: connected`) and a `kill` take 14 s
# because its graceful `quit` queued behind the wait. The price is that QMP
# *events* are not observable; the status transitions they cause are, and are
# reported under the event name QEMU would have emitted. A guest-initiated
# reboot is observed through the serial log's new boot banner instead of the
# RESET event, which is also how every other command scopes the guest.
_STATUS_EVENTS = {
    "shutdown": "SHUTDOWN",
    "paused": "STOP",
    "guest-panicked": "GUEST_PANICKED",
}
_WAIT_POLL_INTERVAL = 0.5

# QEMU closes QMP ~100 ms before its recorded pid vanishes. After a lost
# connection allow only this much identity polling — never an extended wait —
# before calling the transport broken.
_WAIT_TRANSPORT_GRACE = 1.0

_WAIT_REASON_TERMINAL_PANIC = "terminal_panic"
_WAIT_REASON_ALREADY_STOPPED = "already_stopped"


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
                        "waiting for the VM to exit. With explicit --vm, also reads retained "
                        "stopped logs. Exits 0 on match, 3 on terminal panic, "
                        "1 on exit without a match, 124 on timeout.")
    p.add_argument("--ignore-crash", action="store_true",
                   help="With --pattern: keep waiting through a terminal panic instead of "
                        "aborting on it")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata after stop (harness VMs only)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_wait)


# How often the --pattern loop rescans the serial log. Short enough that an
# agent's next command starts promptly; long enough that a multi-minute wait
# is not thousands of syscalls.
_PATTERN_POLL_INTERVAL = 0.25


def _handle_wait(args: argparse.Namespace) -> Result:
    if getattr(args, "pattern", None) is not None:
        return _wait_for_pattern(args)
    if args.vm:
        # A VM that already exited is a FINISHED wait, not an unwaitable one. A
        # 3 s harness beats any two-call agent to the exit, and the old refusal
        # ("needs a running VM") turned the common outcome into an error whose
        # answer depended on whether `wait` started a second earlier or later.
        info = classify_vm(args.vm, orphan_pids=_orphan_serial_logs())
        if info["state"] in (VM_STOPPED, VM_HELD_BACK):
            return _wait_already_stopped(args, info["instance"])
        if info["state"] == VM_ORPHANED:
            _require_running(args.vm, "wait")
    inst = choose_instance(args.vm)
    start = time.monotonic()
    deadline: float | None = (
        start + args.timeout if args.timeout is not None else None
    )

    daemon = _daemon_state(inst)
    if daemon is not None:
        return _wait_via_daemon(args, inst, daemon, start=start, deadline=deadline)
    return _wait_standalone(args, inst, start=start, deadline=deadline, warnings=[])


def _wait_standalone(
    args: argparse.Namespace,
    inst: Any,
    *,
    start: float,
    deadline: float | None,
    warnings: list[str],
    last_event: str | None = None,
    event_data: Any = None,
) -> Result:
    """The poll loop: PID liveness, an incremental console scan and one
    short-lived `query-status` per tick, until the process is gone, the guest
    took a terminal panic, or `deadline` passes.

    Also the continuation of a daemon-backed wait whose subscription the
    daemon ended (`released`, #118): `start`/`deadline` are the original
    wait's, `warnings` carries what the daemon phase collected, and
    `last_event`/`event_data` seed the transition report so an event the
    daemon streamed is not forgotten.
    """
    reason = "timeout"
    stopped = False
    crash: str | None = None
    guest: str | None = None
    probe: _QMPProbe | None = None
    qemu_status = "unknown"
    last_status: str | None = None
    boot_offset = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    # Line-aligned high-water mark of the console bytes already examined.
    # Rescanning from `boot_offset` every tick made a 20 s wait on a chatty
    # guest burn half a core (r2-shared: 10 s user CPU); each tick now reads
    # only what QEMU appended since the last one.
    scanned = boot_offset
    reset_warning = reset_dropped_breakpoints_warning(inst.vm_id) + "\n"

    def scan_console() -> bool:
        """One incremental console scan; adopts a moved boot boundary.

        A new boot banner is a reboot the guest initiated (panic=N, kexec, a
        harness calling reboot). It is persisted as the guest epoch exactly as
        an observed RESET used to be, BEFORE the next liveness check, so a VM
        that exits right after rebooting is scoped to its last boot. A
        boundary that moved DOWN means the log itself was replaced (truncated
        under the loop): the old generation's byte offsets no longer name
        anything, so the new one is adopted the same way (#103).
        """
        nonlocal scanned, boot_offset, last_event, event_data, inst
        scanned, banner, panicked = scan_console_growth(
            inst.serial_log, scanned=scanned, boot_offset=boot_offset
        )
        if banner != boot_offset:
            source = "boot-banner" if banner > boot_offset else "log-replaced"
            boot_offset = banner
            last_event = "RESET"
            event_data = {"source": source, "offset": banner}
            inst = save_guest_epoch_serial_offset(inst, banner)
            # #46: a reset drops the gdbstub breakpoint set without telling the
            # client. `wait` is the one place qmu sees a reset it did not issue.
            # Collected once for the Result (#121): `render` writes it to
            # stderr exactly once and the envelope carries it in `warnings[]`.
            if reset_warning not in warnings and debug_session_present(inst):
                warnings.append(reset_warning)
        return panicked

    def terminal_panic_report() -> str | None:
        return _settled_crash(inst, boot_offset) or extract_crash(
            inst.serial_log, start_offset=boot_offset
        )

    while True:
        # The recorded process identity is the only terminal authority. Checked
        # first so --timeout 0 is "check once, then time out".
        if not instance_alive(inst):
            reason = "process_exited"
            stopped = True
            break

        # #27: a terminal panic ends the guest even though QEMU keeps running
        # (no -no-reboot, panic=0). Reporting "still running" here contradicted
        # `status` on the same VM and sent the reader back to wait again.
        if scan_console():
            reason = _WAIT_REASON_TERMINAL_PANIC
            guest = GUEST_PANICKED
            crash = terminal_panic_report()
            break

        probe = _query_qmp(inst)
        if probe.state == QMP_UNREACHABLE:
            # Identity polling only, bounded by the deadline; EOF alone proves
            # no exit, and a VM that outlives the grace has a broken transport.
            grace_deadline = time.monotonic() + _WAIT_TRANSPORT_GRACE
            if deadline is not None:
                grace_deadline = min(grace_deadline, deadline)
            while True:
                if not instance_alive(inst):
                    stopped = True
                    reason = "process_exited"
                    break
                remaining = grace_deadline - time.monotonic()
                if remaining <= 0:
                    raise QMPError(f"QMP error during wait: {probe.error}")
                time.sleep(min(0.05, remaining))
            break
        if probe.state == QMP_CONNECTED:
            qemu_status = probe.status
            if last_status is not None and probe.status != last_status:
                last_event = _STATUS_EVENTS.get(
                    probe.status, probe.status.upper().replace("-", "_")
                )
                event_data = {
                    "source": "query-status",
                    "from": last_status,
                    "to": probe.status,
                }
            last_status = probe.status
        else:
            # #92: a busy probe observed nothing. `qemu_status` is what the
            # LATEST probe said, so a value carried over from an earlier
            # connected tick would present stale state as a current reading.
            # `last_status` keeps the history for the transition report.
            qemu_status = "unknown"

        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "timeout"
                break
            time.sleep(min(_WAIT_POLL_INTERVAL, remaining))
        else:
            time.sleep(_WAIT_POLL_INTERVAL)

    if not stopped and reason == "timeout":
        # #91: the probe above blocks for its whole connect timeout when a
        # sibling holds the QMP socket, and the guest can die meanwhile. The
        # deadline decides WHEN the wait ends, never WHAT the guest did; the
        # verdict comes from the console as it is now, not as it was before
        # the probe. A timeout with `crash: null` next to a `console_tail`
        # showing the panic sent callers back to wait on a dead guest.
        if scan_console():
            reason = _WAIT_REASON_TERMINAL_PANIC
            guest = GUEST_PANICKED
            crash = terminal_panic_report()

    elapsed = time.monotonic() - start
    if stopped:
        # The guest may have rebooted between the last scan and its exit.
        boot_offset = last_boot_offset(inst.serial_log, start_offset=boot_offset)
        crash = extract_crash(inst.serial_log, start_offset=boot_offset)
        # No process, no guest axis: `unknown` here read as "qmu could not
        # tell", when the honest answer is that there is nothing to classify.
        guest = None
    guest_detail: str | None = None
    if not stopped and guest is None:
        observation = _observe_guest(inst, qmp=probe)
        guest = observation.guest
        guest_detail = observation.detail()

    return _finish_wait(
        args, inst,
        stopped=stopped, reason=reason, elapsed=elapsed, guest=guest,
        guest_detail=guest_detail,
        crash=crash, qmp_state=probe.state if probe is not None else None,
        qemu_status=qemu_status,
        last_event=last_event, event_data=event_data,
        console_tail=_console_tail(inst.serial_log, boot_offset),
        warnings=warnings,
    )


class _WaitReleased(Exception):
    """The daemon ended this wait's subscription while the VM's process lives
    on — an explicit `unwatch`, its own shutdown, or a lost connection. The
    wait is not over: it continues standalone, on PID liveness and the
    console, for whatever is left of its deadline (#118). `note` is the
    warning line the final Result carries; `last_event`/`event_data` are
    what the daemon phase had observed."""

    def __init__(self, note: str, *, last_event: Any = None, event_data: Any = None):
        super().__init__(note)
        self.note = note
        self.last_event = last_event
        self.event_data = event_data


def _daemon_wait_request(
    args: argparse.Namespace,
    inst: Any,
    *,
    pattern: str | None = None,
    start_offset: int | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """Block on the daemon's `wait` op until it answers; no polling here.

    QMP events the daemon observes meanwhile stream back as they happen and
    are relayed to the progress sink. A RESET under an attached debugger
    earns the #46 warning (the breakpoint set is gone): it is appended to
    `warnings` once, for the Result — never written here, so a structured
    caller gets it in `warnings[]` and a terminal sees it exactly once
    (#121). Raises `_WaitReleased` when the daemon answers `released` or
    the connection is lost: the caller finishes the wait standalone.
    """
    started = time.monotonic()
    reset_warning = reset_dropped_breakpoints_warning(inst.vm_id) + "\n"

    def on_event(event: dict[str, Any]) -> None:
        kind = event.get("kind")
        if kind == "progress":
            daemon_client.report_progress(
                float(event.get("elapsed", 0.0)), int(event.get("scanned", 0)),
                f"waiting on {inst.vm_id}",
            )
            return
        if kind == "released":
            daemon_client.report_progress(
                time.monotonic() - started, 0, f"daemon released {inst.vm_id}; finishing standalone",
            )
            return
        if kind == "qmp_event":
            daemon_client.report_progress(
                time.monotonic() - started, int(event.get("boot_offset", 0)),
                f"QMP {event.get('name')} on {inst.vm_id}",
            )
        if (
            kind == "qmp_event" and event.get("name") == "RESET"
            and warnings is not None and reset_warning not in warnings
            and debug_session_present(inst)
        ):
            warnings.append(reset_warning)

    conn = daemon_client.connect()
    if conn is None:
        raise QMPError(f"daemon went away before the wait on '{inst.vm_id}' started")
    deadline = None if args.timeout is None else float(args.timeout)
    with conn:
        try:
            reply = conn.request(
                "wait",
                # The daemon enforces the deadline; the socket budget only
                # guards against a daemon that died with the wait in flight.
                budget=None if deadline is None else deadline + 5.0,
                on_event=on_event,
                vm_id=inst.vm_id,
                pattern=pattern,
                timeout=deadline,
                start_offset=start_offset,
                ignore_crash=bool(getattr(args, "ignore_crash", False)),
            )
        except daemon_client.DaemonUnavailable as exc:
            raise _WaitReleased(
                f"[qmu] Note: the daemon connection was lost during the wait on "
                f"'{inst.vm_id}' ({exc}); the wait finished standalone on PID "
                "liveness.\n"
            ) from exc
    if reply.get("reason") == "released":
        raise _WaitReleased(
            f"[qmu] Note: the daemon released VM '{inst.vm_id}' mid-wait (an "
            "explicit unwatch or a daemon shutdown); the wait finished standalone "
            "on PID liveness.\n",
            last_event=reply.get("last_event"), event_data=reply.get("event_data"),
        )
    return reply


def _wait_via_daemon(
    args: argparse.Namespace, inst: Any, state: dict[str, Any], *,
    start: float, deadline: float | None,
) -> Result:
    """Bare `wait` served by the daemon's event stream instead of a poll loop.

    Same verdicts and the same renderer as the standalone loop: the daemon
    returns WHEN the wait ended and what it observed; the crash report, the
    console tail and the guest axis are read here, from the log as it is
    now, exactly as the standalone path does after its loop. A `released`
    answer hands the rest of the wait to that loop (#118): the daemon no
    longer owns the VM, and this process must not hand it straight back.
    """
    warnings: list[str] = []
    try:
        reply = _daemon_wait_request(args, inst, warnings=warnings)
    except daemon_client.DaemonError as exc:
        raise QMPError(str(exc)) from exc
    except _WaitReleased as released:
        daemon_client.mark_released(inst.vm_id)
        warnings.append(released.note)
        return _wait_standalone(
            args, inst, start=start, deadline=deadline, warnings=warnings,
            last_event=released.last_event, event_data=released.event_data,
        )
    stopped = bool(reply.get("stopped"))
    reason = str(reply.get("reason", "timeout"))
    elapsed = float(reply.get("elapsed", 0.0))
    boot_offset = reply.get("boot_offset")
    if not isinstance(boot_offset, int):
        boot_offset = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    qemu_status = reply.get("qemu_status")
    qemu_status = qemu_status if isinstance(qemu_status, str) else "unknown"
    last_event = reply.get("last_event")
    event_data = reply.get("event_data")

    crash: str | None = None
    guest: str | None = None
    guest_detail: str | None = None
    if reason == _WAIT_REASON_TERMINAL_PANIC:
        guest = GUEST_PANICKED
        crash = _settled_crash(inst, boot_offset) or extract_crash(
            inst.serial_log, start_offset=boot_offset
        )
    if stopped:
        boot_offset = last_boot_offset(inst.serial_log, start_offset=boot_offset)
        crash = extract_crash(inst.serial_log, start_offset=boot_offset)
        guest = None
    elif guest is None:
        probe = _probe_from_daemon({**state, **{
            k: reply[k]
            for k in ("running", "qemu_status", "qmp_busy", "boot_offset") if k in reply
        }})
        observation = _observe_guest(inst, qmp=probe)
        guest = observation.guest
        guest_detail = observation.detail()
    return _finish_wait(
        args, inst,
        stopped=stopped, reason=reason, elapsed=elapsed, guest=guest,
        guest_detail=guest_detail, crash=crash, qmp_state=QMP_DAEMON,
        qemu_status=qemu_status, last_event=last_event, event_data=event_data,
        console_tail=_console_tail(inst.serial_log, boot_offset),
        warnings=warnings,
    )


# How many console lines a bare `wait` hands back with its verdict. A harness
# prints its marker and powers off; without this the only evidence of a
# successful run was a log that the harness auto-clean had already removed.
_CONSOLE_TAIL_LINES = 20


def _console_tail(log_path: str | None, start: int) -> list[str]:
    """The last `_CONSOLE_TAIL_LINES` lines of the current boot's console."""
    if not log_path:
        return []
    try:
        with Path(log_path).open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            stream.seek(start if 0 <= start <= size else 0)
            text = stream.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = [line.rstrip("\r") for line in text.splitlines()]
    while lines and not lines[-1].strip():
        lines.pop()
    return lines[-_CONSOLE_TAIL_LINES:]


def _wait_already_stopped(args: argparse.Namespace, inst: Any) -> Result:
    """Bare `wait --vm X` on a VM whose process exited before the wait began.

    The retained log is scanned from its last boot, like every other reader.
    The harness auto-clean is honoured only once the recorded pid is positively
    gone — a stopped record never names a live process, but the rule that
    identity death must be proven before metadata is removed stays uniform.
    """
    scope = current_boot_offset(inst.serial_log, inst.guest_epoch_serial_offset)
    crash = extract_crash(inst.serial_log, start_offset=scope)
    return _finish_wait(
        args, inst,
        stopped=True, reason=_WAIT_REASON_ALREADY_STOPPED, elapsed=0.0,
        guest=None, guest_detail=None, crash=crash, qmp_state=None,
        qemu_status="unknown", last_event=None, event_data=None,
        console_tail=_console_tail(inst.serial_log, scope),
    )


def _finish_wait(
    args: argparse.Namespace,
    inst: Any,
    *,
    stopped: bool,
    reason: str,
    elapsed: float,
    guest: str | None,
    guest_detail: str | None,
    crash: str | None,
    qmp_state: str | None,
    qemu_status: str,
    last_event: str | None,
    event_data: Any,
    console_tail: list[str],
    warnings: Sequence[str] = (),
) -> Result:
    """Render one bare-`wait` outcome and map it to the exit code.

    0 — the recorded process is gone (now, or before the wait began).
    3 — the guest took a terminal panic while its QEMU process lives on.
    124 — the deadline passed with the process alive and the guest not gone.
    """
    # Operator typos are still worth a line here; the profile bucket is never
    # printed by any command.
    _unknown_params = _warn_unknown_kernel_params(inst)

    cleaned = False
    if stopped and inst.harness and not args.no_clean and not instance_alive(inst):
        # Identity death is proven. Remove owned state directly; do not pass a
        # potentially recycled PID to _kill_vm's pid-only signaling.
        remove_instance(inst.vm_id)
        cleaned = True

    result = {
        "ok": stopped,
        "vm_id": inst.vm_id,
        "stopped": stopped,
        "reason": reason,
        # None once QEMU has exited: there is no guest to classify, and
        # `unknown` read as a probe that failed.
        "guest": guest,
        "guest_detail": guest_detail,
        "elapsed": round(elapsed, 3),
        "qmp": qmp_state,
        "qemu_status": qemu_status,
        "last_event": last_event,
        "event_data": event_data,
        "crash": crash,
        "console_tail": console_tail,
        "cleaned": cleaned,
        "unknown_kernel_params": _unknown_params["all"],
        "unknown_kernel_params_by_source": {
            "operator": _unknown_params["operator"],
            "profile": _unknown_params["profile"],
        },
    }

    if reason == _WAIT_REASON_TERMINAL_PANIC:
        lines = [
            f"VM '{inst.vm_id}' guest PANICKED ({reason}, elapsed={elapsed:.2f}s); "
            f"its QEMU process is still running.",
            f"Reap it with `qmu kill --vm {inst.vm_id}` — the crash report is "
            f"preserved for `qmu crash --vm {inst.vm_id}`.",
        ]
    elif reason == _WAIT_REASON_ALREADY_STOPPED:
        lines = [
            f"VM '{inst.vm_id}' stopped ({reason}, elapsed={elapsed:.2f}s): it "
            f"had exited before this wait began; its retained log was scanned."
        ]
    else:
        lines = [
            f"VM '{inst.vm_id}' {'stopped' if stopped else 'still running'} "
            f"({reason}, elapsed={elapsed:.2f}s)"
        ]
    if guest is not None:
        lines.append(f"Guest: {guest}" + (f" ({guest_detail})" if guest_detail else ""))
    observation_suffix = "" if stopped else " (QEMU process still running)"
    if qmp_state == QMP_BUSY and not stopped:
        lines.append(
            "QMP: busy (held by another client — another qmu command such as "
            "`wait`/`status`, or a debugger bridge), so QEMU's status was not "
            "observed."
        )
    if last_event is not None:
        lines.append(f"Observed QMP event {last_event}{observation_suffix}.")
    if qemu_status not in {"unknown", "running"}:
        lines.append(f"Observed QEMU status {qemu_status}{observation_suffix}.")
    if crash:
        lines.append("\nCrash from serial log:\n" + crash)
    elif stopped and console_tail:
        # The run's own evidence. A harness prints its marker and powers off;
        # the auto-clean below may remove the log this came from.
        lines.append("Console tail:")
        lines.extend(f"  {line}" for line in console_tail)
    if cleaned:
        lines.append("[qmu] Instance metadata cleaned up.")
    if stopped:
        exit_code = 0
    elif reason == _WAIT_REASON_TERMINAL_PANIC:
        exit_code = 3
        result["hint"] = f"Guest PANICKED: qmu crash --vm {inst.vm_id}; then qmu kill --vm {inst.vm_id}"
    else:
        exit_code = 124
        result["hint"] = (
            "VM still running after --timeout; raise --timeout, or check "
            f"qmu status --vm {inst.vm_id}; qmu log --vm {inst.vm_id} --tail 50"
        )
    return Result(data=result, text=lines, stem="wait", exit_code=exit_code).warn(*warnings)


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


def _wait_for_pattern(args: argparse.Namespace) -> Result:
    """Block until a regex matches a serial console line.

    This replaces the `until grep -q ... serial.log; do sleep 2; done` shell
    loop, and fixes its two failure modes: such a loop hangs forever when the
    guest panics before printing the expected marker, and it hangs forever
    when the VM dies. Both terminate here with a distinguishable exit code.
    """
    # A short-lived probe can exit before the caller starts waiting. Explicit
    # selection may inspect its retained evidence; implicit selection remains
    # running-only so an old stopped VM cannot silently satisfy a new wait.
    inst = None
    if args.vm:
        info = classify_vm(args.vm, orphan_pids=_orphan_serial_logs())
        if info["state"] in (VM_RUNNING, VM_STOPPED, VM_HELD_BACK):
            inst = info["instance"]
    if inst is None:
        _require_running(args.vm, "wait")
        inst = choose_instance(args.vm)

    try:
        matcher = re.compile(args.pattern)
    except re.error as exc:
        raise QMUError(f"Invalid --pattern regex {args.pattern!r}: {exc}") from exc

    start = time.monotonic()
    deadline = start + args.timeout if args.timeout is not None else None
    # Use the recorded RESET boundary and the log's latest boot banner. A
    # guest-initiated reboot can occur while no qmu command is observing QMP
    # — unless the daemon watches the VM, whose observed epoch then anchors
    # the scope. The chosen boundary is reported back (`scan_offset`/
    # `scan_scope`) so a marker that fell outside it is never a silent miss:
    # a `dmesg` replay echoed to the console reproduces the banner and moves
    # this boundary.
    daemon = _daemon_state(inst)
    epoch_offset = inst.guest_epoch_serial_offset or 0
    if daemon is not None and isinstance(daemon.get("epoch_offset"), int):
        epoch_offset = daemon["epoch_offset"]
    banner_offset = last_boot_offset(inst.serial_log, start_offset=epoch_offset)
    start_offset = max(epoch_offset, banner_offset)
    scan_scope = "boot-banner" if banner_offset > epoch_offset else "epoch"

    if daemon is not None:
        return _pattern_wait_via_daemon(
            args, inst, matcher, start=start, deadline=deadline,
            start_offset=start_offset, scan_scope=scan_scope,
        )
    return _pattern_wait_standalone(
        args, inst, matcher, start=start, deadline=deadline,
        start_offset=start_offset, scan_scope=scan_scope,
    )


def _pattern_wait_standalone(
    args: argparse.Namespace,
    inst: Any,
    matcher: re.Pattern[str],
    *,
    start: float,
    deadline: float | None,
    start_offset: int,
    scan_scope: str,
    warnings: Sequence[str] = (),
) -> Result:
    """The poll loop over the serial log: one `scan_for_pattern` step and one
    PID-liveness check per tick, until a match, a terminal panic, the process
    exits, or `deadline` passes.

    Also the continuation of a daemon-backed wait whose subscription the
    daemon ended (`released`, #118): the scan restarts at `start_offset` —
    every line before the daemon's cursor had already failed to match, so
    the verdict is the same — and `start`/`deadline` are the original wait's.
    """
    tail = SerialTail(inst.serial_log, offset=start_offset)
    matched_line: str | None = None
    reason = "timeout"
    crash: str | None = None
    saw_dead = False
    terminal_panic_seen = False

    while True:
        try:
            scan = scan_for_pattern(
                tail, matcher, final=saw_dead, stop_at_panic=not args.ignore_crash
            )
        except OSError as exc:
            return _pattern_inconclusive(args, inst, exc)
        if scan.terminal_panic:
            terminal_panic_seen = True
        if scan.matched_line is not None:
            matched_line = scan.matched_line
            reason = "pattern_matched"
            break

        if terminal_panic_seen and not args.ignore_crash:
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

        if saw_dead:
            reason = "process_exited"
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

    return _finish_pattern_wait(
        args, inst,
        matched_line=matched_line, reason=reason, crash=crash,
        terminal_panic_seen=terminal_panic_seen, start_offset=start_offset,
        scan_scope=scan_scope, elapsed=time.monotonic() - start,
        warnings=warnings,
    )


def _pattern_inconclusive(args: argparse.Namespace, inst: Any, exc: BaseException) -> Result:
    """The serial log could not be read: infra class (4), never "no match".

    Evidence that cannot be read is NOT a negative result. Exit 1 is "the
    marker did not appear"; an agent branching on it would record a missing
    log as a failed experiment. The envelope says so.
    """
    message = (
        f"Cannot inspect serial log for '{inst.vm_id}': {exc}. "
        "Pattern result is inconclusive."
    )
    return Result(
        data={
            "ok": False,
            "error": message,
            "error_type": type(exc).__name__,
            "inconclusive": True,
            "vm_id": inst.vm_id,
            "pattern": args.pattern,
            "serial_log": inst.serial_log,
        },
        text=[message],
        stem="wait",
        exit_code=4,
        refusal=True,
    )


def _pattern_wait_via_daemon(
    args: argparse.Namespace,
    inst: Any,
    matcher: re.Pattern[str],
    *,
    start: float,
    deadline: float | None,
    start_offset: int,
    scan_scope: str,
) -> Result:
    """`wait --pattern` served by the daemon: it runs the same per-tick scan
    (`serial.scan_for_pattern`) woken by its 100 ms serial tick, and this
    process blocks on the socket until the verdict. The crash report is read
    here afterwards, exactly as the standalone loop reads it. A `released`
    answer hands the rest of the wait to that loop (#118)."""
    try:
        reply = _daemon_wait_request(args, inst, pattern=args.pattern, start_offset=start_offset)
    except daemon_client.DaemonError as exc:
        if exc.fields.get("inconclusive"):
            return _pattern_inconclusive(args, inst, OSError(str(exc)))
        raise QMPError(str(exc)) from exc
    except _WaitReleased as released:
        daemon_client.mark_released(inst.vm_id)
        return _pattern_wait_standalone(
            args, inst, matcher, start=start, deadline=deadline,
            start_offset=start_offset, scan_scope=scan_scope, warnings=(released.note,),
        )
    matched_line = reply.get("matched_line")
    matched_line = matched_line if isinstance(matched_line, str) else None
    reason = str(reply.get("reason", "timeout"))
    terminal_panic_seen = bool(reply.get("terminal_panic_seen"))
    crash: str | None = None
    if reason == "crash":
        crash = _settled_crash(inst, start_offset) or extract_crash(
            inst.serial_log, start_offset=start_offset
        )
    elif reason == "process_exited":
        crash = extract_crash(inst.serial_log, start_offset=start_offset)
    return _finish_pattern_wait(
        args, inst,
        matched_line=matched_line, reason=reason, crash=crash,
        terminal_panic_seen=terminal_panic_seen, start_offset=start_offset,
        scan_scope=scan_scope, elapsed=float(reply.get("elapsed", 0.0)),
    )


def _finish_pattern_wait(
    args: argparse.Namespace,
    inst: Any,
    *,
    matched_line: str | None,
    reason: str,
    crash: str | None,
    terminal_panic_seen: bool,
    start_offset: int,
    scan_scope: str,
    elapsed: float,
    warnings: Sequence[str] = (),
) -> Result:
    """Render one `--pattern` outcome: 0 match, 3 terminal panic, 1 exit
    without a match, 124 timeout."""
    matched = matched_line is not None
    _unknown_params = _warn_unknown_kernel_params(inst)
    result = {
        "ok": matched,
        "vm_id": inst.vm_id,
        "matched": matched,
        "pattern": args.pattern,
        "matched_line": matched_line,
        "reason": reason,
        "scan_offset": start_offset,
        "scan_scope": scan_scope,
        "elapsed": round(elapsed, 3),
        "crash": crash,
        "unknown_kernel_params": _unknown_params["all"],
        "unknown_kernel_params_by_source": {
            "operator": _unknown_params["operator"],
            "profile": _unknown_params["profile"],
        },
    }

    scope_note = (
        f"scanned from byte {start_offset}: "
        + (
            "latest kernel boot banner"
            if scan_scope == "boot-banner"
            else "recorded guest epoch"
        )
        + "; earlier output was out of scope"
    )
    if matched:
        lines_out = [f"Matched /{args.pattern}/ after {elapsed:.2f}s:", matched_line or ""]
    elif reason == "crash":
        lines_out = [
            f"Kernel crash on '{inst.vm_id}' after {elapsed:.2f}s, "
            f"before /{args.pattern}/ matched ({scope_note}).",
        ]
    elif reason == "process_exited":
        lines_out = [
            f"VM '{inst.vm_id}' exited after {elapsed:.2f}s without matching "
            f"/{args.pattern}/ ({scope_note}).",
        ]
    else:
        lines_out = [
            f"Timed out after {elapsed:.2f}s waiting for /{args.pattern}/ "
            f"on '{inst.vm_id}' ({scope_note}).",
        ]
    if crash:
        lines_out.append("\nCrash from serial log:\n" + crash)
    vm, p = inst.vm_id, args.pattern
    if matched:
        exit_code = 0
    elif crash and terminal_panic_seen:
        exit_code = 3
        result["hint"] = (
            f"Guest panicked before /{p}/ matched; read it: qmu crash --vm {vm}; "
            f"then reap: qmu kill --vm {vm}"
        )
    elif reason == "process_exited":
        exit_code = 1
        result["hint"] = (
            f"QEMU exited before /{p}/ matched; read the retained log: "
            f"qmu log --vm {vm} --tail 100; then qmu prune --vm {vm}"
        )
    else:
        exit_code = 124
        result["hint"] = (
            f"Pattern /{p}/ did not appear within --timeout; raise --timeout, or "
            f"check qmu log --vm {vm} --tail 50 for the marker (scan started at "
            f"byte {start_offset})"
        )
    return Result(data=result, text=lines_out, stem="wait", exit_code=exit_code).warn(*warnings)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _add_list(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="List VMs (running and stopped)")
    _add_common_opts(p)
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.set_defaults(handler=_handle_list)


# Upper bound on concurrent per-VM probes in `list`. Each is one QMP round
# trip plus one ssh handshake; a busy host has tens of VMs, not thousands.
_LIST_MAX_PROBES = 16


def _probe_running(inst: Any) -> _GuestObservation:
    """Both axes for one running VM, with the SSH probe where it can matter.

    `list` used to probe every running VM's sshd in series — a full handshake
    each, 2–5 s per VM whose sshd is gone — so ten VMs cost 15–60 s per call,
    and an agent calls `list` between every step. `_observe_guest` reads the
    serial log and QMP first because they decide whether an ssh probe can tell
    us anything: a panicked guest has no sshd and a paused one cannot answer,
    so both can only time out to the `down` they would report anyway.
    """
    return _observe_guest(inst, probe_ssh=True)


def _probe_all_running(running: list[Any]) -> list[_GuestObservation]:
    """Probe every running VM concurrently; results keep `running`'s order."""
    if not running:
        return []
    workers = min(len(running), _LIST_MAX_PROBES)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_probe_running, running))


def _guest_note(obs: _GuestObservation) -> str | None:
    """The guest-axis clause `list` text appends to a live VM's row.

    Presenting a panicked, paused or unverified VM as a plain [running] is
    the flattening that made `list` and `status` contradict each other. An
    `unknown` names what was checked, so the reader knows which probe to
    believe rather than guessing between "still booting" and "never will".
    """
    if obs.guest == GUEST_PANICKED:
        return "GUEST PANICKED, run `qmu crash`"
    if obs.guest == GUEST_CRASHED:
        return "crash report waiting, run `qmu crash`"
    if obs.guest == GUEST_PAUSED:
        note = "vCPU paused, `qmu cont` resumes"
        if obs.crash_detected:
            note += ", crash report waiting, run `qmu crash`"
        return note
    if obs.guest == GUEST_UNKNOWN:
        return f"guest unknown ({obs.detail()})"
    return None


def _handle_list(args: argparse.Namespace) -> Result:
    # The project-config gate lives at the cli.main dispatch choke point, so
    # this handler is already running under a validated project config.
    running = list_instances()
    stopped = list_stopped_instances()
    if not running and not stopped:
        return Result(data={"ok": True, "vms": []}, text="No VMs.", stem="list")

    # Hoisted: _orphan_serial_logs() walks all of /proc, so calling it per
    # stopped VM made `list --format json` scan the process table N times.
    # Both branches must also read the SAME snapshot, or they can disagree
    # about who is orphaned.
    orphan_logs = _orphan_serial_logs()
    probes = _probe_all_running(running)

    # The one handler that forks on --format itself: the per-VM probes above
    # are shared, but the stopped-VM classification below is re-read per
    # row, so only the requested rendering is built.
    if args.format != "text":
        data = []
        for inst, obs in zip(running, probes):
            data.append({
                "vm_id": inst.vm_id,
                "status": "running",
                "guest": obs.guest,
                "guest_detail": obs.detail(),
                # "skipped" when the guest axis was decided without asking
                # QEMU (a terminal panic needs no second opinion): a null
                # read as "probe failed" and contradicted `status`.
                "qmp": obs.qmp_state or "skipped",
                # Same reading `status` reports: QEMU's run-state when the
                # shared probe connected, "unknown" when it was busy,
                # unreachable or skipped (#106).
                "qemu_status": obs.qmp.status if obs.qmp is not None else "unknown",
                "pid": inst.pid,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "ssh": "n/a (harness)" if inst.harness else obs.ssh_state(),
                "ssh_user": _ssh_user(inst),
                "forwards": inst.forwards,
                "ssh_ready": obs.ssh_ready,
                "ssh_probe_ms": obs.ssh_probe_ms,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel,
                "profile": inst.profile,
                "profile_applied": not inst.cmdline_override,
                "arch": inst.arch,
                "kvm": inst.kvm,
                "serial_log": inst.serial_log,
                "logs_retained": True,
                "crash_detected": obs.crash_detected,
                # Only when the daemon serves the VM (`qmp: "daemon"`): how
                # the boot scope was learned. Absent on the standalone path,
                # whose output shape is unchanged (#70).
                **({"guest_epoch_source": obs.epoch_source} if obs.epoch_source else {}),
            })
        for inst in stopped:
            orphan_pid = orphan_logs.get(inst.serial_log)
            retained = _retained_logs(inst)
            # `status` and `prune` call a young log-only remnant `held_back`;
            # `list` must not present the same artifacts as a plain `stopped`
            # — and must name the same refusal reason they do (#109).
            held = (
                {"held_reason": None, "held_path": None} if orphan_pid
                else classify_vm(inst.vm_id)
            )
            held_reason = held["held_reason"]
            held_back = held_reason is not None
            data.append({
                "vm_id": inst.vm_id,
                "status": "orphaned" if orphan_pid else "stopped",
                "guest": _guest_state(inst) if orphan_pid else None,
                "guest_detail": None,
                "qmp": "skipped",
                # A stopped record's pid is the dead process's; never present
                # it as if it were live.
                "pid": orphan_pid or None,
                "harness": inst.harness,
                "ssh_port": inst.ssh_port,
                "ssh": "n/a (harness)" if inst.harness else "skipped",
                "ssh_user": _ssh_user(inst),
                "forwards": inst.forwards,
                "ssh_ready": None,
                "gdb_port": inst.gdb_port,
                "kernel": inst.kernel or None,
                "profile": inst.profile or None,
                "profile_applied": not inst.cmdline_override,
                "arch": inst.arch,
                "kvm": inst.kvm,
                "serial_log": retained["serial_log"],
                "logs_retained": retained["logs_retained"],
                "crash_detected": retained["crash_detected"],
                "held_back": held_back,
                "held_reason": held_reason,
                "held_path": held["held_path"],
            })
        return Result(data={"ok": True, "vms": data}, text=None, stem="list")

    lines = []
    for inst, obs in zip(running, probes):
        if inst.harness:
            ssh_str = "harness"
        elif inst.ssh_port is None:
            ssh_str = "ssh=none"
        elif obs.debugger_attached:
            ssh_str = f"ssh={inst.ssh_port}(not probed: debugger attached)"
        elif obs.ssh_auth_failed:
            ssh_str = f"ssh={inst.ssh_port}(auth-failed as {inst.ssh_user})"
        else:
            ssh_str = f"ssh={inst.ssh_port}({'ok' if obs.ssh_ready else 'down'})"
        gdb_str = f" gdb={inst.gdb_port}" if inst.gdb_port else ""
        qmp_str = (
            f" qmp={obs.qmp_state}"
            if obs.qmp_state not in (None, QMP_CONNECTED, QMP_DAEMON)
            else ""
        )
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else ""
        # Report the guest axis alongside the existence axis.
        note = _guest_note(obs)
        state_str = f"[running — {note}]" if note else "[running]"
        lines.append(
            f"  {inst.vm_id}  pid={inst.pid}  {ssh_str}{gdb_str}{qmp_str}  "
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
        elif _retained_logs(inst)["crash_detected"]:
            # `kill` kept this report on purpose and said so; a bare
            # [stopped] here hid that from the one command that lists it.
            state = "[stopped — crash report retained]"
        else:
            info = classify_vm(inst.vm_id)
            if info["state"] == VM_HELD_BACK:
                hint = _held_hint(
                    inst.vm_id, info["held_reason"], info["held_path"],
                    older_than=86400.0,
                )
                state = f"[stopped — not prunable: {hint}]"
            else:
                state = "[stopped]"
        lines.append(f"  {inst.vm_id}  {profile_str}  {kernel_str}  {state}")
    return Result(data=None, text="VMs:\n" + "\n".join(lines), stem="list")


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
    """Reject a non-running VM with a description, never with "not found".

    The one refusal for every command that needs a live VM — exec/wait call
    it up front, the rest (`_choose_running` in guest/qmp_cmds) when their
    running-only lookup misses — so all of them say the same thing about the
    same remnant, and name it in `vm_id`.
    """
    if not vm_id:
        return
    explanation = describe_non_running(vm_id, command=command)
    if explanation is not None:
        raise QMUError(
            explanation,
            hint=f"qmu status --vm {vm_id} describes it; qmu launch --name {vm_id} --no-replace starts a fresh one",
            vm_id=vm_id,
        )


def _crash_warning(
    guest: str | None, vm_id: str, *, crash_detected: bool | None = None
) -> str:
    """The one sentence that tells the reader a report is waiting.

    Shared by `status` and `describe_non_running` so the tracked and orphaned
    paths cannot say different things about the same fact. `crash_detected`
    covers the guest states whose precedence beats `crashed` — a paused
    guest can still have a report in its log, and `crash` will find it.
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
    if crash_detected:
        return (
            " A crash report from the current boot is waiting in its log — "
            f"pull it with `qmu crash --vm {vm_id}`."
        )
    return ""


def describe_non_running(
    vm_id: str,
    older_than: float = 86400.0,
    *,
    command: str | None = None,
    info: dict[str, Any] | None = None,
) -> str | None:
    """Explain a vm_id that `list` displays but a running-only lookup misses.

    `status` is the natural next command after spotting something odd in
    `list`, so answering "not found" — while helpfully listing what IS running,
    implying the entry is bogus — is the worst possible response. Shared with
    `prune` so the two cannot drift apart again. `info` lets a caller that
    already classified the VM skip the second `/proc` walk.
    """
    if info is None:
        info = _classify(vm_id, older_than)
    state = info["state"]
    if state == VM_ORPHANED:
        lead = (
            f"VM '{vm_id}' is an orphaned remnant: its metadata is gone but its "
            f"QEMU process (pid {info['pid']}) is still running."
        )
        if command is not None:
            lead += f" `qmu {command}` needs a tracked VM, so it cannot act on it."
        lead += _crash_warning(info.get("guest"), vm_id)
        return (
            f"{lead} Reap it with `qmu kill --vm {vm_id}` or "
            f"`qmu prune --orphans`. Serial log: {info['serial_log']}"
        )
    if state in (VM_STOPPED, VM_HELD_BACK):
        verb = (
            f"`qmu {command}` needs a running VM"
            if command is not None
            else "there is no live state to report"
        )
        retained = _retained_logs(info["instance"])
        if state == VM_HELD_BACK:
            remove = "Not prunable as-is: " + _held_hint(
                vm_id, info["held_reason"], info["held_path"],
                older_than=older_than,
            ) + "."
        else:
            remove = f"Remove them with `qmu prune --vm {vm_id}`."
        if retained["logs_retained"]:
            return (
                f"VM '{vm_id}' is stopped; only its logs remain, so {verb}. "
                f"Read them with `qmu log --vm {vm_id}` or "
                f"`qmu crash --vm {vm_id}`. {remove} "
                f"Serial log: {retained['serial_log']}"
            )
        # A `.qemu.log`/`.qmp.sock`-only remnant (#104): no console to read,
        # but it is on disk and `prune` is the way to remove it.
        what = (
            f"QEMU log: {retained['qemu_log']}"
            if retained["qemu_log"]
            else "no logs"
        )
        return (
            f"VM '{vm_id}' is stopped; no serial log remains, so {verb}. "
            f"{remove} {what}"
        )
    return None


def _status_non_running(args: argparse.Namespace, info: dict[str, Any]) -> Result:
    """`status` on a VM `list` shows but no process serves: a description, not an error.

    A kill that kept its logs is the normal end of every exploit run, and
    the next command is `status`. Exit 1 there made the stopped state look
    like a failed lookup, so callers branched on it as "gone" — while `list`
    still showed the VM and `crash` could still read its report.
    """
    vm_id = args.vm
    state = info["state"]
    inst = info["instance"]
    retained = _retained_logs(inst)
    orphan_pid = info["pid"] if state == VM_ORPHANED else None
    data = {
        "ok": True,
        "vm_id": vm_id,
        "status": state,
        # The guest axis exists only while a process serves it; for an orphan
        # that process is alive, so `list` and `status` must carry the same word.
        "guest": info["guest"] if state == VM_ORPHANED else None,
        "pid": orphan_pid if orphan_pid is not None else (inst.pid or None),
        "pid_alive": orphan_pid is not None,
        "harness": inst.harness,
        "serial_log": retained["serial_log"],
        "qemu_log": retained["qemu_log"],
        "logs_retained": retained["logs_retained"],
        "crash_detected": retained["crash_detected"],
        # Why prune withholds it, or null. A malformed-metadata refusal must
        # never be presented as the age gate (#109).
        "held_reason": info.get("held_reason"),
        "held_path": info.get("held_path"),
    }
    held_hint = (
        _held_hint(
            vm_id, info["held_reason"], info["held_path"], older_than=86400.0
        )
        if state == VM_HELD_BACK
        else None
    )
    if state == VM_ORPHANED:
        text = describe_non_running(vm_id, info=info) or f"VM '{vm_id}' is orphaned."
    elif not retained["logs_retained"]:
        text = (
            f"VM '{vm_id}' is stopped (no serial log retained; QEMU log: "
            f"{retained['qemu_log']}; "
            + (
                f"not prunable as-is: {held_hint})" if held_hint
                else f"remove with: qmu prune --vm {vm_id})"
            )
            if retained["qemu_log"]
            else f"VM '{vm_id}' is stopped (no logs retained)"
        )
    elif retained["crash_detected"]:
        text = (
            f"VM '{vm_id}' is stopped (logs retained; crash report waiting: "
            f"qmu crash --vm {vm_id})"
        )
    else:
        text = (
            f"VM '{vm_id}' is stopped (logs retained: qmu log --vm {vm_id}; "
            + (
                f"not prunable as-is: {held_hint})" if held_hint
                else f"remove with: qmu prune --vm {vm_id})"
            )
        )
    return Result(data=data, text=text, stem="status")


def _handle_status(args: argparse.Namespace) -> Result:
    # Validation of the project/explicit config happens once, at the cli.main
    # dispatch gate (#37), so every sibling verb gives one answer about whether
    # the project is valid. status reads no boot settings from qmu.toml.
    if args.vm:
        info = _classify(args.vm)
        if info["state"] in (VM_STOPPED, VM_HELD_BACK, VM_ORPHANED):
            return _status_non_running(args, info)
    inst = choose_instance(args.vm)

    # One QMP round trip, shared with the guest axis: `status` used to connect
    # twice, so a socket held by a `wait` cost it 2 × 10 s and it still said
    # `qmp: connected`. The SSH probe is skipped when the guest cannot answer
    # (panicked, vCPU halted) — it could only time out to `down`.
    qmp = _query_qmp(inst)
    obs = _observe_guest(inst, qmp=qmp, probe_ssh=True)
    guest = obs.guest

    if inst.harness:
        ssh_state = "n/a (harness)"
    else:
        # "none" (--no-net, no --ssh-port) is a different fact from "down";
        # "skipped (debugger attached)" names why no probe was sent.
        ssh_state = obs.ssh_state()

    accel = {True: "kvm", False: "tcg"}.get(inst.kvm, "unknown")
    result = {
        "ok": True,
        "vm_id": inst.vm_id,
        # Both axes, matching `list`. status is the detailed per-VM command, so
        # it must not be the one that cannot answer what state the VM is in.
        "status": VM_RUNNING,
        "guest": guest,
        "pid": inst.pid,
        "harness": inst.harness,
        "arch": inst.arch,
        "kvm": inst.kvm,
        "qmp": qmp.state,
        "qmp_socket": inst.qmp_socket,
        "qemu_status": qmp.status,
        "guest_detail": obs.detail(),
        "ssh_port": inst.ssh_port,
        "ssh": ssh_state,
        # The account every SSH command logs in as, recorded at launch from
        # [ssh] user — the one fact an `auth-failed` reader needs (#158).
        "ssh_user": _ssh_user(inst),
        "ssh_probe_ms": obs.ssh_probe_ms,
        "forwards": inst.forwards,
        "gdb_port": inst.gdb_port,
        "kernel": inst.kernel,
        "rootfs": inst.rootfs,
        "memory": inst.memory,
        "cpus": inst.cpus,
        "profile": inst.profile,
        # False when a full cmdline override replaced the profile — the text
        # already says "(NOT applied — cmdline was overridden)"; JSON must too.
        "profile_applied": not inst.cmdline_override,
        "cmdline": inst.cmdline,
        "serial_log": inst.serial_log,
        "qemu_log": str(qemu_log_path(inst.vm_id)),
        "started_at": inst.started_at,
        # Evidence, not usability: what `qmu crash` would find in the current
        # boot. Carried on the running row too so `list`/`status`/`crash`
        # agree for a paused guest with a retained report (#93).
        "crash_detected": obs.crash_detected,
    }
    if obs.ssh_auth_failed:
        result["hint"] = _auth_refused_hint(inst)
    if obs.epoch_source and qmp.daemon is not None:
        # Daemon-served only: "observed" means a RESET was witnessed and the
        # scope is anchored on it; "banner" means the newest kernel boot
        # banner decided (standalone has nothing else and reports no key).
        result["guest_epoch_source"] = obs.epoch_source
        result["guest_epoch_serial_offset"] = qmp.daemon.get("epoch_offset")
        result["boot_offset"] = obs.scan_offset

    guest_line = guest if obs.detail() is None else f"{guest} ({obs.detail()})"
    lines = [
        f"VM '{inst.vm_id}'",
        f"  PID:       {inst.pid}",
        f"  Guest:     {guest_line}",
        f"  QMP:       {qmp.state}" + (
            f" (boot scope: {obs.epoch_source} epoch, byte {obs.scan_offset})"
            if obs.epoch_source else ""
        ),
        f"  QEMU:      {qmp.status}",
    ]
    if inst.harness:
        lines.append(f"  Mode:      harness")
        lines.append(f"  SSH:       n/a")
    elif inst.ssh_port is None:
        lines.append(f"  SSH:       none (--no-net, no --ssh-port)")
    elif obs.ssh_probed:
        lines.append(
            f"  SSH:       port {inst.ssh_port} ({ssh_state}, probe "
            f"{obs.ssh_probe_ms} ms)"
        )
    elif obs.debugger_attached:
        lines.append(
            f"  SSH:       port {inst.ssh_port} (not probed: debugger attached; "
            "a login would trip breakpoints)"
        )
    else:
        lines.append(
            f"  SSH:       port {inst.ssh_port} (not probed: guest {guest})"
        )
    if _ssh_user(inst) is not None:
        lines.append(f"  SSH user:  {inst.ssh_user}")
    if obs.ssh_auth_failed:
        lines.append(f"  Hint:      {_auth_refused_hint(inst)}")
    for forward in inst.forwards:
        lines.append(f"  Forward:   {forward_label(forward)}")
    if inst.gdb_port:
        lines.append(f"  GDB:       port {inst.gdb_port}")
    lines.extend([
        f"  Arch:      {inst.arch}",
        f"  Accel:     {accel}",
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
    notice = _crash_warning(guest, inst.vm_id, crash_detected=obs.crash_detected)
    if notice:
        lines.append(notice.strip())
    return Result(data=result, text=lines, stem="status")


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def _add_doctor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="Health check")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_doctor)


# doctor row taxonomy — one glyph per meaning, derived from `status` only:
#   ok   [+]  verified
#   fail [!]  gating: must be fixed; drives `ok: false` and exit 1
#   warn [~]  non-blocking: worth fixing, launch still works
#   info [i]  informational: nothing to fix (optional tooling, cache, skills)
# `blocking` is `status == "fail"`, nothing else, so a script that branches on
# the bool and a human reading the glyph reach the same verdict.
_DOCTOR_GLYPHS = {"ok": "+", "fail": "!", "warn": "~", "info": "i"}


def _doctor_row(
    check: str, status: str, detail: str, hint: str = "", **extra: Any
) -> dict[str, Any]:
    """One doctor check. `hint` is the fix as a command or config edit, kept
    out of the prose so a script can act on it without parsing `detail`; it is
    empty when there is nothing to fix. `extra` adds machine-readable
    companions to a row (e.g. the paths a summarised `detail` elides)."""
    assert status in _DOCTOR_GLYPHS, status
    return {
        "check": check,
        "status": status,
        "detail": detail,
        "blocking": status == "fail",
        "hint": hint,
        **extra,
    }


def _check_libguestfs() -> tuple[dict[str, Any], bool | None]:
    """The libguestfs doctor row, plus whether the appliance can run.

    Every failure here is a warning, never a blocker: libguestfs serves only
    `qmu rootfs *` and `launch --inject`, so a host where launch/exec/crash all
    work must not be red-lined by a 0600 /boot kernel. An unreadable kernel is
    only an input: a cached appliance runs without one (#146), so that case
    starts the appliance once and reports what actually happened. The second
    value is False when the appliance positively cannot run, else True (or
    None when the probe could not finish).
    """
    check = "libguestfs (rootfs inject / launch --inject)"
    fish = shutil.which("guestfish")
    if fish is None:
        return _doctor_row(
            check, "info",
            "guestfish not found in PATH — required only for "
            "`qmu rootfs *` and `qmu launch --inject`. "
            "Install libguestfs-tools.",
            hint="apt install libguestfs-tools",
        ), False

    # A fixed appliance (LIBGUESTFS_PATH) never runs supermin; an explicit
    # supermin kernel overrides the /boot lookup entirely.
    fixed = rootfs_mod.fixed_appliance()
    override = os.environ.get("SUPERMIN_KERNEL")
    problem = rootfs_mod.appliance_kernel_problem()
    if problem is None:
        if fixed:
            detail = f"{fish}; fixed appliance LIBGUESTFS_PATH={fixed}"
        else:
            detail = f"{fish}; SUPERMIN_KERNEL={override}" if override else fish
        return _doctor_row(check, "ok", detail), True
    hint = (
        "export SUPERMIN_KERNEL=<readable kernel image>" if override
        else rootfs_mod.SUPERMIN_ENV_HINT
    )

    runs, why = rootfs_mod.probe_appliance(fish)
    cache = rootfs_mod.appliance_cache_dir()
    if runs:
        detail = (
            f"{fish}; the appliance runs from its cache in {cache}, but "
            f"{problem}, so supermin cannot rebuild it: once the cache goes "
            f"stale (a host package update) or under another TMPDIR/"
            f"LIBGUESTFS_CACHEDIR, `qmu rootfs *` and `launch --inject` fail. "
            f"Point SUPERMIN_KERNEL at a readable kernel to make it durable."
        )
    elif runs is False:
        detail = (
            f"{fish}; {problem}, and the appliance does not start "
            f"(`guestfish -a /dev/null run`: {why}) with no usable cached "
            f"appliance in {cache}, so `qmu rootfs *` and `launch --inject` "
            f"fail until supermin can read a kernel."
        )
    else:
        detail = f"{fish}; {problem}, and the appliance probe did not finish ({why})."
    return _doctor_row(check, "warn", detail, hint=hint), runs


def _check_rootfs_sshd_policy(rootfs: str, appliance_runs: bool | None) -> dict[str, Any]:
    """Can a key other than the image's own log in as root?

    Images `tools/mkrootfs.sh` built before #68 accept root with ANY key —
    the contributing cause of the cross-VM exec P0. That is measured, not
    inferred from a missing stamp (#145): root's shadow entry and the sshd
    config are read with both qmu stamps in one read-only guestfish session.
    `warn`, never `fail`: launch works, the image is merely permissive. An
    image with no qmu stamp and no open path is `info` — nothing is claimed
    about the keys its sshd accepts.
    """
    check = "rootfs sshd policy"
    if appliance_runs is False:
        return _doctor_row(
            check, "info",
            "not checked (libguestfs cannot run its appliance here — see "
            "the libguestfs row)",
            sshd_policy=None,
        )
    try:
        evidence = rootfs_mod.read_sshd_evidence(rootfs)
    except QMUError as exc:
        reason = str(exc).splitlines()[0]
        return _doctor_row(
            check, "info", f"not checked ({reason})", sshd_policy=None,
        )
    rootfs_policy = _stamp_field(evidence.rootfs_stamp, "sshd_policy")
    open_path, why = rootfs_mod.root_login_without_key(evidence)
    if open_path:
        relaxed = _stamp_field(evidence.target_stamp, "hardening") == "relaxed"
        rebuild = (
            "rebuild the target with tools/mktarget.sh"
            + (" --relax-hardening" if relaxed else "")
            + " (same --kernel-abi/--arch)"
            if evidence.target_stamp is not None
            else "rebuild the image with tools/mkrootfs.sh --no-cache "
                 "(another image: lock root's password in it)"
        )
        return _doctor_row(
            check, "warn",
            f"permissive — {why}, so sshd accepts root with ANY key (or none)",
            hint=rebuild, sshd_policy="permissive",
        )
    if rootfs_policy == "key-only":
        return _doctor_row(check, "ok", "key-only", sshd_policy="key-only")
    if evidence.target_stamp is not None:
        return _doctor_row(
            check, "ok",
            f"key-only (tools/mktarget.sh target, {rootfs_mod.TARGET_STAMP_PATH})",
            sshd_policy="key-only",
        )
    if evidence.rootfs_stamp is not None:
        stamp = f"{rootfs_mod.STAMP_PATH} records sshd_policy={rootfs_policy!r}"
    else:
        stamp = f"no qmu stamp ({rootfs_mod.STAMP_PATH}, {rootfs_mod.TARGET_STAMP_PATH})"
    checked = why if open_path is False else f"empty-password login not checked: {why}"
    return _doctor_row(
        check, "info", f"unknown — {stamp}; {checked}", sshd_policy="unknown",
    )


def _stamp_field(stamp: str | None, key: str) -> Any:
    """One field of a JSON stamp, None when absent or unparseable."""
    if stamp is None:
        return None
    try:
        return json.loads(stamp).get(key)
    except (ValueError, AttributeError):
        return None


def _check_cross_toolchain(arch: str) -> list[dict[str, Any]]:
    """Rows for a guest arch that is not the host's: the cross compiler
    `compile --host` would pick and `gdb-multiarch` for pry. Both are `warn`
    when missing — launch/exec work without them — naming the apt package.
    """
    rows: list[dict[str, Any]] = []
    target = normalize_arch(arch)
    candidates = candidate_compilers(arch)
    found = next((shutil.which(c[0]) for c in candidates if shutil.which(c[0])), None)
    check = f"cross compiler for {target} (compile --host)"
    if found is not None:
        rows.append(_doctor_row(check, "ok", found))
    else:
        tried = ", ".join(" ".join(c) for c in candidates) or "(none known)"
        pkg = cross_package(arch)
        rows.append(_doctor_row(
            check, "warn",
            f"not found in PATH (tried: {tried}); `qmu compile --host` "
            f"will fail — compile in the guest, or install it"
            + (f": apt install {pkg}" if pkg else "")
            + ". Override with --cc <compiler>.",
            hint=f"apt install {pkg}" if pkg else "qmu compile --cc <cross compiler>",
        ))
    gdb = shutil.which("gdb-multiarch")
    rows.append(_doctor_row(
        "gdb-multiarch (qmu gdb / pry on a foreign arch)",
        "ok" if gdb else "warn",
        gdb or f"not found in PATH; the host `gdb` cannot debug {target} "
               f"guests. Install it: apt install gdb-multiarch",
        hint="" if gdb else "apt install gdb-multiarch",
    ))
    return rows


def _unconfigured_detail(key: str, flag: str, status: str) -> str:
    text = f"not configured — set {key} in qmu.toml or pass {flag}"
    if status == "fail":
        return text + " (a flagless launch will fail without one)"
    return text + "; not needed for --harness boots"


def _path_hint(key: str, flag: str) -> str:
    """The fix for a missing or unconfigured path field, as a config edit."""
    return f"set {key} in qmu.toml or pass {flag}"


def _ssh_key_permissions_row(written: str, key_path: Path) -> dict[str, Any]:
    """Classify the private key's mode the way OpenSSH will, not by a 0600 ideal.

    `sshkey_perm_ok` refuses a key the caller owns whose group/other bits are
    set — `UNPROTECTED PRIVATE KEY FILE … This private key will be ignored` —
    and that refusal is local and deterministic, so no rootfs can make such
    a key usable: a `fail` (#94). A key the caller cannot read fails for the
    same reason. A key that is merely stricter than 0600 (0400, 0700, or one
    owned by another user, which OpenSSH does not police) works and is `ok`;
    the old row warned on every non-0600 mode and let the unusable case pass
    as non-blocking.
    """
    try:
        st = key_path.stat()
    except OSError as exc:
        return _doctor_row(
            "SSH key permissions", "fail", f"cannot stat: {exc}",
            hint=f"chmod 600 {written}",
        )
    mode = oct(st.st_mode)[-3:]
    if not os.access(key_path, os.R_OK):
        return _doctor_row(
            "SSH key permissions", "fail",
            f"mode={mode} is not readable by you, so ssh cannot load the key",
            hint=f"chmod 600 {written}",
        )
    if st.st_uid == os.getuid() and st.st_mode & 0o077:
        return _doctor_row(
            "SSH key permissions", "fail",
            f"mode={mode} is group/other-accessible — OpenSSH refuses it "
            f"(UNPROTECTED PRIVATE KEY FILE) and every ssh/scp will be denied "
            f"until `chmod 600 {written}`",
            hint=f"chmod 600 {written}",
        )
    return _doctor_row("SSH key permissions", "ok", f"mode={mode}")


# The starter file's `# CHANGE ME` values, as written. A configured path that
# still reads one of these was never edited, and the row says so instead of
# leaving the reader to guess why a file they never created is missing.
_STARTER_PLACEHOLDERS = {
    "kernel": "./bzImage",
    "rootfs": "./rootfs.img",
    "ssh_key": "~/.ssh/qmu_id_rsa",
}


def _missing_path_detail(config: Any, field_name: str) -> str:
    """`<as written> (…not found) — resolves to <abs> [<layer>]` for a
    configured path that does not exist."""
    written = config.written_path(field_name)
    value = getattr(config, field_name)
    note = "CHANGE ME placeholder; " if written == _STARTER_PLACEHOLDERS.get(field_name) else ""
    text = f"{written} ({note}not found)"
    resolved = str(Path(value).expanduser())
    if resolved != written:
        text += f" — resolves to {resolved}"
    return f"{text} [{config.source_layer(field_name)}]"


def _handle_doctor(args: argparse.Namespace) -> Result:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )
    checks: list[dict[str, Any]] = []

    # Config sources — distinguish "loaded a file" from "defaults only", and
    # both of those from "a file was found and REJECTED". resolve_config skips
    # an invalid global with a stderr warning; reporting "No qmu.toml or
    # <global> found. Run: qmu config init" for it contradicted that warning
    # in the same breath and prescribed writing a PROJECT file, which leaves
    # the broken global in place forever. doctor is exempt from the #37
    # dispatch gate because it diagnoses the project layer itself — that
    # justification only holds if it diagnoses the global layer too, which is
    # the layer that is deliberately non-fatal. A rejected file is `fail`:
    # the user's own file is invalid and every command re-warns about it, so
    # leaving it is never the right outcome.
    file_sources = [s for s in config._sources if s.startswith(("global:", "project:", "config:"))]
    project_sources = [s for s in file_sources if not s.startswith("global:")]
    skipped_sources = config._skipped_sources
    if file_sources:
        checks.append(_doctor_row("config", "ok", " -> ".join(config._sources)))
    elif skipped_sources:
        checks.append(_doctor_row(
            "config", "warn",
            "Running on built-in defaults only: every config file "
            "found was rejected (see below).",
            hint="fix or delete the rejected file(s) named below",
        ))
    else:
        checks.append(_doctor_row(
            "config", "warn",
            f"No qmu.toml or {global_config_path()} found. Run: qmu config init",
            hint="qmu config init",
        ))
    for skipped in skipped_sources:
        checks.append(_doctor_row(
            f"{skipped['kind']} config", "fail",
            f"{skipped['path']} EXISTS but is invalid and was skipped: "
            f"{skipped['problem']}. Fix or delete that file — "
            f"`qmu config init` writes a project qmu.toml and will not "
            f"clear this.",
            hint=f"fix or delete {skipped['path']}",
        ))

    # Cache subtrees no qmu command fully reclaims. Informational, never a
    # warning: the subtrees legitimately exist on every machine that has ever
    # built a kernel and there is nothing to "fix". Cheap is_dir() probes only.
    unmanaged_names = unmanaged_subtree_names()
    if unmanaged_names:
        checks.append(_doctor_row(
            "cache", "info",
            ", ".join(f"{n}/" for n in unmanaged_names)
            + " are not reclaimed by `qmu prune --vm/--all`. Size them with "
              "`qmu cache du`; reclaim kernel build residue with "
              "`qmu prune --build-residue --dry-run`.",
        ))

    # QEMU binary (arch-aware). For configured passt, derive the reported path
    # from the same result used for the native-backend capability check.
    binary = config.qemu_binary()
    passt_required = config.net_backend == "passt"
    qemu_caps = probe_qemu_netdevs(binary) if passt_required else None
    qemu = qemu_caps.path if qemu_caps is not None else shutil.which(binary)
    checks.append(_doctor_row(
        binary, "ok" if qemu else "fail",
        qemu or f"Not found in PATH (install the QEMU system emulator for {config.arch})",
        hint="" if qemu else f"install {binary} (the QEMU system emulator for {config.arch})",
    ))

    if not passt_required:
        checks.append(_doctor_row(
            "QEMU native passt (-netdev passt)", "info",
            "Not required for configured net_backend=user.",
        ))
    else:
        assert qemu_caps is not None
        passt_problem = native_passt_problem(qemu_caps)
        checks.append(_doctor_row(
            "QEMU native passt (-netdev passt)",
            "ok" if passt_problem is None else "fail",
            f"{qemu_caps.path} advertises native '-netdev passt'"
            if passt_problem is None
            else passt_problem,
            hint="" if passt_problem is None else
                 "set [machine] net_backend = \"user\" or install a QEMU built with -netdev passt",
        ))

    # Cross toolchain: only meaningful when the configured guest arch is not
    # the host's. `compile --host` and `qmu gdb` pick these by guest arch.
    if normalize_arch(config.arch) != host_arch():
        checks.extend(_check_cross_toolchain(config.arch))

    # Kernel. doctor went green on a starter qmu.toml whose `kernel =` line was
    # still commented out, and the very next `launch` failed on it. A missing
    # configured file blocks (launch would fail identically); "not configured"
    # only warns, because --harness and --kernel launches still work. The
    # starter's live `kernel = "./bzImage"  # CHANGE ME` line lands here
    # until edited, and is named as the placeholder it is.
    kernel_configured = bool(config.kernel)
    if kernel_configured:
        if Path(config.kernel).expanduser().is_file():
            checks.append(_doctor_row("kernel", "ok", config.kernel))
        else:
            checks.append(_doctor_row(
                "kernel", "fail",
                _missing_path_detail(config, "kernel")
                + "; set [boot] kernel in qmu.toml or pass --kernel — launch "
                  "will fail with `Kernel not found`.",
                hint=_path_hint("[boot] kernel", "--kernel"),
            ))
    else:
        checks.append(_doctor_row(
            "kernel", "warn",
            "not configured (set [boot] kernel or pass --kernel; "
            "--harness/launch flags still work)",
            hint=_path_hint("[boot] kernel", "--kernel"),
        ))

    # Initrd (#75): same shape as the kernel row. A configured file that is
    # missing blocks — launch fails on it identically — while "not configured"
    # is merely informational: most rootfs boots have none.
    if config.initrd:
        if Path(config.initrd).expanduser().is_file():
            checks.append(_doctor_row("initrd", "ok", config.initrd))
        else:
            checks.append(_doctor_row(
                "initrd", "fail",
                _missing_path_detail(config, "initrd")
                + "; set [boot] initrd in qmu.toml or pass --initrd — launch "
                  "will fail with `Initrd not found`.",
                hint=_path_hint("[boot] initrd", "--initrd"),
            ))
    else:
        checks.append(_doctor_row(
            "initrd", "info", "not configured (optional; set [boot] initrd or pass --initrd)",
        ))

    # Rootfs and SSH key. "Not configured" gates only when a flagless
    # `qmu launch` would actually fail on it: [boot] kernel is set and the
    # boot is not harness-shaped. A kernel with an initrd and no rootfs is the
    # kernelCTF/syzkaller shape launched with --harness, which needs neither;
    # red-lining every such project would make doctor permanently useless
    # for it. With no kernel configured the launch needs flags anyway, so
    # these are hints, not failures.
    harness_shaped = config.initrd is not None and config.rootfs is None
    unconfigured = "fail" if kernel_configured and not harness_shaped else "warn"
    rootfs_hint = _path_hint("[drive] rootfs", "--rootfs")
    if config.rootfs:
        if Path(config.rootfs).expanduser().exists():
            checks.append(_doctor_row("rootfs image", "ok", config.rootfs))
        else:
            checks.append(_doctor_row(
                "rootfs image", "fail", _missing_path_detail(config, "rootfs"),
                hint=rootfs_hint,
            ))
    else:
        checks.append(_doctor_row(
            "rootfs image", unconfigured,
            _unconfigured_detail("[drive] rootfs", "--rootfs", unconfigured),
            hint=rootfs_hint,
        ))

    key_hint = _path_hint("[ssh] key", "--ssh-key")
    if config.ssh_key:
        key_path = Path(config.ssh_key).expanduser()
        if key_path.exists():
            checks.append(_doctor_row("SSH key", "ok", config.ssh_key))
            checks.append(_ssh_key_permissions_row(config.ssh_key, key_path))
        else:
            checks.append(_doctor_row(
                "SSH key", "fail", _missing_path_detail(config, "ssh_key"),
                hint=key_hint,
            ))
    else:
        checks.append(_doctor_row(
            "SSH key", unconfigured,
            _unconfigured_detail("[ssh] key", "--ssh-key", unconfigured),
            hint=key_hint,
        ))

    # KVM. Distinguish "explicitly disabled" (accel=tcg / --no-kvm) from
    # "unavailable" so a deliberate TCG choice — e.g. to make gdbstub hardware
    # watchpoints deliver (#39) — is not misreported as a missing capability.
    if config.use_kvm():
        if config.accel == "kvm" and not Path("/dev/kvm").exists():
            # accel=kvm forces -enable-kvm unconditionally; if /dev/kvm is
            # absent the launch will fail, so doctor must flag it rather than
            # report a green "forced" it cannot back up.
            checks.append(_doctor_row(
                "KVM", "fail",
                "accel=kvm forces -enable-kvm but /dev/kvm is missing; "
                "launch will fail. Use accel=auto/tcg or --no-kvm.",
                hint="set [machine] accel = \"auto\" (or \"tcg\") in qmu.toml, or pass --no-kvm",
            ))
        else:
            checks.append(_doctor_row(
                "KVM", "ok",
                "KVM acceleration forced (accel=kvm)"
                if config.accel == "kvm"
                else "KVM acceleration available",
            ))
    elif config.accel == "tcg":
        checks.append(_doctor_row(
            "KVM", "info", "Disabled by accel=tcg (--no-kvm); using TCG emulation",
        ))
    else:
        checks.append(_doctor_row(
            "KVM", "info", f"Not available for arch={config.arch} (will use TCG)",
        ))

    # libguestfs (required by `rootfs *` and `launch --inject`). Both the
    # binary and its appliance are checked: guestfish is routinely on PATH
    # while the appliance cannot build, because Debian/Ubuntu ship
    # /boot/vmlinuz-* mode 0600 and the build runs unprivileged. Reporting only
    # "guestfish: found" sends the reader off to debug an opaque supermin
    # failure instead.
    libguestfs_row, appliance_runs = _check_libguestfs()
    checks.append(libguestfs_row)

    # Rootfs sshd policy (#75): only an image that exists can be opened, and
    # a missing one already has its `[!] rootfs image` row above.
    if config.rootfs and Path(config.rootfs).expanduser().exists():
        checks.append(_check_rootfs_sshd_policy(
            str(Path(config.rootfs).expanduser()), appliance_runs,
        ))

    # pry (optional — only needed for `qmu gdb`)
    pry = shutil.which("pry")
    checks.append(_doctor_row(
        "pry (GDB integration)", "ok" if pry else "info",
        pry or "Not found in PATH — required only for `qmu gdb`. "
               "Install pry and ensure it is on PATH.",
        hint="" if pry else "install pry and put it on PATH",
    ))

    # External passt executable (required only when net_backend = "passt")
    passt = shutil.which("passt")
    checks.append(_doctor_row(
        "passt (net_backend=passt)",
        ("ok" if passt else "fail") if passt_required else "info",
        passt or (
            "Not found in PATH — REQUIRED because net_backend=passt. "
            "Install passt (e.g. 'pacman -S passt' / 'apt install passt')."
            if passt_required else
            "Not found — not required for configured net_backend=user."
        ),
        hint="apt install passt" if passt_required and not passt else "",
    ))

    # Running VMs: the same enumeration `list` makes — live records plus
    # qmu-launched QEMUs no live record claims — so the two never disagree
    # about how many VMs are up. Counting records alone reported 0 while
    # `list` was showing an orphaned VM as running. The cache dir is named
    # so a QMU_CACHE_DIR mismatch between shells is visible in the row.
    instances = list_instances()
    orphans = find_orphan_qemus()
    vm_detail = f"{len(instances)} running"
    if orphans:
        vm_detail += f" + {len(orphans)} orphaned (no instance record)"
    vm_detail += f" under {instances_dir()}"
    checks.append(_doctor_row(
        "running VMs", "info", vm_detail,
        hint="qmu prune --orphans --dry-run" if orphans else "",
        running=len(instances), orphaned=len(orphans),
    ))

    # The daemon (#70) — informational: it autostarts on demand, so "not
    # running" is the normal idle state, not a fault. `doctor` never spawns
    # it. `unavailable` (a record names a dead pid, or a socket that will
    # not answer) is the one case worth a glance at daemon.log.
    probe = daemon_client.probe()
    if probe["running"]:
        stale = "" if probe.get("build_current", True) else " (stale build; respawns on next command)"
        daemon_detail = (
            f"running (pid {probe['pid']}, watching {len(probe['vms'])} VM(s), "
            f"idle exit {probe['idle_exit']:g}s){stale}"
        )
        daemon_status = "ok"
    elif probe["mode"] == daemon_client.MODE_OFF:
        daemon_detail = "disabled (QMU_DAEMON=off); every command takes the standalone QMP path"
        daemon_status = "info"
    elif str(probe["reason"]).startswith(("stale", "unresponsive")):
        daemon_detail = f"unavailable: {probe['reason']}; see {daemon_client.log_path()}"
        daemon_status = "warn"
    else:
        daemon_detail = "not running (autostarts on the next VM command; `qmu daemon start` to pre-start)"
        daemon_status = "info"
    checks.append(_doctor_row(
        "daemon", daemon_status, daemon_detail,
        hint="qmu daemon status" if daemon_status == "warn" else "",
        running=probe["running"], mode=probe["mode"],
    ))

    # Skills installed — informational: a missing skill symlink changes what
    # an agent knows, not whether a VM boots. JSON `detail` keeps the full
    # path list (consumers do not pay for length) and `detail_paths` the
    # structured form; the TEXT row renders `summary` instead, because
    # 5 skills × 3 roots ≈ 900 chars dominated every doctor run.
    sources = {d.name: d for d in all_skill_source_dirs()}
    skill_names = list(sources) or ["qmu"]
    roots = skill_install_roots()
    installed: list[Path] = []
    missing: list[Path] = []
    stale: list[Path] = []
    for name in skill_names:
        for root in roots:
            p = root / name
            if not p.exists():
                missing.append(p)
                continue
            installed.append(p)
            src = sources.get(name)
            if src is not None and p.is_symlink() and p.resolve() != src.resolve():
                stale.append(p)
    paths = {
        "installed": [str(p) for p in installed],
        "missing": [str(p) for p in missing],
        "stale": [str(p) for p in stale],
    }
    summary = f"{len(skill_names)} skills × {len(roots)} roots"
    if not installed:
        checks.append(_doctor_row(
            "skills", "info", "not installed. Run: qmu skill install",
            hint="qmu skill install", detail_paths=paths,
            summary=f"{summary}: not installed. Run: qmu skill install",
        ))
    elif missing or stale:
        problems = [f"{len(missing)} missing"] if missing else []
        if stale:
            problems.append(f"{len(stale)} stale (linked to another checkout)")
        counts = f"{len(installed)} installed, {', '.join(problems)}"
        checks.append(_doctor_row(
            "skills", "warn", f"partial: {counts} (run: qmu skill install)",
            hint="qmu skill install", detail_paths=paths,
            summary=f"{summary}: {counts} (run: qmu skill install)",
        ))
    else:
        checks.append(_doctor_row(
            "skills", "ok", ", ".join(paths["installed"]),
            detail_paths=paths, summary=f"{summary} installed",
        ))

    all_ok = not any(c["blocking"] for c in checks)
    lines = ["qmu doctor:"]
    for c in checks:
        shown = c.get("summary", c["detail"])
        lines.append(f"  [{_DOCTOR_GLYPHS[c['status']]}] {c['check']}: {shown}")
    # The starter-file tip only when no project/--config layer applied: with
    # one loaded, `config init` would just refuse to overwrite it.
    if not project_sources:
        lines.append("")
        lines.append("Tip: run `qmu config init` to create a starter qmu.toml in this directory.")
    data: dict[str, Any] = {"ok": all_ok, "checks": checks}
    if not all_ok:
        # The envelope's own recovery (#120): name the failing rows and point
        # at their per-row `hint`s, which are the actual fixes. Never a bare
        # "run qmu doctor" — this IS doctor.
        failing = [c for c in checks if c["blocking"]]
        fixes = "; ".join(f"{c['check']}: {c['hint']}" for c in failing if c["hint"])
        data["hint"] = (
            f"Fix the [!] row(s): {', '.join(c['check'] for c in failing)}"
            + (f" — {fixes}" if fixes else "")
            + ". Each failing row in `checks[]` carries its own `hint`; "
            "re-run qmu doctor until exit 0"
        )
    return Result(
        data=data,
        text=lines,
        stem="doctor",
        exit_code=0 if all_ok else 1,
    )
