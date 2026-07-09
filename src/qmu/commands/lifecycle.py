"""VM lifecycle commands: launch, kill, prune, wait, list, status, doctor.

These manage the QEMU process and its instance metadata. Shared helpers come
from :mod:`.._cliutil`.

The patchable collaborators (``choose_instance``, ``_qmp_ctx``, ``is_pid_alive``,
``extract_crash``) are imported directly into this module's namespace. The test
suite drives the production seams via ``monkeypatch.setattr(lifecycle, ...)``
(e.g. ``lifecycle.choose_instance`` / ``lifecycle._qmp_ctx`` /
``lifecycle.is_pid_alive``); the patches take effect because the handlers read
these names from this module at call time.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from ..config import resolve_config
from ..instance import (
    QMUError,
    choose_instance,
    instance_alive,
    is_pid_alive,
    list_instances,
    list_stopped_instances,
    load_instance,
    remove_instance,
)
from ..paths import (
    all_skill_source_dirs,
    claude_skills_dir,
    codex_home,
    codex_skills_dir,
)
from ..qemu import native_passt_problem, probe_qemu_netdevs
from ..qmp import QMPError
from ..serial import extract_crash
from ..vm import launch_vm
from .._cliutil import (
    _add_common_opts,
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
    p.add_argument("--kernel", required=True, help="Path to bzImage")
    p.add_argument("--config", default=None, help="Path to qmu.toml config file")
    p.add_argument("--rootfs", default=None, help="Path to rootfs image (overrides config)")
    p.add_argument("--ssh-key", default=None, dest="ssh_key", help="SSH private key (overrides config)")
    p.add_argument("--arch", default=None, help="Architecture (overrides config, e.g. x86_64, aarch64)")
    p.add_argument("--memory", default=None, help="VM memory (overrides config)")
    p.add_argument("--cpus", type=int, default=None, help="VM CPU count (overrides config)")
    p.add_argument("--cpu", default=None, dest="cpu_model",
                   help="QEMU -cpu model, e.g. 'host', 'max', 'qemu64' (overrides config)")
    p.add_argument("--profile", default="exploit-dev", help="Boot profile (default: exploit-dev)")
    p.add_argument("--cmdline", default=None, help="Override kernel command line")
    p.add_argument("--gdb", action="store_true", help="Enable GDB stub")
    p.add_argument("--name", default=None, help="VM instance name")
    p.add_argument("--no-replace", action="store_true",
                   help="Don't kill existing VM with same name (default: replace)")
    p.add_argument("--ssh-port", type=int, default=None, help="SSH port (auto-allocated)")
    p.add_argument("--gdb-port", type=int, default=None, help="GDB port (auto-allocated)")
    p.add_argument("--ssh-timeout", type=int, default=60, help="SSH wait timeout in seconds")
    p.add_argument("--no-wait-ssh", action="store_true", help="Don't wait for SSH to be ready")
    p.add_argument("--initrd", default=None, help="Path to initramfs/initrd image")
    p.add_argument("--drive", action="append", dest="drives", default=None,
                   help="QEMU -drive spec, repeatable (suppresses implicit rootfs drive)")
    p.add_argument("--nic-model", default=None, dest="nic_model",
                   help="NIC model (default: virtio-net-pci)")
    p.add_argument("--no-net", action="store_true",
                   help="Disable networking entirely (-nic none)")
    p.add_argument("--net-backend", default=None, dest="net_backend",
                   choices=["user", "passt"],
                   help="Network backend: 'user' (slirp, default) or 'passt' "
                        "(rootless + migratable, so snapshots work). Overrides config.")
    p.add_argument("--harness", action="store_true",
                   help="Harness/judge VM mode: implies --no-wait-ssh + --no-net; "
                        "skips rootfs/ssh-key requirement")
    p.add_argument("extra", nargs="*", help="Extra QEMU arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_launch)


def _handle_launch(args: argparse.Namespace) -> int:
    config = _resolve_config_from_args(args)

    # Harness mode bundles --no-wait-ssh + --no-net
    if args.harness:
        args.no_wait_ssh = True
        args.no_net = True

    # Replace existing VM with the same name (default behavior)
    if args.name and not args.no_replace:
        existing = load_instance(args.name)
        if existing is not None and instance_alive(existing):
            sys.stderr.write(f"[qmu] Replacing existing VM '{args.name}' (pid={existing.pid})\n")
            _kill_vm(existing)
        elif existing is not None:
            # Stale metadata from dead process — just clean up
            remove_instance(existing.vm_id)

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
    lines.append(f"  Profile: {inst.profile}")
    lines.append(f"  Serial:  {inst.serial_log}")
    _emit(args, data=result, text=lines, stem="launch")
    return 0


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


def _handle_kill(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
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
    return 0


# ---------------------------------------------------------------------------
# prune
# ---------------------------------------------------------------------------


def _add_prune(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("prune", help="Remove state files for stopped VMs")
    g = p.add_mutually_exclusive_group()
    # SUPPRESS (like _add_common_opts) so a top-level `--vm X` given before the
    # subcommand is not clobbered by this subparser's own default.
    g.add_argument("--vm", default=argparse.SUPPRESS, help="Prune a specific stopped VM")
    g.add_argument("--all", dest="prune_all", action="store_true",
                   help="Prune every stopped VM")
    p.add_argument("--keep-logs", action="store_true",
                   help="Drop .json + .qmp.sock but preserve .serial.log")
    # _add_common_opts adds --vm too; we declared --vm above so add the rest manually.
    p.add_argument("--format", choices=["text", "json", "ndjson"], default="text")
    p.add_argument("--out", default=None, help="Write output to file instead of stdout")
    p.set_defaults(handler=_handle_prune)


def _handle_prune(args: argparse.Namespace) -> int:
    stopped = list_stopped_instances()
    running = list_instances()
    running_ids = {inst.vm_id for inst in running}

    # SUPPRESS default (fix #2) means the attribute may be absent when --vm is
    # not given after the subcommand; the top-level parser default of None
    # guarantees it otherwise exists.
    vm = getattr(args, "vm", None)
    if vm is not None:
        if vm in running_ids:
            raise QMUError(
                f"VM '{vm}' is running. Use 'qmu kill --vm {vm}' first."
            )
        target = next((inst for inst in stopped if inst.vm_id == vm), None)
        if target is None:
            raise QMUError(f"No stopped VM named '{vm}'.")
        targets = [target]
    elif args.prune_all:
        targets = stopped
    else:
        raise QMUError("Specify either --vm <name> or --all.")

    pruned: list[str] = []
    for inst in targets:
        remove_instance(inst.vm_id, keep_logs=args.keep_logs)
        pruned.append(inst.vm_id)

    if not pruned:
        text = "No stopped VMs to prune."
    else:
        verb = "kept logs for" if args.keep_logs else "removed"
        text = f"Pruned {len(pruned)} VM(s) ({verb}): {', '.join(pruned)}"
    _emit(
        args,
        data={"ok": True, "pruned": pruned, "keep_logs": args.keep_logs},
        text=text,
        stem="prune",
    )
    return 0


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


_STOP_EVENTS = {"STOP", "SHUTDOWN", "POWERDOWN", "RESET"}


def _add_wait(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("wait", help="Block until a VM stops (harness/judge mode)")
    p.add_argument("--timeout", type=float, default=None,
                   help="Max seconds to wait (default: no timeout)")
    p.add_argument("--no-clean", action="store_true",
                   help="Don't remove instance metadata after stop (harness VMs only)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_wait)


def _handle_wait(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)

    start = time.monotonic()
    # `is not None` so --timeout 0 means "check once, then time out immediately"
    # rather than being treated as "no timeout".
    deadline: float | None = (start + args.timeout) if args.timeout is not None else None
    reason = "unknown"
    qemu_status = "unknown"
    event_data: Any = None
    stopped = False

    try:
        with _qmp_ctx(inst) as qmp:
            # Short-circuit: query current state first.
            try:
                status = qmp.execute("query-status")
                if isinstance(status, dict):
                    qemu_status = status.get("status", "unknown")
                    if qemu_status in ("paused", "shutdown", "postmigrate", "guest-panicked"):
                        reason = qemu_status
                        stopped = True
            except (QMPError, OSError):
                pass

            # Loop in 1s ticks: wait for an event OR notice the PID died.
            while not stopped:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    tick = min(1.0, remaining)
                else:
                    tick = 1.0

                ev = qmp.wait_event(_STOP_EVENTS, timeout=tick)
                if ev is not None:
                    reason = ev.get("event", "stopped")
                    event_data = ev.get("data")
                    stopped = True
                    break

                if not is_pid_alive(inst.pid):
                    reason = "process_exited"
                    stopped = True
                    break
    except (QMPError, OSError) as exc:
        # If the QMP socket disappeared, the VM almost certainly stopped.
        if not is_pid_alive(inst.pid):
            stopped = True
            reason = "process_exited"
        else:
            raise QMUError(f"QMP error during wait: {exc}") from exc

    elapsed = time.monotonic() - start
    crash = extract_crash(inst.serial_log) if stopped else None

    result = {
        # ok mirrors success: True when the VM actually stopped, False on the
        # timeout result object (exit 124).
        "ok": stopped,
        "vm_id": inst.vm_id,
        "stopped": stopped,
        "reason": reason,
        "elapsed": round(elapsed, 3),
        "event_data": event_data,
        "crash": crash,
    }

    # Auto-clean harness VMs unless --no-clean.
    cleaned = False
    if stopped and inst.harness and not args.no_clean:
        try:
            _kill_vm(inst, force=False)
            cleaned = True
        except QMUError:
            pass
    result["cleaned"] = cleaned

    lines = [
        f"VM '{inst.vm_id}' {'stopped' if stopped else 'still running'} "
        f"({reason}, elapsed={elapsed:.2f}s)"
    ]
    if crash:
        lines.append("\nCrash from serial log:\n" + crash)
    if cleaned:
        lines.append("[qmu] Instance metadata cleaned up.")
    _emit(args, data=result, text=lines, stem="wait")

    if not stopped:
        return 124  # timeout
    return 0


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _add_list(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="List VMs (running and stopped)")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_list)


def _handle_list(args: argparse.Namespace) -> int:
    running = list_instances()
    stopped = list_stopped_instances()
    if not running and not stopped:
        _emit(args, data={"ok": True, "vms": []}, text="No VMs.", stem="list")
        return 0

    if args.format != "text":
        data = []
        for inst in running:
            entry: dict[str, Any] = {
                "vm_id": inst.vm_id,
                "status": "running",
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
            data.append({
                "vm_id": inst.vm_id,
                "status": "stopped",
                "pid": inst.pid or None,
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

    lines = []
    for inst in running:
        if inst.harness or inst.ssh_port is None:
            ssh_str = "harness"
        else:
            ssh_ok = _make_ssh(inst).is_ready()
            ssh_str = f"ssh={inst.ssh_port}({'ok' if ssh_ok else 'down'})"
        gdb_str = f" gdb={inst.gdb_port}" if inst.gdb_port else ""
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else ""
        lines.append(
            f"  {inst.vm_id}  pid={inst.pid}  {ssh_str}{gdb_str}  "
            f"profile={inst.profile}  {kernel_str}  [running]"
        )
    for inst in stopped:
        kernel_str = f"kernel={Path(inst.kernel).name}" if inst.kernel else "kernel=?"
        profile_str = f"profile={inst.profile}" if inst.profile else "profile=?"
        lines.append(f"  {inst.vm_id}  {profile_str}  {kernel_str}  [stopped]")
    _output("VMs:\n" + "\n".join(lines), args, stem="list")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _add_status(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("status", help="Detailed VM status")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_status)


def _handle_status(args: argparse.Namespace) -> int:
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

    result = {
        "ok": True,
        "vm_id": inst.vm_id,
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
        f"  Profile:   {inst.profile}",
        f"  Cmdline:   {inst.cmdline}",
        f"  Serial:    {inst.serial_log}",
        f"  Started:   {inst.started_at}",
    ])
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


def _handle_doctor(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = resolve_config(
        config_path_override=Path(config_path) if config_path else None,
    )
    checks: list[dict[str, Any]] = []

    # Config sources — distinguish "loaded a file" from "defaults only"
    file_sources = [s for s in config._sources if s.startswith(("global:", "project:", "config:"))]
    if file_sources:
        checks.append({
            "check": "config",
            "status": "ok",
            "detail": " -> ".join(config._sources),
        })
    else:
        checks.append({
            "check": "config",
            "status": "warn",
            "detail": "No qmu.toml or ~/.config/qmu/config.toml found. Run: qmu config init",
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

    # KVM
    if config.use_kvm():
        checks.append({
            "check": "KVM",
            "status": "ok",
            "detail": "KVM acceleration available",
        })
    else:
        checks.append({
            "check": "KVM",
            "status": "info",
            "detail": f"Not available for arch={config.arch} (will use TCG)",
        })

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
