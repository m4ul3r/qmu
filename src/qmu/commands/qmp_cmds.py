"""QMP / debugger commands: gdb, cont, qmp (raw), monitor (HMP), snapshot.

Everything here drives the VM through its QMP socket (or, for gdb, the pry
subprocess against the GDB stub). Shared helpers come from :mod:`.._cliutil`;
this module imports no other ``commands.*`` module and never imports ``cli``.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from ..instance import (
    QMUError,
    VMInstance,
    choose_instance,
    proc_pid_start,
    save_guest_epoch_serial_offset,
    save_instance,
)
from ..snapshot import (
    SnapshotResult,
    delete_snapshot,
    list_snapshots,
    load_snapshot,
    loadvm_restore_state,
    save_snapshot,
)
from ..serial import serial_log_offset
from ..qmp import QMPCommandError, hmp_failed
from ..debug import (
    bridge_alive,
    debug_session_present,
    debug_stub_present,
    gdb_client_attached,
    kvm_watchpoint_warning,
    loadvm_stale_session_warning,
    reap_bridge,
    reset_dropped_breakpoints_warning,
    savevm_breakpoint_warning,
)
from .._cliutil import (
    _add_common_opts,
    _emit,
    _emit_refusal,
    _make_group_help_handler,
    _make_ssh,
    _preflight_ssh_guest,
    _require_ssh,
    _qmp_ctx,
    _stopped_guest_payload,
)


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def _add_snapshot(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("snapshot", help="VM snapshot management")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="snapshot_cmd")

    s = sp.add_parser("save", help="Save a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_save)

    s = sp.add_parser("load", help="Load a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_load)

    s = sp.add_parser("list", help="List snapshots")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_list)

    s = sp.add_parser("delete", help="Delete a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_delete)


def _snapshot_failed(msg: str) -> bool:
    """HMP text classifier for the raw savevm/loadvm routes (and `cli`, which
    re-exports this name). The markers live in :func:`qmp.hmp_failed` so the
    snapshot handlers, `qmu monitor` and `qmu qmp human-monitor-command` all
    agree on what an HMP failure looks like."""
    return hmp_failed(msg)


def _drop_ssh_master(inst: VMInstance) -> None:
    """Close the guest's multiplexed SSH ControlMaster, if any.

    `snapshot load` and `system_reset` replace the guest's TCP state under a
    master connection that outlives the command which opened it
    (`ControlPersist=60`). The next SSH command then reuses the dead master
    and stalls for the whole keepalive window (ServerAliveInterval 5 x
    CountMax 3 = 15 s) before `Broken pipe` — which made the documented
    rewind loop's first `exec` slower than a full relaunch (snapshot audit
    #3, contract #1). Closing before AND after the mutation guarantees no
    master straddles it. Best-effort and silent: harness VMs have no SSH.
    """
    if inst.ssh_port is None:
        return
    _make_ssh(inst).close_control_master()


_SNAPSHOT_ERROR_TYPE = "SnapshotError"


def _snapshot_failure_hint(name: str, vm_id: str, reason: str | None) -> str:
    """The machine-readable fix for a failed snapshot op (envelope `hint`).

    The skill's exit-code table tells agents to "read the `hint`" on exit 1,
    and `SnapshotError` was the one error envelope without one: a typo'd tag
    said only `does not exist in one or more devices` (HMP wording) and left
    the reader to guess that `qmu snapshot list` is the next command.
    """
    if reason == "missing":
        return (
            f"Snapshot '{name}' is not in the image of VM '{vm_id}'. "
            f"List what exists: qmu snapshot list --vm {vm_id}"
        )
    if reason == "bad_name":
        return (
            "HMP parses the snapshot name as one token: it cannot contain "
            f"whitespace. Use e.g. '{'-'.join(name.split())}'."
        )
    return (
        f"Inspect the image's snapshot table with: qmu monitor "
        f"'info snapshots' --vm {vm_id}"
    )


def _inconsistent_restore_hint(vm_id: str, result: SnapshotResult) -> str:
    """The recovery for a load that failed after restoration began.

    `qmu cont` is deliberately NOT offered: `loadvm` reverts the disks before
    it loads the vmstate, so after this failure the paused machine is
    pre-snapshot RAM/devices over post-snapshot disks. The way back to a
    coherent guest is another (compatible) snapshot or a relaunch.
    """
    how_far = (
        "after restoration began (restore_state: partial)"
        if result.restore_state == "partial"
        else "at a point qmu cannot place (restore_state: unknown)"
    )
    state = (
        "qmu left the guest paused"
        if result.guest_paused
        else "the guest is not paused, but its state is still suspect"
    )
    return (
        f"loadvm failed {how_far}: the machine may be inconsistent (disks "
        f"rewound, device state not), so {state}. Recover with a known-good "
        f"snapshot: qmu snapshot load <tag> --vm {vm_id}, or relaunch: "
        f"qmu kill --vm {vm_id} and qmu launch. Do not resume it blindly "
        f"with qmu cont --vm {vm_id}."
    )


def _emit_snapshot_result(
    args: argparse.Namespace,
    op: str,
    inst: VMInstance,
    result: SnapshotResult,
) -> int:
    """Render one snapshot outcome. A failure carries `error` + `error_type`
    like every other error envelope (not a bare `message`) plus a `hint`
    naming the fix, and in text mode goes to stderr under the `[qmu] Error:`
    prefix the skill promises, so an `eval "$(...)"`-style consumer never
    executes prose."""
    stem = f"snapshot-{op}"
    if result.ok:
        data: dict[str, object] = {"ok": True, "name": args.name, "message": result.message}
        text = result.message
        if op == "load":
            # A load that recovered a guest left stopped by a previous failed
            # restore (`restore-vm`) resumed it; QEMU alone would not have.
            data["resumed"] = result.resumed
            if result.resumed:
                text = f"{text} Guest resumed (it was stopped by a previous failed load)."
        _emit(args, data=data, text=text, stem=stem)
        return 0
    error = f"snapshot {op} failed: {result.message}"
    hint = _snapshot_failure_hint(args.name, inst.vm_id, result.reason)
    notes: list[str] = []
    if op == "load":
        if result.restore_state in ("partial", "unknown"):
            # The machine, not the pause, is the urgent fact: QEMU reverts
            # the disks before it loads the vmstate, so a load that failed
            # here left pre-snapshot devices over post-snapshot disks. qmu
            # leaves it paused on purpose; `cont` would run that (#87).
            hint = _inconsistent_restore_hint(inst.vm_id, result)
        elif result.resumed:
            notes.append(
                "loadvm paused the guest before failing; qmu resumed it "
                "(resumed: true)."
            )
        elif result.guest_paused:
            # The stuck pause is the more urgent fix; it leads the hint.
            hint = (
                "loadvm left the guest paused and qmu could not resume it. "
                f"Resume with: qmu cont --vm {inst.vm_id}. Then: {hint}"
            )
    data = {
        "ok": False,
        "error": error,
        "error_type": _SNAPSHOT_ERROR_TYPE,
        "name": args.name,
        "hint": hint,
    }
    if op == "load":
        data["resumed"] = result.resumed
        data["guest_paused"] = result.guest_paused
        data["restore_state"] = result.restore_state
    if getattr(args, "format", "text") == "text":
        sys.stderr.write(f"[qmu] Error: {error}\n")
        for note in notes:
            sys.stderr.write(f"[qmu] {note}\n")
        sys.stderr.write(f"[qmu] {hint}\n")
    else:
        _emit(args, data=data, text=error, stem=stem)
    return 1


def _handle_snapshot_save(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    # A master alive at savevm time is frozen into the image as an established
    # guest sshd session that every later load resurrects as an orphan; close
    # it first so the checkpoint carries no half-open connection.
    _drop_ssh_master(inst)
    with _qmp_ctx(inst) as qmp:
        result = save_snapshot(qmp, args.name)
    rc = _emit_snapshot_result(args, "save", inst, result)
    if rc != 0:
        if result.reason != "bad_name":
            sys.stderr.write(
                "[qmu] qmu's implicit rootfs uses a temporary snapshot=on overlay; "
                "that overlay can hold in-session checkpoints with a raw or qcow2 base, "
                "and those checkpoints disappear when QEMU exits. For durable internal "
                "snapshots, attach a writable qcow2 drive without snapshot=on, for example "
                "`--drive 'file=./rootfs.qcow2,format=qcow2'`. Changing [drive] format "
                "alone remains temporary because qmu still adds snapshot=on.\n"
            )
        return rc
    # #45: a snapshot of a debugged guest freezes any armed software-breakpoint
    # int3s into the image, so a later `snapshot load` + run Oopses at the
    # breakpointed address and reads as the PoC crashing the kernel. Warn only
    # on a successful save (a failed one wrote no image). Gate on the STUB, not
    # a live client: the int3 bytes are baked into the image and survive an
    # uncleanly-detached bridge (the #40 case), so requiring a live client would
    # suppress the very save where the risk is highest.
    if debug_stub_present(inst):
        sys.stderr.write(savevm_breakpoint_warning(inst.vm_id) + "\n")
    return 0


def _snapshot_load_mentions_slirp(msg: str) -> bool:
    return "slirp" in msg.lower()


def _handle_snapshot_load(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    epoch_offset = serial_log_offset(inst.serial_log)
    _drop_ssh_master(inst)
    with _qmp_ctx(inst) as qmp:
        result = load_snapshot(qmp, args.name)
    if result.ok:
        inst = save_guest_epoch_serial_offset(inst, epoch_offset)
        _drop_ssh_master(inst)
    rc = _emit_snapshot_result(args, "load", inst, result)
    if rc != 0:
        if _snapshot_load_mentions_slirp(result.message):
            sys.stderr.write(
                "[qmu] This loadvm error names slirp. The user backend often works for "
                "in-session restore, but this QEMU/build/device combination could not "
                "restore its network state. Use native passt networking only with a selected "
                "QEMU that advertises native '-netdev passt' (documented since QEMU 10.1 but "
                "may be build-optional), or use a manually managed external passt process "
                "with QEMU's stream backend. qmu does not manage that external process.\n"
            )
        # A load that got as far as reverting the disks also reset the
        # machine (`qemu_system_reset(SHUTDOWN_CAUSE_SNAPSHOT_LOAD)` precedes
        # the vmstate load), so the #44 divergence applies to it as well.
        if result.restore_state != "none" and debug_session_present(inst):
            sys.stderr.write(loadvm_stale_session_warning(inst.vm_id) + "\n")
        return rc
    # #44: loadvm rewound the guest, but an attached debugger keeps its pre-load
    # vCPU state and never re-syncs — a silent divergence in the rewind-iterate
    # fast path. A pre-restore refusal (`restore_state: none`) did not rewind.
    if debug_session_present(inst):
        sys.stderr.write(loadvm_stale_session_warning(inst.vm_id) + "\n")
    return 0


def _handle_snapshot_list(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        snaps = list_snapshots(qmp)
    if not snaps:
        text: str | list[str] = "No snapshots."
    else:
        lines = ["Snapshots:"]
        for s in snaps:
            lines.append(f"  {s['id']}  {s['tag']}  size={s['vm_size']}  {s['date']} {s['time']}")
        text = lines
    _emit(args, data={"ok": True, "snapshots": snaps}, text=text, stem="snapshot-list")
    return 0


def _handle_snapshot_delete(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        result = delete_snapshot(qmp, args.name)
    return _emit_snapshot_result(args, "delete", inst, result)


# ---------------------------------------------------------------------------
# gdb
# ---------------------------------------------------------------------------


def _parse_nm_text(stdout: str) -> int:
    addresses: list[int] = []
    for line in stdout.splitlines():
        fields = line.split()
        if not fields or fields[0] != "_text":
            continue
        if len(fields) < 3:
            raise QMUError("local symbol tool returned malformed _text output")
        try:
            addresses.append(int(fields[2], 16))
        except ValueError as exc:
            raise QMUError(
                f"local symbol tool returned invalid _text address: {fields[2]!r}"
            ) from exc
    if not addresses:
        raise QMUError("local vmlinux is missing _text")
    if len(addresses) != 1:
        raise QMUError("local vmlinux contains multiple _text symbols")
    if addresses[0] == 0:
        raise QMUError("local vmlinux has a zero _text address")
    return addresses[0]


def _parse_kallsyms_text(stdout: str) -> int:
    addresses: list[int] = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] != "_text":
            continue
        try:
            addresses.append(int(fields[0], 16))
        except ValueError as exc:
            raise QMUError(
                f"guest returned invalid _text address: {fields[0]!r}"
            ) from exc
    if not addresses:
        raise QMUError("guest /proc/kallsyms is missing _text")
    if len(addresses) != 1:
        raise QMUError("guest /proc/kallsyms contains multiple _text symbols")
    if addresses[0] == 0:
        raise QMUError(
            "guest has restricted /proc/kallsyms: _text address is zero; "
            "use a root SSH user or set kernel.kptr_restrict=0"
        )
    return addresses[0]


def _format_hex(value: int) -> str:
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


_KBASE_ARCHES = frozenset({"x86_64", "i386", "aarch64", "arm"})
_KALLSYMS_QUERY = "awk '$3 == \"_text\" { print $1, $2, $3 }' /proc/kallsyms"


def _read_link_text(symbols: str) -> tuple[Path, int]:
    path = Path(symbols).expanduser().resolve()
    if not path.is_file():
        raise QMUError(f"vmlinux symbols file not found: {path}")

    tool = shutil.which("nm") or shutil.which("llvm-nm")
    if tool is None:
        raise QMUError(
            "no local symbol tool found; install GNU nm (binutils) or llvm-nm"
        )

    result = subprocess.run(
        [tool, "-P", "--defined-only", str(path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout or "no diagnostic").strip()
        raise QMUError(
            f"{Path(tool).name} failed to read {path} "
            f"(exit {result.returncode}): {diagnostic}"
        )
    return path, _parse_nm_text(result.stdout)


def _add_kbase(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "kbase",
        help="Read the guest runtime kernel base and KASLR slide",
    )
    p.add_argument(
        "--symbols",
        required=True,
        help="Path to the matching vmlinux ELF",
    )
    _add_common_opts(p)
    p.set_defaults(handler=_handle_kbase)


def _handle_kbase(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    _require_ssh(inst)

    if (preflight_rc := _preflight_ssh_guest(
        args, inst, stem="kbase"
    )) is not None:
        return preflight_rc

    if inst.arch is None:
        raise QMUError(
            f"VM '{inst.vm_id}' predates architecture metadata; relaunch it "
            "before using qmu kbase"
        )
    if inst.arch not in _KBASE_ARCHES:
        raise QMUError(
            f"qmu kbase does not support guest architecture {inst.arch!r}; "
            f"supported: {', '.join(sorted(_KBASE_ARCHES))}"
        )

    symbols_path, link_base = _read_link_text(args.symbols)
    ssh = _make_ssh(inst)
    rc, stdout, stderr = ssh.run(_KALLSYMS_QUERY, timeout=10.0)
    if rc != 0:
        diagnostic = (stderr or stdout or "no diagnostic").strip()
        raise QMUError(
            f"failed to read guest /proc/kallsyms (exit {rc}): {diagnostic}"
        )

    runtime_base = _parse_kallsyms_text(stdout)
    slide = runtime_base - link_base
    data = {
        "ok": True,
        "vm_id": inst.vm_id,
        "arch": inst.arch,
        "symbols": str(symbols_path),
        "kbase": _format_hex(runtime_base),
        "link_base": _format_hex(link_base),
        "slide": _format_hex(slide),
    }
    _emit(
        args,
        data=data,
        text=(
            f"KBASE={data['kbase']}\n"
            f"LINK_BASE={data['link_base']}\n"
            f"SLIDE={data['slide']}"
        ),
        stem="kbase",
    )
    return 0


def _add_gdb(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "gdb",
        help="Connect pry (headless GDB bridge) to the VM's GDB stub; "
             "non-interactive, does not open a debugger session",
    )
    p.add_argument("--symbols", default=None, help="Path to vmlinux with debug symbols")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_gdb)


_PRY_LAUNCH_TIMEOUT = 15


def _bridge_instance_id(inst: VMInstance) -> str:
    """Stable pry `--instance-id` for this VM's bridge.

    Lets `pry --instance qmu-<vm>` select the bridge without knowing its pid,
    and makes pry itself refuse a second bridge under the same name — a second
    line of defence behind the attach gate below.
    """
    return f"qmu-{inst.vm_id}"


def _pry_launch_error(result: subprocess.CompletedProcess) -> str:
    """Human text from a failed `pry launch --format json`."""
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload["error"]
    return result.stderr.strip() or result.stdout.strip() or "no diagnostic"


def _pry_launch_pid(result: subprocess.CompletedProcess) -> int | None:
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    pid = payload.get("pid") if isinstance(payload, dict) else None
    return pid if isinstance(pid, int) and pid > 0 else None


def _handle_gdb(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    if inst.gdb_port is None:
        raise QMUError(
            "VM was launched without --gdb. Relaunch with: qmu launch --gdb --kernel ..."
        )

    pry = shutil.which("pry")
    if not pry:
        raise QMUError("pry not found in PATH. Install pry and ensure it is on PATH.")

    # #40 / debug audit D4: the QEMU gdbstub serves ONE client. A second
    # `pry launch` against an attached stub blocks until the 15 s cap, exits 4
    # with a raw TimeoutExpired, and leaks a bridge per attempt. Refuse up
    # front when a client is positively attached; "cannot tell" (None) falls
    # through so an unreadable /proc never locks the debugger out.
    attached = gdb_client_attached(inst)
    if attached is True:
        known = bridge_alive(inst)
        bridge = (
            f" (pry bridge pid {inst.gdb_bridge_pid})" if known else ""
        )
        detach = (
            f"pry kill --instance {inst.gdb_bridge_pid}"
            if known
            else "pry kill --instance <pid> (list pids with: pry doctor)"
        )
        raise QMUError(
            f"A debugger client is already attached to port {inst.gdb_port}"
            f"{bridge}. Reuse it, or detach with: {detach}"
        )
    # A recorded bridge that is alive while NO client is attached is the #40
    # stranded case (its stub died under it, or it dropped the connection).
    # It still holds this VM's instance-id, so pry would refuse the launch;
    # reap it first. Only on a positive "not attached" — on None the bridge
    # may be live and talking.
    if attached is False and bridge_alive(inst):
        reap_bridge(inst)

    instance_id = _bridge_instance_id(inst)
    cmd = [
        "pry", "launch", "--format", "json",
        "--instance-id", instance_id,
        "--connect", f"localhost:{inst.gdb_port}",
    ]
    symbols_path = (
        Path(args.symbols).expanduser().resolve() if args.symbols else None
    )
    if symbols_path is not None:
        cmd.extend(["--symbols", str(symbols_path)])

    # `pry launch` is non-interactive: it spins up a headless GDB + bridge in the
    # background, connects to the stub, and returns — it does NOT hand back an
    # interactive debugger session. So capturing output and capping at 15s (pry's
    # own bridge-start wait defaults to 10s) is correct; the agent drives the
    # halted session afterwards via the `pry` CLI.
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_PRY_LAUNCH_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        # The bridge pry detached may have outlived the launcher; reap it by
        # the name we gave it so an attempt never leaves a process behind.
        try:
            subprocess.run(
                [pry, "kill", "--instance", instance_id],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        raise QMUError(
            f"pry launch did not connect to the GDB stub on port {inst.gdb_port} "
            f"within {_PRY_LAUNCH_TIMEOUT} s. Another client may hold the stub "
            "(QEMU serves one); check `pry doctor` and `ss -tnp` for an "
            f"ESTABLISHED socket on port {inst.gdb_port}."
        ) from None
    if result.returncode != 0:
        raise QMUError(f"pry launch failed: {_pry_launch_error(result)}")

    bridge_pid = _pry_launch_pid(result)
    inst = replace(
        inst,
        gdb_bridge_pid=bridge_pid,
        gdb_bridge_pid_start=proc_pid_start(bridge_pid) if bridge_pid else None,
    )
    save_instance(inst)

    # H4: attaching to the gdb stub HALTS the vCPU. Until it is resumed every
    # SSH command (exec/push/pull/compile) refuses with exit 1 and a `qmu cont`
    # hint. Say so and tell them how to resume.
    warning = (
        "WARNING: the vCPU is now HALTED by the debugger. SSH commands (exec/"
        "push/pull/compile) fail fast with exit 1 until you resume it. Resume "
        "with `pry continue` (in the debugger) or `qmu cont`."
    )
    data = {
        "ok": True,
        "vm_id": inst.vm_id,
        "gdb_port": inst.gdb_port,
        "bridge_pid": bridge_pid,
        "bridge_instance_id": instance_id,
        "cpu_state": "halted",
        "warning": warning,
    }
    bridge_line = (
        f"pry bridge pid {bridge_pid} (select it with `pry --instance "
        f"{bridge_pid}` or `pry --instance {instance_id}`; `qmu kill` reaps it)"
        if bridge_pid is not None
        else "pry did not report a bridge pid; `qmu kill` cannot reap it"
    )
    text = (
        f"pry connected to VM '{inst.vm_id}' GDB stub on port "
        f"{inst.gdb_port}\n{bridge_line}\n{warning}"
    )
    if symbols_path is not None:
        symbol_warning = (
            f"WARNING: symbols from '{symbols_path}' were loaded at ELF link-time "
            "addresses; qmu gdb did not apply runtime rebasing. Obtain the runtime "
            f"base with `qmu kbase --vm {inst.vm_id} --symbols {symbols_path}`, then "
            f"reload with `pry load {symbols_path} --base <KBASE>`."
        )
        data.update({
            "symbols": str(symbols_path),
            "symbols_rebased": False,
            "symbol_base": "elf-link-time",
            "kaslr_status": "unknown",
            "symbol_warning": symbol_warning,
        })
        text = f"{text}\n{symbol_warning}"
    # #39: hardware watchpoints set through the QEMU gdbstub can be accepted
    # yet silently never fire under KVM. Warn at attach time — the one
    # moment qmu is on the debug path — but only when the VM was actually
    # launched under KVM (recorded on the instance). Kept in the stdout
    # payload alongside the other gdb warnings so the JSON envelope carries
    # it and stderr stays clean.
    if getattr(inst, "kvm", None) is True:
        kvm_warning = kvm_watchpoint_warning(inst.vm_id)
        data["kvm"] = True
        data["kvm_watchpoint_warning"] = kvm_warning
        text = f"{text}\n{kvm_warning}"
    _emit(
        args,
        data=data,
        text=text,
        stem="gdb",
    )
    return 0


# ---------------------------------------------------------------------------
# cont (resume a halted vCPU)
# ---------------------------------------------------------------------------


def _add_cont(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "cont",
        help="Resume a vCPU halted by the debugger (issues QMP cont)",
    )
    _add_common_opts(p)
    p.add_argument(
        "--force",
        action="store_true",
        help="Resume even when QEMU reports `restore-vm` (a snapshot load that "
             "failed mid-restore left the disks rewound under un-restored "
             "device state). Without it `cont` refuses with exit 1.",
    )
    p.set_defaults(handler=_handle_cont)


def _handle_cont(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        before = qmp.execute("query-status")
        before_state = (
            before.get("status") if isinstance(before, dict) else None
        )
        # #110: `restore-vm` is the one halt `cont` must not be the answer
        # to. A `snapshot load` that failed mid-restore leaves the disk
        # rewound and the devices not; resuming that machine performs the
        # inconsistent resume the failed load refused. The recovery is a
        # known-good load or a relaunch — the same hint `exec` gives.
        if before_state == "restore-vm" and not args.force:
            data, text = _stopped_guest_payload(inst, "restore-vm")
            data["hint"] += " To resume anyway: qmu cont --vm " + inst.vm_id + " --force."
            text.append(f"Override: qmu cont --vm {inst.vm_id} --force")
            _emit_refusal(args, data=data, text=text, stem="cont")
            return 1
        # Resume the guest. QMP "cont" returns {} on success; if the VM is
        # already running QEMU raises an error, which surfaces as QMPError.
        qmp.execute("cont")
        status = qmp.execute("query-status")
    run_state = (
        status.get("status", "unknown") if isinstance(status, dict) else str(status)
    )
    data = {"ok": True, "vm_id": inst.vm_id, "status": run_state}
    text = f"VM '{inst.vm_id}' resumed (status: {run_state})"
    if before_state == "restore-vm":
        data["forced"] = True
        text += " — forced out of restore-vm; the machine state may be inconsistent"
    _emit(args, data=data, text=text, stem="cont")
    return 0


# ---------------------------------------------------------------------------
# qmp (raw)
# ---------------------------------------------------------------------------


def _add_qmp(sub: argparse._SubParsersAction) -> None:
    # The description carries the envelope contract because that is the surface
    # an agent reads before typing (`qmu qmp --help`); a docstring is not one.
    # Raw formatting (matching the top-level parser) so the literal envelope is
    # copy-pasteable -- the default formatter re-wrapped it mid-token.
    p = sub.add_parser(
        "qmp",
        help="Send raw QMP command",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Send a raw QMP command. COMMAND is either the bare method name\n"
            "  qmu qmp query-status\n"
            "or the JSON envelope QEMU's own documentation shows (braces\n"
            "optional):\n"
            "  qmu qmp '{\"execute\": \"query-status\"}'\n"
            "\n"
            "Envelope 'arguments' and --args are the same input: pass one, not\n"
            "both. An envelope 'id' member is REJECTED rather than dropped --\n"
            "qmu sends one command and hands back that reply's payload\n"
            "directly, so an id has nothing to correlate against and accepting\n"
            "it would only buy the caller a false belief that it round-tripped.\n"
            "\n"
            "Any error reply from QEMU -- a method it has no command for,\n"
            "arguments its schema rejects, a device it cannot find -- exits 1\n"
            "(operational). Exit 4 is reserved for the transport. HMP text\n"
            "returned by human-monitor-command that is itself an error report\n"
            "(`unknown command: ...`, `Error: ...`) also exits 1."
        ),
    )
    p.add_argument("command", help="QMP method name or JSON envelope")
    p.add_argument("--args", default=None, help="JSON object of arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_qmp)


_QMP_METHOD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")

_QMP_FORM_HINT = (
    "pass the bare method name (e.g. `qmu qmp query-status`) or a JSON envelope "
    "(`qmu qmp '{\"execute\": \"query-status\"}'`); arguments go in --args '{...}'"
)


def _parse_qmp_command(raw: str, args_json: str | None) -> tuple[str, dict | None]:
    """Accept both call forms an agent actually types: the bare method name
    (`query-status`) and the envelope QEMU's own docs show
    (`{"execute": "query-status", "arguments": {...}}`, with or without braces).

    Before this, an envelope-shaped string was sent to QEMU verbatim as the
    method name, so QEMU answered CommandNotFound and the QMPError surfaced as
    exit 4 -- an infra code for a caller-input mistake (#36). Normalizing here
    is the form half; `_qmp_caller_error` handles the replies QEMU sends for a
    method or arguments it does not accept.

    `raw` is stripped once, up front, and both branches match against the
    stripped candidate with `fullmatch` (not `match`): the bare-name regex has
    no `re.MULTILINE`, so unstripped `match` let a trailing newline sneak
    through as part of the method name (exit 4 on the wire) while unstripped
    leading whitespace wrongly fell into the envelope branch.

    An envelope `id` member (a real QMP protocol field, echoed back by QEMU to
    correlate responses) is REJECTED, not dropped. `QMPClient.execute` has no
    id parameter and `_recv_response` unwraps the reply to its `return`
    payload, so a forwarded id could never reach the caller — and this CLI
    sends one command per process with nothing concurrent to correlate.
    Accepting it therefore buys the caller nothing and costs them the belief
    that a round-trip id worked, which is the same silent-drop failure that
    made a mistyped `argument` (missing the trailing "s") execute the command
    with the caller's arguments discarded and exit 0. Rejecting it puts the
    contract on the surface an agent actually reads (this error, and
    `qmu qmp --help`) instead of leaving it in a docstring.
    """
    if args_json:
        flag_args = json.loads(args_json)
        if not isinstance(flag_args, dict):
            # Name the FLAG the caller typed. Saying "'arguments' must be a
            # JSON object" pointed at an envelope member they never supplied,
            # while the sibling error in `_handle_qmp` for this same flag
            # calls it "--args".
            raise QMUError(
                "Invalid --args JSON: must be a JSON object, got "
                f"{type(flag_args).__name__} -- e.g. "
                "--args '{\"command-line\": \"info status\"}'"
            )
    else:
        flag_args = None

    candidate = raw.strip()
    if _QMP_METHOD_RE.fullmatch(candidate):
        return candidate, flag_args

    invalid = QMUError(f"Invalid QMP command {raw!r}: {_QMP_FORM_HINT}")
    envelope_text = candidate if candidate.startswith("{") else "{" + candidate + "}"
    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError:
        raise invalid from None
    if not isinstance(envelope, dict):
        raise invalid
    unknown_keys = set(envelope) - {"execute", "arguments"}
    if unknown_keys:
        extra = (
            " ('id' is not forwarded: qmu sends one command and returns that "
            "reply's payload, so there is nothing to correlate an id against "
            "-- drop it)"
            if "id" in unknown_keys
            else ""
        )
        raise QMUError(
            f"Invalid QMP command {raw!r}: unknown envelope key(s) "
            f"{', '.join(sorted(unknown_keys))}{extra}; {_QMP_FORM_HINT}"
        )
    method = envelope.get("execute")
    if not isinstance(method, str) or not _QMP_METHOD_RE.fullmatch(method):
        raise invalid

    if "arguments" not in envelope:
        return method, flag_args
    envelope_args = envelope["arguments"]
    if not isinstance(envelope_args, dict):
        raise QMUError("QMP envelope 'arguments' must be a JSON object")
    if args_json:
        raise QMUError(
            "QMP arguments given twice: envelope 'arguments' and --args; "
            "pass them once"
        )
    return method, envelope_args


# QEMU's QAPI input visitor produces exactly these desc shapes (all under class
# GenericError) when the *arguments* do not match the command's schema. Grounded
# in replies measured from QEMU 8.2.2:
#   Parameter 'foo' is unexpected            (extra member)
#   Parameter 'path' is missing              (required member absent)
#   Parameter 'max-bandwidth' expects uint64 (wrong scalar)
#   Parameter 'driver' does not accept value 'nope'      (bad enum member)
#   Invalid parameter type for 'cpu-index', expected: integer
#   QMP input member 'arguments' must be an object
# "Invalid parameter 'x'" is the older (pre-6.0) wording for the enum case.
# Deliberately anchored: an *operational* GenericError such as "failed to open
# file '/x': No such file or directory" or "Property 'p' not found" describes
# host/VM state, not the command text, and must NOT get the "fix your
# arguments" correction attached (it is still exit 1 -- the wire worked).
_QMP_ARG_SHAPE_RE = re.compile(
    r"^(?:"
    r"Parameter '[^']*' (?:is (?:missing|unexpected)|expects |does not accept value )"
    r"|Invalid parameter (?:type for )?'[^']*'"
    r"|QMP input member '[^']*' (?:is unexpected|must be )"
    r")"
)


def _qmp_caller_error(method: str, exc: QMPCommandError) -> QMUError:
    """Re-class a QEMU error *reply* as the exit-1 operational class.

    Exit 4 means "QMP/SSH transport or internal qmu failure", so an agent
    branching on it retries or declares infra breakage. Every QEMU error
    REPLY is the opposite of that: the wire worked and QEMU answered "no",
    which no retry fixes. `qmu qmp --help` promises exit 4 for the transport
    only, and `device_del` with a bad id used to break that promise
    (snapshot audit #9). A method QEMU has no command for and arguments its
    QAPI schema rejects get a correction attached; every other class
    (DeviceNotFound, KVMMissingCap, an operational GenericError like "failed
    to open file ...") keeps QEMU's own words plus the reply class so the
    caller still knows WHICH "no" it was.
    """
    if exc.qmp_class == "CommandNotFound":
        return QMUError(
            f"Unknown QMP command {method!r}: {exc.desc}. "
            "List the commands this QEMU accepts with `qmu qmp query-commands`"
        )
    if exc.qmp_class == "GenericError" and _QMP_ARG_SHAPE_RE.match(exc.desc):
        return QMUError(
            f"Invalid arguments for QMP command {method!r}: {exc.desc}. "
            "Arguments must be a JSON object matching the command's QAPI "
            "schema (`qmu qmp query-qmp-schema --out <file>` dumps it)"
        )
    return QMUError(f"QMP command {method!r} failed ({exc.qmp_class}): {exc.desc}")


def _hmp_verb(command_line: str) -> str:
    """First whitespace-separated token of an HMP command line ("" if none).

    The verb, not the whole line: `help system_reset` shows help and resets
    nothing, so a substring test would warn on it.
    """
    tokens = command_line.split()
    return tokens[0] if tokens else ""


def _hmp_error(command_line: str, output: str) -> QMUError:
    """The exit-1 error for HMP result text that is itself a failure report.

    `qmu monitor nonsense-cmd` and `qmu qmp human-monitor-command` used to
    exit 0 / ok:true with "unknown command: 'nonsense-cmd'" inside the
    payload (snapshot audit D8); `ok` must mean what it says.
    """
    hint = ""
    if _hmp_verb(command_line) == "loadvm":
        if loadvm_restore_state(output) == "none":
            hint = (
                " (loadvm stops the guest before it looks for the tag and only "
                "restarts it on success: check `qmu status`, resume with `qmu cont`)"
            )
        else:
            # Past the tag check loadvm reverts the disks before loading the
            # vmstate; a `cont` here runs the inconsistent result (#87).
            hint = (
                " (loadvm may have failed after restoration began: the disks "
                "may be rewound under device state that is not. Do not `qmu "
                "cont` it; load a known-good snapshot or `qmu kill` and relaunch)"
            )
    return QMUError(f"HMP command {command_line!r} failed: {output.strip()}{hint}")


# HMP verbs / QMP methods that replace the guest's running state. Each needs
# the same bookkeeping the dedicated `snapshot load` handler does, whichever of
# the three raw routes (`qmu monitor`, `qmu qmp system_reset`,
# `qmu qmp human-monitor-command`) reached it.
_TCP_RESETTING_VERBS = frozenset({"system_reset", "loadvm"})


def _before_mutation(inst: VMInstance, verb: str) -> int | None:
    """Pre-mutation bookkeeping; returns the serial epoch to persist on success.

    A qmu-issued `system_reset` used to leave `guest_epoch_serial_offset`
    untouched, so `wait --pattern 'login:'` matched the previous boot in
    0.00 s (snapshot audit D5) — the epoch only advanced on a RESET that
    `wait` itself observed. Capturing the log size here, before the reset
    lands, is exactly what `snapshot load` does.
    """
    if verb in _TCP_RESETTING_VERBS:
        _drop_ssh_master(inst)
        return serial_log_offset(inst.serial_log)
    if verb == "savevm":
        _drop_ssh_master(inst)
    return None


def _after_mutation(
    inst: VMInstance, verb: str, output: str, epoch: int | None
) -> VMInstance:
    """Post-mutation bookkeeping plus the debugger coherence warning.

    One switch for all three raw routes. The `human-monitor-command` one was
    silent (dogfood F4): it reset the machine with an attached debugger, rc 0
    and an empty stderr, which is precisely the wrong-answer-with-no-error
    class debug.py exists to prevent. savevm/loadvm suppress on a failed op
    (the same classifier the snapshot handlers use), since a failed op
    mutated nothing. A failed epoch persist is raised only AFTER the SSH
    master drop and the coherence warning, which the mutation that already
    landed still needs.
    """
    failed = verb in ("savevm", "loadvm") and _snapshot_failed(output)
    persist_error: OSError | None = None
    if verb in _TCP_RESETTING_VERBS and not failed:
        if epoch is not None:
            try:
                inst = save_guest_epoch_serial_offset(inst, epoch)
            except OSError as exc:
                persist_error = exc
        _drop_ssh_master(inst)
    if verb == "system_reset":
        if debug_session_present(inst):
            sys.stderr.write(reset_dropped_breakpoints_warning(inst.vm_id) + "\n")
    elif verb == "savevm":
        if debug_stub_present(inst) and not failed:
            sys.stderr.write(savevm_breakpoint_warning(inst.vm_id) + "\n")
    elif verb == "loadvm":
        if debug_session_present(inst) and not failed:
            sys.stderr.write(loadvm_stale_session_warning(inst.vm_id) + "\n")
    if persist_error is not None:
        raise persist_error
    return inst


def _finish_mutation(
    args: argparse.Namespace,
    inst: VMInstance,
    verb: str,
    output: str,
    epoch: int | None,
    *,
    data: dict[str, object],
    text: object,
    stem: str,
) -> int:
    """Post-mutation bookkeeping, THEN exactly one envelope.

    `_after_mutation` persists the guest epoch, and that write can fail
    (an instance dir the operator chmod'ed, a full disk). The guest mutation
    has already landed by then, so the honest report is a single `ok:false`
    envelope that still carries the QMP result and says the reset happened
    -- never a success envelope followed by a second failure object, which
    is what emitting first produced (#88: exit 4 with two JSON documents on
    stdout, the first of which a consumer could accept as the result).
    Exit 4: the guest did what was asked; qmu's own state is what failed.
    """
    try:
        _after_mutation(inst, verb, output, epoch)
    except OSError as exc:
        error = (
            f"{verb or 'command'} reached the guest, but qmu could not record "
            f"it: {exc}"
        )
        hint = (
            f"The guest mutation was applied; only VM '{inst.vm_id}'s instance "
            "record was not updated (its guest epoch is stale, so `qmu wait "
            "--pattern` may match the previous boot). Make the instances "
            "directory writable and re-check with: qmu status --vm "
            f"{inst.vm_id}"
        )
        if getattr(args, "format", "text") == "text":
            sys.stderr.write(f"[qmu] Error: {error}\n[qmu] {hint}\n")
        else:
            _emit(
                args,
                data={
                    **data,
                    "ok": False,
                    "error": error,
                    "error_type": exc.__class__.__name__,
                    "guest_mutated": True,
                    "hint": hint,
                },
                text=error,
                stem=stem,
            )
        return 4
    _emit(args, data=data, text=text, stem=stem)
    return 0


def _handle_qmp(args: argparse.Namespace) -> int:
    # M3: pre-validate --args JSON with a friendly QMUError instead of letting a
    # raw JSONDecodeError escape as a traceback. Both this and the command-form
    # normalization run before the VM is selected or connected, so a caller-input
    # mistake is an exit-1 QMUError rather than an exit-4 infra failure.
    if args.args:
        try:
            json.loads(args.args)
        except json.JSONDecodeError as exc:
            raise QMUError(f"Invalid --args JSON: {exc}") from exc
    method, qmp_args = _parse_qmp_command(args.command, args.args)
    inst = choose_instance(args.vm)
    # Both raw paths reach a VM-reality mutation -- the QMP method itself
    # (keyed on the NORMALIZED method, so the envelope form counts too) and
    # `human-monitor-command`, whose HMP verb rides inside
    # arguments['command-line'] and was unguarded (F4).
    hmp_line: str | None = None
    if method == "system_reset":
        verb = "system_reset"
    elif method == "human-monitor-command":
        line = qmp_args.get("command-line") if isinstance(qmp_args, dict) else None
        hmp_line = line if isinstance(line, str) else None
        verb = _hmp_verb(hmp_line) if hmp_line is not None else ""
    else:
        verb = ""
    epoch = _before_mutation(inst, verb)
    try:
        with _qmp_ctx(inst) as qmp:
            result = qmp.execute(method, qmp_args)
    except QMPCommandError as exc:
        # A QEMU error REPLY, not a transport fault: the wire worked, so this
        # is the exit-1 class whichever error class QEMU chose.
        raise _qmp_caller_error(method, exc) from exc
    if hmp_line is not None and isinstance(result, str) and hmp_failed(result):
        raise _hmp_error(hmp_line, result)
    # Bookkeeping BEFORE the envelope: the epoch persist can fail (unwritable
    # instance dir), and a success envelope already on stdout cannot be
    # taken back -- `qmu qmp system_reset` printed `ok:true` followed by a
    # second `ok:false` object (#88). Text mode passes the raw QMP return
    # (any JSON type) straight to _output; json mode wraps it so the
    # universal {"ok": ...} contract holds, with the payload under "result".
    return _finish_mutation(
        args, inst, verb, result if isinstance(result, str) else "", epoch,
        data={"ok": True, "result": result}, text=result, stem="qmp",
    )


# ---------------------------------------------------------------------------
# monitor (HMP)
# ---------------------------------------------------------------------------


def _add_monitor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "monitor",
        help="Send HMP monitor command",
        description=(
            "Send a raw HMP (human monitor) command and print its text. "
            "HMP reports failures as text rather than a protocol error, so "
            "output QEMU phrases as one (`unknown command: ...`, `Error: ...`, "
            "`...: extraneous characters at the end of line`) exits 1 with "
            "that text as the error; anything else exits 0 and is passed "
            "through verbatim."
        ),
    )
    p.add_argument("command", nargs="+", help="HMP command")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_monitor)


def _handle_monitor(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    command = " ".join(args.command)
    # HMP is a raw escape hatch, so `qmu monitor {system_reset,savevm,loadvm}`
    # reach the same VM-reality mutations as the dedicated handlers / `qmu qmp`
    # but bypass their bookkeeping and coherence warnings. Route through the
    # shared hooks, keyed on the HMP *verb* so e.g. `monitor help system_reset`
    # -- which resets nothing -- is not caught.
    verb = _hmp_verb(command)
    epoch = _before_mutation(inst, verb)
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute_hmp(command)
    if hmp_failed(result):
        raise _hmp_error(command, result)
    return _finish_mutation(
        args, inst, verb, result, epoch,
        data={"ok": True, "output": result},
        text=result if result.strip() else "(no output)",
        stem="monitor",
    )
