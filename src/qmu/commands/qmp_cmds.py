"""QMP / debugger commands: gdb, cont, qmp (raw), monitor (HMP), snapshot.

Everything here drives the VM through its QMP socket (or, for gdb, the pry
subprocess against the GDB stub). Shared helpers come from :mod:`.._cliutil`;
this module imports no other ``commands.*`` module and never imports ``cli``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from ..instance import (
    QMUError,
    choose_instance,
    save_guest_epoch_serial_offset,
)
from ..snapshot import (
    delete_snapshot,
    list_snapshots,
    load_snapshot,
    save_snapshot,
)
from ..serial import serial_log_offset
from .._cliutil import (
    _add_common_opts,
    _emit,
    _make_group_help_handler,
    _qmp_ctx,
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


# HMP error markers that indicate a snapshot operation actually failed.
# Deliberately specific so benign savevm slirp *warnings* (e.g. "warning: Slirp:
# Save of field ... failed") are NOT treated as hard failures — those lines
# begin with "warning:" and contain none of the markers below, so save still
# exits 0.
_SNAPSHOT_ERROR_MARKERS = (
    "Error:",
    "Missing section footer",
    "Section footer error",
    "does not support",
    "Could not open",
    "No block device",
)


def _snapshot_failed(msg: str) -> bool:
    return any(m in msg for m in _SNAPSHOT_ERROR_MARKERS)


def _handle_snapshot_save(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        msg = save_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-save",
    )
    if failed:
        # savevm stores *internal* snapshots, which QEMU can only write into a
        # writable qcow2 disk. The default implicit rootfs drive is
        # format=raw,snapshot=on (see vm.py): raw images cannot hold internal
        # snapshots, and the snapshot=on overlay is a throwaway that savevm
        # refuses too. Give the actionable requirement rather than the raw HMP
        # error (mirrors the load handler's hint).
        sys.stderr.write(
            f"[qmu] snapshot save failed: {msg}\n"
            "[qmu] `savevm` requires a writable qcow2 rootfs disk to store "
            "internal snapshots; the default format=raw image (and any "
            "snapshot=on overlay) cannot hold them. Rebuild/convert the rootfs "
            "to qcow2 (e.g. `qemu-img convert -O qcow2 rootfs.img rootfs.qcow2`), "
            "set [drive] format = \"qcow2\", and launch with net_backend=passt "
            "(not the default slirp) so the saved state round-trips.\n"
        )
        return 1
    return 0


def _handle_snapshot_load(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        epoch_offset = serial_log_offset(inst.serial_log)
        msg = load_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    if not failed:
        inst = save_guest_epoch_serial_offset(inst, epoch_offset)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-load",
    )
    if failed:
        sys.stderr.write(
            f"[qmu] snapshot load failed: {msg}\n"
            "[qmu] The VM was NOT restored. With the default -net user (slirp) "
            "networking, savevm/loadvm cannot serialize NIC state; relaunch the "
            "VM instead of relying on snapshot restore.\n"
        )
        return 1
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
        msg = delete_snapshot(qmp, args.name)
    failed = _snapshot_failed(msg)
    _emit(
        args,
        data={"ok": not failed, "name": args.name, "message": msg},
        text=msg,
        stem="snapshot-delete",
    )
    if failed:
        sys.stderr.write(f"[qmu] snapshot delete failed: {msg}\n")
        return 1
    return 0


# ---------------------------------------------------------------------------
# gdb
# ---------------------------------------------------------------------------


def _add_gdb(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "gdb",
        help="Connect pry (headless GDB bridge) to the VM's GDB stub; "
             "non-interactive, does not open a debugger session",
    )
    p.add_argument("--symbols", default=None, help="Path to vmlinux with debug symbols")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_gdb)


def _handle_gdb(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    if inst.gdb_port is None:
        raise QMUError(
            "VM was launched without --gdb. Relaunch with: qmu launch --gdb --kernel ..."
        )

    pry = shutil.which("pry")
    if not pry:
        raise QMUError("pry not found in PATH. Install pry and ensure it is on PATH.")

    cmd = ["pry", "launch", "--connect", f"localhost:{inst.gdb_port}"]
    if args.symbols:
        cmd.extend(["--symbols", str(Path(args.symbols).expanduser().resolve())])

    # `pry launch` is non-interactive: it spins up a headless GDB + bridge in the
    # background, connects to the stub, and returns — it does NOT hand back an
    # interactive debugger session. So capturing output and capping at 15s (pry's
    # own bridge-start wait defaults to 10s) is correct; the agent drives the
    # halted session afterwards via the `pry` CLI.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if result.returncode == 0:
        # H4: attaching to the gdb stub HALTS the vCPU. If the agent does not
        # resume it, every subsequent exec/push/pull/compile will hang and fail
        # with an ambiguous transport timeout. Warn loudly and tell them how to
        # resume.
        warning = (
            "WARNING: the vCPU is now HALTED by the debugger. SSH (exec/push/"
            "pull/compile) will hang until you resume it. Resume with `pry "
            "continue` (in the debugger) or `qmu cont`."
        )
        _emit(
            args,
            data={
                "ok": True,
                "vm_id": inst.vm_id,
                "gdb_port": inst.gdb_port,
                "cpu_state": "halted",
                "warning": warning,
            },
            text=f"pry connected to VM '{inst.vm_id}' GDB stub on port "
            f"{inst.gdb_port}\n{warning}",
            stem="gdb",
        )
    else:
        output = result.stderr.strip() or result.stdout.strip()
        _emit(
            args,
            data={"ok": False, "error": output},
            text=f"pry launch failed: {output}",
            stem="gdb",
        )
        return 1
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
    p.set_defaults(handler=_handle_cont)


def _handle_cont(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    with _qmp_ctx(inst) as qmp:
        # Resume the guest. QMP "cont" returns {} on success; if the VM is
        # already running QEMU raises an error, which surfaces as QMPError.
        qmp.execute("cont")
        status = qmp.execute("query-status")
    run_state = (
        status.get("status", "unknown") if isinstance(status, dict) else str(status)
    )
    _emit(
        args,
        data={"ok": True, "vm_id": inst.vm_id, "status": run_state},
        text=f"VM '{inst.vm_id}' resumed (status: {run_state})",
        stem="cont",
    )
    return 0


# ---------------------------------------------------------------------------
# qmp (raw)
# ---------------------------------------------------------------------------


def _add_qmp(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("qmp", help="Send raw QMP command")
    p.add_argument("command", help="QMP command name")
    p.add_argument("--args", default=None, help="JSON arguments")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_qmp)


def _handle_qmp(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    # M3: pre-validate --args JSON with a friendly QMUError instead of letting a
    # raw JSONDecodeError escape as a traceback.
    if args.args:
        try:
            qmp_args = json.loads(args.args)
        except json.JSONDecodeError as exc:
            raise QMUError(f"Invalid --args JSON: {exc}") from exc
    else:
        qmp_args = None
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute(args.command, qmp_args)
    # Text mode passes the raw QMP return (any JSON type) straight to _output;
    # json mode wraps it so the universal {"ok": ...} contract holds, with the
    # original payload under "result".
    _emit(args, data={"ok": True, "result": result}, text=result, stem="qmp")
    return 0


# ---------------------------------------------------------------------------
# monitor (HMP)
# ---------------------------------------------------------------------------


def _add_monitor(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("monitor", help="Send HMP monitor command")
    p.add_argument("command", nargs="+", help="HMP command")
    _add_common_opts(p)
    p.set_defaults(handler=_handle_monitor)


def _handle_monitor(args: argparse.Namespace) -> int:
    inst = choose_instance(args.vm)
    command = " ".join(args.command)
    with _qmp_ctx(inst) as qmp:
        result = qmp.execute_hmp(command)
    _emit(
        args,
        data={"ok": True, "output": result},
        text=result if result.strip() else "(no output)",
        stem="monitor",
    )
    return 0
