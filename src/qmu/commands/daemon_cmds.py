"""`qmu daemon run|start|stop|status` — the supervisor's own lifecycle.

Most callers never type these: the client autostarts the daemon and it idles
out on its own. They exist for the cases autostart cannot cover — a script
that wants the daemon up before a burst of commands (`start`), one that must
leave nothing behind (`stop`), and the human asking what it is doing
(`status`). `run` is the foreground server `start` spawns.
"""

from __future__ import annotations

import argparse
import os
import signal
import time
from typing import Any

from .. import daemon_client
from ..config import resolve_config
from ..daemon import serve
from ..instance import QMUError
from ..paths import cache_home
from .._cliutil import Result, _add_format_opts, _make_group_help_handler


def _add_daemon(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "daemon",
        help="Manage the per-user supervisor that owns QMP connections and serial scans",
        description=(
            "The daemon holds one QMP connection per running VM so events "
            "(RESET, STOP, SHUTDOWN) are observed rather than inferred and "
            "concurrent commands never see `qmp: busy`. It autostarts on "
            "demand (QMU_DAEMON=auto, the default; `off` disables the layer, "
            "`require` makes its absence an error) and exits after "
            "[daemon] idle_exit seconds with no running VM and no client."
        ),
    )
    p.set_defaults(handler=_make_group_help_handler(p))
    ops = p.add_subparsers(dest="daemon_op")

    run = ops.add_parser("run", help="Run the daemon in the foreground (what `start` spawns)")
    run.add_argument("--idle-exit", type=float, default=None,
                     help="Seconds idle before exiting (default: [daemon] idle_exit, 600; 0 = never)")
    _add_format_opts(run)
    run.set_defaults(handler=_handle_daemon_run)

    start = ops.add_parser("start", help="Spawn the daemon detached if none serves this cache dir")
    _add_format_opts(start)
    start.set_defaults(handler=_handle_daemon_start)

    stop = ops.add_parser("stop", help="Ask the daemon to exit")
    _add_format_opts(stop)
    stop.set_defaults(handler=_handle_daemon_stop)

    status = ops.add_parser("status", help="pid, uptime, build id and watched VMs")
    _add_format_opts(status)
    status.set_defaults(handler=_handle_daemon_status)


def _handle_daemon_run(args: argparse.Namespace) -> Result:
    idle_exit = args.idle_exit
    if idle_exit is None:
        idle_exit = float(resolve_config().daemon_idle_exit)
    return Result.silent_exit(serve(cache_home(), idle_exit=idle_exit))


def _handle_daemon_start(args: argparse.Namespace) -> Result:
    if daemon_client.daemon_mode() == daemon_client.MODE_OFF:
        raise QMUError("QMU_DAEMON=off disables the daemon layer; unset it to start one")
    conn = daemon_client.connect(autostart=False)
    if conn is not None:
        with conn:
            info = conn.request("ping")
        return Result(
            data={"ok": True, "started": False, "already_running": True,
                  **daemon_client.summarize(info)},
            text=f"Daemon already running (pid {info['pid']}, build {info['build_id']})",
            stem="daemon",
        )
    conn = daemon_client.connect(autostart=True)
    if conn is None:
        raise QMUError(
            "Daemon did not come up within "
            f"{daemon_client.SPAWN_WAIT_SECONDS:g}s; see {daemon_client.log_path()}"
        )
    with conn:
        info = conn.request("ping")
    return Result(
        data={"ok": True, "started": True, "already_running": False,
              **daemon_client.summarize(info)},
        text=(
            f"Daemon started (pid {info['pid']}, build {info['build_id']}, "
            f"log {daemon_client.log_path()})"
        ),
        stem="daemon",
    )


def _handle_daemon_stop(args: argparse.Namespace) -> Result:
    record = daemon_client.read_record()
    pid = record.get("pid") if record else None
    conn = daemon_client.connect(autostart=False) if daemon_client.enabled() else None
    if conn is None:
        # No reachable daemon. A live record with a dead socket is a wedged
        # daemon: signal it rather than report "not running". Under
        # QMU_DAEMON=off its socket is not tried at all (no connect), and
        # SIGTERM is the daemon's own graceful stop — so say that, not that
        # it failed to answer (#207).
        if daemon_client.record_alive(record) and isinstance(pid, int):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            gone = _wait_gone(pid)
            daemon_client._remove_stale(None)
            data: dict[str, Any] = {
                "ok": gone, "stopped": gone, "pid": pid, "signalled": True,
            }
            if not gone:
                data["hint"] = _still_alive_hint(pid)
            if daemon_client.enabled():
                text = f"Daemon pid {pid} did not answer its socket; sent SIGTERM"
                text += "." if gone else " but it is still alive."
            else:
                text = (f"Daemon pid {pid} stopped (SIGTERM; QMU_DAEMON=off does not use its socket)."
                        if gone else
                        f"Daemon pid {pid} was sent SIGTERM (QMU_DAEMON=off does not use its socket) "
                        "but it is still alive.")
            return Result(
                data=data,
                text=text,
                stem="daemon",
                exit_code=0 if gone else 1,
            )
        daemon_client._remove_stale(None)
        return Result(
            data={"ok": True, "stopped": False, "running": False},
            text="No daemon running.",
            stem="daemon",
        )
    with conn:
        info = conn.request("ping")
        try:
            conn.request("shutdown")
        except (daemon_client.DaemonError, daemon_client.DaemonUnavailable):
            pass
    gone = _wait_gone(info["pid"])
    data = {
        "ok": gone, "stopped": gone, "pid": info["pid"],
        "watched": len(info.get("vms", [])),
    }
    if not gone:
        data["hint"] = _still_alive_hint(info["pid"])
    return Result(
        data=data,
        text=(
            f"Daemon pid {info['pid']} stopped." if gone
            else f"Daemon pid {info['pid']} was asked to stop but is still alive."
        ),
        stem="daemon",
        exit_code=0 if gone else 1,
    )


def _still_alive_hint(pid: int) -> str:
    return (
        f"The daemon (pid {pid}) is still alive 5 s after being asked to stop; "
        f"re-run qmu daemon stop, or `kill -TERM {pid}` (`kill -KILL {pid}` as "
        "a last resort), then qmu daemon status"
    )


def _wait_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if daemon_client.process_gone(pid):
            return True
        time.sleep(0.02)
    return daemon_client.process_gone(pid)


def _handle_daemon_status(args: argparse.Namespace) -> Result:
    probe = daemon_client.probe()
    data = {"ok": True, **probe}
    if not probe["running"]:
        return Result(data=data, text=f"Daemon: not running ({probe['reason']})", stem="daemon")
    if not probe["used"]:
        # QMU_DAEMON=off with a live recorded daemon (#207): only daemon.json
        # is read, so no uptime-from-ping, clients or watched VMs.
        stale = "" if probe["build_current"] else "; STALE build"
        return Result(
            data=data,
            text=[
                f"Daemon: running (pid {probe['pid']}; not used: QMU_DAEMON=off{stale})",
                f"  Socket:    {probe['socket']}",
                "  It holds the QMP connection of every VM it watches, so QMP "
                "commands under QMU_DAEMON=off report those VMs busy.",
                "  Use it: unset QMU_DAEMON.  Release every VM: qmu daemon stop",
            ],
            stem="daemon",
        )
    stale = "" if probe["build_current"] else " — STALE build, respawns on next command"
    lines = [
        f"Daemon: running (pid {probe['pid']}, uptime {probe['uptime']:.0f}s, "
        f"build {probe['build_id']}{stale})",
        f"  Socket:    {probe['socket']}",
        f"  Cache:     {probe['cache_dir']}",
        f"  Idle exit: {probe['idle_exit']:g}s",
        f"  Clients:   {probe['clients']}",
    ]
    vms = probe["vms"]
    if not vms:
        lines.append("  Watching:  no VMs")
    else:
        lines.append("  Watching:")
        for vm in vms:
            state = "exited" if vm["exited"] else ("panicked" if vm["panicked"] else vm["qemu_status"])
            event = f" last_event={vm['last_event']}" if vm.get("last_event") else ""
            lines.append(f"    {vm['vm_id']}  pid={vm['pid']}  {state}{event}")
    return Result(data=data, text=lines, stem="daemon")
