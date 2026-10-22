"""QMP / debugger commands: gdb, cont, qmp (raw), monitor (HMP), snapshot.

Everything here drives the VM through its QMP socket (or, for gdb, the pry
subprocess against the GDB stub). Shared helpers come from :mod:`.._cliutil`;
this module never imports ``cli``, and imports a sibling ``commands.*``
module only lazily, inside a handler: lifecycle's non-running describer and
guest's SSH command watcher (`kbase`).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path

from .. import daemon_client
from ..instance import (
    QMUError,
    VMInstance,
    choose_instance,
    proc_pid_start,
    save_guest_epoch_serial_offset,
    save_instance,
    save_ssh_severed,
)
from ..snapshot import (
    SAVEVM_BASE_SECONDS,
    SAVEVM_SECONDS_PER_GIB,
    SnapshotResult,
    UNSNAPSHOTTABLE_DRIVE_RE,
    delete_snapshot,
    guest_run_state,
    list_snapshots,
    load_snapshot,
    missing_argument_command,
    save_snapshot,
    savevm_timeout,
    settle_loadvm,
)
from ..serial import serial_log_offset
from ..qmp import QMPCommandError, QMPError, QMPTimeoutError, hmp_failed
from ..ssh import SSHError
from ..debug import (
    INT3_LIFTED,
    INT3_POSSIBLE,
    BridgeDrive,
    BridgeStop,
    bridge_alive,
    bridge_instance_id,
    check_unwarned_reboot,
    cont_behind_debugger_warning,
    debug_session_present,
    debug_stub_present,
    drive_bridge_after_loadvm,
    drive_bridge_after_reset,
    gdb_client_attached,
    kvm_watchpoint_warning,
    loadvm_failed_restore_warning,
    loadvm_stale_session_warning,
    mark_debugger_attached,
    mark_debugger_epoch,
    note_coherence_warnings,
    orphaned_breakpoint_stop,
    orphaned_cont_warning,
    qmu_bridge_attached,
    reap_bridge,
    reset_dropped_breakpoints_warning,
    resume_bridge_after_save,
    keep_bridge_stopped_after_save,
    save_stop_failed_warning,
    savevm_breakpoint_state,
    savevm_breakpoint_warning,
    savevm_lifted_note,
    stop_bridge_for_save,
)
from .._cliutil import (
    Result,
    _add_common_opts,
    _refusal,
    _make_group_help_handler,
    _make_ssh,
    _preflight_ssh_guest,
    _require_ssh,
    _qmp_ctx,
    _stopped_guest_payload,
)


def _choose_running(vm_id: str | None, command: str) -> VMInstance:
    """`choose_instance`, with a listed-but-not-running name described.

    Same contract as `guest._choose_running`: on a miss, a stopped/orphaned
    VM `qmu list` shows gets the shared describer's answer and `vm_id`
    (lifecycle imported lazily — it sits beside this module), never "not
    found"; a name no command knows keeps the "not found" listing. A guest
    reboot the VM's debugger was not told about is announced here (#184).
    """
    try:
        inst = choose_instance(vm_id)
    except QMUError:
        from .lifecycle import _require_running

        _require_running(vm_id, command)
        raise
    return check_unwarned_reboot(inst)


def _qemu_status(qmp: object) -> str | None:
    """QEMU's run-state word, or None when QEMU refused or did not answer.

    Only ever asked after the mutation it describes has landed, so a
    timeout here must not turn into that mutation's failure.
    """
    try:
        reply = qmp.execute("query-status")  # type: ignore[attr-defined]
    except (QMPCommandError, QMPTimeoutError):
        return None
    status = reply.get("status") if isinstance(reply, dict) else None
    return status if isinstance(status, str) else None


def _run_state_reader(inst: VMInstance):
    """QEMU's run state on a fresh QMP connection, None when QEMU does not
    answer: what the bridge drive reads around its interrupt to tell a stop
    qmu made from one the operator's target took (#226)."""

    def read() -> str | None:
        try:
            with _qmp_ctx(inst) as qmp:
                return _qemu_status(qmp)
        except (QMPError, OSError):
            return None

    return read


def _status_before_save(qmp: object, inst: VMInstance) -> str | None:
    """QEMU's run state right before a savevm on a `--gdb` VM (#188).

    A timeout here means nothing was saved, which is neither the save's
    budget expiring (124, `may_have_landed`) nor a refused save: it is the
    transport class, said in those words.
    """
    if not debug_stub_present(inst):
        return None
    try:
        reply = qmp.execute("query-status")  # type: ignore[attr-defined]
    except QMPCommandError:
        return None
    except QMPTimeoutError as exc:
        raise QMPError(
            f"QEMU did not answer query-status before the save ({exc}); nothing "
            "was saved"
        ) from exc
    status = reply.get("status") if isinstance(reply, dict) else None
    return status if isinstance(status, str) else None


def _savevm_coherence(
    inst: VMInstance, before: str | None, after: str | None
) -> tuple[str | None, str | None]:
    """`(breakpoints_in_image, stderr line)` for a save that landed (#188).

    `before`/`after` bracket the save: savevm resumes a running guest before
    it returns, so a breakpoint hit right after it reads `debug` for an image
    taken while the guest ran. A save taken at a debugger stop gets a note;
    one that may hold int3 bytes gets the warning naming the save-at-a-stop
    recovery; under TCG there is nothing to say — breakpoints never touch
    guest RAM there.
    """
    state = savevm_breakpoint_state(inst, before, after)
    if state == INT3_LIFTED:
        return state, savevm_lifted_note(inst, before) + "\n"
    if state == INT3_POSSIBLE:
        return state, savevm_breakpoint_warning(inst, before, after) + "\n"
    return state, None


class _SaveStop:
    """A savevm with the bridge `qmu gdb` spawned stopped across it (#201).

    Under KVM, with that bridge attached and QEMU running, qmu stops it
    (`pry interrupt --hold`, so an operator's `pry wait` in flight keeps
    waiting, #228) so GDB lifts its breakpoints from guest RAM, takes the
    save at that stop and gives it back after; otherwise (TCG, another
    client, already stopped) the save runs as it is. `begin` takes `before`,
    QEMU's run state the save starts in, and re-reads it after the
    interrupt: the two decide whether the stop is qmu's to resume
    (`BridgeStop`, #226). `finish` classifies the image
    (`breakpoints_in_image`, which may ask the bridge whether it is stopped)
    BEFORE it gives the bridge back. A save that outran its budget leaves
    the bridge stopped (and held): QEMU may still be writing the image. Any
    other failure gives it back, and `record_on_failure` hands what qmu did
    to the error envelope.
    """

    def __init__(self, inst: VMInstance, event: str):
        self.inst = inst
        self.event = event
        self.before: str | None = None
        self.stop: BridgeStop | None = None
        self.warnings: tuple[str, ...] = ()
        self.drive: BridgeDrive | None = None
        self.coherence: tuple[str | None, str | None] = (None, None)

    def begin(self, qmp: object, before: str | None) -> None:
        self.before = before
        self.stop, error = stop_bridge_for_save(self.inst, before)
        if error:
            self.warnings = (save_stop_failed_warning(self.inst, error),)
        if self.stop is not None:
            self.before = self.save(lambda: _status_before_save(qmp, self.inst))
            self.stop = self.stop.at(self.before)

    def save(self, run):
        """`run()`, resuming the bridge first when it fails other than by
        running out of time."""
        try:
            return run()
        except QMPTimeoutError:
            raise
        except BaseException:
            self.resume()
            raise

    def finish(self, after: str | None, landed: bool) -> BridgeDrive | None:
        """The save returned: what the image holds (`coherence`, for a save
        that `landed`), then resume the bridge."""
        if landed:
            self.coherence = _savevm_coherence(self.inst, self.before, after)
        return self.resume()

    def resume(self) -> BridgeDrive | None:
        if self.stop is not None and self.drive is None:
            self.drive = resume_bridge_after_save(self.stop, self.event)
        return self.drive

    def image_keys(self) -> dict[str, object]:
        """What the saved image holds of the debugger's breakpoints, for the
        envelope of every save route (#227): `breakpoints_in_image`, plus
        `breakpoints_lifted` when qmu stopped its bridge for the save."""
        state, _ = self.coherence
        if state is None:
            return {}
        keys: dict[str, object] = {"breakpoints_in_image": state}
        if self.stop is not None:
            keys["breakpoints_lifted"] = state == INT3_LIFTED
        return keys

    def left_stopped(self) -> tuple[str, ...]:
        """Warnings for a save that outran its budget."""
        if self.stop is None or self.drive is not None:
            return self.warnings
        warning = keep_bridge_stopped_after_save(self.stop, self.event)
        return self.warnings + ((warning,) if warning is not None else ())

    def record_on_failure(self) -> None:
        """An exception other than the save's own timeout is leaving the
        handler: what qmu did to its bridge reaches the error envelope
        through the dispatch warnings."""
        drive = self.drive.warnings if self.drive is not None else ()
        note_coherence_warnings(*self.left_stopped(), *drive)


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------


def _add_snapshot(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("snapshot", help="VM snapshot management")
    p.set_defaults(handler=_make_group_help_handler(p))
    sp = p.add_subparsers(dest="snapshot_cmd")

    s = sp.add_parser("save", help="Save a snapshot")
    s.add_argument("name", help="Snapshot name")
    s.add_argument(
        "--timeout", type=float, default=None, metavar="SECONDS",
        help=(
            "budget for HMP savevm (default: "
            f"{SAVEVM_BASE_SECONDS:g} s + {SAVEVM_SECONDS_PER_GIB:g} s per GiB "
            "of guest RAM, e.g. 140 s for 4G). On expiry the result is UNKNOWN: "
            "exit 124, may_have_landed: true, and QEMU is probably still writing"
        ),
    )
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_save)

    s = sp.add_parser("load", help="Load a snapshot")
    s.add_argument("name", help="Snapshot name")
    _add_common_opts(s)
    s.set_defaults(handler=_handle_snapshot_load)

    s = sp.add_parser("list", help="List snapshots")
    s.add_argument(
        "--timeout", type=float, default=SNAPSHOT_LIST_TIMEOUT, metavar="SECONDS",
        help=(
            f"how long to wait for QEMU to answer (default {SNAPSHOT_LIST_TIMEOUT:g}); "
            "raise it after a `snapshot save` that expired, QEMU may still be "
            "writing that snapshot"
        ),
    )
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
    and stalls — once for the keepalive window, now (#182: the keepalive no
    longer gives up on a silent peer) until its own `--timeout` — or fails
    with `Broken pipe`, which made the documented
    rewind loop's first `exec` slower than a full relaunch (snapshot audit
    #3, contract #1). Closing before AND after the mutation guarantees no
    master straddles it. Best-effort and silent: harness VMs have no SSH.
    """
    if inst.ssh_port is None:
        return
    _make_ssh(inst).close_control_master()


def _sever_sessions(inst: VMInstance, cause: str) -> VMInstance:
    """Stamp the record, then close the guest's SSH ControlMaster (#221).

    Closing the master ends every guest command in flight through it, and
    a load or reset rewinds the guest's TCP state under any other session;
    that command's ssh then exits 255 with nothing to tell it from the
    guest program exiting 255. The stamp (`ssh_severed_at`/`_by`, written
    BEFORE the teardown so the severed command cannot read the record first)
    is what `guest._severed_by` checks, and it is qmu's own record — never
    bytes the guest wrote. Returns the stamped instance: a caller that
    persists `inst` again must carry the stamp, or that write erases it.
    """
    if inst.ssh_port is None:
        return inst  # no SSH endpoint, no session to sever
    try:
        inst = save_ssh_severed(inst, cause)
    except OSError:
        pass  # best-effort, like the teardown: the severed command keeps the old wording
    _drop_ssh_master(inst)
    return inst


_SNAPSHOT_ERROR_TYPE = "SnapshotError"
# Exit code for a `snapshot save` whose budget expired: the window closed and
# the result is unknown — the same code `wait` uses — not 4, which claims the
# transport broke (it did not; QEMU is still inside `savevm`).
SNAPSHOT_TIMEOUT_EXIT = 124

# `snapshot list` default budget. `info snapshots` answers in microseconds
# unless QEMU's main loop is still inside a `savevm` that outlived `snapshot
# save --timeout`; the follow-up the timeout hint names passes a long one.
SNAPSHOT_LIST_TIMEOUT = 30.0


def _snapshot_save_timeout(
    args: argparse.Namespace, inst: VMInstance, timeout: float
) -> Result:
    """`snapshot save` outlived its budget: the result is UNKNOWN, not failed.

    HMP `savevm` runs synchronously on QEMU's main loop, so a save that was
    still writing when the budget expired keeps writing; it usually lands
    minutes later, and every QMP command until then queues behind it (#73).
    Reporting that as exit 4 `timed out` told the reader the transport broke
    and the snapshot was lost — both false. The envelope says what is known
    (`may_have_landed: true`) and names the one command that settles it with
    a budget that will outlast the save.
    """
    follow_up = max(2 * timeout, 300.0)
    error = (
        f"snapshot save '{args.name}' on VM '{inst.vm_id}' did not finish within "
        f"{timeout:g}s; QEMU is probably still writing it, so the result is "
        "unknown and every QMP command queues behind it until it completes"
    )
    hint = (
        f"qmu snapshot list --vm {inst.vm_id} --timeout {follow_up:g} waits for "
        f"QEMU to answer and shows whether '{args.name}' landed. Do not retry the "
        f"save until it does; next time pass qmu snapshot save {args.name} --vm "
        f"{inst.vm_id} --timeout {follow_up:g}."
    )
    data = {
        "ok": False,
        "error": error,
        "error_type": _SNAPSHOT_ERROR_TYPE,
        "vm_id": inst.vm_id,
        "name": args.name,
        "timeout": timeout,
        "may_have_landed": True,
        "hint": hint,
    }
    return Result(
        data=data,
        text=[
            error,
            "The snapshot may have landed (may_have_landed: true).",
            hint,
        ],
        stem="snapshot-save",
        exit_code=SNAPSHOT_TIMEOUT_EXIT,
        refusal=True,
    )


def _snapshot_failure_hint(name: str, vm_id: str, result: SnapshotResult) -> str:
    """The machine-readable fix for a failed snapshot op (envelope `hint`).

    The skill's exit-code table tells agents to "read the `hint`" on exit 1,
    and `SnapshotError` was the one error envelope without one: a typo'd tag
    said only `does not exist in one or more devices` (HMP wording) and left
    the reader to guess that `qmu snapshot list` is the next command.
    """
    reason = result.reason
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
    if reason == "usage":
        # HMP's parser refused the line before the command ran (#239).
        command = missing_argument_command(result.message) or "loadvm"
        return (
            f"HMP `{command}` needs a snapshot name; QEMU refused the line before "
            f"running it, so nothing was touched. Name the tag: qmu monitor "
            f"'{command} <tag>' --vm {vm_id}; list the tags: qmu snapshot list "
            f"--vm {vm_id}"
        )
    if reason == "drive":
        # QEMU names the drive it refused; the snapshot table is empty by
        # construction here, so pointing at it moved nobody forward (#153).
        match = UNSNAPSHOTTABLE_DRIVE_RE.search(result.message)
        device = match.group("device") if match else "?"
        return (
            f"Drive '{device}' is writable but its format (e.g. raw) cannot "
            "hold internal snapshots, and savevm/loadvm need every writable "
            "drive to. Relaunch with snapshot=on (checkpoints last the "
            "session) or readonly=on added to that drive's -drive spec "
            "(--drive or [machine] extra_args), or convert the image to qcow2 "
            f"(qemu-img convert -O qcow2) for durable snapshots. qmu monitor "
            f"'info block' --vm {vm_id} maps '{device}' to its file."
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


def _loadvm_failure_hint(name: str, vm_id: str, result: SnapshotResult) -> str:
    """The `hint` for a failed `loadvm`, on every route that reaches one.

    A load that may have reverted the disks gets the no-`cont` recovery
    (#87). A pre-restore refusal of a running guest left it stopped in
    `restore-vm` only when qmu's resume failed too; that stop is safe to
    resume, but plain `qmu cont` refuses the state (it cannot tell this
    stop from a failed mid-restore), so the hint names `--force` (#206).
    """
    if result.restore_state in ("partial", "unknown"):
        return _inconsistent_restore_hint(vm_id, result)
    hint = _snapshot_failure_hint(name, vm_id, result)
    if result.guest_paused:
        # The stuck pause is the more urgent fix; it leads the hint.
        return (
            "loadvm left the guest paused and qmu could not resume it. Nothing "
            "was restored, so resuming is safe: qmu cont --vm "
            f"{vm_id} --force (QEMU reports restore-vm, which plain qmu cont "
            f"refuses). Then: {hint}"
        )
    return hint


def _snapshot_result(
    args: argparse.Namespace,
    op: str,
    inst: VMInstance,
    result: SnapshotResult,
) -> Result:
    """One snapshot outcome. A failure carries `error` + `error_type`
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
        return Result(data=data, text=text, stem=stem)
    error = f"snapshot {op} failed: {result.message}"
    hint = _snapshot_failure_hint(args.name, inst.vm_id, result)
    notes: list[str] = []
    if op == "load":
        hint = _loadvm_failure_hint(args.name, inst.vm_id, result)
        if result.resumed and result.restore_state not in ("partial", "unknown"):
            notes.append(
                "loadvm paused the guest before failing; qmu resumed it "
                "(resumed: true)."
            )
    data = {
        "ok": False,
        "error": error,
        "error_type": _SNAPSHOT_ERROR_TYPE,
        "vm_id": inst.vm_id,
        "name": args.name,
        "hint": hint,
    }
    if op == "load":
        data["resumed"] = result.resumed
        data["guest_paused"] = result.guest_paused
        data["restore_state"] = result.restore_state
    elif op == "save":
        # Proven: `save_snapshot` cross-checks `info snapshots`. The one save
        # outcome that is NOT proven — the budget expired — is exit 124 with
        # `may_have_landed: true` (`_snapshot_save_timeout`).
        data["may_have_landed"] = False
    return _refusal(data=data, text=[error, *notes, hint], stem=stem)


def _handle_snapshot_save(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "snapshot save")
    timeout = getattr(args, "timeout", None)
    if timeout is None:
        timeout = savevm_timeout(inst.memory)
    # A master alive at savevm time is frozen into the image as an established
    # guest sshd session that every later load resurrects as an orphan; close
    # it first so the checkpoint carries no half-open connection.
    inst = _sever_sessions(inst, "snapshot save")
    stop = _SaveStop(inst, "snapshot save")
    try:
        with _qmp_ctx(inst) as qmp:
            # QEMU's run state across the save decides what the image holds
            # of the debugger's breakpoints (#188): read on both sides, since
            # savevm resumes a running guest before it returns. The bridge
            # `qmu gdb` spawned is stopped for the save (#201).
            stop.begin(qmp, _status_before_save(qmp, inst))
            result = stop.save(lambda: save_snapshot(qmp, args.name, timeout=timeout))
            after = (
                _qemu_status(qmp) if result.ok and debug_stub_present(inst) else None
            )
            drive = stop.finish(after, result.ok)
    except QMPTimeoutError:
        # The client has already closed its socket (`QMPClient.execute`), so
        # the next command connects fresh instead of reading savevm's late
        # reply as its own answer.
        return _snapshot_save_timeout(args, inst, timeout).warn(*stop.left_stopped())
    except BaseException:
        stop.record_on_failure()
        raise
    res = _snapshot_result(args, "save", inst, result)
    res = res.warn(*stop.warnings)
    if drive is not None:
        res = _with_drive(res, drive)
    if res.exit_code != 0:
        if result.reason not in ("bad_name", "drive"):
            res = res.warn(
                "[qmu] qmu's implicit rootfs uses a temporary snapshot=on overlay; "
                "that overlay can hold in-session checkpoints with a raw or qcow2 base, "
                "and those checkpoints disappear when QEMU exits. For durable internal "
                "snapshots, attach a writable qcow2 drive without snapshot=on, for example "
                "`--drive 'file=./rootfs.qcow2,format=qcow2'`. Changing [drive] format "
                "alone remains temporary because qmu still adds snapshot=on.\n"
            )
        return res
    # #45/#188: under KVM a debugger's software breakpoints are int3 bytes in
    # guest RAM whenever GDB has the target running, and a save freezes them
    # into the image: a later `snapshot load` + run Oopses at the breakpointed
    # address and reads as the PoC crashing the kernel. A save at a debugger
    # stop is clean (GDB lifts them while stopped), so the warning only fires
    # when qmu could not confirm one, and names the save-at-a-stop recovery.
    # Gated on the STUB, not a live client: bytes an uncleanly-detached bridge
    # left behind (the #40 case) are captured too. Only a successful save
    # wrote an image.
    state, line = stop.coherence
    if state is not None:
        res = replace(res, data={**res.data, **stop.image_keys()})
    if line is not None:
        res = res.warn(line)
    return res


def _snapshot_load_mentions_slirp(msg: str) -> bool:
    return "slirp" in msg.lower()


def _persist_epoch(inst: VMInstance, offset: int) -> VMInstance:
    """Record the guest generation a qmu command just started, everywhere.

    The record serves the standalone readers; the daemon's watch serves the
    daemon-backed ones and does not re-read the record. `loadvm` emits no
    QMP RESET, so without the hand-off `status`/`list` kept scoping the guest
    axis to the pre-load generation while `qmu crash` used the record (#135).
    """
    inst = save_guest_epoch_serial_offset(inst, offset)
    daemon_client.adopt_epoch(inst.vm_id, offset)
    return inst


def _handle_snapshot_load(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "snapshot load")
    epoch_offset = serial_log_offset(inst.serial_log)

    def sever() -> None:
        # Only once `loadvm` is about to run: a tag the pre-check refuses
        # mutates nothing, so it must not cut the commands in flight either
        # (review of #221: a refused load cut an exec whose process then
        # ran on, while the exec said it had been rewound away).
        nonlocal inst
        inst = _sever_sessions(inst, "snapshot load")

    with _qmp_ctx(inst) as qmp:
        result = load_snapshot(qmp, args.name, before_restore=sever)
    if result.ok:
        inst = _persist_epoch(inst, epoch_offset)
        inst = _sever_sessions(inst, "snapshot load")
    rewound = result.ok or result.restore_state != "none"
    if rewound and debug_stub_present(inst):
        # The restored guest prints no boot banner; the debugger is told
        # about this generation below, so a later reboot is the next news.
        inst = mark_debugger_epoch(inst, epoch_offset)
    res = _snapshot_result(args, "load", inst, result)
    if res.exit_code != 0:
        if _snapshot_load_mentions_slirp(result.message):
            res = res.warn(
                "[qmu] This loadvm error names slirp. The user backend often works for "
                "in-session restore, but this QEMU/build/device combination could not "
                "restore its network state. Use native passt networking only with a selected "
                "QEMU that advertises native '-netdev passt' (documented since QEMU 10.1 but "
                "may be build-optional), or use a manually managed external passt process "
                "with QEMU's stream backend. qmu does not manage that external process.\n"
            )
        # A load that got as far as reverting the disks also reset the
        # machine (`qemu_system_reset(SHUTDOWN_CAUSE_SNAPSHOT_LOAD)` precedes
        # the vmstate load), so the #44 divergence applies to it as well —
        # but nothing may drive the debugger now: a continue, a re-sync or a
        # detach can resume the half-restored machine, qmu's own bridge
        # included.
        if rewound and debug_session_present(inst):
            res = res.warn(loadvm_failed_restore_warning(inst) + "\n")
        return res
    # #44: loadvm rewound the guest, but an attached debugger keeps its pre-load
    # stop reason and breakpoint bookkeeping and never re-syncs — a silent
    # divergence in the rewind-iterate fast path. A pre-restore refusal
    # (`restore_state: none`) did not rewind. The bridge `qmu gdb` spawned,
    # while it holds the stub, is re-synced (#187); any other client is only
    # warned about.
    if qmu_bridge_attached(inst):
        return _with_drive(
            res,
            drive_bridge_after_loadvm(
                inst, "snapshot load", run_state=_run_state_reader(inst)
            ),
        )
    if debug_session_present(inst):
        res = res.warn(loadvm_stale_session_warning(inst) + "\n")
    return res


def _with_drive(res: Result, drive: BridgeDrive) -> Result:
    """`res` carrying what qmu did to its bridge: the envelope's `debugger`,
    the text receipt as stderr notes, and any warning."""
    data = {**res.data, "debugger": drive.data} if isinstance(res.data, dict) else res.data
    return replace(res, data=data, notes=res.notes + drive.notes).warn(*drive.warnings)


def _handle_snapshot_list(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "snapshot list")
    timeout = getattr(args, "timeout", None)
    if timeout is None:
        timeout = SNAPSHOT_LIST_TIMEOUT
    qmp = _qmp_ctx(inst)
    # Set before connecting: the greeting is where a QEMU still inside
    # `savevm` makes a caller wait, so the budget covers connect and reply.
    qmp.greeting_timeout = timeout
    with qmp as client:
        snaps = list_snapshots(client, timeout=timeout)
    if not snaps:
        text: str | list[str] = "No snapshots."
    else:
        lines = ["Snapshots:"]
        for s in snaps:
            lines.append(f"  {s['id']}  {s['tag']}  size={s['vm_size']}  {s['date']} {s['time']}")
        text = lines
    return Result(data={"ok": True, "snapshots": snaps}, text=text, stem="snapshot-list")


def _handle_snapshot_delete(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "snapshot delete")
    with _qmp_ctx(inst) as qmp:
        result = delete_snapshot(qmp, args.name)
    return _snapshot_result(args, "delete", inst, result)


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
        description=(
            "Read the guest runtime kernel base and KASLR slide over SSH "
            "(/proc/kallsyms) and print eval-able KBASE, LINK_BASE and SLIDE. "
            "A halted guest is refused before SSH, and a debugger stop while "
            "kallsyms is read (a breakpoint the read or its login trips) is "
            "reported within about 1 s, as exec, compile, push, pull and dmesg "
            "report one: exit 1, guest_state paused, qemu_status, the resume "
            "hint. Every refusal goes to stderr, so eval \"$(qmu kbase ...)\" "
            "stays a no-op."
        ),
    )
    p.add_argument(
        "--symbols",
        required=True,
        help="Path to the matching vmlinux ELF",
    )
    _add_common_opts(p)
    p.set_defaults(handler=_handle_kbase)


def _handle_kbase(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "kbase")
    _require_ssh(inst)

    if (refused := _preflight_ssh_guest(inst, stem="kbase")) is not None:
        return refused

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
    # #234: the same watch as every other SSH command. A breakpoint the read
    # (or sshd setting up its session: `commit_creds`) trips halts the vCPU
    # with no serial output, and the bare read sat out its 10 s budget into
    # exit 4 "SSH command timed out" with a transport hint. Lazy: `guest` is
    # a sibling command module.
    from .guest import _explain_lost_transport, _guest_abort_watcher

    start_offset = serial_log_offset(inst.serial_log)
    watcher = _guest_abort_watcher(inst, start_offset=start_offset)
    try:
        rc, stdout, stderr = ssh.run(_KALLSYMS_QUERY, timeout=10.0, abort_when=watcher)
    except SSHError:
        explained = _explain_lost_transport(
            _KALLSYMS_QUERY, inst, start_offset=start_offset,
            halted_status=watcher.halted_status,
        )
        if explained is None:
            raise
        # The paused (exit 1) or panic (exit 3) envelope, with the prose on
        # stderr: stdout stays empty, so `eval "$(qmu kbase ...)"` is a no-op.
        exit_code, data, text = explained
        return Result(data=data, text=text, stem="kbase", exit_code=exit_code, refusal=True)
    if rc != 0:
        diagnostic = (stderr or stdout or "no diagnostic").strip()
        raise QMUError(
            f"failed to read guest /proc/kallsyms (exit {rc}): {diagnostic}",
            hint=f"qmu status --vm {inst.vm_id}; qmu log --vm {inst.vm_id} --tail 50",
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
    return Result(
        data=data,
        text=(
            f"KBASE={data['kbase']}\n"
            f"LINK_BASE={data['link_base']}\n"
            f"SLIDE={data['slide']}"
        ),
        stem="kbase",
    )


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


def _handle_gdb(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "gdb")
    if inst.gdb_port is None:
        raise QMUError(
            "VM was launched without --gdb. Relaunch with: qmu launch --gdb --kernel ...",
            hint=f"qmu kill --vm {inst.vm_id}; qmu launch --gdb --name {inst.vm_id} --no-replace",
        )

    pry = shutil.which("pry")
    if not pry:
        raise QMUError(
            "pry not found in PATH. Install pry and ensure it is on PATH.",
            hint="which pry; install pry or add it to PATH, then re-run qmu gdb",
        )

    # #40 / debug audit D4: the QEMU gdbstub serves ONE client. A second
    # `pry launch` against an attached stub blocks until the 15 s cap, exits 4
    # with a raw TimeoutExpired, and leaks a bridge per attempt. Refuse up
    # front when a client is positively attached; "cannot tell" (None) falls
    # through so an unreadable /proc never locks the debugger out.
    attached = gdb_client_attached(inst)
    if attached is True:
        if qmu_bridge_attached(inst):
            detach = f"pry kill --instance {inst.gdb_bridge_pid}"
            raise QMUError(
                f"A debugger client is already attached to port {inst.gdb_port}"
                f" (pry bridge pid {inst.gdb_bridge_pid}). Reuse it, or detach "
                f"with: {detach}",
                hint=f"pry --instance {bridge_instance_id(inst.vm_id)} (reuse) or {detach}",
            )
        # #186: the client is not the bridge qmu spawned (whose process would
        # own the client end of the connection), so `qmu-<vm>` does not reach
        # it; offering that name sent the reader to `No running GDB bridge
        # instance named …`, or to qmu's own bridge after it disconnected.
        # `pry info target` shows which bridge holds the port.
        find = (
            "pry doctor lists the bridges; `pry --instance <pid> info target` "
            f"shows the one on remote localhost:{inst.gdb_port}"
        )
        ours = (
            f"the bridge `qmu gdb` spawned for this VM (pid {inst.gdb_bridge_pid}) "
            "is alive but not connected to the stub, so its qmu name does not "
            "reach the client"
            if bridge_alive(inst)
            else "no bridge `qmu gdb` spawned is alive for this VM, so there is "
            "no qmu-named instance to reuse"
        )
        raise QMUError(
            f"A debugger client is already attached to port {inst.gdb_port}, "
            f"and it is not a bridge `qmu gdb` spawned ({ours}). Reuse the "
            "client under its own pry name, or detach with: pry kill --instance "
            "<pid> (list pids with: pry doctor)",
            hint=f"{find}; reuse it with pry --instance <pid>, or detach it with pry kill --instance <pid>",
        )
    # A recorded bridge that is alive while NO client is attached is the #40
    # stranded case (its stub died under it, or it dropped the connection).
    # It still holds this VM's instance-id, so pry would refuse the launch;
    # reap it first. Only on a positive "not attached" — on None the bridge
    # may be live and talking.
    if attached is False and bridge_alive(inst):
        reap_bridge(inst)

    instance_id = bridge_instance_id(inst.vm_id)
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
            f"ESTABLISHED socket on port {inst.gdb_port}.",
            hint=f"pry doctor; ss -tnp | grep :{inst.gdb_port}",
        ) from None
    if result.returncode != 0:
        raise QMUError(
            f"pry launch failed: {_pry_launch_error(result)}",
            hint=(
                f"pry doctor; qmu log --vm {inst.vm_id} --tail 50; then re-run "
                f"qmu gdb --vm {inst.vm_id}"
            ),
        )

    bridge_pid = _pry_launch_pid(result)
    inst = replace(
        inst,
        gdb_bridge_pid=bridge_pid,
        gdb_bridge_pid_start=proc_pid_start(bridge_pid) if bridge_pid else None,
    )
    save_instance(inst)
    # The new client sees the guest as it is now; only a reboot after this
    # is news to it (#184).
    inst = mark_debugger_attached(inst)

    # H4: attaching to the gdb stub HALTS the vCPU. Until it is resumed every
    # SSH command (exec/push/pull/compile) refuses with exit 1. The resume is
    # the bridge's: `qmu cont` resumes QEMU behind GDB's back, which still
    # believes the target stopped and halts it again on its next command
    # (#225).
    warning = (
        "WARNING: the vCPU is now HALTED by the debugger. SSH commands (exec/"
        "push/pull/compile) fail fast with exit 1 until you resume it. Resume "
        f"through the debugger: `pry --instance {instance_id} continue "
        "--background` (GDB inserts its breakpoints when it resumes). Not `qmu "
        "cont`: it resumes QEMU behind GDB's back, and GDB, still believing the "
        "target stopped, halts it again on its next command (`pry status` "
        "included)."
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
            "addresses; qmu gdb did not apply runtime rebasing. Rebase with no SSH "
            f"once the kernel has booted: `pry --instance {instance_id} kbase` "
            "validates the running kernel's base against this vmlinux and rebases "
            "it (it exits 1 rather than guess). Or obtain the runtime base with "
            f"`qmu kbase --vm {inst.vm_id} --symbols {symbols_path}` (SSH: resume "
            f"with `pry --instance {instance_id} continue --background` first), "
            f"then reload with `pry --instance {instance_id} load {symbols_path} "
            "--base <KBASE>`."
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
    # it and stderr stays clean. `kvm` itself is always present with the
    # recorded value, exactly as `launch`/`status`/`list` report it (#134).
    data["kvm"] = getattr(inst, "kvm", None)
    if data["kvm"] is True:
        kvm_warning = kvm_watchpoint_warning(inst.vm_id)
        data["kvm_watchpoint_warning"] = kvm_warning
        text = f"{text}\n{kvm_warning}"
    return Result(data=data, text=text, stem="gdb")


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


# How long `cont` gives a vCPU resumed from a gdbstub stop before it trusts a
# `running` answer: an orphaned int3 halts it again within microseconds, but
# QEMU may answer the `query-status` right behind the `cont` first (#237).
_CONT_SETTLE_SECONDS = 0.25


def _handle_cont(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "cont")
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
            return _refusal(data=data, text=text, stem="cont")
        # Resume the guest. QMP "cont" returns {} on success; if the VM is
        # already running QEMU raises an error, which surfaces as QMPError.
        qmp.execute("cont")
        status = qmp.execute("query-status")
        if before_state == "debug" and _halted(status) is None:
            time.sleep(_CONT_SETTLE_SECONDS)
            status = qmp.execute("query-status")
    run_state = (
        status.get("status", "unknown") if isinstance(status, dict) else str(status)
    )
    halted = _halted(status)
    if halted is not None:
        # #237: QEMU took the `cont` and the vCPU is halted again — an int3
        # nobody owns re-runs at once. That is not a resume.
        data, text = _stopped_guest_payload(inst, halted)
        data["status"] = run_state
        data["resumed"] = False
        lead = (
            f"VM '{inst.vm_id}' did not stay resumed: QEMU took the cont, and "
            f"the vCPU halted again at once (status: {run_state})."
        )
        data["hint"] = f"{lead} {data['hint']}"
        return _refusal(data=data, text=[lead, *text], stem="cont")
    data = {"ok": True, "vm_id": inst.vm_id, "status": run_state}
    text = f"VM '{inst.vm_id}' resumed (status: {run_state})"
    if before_state == "restore-vm":
        data["forced"] = True
        text += " — forced out of restore-vm; the machine state may be inconsistent"
    result = Result(data=data, text=text, stem="cont")
    # #225: a stop a debugger holds is the debugger's to resume.
    behind = cont_behind_debugger_warning(inst, before_state)
    if behind is not None:
        result = result.warn(behind)
    elif orphaned_breakpoint_stop(inst, before_state):
        result = result.warn(orphaned_cont_warning(inst))
    return result


def _halted(status: object) -> str | None:
    """QEMU's status word when a `query-status` reply says the vCPUs are not
    running, else None (running, or no answer to judge by) — the rule
    `_cliutil._qmp_stopped_status` applies to the SSH commands."""
    if not isinstance(status, dict) or status.get("running") is True:
        return None
    name = status.get("status")
    if status.get("running") is False:
        return name if isinstance(name, str) else "paused"
    return name if isinstance(name, str) and name != "running" else None


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


def _hmp_error(
    command_line: str, output: str, *, vm_id: str | None = None,
    loadvm: SnapshotResult | None = None,
) -> QMUError:
    """The exit-1 error for HMP result text that is itself a failure report.

    `qmu monitor nonsense-cmd` and `qmu qmp human-monitor-command` used to
    exit 0 / ok:true with "unknown command: 'nonsense-cmd'" inside the
    payload (snapshot audit D8); `ok` must mean what it says. A failed raw
    `loadvm` (`loadvm`: what `settle_loadvm` made of it) carries what
    `snapshot load` reports for the same failure — `restore_state`,
    `resumed`, `guest_paused` and the same hint — so the two routes give one
    answer (#206).
    """
    message = f"HMP command {command_line!r} failed: {output.strip()}"
    if loadvm is None:
        return QMUError(message, vm_id=vm_id)
    if loadvm.restore_state != "none":
        # Past the tag check loadvm reverts the disks before loading the
        # vmstate; a `cont` here runs the inconsistent result (#87).
        message += (
            " (loadvm may have failed after restoration began: the disks "
            "may be rewound under device state that is not. Do not `qmu "
            "cont` it; load a known-good snapshot or `qmu kill` and relaunch)"
        )
    elif loadvm.resumed:
        message += (
            " (loadvm paused the guest before it refused; nothing was restored, "
            "and qmu resumed it)"
        )
    elif loadvm.guest_paused:
        message += (
            " (loadvm paused the guest before it refused, and qmu could not "
            "resume it; nothing was restored)"
        )
    tokens = command_line.split()
    return QMUError(
        message,
        hint=_loadvm_failure_hint(
            tokens[1] if len(tokens) > 1 else "<tag>", vm_id or "<vm_id>", loadvm
        ),
        vm_id=vm_id,
        fields={
            "restore_state": loadvm.restore_state,
            "resumed": loadvm.resumed,
            "guest_paused": loadvm.guest_paused,
        },
    )


# HMP verbs / QMP methods that replace the guest's running state. Each needs
# the same bookkeeping the dedicated `snapshot load` handler does, whichever of
# the three raw routes (`qmu monitor`, `qmu qmp system_reset`,
# `qmu qmp human-monitor-command`) reached it.
_TCP_RESETTING_VERBS = frozenset({"system_reset", "loadvm"})


def _before_mutation(inst: VMInstance, verb: str) -> tuple[VMInstance, int | None]:
    """Pre-mutation bookkeeping; returns the (session-severed) instance and
    the serial epoch to persist on success.

    A qmu-issued `system_reset` used to leave `guest_epoch_serial_offset`
    untouched, so `wait --pattern 'login:'` matched the previous boot in
    0.00 s (snapshot audit D5) — the epoch only advanced on a RESET that
    `wait` itself observed. Capturing the log size here, before the reset
    lands, is exactly what `snapshot load` does.
    """
    if verb in _TCP_RESETTING_VERBS:
        inst = _sever_sessions(inst, verb)
        return inst, serial_log_offset(inst.serial_log)
    if verb == "savevm":
        inst = _sever_sessions(inst, verb)
    return inst, None


def _status_after_mutation(qmp: object, inst: VMInstance, verb: str) -> str | None:
    """QEMU's run state right after a raw `savevm`/`system_reset` on a `--gdb` VM.

    Asked on the same connection. After a savevm it is the second half of
    the bracket `breakpoints_in_image` needs (#188); after a reset it tells a
    guest that is booting from one left halted at the reset vector.
    """
    if verb not in ("savevm", "system_reset") or not debug_stub_present(inst):
        return None
    return _qemu_status(qmp)


def _after_mutation(
    inst: VMInstance, verb: str, output: str, epoch: int | None,
    warnings: list[str],
    status_after: str | None = None,
    drives: list[BridgeDrive] | None = None,
) -> VMInstance:
    """Post-mutation bookkeeping plus the debugger coherence step.

    One switch for all three raw routes. The `human-monitor-command` one was
    silent (dogfood F4): it reset the machine with an attached debugger, rc 0
    and an empty stderr, which is precisely the wrong-answer-with-no-error
    class debug.py exists to prevent. savevm/loadvm suppress on a failed op
    (the same classifier the snapshot handlers use), since a failed op
    landed still needs. A reset or load under the bridge `qmu gdb` spawned,
    while it holds the stub, drives it (#187) and appends what it did to
    `drives`; any other client gets the coherence warning in `warnings`. Both
    are filled even when the persist raises, so the caller can put them on
    its Result: stderr in every mode and the envelope's `warnings[]` (#74).
    `status_after` is QEMU's run state right after a reset. A savevm's
    coherence is decided by `_SaveStop` while the save is bracketed.
    """
    if drives is None:
        drives = []
    failed = verb in ("savevm", "loadvm") and _snapshot_failed(output)
    persist_error: OSError | None = None
    if verb in _TCP_RESETTING_VERBS and not failed:
        if epoch is not None:
            try:
                inst = _persist_epoch(inst, epoch)
            except OSError as exc:
                persist_error = exc
        inst = _sever_sessions(inst, verb)
        if debug_stub_present(inst):
            # The warning below tells the debugger about this generation; a
            # reset's boot banner is still to come and belongs to it (#184).
            start = epoch if epoch is not None else serial_log_offset(inst.serial_log)
            inst = mark_debugger_epoch(
                inst, start, banners=1 if verb == "system_reset" else 0
            )
    owned = (
        verb in _TCP_RESETTING_VERBS and not failed and qmu_bridge_attached(inst)
    )
    if verb == "system_reset":
        if owned:
            drives.append(
                drive_bridge_after_reset(
                    inst, epoch=epoch, qemu_status=status_after,
                    run_state=_run_state_reader(inst),
                )
            )
        elif debug_session_present(inst):
            warnings.append(
                reset_dropped_breakpoints_warning(inst, qemu_status=status_after) + "\n"
            )
    elif verb == "loadvm":
        if owned:
            drives.append(
                drive_bridge_after_loadvm(inst, "loadvm", run_state=_run_state_reader(inst))
            )
        elif debug_session_present(inst) and not failed:
            warnings.append(loadvm_stale_session_warning(inst) + "\n")
    if persist_error is not None:
        raise persist_error
    return inst


def _finish_mutation(
    inst: VMInstance,
    verb: str,
    output: str,
    epoch: int | None,
    *,
    data: dict[str, object],
    text: object,
    stem: str,
    call: _RawCall,
) -> Result:
    """Post-mutation bookkeeping, THEN exactly one envelope.

    `_after_mutation` persists the guest epoch, and that write can fail
    (an instance dir the operator chmod'ed, a full disk). The guest mutation
    has already landed by then, so the honest report is a single `ok:false`
    envelope that still carries the QMP result and says the reset happened
    -- never a success envelope followed by a second failure object, which
    is what emitting first produced (#88: exit 4 with two JSON documents on
    stdout, the first of which a consumer could accept as the result).
    Exit 4: the guest did what was asked; qmu's own state is what failed.
    A savevm's envelope carries what the image holds of the debugger's
    breakpoints, as `snapshot save`'s does (#227), and a loadvm's whether
    qmu resumed a guest a previous failed load had left stopped (#206).
    """
    save_stop = call.save_stop
    if save_stop is not None:
        data = {**data, **save_stop.image_keys()}
    if call.loadvm is not None:
        data = {**data, "resumed": call.loadvm.resumed}
    warnings: list[str] = []
    drives: list[BridgeDrive] = []
    try:
        _after_mutation(inst, verb, output, epoch, warnings, call.status_after, drives)
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
        res = Result(
            data={
                **data,
                "ok": False,
                "error": error,
                "error_type": exc.__class__.__name__,
                "guest_mutated": True,
                "hint": hint,
            },
            text=[error, hint],
            stem=stem,
            exit_code=4,
            refusal=True,
        ).warn(*warnings)
    else:
        res = Result(data=data, text=text, stem=stem).warn(*warnings)
    if call.loadvm is not None and call.loadvm.resumed:
        res = replace(res, notes=res.notes + (
            "[qmu] The guest was stopped by a previous failed load (restore-vm); "
            "qmu resumed it (resumed: true).",
        ))
    if save_stop is not None:
        _, line = save_stop.coherence
        res = res.warn(*save_stop.warnings, *([line] if line is not None else []))
        drives.extend([save_stop.drive] if save_stop.drive is not None else [])
    for drive in drives:
        res = _with_drive(res, drive)
    return res


@dataclass(frozen=True)
class _RawCall:
    """What a raw route's QMP/HMP call did: QEMU's `result`, the run state
    right after a reset (`status_after`), the savevm bracket (`save_stop`)
    and a loadvm's settled outcome (`loadvm`)."""

    result: object
    status_after: str | None = None
    save_stop: _SaveStop | None = None
    loadvm: SnapshotResult | None = None


def _raw_mutation(qmp: object, inst: VMInstance, verb: str, run) -> _RawCall:
    """A raw route's QMP/HMP call `run()`.

    QEMU's run state after a reset tells a booting guest from one left
    halted at the reset vector. A savevm is bracketed by the run state on
    both sides (#188), with the bridge `qmu gdb` spawned stopped across it
    (#201), exactly as `snapshot save` does. A loadvm is settled the way
    `snapshot load` settles it (`settle_loadvm`): `hmp_loadvm` stops a
    running guest before it looks for the tag, so a refused tag is resumed
    here too instead of being left in `restore-vm` (#206)."""
    if verb == "loadvm":
        was_running, run_state = guest_run_state(qmp)
        result = run()
        if not isinstance(result, str):
            return _RawCall(result)
        return _RawCall(result, loadvm=settle_loadvm(qmp, result, was_running, run_state))
    if verb != "savevm":
        result = run()
        return _RawCall(result, status_after=_status_after_mutation(qmp, inst, verb))
    stop = _SaveStop(inst, "savevm")
    try:
        stop.begin(qmp, _status_before_save(qmp, inst))
        result = stop.save(run)
    except BaseException:
        stop.record_on_failure()
        raise
    landed = not (isinstance(result, str) and hmp_failed(result))
    stop.finish(_status_after_mutation(qmp, inst, verb), landed)
    return _RawCall(result, save_stop=stop)


def _handle_qmp(args: argparse.Namespace) -> Result:
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
    inst = _choose_running(args.vm, "qmp")
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
    inst, epoch = _before_mutation(inst, verb)
    try:
        with _qmp_ctx(inst) as qmp:
            call = _raw_mutation(
                qmp, inst, verb, lambda: qmp.execute(method, qmp_args)
            )
    except QMPCommandError as exc:
        # A QEMU error REPLY, not a transport fault: the wire worked, so this
        # is the exit-1 class whichever error class QEMU chose.
        raise _qmp_caller_error(method, exc) from exc
    result = call.result
    if hmp_line is not None and isinstance(result, str) and hmp_failed(result):
        if call.save_stop is not None:
            call.save_stop.record_on_failure()
        raise _hmp_error(hmp_line, result, vm_id=inst.vm_id, loadvm=call.loadvm)
    # Bookkeeping BEFORE the envelope: the epoch persist can fail (unwritable
    # instance dir), and a success envelope already on stdout cannot be
    # taken back -- `qmu qmp system_reset` printed `ok:true` followed by a
    # second `ok:false` object (#88). Text mode passes the raw QMP return
    # (any JSON type) straight to _output; json mode wraps it so the
    # universal {"ok": ...} contract holds, with the payload under "result".
    return _finish_mutation(
        inst, verb, result if isinstance(result, str) else "", epoch,
        data={"ok": True, "result": result}, text=result, stem="qmp", call=call,
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


def _handle_monitor(args: argparse.Namespace) -> Result:
    inst = _choose_running(args.vm, "monitor")
    command = " ".join(args.command)
    # HMP is a raw escape hatch, so `qmu monitor {system_reset,savevm,loadvm}`
    # reach the same VM-reality mutations as the dedicated handlers / `qmu qmp`
    # but bypass their bookkeeping and coherence warnings. Route through the
    # shared hooks, keyed on the HMP *verb* so e.g. `monitor help system_reset`
    # -- which resets nothing -- is not caught.
    verb = _hmp_verb(command)
    inst, epoch = _before_mutation(inst, verb)
    with _qmp_ctx(inst) as qmp:
        call = _raw_mutation(qmp, inst, verb, lambda: qmp.execute_hmp(command))
    result = call.result
    if hmp_failed(result):
        if call.save_stop is not None:
            call.save_stop.record_on_failure()
        raise _hmp_error(command, result, vm_id=inst.vm_id, loadvm=call.loadvm)
    return _finish_mutation(
        inst, verb, result, epoch,
        data={"ok": True, "output": result},
        text=result if result.strip() else "(no output)",
        stem="monitor", call=call,
    )
