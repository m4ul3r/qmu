from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from .qmp import QMPClient, QMPError, hmp_failed


@dataclass(frozen=True)
class SnapshotResult:
    """Outcome of one HMP snapshot operation.

    `message` is the HMP text verbatim when QEMU printed any, else a
    synthesized success line. The run-state fields only ever apply to a
    load: QEMU's `hmp_loadvm` stops the guest (`restore-vm`) before it
    looks for the tag and only restarts it on success -- and then only if it
    was running before -- so a refused name leaves a previously running guest
    paused with no error saying so. qmu owns the operation and the pre-load
    state, so when the failure provably happened before any restoration it
    resumes the guest (`resumed`) or, if that failed too, says the guest is
    paused (`guest_paused`). When restoration had already begun
    (`restore_state` `partial`) or qmu cannot tell (`unknown`), the disks may
    already be rewound under device state that is not -- QEMU reverts the
    block layer before it loads the vmstate -- so the guest is deliberately
    left paused: a `cont` there runs an inconsistent machine and reported
    `resumed: true` on it (#87). A SUCCESSFUL load that recovers from that
    pause (`restore-vm`) resumes the now-consistent guest (`resumed`).
    """

    ok: bool
    message: str
    resumed: bool = False
    guest_paused: bool = False
    # Why a FAILED operation failed, for the CLI's `hint`: `missing` (no such
    # tag), `bad_name` (HMP parse error), `drive` (a writable drive whose
    # format cannot hold internal snapshots), `hmp` (any other QEMU refusal).
    reason: str | None = None
    # How far a FAILED load got: `none` (QEMU refused before touching the
    # machine), `partial` (QEMU's error text shows restoration had started),
    # `unknown` (an error form qmu cannot place). None for every other op.
    restore_state: str | None = None


def guest_run_state(qmp: QMPClient) -> tuple[bool | None, str | None]:
    """QMP `query-status` as (`running`, `status`); None for what cannot be read."""
    try:
        status = qmp.execute("query-status")
    except QMPError:
        return None, None
    if not isinstance(status, dict):
        return None, None
    running = status.get("running")
    name = status.get("status")
    return (
        running if isinstance(running, bool) else None,
        name if isinstance(name, str) else None,
    )


def guest_running(qmp: QMPClient) -> bool | None:
    """QMP `query-status` `running` flag; None when it cannot be read."""
    return guest_run_state(qmp)[0]


def resume_guest(qmp: QMPClient) -> bool:
    """Issue QMP `cont`; True when the guest is positively running afterwards."""
    try:
        qmp.execute("cont")
    except QMPError:
        return False
    return guest_running(qmp) is True


def snapshot_tags(qmp: QMPClient) -> set[str]:
    return {snap["tag"] for snap in list_snapshots(qmp)}


# QEMU's refusal to snapshot a machine with a writable drive that cannot
# hold internal snapshots (a raw `-drive` without snapshot=on/readonly=on).
# The device name is QEMU's (`virtio1`), not a qmu name.
UNSNAPSHOTTABLE_DRIVE_RE = re.compile(
    r"Device '(?P<device>[^']*)' (is writable but )?does not support snapshots"
)


def _classify_hmp_failure(message: str) -> str:
    """Bucket an HMP savevm/loadvm/delvm error so the CLI can name the fix.

    `missing` — the tag is not in the image (`loadvm` says "does not exist in
    one or more devices"); `bad_name` — HMP could not parse the name as one
    token (whitespace); `drive` — a writable drive cannot hold snapshots
    (`Device 'virtio1' is writable but does not support snapshots`); `hmp` —
    anything else QEMU refused.
    """
    if "does not exist" in message:
        return "missing"
    if "extraneous characters" in message:
        return "bad_name"
    if UNSNAPSHOTTABLE_DRIVE_RE.search(message):
        return "drive"
    return "hmp"


# Default `snapshot save` budget: SAVEVM_BASE_SECONDS + SAVEVM_SECONDS_PER_GIB
# per GiB of guest RAM. HMP `savevm` writes every non-zero guest page into the
# qcow2 synchronously on QEMU's main loop, so its cost is the guest's dirty RAM
# and the host's disk, not a constant. Measured on QEMU 8.2.2 / NVMe with RAM
# fully dirtied (random pages, the worst case): 1 GiB 4.9 s idle host, 3.8-4.1 s
# under 4 concurrent `dd oflag=direct` writers + 10 CPU burners (load 12);
# 4 GiB 15.6 s idle, 22.2 s under that load — i.e. ~5.5 s/GiB loaded. The
# formula keeps >= 3x headroom over the loaded figure at every size (4 GiB:
# 140 s vs 22 s) and starts at the old flat 60 s, which a loaded 4 GiB save
# overran in the field (#73). `--timeout` overrides it.
SAVEVM_BASE_SECONDS = 60.0
SAVEVM_SECONDS_PER_GIB = 20.0

_MEMORY_SIZE_RE = re.compile(
    r"^\s*(?:size=)?(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>[kKmMgGtT])?(?:i?[bB])?\s*(?:,.*)?$"
)


def memory_gib(memory: str | None) -> float | None:
    """Guest RAM in GiB from a QEMU `-m` value (`4G`, `4096M`, `4096`, `size=4G,...`).

    A bare number is MiB, as QEMU reads it. None when the value is not a size
    qmu can read.
    """
    if not memory:
        return None
    m = _MEMORY_SIZE_RE.match(memory)
    if m is None:
        return None
    num = float(m.group("num"))
    unit = (m.group("unit") or "M").upper()
    scale = {"K": 1 / 1024 ** 2, "M": 1 / 1024, "G": 1.0, "T": 1024.0}[unit]
    return num * scale


def savevm_timeout(memory: str | None) -> float:
    """The default `snapshot save` budget for a guest with `memory` of RAM.

    An unreadable size is budgeted as the built-in default of 4 GiB rather
    than as zero: a budget too short reports an unknown result (#73), a
    budget too long only waits.
    """
    gib = memory_gib(memory)
    if gib is None:
        gib = 4.0
    return SAVEVM_BASE_SECONDS + SAVEVM_SECONDS_PER_GIB * gib


def save_snapshot(qmp: QMPClient, name: str, timeout: float = SAVEVM_BASE_SECONDS) -> SnapshotResult:
    """Save a VM snapshot and confirm it is listed afterwards.

    HMP parse errors (`savevm: extraneous characters at the end of line` for
    a name with whitespace) come back as result text with no snapshot written,
    so the result is cross-checked against `info snapshots` rather than
    trusting a reply that merely arrived.

    `timeout` bounds the `savevm` itself (see `savevm_timeout`); when it
    expires `QMPTimeoutError` propagates with the socket closed, and QEMU is
    most likely still writing the snapshot — the caller reports that as an
    unknown result, not as a failure.
    """
    result = qmp.execute_hmp(f"savevm {name}", timeout=timeout).strip()
    if hmp_failed(result):
        return SnapshotResult(False, result, reason=_classify_hmp_failure(result))
    if name not in snapshot_tags(qmp):
        return SnapshotResult(
            False,
            result or f"Snapshot '{name}' is not listed by 'info snapshots' after savevm",
            reason=_classify_hmp_failure(result) if result else "hmp",
        )
    return SnapshotResult(True, result or f"Snapshot '{name}' saved.")


# What QEMU's `load_snapshot()` prints when it refuses BEFORE touching the
# machine (tag lookup, vmstate-device lookup, disk-only check, HMP parse) vs.
# AFTER `bdrv_all_goto_snapshot` has reverted the disks (vmstate open/load,
# the per-device migration failures that precede its summary line). Anchored
# at line starts like `qmp.hmp_failed`. A message is `none` only when EVERY
# line is a pre-restore form; a single post-restore line makes it `partial`;
# anything else is `unknown` and treated as unsafe to resume.
_PRE_RESTORE_LINE_RES = tuple(
    re.compile(pattern)
    for pattern in (
        r"(Error: )?Snapshot '.*' does not exist",
        r"(Error: )?This is a disk-only snapshot",
        r"(Error: )?No block device ",
        r"(Error: )?Device '[^']*' (is writable but )?does not support snapshots",
        r"unknown command: ",
        r"\S+: extraneous characters at the end of line",
        r'Try "help',
    )
)
_POST_RESTORE_LINE_RES = tuple(
    re.compile(pattern)
    for pattern in (
        r"(Error: )?Error -?\d+ while loading VM state",
        r"(Error: )?Could not open VM state file",
        r"(Error: )?Could not load snapshot '",
        r"error while loading state",
        r"Missing section footer",
        r"(Error: )?Section footer error",
        r"Unknown ramblock ",
        r"(Error: )?load of migration failed",
        r"(Error: )?duplicate yank instance",
    )
)


def loadvm_restore_state(message: str) -> str:
    """How far a FAILED `loadvm` got, from its HMP error text.

    `none`: QEMU refused before any restoration, so the machine is exactly
    what it was and resuming it is safe. `partial`: the disks were reverted
    (QEMU does that first) and the vmstate load then failed, so the guest
    now runs pre-snapshot devices over post-snapshot disks. `unknown`: an
    error form this table does not place; resuming it is a guess, and the
    guess that shipped reported `resumed: true` on a machine whose disk had
    just been rewound under a live kernel (#87).
    """
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    if any(p.match(line) for line in lines for p in _POST_RESTORE_LINE_RES):
        return "partial"
    if lines and all(
        any(p.match(line) for p in _PRE_RESTORE_LINE_RES) for line in lines
    ):
        return "none"
    return "unknown"


# QEMU's run state after a `loadvm` that failed past the tag check: qmu leaves
# the guest there on purpose (see `load_snapshot`), so it is the one stopped
# state a later SUCCESSFUL load is entitled to undo.
_FAILED_RESTORE_RUN_STATE = "restore-vm"


def load_snapshot(
    qmp: QMPClient,
    name: str,
    timeout: float = 60.0,
    *,
    before_restore: Callable[[], None] | None = None,
) -> SnapshotResult:
    """Load a VM snapshot; resume the guest only when loadvm provably did
    not start restoring it.

    The tag is checked against `info snapshots` first so the common failure
    (a typo) never reaches `loadvm` at all -- QEMU would stop the guest
    before noticing. What `loadvm` itself answers is settled by
    `settle_loadvm`, which the raw `loadvm` routes share. `before_restore`
    runs once the tag passed that check, right before `loadvm`: the caller's
    side effects of a load (closing the SSH ControlMaster) belong to a load
    that is attempted, never to a refused name.
    """
    if name not in snapshot_tags(qmp):
        return SnapshotResult(
            False,
            f"Snapshot '{name}' does not exist",
            reason="missing",
            restore_state="none",
        )
    if before_restore is not None:
        before_restore()
    was_running, run_state = guest_run_state(qmp)
    result = qmp.execute_hmp(f"loadvm {name}", timeout=timeout)
    return settle_loadvm(
        qmp, result, was_running, run_state, loaded=f"Snapshot '{name}' loaded."
    )


def settle_loadvm(
    qmp: QMPClient,
    result: str,
    was_running: bool | None,
    run_state: str | None,
    *,
    loaded: str = "Snapshot loaded.",
) -> SnapshotResult:
    """The outcome of an HMP `loadvm` that answered `result`, issued from the
    run state `guest_run_state` read just before it.

    `hmp_loadvm` stops the guest (`restore-vm`) before it looks for the tag
    and restarts it only on success, so a failure's error text decides
    (`loadvm_restore_state`): a pre-restore refusal gets the pre-load run
    state back; anything that may have reverted the disks is left paused and
    reported as such, because `cont` on it is not a rollback. Every route
    to `loadvm` -- `snapshot load`, `monitor loadvm`, `qmp
    human-monitor-command` -- settles it here, so a missing tag leaves a
    running guest running on all of them (#206).

    `hmp_loadvm` restarts the guest after a successful load only if it was
    running before, so the recovery that failure's hint names -- load a
    known-good tag -- would otherwise succeed and leave the guest stopped in
    `restore-vm` with no error saying so. A successful load therefore resumes
    a guest stopped in exactly that state (`resumed: true`); a guest the
    operator or a debugger paused (`paused`, `debug`, ...) stays paused.
    """
    result = result.strip()
    if not hmp_failed(result):
        resumed = False
        if was_running is False and run_state == _FAILED_RESTORE_RUN_STATE:
            resumed = resume_guest(qmp)
        return SnapshotResult(True, result or loaded, resumed=resumed)
    restore_state = loadvm_restore_state(result)
    resumed = guest_paused = False
    if restore_state == "none":
        if was_running and guest_running(qmp) is False:
            resumed = resume_guest(qmp)
            guest_paused = not resumed
    else:
        guest_paused = guest_running(qmp) is False
    return SnapshotResult(
        False,
        result,
        resumed=resumed,
        guest_paused=guest_paused,
        reason=_classify_hmp_failure(result),
        restore_state=restore_state,
    )


def delete_snapshot(qmp: QMPClient, name: str, timeout: float = 30.0) -> SnapshotResult:
    """Delete a VM snapshot. HMP `delvm` is silent for a missing tag, so the
    tag is checked against `info snapshots` first."""
    if name not in snapshot_tags(qmp):
        return SnapshotResult(False, f"Snapshot '{name}' does not exist", reason="missing")
    result = qmp.execute_hmp(f"delvm {name}", timeout=timeout).strip()
    if hmp_failed(result):
        return SnapshotResult(False, result, reason="hmp")
    return SnapshotResult(True, result or f"Snapshot '{name}' deleted.")


def list_snapshots(qmp: QMPClient, timeout: float = 30.0) -> list[dict[str, Any]]:
    """List VM snapshots. Returns parsed list.

    `timeout` bounds the `info snapshots` reply; QEMU answers it in
    microseconds unless its main loop is still inside a `savevm` that
    outlived `snapshot save --timeout`, which is exactly when a caller passes
    a long one.
    """
    raw = qmp.execute_hmp("info snapshots", timeout=timeout)
    return parse_snapshot_list(raw)


def parse_snapshot_list(raw: str) -> list[dict[str, Any]]:
    """Parse 'info snapshots' HMP output into structured data.

    Example HMP output:
        List of snapshots present on all disks:
        ID        TAG               VM SIZE                DATE     VM CLOCK     ICOUNT
        --        clean             913 MiB 2026-03-25 23:42:16 00:00:28.552
    """
    # Regex: ID  TAG  SIZE UNIT  DATE  TIME  VM_CLOCK  [ICOUNT]
    snap_re = re.compile(
        r"^\s*(\S+)\s+(\S+)\s+"
        r"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\s*\S+)\s+"  # QEMU's %g size + unit
        r"(\d{4}-\d{2}-\d{2})\s+"                # date
        r"(\d{2}:\d{2}:\d{2})\s+"                # time
        r"(\S+)"                                   # vm_clock
    )
    snapshots: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("List of") or line.startswith("ID"):
            continue
        m = snap_re.match(line)
        if m:
            snapshots.append({
                "id": m.group(1),
                "tag": m.group(2),
                "vm_size": m.group(3).strip(),
                "date": m.group(4),
                "time": m.group(5),
                "vm_clock": m.group(6),
            })
    return snapshots
