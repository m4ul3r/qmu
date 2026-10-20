from __future__ import annotations

import json
import math
import os
import stat
import sys
import tempfile
import time
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from .paths import instance_json_path, instances_dir, qemu_log_path, serial_log_path
from .runtime import probe_unix_socket

_KNOWN_INSTANCE_SUFFIXES = (".serial.log", ".qemu.log", ".qmp.sock", ".json")


class QMUError(RuntimeError):
    """An operational qmu error (exit 1).

    `hint` is an optional recovery step (`qmu log --vm X --tail 50`, "pass
    --ssh-port N") that rides as `hint` in the `{"ok": false}` envelope and,
    in text mode, as a `[qmu] Hint:` line after the error. Subclasses inherit
    the keyword; a subclass that renders its own structured hint
    (`ConfigError`) keeps its own `hint` attribute, which this base reads.
    """

    def __init__(self, *args: object, hint: str | None = None) -> None:
        super().__init__(*args)
        self.hint = hint if hint is not None else getattr(self, "hint", None)


@dataclass(kw_only=True)
class VMInstance:
    vm_id: str
    pid: int
    qmp_socket: str
    ssh_port: int | None
    ssh_key: str | None
    # Defaulted so instance JSON written before ssh_user existed still loads
    # (_instance_from_dict omits the absent key and VMInstance supplies "root").
    ssh_user: str = "root"
    gdb_port: int | None
    serial_log: str
    kernel: str
    # Guest/QEMU architecture recorded at launch. None keeps instance JSON
    # written before this field existed loadable without guessing from the host.
    arch: str | None = None
    rootfs: str | None
    memory: str
    cpus: int
    cmdline: str
    profile: str
    started_at: str
    harness: bool = False
    nic_model: str | None = None
    # Kernel start-time of the QEMU process (jiffies since boot, from
    # /proc/<pid>/stat field 22). Used to detect PID recycling across reboots.
    # Defaulted so instance JSON written before this field existed still loads.
    pid_start: str | None = None
    # Byte offset at which the currently restored guest generation begins.
    # Zero preserves old instance JSON and includes all bytes from a new launch.
    guest_epoch_serial_offset: int = 0
    # How that boundary was learned: "observed" (a QMP RESET the daemon saw,
    # or a snapshot load qmu performed — the log size at the event) or
    # "banner" (the kernel's boot banner, the log-local heuristic a standalone
    # `wait` falls back to). None for a record that never moved its epoch.
    # `status` reports it as `guest_epoch_source` when the daemon serves the
    # VM, so a reader knows whether a reboot was witnessed or inferred.
    guest_epoch_source: str | None = None
    # Whether `cmdline` came from a full override rather than from `profile`.
    # Without this, `status` prints a Profile: whose parameters never reached
    # the kernel, and unknown-param attribution credits a profile that
    # contributed nothing. Defaulted so older instance JSON still loads.
    cmdline_override: bool = False
    # Whether QEMU was launched with `-enable-kvm`. Recorded so a later
    # `qmu gdb` can surface the hardware-watchpoint caveats that apply under KVM
    # (#39) without re-deriving host state that may have changed since launch.
    # None keeps instance JSON written before this field existed loadable
    # (accel unknown).
    kvm: bool | None = None
    # The pry bridge (headless GDB) `qmu gdb` spawned for this VM, with its
    # /proc start-time so a recycled pid is never mistaken for it (#40). qmu
    # owns this process: `kill` reaps it through `debug.reap_bridge` and a
    # second `qmu gdb` names it instead of spawning another. None when no
    # bridge was spawned or the record predates the field.
    gdb_bridge_pid: int | None = None
    gdb_bridge_pid_start: str | None = None
    # Extra host->guest TCP forwards on qmu's own NIC (`--forward`, #149):
    # `{"host", "host_port", "guest_port"}` with the host port as allocated,
    # so `status`/`list` can answer where a guest service is reachable the
    # way they answer `ssh_port`. Empty for records that predate the field.
    forwards: list[dict] = field(default_factory=list)


def _instance_from_dict(data: dict) -> VMInstance:
    """Tolerant constructor: ignore unknown keys (forward compat for old JSON)."""
    known = {f.name for f in fields(VMInstance)}
    return VMInstance(**{k: v for k, v in data.items() if k in known})


def save_instance(inst: VMInstance) -> Path:
    path = instance_json_path(inst.vm_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file in the SAME dir and os.replace() onto the target so a
    # crash mid-write can never leave a truncated .json that makes a live VM
    # vanish from `qmu list`. os.replace is atomic when src/dst share a fs.
    payload = json.dumps(asdict(inst), indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        os.replace(tmp, path)
    except BaseException:
        # Don't litter the instances dir with partial temp files on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path

def save_guest_epoch_serial_offset(
    inst: VMInstance, offset: int, *, source: str = "observed"
) -> VMInstance:
    """Atomically persist an explicitly captured guest-generation boundary."""
    if type(offset) is not int:
        raise TypeError("offset must be an integer")
    if offset < 0:
        raise ValueError("offset must be non-negative")
    updated = replace(inst, guest_epoch_serial_offset=offset, guest_epoch_source=source)
    save_instance(updated)
    return updated


def load_instance(vm_id: str) -> VMInstance | None:
    path = instance_json_path(vm_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return _instance_from_dict(data)
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        # pid 0 signals our own process group; negatives signal a group by id.
        # Neither identifies a single VM process — treat as not alive.
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def proc_pid_start(pid: int) -> str | None:
    """Return the kernel start-time of `pid` (field 22 of /proc/<pid>/stat).

    The comm field (2) is in parentheses and may itself contain spaces or
    parens, so we split on the LAST ')' before tokenizing. Returns None if
    /proc is unavailable (non-Linux) or the process is gone/unreadable.
    """
    if pid <= 0:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    try:
        rest = stat.rsplit(")", 1)[1].split()
        # rest[0] is field 3 (state); field 22 (starttime) is rest[19].
        return rest[19]
    except IndexError:
        return None


def instance_alive(inst: VMInstance) -> bool:
    """Liveness check that guards against PID recycling.

    A recorded pid can be reused by an unrelated process after a reboot (the
    instance JSON outlives the kernel's pid namespace). When the instance has
    a recorded pid_start, require the current /proc start-time to match; if
    /proc is unavailable (non-Linux) or pid_start was never recorded (old
    JSON), fall back to pid-only liveness.
    """
    if inst.pid <= 0:
        return False
    if not is_pid_alive(inst.pid):
        return False
    if inst.pid_start is None:
        return True
    current = proc_pid_start(inst.pid)
    if current is None:
        if not os.path.isdir("/proc"):
            # Non-Linux: /proc not available, cannot verify identity.
            # Fall back to pid-only liveness (already confirmed above).
            return True
        # /proc exists but the stat entry is gone/unreadable: the process
        # most likely exited between the kill(0) probe and this read.
        return False
    return current == inst.pid_start


def _iter_instance_records() -> list[VMInstance]:
    """Read every parseable .json record under instances_dir(). Pure: no filesystem mutation."""
    idir = instances_dir()
    if not idir.exists():
        return []
    out: list[VMInstance] = []
    for p in sorted(idir.glob("*.json")):
        try:
            data = json.loads(p.read_text())
            out.append(_instance_from_dict(data))
        except (json.JSONDecodeError, TypeError, KeyError):
            continue
    return out


def list_instances() -> list[VMInstance]:
    """Return VMInstance records whose process is still alive."""
    return [inst for inst in _iter_instance_records() if instance_alive(inst)]


def list_stopped_instances() -> list[VMInstance]:
    """Return VMInstance records whose process has exited.

    Also surfaces metadata-free remnants (no parseable .json) by synthesizing
    a minimal record — a stale `.serial.log` so users can still recover
    forensics, and equally a `.qemu.log`- or `.qmp.sock`-only bundle. Those
    used to be invisible here while `prune --older-than 0` still removed
    them, so `list`/`status`/`kill` called a remnant absent that `prune`
    then reported pruning (#104). The one discovery (`discover_instance_
    artifacts`) feeds both this and prune eligibility so they cannot drift.
    """
    records = _iter_instance_records()
    stopped = [inst for inst in records if not instance_alive(inst)]
    known_ids = {inst.vm_id for inst in records}

    for bundle in discover_instance_artifacts():
        if bundle.vm_id in known_ids:
            continue
        if bundle.serial_log is None and bundle.qemu_log is None:
            # A lone unparseable .json names nothing qmu can describe or
            # remove, and a lone QMP socket something still answers on is
            # not a stopped VM; both stay absent rather than "held back"
            # with an age-gate explanation that would be false.
            if bundle.qmp_socket is None or not _qmp_safe_to_prune(bundle.qmp_socket):
                continue
        stopped.append(_synthesize_orphan(bundle.vm_id, bundle.serial_log))
    return stopped


def _synthesize_orphan(vm_id: str, log_path: Path | None) -> VMInstance:
    """Build a minimal VMInstance for a remnant that lost its .json.

    `log_path` is None for a bundle with no serial log; the record then
    names the conventional path, which readers already treat as "no log"
    when it does not exist.
    """
    return VMInstance(
        vm_id=vm_id,
        pid=0,
        qmp_socket="",
        ssh_port=None,
        ssh_key=None,
        gdb_port=None,
        serial_log=str(log_path if log_path is not None else serial_log_path(vm_id)),
        kernel="",
        rootfs=None,
        memory="",
        cpus=0,
        cmdline="",
        profile="",
        started_at="",
        harness=False,
        nic_model=None,
    )


@dataclass(frozen=True, kw_only=True)
class InstanceArtifacts:
    vm_id: str
    instance: VMInstance | None
    invalid_json: bool
    json_path: Path | None
    qmp_socket: Path | None
    serial_log: Path | None
    qemu_log: Path | None


def _match_known_suffix(name: str) -> tuple[str, str] | None:
    """Return (vm_id, suffix) for the longest known exact suffix, else None."""
    for suffix in _KNOWN_INSTANCE_SUFFIXES:
        if name.endswith(suffix):
            vm_id = name[: -len(suffix)]
            if vm_id:
                return vm_id, suffix
    return None


def _is_discoverable_instance_node(mode: int, suffix: str) -> bool:
    """Accept regular files; also accept Unix sockets for the QMP suffix."""
    if stat.S_ISLNK(mode) or stat.S_ISDIR(mode):
        return False
    if stat.S_ISREG(mode):
        return True
    return suffix == ".qmp.sock" and stat.S_ISSOCK(mode)


def discover_instance_artifacts() -> list[InstanceArtifacts]:
    """Group exact known instance suffixes under instances_dir() by VM id.

    Scans only direct children. Directories, symlinks, nested files, and
    unknown suffixes are ignored. JSON is parsed with the tolerant constructor;
    ``invalid_json`` is True only when a ``.json`` path exists but cannot
    produce a ``VMInstance``.
    """
    idir = instances_dir()
    if not idir.exists():
        return []

    grouped: dict[str, dict[str, Path]] = {}
    try:
        children = sorted(idir.iterdir())
    except OSError:
        return []

    for path in children:
        try:
            st = path.lstat()
        except OSError:
            continue
        matched = _match_known_suffix(path.name)
        if matched is None:
            continue
        vm_id, suffix = matched
        if not _is_discoverable_instance_node(st.st_mode, suffix):
            continue
        grouped.setdefault(vm_id, {})[suffix] = path

    bundles: list[InstanceArtifacts] = []
    for vm_id in sorted(grouped):
        paths = grouped[vm_id]
        json_path = paths.get(".json")
        instance: VMInstance | None = None
        invalid_json = False
        if json_path is not None:
            try:
                data = json.loads(json_path.read_text())
                instance = _instance_from_dict(data)
            except (json.JSONDecodeError, TypeError, KeyError, OSError, UnicodeError):
                invalid_json = True
                instance = None
        bundles.append(
            InstanceArtifacts(
                vm_id=vm_id,
                instance=instance,
                invalid_json=invalid_json,
                json_path=json_path,
                qmp_socket=paths.get(".qmp.sock"),
                serial_log=paths.get(".serial.log"),
                qemu_log=paths.get(".qemu.log"),
            )
        )
    return bundles


def _path_mtime(path: Path | None) -> float | None:
    if path is None:
        return None
    try:
        return path.lstat().st_mtime
    except OSError:
        return None


def _bundle_too_young(
    bundle: InstanceArtifacts, *, cutoff: float
) -> Path | None:
    """The first present artifact newer than cutoff (or unstatable), else None."""
    for path in (
        bundle.json_path,
        bundle.qmp_socket,
        bundle.serial_log,
        bundle.qemu_log,
    ):
        if path is None:
            continue
        mtime = _path_mtime(path)
        # Path listed but unstatable: treat as ineligible.
        if mtime is None or mtime > cutoff:
            return path
    return None


def _qmp_safe_to_prune(qmp_socket: Path | None) -> bool:
    if qmp_socket is None:
        return True
    try:
        st = qmp_socket.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISSOCK(st.st_mode):
        # Non-socket leftover at the QMP path cannot be a live QMP channel.
        return True
    state = probe_unix_socket(qmp_socket)
    return state in ("stale", "gone")


# Why prune withholds a bundle. `classify_vm` reports the reason next to
# `held_back` so no command describes a permanent metadata refusal as an age
# gate that `--older-than 0` could clear (#109).
HELD_AGE = "age"                            # younger than the --older-than cutoff
HELD_MALFORMED_METADATA = "malformed-metadata"  # unparseable .json, no serial log
HELD_QMP_BUSY = "qmp-busy"                  # the QMP socket still answers


def prune_refusal(
    bundle: InstanceArtifacts, *, cutoff: float
) -> tuple[str, Path | None] | None:
    """Why `bundle` is withheld from prune: (reason, path), or None if eligible.

    Parseable stopped records and serial-only orphans are immediately
    eligible (no age gate). QEMU-log/QMP-only remnants require every present
    known artifact to be at or older than the cutoff, and any QMP socket must
    probe stale/gone. Malformed JSON without a serial-log recovery path is
    refused regardless of age: qmu cannot tell what the bundle was, so it is
    the operator's call — repair or delete the .json by hand. Live parseable
    instances are not a refusal class; callers exclude them first.
    """
    if bundle.instance is not None:
        if not _qmp_safe_to_prune(bundle.qmp_socket):
            return HELD_QMP_BUSY, bundle.qmp_socket
        return None

    if bundle.invalid_json:
        # Unknown identity: only the serial-log recovery path is eligible.
        if bundle.serial_log is None:
            return HELD_MALFORMED_METADATA, bundle.json_path
        if not _qmp_safe_to_prune(bundle.qmp_socket):
            return HELD_QMP_BUSY, bundle.qmp_socket
        return None

    # Metadata-free remnant: serial-only stays immediate; qemu/QMP age-gated.
    if (
        bundle.serial_log is not None
        and bundle.qmp_socket is None
        and bundle.qemu_log is None
    ):
        return None

    young = _bundle_too_young(bundle, cutoff=cutoff)
    if young is not None:
        return HELD_AGE, young
    if not _qmp_safe_to_prune(bundle.qmp_socket):
        return HELD_QMP_BUSY, bundle.qmp_socket
    return None


def _prune_cutoff(older_than_seconds: float, now: float | None) -> float:
    if not math.isfinite(older_than_seconds) or older_than_seconds < 0:
        raise ValueError("older_than_seconds must be finite and non-negative")
    current_time = time.time() if now is None else now
    if not math.isfinite(current_time):
        raise ValueError("now must be finite")
    return current_time - older_than_seconds


def prune_refusals(
    *, older_than_seconds: float, now: float | None = None
) -> dict[str, tuple[str, Path | None]]:
    """Map vm_id -> (reason, path) for every stopped bundle prune withholds."""
    cutoff = _prune_cutoff(older_than_seconds, now)
    refused: dict[str, tuple[str, Path | None]] = {}
    for bundle in discover_instance_artifacts():
        if bundle.instance is not None and instance_alive(bundle.instance):
            continue
        refusal = prune_refusal(bundle, cutoff=cutoff)
        if refusal is not None:
            refused[bundle.vm_id] = refusal
    return refused


def list_prunable_instance_ids(
    *, older_than_seconds: float, now: float | None = None
) -> list[str]:
    """Return VM ids whose exact known artifacts are safe to prune.

    The complement of `prune_refusals` over the same discovery; see
    `prune_refusal` for the eligibility rules.
    """
    cutoff = _prune_cutoff(older_than_seconds, now)
    eligible: list[str] = []
    for bundle in discover_instance_artifacts():
        if bundle.instance is not None and instance_alive(bundle.instance):
            continue
        if prune_refusal(bundle, cutoff=cutoff) is None:
            eligible.append(bundle.vm_id)
    return eligible


def remove_instance(vm_id: str, *, keep_logs: bool = False) -> None:
    """Remove instance state files. With keep_logs=True, preserve the logs.

    Both the guest serial log (.serial.log) and QEMU's own stdout/stderr log
    (.qemu.log, written by launch_vm) are treated as logs: dropped by default,
    kept together under keep_logs so post-mortem forensics stay intact.
    """
    instance_json_path(vm_id).unlink(missing_ok=True)
    (instances_dir() / f"{vm_id}.qmp.sock").unlink(missing_ok=True)
    if not keep_logs:
        serial_log_path(vm_id).unlink(missing_ok=True)
        qemu_log_path(vm_id).unlink(missing_ok=True)


# The auto-selection a running command made, consumed by the output layer so
# the JSON envelope can carry `autoselected: true` without every handler
# plumbing it. Per-dispatch state: `cli.main` resets it through
# `reset_autoselection()` before each command. A ContextVar, not a module
# global, so concurrent in-process dispatches (the MCP façade runs each tool
# call in its own context) cannot attribute one call's pick to another.
_autoselected_vm: ContextVar[str | None] = ContextVar("qmu_autoselected_vm", default=None)


def reset_autoselection() -> None:
    _autoselected_vm.set(None)


def autoselected_vm() -> str | None:
    """The vm_id this dispatch auto-selected, or None when `--vm` named one."""
    return _autoselected_vm.get()


def _require_vm_env_set() -> bool:
    return os.environ.get("QMU_REQUIRE_VM", "") not in ("", "0")


def _autoselect(inst: VMInstance, *, running: bool) -> VMInstance:
    """Record and disclose a pick the caller did not make.

    Never silent: on a shared host a vm-less `qmu exec`/`kill`/`log` acting
    on "the only running VM" acts on whatever VM happens to be alive, which
    may be a peer's. The note goes to stderr so stdout stays the command's
    own payload; JSON readers get `autoselected: true` from the output layer.
    """
    _autoselected_vm.set(inst.vm_id)
    which = "only running VM" if running else "only VM (stopped)"
    sys.stderr.write(
        f"[qmu] Auto-selected the {which} '{inst.vm_id}' (pass --vm to pin it).\n"
    )
    return inst


def _refuse_autoselect_if_required() -> None:
    """`QMU_REQUIRE_VM=1` turns auto-selection into an error (exit 1).

    For agents sharing a host: the opt-out that makes a forgotten `--vm` a
    refusal instead of an action on a VM that may belong to someone else.
    """
    if _require_vm_env_set():
        raise QMUError("--vm is required: QMU_REQUIRE_VM is set")


def choose_instance(vm_id: str | None = None) -> VMInstance:
    if vm_id is None:
        _refuse_autoselect_if_required()
    instances = list_instances()
    if not instances:
        raise QMUError(
            "No running VMs. Start one with: qmu launch --kernel <bzImage>",
            hint="qmu list; qmu launch --name <name> --no-replace",
        )

    if vm_id is not None:
        for inst in instances:
            if inst.vm_id == vm_id:
                return inst
        # The near-miss inventory must be as wide as `qmu list`. A one-character
        # typo on a STOPPED vm_id used to answer "not found. Running: <live>",
        # hiding the very VM the caller was aiming at and making the next move a
        # second guess instead of a corrected name. Same wording as
        # find_instance below, so the two lookups cannot drift.
        stopped = list_stopped_instances()
        raise QMUError(
            f"VM '{vm_id}' not found. "
            f"Running: {', '.join(i.vm_id for i in instances) or 'none'}; "
            f"Stopped: {', '.join(i.vm_id for i in stopped) or 'none'}.",
            hint="qmu list",
        )

    if len(instances) == 1:
        return _autoselect(instances[0], running=True)

    lines = [f"Multiple VMs running. Specify one with --vm <id>:"]
    for inst in instances:
        if inst.harness or inst.ssh_port is None:
            lines.append(f"  {inst.vm_id}  (pid={inst.pid}, harness)")
        else:
            lines.append(f"  {inst.vm_id}  (pid={inst.pid}, ssh={inst.ssh_port})")
    raise QMUError("\n".join(lines), hint="qmu list; pass --vm <id>")


def find_instance(vm_id: str | None = None) -> VMInstance:
    """Locate a VM whether it's running or stopped. Used by read-only commands."""
    if vm_id is None:
        _refuse_autoselect_if_required()
    running = list_instances()
    stopped = list_stopped_instances()

    if vm_id is not None:
        for inst in running + stopped:
            if inst.vm_id == vm_id:
                return inst
        raise QMUError(
            f"VM '{vm_id}' not found. "
            f"Running: {', '.join(i.vm_id for i in running) or 'none'}; "
            f"Stopped: {', '.join(i.vm_id for i in stopped) or 'none'}.",
            hint="qmu list",
        )

    candidates = running + stopped
    if not candidates:
        raise QMUError(
            "No VMs found. Start one with: qmu launch --kernel <bzImage>",
            hint="qmu list; qmu launch --name <name> --no-replace",
        )
    if len(candidates) == 1:
        return _autoselect(candidates[0], running=bool(running))

    # Exactly one VM is running: that is the obvious intent, and it is what
    # `choose_instance` (status/exec/kill) already does. Without this tie-break
    # `log` and `crash` -- the two commands reached for during crash triage --
    # were the ONLY ones that failed to auto-select, because they alone count
    # stopped VMs as candidates. SKILL.md promised "with one VM running,
    # commands auto-select it", and for these two that was false as soon as a
    # single stopped remnant existed. Reading a stopped VM's log still works
    # via an explicit --vm, so nothing that f792840 fixed is regressed.
    if len(running) == 1:
        return _autoselect(running[0], running=True)

    raise QMUError(ambiguous_vm_message(running, stopped))


# How many stopped VMs to name before summarising. The list used to be
# unbounded: on a cache with 58 stopped VMs a bare `qmu log` emitted a 60-line,
# ~489-token error and never mentioned the remedy, on every call.
_AMBIGUITY_LIST_LIMIT = 5


def ambiguous_vm_message(
    running: list[VMInstance], stopped: list[VMInstance]
) -> str:
    lines = ["Multiple VMs found. Specify one with --vm <id>:"]
    for inst in running:
        lines.append(f"  {inst.vm_id}  (pid={inst.pid}, running)")
    shown = stopped[:_AMBIGUITY_LIST_LIMIT]
    for inst in shown:
        lines.append(f"  {inst.vm_id}  (stopped)")
    withheld = len(stopped) - len(shown)
    if withheld > 0:
        lines.append(
            f"  ... and {withheld} more stopped VM(s) — see `qmu list`."
        )
    if stopped:
        # Never recommend `prune --all`: on a shared host the stopped VMs
        # listed here include other people's, and the hint was followed.
        example = shown[0].vm_id
        lines.append(
            "Stopped VMs count as candidates so their logs stay readable. "
            "Remove a stopped VM's state with `qmu prune --vm <id>`, e.g. "
            f"`qmu prune --vm {example}`."
        )
    return "\n".join(lines)


def find_orphan_qemus() -> list[dict[str, Any]]:
    """Return qmu-launched QEMU processes that no live instance record claims.

    Identified by the QMP socket path in their argv, which always points into
    qmu's own instances directory — so this can never match an unrelated QEMU
    the user is running. Matching on the process name is not viable: comm is
    truncated to 15 chars, and a `pgrep -f` broad enough to catch the argv also
    matches the calling shell.
    """
    marker = str(instances_dir())
    claimed = {
        inst.pid for inst in list_instances() if instance_alive(inst)
    }

    orphans: list[dict[str, Any]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in claimed:
            continue
        try:
            argv = (entry / "cmdline").read_bytes().decode(errors="replace")
        except OSError:
            continue
        parts = [p for p in argv.split("\0") if p]
        if not parts or "qemu-system-" not in parts[0]:
            continue
        if marker not in argv:
            continue
        serial = next(
            (p.split("file:", 1)[1] for p in parts if p.startswith("file:")),
            None,
        )
        # The rootfs is in the orphan's own argv, so a holder can be named even
        # though an orphan has no metadata to match on by definition.
        rootfs = None
        for part in parts:
            if not part.startswith("file="):
                continue
            candidate = part.split("file=", 1)[1].split(",", 1)[0]
            if candidate:
                rootfs = candidate
                break
        orphans.append({
            "pid": pid,
            "serial_log": serial,
            "rootfs": rootfs,
            "qmp_socket": next(
                (p.split("unix:", 1)[1].split(",", 1)[0]
                 for p in parts if p.startswith("unix:")),
                None,
            ),
            "cmdline": " ".join(parts),
        })
    return orphans


def orphan_serial_logs() -> dict[str, int]:
    """Map serial-log path -> pid for every untracked qmu QEMU."""
    mapping: dict[str, int] = {}
    for orphan in find_orphan_qemus():
        serial = orphan.get("serial_log")
        if serial:
            mapping[serial] = orphan["pid"]
    return mapping


# Every observable state a vm_id can be in. Commands MUST classify through
# `classify_vm` rather than each deciding for themselves what a name means:
# six rounds of dogfooding produced the same defect repeatedly — one command
# reporting "not found" for a VM another command was displaying — because
# `status`/`kill` looked only at running instances while `list`/`log` also saw
# remnants.
VM_RUNNING = "running"
VM_ORPHANED = "orphaned"      # remnant with no metadata, but its QEMU is alive
VM_HELD_BACK = "held_back"    # stopped remnant the prune age gate withheld
VM_STOPPED = "stopped"        # stopped remnant, eligible to prune
VM_ABSENT = "absent"


def classify_vm(
    vm_id: str,
    *,
    older_than_seconds: float = 86400.0,
    orphan_pids: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return the single authoritative description of `vm_id`.

    Keys: state, instance (VMInstance|None), pid (int|None), serial_log,
    held_reason (one of HELD_* when state is `held_back`, else None) and
    held_path (the artifact the refusal is about, or None).
    """
    for inst in list_instances():
        if inst.vm_id == vm_id:
            return {
                "state": VM_RUNNING,
                "instance": inst,
                "pid": inst.pid,
                "serial_log": inst.serial_log,
                "held_reason": None,
                "held_path": None,
            }

    stopped = {inst.vm_id: inst for inst in list_stopped_instances()}
    inst = stopped.get(vm_id)
    if inst is None:
        return {
            "state": VM_ABSENT, "instance": None, "pid": None, "serial_log": None,
            "held_reason": None, "held_path": None,
        }

    if orphan_pids is None:
        orphan_pids = orphan_serial_logs()
    orphan_pid = orphan_pids.get(inst.serial_log)
    if orphan_pid is not None:
        return {
            "state": VM_ORPHANED,
            "instance": inst,
            "pid": orphan_pid,
            "serial_log": inst.serial_log,
            "held_reason": None,
            "held_path": None,
        }

    refusal = prune_refusals(older_than_seconds=older_than_seconds).get(vm_id)
    if refusal is None:
        return {
            "state": VM_STOPPED, "instance": inst, "pid": None,
            "serial_log": inst.serial_log,
            "held_reason": None, "held_path": None,
        }
    reason, path = refusal
    return {
        "state": VM_HELD_BACK, "instance": inst, "pid": None,
        "serial_log": inst.serial_log,
        "held_reason": reason,
        "held_path": str(path) if path is not None else None,
    }


def held_back_vms(
    *,
    older_than_seconds: float = 86400.0,
    orphan_pids: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Stopped remnants prune withholds, as `{vm_id, reason, path}` in a stable order.

    Not every refusal is the age gate: a malformed `.json` with no serial log
    is withheld at any `--older-than`, so each entry carries its reason.
    """
    refused = prune_refusals(older_than_seconds=older_than_seconds)
    orphaned = set(
        orphan_serial_logs() if orphan_pids is None else orphan_pids
    )
    out: list[dict[str, Any]] = []
    for inst in sorted(list_stopped_instances(), key=lambda i: i.vm_id):
        if inst.serial_log in orphaned:
            continue
        refusal = refused.get(inst.vm_id)
        if refusal is None:
            continue
        reason, path = refusal
        out.append({
            "vm_id": inst.vm_id,
            "reason": reason,
            "path": str(path) if path is not None else None,
        })
    return out


def held_back_vm_ids(
    *,
    older_than_seconds: float = 86400.0,
    orphan_pids: dict[str, int] | None = None,
) -> list[str]:
    """Stopped remnants prune withheld, in a stable order."""
    return [
        entry["vm_id"] for entry in held_back_vms(
            older_than_seconds=older_than_seconds, orphan_pids=orphan_pids
        )
    ]
