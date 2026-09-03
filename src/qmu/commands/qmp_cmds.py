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
from pathlib import Path

from ..instance import (
    QMUError,
    VMInstance,
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
from ..qmp import QMPCommandError
from ..debug import (
    debug_session_present,
    debug_stub_present,
    kvm_watchpoint_warning,
    loadvm_stale_session_warning,
    reset_dropped_breakpoints_warning,
    savevm_breakpoint_warning,
)
from .._cliutil import (
    _add_common_opts,
    _emit,
    _make_group_help_handler,
    _make_ssh,
    _preflight_ssh_guest,
    _require_ssh,
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
        sys.stderr.write(
            f"[qmu] snapshot save failed: {msg}\n"
            "[qmu] qmu's implicit rootfs uses a temporary snapshot=on overlay; "
            "that overlay can hold in-session checkpoints with a raw or qcow2 base, "
            "and those checkpoints disappear when QEMU exits. For durable internal "
            "snapshots, attach a writable qcow2 drive without snapshot=on, for example "
            "`--drive 'file=./rootfs.qcow2,format=qcow2'`. Changing [drive] format "
            "alone remains temporary because qmu still adds snapshot=on.\n"
        )
        return 1
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
        sys.stderr.write(f"[qmu] snapshot load failed: {msg}\n")
        if _snapshot_load_mentions_slirp(msg):
            sys.stderr.write(
                "[qmu] This loadvm error names slirp. The user backend often works for "
                "in-session restore, but this QEMU/build/device combination could not "
                "restore its network state. Use native passt networking only with a selected "
                "QEMU that advertises native '-netdev passt' (documented since QEMU 10.1 but "
                "may be build-optional), or use a manually managed external passt process "
                "with QEMU's stream backend. qmu does not manage that external process.\n"
            )
        return 1
    # #44: loadvm rewound the guest, but an attached debugger keeps its pre-load
    # vCPU state and never re-syncs — a silent divergence in the rewind-iterate
    # fast path. Warn only on a successful load (a failed one did not rewind).
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
        data = {
            "ok": True,
            "vm_id": inst.vm_id,
            "gdb_port": inst.gdb_port,
            "cpu_state": "halted",
            "warning": warning,
        }
        text = (
            f"pry connected to VM '{inst.vm_id}' GDB stub on port "
            f"{inst.gdb_port}\n{warning}"
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
            "A method QEMU has no command for, or arguments its schema rejects,\n"
            "exits 1 (caller error). Exit 4 is reserved for the transport."
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
# host/VM state, not the command text, and must NOT be reclassified.
_QMP_ARG_SHAPE_RE = re.compile(
    r"^(?:"
    r"Parameter '[^']*' (?:is (?:missing|unexpected)|expects |does not accept value )"
    r"|Invalid parameter (?:type for )?'[^']*'"
    r"|QMP input member '[^']*' (?:is unexpected|must be )"
    r")"
)


def _qmp_caller_error(method: str, exc: QMPCommandError) -> QMUError | None:
    """Re-class a QEMU error *reply* that proves the fault is caller input.

    Exit 4 means "QMP/SSH transport or internal qmu failure", so an agent
    branching on it retries or declares infra breakage. `qmu qmp query-staus`
    used to land there: the method reached QEMU intact and came back
    CommandNotFound, which is the opposite of a transport fault and cannot be
    fixed by retrying. That is the very defect #36 names -- "an infra code for
    a caller-input mistake" -- and only the command-FORM half was closed
    before. A method QEMU has no command for, and arguments its QAPI schema
    rejects, are exit-1 caller errors with a correction attached.

    Returns None for every other reply (DeviceNotFound, KVMMissingCap, an
    operational GenericError like "failed to open file ..."): those report
    host/VM state rather than what was typed, so the caller keeps the
    QMPError -> 4 they have today instead of a wrong "you typo'd" verdict.
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
    return None


def _hmp_verb(command_line: str) -> str:
    """First whitespace-separated token of an HMP command line ("" if none).

    The verb, not the whole line: `help system_reset` shows help and resets
    nothing, so a substring test would warn on it.
    """
    tokens = command_line.split()
    return tokens[0] if tokens else ""


def _emit_mutation_coherence_warning(
    inst: VMInstance, verb: str, output: str
) -> None:
    """Warn once for whichever VM-reality mutation `verb` just performed.

    One switch for all three routes to these mutations -- `qmu monitor <verb>`,
    `qmu qmp system_reset`, and `qmu qmp human-monitor-command` with the verb
    inside `arguments['command-line']`. The last one was silent (dogfood F4):
    it reset the machine with an attached debugger, rc 0 and an empty stderr,
    which is precisely the wrong-answer-with-no-error class debug.py exists to
    prevent -- and the envelope normalization made it trivially typeable.
    savevm/loadvm suppress on a failed op (the same _snapshot_failed the
    snapshot handlers use), since a failed op mutated nothing.
    """
    if verb == "system_reset":
        if debug_session_present(inst):
            sys.stderr.write(reset_dropped_breakpoints_warning(inst.vm_id) + "\n")
    elif verb == "savevm":
        if debug_stub_present(inst) and not _snapshot_failed(output):
            sys.stderr.write(savevm_breakpoint_warning(inst.vm_id) + "\n")
    elif verb == "loadvm":
        if debug_session_present(inst) and not _snapshot_failed(output):
            sys.stderr.write(loadvm_stale_session_warning(inst.vm_id) + "\n")


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
    try:
        with _qmp_ctx(inst) as qmp:
            result = qmp.execute(method, qmp_args)
    except QMPCommandError as exc:
        # A QEMU error REPLY, not a transport fault: the wire worked. Re-class
        # the subset that proves caller input is at fault (exit 1); everything
        # else keeps the QMPError -> exit 4 it has today.
        caller_error = _qmp_caller_error(method, exc)
        if caller_error is None:
            raise
        raise caller_error from exc
    # Text mode passes the raw QMP return (any JSON type) straight to _output;
    # json mode wraps it so the universal {"ok": ...} contract holds, with the
    # original payload under "result".
    _emit(args, data={"ok": True, "result": result}, text=result, stem="qmp")
    # #46: a machine reset silently drops the gdbstub breakpoint set. Both raw
    # paths reach it -- the QMP method itself (keyed on the NORMALIZED method,
    # so the envelope form warns too) and `human-monitor-command`, whose HMP
    # verb rides inside arguments['command-line'] and was unguarded (F4).
    if method == "system_reset":
        _emit_mutation_coherence_warning(inst, "system_reset", "")
    elif method == "human-monitor-command":
        line = qmp_args.get("command-line") if isinstance(qmp_args, dict) else None
        _emit_mutation_coherence_warning(
            inst,
            _hmp_verb(line) if isinstance(line, str) else "",
            result if isinstance(result, str) else "",
        )
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
    # HMP is a raw escape hatch, so `qmu monitor {system_reset,savevm,loadvm}`
    # reach the same VM-reality mutations as the dedicated handlers / `qmu qmp`
    # but bypass their coherence warnings. Re-emit through the shared switch,
    # which is keyed on the HMP *verb* so e.g. `monitor help system_reset` --
    # which resets nothing -- is not caught.
    _emit_mutation_coherence_warning(inst, _hmp_verb(command), result)
    return 0
