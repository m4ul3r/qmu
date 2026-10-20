from __future__ import annotations

import base64
import os
import posixpath
import re
import shutil
import stat as stat_mod
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, NamedTuple, Sequence

from .instance import QMUError


def guestfish_quote(arg: str) -> str:
    """Quote one argument for a guestfish script line (`guestfish(1)` QUOTING).

    guestfish is not a shell: `shlex.quote` renders `don't.txt` as
    `'don'"'"'t.txt'`, which its parser rejects with "command arguments not
    separated by whitespace". Double quotes are the only form with escapes,
    so every argument is double-quoted with `\\\\`/`\\"` escapes and control
    characters as three-digit octal (`\\ooo`) — a newline in a name would
    otherwise end the script line. Non-ASCII passes through verbatim.
    """
    out = ['"']
    for ch in arg:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ch == "\x7f":
            out.append(f"\\{ord(ch):03o}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


GUESTFISH_HINT = (
    "guestfish not found. Install libguestfs-tools:\n"
    "  Debian/Ubuntu:  sudo apt install libguestfs-tools\n"
    "  Fedora:         sudo dnf install libguestfs-tools-c\n"
    "  Arch:           sudo pacman -S libguestfs"
)


def _require_guestfish() -> str:
    path = shutil.which("guestfish")
    if path is None:
        raise QMUError(GUESTFISH_HINT, hint="apt install libguestfs-tools")
    return path


def _drive_files_from_proc(pid: int | None) -> list[str]:
    """Every `file=` path in a live QEMU's argv (its -drive specs).

    A relative `file=./rootfs.img` is relative to where that QEMU was
    launched, not to this caller's CWD, so it is anchored at the process cwd.
    """
    if pid is None:
        return []
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
        cwd = Path(os.readlink(f"/proc/{pid}/cwd"))
    except OSError:
        return []
    files: list[str] = []
    for part in argv.split("\0"):
        for option in part.split(","):
            if option.startswith("file=") and option[5:]:
                files.append(str(cwd / option[5:]))
    return files


def require_image_free(image: str) -> None:
    """Refuse to touch an image a running qmu VM still holds.

    qmu owns the instance metadata, so it can name the blocking VM instead of
    letting libguestfs report a locked image as a generic appliance failure.
    An untracked QEMU is invisible here and is caught after the fact by the
    image-lock branch of `_diagnose_guestfish_failure`.
    """
    # Imported lazily: instance.py is below rootfs.py in the dependency DAG for
    # QMUError only, and a module-level import of the listing helpers would
    # make that edge circular.
    from .instance import (
        find_orphan_qemus,
        instance_alive,
        list_instances,
        list_stopped_instances,
    )

    try:
        target = Path(image).expanduser().resolve()
    except OSError:
        return

    holders = []
    for inst in list_instances():
        if not instance_alive(inst):
            continue
        # `inst.rootfs` is only the implicit drive. A --drive launch records
        # none (the configured image was never attached), so its disks are
        # read from the live process argv, the same `file=` fields the orphan
        # scan parses; otherwise a tracked, `qmu list`-visible VM holding the
        # image fell through to libguestfs and was blamed on an orphan.
        candidates = [inst.rootfs] if inst.rootfs else _drive_files_from_proc(inst.pid)
        for candidate in candidates:
            try:
                if Path(candidate).expanduser().resolve() == target:
                    holders.append(inst.vm_id)
                    break
            except OSError:
                continue

    # An orphan has no metadata by definition, so matching it by instance
    # record can never work — but its own argv carries the -drive file=, from
    # the same /proc cmdline the orphan scan already parses. Match on that.
    serial_to_vm = {
        inst.serial_log: inst.vm_id for inst in list_stopped_instances()
    }
    for orphan in find_orphan_qemus():
        candidate = orphan.get("rootfs")
        if not candidate:
            continue
        try:
            if Path(candidate).expanduser().resolve() != target:
                continue
        except OSError:
            continue
        name = serial_to_vm.get(orphan.get("serial_log") or "", "?")
        holders.append(f"{name} (orphaned, pid {orphan['pid']})")

    if holders:
        listed = ", ".join(holders)
        fix = "; ".join(
            f"qmu kill --vm {vm.split(' ')[0]}" for vm in holders
        )
        raise QMUError(
            f"Cannot write to {image}: it is still held by: {listed}. "
            f"Stop them first:  {fix}",
            hint=fix,
        )


def _mount_args(partition: int) -> list[str]:
    """Build guestfish -m flags. partition=0 means whole-disk."""
    if partition == 0:
        return ["-m", "/dev/sda"]
    return ["-m", f"/dev/sda{partition}"]


def parse_mapping(spec: str) -> tuple[str, str]:
    """Parse a LOCAL:GUEST string into (local, guest). Splits on first ':'.

    The hint is the corrected form: an image command has no VM, so the
    default `qmu status --vm <vm_id>` recovery is meaningless here (#178).
    """
    if ":" not in spec:
        raise QMUError(
            f"Invalid mapping '{spec}'. Expected LOCAL:GUEST (e.g. ./run.sh:/root/)",
            hint=(
                f"one LOCAL:GUEST argument per file, joined by ':' — e.g. "
                f"{spec}:/root/ (a GUEST ending in / is a directory)"
            ),
        )
    local, guest = spec.split(":", 1)
    if not local or not guest:
        raise QMUError(
            f"Invalid mapping '{spec}'. Both LOCAL and GUEST must be non-empty.",
            hint="name both sides: LOCAL:GUEST, e.g. ./run.sh:/root/",
        )
    return local, guest


SUPERMIN_KERNEL_HINT = (
    "libguestfs could not build its appliance: supermin cannot READ a kernel "
    "(/boot/vmlinuz-* is commonly mode 0600 on Debian/Ubuntu, and the build "
    "runs unprivileged) and no cached appliance covers it. Point supermin at a "
    "readable kernel for this host's arch (no root needed; a kernel with "
    "virtio built in, such as a tools/kbuild.sh one, needs only an empty "
    "modules.dep):\n"
    "  mkdir -p /var/tmp/qmu-supermin-modules && touch /var/tmp/qmu-supermin-modules/modules.dep\n"
    "  export SUPERMIN_KERNEL=<readable kernel image> \\\n"
    "         SUPERMIN_KERNEL_VERSION=<its version> \\\n"
    "         SUPERMIN_MODULES=/var/tmp/qmu-supermin-modules\n"
    "or make the host kernels readable (system-wide, needs root):\n"
    "  sudo chmod 0644 /boot/vmlinuz-*\n"
    "Run `qmu doctor` to re-check."
)

# The envelope `hint` for the same failure: the fix as one line.
SUPERMIN_ENV_HINT = (
    "export SUPERMIN_KERNEL=<readable kernel> SUPERMIN_KERNEL_VERSION=<its version> "
    "SUPERMIN_MODULES=<dir with its modules.dep>  (or: sudo chmod 0644 /boot/vmlinuz-*)"
)


def appliance_cache_dir() -> Path:
    """Where libguestfs keeps the supermin appliance it built and reuses.

    `$LIBGUESTFS_CACHEDIR`, else `$TMPDIR`, else `/var/tmp` — libguestfs's own
    order — so a different TMPDIR is a different, possibly empty, cache.
    """
    base = os.environ.get("LIBGUESTFS_CACHEDIR") or os.environ.get("TMPDIR") or "/var/tmp"
    return Path(base) / f".guestfs-{os.getuid()}" / "appliance.d"


def fixed_appliance() -> str | None:
    """The `LIBGUESTFS_PATH` directory holding a fixed appliance, or None.

    libguestfs-make-fixed-appliance writes `README.fixed` beside `kernel`,
    `initrd` and `root`; libguestfs then boots that and never runs supermin,
    so no host kernel needs to be readable and there is no cache to go stale.
    """
    for entry in (os.environ.get("LIBGUESTFS_PATH") or "").split(":"):
        if entry and all(
            (Path(entry) / name).is_file() for name in ("README.fixed", "kernel", "initrd", "root")
        ):
            return entry
    return None


def appliance_kernel_problem(boot: Path = Path("/boot")) -> str | None:
    """Why supermin cannot read a kernel to (re)build the appliance, or None.

    Only an input check: a cached appliance runs without any kernel being
    readable now, so this alone never says whether `rootfs *` works. A fixed
    appliance needs no kernel at all.
    """
    if fixed_appliance() is not None:
        return None
    override = os.environ.get("SUPERMIN_KERNEL")
    if override:
        if os.access(override, os.R_OK):
            return None
        return f"SUPERMIN_KERNEL={override} is NOT readable"
    kernels = sorted(boot.glob("vmlinuz-*")) if boot.is_dir() else []
    if not kernels:
        return "no /boot/vmlinuz-* found"
    if any(os.access(k, os.R_OK) for k in kernels):
        return None
    return "no /boot/vmlinuz-* is readable (they are mode 0600)"


# A warm cache starts in ~3 s and an unreadable-kernel build fails in ~1 s;
# this only bounds a host where the appliance hangs, so `doctor` stays quick.
APPLIANCE_PROBE_TIMEOUT = 20.0


def probe_appliance(fish: str, timeout: float = APPLIANCE_PROBE_TIMEOUT) -> tuple[bool | None, str]:
    """Start the appliance once, against no disk: the capability itself.

    `(True, "")` when it runs (built now or served from the cache),
    `(False, why)` when it does not, `(None, why)` when the probe could not
    finish. ~3 s from a warm cache; a failed supermin build fails in ~1 s.
    """
    try:
        proc = subprocess.run(
            [fish, "--ro", "-a", "/dev/null", "run"],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, f"`guestfish -a /dev/null run` did not finish in {timeout:g}s"
    except OSError as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, ""
    lines = _failure_text(proc).splitlines()
    if not lines:
        return False, f"exit {proc.returncode}"
    return False, re.sub(r"^\*stdin\*:\d+: ", "", lines[0])


def _missing_dirs(
    fish: str,
    image: str,
    partition: int,
    guest_dirs: list[str],
    *,
    read_only: bool = False,
) -> list[str]:
    """Return which of `guest_dirs` do not exist as directories in the image.

    `read_only` opens the image `--ro`, which works while a VM still holds it:
    `launch --inject` validates its targets *before* killing the VM it
    replaces, and at that moment the old VM is still the holder.
    """
    wanted = sorted({d for d in guest_dirs if d != "/"})
    if not wanted:
        return []

    script = "".join(f"is-dir {guestfish_quote(d)}\n" for d in wanted)
    mode = "--ro" if read_only else "--rw"
    cmd = [fish, mode, "-a", image] + _mount_args(partition)
    proc = _invoke(cmd, script)
    if proc.returncode != 0:
        out = _failure_text(proc)
        diagnosis = _diagnose_guestfish_failure(out, image, partition)
        raise QMUError(
            f"guestfish could not inspect {image} (exit {proc.returncode}).\n"
            f"{diagnosis.cause if diagnosis else ''}\n\nguestfish said:\n{out}".strip(),
            hint=diagnosis.hint if diagnosis else _shell_hint(image),
        )

    answers = proc.stdout.split()
    # A short read means guestfish stopped early; treat it as inconclusive
    # rather than inventing a verdict about paths it never reported on.
    if len(answers) != len(wanted):
        return []
    return [d for d, ok in zip(wanted, answers) if ok.strip().lower() != b"true"]


class Diagnosis(NamedTuple):
    """A recognised guestfish failure: the cause for the message, and the
    one-line recovery for the envelope `hint`."""

    cause: str
    hint: str


def _shell_hint(image: str) -> str:
    """The recovery for a guestfish failure nothing more specific explains."""
    return f"qmu rootfs shell {image} --partition <N> to inspect the image"


def _diagnose_guestfish_failure(output: str, image: str, partition: int) -> Diagnosis | None:
    """Translate a known guestfish/supermin failure into an actionable cause.

    libguestfs reports several unrelated problems through the same opaque
    "appliance closed the connection unexpectedly" banner, so the raw blob
    routinely sends the reader after the wrong thing.
    """
    lowered = output.lower()

    # QEMU's image lock is the precise, deterministic signal that another
    # process holds the image — including a QEMU that qmu no longer tracks, so
    # it catches cases the instance-metadata pre-check cannot see. Check it
    # before the generic appliance banner, which this failure also prints.
    if "failed to get" in lowered and "lock" in lowered:
        return Diagnosis(
            f"Another process still has {image} open for writing (QEMU holds an "
            f"image lock while a VM runs). Run `qmu list` and `qmu kill --vm <id>`; "
            f"if qmu lists nothing, an untracked QEMU survived — check "
            f"`pgrep -af qemu-system` and kill it.",
            "qmu list, then qmu kill --vm <id> for the VM holding the image",
        )

    # Without LIBGUESTFS_DEBUG libguestfs prints only "supermin exited with
    # error status 1" — never supermin's own "Permission denied" — so the
    # unreadable kernel is confirmed on the host instead of in the text.
    if "supermin" in lowered and (
        "permission denied" in lowered or "exited with error status" in lowered
    ):
        if "permission denied" in lowered or appliance_kernel_problem() is not None:
            return Diagnosis(SUPERMIN_KERNEL_HINT, SUPERMIN_ENV_HINT)
        return Diagnosis(
            "libguestfs could not build its appliance (supermin failed) although "
            "a kernel is readable. Rerun with LIBGUESTFS_DEBUG=1 "
            "LIBGUESTFS_TRACE=1 for supermin's own error; `qmu doctor` "
            "re-checks the appliance.",
            "rerun with LIBGUESTFS_DEBUG=1 LIBGUESTFS_TRACE=1 for supermin's error; qmu doctor",
        )

    # Distinguish "the image has no such partition" from "the image has no
    # such path". Both surface as ENOENT; only the first is about --partition,
    # and pointing at --partition for a typo'd path sends the reader after the
    # wrong thing.
    if "no such file or directory" in lowered and "/dev/sda" not in output:
        return Diagnosis(
            f"That path does not exist inside {image}. List what is actually "
            f"there with `qmu rootfs ls {image} <dir> --partition {partition}`.",
            f"qmu rootfs ls {image} <dir> --partition {partition}",
        )

    if "is a directory" in lowered or "not a regular file" in lowered:
        return Diagnosis(
            "That path is a directory. Use `qmu rootfs ls` to list it, or "
            "`qmu rootfs rm --recursive` to delete it.",
            "qmu rootfs ls to list it, or qmu rootfs rm --recursive to delete it",
        )

    # guestfish prints the partitions it DID find; surface its own answer.
    if "did you mean" in lowered or (
        "no such file or directory" in lowered and "/dev/sda" in output
    ):
        suggestion = "--partition 0" if partition != 0 else "--partition 1"
        return Diagnosis(
            f"Partition /dev/sda{partition or ''} was not found in {image}. "
            f"A whole-disk (partitionless) image needs --partition 0; a "
            f"partitioned one needs the partition number. Try {suggestion}, or "
            f"run `qmu rootfs shell {image} --partition 0` and use `list-filesystems`.",
            f"retry with {suggestion}",
        )

    if "closed the connection unexpectedly" in lowered:
        # The busy-image pre-check already ran and found no *tracked* holder, so
        # an orphaned QEMU is the leading suspect. `qmu list` DOES surface those
        # now, as [ORPHANED — process alive] — saying otherwise steers the
        # reader away from the one command that answers the question.
        return Diagnosis(
            f"libguestfs could not open {image}. The usual causes, in order: "
            f"an orphaned QEMU still holds it — `qmu list` shows those as "
            f"[ORPHANED — process alive]; reap it with `qmu kill --vm <id>` or "
            f"`qmu prune --orphans` (add --dry-run to look first). Otherwise "
            f"the appliance failed to build: run `qmu doctor`, and "
            f"LIBGUESTFS_DEBUG=1 for detail.",
            "qmu list (an [ORPHANED] VM may hold the image); otherwise qmu doctor",
        )

    return None


def _inject_guest_dirs(mappings: list[tuple[str, str]]) -> list[str]:
    # GUEST is always a directory (documented contract); a trailing slash is
    # optional. Normalizing keeps `/root` and `/root/` identical instead of
    # silently diverging to `/` via dirname().
    return [guest.rstrip("/") or "/" for _, guest in mappings]


def preflight_inject(
    image: str,
    mappings: list[tuple[str, str]],
    partition: int = 1,
    *,
    mkdir: bool = False,
) -> None:
    """Raise the error `inject` would raise for bad inputs, without writing.

    Checks the image exists, every LOCAL exists, and (unless `mkdir`) every
    GUEST directory exists — using a read-only guestfish open and no busy-image
    guard, so it works while a VM still holds the image. `launch --inject` runs
    this before replacing a same-named VM: a typo'd destination used to kill
    the healthy VM and *then* fail, leaving nothing running.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    for local, _ in mappings:
        if not Path(local).exists():
            raise QMUError(f"Local file not found: {local}")
    if mkdir:
        return
    guest_dirs = _inject_guest_dirs(mappings)
    missing = _missing_dirs(
        fish, str(img_path), partition, guest_dirs, read_only=True
    )
    if missing:
        listed = ", ".join(sorted(missing))
        raise QMUError(
            f"Guest directory not found in {image}: {listed}. "
            f"Injecting would have created it and reported success, hiding a "
            f"typo. Pass --mkdir to create it on purpose, or check the path "
            f"with `qmu rootfs ls {image} / --partition {partition}`.",
            hint=f"qmu rootfs ls {image} / --partition {partition}; or re-run with --mkdir",
        )


def inject(
    image: str,
    mappings: list[tuple[str, str]],
    partition: int = 1,
    *,
    mkdir: bool = False,
) -> None:
    """Copy local files into a guest image using guestfish (no root required).

    GUEST is interpreted as a directory; the local filename is preserved.

    A missing GUEST directory is an ERROR unless `mkdir` is set. Creating it
    silently makes a typo'd destination report success — `./exploit:/rooot`
    would land the binary in a fresh `/rooot` while `/root/exploit` still holds
    the previous iteration's build, which is exactly the stale-code failure
    injection is supposed to rule out.

    Injected paths end up owned by root (0:0). `copy-in` preserves the host
    uid/gid, so an unprivileged host user's files landed as e.g. 1005:1000 —
    an uid that usually names nobody in the guest. Mode bits are kept as-is,
    so an executable stays executable and a 0600 key stays private.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    # Cheap input checks first, then the holder refusal (0.2 s), then the
    # guestfish probe (seconds) — the same order a caller would want them in.
    for local, _ in mappings:
        if not Path(local).exists():
            raise QMUError(f"Local file not found: {local}")
    require_image_free(image)
    preflight_inject(image, mappings, partition, mkdir=mkdir)
    guest_dirs = _inject_guest_dirs(mappings)

    script_lines: list[str] = []
    for (local, _), guest_dir in zip(mappings, guest_dirs):
        local_path = Path(local).resolve()
        target = posixpath.join(guest_dir, local_path.name)
        if mkdir:
            script_lines.append(f"-mkdir-p {guestfish_quote(guest_dir)}")
        script_lines.append(
            f"copy-in {guestfish_quote(str(local_path))} {guestfish_quote(guest_dir)}"
        )
        script_lines += _ownership_lines(local_path, target)

    script = "\n".join(script_lines) + "\n"
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    proc = _invoke(cmd, script)
    if proc.returncode != 0:
        raise _guestfish_failure(
            proc.returncode, proc.stderr or proc.stdout or b"", image, partition, "inject"
        )


def _landed_paths(local_path: Path, target: str) -> list[tuple[str, int]]:
    """`(guest_path, lstat st_mode)` for every path `copy-in` lands.

    Enumerated from the *source* tree, never from the guest: the destination
    may already hold files from a previous injection or the image's own
    layout, and a merge must leave those untouched. Sockets are skipped —
    tar does not archive them, so there is nothing landed to normalize.
    """
    landed = [(target, local_path.lstat().st_mode)]
    if not local_path.is_dir():
        return landed
    for root, dirs, files in os.walk(local_path, followlinks=False):
        rel_root = Path(root).relative_to(local_path)
        for name in sorted(dirs + files):
            mode = (Path(root) / name).lstat().st_mode
            if stat_mod.S_ISSOCK(mode):
                continue
            guest = posixpath.join(target, *rel_root.parts, name)
            landed.append((guest, mode))
    return landed


def _ownership_lines(local_path: Path, target: str) -> list[str]:
    """Script lines that root-own exactly what this injection copied.

    `copy-in` preserves the host uid/gid, so every landed path is `lchown`ed:
    `chown` follows symlinks, which fails on a dangling link (a perfectly
    valid thing to ship in a fixture tree) and re-owns an unrelated referent
    for a link to an existing guest path. Ownership changes clear setuid/
    setgid on Linux, so each non-link path then gets its source mode back —
    a `6755` fixture that lands as `0755` has lost the behavior it tests.
    Symlinks keep their 0777: `chmod` would follow them.
    """
    lines: list[str] = []
    for guest, mode in _landed_paths(local_path, target):
        lines.append(f"lchown 0 0 {guestfish_quote(guest)}")
        if not stat_mod.S_ISLNK(mode):
            lines.append(f"chmod 0{stat_mod.S_IMODE(mode):o} {guestfish_quote(guest)}")
    return lines


def _invoke(cmd: list[str], script: str) -> subprocess.CompletedProcess[bytes]:
    """Run guestfish on `script` with a byte-exact transport.

    Text mode would apply universal-newline decoding to stdout, which turns a
    `\\r` inside an `ls0` frame into `\\n` *before* the NUL split — a CR-named
    file then vanished from a listing and the LF-named sibling was reported
    twice, with exit 0. Names that are not UTF-8 ride the script as
    `surrogateescape` so the bytes guestfish printed are the bytes it gets
    back.
    """
    return subprocess.run(
        cmd, input=script.encode("utf-8", "surrogateescape"), capture_output=True
    )


def _failure_text(proc: subprocess.CompletedProcess[bytes]) -> str:
    return (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()


def _run_script(
    image: str,
    partition: int,
    script: str,
    action: str,
    *,
    read_only: bool = False,
) -> bytes:
    """Run a guestfish script against an image and return its raw stdout.

    A read-only run skips the busy-image guard and opens the image `--ro`.
    Inspecting an image while a VM runs is precisely the "did my inject land,
    am I about to run stale code" check these commands exist for, and it is
    safe — only writers need the image to itself.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    if not read_only:
        require_image_free(image)

    mode = "--ro" if read_only else "--rw"
    cmd = [fish, mode, "-a", str(img_path)] + _mount_args(partition)
    proc = _invoke(cmd, script)
    if proc.returncode != 0:
        raise _guestfish_failure(
            proc.returncode, proc.stderr or proc.stdout or b"", image, partition, action
        )
    return proc.stdout


def _guestfish_failure(
    returncode: int, stderr: bytes, image: str, partition: int, action: str
) -> QMUError:
    out = stderr.decode("utf-8", "replace").strip()
    diagnosis = _diagnose_guestfish_failure(out, image, partition) or Diagnosis(
        f"Try `qmu rootfs shell {image} --partition <N>` to inspect.", _shell_hint(image),
    )
    return QMUError(
        f"guestfish {action} failed (exit {returncode}).\n{diagnosis.cause}\n\n"
        f"guestfish said:\n{out}",
        hint=diagnosis.hint,
    )


_PHASE_MARKER = b"qmu-phase-done\n"


def _run_session(
    image: str,
    partition: int,
    action: str,
    first: str,
    then: Callable[[], str],
    *,
    read_only: bool = False,
) -> bytes:
    """Run two scripts in ONE guestfish session; return the second's stdout.

    The appliance boot is the whole cost of a guestfish run (~1.3 s), so a
    command whose second half depends on the first's answer — `ls` needs the
    names before it can stat them — should not pay it twice. `first` must
    print nothing to stdout (send its data to a host file); it is followed by
    an `echo` marker, and `then()` is called once the marker arrives, so it
    can read that file and build the rest of the script. Keeping stdout
    silent until the marker is what makes the sync airtight: no guest name
    can forge a terminator in a stream that carries only the terminator.
    Same byte-exact transport as `_invoke`; guestfish exits on the first
    failing command, which surfaces as EOF before the marker.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    if not read_only:
        require_image_free(image)

    mode = "--ro" if read_only else "--rw"
    cmd = [fish, mode, "-a", str(img_path)] + _mount_args(partition)
    with tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr
        )
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write((first + "echo " + _PHASE_MARKER.decode()).encode(
            "utf-8", "surrogateescape"
        ))
        proc.stdin.flush()
        seen = b""
        while seen != _PHASE_MARKER:
            chunk = proc.stdout.read1(len(_PHASE_MARKER) - len(seen))
            if not chunk:
                break
            seen += chunk
        if seen != _PHASE_MARKER:
            proc.stdin.close()
            proc.wait()
            stderr.seek(0)
            raise _guestfish_failure(
                proc.returncode, stderr.read(), image, partition, action
            )
        out, _ = proc.communicate(then().encode("utf-8", "surrogateescape"))
        if proc.returncode != 0:
            stderr.seek(0)
            raise _guestfish_failure(
                proc.returncode, stderr.read(), image, partition, action
            )
    return out


def _decode_name(raw: bytes) -> tuple[str, str | None]:
    """`(text, bytes_b64)` for a guest name or link target.

    `text` is the exact name when it is valid UTF-8 and the b64 field is
    None. Otherwise `text` is a lossy rendering fit for a JSON/terminal
    consumer and `bytes_b64` carries the exact bytes, so the entry is still
    reversible without putting lone surrogates on stdout.
    """
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace"), base64.b64encode(raw).decode("ascii")


def _parse_stat_blocks(out: bytes) -> list[dict[str, int]]:
    """Split concatenated `lstatns` output into one {field: int} per record."""
    records: list[dict[str, int]] = []
    for raw in out.decode("ascii", "replace").split("\n"):
        line = raw.strip()
        if ":" not in line or not line.startswith("st_"):
            continue
        key, _, value = line.partition(":")
        if key == "st_dev":
            records.append({})
        if not records:
            continue
        try:
            records[-1][key] = int(value.strip())
        except ValueError:
            continue
    return records


_TYPE_NAMES = (
    (stat_mod.S_ISDIR, "dir"),
    (stat_mod.S_ISREG, "file"),
    (stat_mod.S_ISLNK, "symlink"),
    (stat_mod.S_ISCHR, "chardev"),
    (stat_mod.S_ISBLK, "blockdev"),
    (stat_mod.S_ISFIFO, "fifo"),
    (stat_mod.S_ISSOCK, "socket"),
)


def _entry_from_stat(name: bytes, st: dict[str, int], target: bytes | None) -> dict:
    mode = st.get("st_mode", 0)
    kind = next((label for test, label in _TYPE_NAMES if test(mode)), "unknown")
    mtime = datetime.fromtimestamp(st.get("st_mtime_sec", 0), tz=timezone.utc)
    text, name_b64 = _decode_name(name)
    entry = {
        "name": text,
        "type": kind,
        "mode": f"{stat_mod.S_IMODE(mode):04o}",
        "uid": st.get("st_uid", 0),
        "gid": st.get("st_gid", 0),
        "size": st.get("st_size", 0),
        "mtime": mtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if name_b64 is not None:
        entry["name_bytes_b64"] = name_b64
    if kind == "symlink":
        target_text, target_b64 = _decode_name(target or b"")
        entry["target"] = target_text
        if target_b64 is not None:
            entry["target_bytes_b64"] = target_b64
    return entry


def _display(text: str) -> str:
    """A name for one terminal line: control characters become escapes."""
    return "".join(
        {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(ch, f"\\x{ord(ch):02x}")
        if ord(ch) < 0x20 or ch == "\x7f" else ch
        for ch in text
    )


def format_entry(entry: dict) -> str:
    """One `ls -l`-style line for a `listdir` entry."""
    mode = int(entry["mode"], 8)
    type_bits = {
        "dir": stat_mod.S_IFDIR, "file": stat_mod.S_IFREG, "symlink": stat_mod.S_IFLNK,
        "chardev": stat_mod.S_IFCHR, "blockdev": stat_mod.S_IFBLK,
        "fifo": stat_mod.S_IFIFO, "socket": stat_mod.S_IFSOCK,
    }.get(entry["type"], 0)
    line = (
        f"{stat_mod.filemode(type_bits | mode)} {entry['uid']:>5} {entry['gid']:>5} "
        f"{entry['size']:>9} {entry['mtime']} {_display(entry['name'])}"
    )
    if entry["type"] == "symlink":
        line += f" -> {_display(entry['target'])}"
    return line


def _split_tail_stats(out: bytes, count: int) -> tuple[bytes, list[dict[str, int]]]:
    """Split a script's stdout into (prefix, last `count` lstatns records).

    The stat records are the *tail* of the output and each starts with an
    `st_dev:` line, so the boundary is the `count`-th-last such line. Data
    printed before them (readlink targets) cannot move that boundary no
    matter what it contains — a target of `st_dev: 1` only adds lines
    *before* the real records.
    """
    lines = out.split(b"\n")
    starts = [i for i, line in enumerate(lines) if line.startswith(b"st_dev:")]
    if len(starts) < count:
        return out, _parse_stat_blocks(out)
    cut = starts[len(starts) - count] if count else len(lines)
    prefix = b"\n".join(lines[:cut])
    if cut:
        prefix += b"\n"
    return prefix, _parse_stat_blocks(b"\n".join(lines[cut:]))


def _parse_readlink_targets(
    links_out: bytes, stats: list[dict[str, int]]
) -> list[bytes | None] | None:
    """Per-entry symlink targets from concatenated `readlink` output.

    guestfish prints each target followed by a newline, with nothing else to
    frame it, so a target containing a newline — or any sentinel a parser
    might choose — cannot be split on a delimiter. Parsing is positional
    instead: a symlink's `st_size` is the byte length of its target, so each
    symlink entry consumes exactly that many bytes plus the newline. Returns
    None when the output does not fit that shape (a readlink failed, or the
    link changed between stat and readlink), which the caller reports rather
    than guesses about.
    """
    data = links_out
    pos = 0
    targets: list[bytes | None] = []
    for st in stats:
        if not stat_mod.S_ISLNK(st.get("st_mode", 0)):
            targets.append(None)
            continue
        size = st.get("st_size", 0)
        chunk = data[pos : pos + size]
        if len(chunk) != size or data[pos + size : pos + size + 1] != b"\n":
            return None
        targets.append(chunk)
        pos += size + 1
    if pos != len(data):
        return None
    return targets


def listdir(image: str, guest_path: str = "/", partition: int = 1) -> list[dict]:
    """List a directory inside the image as structured entries.

    Each entry is `{name, type, mode, uid, gid, size, mtime[, target]}`:
    `type` is one of file/dir/symlink/chardev/blockdev/fifo/socket, `mode` the
    permission bits as 4-digit octal, `mtime` ISO-8601 UTC, `target` present
    only for symlinks. Exists so an injection can be *verified*: a silently
    stale rootfs means the next boot re-runs the previous iteration's binary
    while looking fresh.

    Names come from `ls0` (NUL-terminated, so a newline in a name is data,
    not a record boundary) over a byte transport — text mode would fold a
    `\\r` into `\\n` before the split. Link targets are parsed by position
    from their `st_size`, never by a string delimiter: a sentinel string
    appearing as a target shifted every later entry's target while still
    reporting success. A name or target that is not UTF-8 gets a lossy
    `name`/`target` plus `name_bytes_b64`/`target_bytes_b64`.

    One guestfish session (#76): `ls0` lands in a host temp file, and the
    readlink/stat script is composed from it once the session reports the
    listing done — a second appliance boot doubled the cost of every `ls`.
    """
    path = guest_path or "/"
    names: list[bytes] = []

    def stat_script() -> str:
        names[:] = sorted(n for n in names_file.read_bytes().split(b"\0") if n)
        full = [
            posixpath.join(path, n.decode("utf-8", "surrogateescape")) for n in names
        ]
        # `-readlink` tolerates the error a non-symlink produces (stderr
        # only) and prints nothing for it. Targets come first and the stat
        # records last, so the records can be found from the tail regardless
        # of what the targets contain.
        return "".join(f"-readlink {guestfish_quote(p)}\n" for p in full) + "".join(
            f"lstatns {guestfish_quote(p)}\n" for p in full
        )

    with tempfile.TemporaryDirectory(prefix="qmu-ls-") as tmp:
        names_file = Path(tmp) / "names"
        out = _run_session(
            image, partition, "ls",
            f"ls0 {guestfish_quote(path)} {guestfish_quote(str(names_file))}\n",
            stat_script, read_only=True,
        )
    if not names:
        return []

    links_part, stats = _split_tail_stats(out, len(names))
    said = out.decode("utf-8", "replace").strip()
    if len(stats) != len(names):
        raise QMUError(
            f"guestfish ls returned {len(stats)} stat records for {len(names)} "
            f"entries in {path}; the listing is inconclusive.\n\nguestfish said:\n"
            f"{said}"
        )
    targets = _parse_readlink_targets(links_part, stats)
    if targets is None:
        raise QMUError(
            f"guestfish ls could not align readlink output with the symlinks "
            f"in {path}; the listing is inconclusive.\n\nguestfish said:\n"
            f"{said}"
        )
    return [
        _entry_from_stat(name, st, target)
        for name, st, target in zip(names, stats, targets)
    ]


def read_file(image: str, guest_path: str, partition: int = 1) -> bytes:
    """Return the exact bytes of a file inside the image.

    Uses `download` rather than guestfish's `cat`, which appends a newline to
    whatever it prints: a 74-byte script came back as 75 bytes, so a checksum
    comparison against the local source failed for a file that was identical.
    """
    with tempfile.NamedTemporaryFile(prefix="qmu-rootfs-cat-", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _run_script(
            image,
            partition,
            f"download {guestfish_quote(guest_path)} {guestfish_quote(str(tmp_path))}\n",
            "cat",
            read_only=True,
        )
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


# Provenance stamps. `tools/mkrootfs.sh` writes STAMP_PATH; its `sshd_policy`
# records whether sshd was built key-only (#68). `tools/mktarget.sh` writes
# TARGET_STAMP_PATH and has built key-only targets since its first version.
# Neither stamp's absence says anything about sshd by itself: an image either
# tool did not build has none, whatever its sshd does (#145).
STAMP_PATH = "/etc/qmu-rootfs.json"
TARGET_STAMP_PATH = "/etc/qmu-target.json"

_EVIDENCE_MARK = "@@qmu-sshd-evidence@@"


@dataclass(frozen=True)
class SshdEvidence:
    """What an image says about root's SSH login, read in one session."""

    rootfs_stamp: str | None    # /etc/qmu-rootfs.json, None when absent
    target_stamp: str | None    # /etc/qmu-target.json, None when absent
    root_shadow: str | None     # root's /etc/shadow line, None when unreadable
    sshd_config: str            # /etc/ssh/sshd_config ("" when absent)
    sshd_config_d: tuple[str, ...]  # /etc/ssh/sshd_config.d/*.conf, one per file, glob order


def read_sshd_evidence(image: str, partition: int = 0) -> SshdEvidence:
    """Both qmu stamps, root's shadow entry and the sshd config, read-only.

    Busy-safe, so `doctor` can ask while a VM holds the image. Whole-disk by
    default: the mkrootfs and mktarget layout. `-` prefixes keep a missing
    file from ending the script; the `exists` answers tell absent from empty.
    Raises QMUError when guestfish is missing or cannot open the image.
    """
    sections = ("rootfs", "target", "shadow", "sshd")
    with tempfile.TemporaryDirectory(prefix="qmu-sshd-") as scratch:
        dropins = Path(scratch) / "sshd_config.d.tar"
        script = (
            f"exists {STAMP_PATH}\nexists {TARGET_STAMP_PATH}\n"
            f"echo {_EVIDENCE_MARK} rootfs\n-cat {STAMP_PATH}\n"
            f"echo {_EVIDENCE_MARK} target\n-cat {TARGET_STAMP_PATH}\n"
            f"echo {_EVIDENCE_MARK} shadow\n-egrep ^root: /etc/shadow\n"
            f"echo {_EVIDENCE_MARK} sshd\n-cat /etc/ssh/sshd_config\n"
            # Per file, not concatenated: sshd ends a drop-in's `Match`
            # block at the end of that file.
            f"-tar-out /etc/ssh/sshd_config.d {guestfish_quote(str(dropins))}\n"
        )
        out = _run_script(image, partition, script, "sshd", read_only=True)
        included = _read_dropins(dropins)
    lines = out.decode("utf-8", "replace").splitlines()
    has_rootfs, has_target = (
        [answer.strip().lower() == "true" for answer in lines[:2]] + [False, False]
    )[:2]
    body: dict[str, list[str]] = {name: [] for name in sections}
    current: str | None = None
    for line in lines[2:]:
        if line.startswith(_EVIDENCE_MARK + " "):
            current = line[len(_EVIDENCE_MARK) + 1:].strip()
            continue
        if current in body:
            body[current].append(line)
    text = {name: "\n".join(body[name]).strip() for name in sections}
    shadow = text["shadow"].splitlines()
    return SshdEvidence(
        rootfs_stamp=text["rootfs"] if has_rootfs else None,
        target_stamp=text["target"] if has_target else None,
        root_shadow=shadow[0] if shadow else None,
        sshd_config=text["sshd"],
        sshd_config_d=included,
    )


def _read_dropins(archive: Path) -> tuple[str, ...]:
    """The `*.conf` files of a `tar-out` of sshd_config.d, in glob order.
    No archive (the directory is absent) is no drop-ins."""
    if not archive.is_file() or archive.stat().st_size == 0:
        return ()
    texts: list[tuple[str, str]] = []
    try:
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                name = posixpath.normpath(member.name)
                if member.isfile() and "/" not in name and name.endswith(".conf"):
                    data = tar.extractfile(member)
                    if data is not None:
                        texts.append((name, data.read().decode("utf-8", "replace")))
    except tarfile.TarError:
        return ()
    return tuple(text for _, text in sorted(texts))


_SSHD_LINE = re.compile(r"^\s*([A-Za-z]\w*)\s*(?:=\s*|\s+)(.*)$")


def _sshd_settings(main: str, included: Sequence[str]) -> dict[str, str]:
    """First value of each keyword, as sshd resolves them outside `Match`.

    sshd keeps the FIRST value it reads, and a `Match` line makes everything
    after it in that file conditional — the state resets at the end of each
    included file. An `Include` of sshd_config.d expands to `included` in
    place (Debian/Ubuntu put it on the first line).
    """
    settings: dict[str, str] = {}

    def walk(text: str, expand: bool) -> None:
        for raw in text.splitlines():
            m = _SSHD_LINE.match(raw)
            if m is None:
                continue
            key, value = m.group(1).lower(), m.group(2).split()
            if key == "match":
                return
            if key == "include":
                if expand and any("sshd_config.d" in v for v in value):
                    for dropin in included:
                        walk(dropin, False)
                continue
            settings.setdefault(key, value[0].lower() if value else "")

    walk(main, True)
    return settings


def root_login_without_key(evidence: SshdEvidence) -> tuple[bool | None, str]:
    """Does sshd let root in with an empty password, i.e. with ANY key or none?

    That is OpenSSH's `none` authentication: it succeeds for root when root's
    password is empty, `PermitEmptyPasswords yes`, `PasswordAuthentication`
    is not `no` and `PermitRootLogin yes` — the legacy mkrootfs setup.
    `(None, why)` when the image does not let that be decided.
    """
    if evidence.root_shadow is None:
        return None, "root's /etc/shadow entry is unreadable"
    if not evidence.sshd_config:
        return None, "no /etc/ssh/sshd_config"
    fields = evidence.root_shadow.split(":")
    password = fields[1] if len(fields) > 1 else "?"
    settings = _sshd_settings(evidence.sshd_config, evidence.sshd_config_d)
    if password != "":
        state = "locked" if password.startswith(("!", "*")) else "set"
        return False, f"root's password is {state}"
    if settings.get("permitemptypasswords", "no") != "yes":
        return False, "root's password is empty but sshd refuses empty passwords"
    if settings.get("passwordauthentication", "yes") == "no":
        return False, "root's password is empty but PasswordAuthentication is no"
    if settings.get("permitrootlogin", "prohibit-password") != "yes":
        return False, "root's password is empty but PermitRootLogin is not yes"
    return True, (
        "root's password is empty and sshd_config sets PermitEmptyPasswords "
        "yes and PermitRootLogin yes"
    )


def remove(
    image: str,
    guest_paths: list[str],
    partition: int = 1,
    *,
    recursive: bool = False,
    force: bool = False,
) -> dict[str, list[str]]:
    """Delete files (or, with `recursive`, directories) inside the image.

    Returns `{"removed": [...], "missing": [...]}` so the caller reports what
    actually happened rather than echoing its arguments back as "Removed".

    A path that does not exist is an ERROR unless `force` is set. `rm-f`'s
    shell semantics — succeed silently on a missing path — are wrong for a
    command whose purpose is ruling out stale state: a typo'd path would report
    "Removed" while the real file stayed put. `cat` and `ls` already error on a
    missing path; this keeps `rm` consistent with its siblings. With `force`
    the existence probe still runs, because "ignore missing paths" must not
    become "claim they were removed": the missing ones come back in `missing`.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")

    present = list(guest_paths)
    missing: list[str] = []
    # The ancestors ride the same appliance run: the missing-path hint names
    # the nearest one that exists, since a parent missing too would make the
    # suggested `rootfs ls` fail as well (#202).
    ancestors: list[str] = []
    for p in guest_paths:
        a = posixpath.dirname(p.rstrip("/")) or "/"
        while a not in ancestors and a != "/":
            ancestors.append(a)
            a = posixpath.dirname(a) or "/"
    probed = list(guest_paths) + ancestors
    script = "".join(f"exists {guestfish_quote(p)}\n" for p in probed)
    out = _run_script(image, partition, script, "rm")
    answers = out.split()
    exists: dict[str, bool] = {"/": True}
    if len(answers) == len(probed):
        exists.update(
            (p, a.strip().lower() == b"true") for p, a in zip(probed, answers)
        )
        present = []
        for guest_path in guest_paths:
            (present if exists[guest_path] else missing).append(guest_path)
    if missing and not force:
        parent = posixpath.dirname(missing[0].rstrip("/")) or "/"
        while not exists.get(parent, True):
            parent = posixpath.dirname(parent) or "/"
        raise QMUError(
            f"Not found in {image}: {', '.join(missing)}. "
            f"Nothing was removed. Pass --force to ignore missing paths, "
            f"or check with `qmu rootfs ls`.",
            hint=(
                f"qmu rootfs ls {image} {parent} --partition {partition}; "
                "or re-run with --force to skip missing paths"
            ),
        )
    if not present:
        return {"removed": [], "missing": missing}

    # `--force` must actually tolerate a missing path: skipping the existence
    # probe is not enough, because plain `rm` errors on ENOENT too. This is the
    # documented escape hatch from the strict default, so it has to work.
    if recursive:
        verb = "rm-rf"
    elif force:
        verb = "rm-f"
    else:
        verb = "rm"
    script = "".join(f"{verb} {guestfish_quote(p)}\n" for p in present)
    _run_script(image, partition, script, "rm")
    return {"removed": present, "missing": missing}


def shell(image: str, partition: int = 1) -> int:
    """Drop into an interactive guestfish shell with the image mounted RW."""
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    require_image_free(image)
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    return subprocess.call(cmd)
