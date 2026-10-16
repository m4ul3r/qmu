from __future__ import annotations

import os
import posixpath
import shlex
import shutil
import stat as stat_mod
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .instance import QMUError


GUESTFISH_HINT = (
    "guestfish not found. Install libguestfs-tools:\n"
    "  Debian/Ubuntu:  sudo apt install libguestfs-tools\n"
    "  Fedora:         sudo dnf install libguestfs-tools-c\n"
    "  Arch:           sudo pacman -S libguestfs"
)


def _require_guestfish() -> str:
    path = shutil.which("guestfish")
    if path is None:
        raise QMUError(GUESTFISH_HINT)
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
            f"Stop them first:  {fix}"
        )


def _mount_args(partition: int) -> list[str]:
    """Build guestfish -m flags. partition=0 means whole-disk."""
    if partition == 0:
        return ["-m", "/dev/sda"]
    return ["-m", f"/dev/sda{partition}"]


def parse_mapping(spec: str) -> tuple[str, str]:
    """Parse a LOCAL:GUEST string into (local, guest). Splits on first ':'."""
    if ":" not in spec:
        raise QMUError(
            f"Invalid mapping '{spec}'. Expected LOCAL:GUEST (e.g. ./run.sh:/root/)"
        )
    local, guest = spec.split(":", 1)
    if not local or not guest:
        raise QMUError(f"Invalid mapping '{spec}'. Both LOCAL and GUEST must be non-empty.")
    return local, guest


SUPERMIN_KERNEL_HINT = (
    "libguestfs could not build its appliance because it cannot READ the host "
    "kernel: /boot/vmlinuz-* is commonly mode 0600 on Debian/Ubuntu, and the "
    "appliance build runs unprivileged. Fix either way:\n"
    "  sudo chmod 0644 /boot/vmlinuz-*\n"
    "or point supermin at a readable copy (leaves system perms alone):\n"
    "  sudo install -m 0644 /boot/vmlinuz-$(uname -r) /var/tmp/vmlinuz\n"
    "  export SUPERMIN_KERNEL=/var/tmp/vmlinuz \\\n"
    "         SUPERMIN_KERNEL_VERSION=$(uname -r) \\\n"
    "         SUPERMIN_MODULES=/lib/modules/$(uname -r)\n"
    "Run `qmu doctor` to re-check."
)


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

    script = "".join(f"is-dir {shlex.quote(d)}\n" for d in wanted)
    mode = "--ro" if read_only else "--rw"
    cmd = [fish, mode, "-a", image] + _mount_args(partition)
    proc = subprocess.run(cmd, input=script, text=True, capture_output=True)
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        diagnosis = _diagnose_guestfish_failure(out, image, partition)
        raise QMUError(
            f"guestfish could not inspect {image} (exit {proc.returncode}).\n"
            f"{diagnosis or ''}\n\nguestfish said:\n{out}".strip()
        )

    answers = proc.stdout.split()
    # A short read means guestfish stopped early; treat it as inconclusive
    # rather than inventing a verdict about paths it never reported on.
    if len(answers) != len(wanted):
        return []
    return [d for d, ok in zip(wanted, answers) if ok.strip().lower() != "true"]


def _diagnose_guestfish_failure(output: str, image: str, partition: int) -> str | None:
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
        return (
            f"Another process still has {image} open for writing (QEMU holds an "
            f"image lock while a VM runs). Run `qmu list` and `qmu kill --vm <id>`; "
            f"if qmu lists nothing, an untracked QEMU survived — check "
            f"`pgrep -af qemu-system` and kill it."
        )

    if "supermin" in lowered and "permission denied" in lowered:
        return SUPERMIN_KERNEL_HINT

    # Distinguish "the image has no such partition" from "the image has no
    # such path". Both surface as ENOENT; only the first is about --partition,
    # and pointing at --partition for a typo'd path sends the reader after the
    # wrong thing.
    if "no such file or directory" in lowered and "/dev/sda" not in output:
        return (
            f"That path does not exist inside {image}. List what is actually "
            f"there with `qmu rootfs ls {image} <dir> --partition {partition}`."
        )

    if "is a directory" in lowered or "not a regular file" in lowered:
        return (
            "That path is a directory. Use `qmu rootfs ls` to list it, or "
            "`qmu rootfs rm --recursive` to delete it."
        )

    # guestfish prints the partitions it DID find; surface its own answer.
    if "did you mean" in lowered or (
        "no such file or directory" in lowered and "/dev/sda" in output
    ):
        suggestion = "--partition 0" if partition != 0 else "--partition 1"
        return (
            f"Partition /dev/sda{partition or ''} was not found in {image}. "
            f"A whole-disk (partitionless) image needs --partition 0; a "
            f"partitioned one needs the partition number. Try {suggestion}, or "
            f"run `qmu rootfs shell {image} --partition 0` and use `list-filesystems`."
        )

    if "closed the connection unexpectedly" in lowered:
        # The busy-image pre-check already ran and found no *tracked* holder, so
        # an orphaned QEMU is the leading suspect. `qmu list` DOES surface those
        # now, as [ORPHANED — process alive] — saying otherwise steers the
        # reader away from the one command that answers the question.
        return (
            f"libguestfs could not open {image}. The usual causes, in order: "
            f"an orphaned QEMU still holds it — `qmu list` shows those as "
            f"[ORPHANED — process alive]; reap it with `qmu kill --vm <id>` or "
            f"`qmu prune --orphans` (add --dry-run to look first). Otherwise "
            f"the appliance failed to build: run `qmu doctor`, and "
            f"LIBGUESTFS_DEBUG=1 for detail."
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
            f"with `qmu rootfs ls {image} / --partition {partition}`."
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
    dir_targets: list[str] = []
    for (local, _), guest_dir in zip(mappings, guest_dirs):
        local_path = Path(local).resolve()
        target = posixpath.join(guest_dir, local_path.name)
        if mkdir:
            script_lines.append(f"-mkdir-p {shlex.quote(guest_dir)}")
        script_lines.append(
            f"copy-in {shlex.quote(str(local_path))} {shlex.quote(guest_dir)}"
        )
        script_lines.append(f"chown 0 0 {shlex.quote(target)}")
        if local_path.is_dir():
            dir_targets.append(target)

    script = "\n".join(script_lines) + "\n"
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    proc = subprocess.run(cmd, input=script, text=True, capture_output=True)
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        diagnosis = _diagnose_guestfish_failure(out, image, partition)
        if diagnosis is None:
            diagnosis = f"Try `qmu rootfs shell {image} --partition <N>` to inspect."
        raise QMUError(
            f"guestfish inject failed (exit {proc.returncode}).\n{diagnosis}\n\n"
            f"guestfish said:\n{out}"
        )

    # guestfish has no recursive chown; a copied-in directory tree needs its
    # contents enumerated first, then chowned in a second pass. `find` prints
    # paths relative to its argument (leading `/`), one per line, with nothing
    # between consecutive lists, so each list is closed with an echo marker.
    if dir_targets:
        find_script = "".join(
            f"find {shlex.quote(t)}\necho {_SEP_MARKER}\n" for t in dir_targets
        )
        found = _run_script(image, partition, find_script, "inject")
        chown_lines: list[str] = []
        lists = found.split(_SEP_MARKER + "\n")
        for target, listing in zip(dir_targets, lists):
            for rel in listing.split("\n"):
                if rel:
                    chown_lines.append(
                        f"chown 0 0 {shlex.quote(target + rel)}"
                    )
        if chown_lines:
            _run_script(image, partition, "".join(l + "\n" for l in chown_lines), "inject")


def _run_script(
    image: str,
    partition: int,
    script: str,
    action: str,
    *,
    read_only: bool = False,
) -> str:
    """Run a guestfish script against an image and return its stdout.

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
    proc = subprocess.run(cmd, input=script, text=True, capture_output=True)
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        diagnosis = _diagnose_guestfish_failure(out, image, partition)
        if diagnosis is None:
            diagnosis = f"Try `qmu rootfs shell {image} --partition <N>` to inspect."
        raise QMUError(
            f"guestfish {action} failed (exit {proc.returncode}).\n{diagnosis}\n\n"
            f"guestfish said:\n{out}"
        )
    return proc.stdout


def _parse_stat_blocks(out: str) -> list[dict[str, int]]:
    """Split concatenated `lstatns` output into one {field: int} per record."""
    records: list[dict[str, int]] = []
    for raw in out.splitlines():
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


def _entry_from_stat(name: str, st: dict[str, int], target: str | None) -> dict:
    mode = st.get("st_mode", 0)
    kind = next((label for test, label in _TYPE_NAMES if test(mode)), "unknown")
    mtime = datetime.fromtimestamp(st.get("st_mtime_sec", 0), tz=timezone.utc)
    entry = {
        "name": name,
        "type": kind,
        "mode": f"{stat_mod.S_IMODE(mode):04o}",
        "uid": st.get("st_uid", 0),
        "gid": st.get("st_gid", 0),
        "size": st.get("st_size", 0),
        "mtime": mtime.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if kind == "symlink":
        entry["target"] = target or ""
    return entry


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
        f"{entry['size']:>9} {entry['mtime']} {entry['name']}"
    )
    if entry["type"] == "symlink":
        line += f" -> {entry['target']}"
    return line


_LINKS_MARKER = "__QMU_LINKS__"
_SEP_MARKER = "__QMU_SEP__"


def listdir(image: str, guest_path: str = "/", partition: int = 1) -> list[dict]:
    """List a directory inside the image as structured entries.

    Each entry is `{name, type, mode, uid, gid, size, mtime[, target]}`:
    `type` is one of file/dir/symlink/chardev/blockdev/fifo/socket, `mode` the
    permission bits as 4-digit octal, `mtime` ISO-8601 UTC, `target` present
    only for symlinks. Exists so an injection can be *verified*: a silently
    stale rootfs means the next boot re-runs the previous iteration's binary
    while looking fresh.
    """
    path = guest_path or "/"
    names_out = _run_script(
        image, partition, f"ls {shlex.quote(path)}\n", "ls", read_only=True
    )
    names = [n for n in names_out.split("\n") if n]
    if not names:
        return []

    full = [posixpath.join(path, n) for n in names]
    script = "".join(f"lstatns {shlex.quote(p)}\n" for p in full)
    # `-readlink` tolerates the error a non-symlink produces (stderr only);
    # the separators keep the per-entry answers aligned with `names`.
    script += f"echo {_LINKS_MARKER}\n"
    script += "".join(f"-readlink {shlex.quote(p)}\necho {_SEP_MARKER}\n" for p in full)
    out = _run_script(image, partition, script, "ls", read_only=True)

    stat_part, _, links_part = out.partition(_LINKS_MARKER + "\n")
    stats = _parse_stat_blocks(stat_part)
    targets: list[str | None] = []
    for chunk in links_part.split(_SEP_MARKER + "\n")[: len(names)]:
        targets.append(chunk.rstrip("\n") or None)
    if len(stats) != len(names):
        raise QMUError(
            f"guestfish ls returned {len(stats)} stat records for {len(names)} "
            f"entries in {path}; the listing is inconclusive.\n\nguestfish said:\n"
            f"{out.strip()}"
        )
    targets += [None] * (len(names) - len(targets))
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
            f"download {shlex.quote(guest_path)} {shlex.quote(str(tmp_path))}\n",
            "cat",
            read_only=True,
        )
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


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
    script = "".join(f"exists {shlex.quote(p)}\n" for p in guest_paths)
    out = _run_script(image, partition, script, "rm")
    answers = out.split()
    if len(answers) == len(guest_paths):
        present = []
        for guest_path, answer in zip(guest_paths, answers):
            (present if answer.strip().lower() == "true" else missing).append(guest_path)
    if missing and not force:
        raise QMUError(
            f"Not found in {image}: {', '.join(missing)}. "
            f"Nothing was removed. Pass --force to ignore missing paths, "
            f"or check with `qmu rootfs ls`."
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
    script = "".join(f"{verb} {shlex.quote(p)}\n" for p in present)
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
