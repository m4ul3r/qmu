from __future__ import annotations

import shlex
import shutil
import subprocess
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
        if not inst.rootfs or not instance_alive(inst):
            continue
        try:
            if Path(inst.rootfs).expanduser().resolve() == target:
                holders.append(inst.vm_id)
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
    fish: str, image: str, partition: int, guest_dirs: list[str]
) -> list[str]:
    """Return which of `guest_dirs` do not exist as directories in the image."""
    wanted = sorted({d for d in guest_dirs if d != "/"})
    if not wanted:
        return []

    script = "".join(f"is-dir {shlex.quote(d)}\n" for d in wanted)
    cmd = [fish, "--rw", "-a", image] + _mount_args(partition)
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
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    require_image_free(image)

    # Validate locals up-front for clearer errors.
    for local, _ in mappings:
        if not Path(local).exists():
            raise QMUError(f"Local file not found: {local}")

    # GUEST is always a directory (documented contract); a trailing slash is
    # optional. Normalizing keeps `/root` and `/root/` identical instead of
    # silently diverging to `/` via dirname().
    guest_dirs = [guest.rstrip("/") or "/" for _, guest in mappings]

    if not mkdir:
        missing = _missing_dirs(fish, str(img_path), partition, guest_dirs)
        if missing:
            listed = ", ".join(sorted(missing))
            raise QMUError(
                f"Guest directory not found in {image}: {listed}. "
                f"Injecting would have created it and reported success, hiding a "
                f"typo. Pass --mkdir to create it on purpose, or check the path "
                f"with `qmu rootfs ls {image} / --partition {partition}`."
            )

    script_lines: list[str] = []
    for (local, _), guest_dir in zip(mappings, guest_dirs):
        if mkdir:
            script_lines.append(f"-mkdir-p {shlex.quote(guest_dir)}")
        script_lines.append(
            f"copy-in {shlex.quote(str(Path(local).resolve()))} {shlex.quote(guest_dir)}"
        )

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


def listdir(image: str, guest_path: str = "/", partition: int = 1) -> list[str]:
    """List a directory inside the image.

    Exists so an injection can be *verified*: a silently stale rootfs means the
    next boot re-runs the previous iteration's binary while looking fresh.
    """
    path = guest_path or "/"
    out = _run_script(
        image, partition, f"ll {shlex.quote(path)}\n", "ls", read_only=True
    )
    return [line for line in out.splitlines() if line.strip()]


def read_file(image: str, guest_path: str, partition: int = 1) -> str:
    """Return the contents of a file inside the image."""
    return _run_script(
        image, partition, f"cat {shlex.quote(guest_path)}\n", "cat", read_only=True
    )


def remove(
    image: str,
    guest_paths: list[str],
    partition: int = 1,
    *,
    recursive: bool = False,
    force: bool = False,
) -> None:
    """Delete files (or, with `recursive`, directories) inside the image.

    A path that does not exist is an ERROR unless `force` is set. `rm-f`'s
    shell semantics — succeed silently on a missing path — are wrong for a
    command whose purpose is ruling out stale state: a typo'd path would report
    "Removed" while the real file stayed put. `cat` and `ls` already error on a
    missing path; this keeps `rm` consistent with its siblings.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")

    if not force:
        script = "".join(f"exists {shlex.quote(p)}\n" for p in guest_paths)
        out = _run_script(image, partition, script, "rm")
        answers = out.split()
        if len(answers) == len(guest_paths):
            absent = [
                p for p, ok in zip(guest_paths, answers)
                if ok.strip().lower() != "true"
            ]
            if absent:
                raise QMUError(
                    f"Not found in {image}: {', '.join(absent)}. "
                    f"Nothing was removed. Pass --force to ignore missing paths, "
                    f"or check with `qmu rootfs ls`."
                )

    # `--force` must actually tolerate a missing path: skipping the existence
    # probe is not enough, because plain `rm` errors on ENOENT too. This is the
    # documented escape hatch from the strict default, so it has to work.
    if recursive:
        verb = "rm-rf"
    elif force:
        verb = "rm-f"
    else:
        verb = "rm"
    script = "".join(f"{verb} {shlex.quote(p)}\n" for p in guest_paths)
    _run_script(image, partition, script, "rm")


def shell(image: str, partition: int = 1) -> int:
    """Drop into an interactive guestfish shell with the image mounted RW."""
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    require_image_free(image)
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    return subprocess.call(cmd)
