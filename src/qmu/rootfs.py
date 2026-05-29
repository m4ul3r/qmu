from __future__ import annotations

import os
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


def inject(image: str, mappings: list[tuple[str, str]], partition: int = 1) -> None:
    """Copy local files into a guest image using guestfish (no root required).

    GUEST is interpreted as a directory; the local filename is preserved.
    Parent directories are created as needed.
    """
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")

    # Validate locals up-front for clearer errors.
    for local, _ in mappings:
        if not Path(local).exists():
            raise QMUError(f"Local file not found: {local}")

    script_lines: list[str] = []
    for local, guest in mappings:
        # If guest looks like a directory (trailing /), copy into it directly.
        # Otherwise treat parent directory as the destination.
        if guest.endswith("/"):
            guest_dir = guest.rstrip("/") or "/"
        else:
            guest_dir = os.path.dirname(guest) or "/"
        script_lines.append(f"-mkdir-p {shlex.quote(guest_dir)}")
        script_lines.append(
            f"copy-in {shlex.quote(str(Path(local).resolve()))} {shlex.quote(guest_dir)}"
        )

    script = "\n".join(script_lines) + "\n"
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    proc = subprocess.run(cmd, input=script, text=True, capture_output=True)
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        raise QMUError(
            f"guestfish inject failed (exit {proc.returncode}). "
            f"Try `qmu rootfs shell {image} --partition <N>` to inspect.\n{out}"
        )


def shell(image: str, partition: int = 1) -> int:
    """Drop into an interactive guestfish shell with the image mounted RW."""
    fish = _require_guestfish()
    img_path = Path(image)
    if not img_path.exists():
        raise QMUError(f"Image not found: {image}")
    cmd = [fish, "--rw", "-a", str(img_path)] + _mount_args(partition)
    return subprocess.call(cmd)
