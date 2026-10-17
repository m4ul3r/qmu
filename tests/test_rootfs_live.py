"""Live `qmu rootfs` checks against a real guestfish and a real ext4 image.

Skipped unless `QMU_LIVE_GUESTFISH=1`. Unit doubles cannot see the defects
these pin — guestfish's own argument parser, ownership-change side effects
on special bits, `chown` following symlinks, and readlink/ls framing — so
each test builds a tiny ext4 image with `guestfish -N fs:ext4:16M`, injects
through `inject()`, and reads back through `listdir()`.

Environment (same as `qmu doctor` needs for guestfish):
  QMU_LIVE_GUESTFISH=1          enable these tests
  SUPERMIN_KERNEL / SUPERMIN_KERNEL_VERSION / SUPERMIN_MODULES
                                point libguestfs at a readable kernel when
                                /boot is mode 0600 (see CLAUDE.md gotchas)
  QMU_LIVE_ROOTFS=<img>         optional: a rootfs image to copy (sparse)
                                instead of building a scratch ext4 image
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from qmu import rootfs as rootfs_mod
from qmu.instance import QMUError

pytestmark = pytest.mark.skipif(
    os.environ.get("QMU_LIVE_GUESTFISH") != "1" or shutil.which("guestfish") is None,
    reason="set QMU_LIVE_GUESTFISH=1 (and have guestfish) to run live rootfs tests",
)


def _fish(image: Path, *commands: str) -> str:
    cmd = ["guestfish", "--rw", "-a", str(image), "-m", "/dev/sda"]
    proc = subprocess.run(cmd, input="\n".join(commands) + "\n", text=True,
                          capture_output=True)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture
def image(tmp_path):
    img = tmp_path / "private.img"
    source = os.environ.get("QMU_LIVE_ROOTFS")
    if source:
        subprocess.run(["cp", "--sparse=always", source, str(img)], check=True)
    else:
        proc = subprocess.run(
            ["guestfish", "-N", f"{img}=disk:16M", "mkfs", "ext4", "/dev/sda"],
            text=True, capture_output=True,
        )
        assert proc.returncode == 0, proc.stderr
    _fish(img, "mkdir-p /root")
    return img


def _ls(image: Path, path: str) -> dict[str, dict]:
    return {e["name"]: e for e in rootfs_mod.listdir(str(image), path, partition=0)}


def test_special_bits_survive_injection(image, tmp_path):
    """#96: chown clears setuid/setgid; a 6755 fixture landed as 0755."""
    src = tmp_path / "mode-exec"
    src.write_text("#!/bin/sh\nexit 0\n")
    src.chmod(0o6755)
    (tmp_path / "sgid-dir").mkdir()
    (tmp_path / "sgid-dir").chmod(0o2775)
    (tmp_path / "sgid-dir" / "inner").write_text("x")
    (tmp_path / "sgid-dir" / "inner").chmod(0o4700)

    rootfs_mod.inject(str(image), [(str(src), "/root"), (str(tmp_path / "sgid-dir"), "/root")],
                      partition=0)

    root = _ls(image, "/root")
    assert (root["mode-exec"]["mode"], root["mode-exec"]["uid"], root["mode-exec"]["gid"]) == ("6755", 0, 0)
    assert root["sgid-dir"]["mode"] == "2775"
    assert _ls(image, "/root/sgid-dir")["inner"]["mode"] == "4700"


def test_dangling_symlink_injects_and_lists(image, tmp_path):
    """#95: `chown` followed the link and failed the whole inject."""
    tree = tmp_path / "dangling"
    tree.mkdir()
    (tree / "link").symlink_to("/review-does-not-exist")
    (tree / "file").write_text("x")

    rootfs_mod.inject(str(image), [(str(tree), "/root")], partition=0)

    got = _ls(image, "/root/dangling")
    assert got["link"]["type"] == "symlink"
    assert got["link"]["target"] == "/review-does-not-exist"
    assert (got["link"]["uid"], got["link"]["gid"]) == (0, 0)
    assert (got["file"]["uid"], got["file"]["gid"]) == (0, 0)


def test_symlink_to_existing_guest_path_does_not_touch_its_referent(image, tmp_path):
    """#95: `chown` on a link to an existing path re-owned the referent."""
    _fish(image, "write /root/referent data", "chown 1234 1234 /root/referent",
          "chmod 0600 /root/referent")
    tree = tmp_path / "linked"
    tree.mkdir()
    (tree / "ref").symlink_to("/root/referent")

    rootfs_mod.inject(str(image), [(str(tree), "/root")], partition=0)

    referent = _ls(image, "/root")["referent"]
    assert (referent["uid"], referent["gid"], referent["mode"]) == (1234, 1234, "0600")
    link = _ls(image, "/root/linked")["ref"]
    assert (link["type"], link["uid"], link["target"]) == ("symlink", 0, "/root/referent")


def test_directory_merge_leaves_pre_existing_files_alone(image, tmp_path):
    """#97: the recursive chown re-owned an unrelated file under the merge target."""
    _fish(image, "mkdir-p /root/merge-tree", "write /root/merge-tree/keep existing",
          "chown 1234 1234 /root/merge-tree/keep", "chmod 0600 /root/merge-tree/keep")
    tree = tmp_path / "merge-tree"
    tree.mkdir()
    (tree / "new").write_text("new file\n")
    (tree / "new").chmod(0o664)

    rootfs_mod.inject(str(image), [(str(tree), "/root")], partition=0)

    got = _ls(image, "/root/merge-tree")
    assert (got["keep"]["uid"], got["keep"]["gid"], got["keep"]["mode"]) == (1234, 1234, "0600")
    assert (got["new"]["uid"], got["new"]["gid"], got["new"]["mode"]) == (0, 0, "0664")


_AWKWARD_NAMES = [
    "don't.txt", 'say "hi".txt', "with space.txt", "back\\slash.txt",
    "new\nline.txt", "tab\there.txt", "ünïcødé.txt",
]


def test_awkward_names_inject_list_cat_and_remove(image, tmp_path):
    """#98: shell quoting is not guestfish quoting; `don't.txt` broke
    inject and ls with 'command arguments not separated by whitespace'."""
    tree = tmp_path / "quote-tree"
    tree.mkdir()
    for name in _AWKWARD_NAMES:
        (tree / name).write_text(name)
    (tree / "sep-link").symlink_to("__QMU_SEP__")

    rootfs_mod.inject(str(image), [(str(tree), "/root")], partition=0)

    got = _ls(image, "/root/quote-tree")
    assert set(got) == set(_AWKWARD_NAMES) | {"sep-link"}
    for name in _AWKWARD_NAMES:
        assert (got[name]["uid"], got[name]["gid"], got[name]["type"]) == (0, 0, "file")
        assert rootfs_mod.read_file(
            str(image), f"/root/quote-tree/{name}", partition=0
        ) == name.encode()
    assert got["sep-link"]["target"] == "__QMU_SEP__"

    result = rootfs_mod.remove(
        str(image), [f"/root/quote-tree/{n}" for n in _AWKWARD_NAMES[:2]], partition=0
    )
    assert result["missing"] == []
    assert set(_ls(image, "/root/quote-tree")) == set(_AWKWARD_NAMES[2:]) | {"sep-link"}


def test_mkdir_creates_an_awkwardly_named_guest_dir(image, tmp_path):
    src = tmp_path / "exploit"
    src.write_text("x")
    guest = "/root/it's \"here\""
    with pytest.raises(QMUError, match="Guest directory not found"):
        rootfs_mod.inject(str(image), [(str(src), guest)], partition=0)
    rootfs_mod.inject(str(image), [(str(src), guest)], partition=0, mkdir=True)
    assert _ls(image, guest)["exploit"]["type"] == "file"


def test_link_targets_are_data_not_framing(image):
    """#99: a target equal to the old separator emptied every target after it."""
    _fish(image, "mkdir-p /root/separator-links",
          "ln-s __QMU_SEP__ /root/separator-links/a",
          "ln-s /etc/passwd /root/separator-links/b",
          'ln-s "multi\\nline" /root/separator-links/c',
          'ln-s "st_dev: 1" /root/separator-links/d',
          'touch "/root/separator-links/new\\nline"',
          'ln-s "new\\nline" "/root/separator-links/f"')

    got = _ls(image, "/root/separator-links")

    assert {n: e.get("target") for n, e in got.items()} == {
        "a": "__QMU_SEP__", "b": "/etc/passwd", "c": "multi\nline",
        "d": "st_dev: 1", "new\nline": None, "f": "new\nline",
    }
    assert got["new\nline"]["type"] == "file"
    assert all(e["type"] == "symlink" for n, e in got.items() if n != "new\nline")


def test_cr_and_lf_names_are_distinct_entries(image):
    """#111: text-mode stdout turned the `\\r` into `\\n` before the NUL split,
    so the CR-named file vanished and the LF-named one was listed twice."""
    _fish(image, "mkdir-p /root/cr-case",
          'write "/root/cr-case/a\\rb" CR-CONTENT',
          'write "/root/cr-case/a\\nb" LF',
          'write "/root/cr-case/a\\r\\nb" CRLF-CON',
          'ln-s "x\\ry" "/root/cr-case/link"')

    got = _ls(image, "/root/cr-case")

    assert {n: e["size"] for n, e in got.items() if e["type"] == "file"} == {
        "a\rb": 10, "a\nb": 2, "a\r\nb": 8,
    }
    assert got["link"]["target"] == "x\ry"
    assert rootfs_mod.read_file(str(image), "/root/cr-case/a\rb", partition=0) == b"CR-CONTENT"
    assert rootfs_mod.remove(str(image), ["/root/cr-case/a\rb"], partition=0)["removed"] == [
        "/root/cr-case/a\rb"
    ]
    assert set(_ls(image, "/root/cr-case")) == {"a\nb", "a\r\nb", "link"}


def test_non_utf8_name_round_trips_as_bytes(image):
    import base64
    _fish(image, "mkdir-p /root/latin1",
          'write "/root/latin1/caf\\351" x',
          'ln-s "\\377\\376" /root/latin1/l')

    entries = rootfs_mod.listdir(str(image), "/root/latin1", partition=0)

    by_b64 = {e.get("name_bytes_b64"): e for e in entries}
    name = by_b64[base64.b64encode(b"caf\xe9").decode()]
    assert name["size"] == 1
    link = next(e for e in entries if e["name"] == "l")
    assert base64.b64decode(link["target_bytes_b64"]) == b"\xff\xfe"
    # The bytes recovered from the listing address the file again.
    raw = base64.b64decode(name["name_bytes_b64"]).decode("utf-8", "surrogateescape")
    assert rootfs_mod.read_file(str(image), "/root/latin1/" + raw, partition=0) == b"x"
