"""qmu rootfs — guestfish missing should produce a clear install hint."""

from __future__ import annotations

from unittest import mock

import pytest

from qmu.instance import QMUError
from qmu import rootfs as rootfs_mod


def test_missing_guestfish_raises_with_install_hint():
    with mock.patch.object(rootfs_mod.shutil, "which", return_value=None):
        with pytest.raises(QMUError) as excinfo:
            rootfs_mod._require_guestfish()
    msg = str(excinfo.value)
    assert "guestfish" in msg
    assert "libguestfs-tools" in msg


def test_parse_mapping_basic():
    assert rootfs_mod.parse_mapping("./run.sh:/root/") == ("./run.sh", "/root/")


def test_parse_mapping_only_first_colon_splits():
    """Guest paths could in principle contain colons (rare); split on first only."""
    local, guest = rootfs_mod.parse_mapping("/tmp/a:/etc/rc:d/foo")
    assert local == "/tmp/a"
    assert guest == "/etc/rc:d/foo"


def test_parse_mapping_rejects_missing_colon():
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping("nope")


def test_parse_mapping_rejects_empty_side():
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping(":foo")
    with pytest.raises(QMUError):
        rootfs_mod.parse_mapping("foo:")


def test_mount_args_partition_zero_uses_whole_disk():
    assert rootfs_mod._mount_args(0) == ["-m", "/dev/sda"]


def test_mount_args_partition_one_default():
    assert rootfs_mod._mount_args(1) == ["-m", "/dev/sda1"]


def test_inject_image_missing_raises():
    with pytest.raises(QMUError):
        rootfs_mod.inject("/nonexistent/img", [], partition=1)


def _run_inject_capture_script(tmp_path, guest, mkdir=False):
    """Run inject with guestfish/image stubbed out and return the script text
    piped to guestfish. Lets us assert on the generated commands directly."""
    local = tmp_path / "exploit"
    local.write_text("payload")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")

    completed = mock.Mock(returncode=0, stderr="", stdout="")
    with mock.patch.object(rootfs_mod, "_require_guestfish", return_value="guestfish"):
        with mock.patch.object(
            rootfs_mod.subprocess, "run", return_value=completed
        ) as run:
            rootfs_mod.inject(
                str(image), [(str(local), guest)], partition=1, mkdir=mkdir
            )
    return run.call_args.kwargs["input"]


def _copy_in_lines(script: str) -> list[str]:
    return [l for l in script.splitlines() if l.startswith("copy-in ")]


def test_inject_treats_guest_without_trailing_slash_as_dir(tmp_path):
    # Regression: `/root` used to collapse to `/` via dirname().
    script = _run_inject_capture_script(tmp_path, "/root")
    assert _copy_in_lines(script) == [f"copy-in {tmp_path / 'exploit'} /root"]


def test_inject_trailing_slash_matches_no_slash(tmp_path):
    with_slash = _run_inject_capture_script(tmp_path, "/root/")
    no_slash = _run_inject_capture_script(tmp_path, "/root")
    assert with_slash == no_slash
    assert "copy-in " in with_slash


def test_inject_root_guest_stays_root(tmp_path):
    script = _run_inject_capture_script(tmp_path, "/")
    assert _copy_in_lines(script)[0].endswith(" /")


def test_inject_does_not_create_the_guest_dir_by_default(tmp_path):
    """A silent mkdir turns a typo'd destination into a reported success."""
    script = _run_inject_capture_script(tmp_path, "/root")
    assert "mkdir" not in script


def test_inject_creates_the_guest_dir_when_asked(tmp_path):
    script = _run_inject_capture_script(tmp_path, "/root", mkdir=True)
    assert "-mkdir-p /root\n" in script


def test_inject_chowns_the_landed_path_to_root(tmp_path):
    """copy-in keeps the host uid/gid (1005:1000 in the audit); the guest
    file must be root's, at the path the filename-preserving contract puts it."""
    script = _run_inject_capture_script(tmp_path, "/root")
    assert "chown 0 0 /root/exploit\n" in script
    script = _run_inject_capture_script(tmp_path, "/")
    assert "chown 0 0 /exploit\n" in script


def test_inject_chowns_a_directory_tree_recursively(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a").write_text("x")
    (tree / "sub" / "b").write_text("y")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    scripts: list[str] = []

    def fake_run(cmd, input=None, text=None, capture_output=None):
        scripts.append(input)
        if input.startswith("find "):
            return mock.Mock(returncode=0, stderr="",
                             stdout="/a\n/sub\n/sub/b\n__QMU_SEP__\n")
        return mock.Mock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    rootfs_mod.inject(str(image), [(str(tree), "/opt")], partition=0, mkdir=True)

    assert "chown 0 0 /opt/tree\n" in scripts[0]
    assert scripts[1] == "find /opt/tree\necho __QMU_SEP__\n"
    assert scripts[2] == (
        "chown 0 0 /opt/tree/a\nchown 0 0 /opt/tree/sub\nchown 0 0 /opt/tree/sub/b\n"
    )


def test_preflight_inject_opens_read_only_and_skips_the_busy_guard(tmp_path, monkeypatch):
    """launch --inject validates its targets while the VM it replaces still
    holds the image, so the probe must neither take the guard nor open --rw."""
    local = tmp_path / "exploit"
    local.write_text("payload")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    seen: dict = {}
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(
        rootfs_mod, "require_image_free",
        lambda img: pytest.fail("preflight must not take the write guard"),
    )

    def fake_run(cmd, input=None, text=None, capture_output=None):
        seen["cmd"] = cmd
        return mock.Mock(returncode=0, stderr="", stdout="false\n")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    with pytest.raises(QMUError, match="Guest directory not found in .*: /rooot"):
        rootfs_mod.preflight_inject(str(image), [(str(local), "/rooot")], partition=0)
    assert "--ro" in seen["cmd"]

    with pytest.raises(QMUError, match="Local file not found"):
        rootfs_mod.preflight_inject(str(image), [("/no/such", "/root")], partition=0)
    with pytest.raises(QMUError, match="Image not found"):
        rootfs_mod.preflight_inject("/no/img", [(str(local), "/root")], partition=0)


_STAT_FILE = (
    "st_dev: 2048\nst_ino: 306\nst_mode: 33261\nst_nlink: 1\nst_uid: 1005\n"
    "st_gid: 1000\nst_rdev: 0\nst_size: 74\nst_blksize: 4096\nst_blocks: 8\n"
    "st_atime_sec: 1\nst_atime_nsec: 0\nst_mtime_sec: 1618084800\n"
    "st_mtime_nsec: 0\nst_ctime_sec: 1\nst_ctime_nsec: 0\n"
)
_STAT_LINK = (
    "st_dev: 2048\nst_ino: 139\nst_mode: 41471\nst_nlink: 1\nst_uid: 0\n"
    "st_gid: 0\nst_rdev: 0\nst_size: 27\nst_blksize: 4096\nst_blocks: 0\n"
    "st_mtime_sec: 1782172800\nst_mtime_nsec: 0\n"
)


def test_listdir_returns_structured_entries(tmp_path, monkeypatch):
    """JSON used to carry raw `ls -l` strings (harness F14)."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    scripts: list[str] = []

    def fake_run(cmd, input=None, text=None, capture_output=None):
        scripts.append(input)
        if input.startswith("ls "):
            return mock.Mock(returncode=0, stderr="", stdout="run.sh\nlocaltime\n")
        return mock.Mock(
            returncode=0, stderr="",
            stdout=_STAT_FILE + _STAT_LINK + "__QMU_LINKS__\n"
                   "__QMU_SEP__\n/usr/share/zoneinfo/Etc/UTC\n__QMU_SEP__\n",
        )

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    entries = rootfs_mod.listdir(str(image), "/etc", partition=0)

    assert scripts[0] == "ls /etc\n"
    assert "lstatns /etc/run.sh\n" in scripts[1]
    assert "-readlink /etc/localtime\n" in scripts[1]
    assert entries == [
        {"name": "run.sh", "type": "file", "mode": "0755", "uid": 1005,
         "gid": 1000, "size": 74, "mtime": "2021-04-10T20:00:00Z"},
        {"name": "localtime", "type": "symlink", "mode": "0777", "uid": 0,
         "gid": 0, "size": 27, "mtime": "2026-06-23T00:00:00Z",
         "target": "/usr/share/zoneinfo/Etc/UTC"},
    ]
    assert rootfs_mod.format_entry(entries[0]) == (
        "-rwxr-xr-x  1005  1000        74 2021-04-10T20:00:00Z run.sh"
    )
    assert rootfs_mod.format_entry(entries[1]).endswith(
        "localtime -> /usr/share/zoneinfo/Etc/UTC"
    )


def test_listdir_short_stat_read_is_an_error_not_a_guess(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")

    def fake_run(cmd, input=None, text=None, capture_output=None):
        if input.startswith("ls "):
            return mock.Mock(returncode=0, stderr="", stdout="a\nb\n")
        return mock.Mock(returncode=0, stderr="", stdout=_STAT_FILE + "__QMU_LINKS__\n")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)
    with pytest.raises(QMUError, match="inconclusive"):
        rootfs_mod.listdir(str(image), "/x", partition=0)


def _fake_download(payload: bytes):
    def fake_run(cmd, input=None, text=None, capture_output=None):
        assert input.startswith("download ")
        from pathlib import Path
        Path(input.split()[-1]).write_bytes(payload)
        return mock.Mock(returncode=0, stderr="", stdout="")
    return fake_run


def test_cat_text_is_byte_exact(tmp_path, monkeypatch, capfdbinary):
    """guestfish `cat` appended a newline; 74 bytes came back as 75 (harness F15)."""
    from qmu import cli
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_download(b"poweroff -f"))

    rc = cli.main(["rootfs", "cat", str(image), "/run.sh", "--partition", "0"])

    assert rc == 0
    assert capfdbinary.readouterr().out == b"poweroff -f"


def test_cat_json_reports_size_and_encoding(tmp_path, monkeypatch, capsys):
    import json
    from qmu import cli
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_download(b"poweroff -f"))
    rc = cli.main(["rootfs", "cat", str(image), "/run.sh", "--partition", "0",
                   "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert (data["content"], data["size"], data["encoding"]) == ("poweroff -f", 11, "utf-8")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_download(b"\x7fELF\x00\xff"))
    rc = cli.main(["rootfs", "cat", str(image), "/bin/x", "--partition", "0",
                   "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["encoding"] == "base64"
    assert data["size"] == 6
    import base64
    assert base64.b64decode(data["content"]) == b"\x7fELF\x00\xff"


def test_inject_json_reports_landed_path_and_owner(tmp_path, monkeypatch, capsys):
    import json
    from qmu import cli
    local = tmp_path / "exploit"
    local.write_text("payload")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "inject", lambda *a, **k: None)

    rc = cli.main(["rootfs", "inject", str(image), f"{local}:/root/", "--partition",
                   "0", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["injected"] == [
        {"local": str(local), "guest": "/root/", "path": "/root/exploit", "owner": "0:0"}
    ]
