"""qmu rootfs — guestfish missing should produce a clear install hint."""

from __future__ import annotations

import base64
import json
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


def _inject_with_fake_guestfish(tmp_path, guest, mkdir=False, *, dir_exists=True):
    """Run inject against a stubbed guestfish whose `is-dir` answers `dir_exists`."""
    local = tmp_path / "exploit"
    local.write_text("payload")
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    answer = b"true\n" if dir_exists else b"false\n"
    completed = mock.Mock(returncode=0, stderr=b"", stdout=answer)
    with mock.patch.object(rootfs_mod, "_require_guestfish", return_value="guestfish"):
        with mock.patch.object(rootfs_mod.subprocess, "run", return_value=completed):
            rootfs_mod.inject(
                str(image), [(str(local), guest)], partition=1, mkdir=mkdir
            )


@pytest.mark.parametrize("guest", ["/root", "/root/"])
def test_inject_guest_is_a_directory_with_or_without_trailing_slash(tmp_path, guest):
    # Regression: `/root` used to collapse to `/` via dirname().
    local = tmp_path / "exploit"
    local.write_text("payload")
    assert rootfs_mod._inject_guest_dirs([(str(local), guest)]) == ["/root"]
    assert rootfs_mod._landed_paths(local, "/root/exploit")[0][0] == "/root/exploit"


def test_inject_root_guest_stays_root():
    assert rootfs_mod._inject_guest_dirs([("x", "/")]) == ["/"]


def test_inject_refuses_a_missing_guest_dir_by_default(tmp_path):
    """A silent mkdir turns a typo'd destination into a reported success."""
    with pytest.raises(QMUError, match="Guest directory not found"):
        _inject_with_fake_guestfish(tmp_path, "/rooot", dir_exists=False)


def test_inject_creates_the_guest_dir_when_asked(tmp_path):
    _inject_with_fake_guestfish(tmp_path, "/rooot", mkdir=True, dir_exists=False)


def test_landed_paths_cover_exactly_the_source_tree(tmp_path):
    """Ownership is normalized for what *this* injection copied — enumerated
    from the source, so a pre-existing guest file under a merged directory
    is never touched (it used to be chowned to 0:0 along with the tree)."""
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a").write_text("x")
    (tree / "sub" / "b").write_text("y")
    (tree / "sub" / "dangling").symlink_to("/does/not/exist")
    (tree / "a").chmod(0o6755)

    landed = rootfs_mod._landed_paths(tree, "/opt/tree")

    assert [p for p, _ in landed] == [
        "/opt/tree", "/opt/tree/a", "/opt/tree/sub",
        "/opt/tree/sub/b", "/opt/tree/sub/dangling",
    ]
    modes = dict(landed)
    assert rootfs_mod.stat_mod.S_IMODE(modes["/opt/tree/a"]) == 0o6755
    assert rootfs_mod.stat_mod.S_ISLNK(modes["/opt/tree/sub/dangling"])


def test_landed_paths_single_file_and_symlink(tmp_path):
    f = tmp_path / "exploit"
    f.write_text("x")
    f.chmod(0o700)
    link = tmp_path / "link"
    link.symlink_to("/nowhere")
    (p, mode), = rootfs_mod._landed_paths(f, "/root/exploit")
    assert (p, rootfs_mod.stat_mod.S_IMODE(mode)) == ("/root/exploit", 0o700)
    (p, mode), = rootfs_mod._landed_paths(link, "/root/link")
    assert p == "/root/link" and rootfs_mod.stat_mod.S_ISLNK(mode)


def test_landed_paths_skip_sockets(tmp_path):
    import socket
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "f").write_text("x")
    with socket.socket(socket.AF_UNIX) as s:
        s.bind(str(tree / "sock"))
        assert [p for p, _ in rootfs_mod._landed_paths(tree, "/t")] == ["/t", "/t/f"]


@pytest.mark.parametrize("name", [
    "don't.txt", 'say "hi".txt', "with space.txt", "back\\slash.txt",
    "new\nline.txt", "tab\there", "ünïcødé.txt", "", "\x7f",
])
def test_guestfish_quote_round_trips_through_guestfish_rules(name):
    """Decode with guestfish's own double-quote rules (guestfish(1) QUOTING):
    one token, terminated by the closing quote, escapes \\\\ \\" and \\ooo."""
    quoted = rootfs_mod.guestfish_quote(name)
    assert "\n" not in quoted and "\t" not in quoted, "a raw control char breaks the line"
    assert _guestfish_unquote(quoted) == name


def test_guestfish_quote_is_not_shell_quoting():
    """shlex's `'don'"'"'t'` form is what guestfish rejects with
    'command arguments not separated by whitespace'."""
    assert rootfs_mod.guestfish_quote("don't.txt") == '"don\'t.txt"'
    assert rootfs_mod.guestfish_quote('a"b\\c') == '"a\\"b\\\\c"'
    assert rootfs_mod.guestfish_quote("a\nb") == '"a\\012b"'


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

    def fake_run(cmd, input=None, capture_output=None):
        seen["cmd"] = cmd
        assert isinstance(input, bytes), "guestfish transport must be byte-exact"
        return mock.Mock(returncode=0, stderr=b"", stdout=b"false\n")

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)

    with pytest.raises(QMUError, match="Guest directory not found in .*: /rooot"):
        rootfs_mod.preflight_inject(str(image), [(str(local), "/rooot")], partition=0)
    assert "--ro" in seen["cmd"]

    with pytest.raises(QMUError, match="Local file not found"):
        rootfs_mod.preflight_inject(str(image), [("/no/such", "/root")], partition=0)
    with pytest.raises(QMUError, match="Image not found"):
        rootfs_mod.preflight_inject("/no/img", [(str(local), "/root")], partition=0)


def _stat_block(mode: int, size: int, uid: int = 0, gid: int = 0, mtime: int = 0) -> bytes:
    return (
        f"st_dev: 2048\nst_ino: 306\nst_mode: {mode}\nst_nlink: 1\nst_uid: {uid}\n"
        f"st_gid: {gid}\nst_rdev: 0\nst_size: {size}\nst_blksize: 4096\nst_blocks: 8\n"
        f"st_atime_sec: 1\nst_atime_nsec: 0\nst_mtime_sec: {mtime}\n"
        f"st_mtime_nsec: 0\nst_ctime_sec: 1\nst_ctime_nsec: 0\n"
    ).encode()


def _guestfish_unquote(token: str) -> str:
    """Decode one double-quoted guestfish argument (guestfish(1) QUOTING)."""
    assert token[0] == '"' and token[-1] == '"', token
    body, out, i = token[1:-1], [], 0
    while i < len(body):
        ch = body[i]
        assert ch != '"'
        if ch == "\\":
            nxt = body[i + 1]
            if nxt in '"\\':
                out.append(nxt); i += 2
            else:
                out.append(chr(int(body[i + 1:i + 4], 8))); i += 4
        else:
            out.append(ch); i += 1
    return "".join(out)


def _b(s: str | bytes) -> bytes:
    return s if isinstance(s, bytes) else s.encode("utf-8", "surrogateescape")


def _fake_guestfish(tree: dict[str, dict[str | bytes, tuple]]):
    """A subprocess.run double that behaves like guestfish for the commands
    `listdir` emits: `ls0 DIR -` (NUL-terminated names), `-readlink P`
    (target + newline for symlinks, nothing otherwise) and `lstatns P`.
    `tree` is {dir: {name: (st_mode, size, uid, gid, target)}}; names and
    targets may be bytes to model a guest that is not UTF-8. Like the real
    guestfish it reads and writes raw bytes, so a `\\r` in a name survives
    only if the caller never puts the pipe in text mode."""
    import posixpath

    btree = {d: {_b(n): v for n, v in entries.items()} for d, entries in tree.items()}

    def lookup(path):
        d, n = posixpath.split(path)
        return btree[d][_b(n)]

    def run(cmd, input=None, capture_output=None):
        assert isinstance(input, bytes), "guestfish transport must be byte-exact"
        out = []
        for line in input.decode("utf-8", "surrogateescape").split("\n"):
            if not line:
                continue
            verb, _, rest = line.partition(" ")
            if verb == "ls0":
                arg = _guestfish_unquote(rest[: rest.rindex('"') + 1])
                assert rest.endswith(" -")
                out.append(b"".join(n + b"\0" for n in btree[arg]))
            elif verb == "-readlink":
                mode, size, uid, gid, target = lookup(_guestfish_unquote(rest))
                if rootfs_mod.stat_mod.S_ISLNK(mode):
                    out.append(_b(target) + b"\n")
            elif verb == "lstatns":
                mode, size, uid, gid, target = lookup(_guestfish_unquote(rest))
                out.append(_stat_block(mode, size, uid, gid))
            else:
                raise AssertionError(f"unexpected guestfish command: {line}")
        return mock.Mock(returncode=0, stderr=b"", stdout=b"".join(out))

    return run


_REG = 0o100755
_LNK = 0o120777


def test_listdir_returns_structured_entries(tmp_path, monkeypatch):
    """JSON used to carry raw `ls -l` strings (harness F14)."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_guestfish({
        "/etc": {
            "run.sh": (_REG, 74, 1005, 1000, None),
            "localtime": (_LNK, 27, 0, 0, "/usr/share/zoneinfo/Etc/UTC"),
        },
    }))

    entries = rootfs_mod.listdir(str(image), "/etc", partition=0)

    assert entries == [
        {"name": "localtime", "type": "symlink", "mode": "0777", "uid": 0,
         "gid": 0, "size": 27, "mtime": "1970-01-01T00:00:00Z",
         "target": "/usr/share/zoneinfo/Etc/UTC"},
        {"name": "run.sh", "type": "file", "mode": "0755", "uid": 1005,
         "gid": 1000, "size": 74, "mtime": "1970-01-01T00:00:00Z"},
    ]
    assert rootfs_mod.format_entry(entries[1]) == (
        "-rwxr-xr-x  1005  1000        74 1970-01-01T00:00:00Z run.sh"
    )
    assert rootfs_mod.format_entry(entries[0]).endswith(
        "localtime -> /usr/share/zoneinfo/Etc/UTC"
    )


def test_listdir_targets_and_names_are_data_not_framing(tmp_path, monkeypatch):
    """A link target equal to the old `__QMU_SEP__` delimiter shifted every
    later target (b reported "" and c reported b's target); a target or name
    holding a newline, or a target that looks like a stat line, must likewise
    come back verbatim."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_guestfish({
        "/root/links": {
            "a": (_LNK, 11, 0, 0, "__QMU_SEP__"),
            "b": (_LNK, 11, 0, 0, "/etc/passwd"),
            "c": (_LNK, 10, 0, 0, "multi\nline"),
            "d": (_LNK, 11, 0, 0, "st_dev: 1\n\n"),
            "don't\n.txt": (_REG, 3, 0, 0, None),
            "e": (_LNK, 0, 0, 0, ""),
            "f": (_REG, 5, 0, 0, None),
            "ü": (_LNK, 2, 0, 0, "ü"),
        },
    }))

    entries = rootfs_mod.listdir(str(image), "/root/links", partition=0)

    assert [(e["name"], e.get("target")) for e in entries] == [
        ("a", "__QMU_SEP__"), ("b", "/etc/passwd"), ("c", "multi\nline"),
        ("d", "st_dev: 1\n\n"), ("don't\n.txt", None), ("e", ""),
        ("f", None), ("ü", "ü"),
    ]


def test_listdir_misaligned_readlink_output_is_an_error_not_a_guess(tmp_path, monkeypatch):
    """If a symlink's readlink output does not match its st_size (the link
    changed under us, or readlink failed), report rather than mis-assign."""
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_guestfish({
        "/x": {"a": (_LNK, 5, 0, 0, "/etc/passwd")},
    }))
    with pytest.raises(QMUError, match="inconclusive"):
        rootfs_mod.listdir(str(image), "/x", partition=0)


def test_listdir_short_stat_read_is_an_error_not_a_guess(tmp_path, monkeypatch):
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")

    def fake_run(cmd, input=None, capture_output=None):
        if input.startswith(b"ls0 "):
            return mock.Mock(returncode=0, stderr=b"", stdout=b"a\0b\0")
        return mock.Mock(returncode=0, stderr=b"", stdout=_stat_block(_REG, 1))

    monkeypatch.setattr(rootfs_mod.subprocess, "run", fake_run)
    with pytest.raises(QMUError, match="inconclusive"):
        rootfs_mod.listdir(str(image), "/x", partition=0)


def _fake_download(payload: bytes):
    def fake_run(cmd, input=None, capture_output=None):
        assert input.startswith(b"download ")
        from pathlib import Path
        Path(_guestfish_unquote(input.decode().strip().split(" ")[-1])).write_bytes(payload)
        return mock.Mock(returncode=0, stderr=b"", stdout=b"")
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


def _listdir(tmp_path, monkeypatch, entries: dict[str | bytes, tuple]) -> list[dict]:
    image = tmp_path / "rootfs.img"
    image.write_text("disk")
    monkeypatch.setattr(rootfs_mod, "_require_guestfish", lambda: "guestfish")
    monkeypatch.setattr(rootfs_mod.subprocess, "run", _fake_guestfish({"/d": entries}))
    return rootfs_mod.listdir(str(image), "/d", partition=0)


def test_listdir_keeps_cr_lf_and_crlf_names_distinct(tmp_path, monkeypatch):
    """#111: text-mode stdout folded `\\r` into `\\n` before the NUL split, so
    the CR-named file vanished and the LF-named one was listed twice."""
    entries = _listdir(tmp_path, monkeypatch, {
        "a\rb": (_REG, 10, 0, 0, None),
        "a\nb": (_REG, 2, 0, 0, None),
        "a\r\nb": (_REG, 8, 0, 0, None),
    })
    assert sorted((e["name"], e["size"]) for e in entries) == [
        ("a\nb", 2), ("a\r\nb", 8), ("a\rb", 10),
    ]
    assert not any("name_bytes_b64" in e for e in entries)
    # The JSON a consumer reads back distinguishes the three as well.
    assert {json.loads(json.dumps(e))["name"] for e in entries} == {"a\rb", "a\nb", "a\r\nb"}


def test_listdir_cr_in_link_target_is_preserved(tmp_path, monkeypatch):
    entries = _listdir(tmp_path, monkeypatch, {
        "link": (_LNK, 3, 0, 0, "x\ry"), "other": (_LNK, 3, 0, 0, "x\ny"),
    })
    assert [e["target"] for e in entries] == ["x\ry", "x\ny"]


def test_listdir_non_utf8_name_and_target_carry_exact_bytes(tmp_path, monkeypatch):
    raw_name = b"caf\xe9"
    raw_target = b"\xff\xfe"
    entries = _listdir(tmp_path, monkeypatch, {
        raw_name: (_REG, 1, 0, 0, None), "l": (_LNK, 2, 0, 0, raw_target),
    })
    by_name = {e.get("name_bytes_b64", e["name"]): e for e in entries}
    name_entry = by_name[base64.b64encode(raw_name).decode()]
    assert base64.b64decode(name_entry["name_bytes_b64"]) == raw_name
    assert name_entry["size"] == 1
    link = by_name["l"]
    assert base64.b64decode(link["target_bytes_b64"]) == raw_target
    assert "name_bytes_b64" not in link
    # Every field is encodable for a stdout consumer: no lone surrogates.
    for e in entries:
        json.dumps(e).encode("utf-8")
        rootfs_mod.format_entry(e).encode("utf-8")


def test_format_entry_keeps_one_line_per_entry(tmp_path, monkeypatch):
    entries = _listdir(tmp_path, monkeypatch, {
        "a\rb": (_REG, 1, 0, 0, None), "a\nb": (_REG, 1, 0, 0, None),
        "a\r\nb": (_REG, 1, 0, 0, None),
    })
    lines = [rootfs_mod.format_entry(e) for e in entries]
    assert all("\n" not in line and "\r" not in line for line in lines)
    assert len(set(lines)) == 3
