from __future__ import annotations

import gzip
import json
import re
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MKTARGET = ROOT / "tools/mktarget.sh"


# --- fixture archive contents ------------------------------------------------
#
# Deliberately shaped like the real indexes: every ABI appears under BOTH
# linux-image-unsigned-<ABI>-generic and linux-image-<ABI>-generic, and the
# -updates and -security pockets carry the same build. That is four rows per
# ABI, and collapsing them to one is the behaviour under test.

_RELEASE_POCKET_ABIS = [("6.8.0-31", "6.8.0-31.31")]
_UPDATES_ABIS = [
    ("6.8.0-53", "6.8.0-53.55"),   # note: NOT the abi doubled
    ("6.8.0-124", "6.8.0-124.124"),
    ("6.8.0-137", "6.8.0-137.137"),
]
# Mirrors reality: symbol availability is uncorrelated with recency.
_DBGSYM_ABIS = ["6.8.0-31", "6.8.0-124"]


def _packages_body(entries: list[tuple[str, str]]) -> str:
    stanzas = []
    for abi, ver in entries:
        for name in (
            f"linux-image-unsigned-{abi}-generic",
            f"linux-image-{abi}-generic",
        ):
            stanzas.append(
                f"Package: {name}\nVersion: {ver}\n"
                f"Architecture: amd64\nInstalled-Size: 14792\n"
            )
        stanzas.append(
            f"Package: linux-modules-{abi}-generic\nVersion: {ver}\n"
            f"Architecture: amd64\n"
        )
    return "\n".join(stanzas) + "\n"


def _ddebs_body(abis: list[str]) -> str:
    return (
        "\n".join(
            f"Package: linux-image-unsigned-{abi}-generic-dbgsym\n"
            f"Version: x\nArchitecture: amd64\n"
            for abi in abis
        )
        + "\n"
    )


@pytest.fixture
def mktarget_env(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker.jsonl"
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()

    # Pre-gzipped index bodies the fake curl serves verbatim.
    (fixtures / "release.gz").write_bytes(
        gzip.compress(_packages_body(_RELEASE_POCKET_ABIS).encode())
    )
    (fixtures / "updates.gz").write_bytes(
        gzip.compress(_packages_body(_UPDATES_ABIS).encode())
    )
    (fixtures / "empty.gz").write_bytes(gzip.compress(b"\n"))
    (fixtures / "ddebs.gz").write_bytes(gzip.compress(_ddebs_body(_DBGSYM_ABIS).encode()))

    curl = fake_bin / "curl"
    curl.write_text(
        f'''#!/usr/bin/env python3
import os
import sys
from pathlib import Path

FIX = Path({str(fixtures)!r})
args = sys.argv[1:]
url = [a for a in args if a.startswith("http")]
if not url:
    raise SystemExit(2)
url = url[-1]

# honour -o, as the real curl does: the ddebs pocket probe uses -o /dev/null
# and a fake that ignored it would invent a stdout leak the script does not have
out = None
if "-o" in args:
    out = args[args.index("-o") + 1]

# The script distinguishes "this pocket 404s" from "this fetch faulted", and it
# can only do that by reading -w %{{http_code}}. A fake that ignored -w would
# make every fetch look like a fault, so the contract is modelled here.
want_code = "-w" in args and "%{{http_code}}" in args[args.index("-w") + 1]
fail_hard = "-f" in args or "-sSfL" in args

def finish(code: int, data: bytes = b""):
    if code == 200 and data:
        if out is not None:
            Path(out).write_bytes(data)
        else:
            sys.stdout.buffer.write(data)
    if want_code:
        sys.stdout.write(str(code).zfill(3))
    if code == 0:
        raise SystemExit(7)          # transport failure, as curl reports it
    if code >= 400 and fail_hard:
        raise SystemExit(22)         # curl -f on an HTTP error
    raise SystemExit(0)

# fault injection: substring match on the URL
fault = os.environ.get("MKTARGET_FAKE_CURL_FAULT")
if fault and fault in url:
    finish(0)
gone = os.environ.get("MKTARGET_FAKE_CURL_404")
if gone and gone in url:
    finish(404)

if url.endswith("/Release"):
    finish(200, b"Origin: Ubuntu\\nDate: Thu, 25 Apr 2024 15:10:33 UTC\\n")

if "ddebs" in url:
    # only the release pocket carries dbgsym in this fixture, and ddebs has no
    # -security pocket at all -- that is a 404, not an empty index
    if "/dists/noble-security/" in url:
        finish(404)
    body = FIX / ("ddebs.gz" if "/dists/noble/" in url else "empty.gz")
elif "/dists/noble/" in url:
    body = FIX / "release.gz"
elif "-updates/" in url or "-security/" in url:
    body = FIX / "updates.gz"
else:
    finish(404)

finish(200, body.read_bytes())
'''
    )
    curl.chmod(0o755)

    docker = fake_bin / "docker"
    dockerfile_log = tmp_path / "Dockerfile.sent"
    docker.write_text(
        f'''#!/usr/bin/env python3
import json
import os
import sys
import tarfile
import io
from pathlib import Path

args = sys.argv[1:]
LOG = Path({str(docker_log)!r})
DOCKERFILE = Path({str(dockerfile_log)!r})
with LOG.open("a") as fh:
    fh.write(json.dumps(args) + "\\n")

if os.environ.get("MKTARGET_FAIL_IF_DOCKER_RUNS") == "1":
    print("docker was forbidden for this cache hit", file=sys.stderr)
    raise SystemExit(97)

verb = args[0] if args else ""

if verb == "build":
    # consume the Dockerfile on stdin so the writer never sees EPIPE, and keep
    # it: what the guest ends up with is decided here, so assertions about the
    # guest should read this rather than grepping the script's own source
    DOCKERFILE.write_text(sys.stdin.read())
    raise SystemExit(0)

if verb == "create":
    print("fakecid123")
    raise SystemExit(0)

if verb == "cp":
    src, dest = args[1], args[2]
    name = src.split(":", 1)[1]
    dest = Path(dest)
    if dest.is_dir():
        dest = dest / Path(name).name
    if "vmlinuz" in name:
        # bzImage-shaped: must NOT have gzip magic, or the script would
        # try to decompress it
        dest.write_bytes(b"MZ\\x00\\x00bzImage-ish\\n")
    elif "config" in name:
        dest.write_text("CONFIG_EXT4_FS=y\\nCONFIG_RANDOM_KMALLOC_CACHES=y\\n")
    elif "dpkg/status" in name:
        # dpkg's real paragraph shape: Status precedes Version, not-installed
        # entries linger in the database, and the file ends without a blank line
        dest.write_text(
            "Package: apparmor\\n"
            "Status: install ok installed\\n"
            "Architecture: amd64\\n"
            "Version: 4.0.1really4.0.0-beta3-0ubuntu0.24.04.4\\n"
            "\\n"
            "Package: procps\\n"
            "Status: install ok installed\\n"
            "Version: 2:4.0.4-4ubuntu3.2\\n"
            "\\n"
            "Package: removed-but-configured\\n"
            "Status: deinstall ok config-files\\n"
            "Version: 1.0\\n"
            "\\n"
            "Package: systemd\\n"
            "Status: install ok installed\\n"
            "Version: 255.4-1ubuntu8.6\\n"
        )
    else:
        dest.write_text("ffffffff81000000 T _text\\n")
    raise SystemExit(0)

if verb == "export":
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("etc/hostname")
        data = b"qmu-ubuntu\\n"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    sys.stdout.buffer.write(buf.getvalue())
    raise SystemExit(0)

if verb == "rm":
    raise SystemExit(0)

if verb == "run":
    # drain stdin (docker export pipes into the mke2fs helper)
    try:
        sys.stdin.buffer.read()
    except Exception:
        pass
    out = None
    for i, a in enumerate(args):
        if a == "-v":
            host, container = args[i + 1].rsplit(":", 1)
            if container == "/output":
                out = Path(host)
    inner = args[-1]
    if out is not None and "mke2fs" in inner:
        (out / "rootfs.img").write_bytes(b"\\0" * 4096)
    elif out is not None and "dbgsym" in inner:
        if os.environ.get("MKTARGET_FAKE_DBGSYM_FAIL") == "1":
            print("ddeb extraction blew up", file=sys.stderr)
            raise SystemExit(1)
        krel = next(a.split("=", 1)[1] for a in args if a.startswith("KREL="))
        (out / ("vmlinux-" + krel)).write_text("ELF\\n")
        # --symbols=full additionally unpacks the module debug tree; a helper
        # that produced only vmlinux would let a full request look satisfied
        if "KEEP_MODULES=1" in args:
            mods = out / "usr/lib/debug/lib/modules" / krel / "kernel/fs/overlayfs"
            mods.mkdir(parents=True, exist_ok=True)
            (mods / "overlay.ko").write_text("ELF\\n")
    raise SystemExit(0)

raise SystemExit(0)
'''
    )
    docker.chmod(0o755)

    env = {
        "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(tmp_path / "home"),
        "QMU_CACHE_DIR": str(cache),
    }
    (tmp_path / "home").mkdir()

    class Env:
        def __init__(self):
            self.cache = cache
            self.env = env
            self.tmp_path = tmp_path

        def run(self, *extra, fail_if_docker_runs=False, **envvars):
            e = dict(env)
            if fail_if_docker_runs:
                e["MKTARGET_FAIL_IF_DOCKER_RUNS"] = "1"
            e.update(envvars)
            return subprocess.run(
                [str(MKTARGET), *extra],
                text=True,
                capture_output=True,
                check=False,
                env=e,
            )

        def docker_calls(self):
            if not docker_log.exists():
                return []
            return [json.loads(l) for l in docker_log.read_text().splitlines() if l]

        def dockerfile(self):
            return dockerfile_log.read_text()

        def clear_docker_log(self):
            docker_log.unlink(missing_ok=True)

        def fixture(self, name):
            return fixtures / name

        def set_release_pocket(self, entries):
            """Rewrite the release-pocket index, as the archive itself would."""
            (fixtures / "release.gz").write_bytes(
                gzip.compress(_packages_body(entries).encode())
            )

    return Env()


def _run_block(dockerfile: str, marker: str) -> str:
    """The text of the single RUN instruction containing `marker`.

    Reads the Dockerfile that was actually sent to `docker build`, so a layer
    that exists in mktarget.sh but never reaches the build cannot pass.
    """
    blocks, cur = [], []
    for line in dockerfile.splitlines():
        cur.append(line)
        if not line.rstrip().endswith("\\"):
            blocks.append("\n".join(cur))
            cur = []
    if cur:
        blocks.append("\n".join(cur))
    hits = [b for b in blocks if b.lstrip().startswith("RUN") and marker in b]
    assert len(hits) == 1, f"want 1 RUN block containing {marker!r}, found {len(hits)}"
    return hits[0]


def _user_stub_bin(tmp_path, passwd_lines):
    """A PATH shim for the account tools, backed by a fake /etc/passwd.

    Lets the guest's user-setup logic actually RUN. Without this the suite could
    only assert on the text of the Dockerfile, which is how `useradd -u 1000`
    against an already-occupied uid 1000 shipped: every test passed and every
    real build with --unpriv-user died.
    """
    binp = tmp_path / "userbin"
    binp.mkdir()
    pw = tmp_path / "passwd.fixture"
    pw.write_text("".join(l + "\n" for l in passwd_lines))
    log = tmp_path / "usercalls.log"

    preamble = f'''#!/usr/bin/env python3
import sys
from pathlib import Path
PW = Path({str(pw)!r})
LOG = Path({str(log)!r})
ARGS = sys.argv[1:]
with LOG.open("a") as fh:
    fh.write(" ".join([Path(sys.argv[0]).name] + ARGS) + "\\n")
ROWS = [l.split(":") for l in PW.read_text().splitlines() if l.strip()]
'''
    bodies = {
        "id": '''
name = ARGS[-1]
for r in ROWS:
    if r[0] == name:
        print(r[2]); raise SystemExit(0)
print("id: no such user", file=sys.stderr); raise SystemExit(1)
''',
        "getent": '''
key = ARGS[-1]
for r in ROWS:
    if r[0] == key or r[2] == key:
        print(":".join(r)); raise SystemExit(0)
raise SystemExit(2)
''',
    }
    for name in ("useradd", "usermod", "groupmod", "chpasswd"):
        bodies[name] = "\nraise SystemExit(0)\n"

    for name, body in bodies.items():
        p = binp / name
        p.write_text(preamble + body)
        p.chmod(0o755)
    return binp, log


def _exec_user_setup(mktarget_env, tmp_path, unpriv_user, passwd_lines):
    """Run the guest's account-resolution logic against the fake passwd db."""
    block = _run_block(mktarget_env.dockerfile(), "must name a non-root user")
    script = re.sub(r"^RUN\s+", "", block)
    # stop before the parts that would write to the real /home; the account
    # resolution above it is what this exercises
    cut = script.index('mkdir -p "/home/')
    script = script[:cut].rstrip().rstrip("\\").rstrip().rstrip(";")

    binp, log = _user_stub_bin(tmp_path, passwd_lines)
    proc = subprocess.run(
        ["sh", "-c", script],
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": f"{binp}:/usr/bin:/bin",
            "UNPRIV_USER": unpriv_user,
        },
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return proc, calls


def _assignments(stdout: str) -> dict[str, str]:
    """Parse stdout the way `eval $(...)` would, and fail if it is not pure."""
    out = {}
    for line in stdout.splitlines():
        assert "=" in line, f"non-assignment line leaked to stdout: {line!r}"
        key, value = line.split("=", 1)
        assert key.isidentifier(), f"not a shell identifier: {key!r}"
        # shlex.split mirrors what the shell does to the %q-quoted value
        parts = shlex.split(value)
        out[key] = parts[0] if parts else ""
    return out


# --- tests -------------------------------------------------------------------


def test_list_abis_emits_no_assignments_and_dedups(mktarget_env):
    r = mktarget_env.run("--list-abis")
    assert r.returncode == 0, r.stderr
    # the whole table goes to stderr; stdout must stay empty so that
    # `eval $(mktarget.sh --list-abis)` cannot silently assign anything
    assert r.stdout == ""
    assert not mktarget_env.docker_calls()

    table = [l for l in r.stderr.splitlines() if l.startswith("6.8.")]
    abis = [l.split()[0] for l in table]
    assert abis == sorted(set(abis), key=lambda s: int(s.rsplit("-", 1)[1])), table
    # one row per ABI even though the fixture has four rows for each
    assert len(abis) == len(set(abis))
    assert set(abis) == {"6.8.0-31", "6.8.0-53", "6.8.0-124", "6.8.0-137"}

    rows = {l.split()[0]: l.split() for l in table}
    # the release pocket wins for the GA ABI, and the deb version is taken from
    # the index rather than reconstructed from the ABI
    assert rows["6.8.0-31"][2] == "noble"
    assert rows["6.8.0-53"][1] == "6.8.0-53.55"
    # dbgsym column reflects the ddebs index, not recency
    assert rows["6.8.0-31"][3] == "yes"
    assert rows["6.8.0-137"][3] == "no"


def test_ga_resolves_to_release_pocket_abi(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    a = _assignments(r.stdout)
    assert a["KERNEL_ABI"] == "6.8.0-31"
    assert a["KERNEL_DEB_VERSION"] == "6.8.0-31.31"
    assert a["PROFILE"] == "ubuntu-target"


def test_latest_prefers_highest_abi_numerically_not_lexically(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "latest")
    assert r.returncode == 0, r.stderr
    # lexical sorting would pick 6.8.0-53
    assert _assignments(r.stdout)["KERNEL_ABI"] == "6.8.0-137"


def test_latest_with_symbols_skips_newer_symbolless_abis(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "latest-with-symbols")
    assert r.returncode == 0, r.stderr
    # -137 is newer but has no dbgsym; -124 does
    assert _assignments(r.stdout)["KERNEL_ABI"] == "6.8.0-124"


def test_symbols_on_symbolless_abi_fails_before_building(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "6.8.0-137", "--symbols")
    assert r.returncode == 2
    assert "no dbgsym exists" in r.stderr
    # the available ABIs are named so the user can act
    assert "6.8.0-124" in r.stderr
    assert "latest-with-symbols" in r.stderr
    # and nothing was built
    assert not any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_unknown_abi_spec_is_rejected(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "6.8")
    assert r.returncode == 2
    assert "unrecognised --kernel-abi" in r.stderr


def test_missing_abi_points_at_list_abis(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "9.9.9-1")
    assert r.returncode == 2
    assert "--list-abis" in r.stderr


@pytest.mark.parametrize(
    "arch,needle",
    [
        ("i386", "no Ubuntu kernel"),
        ("arm32", "not supported yet"),
        ("riscv64", "unsupported --arch"),
    ],
)
def test_rejected_arches_fail_before_any_docker_call(mktarget_env, arch, needle):
    r = mktarget_env.run("--arch", arch)
    assert r.returncode == 2
    assert needle in r.stderr
    assert not mktarget_env.docker_calls()


def test_stdout_is_pure_and_quoted_for_hostile_paths(mktarget_env):
    outdir = mktarget_env.tmp_path / "out dir; echo pwned"
    r = mktarget_env.run("--outdir", str(outdir))
    assert r.returncode == 0, r.stderr
    a = _assignments(r.stdout)
    # %q quoting survives a round-trip through the shell's own parser
    assert a["ROOTFS"] == str(outdir / "rootfs.img")
    # and evaluating it really is inert
    probe = subprocess.run(
        ["bash", "-c", f"eval {shlex.quote(r.stdout)}; printf '%s' \"$ROOTFS\""],
        text=True,
        capture_output=True,
        check=True,
    )
    assert probe.stdout == str(outdir / "rootfs.img")


def test_kernel_packages_are_version_pinned_with_no_recommends(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    build = next(c for c in mktarget_env.docker_calls() if c[0] == "build")
    kpkgs = next(
        a.split("=", 1)[1] for a in build if a.startswith("KPKGS=")
    )
    # the exact deb version, not a floating meta-package
    assert "linux-image-unsigned-6.8.0-31-generic=6.8.0-31.31" in kpkgs
    assert "linux-modules-6.8.0-31-generic=6.8.0-31.31" in kpkgs
    assert "linux-image-generic" not in kpkgs
    # modules-extra is on by default: several notable LPE targets live there
    assert "linux-modules-extra-6.8.0-31-generic=6.8.0-31.31" in kpkgs


def test_no_modules_extra_flag_drops_the_package(mktarget_env):
    r = mktarget_env.run("--no-modules-extra")
    assert r.returncode == 0, r.stderr
    build = next(c for c in mktarget_env.docker_calls() if c[0] == "build")
    kpkgs = next(a.split("=", 1)[1] for a in build if a.startswith("KPKGS="))
    assert "linux-modules-extra" not in kpkgs


def test_container_marker_is_stripped_after_export(mktarget_env):
    """/.dockerenv makes systemd-detect-virt report docker, whereupon AppArmor
    loads none of its profiles while still exiting 0. It cannot be removed
    inside the build (docker bind-mounts it), so the strip must happen between
    docker export and mke2fs."""
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    mke2fs = next(
        c for c in mktarget_env.docker_calls()
        if c[0] == "run" and "mke2fs" in c[-1]
    )
    inner = mke2fs[-1]
    assert "rm -f /rootfs/.dockerenv" in inner
    assert inner.index("dockerenv") < inner.index("mke2fs")


def test_guest_stamp_is_deterministic_across_rebuilds(mktarget_env):
    """GUEST_STAMP is a build-arg, so any value that changes between runs
    invalidates BuildKit's cache from the ARG declaration onward and re-runs the
    whole apt install -- ~12 minutes under qemu-user for a cross-arch target."""
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    stamp1 = next(
        a for c in mktarget_env.docker_calls() if c[0] == "build"
        for a in c if a.startswith("GUEST_STAMP=")
    )
    mktarget_env.clear_docker_log()

    # force a real rebuild rather than a cache hit
    Path(_assignments(first.stdout)["ROOTFS"]).unlink()
    second = mktarget_env.run("--kernel-abi", "ga")
    assert second.returncode == 0, second.stderr
    stamp2 = next(
        a for c in mktarget_env.docker_calls() if c[0] == "build"
        for a in c if a.startswith("GUEST_STAMP=")
    )

    assert stamp1 == stamp2
    # the volatile fields belong to the host manifest only
    assert "built_at" not in stamp1
    assert "archive_release_date" not in stamp1
    manifest = json.loads(Path(_assignments(second.stdout)["TARGET_MANIFEST"]).read_text())
    assert manifest["built_at"]
    assert manifest["archive_release_date"]


def test_mke2fs_helper_runs_on_the_host_platform(mktarget_env):
    """Untarring an export and writing ext4 is arch-independent, but after a
    cross-arch build the local ubuntu:<suite> tag points at the target-arch
    image -- so an unpinned helper would run under qemu-user and emulate tar
    and mke2fs for minutes."""
    r = mktarget_env.run("--arch", "arm64", "--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    mke2fs = next(
        c for c in mktarget_env.docker_calls()
        if c[0] == "run" and "mke2fs" in c[-1]
    )
    platform = mke2fs[mke2fs.index("--platform") + 1]
    assert platform != "linux/arm64", "helper was pinned to the TARGET platform"
    assert platform in ("linux/amd64", "linux/arm64")

    # the symbols helper, by contrast, MUST be the target platform: it runs
    # `apt-get download` and would otherwise resolve the wrong arch's ddeb
    r2 = mktarget_env.run("--arch", "arm64", "--kernel-abi", "ga", "--symbols")
    assert r2.returncode == 0, r2.stderr
    sym = next(
        c for c in mktarget_env.docker_calls()
        if c[0] == "run" and "dbgsym" in c[-1]
    )
    assert sym[sym.index("--platform") + 1] == "linux/arm64"


def test_fidelity_is_the_default_and_is_recorded(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    a = _assignments(r.stdout)
    manifest = json.loads(Path(a["TARGET_MANIFEST"]).read_text())
    assert manifest["hardening"] == "fidelity"
    assert manifest["abi"] == "6.8.0-31"
    assert manifest["kernel_deb_version"] == "6.8.0-31.31"
    assert manifest["modules_extra"] is True
    # no relaxation warning when nothing was relaxed
    assert "HARDENING RELAXED" not in r.stderr


def test_relax_hardening_is_recorded_in_four_places(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "ga", "--relax-hardening")
    assert r.returncode == 0, r.stderr
    a = _assignments(r.stdout)
    # 1. a distinct cache dir, so a relaxed image is never served to a
    #    fidelity request
    assert a["ROOTFS"].endswith("6.8.0-31-generic-relaxed/rootfs.img")
    # 2. the manifest
    assert json.loads(Path(a["TARGET_MANIFEST"]).read_text())["hardening"] == "relaxed"
    # 3. a loud stderr banner
    assert "HARDENING RELAXED" in r.stderr
    # 4. the guest hostname and console banner, baked at build time
    build = next(c for c in mktarget_env.docker_calls() if c[0] == "build")
    assert any(a_ == "HOSTNAME_GUEST=qmu-ubuntu-relaxed" for a_ in build)
    stamp = next(a_ for a_ in build if a_.startswith("GUEST_STAMP="))
    assert '"hardening": "relaxed"' in stamp


def test_relaxed_and_fidelity_variants_do_not_share_a_cache_dir(mktarget_env):
    fid = _assignments(mktarget_env.run("--kernel-abi", "ga").stdout)
    rel = _assignments(mktarget_env.run("--kernel-abi", "ga", "--relax-hardening").stdout)
    assert fid["ROOTFS"] != rel["ROOTFS"]


def test_cache_hit_is_byte_identical_and_runs_no_docker(mktarget_env):
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    mktarget_env.clear_docker_log()

    second = mktarget_env.run("--kernel-abi", "ga", fail_if_docker_runs=True)
    assert second.returncode == 0, second.stderr
    assert second.stdout == first.stdout
    assert not mktarget_env.docker_calls()


def test_cache_is_incomplete_without_every_emitted_product(mktarget_env):
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    a = _assignments(first.stdout)
    # a boot image alone must never count as a complete target
    Path(a["SYSTEM_MAP"]).unlink()
    mktarget_env.clear_docker_log()

    second = mktarget_env.run("--kernel-abi", "ga")
    assert second.returncode == 0, second.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_symbols_are_added_without_rebuilding_the_measured_rootfs(mktarget_env):
    """A target built without symbols must not satisfy a later --symbols run --
    but satisfying it must not rebuild the image either. Only the kernel debs
    are version-pinned, so re-running apt can change apparmor or procps out from
    under a result already measured on that rootfs."""
    plain = mktarget_env.run("--kernel-abi", "ga")
    assert plain.returncode == 0, plain.stderr
    assert "VMLINUX=" not in plain.stdout
    rootfs = Path(_assignments(plain.stdout)["ROOTFS"])
    before = (rootfs.read_bytes(), rootfs.stat().st_mtime_ns)
    built_at = json.loads(
        Path(_assignments(plain.stdout)["TARGET_MANIFEST"]).read_text()
    )["built_at"]
    mktarget_env.clear_docker_log()

    withsym = mktarget_env.run("--kernel-abi", "ga", "--symbols")
    assert withsym.returncode == 0, withsym.stderr
    assert "VMLINUX=" in withsym.stdout

    verbs = [c[0] for c in mktarget_env.docker_calls()]
    assert "build" not in verbs, "the image was rebuilt to add symbols"
    assert "export" not in verbs, "the rootfs was regenerated to add symbols"
    assert any(
        c[0] == "run" and "dbgsym" in c[-1] for c in mktarget_env.docker_calls()
    ), "symbols were never fetched"

    assert (rootfs.read_bytes(), rootfs.stat().st_mtime_ns) == before
    manifest = json.loads(Path(_assignments(withsym.stdout)["TARGET_MANIFEST"]).read_text())
    # the manifest now records symbols, but still dates the image it describes
    assert manifest["dbgsym_version"] == "6.8.0-31.31"
    assert manifest["built_at"] == built_at

    # and the upgraded target is a plain cache hit from here on
    mktarget_env.clear_docker_log()
    again = mktarget_env.run("--kernel-abi", "ga", "--symbols", fail_if_docker_runs=True)
    assert again.returncode == 0, again.stderr
    assert again.stdout == withsym.stdout


def test_a_failed_symbols_upgrade_leaves_the_cached_target_usable(mktarget_env):
    """The image was never touched, so a failed symbol fetch must not condemn a
    good target to a full rebuild."""
    plain = mktarget_env.run("--kernel-abi", "ga")
    assert plain.returncode == 0, plain.stderr

    broken = mktarget_env.run(
        "--kernel-abi", "ga", "--symbols", MKTARGET_FAKE_DBGSYM_FAIL="1"
    )
    assert broken.returncode == 2
    mktarget_env.clear_docker_log()

    after = mktarget_env.run("--kernel-abi", "ga", fail_if_docker_runs=True)
    assert after.returncode == 0, after.stderr
    assert after.stdout == plain.stdout


def test_vmlinux_is_not_emitted_without_symbols_even_if_cached(mktarget_env):
    """A vmlinux left by an earlier --symbols run must not be advertised by a
    plain run, or `$VMLINUX` cannot answer "did I get symbols THIS run"."""
    withsym = mktarget_env.run("--kernel-abi", "ga", "--symbols")
    assert withsym.returncode == 0, withsym.stderr
    vmlinux = Path(_assignments(withsym.stdout)["VMLINUX"])
    assert vmlinux.exists()

    # cache hit: the file is still on disk, deliberately, but is not claimed
    plain = mktarget_env.run("--kernel-abi", "ga")
    assert plain.returncode == 0, plain.stderr
    assert vmlinux.exists()
    assert "VMLINUX=" not in plain.stdout

    # A cache hit does not rewrite target.json, and the manifest legitimately
    # describes what is in the directory -- which still includes that vmlinux.
    # A FRESH build without --symbols is where the manifest must not claim it.
    Path(_assignments(plain.stdout)["ROOTFS"]).unlink()
    fresh = mktarget_env.run("--kernel-abi", "ga")
    assert fresh.returncode == 0, fresh.stderr
    assert "VMLINUX=" not in fresh.stdout
    manifest = json.loads(Path(_assignments(fresh.stdout)["TARGET_MANIFEST"]).read_text())
    assert manifest["dbgsym_version"] is None
    assert manifest["dwarf_comp_dir"] == ""


def test_relax_hardening_covers_userfaultfd(mktarget_env):
    """vm.unprivileged_userfaultfd is gated by the upstream kernel default, not
    an Ubuntu sysctl file, so it is easy to leave out of the relax set -- and
    uffd is what most heap PoCs need for grooming. Leaving it restricted on the
    *debugging* image is a trap."""
    r = mktarget_env.run("--kernel-abi", "ga", "--relax-hardening")
    assert r.returncode == 0, r.stderr
    build = next(c for c in mktarget_env.docker_calls() if c[0] == "build")
    # RELAX is what switches the sysctl-writing layer on
    assert "RELAX=1" in build
    # read the Dockerfile actually handed to docker, not the script's source:
    # a knob present in the file but never reaching the build is still absent
    # from the guest, and grepping mktarget.sh cannot tell the difference
    relax_block = _run_block(mktarget_env.dockerfile(), "99-qmu-relax.conf")
    for knob in (
        "kernel.kptr_restrict = 0",
        "kernel.dmesg_restrict = 0",
        "kernel.unprivileged_bpf_disabled = 0",
        "kernel.apparmor_restrict_unprivileged_userns = 0",
        "vm.unprivileged_userfaultfd = 1",
    ):
        assert knob in relax_block, knob


def test_generated_toml_carries_fidelity_profiles(mktarget_env):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    toml = Path(_assignments(r.stdout)["QMU_TOML"]).read_text()
    assert "[profiles.ubuntu-target]" in toml
    assert "[profiles.ubuntu-debug]" in toml
    assert "[profiles.ubuntu-trigger]" in toml
    # the point of the feature: the LSM stack must not be disabled
    target_line = next(
        l for l in toml.splitlines()
        if l.startswith("cmdline") and "nokaslr" not in l and "panic_on" not in l
    )
    assert "apparmor=0" not in target_line
    assert "selinux=0" not in target_line
    assert "nokaslr" not in target_line
    # kasan.fault is inert on a distro kernel and must not be implied
    assert "kasan.fault" not in toml


def test_arm64_toml_uses_virt_machine_and_vda(mktarget_env):
    r = mktarget_env.run("--arch", "arm64", "--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    toml = Path(_assignments(r.stdout)["QMU_TOML"]).read_text()
    assert 'arch = "aarch64"' in toml
    assert '"-M", "virt"' in toml
    assert "root=/dev/vda" in toml
    assert "console=ttyAMA0" in toml


# --- cache identity ----------------------------------------------------------


@pytest.mark.parametrize(
    "flag",
    [
        ("--headers",),
        ("--packages", "strace"),
        ("--size", "8G"),
        ("--unpriv-user", "researcher"),
        ("--no-modules-extra",),
        ("--initramfs",),
    ],
)
def test_build_affecting_options_are_not_served_from_a_default_cache(mktarget_env, flag):
    """The cache directory used to be keyed by ABI and flavour alone, so these
    all returned the default image while stdout advertised the option: headers
    absent, user still `ubuntu`, package missing, filesystem still 4 GiB."""
    base = mktarget_env.run("--kernel-abi", "ga")
    assert base.returncode == 0, base.stderr
    mktarget_env.clear_docker_log()

    variant = mktarget_env.run("--kernel-abi", "ga", *flag)
    assert variant.returncode == 0, variant.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls()), (
        f"{flag} was served from the default cache"
    )
    # and it lands somewhere else, so the two do not evict each other
    assert _assignments(variant.stdout)["ROOTFS"] != _assignments(base.stdout)["ROOTFS"]

    # the variant is itself cacheable -- the key must be stable across runs
    mktarget_env.clear_docker_log()
    again = mktarget_env.run("--kernel-abi", "ga", *flag, fail_if_docker_runs=True)
    assert again.returncode == 0, again.stderr
    assert again.stdout == variant.stdout


def test_package_order_does_not_change_cache_identity(mktarget_env):
    first = mktarget_env.run("--packages", "strace,ltrace")
    assert first.returncode == 0, first.stderr
    mktarget_env.clear_docker_log()
    second = mktarget_env.run("--packages", "ltrace,strace", fail_if_docker_runs=True)
    assert second.returncode == 0, second.stderr
    assert second.stdout == first.stdout


def test_same_abi_at_a_newer_deb_version_rebuilds(mktarget_env):
    """`6.17.0-42` ships as both `.42` and `.42+1`. The ABI names the cache
    directory, so a bumped deb version used to return the OLD kernel while
    KERNEL_DEB_VERSION on stdout claimed the new one."""
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    assert _assignments(first.stdout)["KERNEL_DEB_VERSION"] == "6.8.0-31.31"
    mktarget_env.clear_docker_log()

    mktarget_env.set_release_pocket([("6.8.0-31", "6.8.0-31.32")])
    second = mktarget_env.run("--kernel-abi", "ga")
    assert second.returncode == 0, second.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())
    a = _assignments(second.stdout)
    assert a["KERNEL_DEB_VERSION"] == "6.8.0-31.32"
    # the emitted version and the version actually installed must agree
    build = next(c for c in mktarget_env.docker_calls() if c[0] == "build")
    kpkgs = next(x.split("=", 1)[1] for x in build if x.startswith("KPKGS="))
    assert "6.8.0-31.32" in kpkgs
    assert json.loads(Path(a["TARGET_MANIFEST"]).read_text())[
        "kernel_deb_version"
    ] == "6.8.0-31.32"


def test_interrupted_build_is_not_a_cache_hit(mktarget_env):
    """An aborted rebuild leaves a truncated rootfs among stale siblings. Every
    file exists, so the old `-f` test called it complete and the target booted
    into an unexplained panic."""
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    rootfs = Path(_assignments(first.stdout)["ROOTFS"])
    rootfs.write_bytes(b"\0" * 512)          # truncated, still present
    mktarget_env.clear_docker_log()

    second = mktarget_env.run("--kernel-abi", "ga")
    assert second.returncode == 0, second.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_a_directory_without_a_completion_stamp_is_never_cached(mktarget_env):
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    outdir = Path(_assignments(first.stdout)["ROOTFS"]).parent
    stamp = outdir / ".mktarget-stamp"
    assert stamp.exists(), "a completed build must leave a stamp"
    stamp.unlink()
    mktarget_env.clear_docker_log()

    second = mktarget_env.run("--kernel-abi", "ga")
    assert second.returncode == 0, second.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_stamp_is_removed_before_a_rebuild_starts(mktarget_env):
    """Proves the ordering the atomicity argument rests on: if the stamp
    outlived the start of a rebuild, a kill mid-build would leave one."""
    first = mktarget_env.run("--kernel-abi", "ga")
    assert first.returncode == 0, first.stderr
    outdir = Path(_assignments(first.stdout)["ROOTFS"]).parent
    stamp = outdir / ".mktarget-stamp"

    probe = mktarget_env.tmp_path / "stamp-at-build-time"
    docker = Path(mktarget_env.env["PATH"].split(":")[0]) / "docker"
    original = docker.read_text()
    docker.write_text(
        original.replace(
            'verb = args[0] if args else ""',
            'verb = args[0] if args else ""\n'
            f'if verb == "build":\n'
            f'    Path({str(probe)!r}).write_text(str(Path({str(stamp)!r}).exists()))\n',
        )
    )
    r = mktarget_env.run("--kernel-abi", "ga", "--no-cache")
    assert r.returncode == 0, r.stderr
    assert probe.read_text() == "False"
    assert stamp.exists(), "and it must be back once the build completes"


# --- archive faults vs genuinely absent pockets -------------------------------


def test_a_faulting_pocket_fails_instead_of_silently_narrowing_latest(mktarget_env):
    """If -updates merely times out it must not look like a -updates with no
    kernels in it: that turned `--kernel-abi latest` into `ga` and destroyed the
    pin the whole tool exists to provide."""
    r = mktarget_env.run(
        "--kernel-abi", "latest", MKTARGET_FAKE_CURL_FAULT="dists/noble-"
    )
    assert r.returncode == 2
    assert "fetch fault" in r.stderr
    assert "6.8.0-31" not in r.stdout      # must not fall back to the GA kernel
    assert r.stdout == ""
    assert not any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_a_404_pocket_is_treated_as_empty_and_still_resolves(mktarget_env):
    """The other half of the distinction: a pocket that genuinely has no index
    is normal (ddebs has no -security) and must not stop a build."""
    r = mktarget_env.run(
        "--kernel-abi", "latest", MKTARGET_FAKE_CURL_404="dists/noble-security/"
    )
    assert r.returncode == 0, r.stderr
    assert _assignments(r.stdout)["KERNEL_ABI"] == "6.8.0-137"
    assert "404" in r.stderr


# --- guest hardening ----------------------------------------------------------


def test_root_ssh_is_key_only(mktarget_env):
    """The image used to delete root's password and enable empty-password
    logins, so any local process could enter the guest as root with no
    credential and perturb the measurement."""
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    # "authorized_keys" alone also matches the unprivileged-user layer
    block = _run_block(mktarget_env.dockerfile(), "sshd_config.d/60-qmu.conf")

    assert "passwd -d root" not in block
    assert "PermitEmptyPasswords yes" not in block
    assert "PermitRootLogin yes" not in block

    assert "PermitRootLogin prohibit-password" in block
    assert "PasswordAuthentication no" in block
    assert "KbdInteractiveAuthentication no" in block
    assert "PermitEmptyPasswords no" in block
    # and the drop-in has to be reachable, or none of the above applies
    assert "sshd_config.d/60-qmu.conf" in block
    assert "Include /etc/ssh/sshd_config.d/" in block


def test_unpriv_user_defaults_to_the_existing_uid_1000_account(mktarget_env, tmp_path):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    proc, calls = _exec_user_setup(
        mktarget_env, tmp_path, "ubuntu",
        [f"ubuntu:x:1000:1000::{tmp_path}/home/ubuntu:/bin/bash"],
    )
    assert proc.returncode == 0, proc.stderr
    assert not any(c.startswith(("useradd", "usermod -l")) for c in calls), calls


def test_unpriv_user_renames_the_uid_1000_account(mktarget_env, tmp_path):
    """`useradd -m -s /bin/bash -u 1000 researcher` against an image that
    already has `ubuntu` at 1000 fails with "UID 1000 is not unique" and takes
    the whole build with it."""
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    proc, calls = _exec_user_setup(
        mktarget_env, tmp_path, "researcher",
        [f"ubuntu:x:1000:1000::{tmp_path}/home/ubuntu:/bin/bash"],
    )
    assert proc.returncode == 0, proc.stderr
    assert not any("useradd" in c for c in calls), calls
    rename = next(c for c in calls if c.startswith("usermod -l"))
    assert "researcher" in rename and rename.endswith("ubuntu")
    assert any(c.startswith("groupmod -n researcher") for c in calls), calls


def test_unpriv_user_creates_the_account_when_uid_1000_is_free(mktarget_env, tmp_path):
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    proc, calls = _exec_user_setup(
        mktarget_env, tmp_path, "researcher", ["root:x:0:0::/root:/bin/bash"],
    )
    assert proc.returncode == 0, proc.stderr
    assert any(c == "useradd -m -s /bin/bash -u 1000 researcher" for c in calls), calls


@pytest.mark.parametrize("name", ["root", "daemon", "nobody"])
def test_an_existing_account_that_is_not_uid_1000_is_refused(mktarget_env, tmp_path, name):
    """Accepting an existing account at any other uid would label it "the
    unprivileged user" while the skill promises uid 1000. `nobody` is the case
    that matters: noble ships it at 65534 with /usr/sbin/nologin, so a uid<1000
    guard waves it through and the PoC user cannot even get a shell."""
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    proc, calls = _exec_user_setup(
        mktarget_env, tmp_path, name,
        [
            "root:x:0:0::/root:/bin/bash",
            "daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
            "ubuntu:x:1000:1000::/home/ubuntu:/bin/bash",
            "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
        ],
    )
    assert proc.returncode == 1, proc.stdout
    assert "unpriv-user" in proc.stderr
    assert not any("useradd" in c or "usermod" in c for c in calls), calls


# --- symbols ------------------------------------------------------------------


def test_symbols_full_is_not_satisfied_by_a_vmlinux_only_cache(mktarget_env):
    """`--symbols` fetches vmlinux; `--symbols=full` also needs the module debug
    tree. Completeness checked only vmlinux, so the second returned exit 0 with
    no module symbols at all -- found only when GDB failed to resolve one."""
    vm = mktarget_env.run("--kernel-abi", "ga", "--symbols")
    assert vm.returncode == 0, vm.stderr
    outdir = Path(_assignments(vm.stdout)["ROOTFS"]).parent
    assert not (outdir / "usr/lib/debug/lib/modules").exists()
    mktarget_env.clear_docker_log()

    full = mktarget_env.run("--kernel-abi", "ga", "--symbols=full")
    assert full.returncode == 0, full.stderr
    assert any(
        c[0] == "run" and "KEEP_MODULES=1" in c for c in mktarget_env.docker_calls()
    ), "the full-symbol helper never ran"
    mods = outdir / "usr/lib/debug/lib/modules" / _assignments(full.stdout)["KERNEL_RELEASE"]
    assert list(mods.rglob("*.ko")), "module debug objects were not extracted"


def test_an_emptied_module_debug_tree_is_not_a_cache_hit(mktarget_env):
    """Completeness checked only that the directory existed, so deleting every
    .ko while leaving the tree in place made the next --symbols=full request a
    hit with no module symbols in it."""
    full = mktarget_env.run("--kernel-abi", "ga", "--symbols=full")
    assert full.returncode == 0, full.stderr
    outdir = Path(_assignments(full.stdout)["ROOTFS"]).parent
    mods = outdir / "usr/lib/debug/lib/modules" / _assignments(full.stdout)["KERNEL_RELEASE"]
    for ko in mods.rglob("*.ko"):
        ko.unlink()
    assert mods.is_dir()
    mktarget_env.clear_docker_log()

    again = mktarget_env.run("--kernel-abi", "ga", "--symbols=full")
    assert again.returncode == 0, again.stderr
    assert any(
        c[0] == "run" and "KEEP_MODULES=1" in c for c in mktarget_env.docker_calls()
    ), "the emptied tree was accepted as cached"
    assert list(mods.rglob("*.ko"))


def test_a_failed_symbol_extraction_leaves_no_target(mktarget_env):
    """--symbols promises an artifact, so a failure has to be fatal rather than
    a warning: a target quietly built without it lets a GDB session start
    against symbols the caller believes they asked for."""
    r = mktarget_env.run("--kernel-abi", "ga", "--symbols", MKTARGET_FAKE_DBGSYM_FAIL="1")
    assert r.returncode == 2
    assert r.stdout == ""
    assert "debug-symbol extraction failed" in r.stderr
    # and the half-built directory must not be usable next time
    mktarget_env.clear_docker_log()
    after = mktarget_env.run("--kernel-abi", "ga")
    assert after.returncode == 0, after.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())


def test_symbols_full_module_extraction_is_not_swallowed(mktarget_env):
    """The module half of --symbols=full used to end in `|| true`, so a failed
    download produced a target claiming full symbols with none in it. The
    container script has to treat that as fatal.

    This reads the helper text because the fake docker does not execute the
    inner shell; the surrounding contract is covered behaviourally above.
    """
    r = mktarget_env.run("--kernel-abi", "ga", "--symbols=full")
    assert r.returncode == 0, r.stderr
    helper = next(
        c[-1] for c in mktarget_env.docker_calls()
        if c[0] == "run" and "dbgsym" in c[-1]
    )
    keep = helper.split('if [ "$KEEP_MODULES" = "1" ]')[1]
    # comments stripped: the block explains the `|| true` it no longer has
    keep = "\n".join(l for l in keep.splitlines() if not l.lstrip().startswith("#"))
    assert "|| true" not in keep
    assert "exit 1" in keep


def test_initrd_is_not_emitted_without_initramfs_even_if_cached(mktarget_env):
    """Same contract as VMLINUX: gated on the flag, not on the file, so
    `[ -n "$INITRD" ]` answers "did I ask for one THIS run"."""
    withinit = mktarget_env.run("--kernel-abi", "ga", "--initramfs")
    assert withinit.returncode == 0, withinit.stderr
    initrd = Path(_assignments(withinit.stdout)["INITRD"])
    assert initrd.exists()

    plain = mktarget_env.run("--kernel-abi", "ga")
    assert plain.returncode == 0, plain.stderr
    assert "INITRD=" not in plain.stdout


# --- attribution --------------------------------------------------------------


def test_userland_package_versions_are_recorded(mktarget_env):
    """The kernel version alone cannot attribute a hardening result: whether an
    unprivileged-userns PoC is blocked is decided by the apparmor package, which
    ships the only file that sets that sysctl."""
    r = mktarget_env.run("--kernel-abi", "ga")
    assert r.returncode == 0, r.stderr
    a = _assignments(r.stdout)
    manifest = json.loads(Path(a["TARGET_MANIFEST"]).read_text())

    assert manifest["userland"]["apparmor"].startswith("4.0.1really")
    assert manifest["userland"]["procps"] == "2:4.0.4-4ubuntu3.2"
    assert manifest["userland"]["systemd"] == "255.4-1ubuntu8.6"

    packages = Path(manifest["packages_manifest"])
    rows = dict(l.split("\t") for l in packages.read_text().splitlines())
    assert rows["procps"] == "2:4.0.4-4ubuntu3.2"
    # a package whose files were removed is not installed and must not be listed
    assert "removed-but-configured" not in rows
