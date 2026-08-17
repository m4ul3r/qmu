from __future__ import annotations

import gzip
import json
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
import sys
from pathlib import Path

FIX = Path({str(fixtures)!r})
url = [a for a in sys.argv[1:] if a.startswith("http")]
if not url:
    raise SystemExit(2)
url = url[-1]

if url.endswith("/Release"):
    sys.stdout.write("Origin: Ubuntu\\nDate: Thu, 25 Apr 2024 15:10:33 UTC\\n")
    raise SystemExit(0)

if "ddebs" in url:
    # only the release pocket carries dbgsym in this fixture
    body = FIX / ("ddebs.gz" if "/dists/noble/" in url else "empty.gz")
elif "/dists/noble/" in url:
    body = FIX / "release.gz"
elif "-updates/" in url or "-security/" in url:
    body = FIX / "updates.gz"
else:
    raise SystemExit(22)

sys.stdout.buffer.write(body.read_bytes())
'''
    )
    curl.chmod(0o755)

    docker = fake_bin / "docker"
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
with LOG.open("a") as fh:
    fh.write(json.dumps(args) + "\\n")

if os.environ.get("MKTARGET_FAIL_IF_DOCKER_RUNS") == "1":
    print("docker was forbidden for this cache hit", file=sys.stderr)
    raise SystemExit(97)

verb = args[0] if args else ""

if verb == "build":
    # consume the Dockerfile on stdin so the writer never sees EPIPE
    sys.stdin.read()
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
        for a in args:
            if a.startswith("KREL="):
                (out / ("vmlinux-" + a.split("=", 1)[1])).write_text("ELF\\n")
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

        def run(self, *extra, fail_if_docker_runs=False):
            e = dict(env)
            if fail_if_docker_runs:
                e["MKTARGET_FAIL_IF_DOCKER_RUNS"] = "1"
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

        def clear_docker_log(self):
            docker_log.unlink(missing_ok=True)

    return Env()


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


def test_symbols_request_makes_vmlinux_part_of_the_cache_contract(mktarget_env):
    """A target built without symbols must not satisfy a later --symbols run."""
    plain = mktarget_env.run("--kernel-abi", "ga")
    assert plain.returncode == 0, plain.stderr
    assert "VMLINUX=" not in plain.stdout
    mktarget_env.clear_docker_log()

    withsym = mktarget_env.run("--kernel-abi", "ga", "--symbols")
    assert withsym.returncode == 0, withsym.stderr
    assert any(c[0] == "build" for c in mktarget_env.docker_calls())
    assert "VMLINUX=" in withsym.stdout


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
