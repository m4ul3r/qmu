from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KBUILD = ROOT / "tools/kbuild.sh"


def _parse_assignments(stdout: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


class KbuildEnv:
    def __init__(self, cache: Path, env: dict[str, str], docker_log: Path):
        self.cache = cache
        self.env = env
        self.docker_log = docker_log
        self.source_makefile = cache / "kernels/src/linux-7.0/Makefile"

    def run(
        self,
        *extra: str,
        fail_if_docker_runs: bool = False,
        omit_artifact: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        if fail_if_docker_runs:
            env["KBUILD_FAIL_IF_DOCKER_RUNS"] = "1"
        if omit_artifact is not None:
            env["KBUILD_OMIT_ARTIFACT"] = omit_artifact
        return subprocess.run(
            [str(KBUILD), "--version", "7.0", "--arch", "x86_64", *extra],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def docker_runs(self) -> list[list[str]]:
        if not self.docker_log.exists():
            return []
        return [
            json.loads(line)
            for line in self.docker_log.read_text().splitlines()
            if line
        ]

    def last_docker_run(self) -> list[str]:
        return self.docker_runs()[-1]

    def clear_docker_log(self) -> None:
        self.docker_log.unlink(missing_ok=True)


@pytest.fixture
def kbuild_env(tmp_path):
    cache = tmp_path / "cache"
    source = cache / "kernels/src/linux-7.0"
    source.mkdir(parents=True)
    (source / "scripts/gdb/linux").mkdir(parents=True)
    (source / "scripts/gdb/linux/constants.py.in").write_text("LX_CONFIG_HZ = 250\n")
    (source / "Makefile").write_text("VERSION = 7\nPATCHLEVEL = 0\n")
    (cache / "kernels/src/linux-7.0.tar.xz").write_bytes(b"")

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    docker_log = tmp_path / "docker-runs.jsonl"

    docker = fake_bin / "docker"
    docker.write_text(
        """#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    raise SystemExit(0)
if not args or args[0] != "run":
    print(f"unexpected fake docker invocation: {args!r}", file=sys.stderr)
    raise SystemExit(96)

log = Path(os.environ["KBUILD_DOCKER_LOG"])
with log.open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
if os.environ.get("KBUILD_FAIL_IF_DOCKER_RUNS") == "1":
    print("docker run was forbidden for this cache hit", file=sys.stderr)
    raise SystemExit(97)

mounts = {}
for index, arg in enumerate(args):
    if arg != "-v":
        continue
    host, container, mode = args[index + 1].rsplit(":", 2)
    mounts[container] = Path(host)
if "/src" not in mounts:
    # a qmu-kmake module build: logged above, nothing to produce
    raise SystemExit(0)
source = mounts["/src"]
output = mounts["/output"]
output.mkdir(parents=True, exist_ok=True)

# Helper regressions execute the entire container command, not just its artifact
# handoff. Only the fixed output mount is redirected; make runs real miniature
# targets in the private source tree.
if os.environ.get("KBUILD_EXECUTE_INNER") == "1":
    inner = args[-1].replace("/output", '"$KBUILD_TEST_OUTPUT"')
    env = dict(os.environ, KBUILD_TEST_OUTPUT=str(output))
    command = args[args.index("bash"):-1] + [inner]
    result = subprocess.run(command, cwd=source, env=env, check=False)
    raise SystemExit(result.returncode)

(output / ".config").write_text("CONFIG_DEBUG_INFO=y\\nCONFIG_GDB_SCRIPTS=y\\n")

inner = args[-1]
if "CONFIG_ONLY='true'" in inner:
    # the container configures the shared tree, then copies its .config out
    (source / ".config").write_text("CONFIG_DEBUG_INFO=y\\nCONFIG_GDB_SCRIPTS=y\\n")
    raise SystemExit(0)

omit = os.environ.get("KBUILD_OMIT_ARTIFACT")
def write_artifact(relative, content):
    path = output / relative
    if relative == omit:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

write_artifact("bzImage", "kernel image\\n")
write_artifact("vmlinux", "ELF symbols\\n")
write_artifact("System.map", "ffffffff81000000 T _text\\n")
write_artifact("build/Makefile", "VERSION = 7\\nPATCHLEVEL = 0\\n")
write_artifact("build/.config", "CONFIG_DEBUG_INFO=y\\n")
write_artifact("build/Module.symvers", "0x00000000\\t_printk\\tvmlinux\\tEXPORT_SYMBOL\\t\\n")

# The real build leaves intermediates in the bind-mounted source tree, plus the
# artifacts kbuild copies out. clean_build_residue runs host-side, after this.
(source / "kernel").mkdir(parents=True, exist_ok=True)
(source / "arch/x86/boot").mkdir(parents=True, exist_ok=True)
(source / "kernel/fork.o").write_text("obj\\n")
(source / "kernel/.fork.o.cmd").write_text("savedcmd := gcc\\n")
(source / "built-in.a").write_text("ar\\n")
(source / "kernel/mod.ko").write_text("ko\\n")
(source / "vmlinux").write_text("ELF symbols\\n")
(source / "System.map").write_text("ffffffff81000000 T _text\\n")
(source / "vmlinux.unstripped").write_text("ELF unstripped\\n")
(source / ".config").write_text("CONFIG_DEBUG_INFO=y\\nCONFIG_GDB_SCRIPTS=y\\n")
(source / "arch/x86/boot/bzImage").write_text("kernel image\\n")
write_artifact("scripts/gdb/vmlinux-gdb.py", "# generated loader\\n")
write_artifact("scripts/gdb/linux/constants.py", "LX_CONFIG_HZ = 250\\n")
loader = output / "vmlinux-gdb.py"
if "vmlinux-gdb.py" == omit:
    loader.unlink(missing_ok=True)
else:
    loader.unlink(missing_ok=True)
    loader.symlink_to("scripts/gdb/vmlinux-gdb.py")
"""
    )
    docker.chmod(0o755)

    fake_tar = fake_bin / "tar"
    fake_tar.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path
source = Path(os.environ["QMU_CACHE_DIR"]) / "kernels/src/linux-7.0"
source.mkdir(parents=True, exist_ok=True)
(source / "Makefile").write_text("VERSION = 7\\nPATCHLEVEL = 0\\n")
"""
    )
    fake_tar.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "QMU_CACHE_DIR": str(cache),
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "KBUILD_DOCKER_LOG": str(docker_log),
        }
    )
    return KbuildEnv(cache, env, docker_log)


def _use_real_helper_targets(kbuild_env, mode):
    """Run the real container shell against tiny, offline kernel make targets."""
    source = kbuild_env.source_makefile.parent
    helpers = source / "scripts/gdb"
    constants_input = helpers / "linux/constants.py.in"
    if mode == "early":
        constants_input.unlink()
    else:
        constants_input.write_text("LX_CONFIG_HZ = @HZ@\n")
    (helpers / "qmu_helper.py").write_text("VALUE = 'exported upstream layout'\n")
    (helpers / "vmlinux-gdb.py").write_text(
        "import os, sys\n"
        "sys.path.insert(0, os.path.dirname(__file__) + '/scripts/gdb')\n"
        "import qmu_helper\n"
        "print(qmu_helper.VALUE)\n"
    )
    config = source / "scripts/config"
    config.write_text("#!/bin/sh\nexit 0\n")
    config.chmod(0o755)
    helper_target = "scripts_gdb" if mode == "modern" else "prepare"
    makefile = """
.PHONY: mrproper defconfig kvm_guest.config olddefconfig bzImage modules_prepare prepare scripts_gdb
mrproper:
\trm -f .config vmlinux System.map vmlinux-gdb.py scripts/gdb/linux/constants.py Module.symvers vmlinux.symvers
defconfig:
\tprintf 'CONFIG_DEBUG_INFO=y\\nCONFIG_GDB_SCRIPTS=y\\n' > .config
kvm_guest.config olddefconfig:
\t@:
modules_prepare:
\tmkdir -p include/generated arch/x86/include/generated
\tprintf '#define CONFIG_X86_64 1\\n' > include/generated/autoconf.h
\tprintf '/* asm-offsets */\\n' > arch/x86/include/generated/asm-offsets.h
modules:
\ttest -n "$(M)" && test -f include/generated/autoconf.h
\tif test "$$KBUILD_TEST_KDIR_BROKEN" != 1; then touch $(M)/kdircheck.ko; fi
bzImage:
\tmkdir -p arch/x86/boot
\tprintf 'kernel image\\n' > arch/x86/boot/bzImage
\tprintf 'ELF symbols\\n' > vmlinux
\tprintf 'ffffffff81000000 T _text\\n' > System.map
\tprintf '0x00000000\\t_printk\\tvmlinux\\tEXPORT_SYMBOL\\t\\n' > vmlinux.symvers
\tln -fsn "$(CURDIR)/scripts/gdb/vmlinux-gdb.py" vmlinux-gdb.py
"""
    # In legacy trees there must be no scripts_gdb rule, including a phony
    # declaration: GNU make otherwise accepts the nonexistent target.
    if mode != "modern":
        makefile = makefile.replace("prepare scripts_gdb\n", "prepare\n")
    else:
        makefile += "prepare:\n\t@touch unexpected-fallback\n"
    makefile += f"""
{helper_target}:
\t@touch helper-called
\t@if test "$$KBUILD_TEST_FAIL_HELPER" = 1; then echo helper-generation-failed >&2; exit 23; fi
"""
    if mode != "early":
        makefile += (
            "\t@if test \"$$KBUILD_TEST_SKIP_CONSTANTS\" != 1; then "
            "sed 's/@HZ@/250/' scripts/gdb/linux/constants.py.in "
            "> scripts/gdb/linux/constants.py; fi\n"
        )
    kbuild_env.source_makefile.write_text(makefile)
    kbuild_env.env["KBUILD_EXECUTE_INNER"] = "1"
    return source


@pytest.mark.parametrize("mode", ["modern", "legacy", "early"])
def test_container_build_exports_helpers_for_upstream_capabilities(kbuild_env, mode):
    source = _use_real_helper_targets(kbuild_env, mode)
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    values = _parse_assignments(result.stdout)
    assert list(values) == ["KERNEL", "VMLINUX", "CONFIG", "KERNEL_SRC", "VMLINUX_GDB", "KDIR"]
    # The module build dir is this build's prepared tree, exported from the
    # container: vmlinux.symvers becomes the Module.symvers modpost reads.
    kdir = Path(values["KDIR"])
    assert (kdir / "Module.symvers").read_text().startswith("0x00000000\t_printk\tvmlinux")
    assert (kdir / "include/generated/autoconf.h").is_file()
    assert (kdir / "arch/x86/include/generated/asm-offsets.h").is_file()
    assert (kdir / "Makefile").is_file() and (kdir / ".config").is_file()
    assert (source / "helper-called").is_file()
    loader = Path(values["VMLINUX_GDB"])
    # The copied loader must resolve its module relative to the exported build
    # root, not depend on Docker's /src mount or a flattened helper directory.
    imported = subprocess.run(
        ["python3", str(loader)], cwd=loader.parent, text=True,
        capture_output=True, check=False, timeout=5,
    )
    assert imported.returncode == 0, imported.stderr
    assert imported.stdout == "exported upstream layout\n"
    constants = loader.parent / "scripts/gdb/linux/constants.py"
    if mode == "early":
        assert not constants.exists()
    else:
        assert constants.read_text() == "LX_CONFIG_HZ = 250\n"

    kbuild_env.clear_docker_log()
    cached = kbuild_env.run(fail_if_docker_runs=True)
    assert cached.returncode == 0, cached.stderr
    assert cached.stdout == result.stdout
    assert kbuild_env.docker_runs() == []
    if mode != "early":
        constants.unlink()
        repaired = kbuild_env.run()
        assert repaired.returncode == 0, repaired.stderr
        assert constants.read_text() == "LX_CONFIG_HZ = 250\n"


@pytest.mark.parametrize("mode", ["modern", "legacy"])
def test_helper_target_failure_is_fatal_without_fallback(kbuild_env, mode):
    source = _use_real_helper_targets(kbuild_env, mode)
    kbuild_env.env["KBUILD_TEST_FAIL_HELPER"] = "1"
    result = kbuild_env.run()
    assert result.returncode != 0
    assert result.stdout == ""
    assert "helper-generation-failed" in result.stderr
    assert (source / "helper-called").is_file()
    assert not (source / "unexpected-fallback").exists()
    assert (source / "arch/x86/boot/bzImage").is_file()


def test_module_dir_that_cannot_build_a_module_fails_the_build(kbuild_env):
    """A KDIR missing a header a module needs (4.x arm64 lacked arm's
    asm/opcodes.h) was served as a complete cache; the build now proves it."""
    _use_real_helper_targets(kbuild_env, "modern")
    kbuild_env.env["KBUILD_TEST_KDIR_BROKEN"] = "1"
    result = kbuild_env.run()
    assert result.returncode != 0
    assert result.stdout == ""
    kbuild_env.env.pop("KBUILD_TEST_KDIR_BROKEN")
    assert kbuild_env.run(fail_if_docker_runs=True).returncode != 0, "broken KDIR was cached"


@pytest.mark.parametrize("mode", ["modern", "legacy"])
def test_successful_helper_target_without_required_constants_is_rejected(
    kbuild_env, mode
):
    _use_real_helper_targets(kbuild_env, mode)
    kbuild_env.env["KBUILD_TEST_SKIP_CONSTANTS"] = "1"
    result = kbuild_env.run()
    assert result.returncode != 0
    assert result.stdout == ""
    assert "constants.py" in result.stderr


def test_container_config_only_does_not_build_image_or_helpers(kbuild_env):
    source = _use_real_helper_targets(kbuild_env, "modern")
    kbuild_env.env["KBUILD_TEST_FAIL_HELPER"] = "1"
    result = kbuild_env.run("--config-only")
    assert result.returncode == 0, result.stderr
    values = _parse_assignments(result.stdout)
    assert list(values) == ["CONFIG", "KERNEL_SRC"]
    # KERNEL_SRC is the tree configured with CONFIG, ready for `make -C`.
    assert Path(values["KERNEL_SRC"], ".config").read_text() == Path(values["CONFIG"]).read_text()
    assert "CONFIG_GDB_SCRIPTS=y" in Path(values["CONFIG"]).read_text()
    assert not (source / "helper-called").exists()
    assert not (source / "arch/x86/boot/bzImage").exists()


def test_fresh_build_generates_gdb_helpers_and_exports_debug_paths(kbuild_env):
    result = kbuild_env.run()
    values = _parse_assignments(result.stdout)
    assert result.returncode == 0, result.stderr
    assert list(values) == [
        "KERNEL", "VMLINUX", "CONFIG", "KERNEL_SRC", "VMLINUX_GDB", "KDIR"
    ]
    assert Path(values["KERNEL"]).is_file()
    assert Path(values["VMLINUX"]).is_file()
    assert Path(values["CONFIG"]).is_file()
    assert (Path(values["KERNEL_SRC"]) / "Makefile").is_file()
    loader = Path(values["VMLINUX_GDB"])
    assert loader == Path(values["VMLINUX"]).parent / "vmlinux-gdb.py"
    assert loader.is_file()
    assert (loader.parent / "scripts/gdb/vmlinux-gdb.py").is_file()
    assert (loader.parent / "scripts/gdb/linux/constants.py").is_file()


def test_complete_cache_hit_matches_fresh_output_without_docker(kbuild_env):
    fresh = kbuild_env.run()
    assert fresh.returncode == 0
    kbuild_env.clear_docker_log()
    cached = kbuild_env.run(fail_if_docker_runs=True)
    assert cached.returncode == 0, cached.stderr
    assert cached.stdout == fresh.stdout
    assert kbuild_env.docker_runs() == []


@pytest.mark.parametrize(
    "missing",
    [
        "vmlinux",
        ".config",
        "vmlinux-gdb.py",
        "scripts/gdb/vmlinux-gdb.py",
        "scripts/gdb/linux/constants.py",
        "build/Module.symvers",
        "build/qmu-kmake",
    ],
)
def test_incomplete_debug_cache_is_repaired(kbuild_env, missing):
    first = kbuild_env.run()
    values = _parse_assignments(first.stdout)
    output = Path(values["KERNEL"]).parent
    target = output / missing
    target.unlink()
    kbuild_env.clear_docker_log()

    repaired = kbuild_env.run()

    assert repaired.returncode == 0, repaired.stderr
    assert kbuild_env.docker_runs(), "incomplete cache was incorrectly accepted"
    assert target.is_file()
    assert _parse_assignments(repaired.stdout) == values


def test_cache_without_retained_source_is_repaired(kbuild_env):
    first = kbuild_env.run()
    assert first.returncode == 0, first.stderr
    kbuild_env.source_makefile.unlink()
    kbuild_env.clear_docker_log()

    repaired = kbuild_env.run()

    assert repaired.returncode == 0, repaired.stderr
    assert kbuild_env.docker_runs(), "cache without retained source was accepted"
    assert kbuild_env.source_makefile.is_file()
    assert repaired.stdout == first.stdout


def test_missing_generated_product_rejects_build_without_assignments(
    kbuild_env, tmp_path
):
    output = tmp_path / "missing-generated-product"

    result = kbuild_env.run(
        "--outdir",
        str(output),
        omit_artifact="scripts/gdb/linux/constants.py",
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "constants.py" in result.stderr


def test_config_only_outputs_only_config_and_skips_scripts_gdb(kbuild_env, tmp_path):
    cold = tmp_path / "config-only"
    result = kbuild_env.run("--config-only", "--outdir", str(cold))
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        f"CONFIG={cold}/.config\nKERNEL_SRC={kbuild_env.source_makefile.parent}\n"
    )
    assert (cold / ".config").is_file()
    assert not (cold / "vmlinux-gdb.py").exists()

    warm_build = kbuild_env.run()
    warm_values = _parse_assignments(warm_build.stdout)
    output = Path(warm_values["CONFIG"]).parent
    kbuild_env.clear_docker_log()
    warm_config = kbuild_env.run("--config-only")
    assert warm_config.returncode == 0
    assert warm_config.stdout == (
        f"CONFIG={output}/.config\nKERNEL_SRC={kbuild_env.source_makefile.parent}\n"
    )
    assert kbuild_env.docker_runs() == []


def test_fresh_output_is_shell_evaluable_in_stable_order(kbuild_env):
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    values = _parse_assignments(result.stdout)

    evaluated = subprocess.run(
        [
            "bash",
            "-c",
            'set -eu; eval "$1"; printf "%s\\n" '
            '"$KERNEL" "$VMLINUX" "$CONFIG" "$KERNEL_SRC" "$VMLINUX_GDB" "$KDIR"',
            "bash",
            result.stdout,
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert evaluated.returncode == 0, evaluated.stderr
    assert evaluated.stdout.splitlines() == list(values.values())
    assert list(values) == [
        "KERNEL", "VMLINUX", "CONFIG", "KERNEL_SRC", "VMLINUX_GDB", "KDIR"
    ]


def _with_hostile_cache(kbuild_env, tmp_path):
    cache = tmp_path / "$(touch injected-cache) cache with spaces;dollar$HOME-glob*"
    source = cache / "kernels/src/linux-7.0"
    source.mkdir(parents=True)
    (source / "Makefile").write_text("VERSION = 7\nPATCHLEVEL = 0\n")
    (source / "scripts/gdb/linux").mkdir(parents=True)
    (source / "scripts/gdb/linux/constants.py.in").write_text("LX_CONFIG_HZ = 250\n")
    (cache / "kernels/src/linux-7.0.tar.xz").write_bytes(b"")
    env = kbuild_env.env.copy()
    env["QMU_CACHE_DIR"] = str(cache)
    return KbuildEnv(cache, env, kbuild_env.docker_log)


def _evaluate_build_output(stdout, cwd):
    return subprocess.run(
        [
            "bash",
            "-c",
            'set -u; eval "$1"; printf "%s\\n" '
            '"$KERNEL" "$VMLINUX" "$CONFIG" "$KERNEL_SRC" "$VMLINUX_GDB" "$KDIR"',
            "bash",
            stdout,
        ],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _evaluate_config_output(stdout, cwd):
    return subprocess.run(
        ["bash", "-c", 'set -u; eval "$1"; printf "%s\\n" "$CONFIG"', "bash", stdout],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_fresh_output_shell_quotes_literal_hostile_paths(kbuild_env, tmp_path):
    hostile = _with_hostile_cache(kbuild_env, tmp_path)
    output = tmp_path / "$(touch injected-out) output with spaces;dollar$HOME-glob*"

    result = hostile.run("--outdir", str(output))
    evaluated = _evaluate_build_output(result.stdout, tmp_path)

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "injected-out").exists()
    assert not (tmp_path / "injected-cache").exists()
    assert evaluated.returncode == 0, evaluated.stderr
    assert evaluated.stdout.splitlines() == [
        str(output / "bzImage"),
        str(output / "vmlinux"),
        str(output / ".config"),
        str(hostile.cache / "kernels/src/linux-7.0"),
        str(output / "vmlinux-gdb.py"),
        str(output / "build"),
    ]


def test_cached_output_shell_quotes_literal_hostile_paths(kbuild_env, tmp_path):
    hostile = _with_hostile_cache(kbuild_env, tmp_path)
    output = tmp_path / "$(touch injected-out) output with spaces;dollar$HOME-glob*"
    fresh = hostile.run("--outdir", str(output))
    assert fresh.returncode == 0, fresh.stderr
    hostile.clear_docker_log()

    cached = hostile.run(
        "--outdir", str(output), fail_if_docker_runs=True
    )
    evaluated = _evaluate_build_output(cached.stdout, tmp_path)

    assert cached.returncode == 0, cached.stderr
    assert hostile.docker_runs() == []
    assert cached.stdout == fresh.stdout
    assert not (tmp_path / "injected-out").exists()
    assert not (tmp_path / "injected-cache").exists()
    assert evaluated.returncode == 0, evaluated.stderr
    assert evaluated.stdout.splitlines() == [
        str(output / "bzImage"),
        str(output / "vmlinux"),
        str(output / ".config"),
        str(hostile.cache / "kernels/src/linux-7.0"),
        str(output / "vmlinux-gdb.py"),
        str(output / "build"),
    ]


def test_module_wrapper_builds_in_the_kernel_toolchain_image(kbuild_env, tmp_path):
    """#154: a module built by the host's GCC instead of the kernel's is a
    silent ABI risk; `qmu-kmake` runs make in the image that built it."""
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    kdir = Path(_parse_assignments(result.stdout)["KDIR"])
    module = tmp_path / "oops-mod"
    module.mkdir()
    kbuild_env.clear_docker_log()

    built = subprocess.run(
        [str(kdir / "qmu-kmake"), "modules"], cwd=module, env=kbuild_env.env,
        text=True, capture_output=True, check=False,
    )

    assert built.returncode == 0, built.stderr
    run = kbuild_env.last_docker_run()
    image = run.index("make") - 1
    assert run[image] == "qmu-kbuild:noble-x86_64"
    assert run[image + 1:] == [
        "make", "-C", str(kdir), f"M={module}", "ARCH=x86_64", "CROSS_COMPILE=", "modules",
    ]
    assert f"{kdir}:{kdir}:ro" in run and f"{module}:{module}:rw" in run


def test_config_only_output_shell_quotes_literal_hostile_cache_path(
    kbuild_env, tmp_path
):
    hostile = _with_hostile_cache(kbuild_env, tmp_path)

    result = hostile.run("--config-only")
    evaluated = _evaluate_config_output(result.stdout, tmp_path)

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "injected-cache").exists()
    assert evaluated.returncode == 0, evaluated.stderr
    assert evaluated.stdout == str(hostile.cache / "kernels/7.0/x86_64/.config") + "\n"


# ---------------------------------------------------------------------------
# System.map preservation + host-side residue clean
# ---------------------------------------------------------------------------

RESIDUE = ("kernel/fork.o", "kernel/.fork.o.cmd", "built-in.a", "kernel/mod.ko")
PROTECTED = (
    "Makefile", ".config", "vmlinux", "System.map", "vmlinux.unstripped",
    "arch/x86/boot/bzImage",
)


def test_system_map_is_copied_to_the_output_directory(kbuild_env):
    """kbuild never preserved System.map, so the source tree held the only copy.

    mktarget.sh keeps System.map for its targets and the ubuntu-target skill
    documents it as the kbase fallback, so the omission was a real gap.
    """
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    outdir = kbuild_env.cache / "kernels/7.0/x86_64"
    assert (outdir / "System.map").is_file()
    assert (outdir / "System.map").read_text().strip().endswith("_text")


def test_residue_is_cleaned_by_default_and_artifacts_survive(kbuild_env):
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    src = kbuild_env.source_makefile.parent

    for relative in RESIDUE:
        assert not (src / relative).exists(), f"{relative} should have been cleaned"
    for relative in PROTECTED:
        assert (src / relative).is_file(), f"{relative} must never be cleaned"


def test_keep_residue_leaves_everything_in_place(kbuild_env):
    result = kbuild_env.run("--keep-residue")
    assert result.returncode == 0, result.stderr
    src = kbuild_env.source_makefile.parent
    for relative in RESIDUE + PROTECTED:
        assert (src / relative).is_file(), f"{relative} should have been kept"


def test_cleaned_tree_is_still_a_cache_hit_with_no_docker_run(kbuild_env):
    """Residue cleanup must not invalidate the complete build cache."""
    first = kbuild_env.run()
    assert first.returncode == 0, first.stderr
    kbuild_env.clear_docker_log()

    second = kbuild_env.run(fail_if_docker_runs=True)
    assert second.returncode == 0, second.stderr
    assert kbuild_env.docker_runs() == [], "a cleaned tree forced a rebuild"
    assert _parse_assignments(second.stdout)["KERNEL_SRC"].endswith("linux-7.0")


def test_clean_is_scoped_to_the_source_tree_and_spares_arch_boot(kbuild_env):
    result = kbuild_env.run()
    assert result.returncode == 0, result.stderr
    src = kbuild_env.source_makefile.parent
    # The boot image remains available in the retained source tree.
    assert (src / "arch/x86/boot/bzImage").is_file()


def test_config_only_keep_residue_leaves_the_tree_for_a_hand_build(kbuild_env):
    """#165: `--config-only --keep-residue` is the start of a hand `make -C
    "$KERNEL_SRC"`; it must not strip what is already in the tree."""
    src = kbuild_env.source_makefile.parent
    (src / "kernel").mkdir(parents=True, exist_ok=True)
    (src / "kernel/fork.o").write_text("obj\n")

    kept = kbuild_env.run("--config-only", "--keep-residue")
    assert kept.returncode == 0, kept.stderr
    assert (src / "kernel/fork.o").is_file()

    kbuild_env.run("--config-only", "--no-cache")
    assert not (src / "kernel/fork.o").exists()


# ---------------------------------------------------------------------------
# custom kconfig overlay (--config-enable / --config-disable / --config-fragment)
# ---------------------------------------------------------------------------

# scripts/config as far as kbuild uses it: edits .config in place.
FAKE_SCRIPTS_CONFIG = """#!/usr/bin/env python3
import re, sys
from pathlib import Path
op, sym, *rest = sys.argv[1:]
value = {"--enable": "y", "--module": "m", "--disable": None}.get(op)
if op == "--set-str":
    value = '"%s"' % rest[0]
elif op == "--set-val":
    value = rest[0]
cfg = Path(".config")
lines = cfg.read_text().splitlines() if cfg.exists() else []
lines = [l for l in lines if not re.match(rf"^(CONFIG_{sym}=|# CONFIG_{sym} is not set)", l)]
lines.append(f"CONFIG_{sym}={value}" if value else f"# CONFIG_{sym} is not set")
cfg.write_text("\\n".join(lines) + "\\n")
"""


def _use_real_kconfig(kbuild_env):
    """The real container shell, with a scripts/config that edits .config and
    an olddefconfig that drops $KBUILD_TEST_UNMET (an unmet `depends on`)."""
    source = _use_real_helper_targets(kbuild_env, "modern")
    config = source / "scripts/config"
    config.write_text(FAKE_SCRIPTS_CONFIG)
    config.chmod(0o755)
    makefile = kbuild_env.source_makefile
    makefile.write_text(makefile.read_text().replace(
        "kvm_guest.config olddefconfig:\n\t@:\n",
        "kvm_guest.config:\n\t@:\nolddefconfig:\n"
        "\t@if test -n \"$$KBUILD_TEST_UNMET\"; then "
        "sed -i \"/^CONFIG_$$KBUILD_TEST_UNMET=/d\" .config; fi\n",
    ))
    return source


def test_overlay_is_applied_after_the_builtin_overlays(kbuild_env):
    _use_real_kconfig(kbuild_env)
    result = kbuild_env.run(
        "--config-enable", "NF_TABLES,CONFIG_USER_NS", "--config-disable", "KASAN"
    )
    assert result.returncode == 0, result.stderr
    values = _parse_assignments(result.stdout)
    config = Path(values["CONFIG"]).read_text().splitlines()
    assert "CONFIG_NF_TABLES=y" in config
    assert "CONFIG_USER_NS=y" in config
    assert "# CONFIG_KASAN is not set" in config  # the built-in overlay enables it
    assert "CONFIG_DEBUG_INFO=y" in config        # the built-in overlays still apply
    assert Path(values["KERNEL"]).is_file()


def test_a_custom_config_never_shares_another_configs_cache(kbuild_env, tmp_path):
    stock = kbuild_env.run()
    assert stock.returncode == 0, stock.stderr
    stock_kernel = _parse_assignments(stock.stdout)["KERNEL"]

    kbuild_env.clear_docker_log()
    custom = kbuild_env.run("--config-enable", "NF_TABLES")
    assert custom.returncode == 0, custom.stderr
    assert kbuild_env.docker_runs(), "a custom config was served the stock build"
    custom_kernel = _parse_assignments(custom.stdout)["KERNEL"]
    assert Path(custom_kernel).parent != Path(stock_kernel).parent

    # The same overlay spelled as a fragment is the same config: a cache hit.
    fragment = tmp_path / "nft.config"
    fragment.write_text("# netfilter\nCONFIG_NF_TABLES=y\n")
    kbuild_env.clear_docker_log()
    again = kbuild_env.run("--config-fragment", str(fragment), fail_if_docker_runs=True)
    assert again.returncode == 0, again.stderr
    assert _parse_assignments(again.stdout)["KERNEL"] == custom_kernel

    # A different overlay is a different build; the stock cache still hits.
    kbuild_env.clear_docker_log()
    other = kbuild_env.run("--config-enable", "NF_TABLES", "--config-disable", "KASAN")
    assert other.returncode == 0, other.stderr
    assert kbuild_env.docker_runs()
    assert _parse_assignments(other.stdout)["KERNEL"] not in (custom_kernel, stock_kernel)
    kbuild_env.clear_docker_log()
    assert kbuild_env.run(fail_if_docker_runs=True).returncode == 0


def test_an_outdir_holding_another_config_is_rebuilt(kbuild_env, tmp_path):
    outdir = tmp_path / "shared-outdir"
    assert kbuild_env.run("--outdir", str(outdir), "--config-enable", "NF_TABLES").returncode == 0
    kbuild_env.clear_docker_log()
    stock = kbuild_env.run("--outdir", str(outdir))
    assert stock.returncode == 0, stock.stderr
    assert kbuild_env.docker_runs(), "the stock config was served a custom build"


def test_a_setting_olddefconfig_drops_fails_the_build(kbuild_env):
    """A kernel quietly missing the requested option is the failure the
    verify step exists for: no assignments, the symbol named, nothing cached."""
    _use_real_kconfig(kbuild_env)
    kbuild_env.env["KBUILD_TEST_UNMET"] = "NF_TABLES"
    result = kbuild_env.run("--config-enable", "NF_TABLES,USER_NS")
    assert result.returncode == 1
    assert result.stdout == ""
    assert "CONFIG_NF_TABLES=y" in result.stderr
    assert "CONFIG_USER_NS" not in result.stderr

    del kbuild_env.env["KBUILD_TEST_UNMET"]
    retry = kbuild_env.run("--config-enable", "NF_TABLES,USER_NS")
    assert retry.returncode == 0, retry.stderr
    assert "CONFIG_NF_TABLES=y" in Path(_parse_assignments(retry.stdout)["CONFIG"]).read_text()


@pytest.mark.parametrize("line", ["CONFIG_FOO=maybe", "FOO=y", 'CONFIG_FOO="a\\"b"'])
def test_a_malformed_fragment_is_refused_before_anything_runs(kbuild_env, tmp_path, line):
    fragment = tmp_path / "bad.config"
    fragment.write_text(line + "\n")
    result = kbuild_env.run("--config-fragment", str(fragment), fail_if_docker_runs=True)
    assert result.returncode == 2
    assert f"{fragment}:1" in result.stderr
    assert kbuild_env.docker_runs() == []
