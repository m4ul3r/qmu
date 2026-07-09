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
source = mounts["/src"]
output = mounts["/output"]
output.mkdir(parents=True, exist_ok=True)
(output / ".config").write_text("CONFIG_DEBUG_INFO=y\\nCONFIG_GDB_SCRIPTS=y\\n")

inner = args[-1]
if "CONFIG_ONLY='true'" in inner:
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


def test_fresh_build_generates_gdb_helpers_and_exports_debug_paths(kbuild_env):
    result = kbuild_env.run()
    values = _parse_assignments(result.stdout)
    assert result.returncode == 0, result.stderr
    assert list(values) == [
        "KERNEL", "VMLINUX", "CONFIG", "KERNEL_SRC", "VMLINUX_GDB"
    ]
    assert Path(values["KERNEL"]).is_file()
    assert Path(values["VMLINUX"]).is_file()
    assert Path(values["CONFIG"]).is_file()
    assert (Path(values["KERNEL_SRC"]) / "Makefile").is_file()
    loader = Path(values["VMLINUX_GDB"])
    assert loader == Path(values["VMLINUX"]).parent / "vmlinux-gdb.py"
    assert loader.is_file()
    assert loader.is_symlink()
    assert loader.readlink() == Path("scripts/gdb/vmlinux-gdb.py")
    assert (loader.parent / "scripts/gdb/vmlinux-gdb.py").is_file()
    assert (loader.parent / "scripts/gdb/linux/constants.py").is_file()
    docker_argv = kbuild_env.last_docker_run()
    inner = docker_argv[-1]
    assert "scripts_gdb" in inner
    assert "cp -a scripts/gdb /output/scripts/gdb" in inner
    assert "-v" in docker_argv
    assert any(arg.endswith(":/src:rw") for arg in docker_argv)
    assert any(arg.endswith(":/output:rw") for arg in docker_argv)
    assert docker_argv[docker_argv.index("-w") + 1] == "/src"


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
    assert result.stdout == f"CONFIG={cold}/.config\n"
    assert (cold / ".config").is_file()
    assert not (cold / "vmlinux-gdb.py").exists()
    assert "scripts_gdb" not in kbuild_env.last_docker_run()[-1]

    warm_build = kbuild_env.run()
    warm_values = _parse_assignments(warm_build.stdout)
    output = Path(warm_values["CONFIG"]).parent
    kbuild_env.clear_docker_log()
    warm_config = kbuild_env.run("--config-only")
    assert warm_config.returncode == 0
    assert warm_config.stdout == f"CONFIG={output}/.config\n"
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
            '"$KERNEL" "$VMLINUX" "$CONFIG" "$KERNEL_SRC" "$VMLINUX_GDB"',
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
        "KERNEL", "VMLINUX", "CONFIG", "KERNEL_SRC", "VMLINUX_GDB"
    ]


def _with_hostile_cache(kbuild_env, tmp_path):
    cache = tmp_path / "$(touch injected-cache) cache with spaces;dollar$HOME-glob*"
    source = cache / "kernels/src/linux-7.0"
    source.mkdir(parents=True)
    (source / "Makefile").write_text("VERSION = 7\nPATCHLEVEL = 0\n")
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
            '"$KERNEL" "$VMLINUX" "$CONFIG" "$KERNEL_SRC" "$VMLINUX_GDB"',
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
    ]


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
