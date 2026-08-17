"""Host-side toolchain resolution for ``qmu compile --host``.

Building the guest binary on the *host* removes qmu's dependency on a compiler
inside the guest. Two things make the in-guest build the wrong default for a lot
of real work:

- A minimal rootfs (the one ``qmu-linux-rootfs`` produces, kernelCTF's, most
  vendor images) ships no gcc at all, so ``qmu compile`` fails on a VM that is
  otherwise perfectly usable.
- A cross-arch guest runs under TCG. Compiling an exploit inside an emulated
  aarch64 or arm guest is orders of magnitude slower than invoking the host's
  cross-compiler, and burns that time on every edit.

The compiler is selected from the **guest** architecture recorded on the
instance (``VMInstance.arch``), never from the host's. Picking by host arch would
happily produce an x86_64 binary for an aarch64 guest, which then fails to exec
in the guest as a bare "cannot execute binary file" — a much worse error than an
up-front "no aarch64 toolchain found".

This module is a leaf domain module: it knows nothing about instances, SSH, or
the CLI, so the selection table is unit-testable without a VM.
"""

from __future__ import annotations

import platform
import shlex
import shutil
import subprocess
from pathlib import Path

from .instance import QMUError


# Guest-arch spellings that mean the same target. qmu's own config uses the
# qemu-system-* spellings ("x86_64", "aarch64", "arm"), but a hand-written
# qmu.toml or a --arch flag may carry the Debian/uname spelling instead.
_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "x64": "x86_64",
    "i386": "i386",
    "i486": "i386",
    "i586": "i386",
    "i686": "i386",
    "x86": "i386",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "arm": "arm",
    "armv7l": "arm",
    "armv7": "arm",
    "armhf": "arm",
    "arm32": "arm",
}

# Cross-toolchain command names per normalized guest arch, in preference order.
# These are the Debian/Ubuntu gcc-*-linux-gnu* package names, which is what the
# qmu-linux-kbuild skill installs and what the dogfooding workflow already has.
_CROSS_CANDIDATES = {
    "x86_64": (("x86_64-linux-gnu-gcc",),),
    "i386": (("i686-linux-gnu-gcc",), ("i586-linux-gnu-gcc",)),
    "aarch64": (("aarch64-linux-gnu-gcc",),),
    "arm": (("arm-linux-gnueabihf-gcc",), ("arm-linux-gnueabi-gcc",)),
}

# Packages to name in the "no toolchain" error. An actionable install line beats
# a bare failure for an agent that cannot go read a wiki.
_CROSS_PACKAGES = {
    "x86_64": "gcc-x86-64-linux-gnu",
    "i386": "gcc-i686-linux-gnu (or gcc-multilib for the gcc -m32 path)",
    "aarch64": "gcc-aarch64-linux-gnu",
    "arm": "gcc-arm-linux-gnueabihf",
}


def normalize_arch(arch: str | None) -> str | None:
    """Map an arch spelling onto qmu's canonical one. None passes through.

    Unknown spellings are returned lowercased rather than rejected: the caller
    reports "no toolchain for <arch>" with the candidates it tried, which is more
    useful than refusing a target this table simply has not heard of yet.
    """
    if arch is None:
        return None
    key = arch.strip().lower()
    return _ARCH_ALIASES.get(key, key)


def host_arch() -> str:
    """The host's canonical arch (indirected for testability)."""
    return normalize_arch(platform.machine()) or "x86_64"


def candidate_compilers(arch: str | None) -> list[list[str]]:
    """Ordered candidate compiler argv prefixes for a guest arch.

    A candidate is an argv *list*, not a bare name, because the 32-bit x86 case
    is legitimately "the host gcc plus a flag" (``gcc -m32``) rather than a
    separate binary. Returning argv keeps that uniform for the caller.
    """
    target = normalize_arch(arch)
    host = host_arch()
    candidates: list[list[str]] = []

    # Same-arch guest: the plain host compiler is the right answer and is the
    # one most likely to be installed.
    if target is None or target == host:
        candidates.extend([["cc"], ["gcc"]])

    for cand in _CROSS_CANDIDATES.get(target or "", ()):  # type: ignore[arg-type]
        candidates.append(list(cand))

    # An i386 guest on an x86_64 host is buildable by the host gcc with -m32,
    # provided the 32-bit libc is present (gcc-multilib). Offered last so a real
    # i686 cross-compiler wins when both exist: -m32 fails at link time rather
    # than at exec time when multilib is missing, which is harder to read.
    if target == "i386" and host == "x86_64":
        candidates.append(["gcc", "-m32"])

    return candidates


def resolve_host_cc(arch: str | None, override: str | None = None) -> list[str]:
    """Return the compiler argv prefix to build for guest `arch`.

    `override` (from ``--cc``) is honored verbatim and is *not* checked against
    the target arch: it exists precisely so an unusual toolchain (a musl cross,
    a clang with an explicit --target, a wrapper script) can be used without qmu
    having to model it. It is split with :func:`shlex.split`, so a quoted
    argument survives: ``--cc "/opt/my toolchain/gcc"``.

    An instance with no recorded arch is refused rather than guessed. Falling
    back to the host compiler there would hand a cross-arch guest a host-arch
    binary that fails to exec as "cannot execute binary file" — the exact
    silent-wrong-answer this module exists to prevent — and the two ways out
    (relaunch so the arch is recorded, or name the compiler) are both cheap.
    """
    if override:
        try:
            parts = shlex.split(override)
        except ValueError as exc:
            raise QMUError(f"--cc is not a parseable command: {exc}") from exc
        if not parts:
            raise QMUError("--cc was given an empty compiler command")
        if shutil.which(parts[0]) is None:
            raise QMUError(
                f"Compiler not found on PATH: {parts[0]} (from --cc). "
                "Give an absolute path or install it."
            )
        return parts

    if arch is None:
        raise QMUError(
            "Cannot pick a host compiler: this VM's instance record has no "
            "architecture (it predates the recorded arch field). Relaunch it so "
            "the arch is recorded, or name the compiler: "
            "qmu compile --host --cc <compiler>"
        )

    candidates = candidate_compilers(arch)
    for cand in candidates:
        if shutil.which(cand[0]) is not None:
            return cand

    target = normalize_arch(arch) or "unknown"
    tried = ", ".join(" ".join(c) for c in candidates) or "(none)"
    pkg = _CROSS_PACKAGES.get(target)
    install = f" Try: apt install {pkg}." if pkg else ""
    raise QMUError(
        f"No host compiler found for guest arch '{target}'. Tried: {tried}."
        f"{install} Override with: qmu compile --host --cc <compiler>"
    )


def host_compile(
    source: Path,
    output: Path,
    cflags: str,
    cc: list[str],
    timeout: float = 120.0,
) -> tuple[int, str, str, list[str]]:
    """Compile `source` to `output` on the host. Returns (rc, stdout, stderr, argv).

    `cflags` is split with :func:`shlex.split`, not on bare whitespace: the
    in-guest path interpolates the flags into a guest shell, so a quoted flag
    like ``-DMSG='"hello world"'`` works there, and splitting on whitespace here
    would silently break it on --host only. There is no shell in this path, so
    the split has to do the quoting work the shell would have done.

    A compile failure is returned as a non-zero rc, not raised: the caller renders
    it as the same "Compilation failed" envelope the in-guest path produces.
    """
    try:
        flags = shlex.split(cflags)
    except ValueError as exc:
        raise QMUError(f"--cflags is not parseable: {exc}") from exc
    argv = [*cc, *flags, "-o", str(output), str(source)]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise QMUError(
            f"Host compile timed out after {timeout}s: {' '.join(argv)}"
        ) from exc
    except OSError as exc:
        raise QMUError(f"Host compile could not start {argv[0]}: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr, argv
