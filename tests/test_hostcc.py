"""Host-toolchain selection for `qmu compile --host` (qmu.hostcc).

The load-bearing property is that the compiler is chosen from the GUEST arch,
never the host's. Picking the host compiler for a cross-arch guest produces a
binary that fails to exec inside the VM as a bare "cannot execute binary file",
which reads like a guest problem rather than a missing toolchain — so these
tests pin cross-selection even when a perfectly good host `gcc`/`cc` is present.

`shutil.which` and `platform.machine` are patched on the hostcc module so the
table is exercised independently of whatever toolchains this developer happens
to have installed.
"""

from __future__ import annotations

import pytest

from qmu import hostcc
from qmu.instance import QMUError


def _fake_which(available: set[str]):
    def _which(name, *args, **kwargs):
        return f"/usr/bin/{name}" if name in available else None

    return _which


@pytest.fixture
def x86_host(monkeypatch):
    monkeypatch.setattr(hostcc.platform, "machine", lambda: "x86_64")


# --- arch normalization ----------------------------------------------------

@pytest.mark.parametrize(
    "spelling,expected",
    [
        ("x86_64", "x86_64"),
        ("amd64", "x86_64"),
        ("aarch64", "aarch64"),
        ("arm64", "aarch64"),
        ("ARM64", "aarch64"),
        ("armhf", "arm"),
        ("armv7l", "arm"),
        ("i686", "i386"),
        ("i386", "i386"),
    ],
)
def test_normalize_arch_aliases(spelling, expected):
    assert hostcc.normalize_arch(spelling) == expected


def test_normalize_arch_passes_none_through():
    assert hostcc.normalize_arch(None) is None


def test_normalize_arch_keeps_unknown_spelling():
    """An unheard-of target is lowercased, not rejected: the caller's 'no
    toolchain for <arch>' error is more useful than refusing to try."""
    assert hostcc.normalize_arch("Riscv64") == "riscv64"


# --- selection -------------------------------------------------------------

def test_cross_arch_prefers_cross_compiler_over_host_gcc(monkeypatch, x86_host):
    """An aarch64 guest on an x86_64 host must NOT get the host gcc."""
    monkeypatch.setattr(
        hostcc.shutil, "which", _fake_which({"cc", "gcc", "aarch64-linux-gnu-gcc"})
    )
    assert hostcc.resolve_host_cc("aarch64") == ["aarch64-linux-gnu-gcc"]


def test_same_arch_uses_plain_host_compiler(monkeypatch, x86_host):
    monkeypatch.setattr(
        hostcc.shutil, "which", _fake_which({"cc", "gcc", "x86_64-linux-gnu-gcc"})
    )
    assert hostcc.resolve_host_cc("x86_64") == ["cc"]


def test_unknown_instance_arch_falls_back_to_host_compiler(monkeypatch, x86_host):
    """arch=None (instance JSON written before the field existed) still builds."""
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which({"cc"}))
    assert hostcc.resolve_host_cc(None) == ["cc"]


def test_arm_guest_prefers_hardfloat_then_softfloat(monkeypatch, x86_host):
    monkeypatch.setattr(
        hostcc.shutil,
        "which",
        _fake_which({"arm-linux-gnueabihf-gcc", "arm-linux-gnueabi-gcc"}),
    )
    assert hostcc.resolve_host_cc("arm") == ["arm-linux-gnueabihf-gcc"]

    monkeypatch.setattr(
        hostcc.shutil, "which", _fake_which({"arm-linux-gnueabi-gcc"})
    )
    assert hostcc.resolve_host_cc("armhf") == ["arm-linux-gnueabi-gcc"]


def test_i386_prefers_real_cross_over_m32(monkeypatch, x86_host):
    """`gcc -m32` fails at LINK time when multilib is missing, which is harder to
    read than a missing-compiler error, so a real i686 cross wins when present."""
    monkeypatch.setattr(
        hostcc.shutil, "which", _fake_which({"gcc", "i686-linux-gnu-gcc"})
    )
    assert hostcc.resolve_host_cc("i386") == ["i686-linux-gnu-gcc"]


def test_i386_falls_back_to_m32_on_x86_64_host(monkeypatch, x86_host):
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which({"gcc"}))
    assert hostcc.resolve_host_cc("i386") == ["gcc", "-m32"]


def test_no_toolchain_names_arch_candidates_and_escape_hatch(monkeypatch, x86_host):
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which(set()))
    with pytest.raises(QMUError) as exc:
        hostcc.resolve_host_cc("aarch64")
    message = str(exc.value)
    assert "aarch64" in message
    assert "aarch64-linux-gnu-gcc" in message      # what was tried
    assert "gcc-aarch64-linux-gnu" in message      # how to install it
    assert "--cc" in message                       # how to override it


# --- --cc override ---------------------------------------------------------

def test_cc_override_is_used_verbatim(monkeypatch, x86_host):
    """The override is deliberately NOT validated against the guest arch: it
    exists so an unmodelled toolchain (musl cross, clang --target, a wrapper)
    can be used without qmu having to know about it."""
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which({"clang", "gcc"}))
    assert hostcc.resolve_host_cc(
        "aarch64", "clang --target=aarch64-linux-gnu"
    ) == ["clang", "--target=aarch64-linux-gnu"]


def test_cc_override_missing_binary_is_an_error(monkeypatch, x86_host):
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which({"gcc"}))
    with pytest.raises(QMUError) as exc:
        hostcc.resolve_host_cc("x86_64", "nope-gcc")
    assert "nope-gcc" in str(exc.value)


def test_empty_cc_override_is_an_error(monkeypatch, x86_host):
    monkeypatch.setattr(hostcc.shutil, "which", _fake_which({"gcc"}))
    with pytest.raises(QMUError):
        hostcc.resolve_host_cc("x86_64", "   ")


# --- host_compile ----------------------------------------------------------

def test_host_compile_builds_a_real_binary(tmp_path):
    cc = hostcc.resolve_host_cc(hostcc.host_arch())
    source = tmp_path / "hello.c"
    source.write_text("int main(void) { return 7; }\n")
    out = tmp_path / "hello"

    rc, _stdout, stderr, argv = hostcc.host_compile(source, out, "-O0", cc)

    assert rc == 0, stderr
    assert out.exists()
    # cflags are split into separate argv entries (there is no shell here).
    assert argv[-4:] == ["-O0", "-o", str(out), str(source)]


def test_host_compile_returns_rc_for_a_broken_source(tmp_path):
    """A compile error is a return value, not an exception: the caller renders
    it as the same 'Compilation failed' envelope the in-guest path produces."""
    cc = hostcc.resolve_host_cc(hostcc.host_arch())
    source = tmp_path / "broken.c"
    source.write_text("int main(void) { this is not c }\n")

    rc, _stdout, stderr, _argv = hostcc.host_compile(
        source, tmp_path / "broken", "-O0", cc
    )

    assert rc != 0
    assert stderr.strip()


def test_host_compile_missing_compiler_raises_qmu_error(tmp_path):
    source = tmp_path / "hello.c"
    source.write_text("int main(void) { return 0; }\n")
    with pytest.raises(QMUError) as exc:
        hostcc.host_compile(
            source, tmp_path / "hello", "", ["/nonexistent/definitely-not-a-cc"]
        )
    assert "could not start" in str(exc.value)
