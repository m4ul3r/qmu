---
name: qmu-linux-kbuild
description: Build Linux kernels (v4.x-latest) for QEMU exploit development via Docker. Handles version-to-toolchain mapping, cross-compilation (x86_64, i386, arm64, arm32, arm32hf), and exploit-dev configs (KASAN, debug info). Output integrates directly with qmu launch --kernel.
---

# qmu-linux-kbuild

Use this skill when the user needs a Linux kernel image for `qmu launch --kernel` and does not have a pre-built one, wants a specific kernel version, or needs a cross-architecture kernel. The script builds kernels inside Docker containers with GCC versions matched to the target kernel, so even 4.x kernels build reliably on modern hosts.

The script lives at `/opt/qmu/tools/kbuild.sh`.

## Quick reference

```bash
# Build x86_64 kernel (most common)
tools/kbuild.sh --version 6.6.75

# Build and immediately launch with qmu
eval $(tools/kbuild.sh --version 6.6.75)
qmu launch --kernel "$KERNEL"

# Cross-compile for arm64
tools/kbuild.sh --version 5.15.170 --arch arm64

# Build an old 4.x kernel
tools/kbuild.sh --version 4.4.138 --arch arm32

# 32-bit x86
tools/kbuild.sh --version 5.10.230 --arch i386

# ARM hard-float
tools/kbuild.sh --version 6.1.120 --arch arm32hf

# Force rebuild (ignore cache)
tools/kbuild.sh --version 6.6.75 --no-cache

# Generate .config only (inspect/customize before building)
tools/kbuild.sh --version 6.6.75 --config-only

# Override container for edge cases
tools/kbuild.sh --version 5.4.0 --container focal
```

## Output format

The script prints eval-able shell variables to stdout (all logs go to stderr):

```
KERNEL=/home/user/.cache/qmu/kernels/6.6.75/x86_64/bzImage
VMLINUX=/home/user/.cache/qmu/kernels/6.6.75/x86_64/vmlinux
CONFIG=/home/user/.cache/qmu/kernels/6.6.75/x86_64/.config
```

Use `eval $(tools/kbuild.sh ...)` to capture these into shell variables.

## Version-to-container mapping

The script auto-selects a Docker image (Ubuntu base + GCC version) that can build the target kernel. Each image is tagged per-architecture (`qmu-kbuild:<container>-<arch>`) and only installs the toolchain needed for that specific arch.

| Container tag | Ubuntu | GCC | Kernel range | When to override |
|---|---|---|---|---|
| `xenial` | 16.04 | 5 | 4.0 - 4.9 | Very old kernels that fail with GCC 7 |
| `bionic` | 18.04 | 7 | 4.10 - 5.3 | Default for late 4.x and early 5.x |
| `focal` | 20.04 | 9 | 5.4 - 5.19 | Mid-range 5.x LTS kernels |
| `jammy` | 22.04 | 11 | 6.0 - 6.6 | Current LTS kernels |
| `noble` | 24.04 | 13 | 6.7+ | Latest mainline kernels (including 7.x) |

If a build fails due to GCC incompatibility, override with `--container`:
```bash
# kernel 5.4.0 fails on bionic (GCC 7)? try focal (GCC 9)
tools/kbuild.sh --version 5.4.0 --container focal
```

## Docker image design

Images are built on first use and cached by Docker. The builder uses a single generic `build_docker_image()` function that:

1. Picks the Ubuntu base + python package based on container tag
2. Installs common build deps (`build-essential bc bison flex libelf-dev libssl-dev cpio kmod xz-utils`)
3. Installs only the arch-specific toolchain in a separate layer:
   - `x86_64`: no extra packages (native)
   - `i386`: `gcc-multilib`
   - `arm64`: `gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu`
   - `arm32`: `gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi`
   - `arm32hf`: `gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf`

This avoids the `gcc-multilib` vs cross-compiler package conflict by never installing them together.

Image tags follow the pattern `qmu-kbuild:<container>-<arch>` (e.g., `qmu-kbuild:xenial-arm32`, `qmu-kbuild:jammy-x86_64`).

## Architecture details

### x86_64 (default)

- QEMU binary: `qemu-system-x86_64`
- Kernel image: `bzImage`
- KVM acceleration: works natively on x86_64 hosts
- KASAN: supported since 4.0
- Docker toolchain: native GCC (no cross-compiler needed)

```bash
eval $(tools/kbuild.sh --version 6.6.75)
qmu launch --kernel "$KERNEL"
```

### i386 (32-bit x86)

- QEMU binary: `qemu-system-i386`
- Kernel image: `bzImage`
- Docker toolchain: `gcc-multilib` (native GCC with -m32)
- KASAN: **not supported** — 32-bit x86 has no `HAVE_ARCH_KASAN` (KASAN needs a 64-bit address space for its shadow region); use x86_64 if you need KASAN
- Set `arch = "i386"` in qmu.toml

```bash
eval $(tools/kbuild.sh --version 5.10.230 --arch i386)
qmu launch --kernel "$KERNEL" --arch i386
```

### arm64 (aarch64)

- QEMU binary: `qemu-system-aarch64`
- Kernel image: `Image` (not bzImage)
- Docker toolchain: `gcc-aarch64-linux-gnu`
- KASAN: supported since 4.15
- Needs `-M virt -cpu cortex-a57` QEMU args

```bash
eval $(tools/kbuild.sh --version 5.15.170 --arch arm64)
qmu launch --kernel "$KERNEL" --arch aarch64 \
  --extra-args "-M virt -cpu cortex-a57"
```

Or in qmu.toml:
```toml
[machine]
arch = "aarch64"
extra_args = ["-M", "virt", "-cpu", "cortex-a57"]
```

### arm32 / arm32hf

- QEMU binary: `qemu-system-arm`
- Kernel image: `zImage`
- Docker toolchain: `gcc-arm-linux-gnueabi` (arm32) or `gcc-arm-linux-gnueabihf` (arm32hf)
- KASAN: **not supported** on arm32 upstream
- Needs `-M vexpress-a15` QEMU args
- Kernels < 5.0 use `vexpress_defconfig`; >= 5.0 use `multi_v7_defconfig`
- arm32 vs arm32hf: kernel itself is identical (kernel does not use FP); the difference is the cross-compiler ABI, which affects vermagic and any userspace built alongside

```bash
eval $(tools/kbuild.sh --version 6.1.120 --arch arm32hf)
qmu launch --kernel "$KERNEL" --arch arm \
  --extra-args "-M vexpress-a15 -cpu cortex-a15" \
  --cmdline "console=ttyAMA0 root=/dev/mmcblk0 rw"
```

## Kernel config overlays

The script applies exploit-dev-focused config overlays on top of the arch-appropriate defconfig:

**Always enabled:**
- `EXT4_FS`, `ATA`, `ATA_PIIX`, `SATA_AHCI` (storage for rootfs)
- `E1000`, `E1000E`, `VIRTIO_NET` (networking)
- `DEVTMPFS`, `DEVTMPFS_MOUNT` (device infrastructure)
- `KALLSYMS`, `KALLSYMS_ALL`, `DEBUG_KERNEL`, `MAGIC_SYSRQ` (debug)
- `MODULES`, `MODULE_UNLOAD` (LKM exploit development)
- `IKCONFIG`, `IKCONFIG_PROC` (runtime config inspection via `/proc/config.gz`)
- `DEBUG_INFO`, `GDB_SCRIPTS` (debugger support)

**Version-gated:**
- `KASAN` + `KASAN_GENERIC` (>= 5.11) or `KASAN_OUTLINE` (< 5.11) — x86_64 >= 4.0, arm64 >= 4.15; i386 and arm32 never (no `HAVE_ARCH_KASAN`)
- `DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT` — >= 5.18 only (before 5.18, `DEBUG_INFO=y` is sufficient)

For x86_64/i386, `kvm_guest.config` is also applied for QEMU-optimized virtio defaults.

To inspect the config inside a running guest: `zcat /proc/config.gz | grep KASAN`

## Cache layout

Built kernels are cached and reused on subsequent runs:

```
~/.cache/qmu/kernels/
  src/
    linux-6.6.75/              # shared kernel source (all arches)
    linux-6.6.75.tar.xz        # downloaded tarball
  6.6.75/
    x86_64/
      bzImage                  # kernel image
      vmlinux                  # debug symbols
      .config                  # kernel config used
      build.log                # full build output
    arm64/
      Image
      vmlinux
      .config
      build.log
```

Use `--no-cache` to force a rebuild. Use `--config-only` to generate and inspect `.config` before committing to a full build.

## Troubleshooting

**Build fails with compiler errors (e.g., `-Wattribute-alias` as error):**
Old kernels (4.x) are strict about compiler warnings and fail with newer GCC. The auto-selected container should handle this, but if it doesn't, try an older one:
```bash
tools/kbuild.sh --version 4.4.138 --arch arm32  # auto-selects xenial (GCC 5)
# If xenial somehow fails, there's no older option — the kernel genuinely needs GCC 5
```

**Build fails with apt-get errors (exit code 100):**
Docker image build failed to install packages. This can happen if Ubuntu mirrors are temporarily unavailable. Retry, or try a different container:
```bash
tools/kbuild.sh --version 5.3.18 --container focal  # bump up from bionic
```

**KASAN not appearing in dmesg:**
- arm32 and i386: KASAN is not supported upstream (no `HAVE_ARCH_KASAN`). Use x86_64 or arm64.
- Check version: x86_64 needs >= 4.0, arm64 needs >= 4.15.
- Verify: `zcat /proc/config.gz | grep KASAN` inside the guest.

**arm64 kernel panics immediately:**
- Ensure QEMU uses `-M virt -cpu cortex-a57` (not the default PC machine type).
- Use an arm64 rootfs, not an x86 one.

**"No space left on device" during build:**
Docker storage may be full. Run `docker system prune` to reclaim space.

**Download fails:**
- Check the version exists at https://cdn.kernel.org/pub/linux/kernel/
- Override the mirror: `QMU_KBUILD_MIRROR=https://mirrors.edge.kernel.org/pub/linux/kernel`
- For v7.x kernels, the URL becomes `v7.x/linux-7.0.11.tar.xz` — this is handled automatically.

**Want to rebuild a Docker image from scratch:**
```bash
docker rmi qmu-kbuild:jammy-x86_64  # remove cached image
tools/kbuild.sh --version 6.6.75 --no-cache  # rebuilds image + kernel
```
