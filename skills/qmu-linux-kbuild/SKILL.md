---
name: qmu-linux-kbuild
description: Build Linux kernels (v4.x–latest) for QEMU exploit development inside Docker, with the GCC matched to the kernel version. Cross-compiles x86_64, i386, arm64, arm32, arm32hf with an exploit-dev config (KASAN, full DWARF, GDB helpers). Output is eval-able for `qmu launch --kernel`.
---

# qmu-linux-kbuild

`tools/kbuild.sh` downloads a kernel.org tarball, builds it in a
`qmu-kbuild:<ubuntu>-<arch>` container whose GCC matches the kernel's era, and
prints eval-able paths to the boot image, `vmlinux`, `.config`, the retained
source tree, the GDB helper loader and a per-arch out-of-tree module build
directory. It answers "is this a bug?" against a
kernel whose config you control. For "does this work on Ubuntu?" use
`qmu-ubuntu-target` (`tools/mktarget.sh`), which installs Ubuntu's own kernel
at a pinned ABI.

The script is not on `PATH`: from a qmu checkout it is `tools/kbuild.sh` (the
form used below); from this skill's directory, `../../tools/kbuild.sh`.

## Decision table

| Need | Run |
|---|---|
| An x86_64 kernel and boot it | `eval "$(tools/kbuild.sh --version 6.6.75)"; qmu launch --kernel "$KERNEL"` |
| A rootfs to go with it | `eval "$(tools/mkrootfs.sh)"` (`qmu-linux-rootfs`), then add `--rootfs "$ROOTFS" --ssh-key "$SSH_KEY"` |
| arm64 kernel | `eval "$(tools/kbuild.sh --version 6.6.75 --arch arm64)"` → `KERNEL` is `Image`; boot per `skill://qmu/reference/cross-arch.md` |
| i386 / arm32 / arm32hf | `--arch i386` (`bzImage`), `--arch arm32` or `--arch arm32hf` (`zImage`; `<5.0` uses `vexpress_defconfig`, else `multi_v7_defconfig`) |
| A custom config (subsystem the overlays leave off, KASAN off for a realistic slab layout) | `eval "$(tools/kbuild.sh --version 6.1.75 --config-enable NF_TABLES,USER_NS --config-disable KASAN)"`, or `--config-fragment nft.config` (kconfig fragment lines) — applied after the built-in overlays, before the final `olddefconfig`, under the same lock and output contract, cached in its own `6.1.75/x86_64-kconfig-<hash>/`; see *Config* |
| Inspect the config before a long build | `tools/kbuild.sh --version 6.6.75 --config-only` (with the same `--config-*` flags) → prints `CONFIG=` and `KERNEL_SRC=`. A hand-edited `.config` is never consumed by kbuild (every build regenerates it); express the change as `--config-enable`/`--config-disable`/`--config-fragment` instead |
| Build what the flags cannot express (a patched tree) | after a `--keep-residue` build of the same arch, `eval "$(tools/kbuild.sh --version 6.6.75 --config-only --keep-residue)"` reconfigures `KERNEL_SRC` with `CONFIG` **without** mrproper, so the previous objects stay for an incremental build; build it in the toolchain image, not with the host GCC: `docker run --rm --user "$(id -u):$(id -g)" -v "$KERNEL_SRC:/src" -w /src qmu-kbuild:jammy-x86_64 make -j8 bzImage` (outside kbuild's lock: run no kbuild of that version meanwhile) |
| GDB/pry source-level debugging | after a normal build: `pry gdb "add-auto-load-safe-path $(dirname "$VMLINUX_GDB")"; pry gdb "set substitute-path /src $KERNEL_SRC"; pry gdb "source $VMLINUX_GDB"` |
| Build a `.ko` for the guest (e.g. a survivable Oops on a config without LKDTM) | `cd mymod && "$KDIR/qmu-kmake" modules` — see *Out-of-tree modules* |
| Constrained host | `--jobs 4` (default `nproc`) |
| Build fails with a GCC error | `--container focal` (one newer than auto-selected; table below) |
| Keep `*.o`/`.cmd` for an incremental `make -C "$KERNEL_SRC"` | `--keep-residue` (default removes them after a successful build) |
| Reclaim residue left by older builds | `qmu cache du`, then `qmu prune --build-residue --dry-run`, then `qmu prune --build-residue` |
| Force a rebuild | `--no-cache` |
| Artifacts outside the cache | `--outdir /data/kernels/6.6.75` (the shared source tree stays under `$CACHE/kernels/src/`) |

## Output contract

Stdout carries only `printf %q`-quoted assignments, in this order; all logs,
Docker output and make output go to stderr.

```
KERNEL=/home/user/.cache/qmu/kernels/6.6.75/x86_64/bzImage
VMLINUX=/home/user/.cache/qmu/kernels/6.6.75/x86_64/vmlinux
CONFIG=/home/user/.cache/qmu/kernels/6.6.75/x86_64/.config
KERNEL_SRC=/home/user/.cache/qmu/kernels/src/linux-6.6.75
VMLINUX_GDB=/home/user/.cache/qmu/kernels/6.6.75/x86_64/vmlinux-gdb.py
KDIR=/home/user/.cache/qmu/kernels/6.6.75/x86_64/build
```

| Variable | Meaning |
|---|---|
| `KERNEL` | boot image: `bzImage` (x86_64, i386), `Image` (arm64), `zImage` (arm32, arm32hf) |
| `VMLINUX` | unstripped ELF with DWARF; `qmu gdb --symbols "$VMLINUX"`, `pry load` |
| `CONFIG` | the final `.config` the kernel was built with |
| `KERNEL_SRC` | retained source tree, mounted at `/src` during the build (DWARF paths start with `/src`). Shared by every arch of the version and left in the state of the last build — a source listing for `pry load --src`, **never** a module build tree |
| `VMLINUX_GDB` | `vmlinux-gdb.py` loader next to a copied `scripts/gdb/` tree; never move it out of that directory |
| `KDIR` | this arch's prepared module build tree (`.config`, `Module.symvers`, generated headers, the build's host tools) plus `qmu-kmake`; see *Out-of-tree modules* |
| *(no variable)* | `System.map` and `build.log` are also written next to `KERNEL` |

`--config-only` prints only `CONFIG=…` and `KERNEL_SRC=…` (no kernel, no
`VMLINUX_GDB`, no `lx-*` helpers); `KERNEL_SRC` is then the source tree
configured with that `.config`, ready for `make -C`.

| Exit | Meaning | Next |
|---|---|---|
| `0` | built, or served from cache; assignments on stdout | `qmu launch --kernel "$KERNEL"` |
| `1` | the containerised build failed; last stderr line is `kbuild: build failed (exit N) — check <outdir>/build.log`. Or a requested `--config-*` setting did not survive `olddefconfig` (`kbuild: requested CONFIG_X=y, but olddefconfig resolved it to: not set (an unmet depends on …)`, or `… this kernel's Kconfig declares no symbol X (misspelled, or not in this version)`, then `… nothing was built`). Or the resolved config has `MODULES` off (`… refusing to build a kernel without module support`) | read `build.log`; GCC errors → `--container` one step newer; apt/network errors → retry; a dropped setting → enable its `depends on` symbols too (`grep -rn -A8 '^config X$' "$KERNEL_SRC" --include='Kconfig*'`); an unknown symbol → fix the spelling |
| `2` | usage: missing/invalid `--version` (`major.minor[.patch]`), unsupported `--arch` or `--container`, unknown flag, `--help`, an invalid `--config-*` symbol or fragment line (`kbuild: error: <file>:<line>: …`); lock file unusable (e.g. NFS); extraction failed; products missing after an apparently successful build. Message is `kbuild: error: …` on stderr | fix the argument; for the lock, use a local `QMU_CACHE_DIR` |
| `130` / `143` | interrupted by SIGINT / SIGTERM; the build container is removed on the way out | rerun; nothing partial is served as a cache hit |
| other | a host step failed under `set -e` (`curl` download, `tar`, `docker build` of the toolchain image); the status is that tool's | `curl` 22 ⇒ version does not exist on the mirror; retry apt failures |

## Flags and environment

| Flag | Effect |
|---|---|
| `--version VER` | required; `major.minor[.patch]`, e.g. `6.6.75`, `7.0` |
| `--arch ARCH` | `x86_64` (default), `i386`, `arm64`, `arm32`, `arm32hf` |
| `--container TAG` | override the auto-selected toolchain image: `xenial`, `bionic`, `focal`, `jammy`, `noble` |
| `--outdir DIR` | artifact directory (default `$CACHE/kernels/VER/ARCH`, or `VER/ARCH-kconfig-<hash>` with `--config-*`) |
| `--jobs N` | `make -jN` (default `nproc`) |
| `--no-cache` | rebuild even if a complete cached build exists |
| `--config-only` | generate `.config` and exit; prints `CONFIG=` and `KERNEL_SRC=`. With `--keep-residue` it skips the `mrproper` and the residue clean, so the tree keeps the previous build's objects (after a build of another arch, run it without `--keep-residue`) |
| `--config-enable SYM[,SYM…]` | `CONFIG_SYM=y` after the built-in overlays (repeatable; `SYM` or `CONFIG_SYM`) |
| `--config-disable SYM[,SYM…]` | `CONFIG_SYM=n` likewise — e.g. `--config-disable KASAN`. `MODULES` is refused (exit 2): every build exports `KDIR`, which needs module support; a config that resolves to `MODULES` off any other way fails (exit 1) before compiling |
| `--config-fragment FILE` | apply a kconfig fragment: `CONFIG_X=y\|m\|n\|"str"\|<number>` and `# CONFIG_X is not set` lines, other `#` lines ignored (repeatable; the last setting of a symbol wins) |
| `--keep-residue` | keep `*.o`, `*.a`, `*.ko`, `.*.cmd`, `.tmp_vmlinux*` in `KERNEL_SRC` after a successful build |
| `--verbose` | show the Docker image build and full make output (default passes `-s` to make) |
| `-h`, `--help` | usage on stderr, exit 2 |

`QMU_CACHE_DIR` overrides `~/.cache/qmu` (shared with mkrootfs/mktarget);
`QMU_KBUILD_MIRROR` overrides `https://cdn.kernel.org/pub/linux/kernel`
(the tarball URL is `$MIRROR/v<major>.x/linux-<ver>.tar.xz`).

## Shared source tree and the per-version lock

Every arch of one version shares one extracted tree,
`$CACHE/kernels/src/linux-<ver>/`, and every build starts with `make mrproper`
+ defconfig + overlays in that tree. Every invocation for a version — cached or
not, any `--arch`, `--config-only` included — takes an exclusive `flock` on
`$CACHE/kernels/.src-linux-<ver>.lock` **before** the cache check, so two
invocations for the same version serialize instead of corrupting each other
(a `--config-only` mid-build used to delete `generated/autoconf.h` under the
running compile). Different versions use different lock files and run in
parallel.

A blocked invocation prints `kbuild: waiting for another kbuild invocation
holding the linux-<ver> source tree...` once, then blocks with no timeout and
no opt-out; past that line a wait and a hang look the same. Who holds it:
`fuser -v "$CACHE/kernels/.src-linux-<ver>.lock"`. When it gets the lock it
prints `kbuild: acquired linux-<ver> source-tree lock` and continues — which,
for a `--config-only` or a different-arch build, means mrproper on the tree
the previous invocation just built in; the previous invocation's artifacts are
already copied to its `--outdir`, so nothing it printed becomes stale.

Consequence for `--config-only`: it is safe to run beside a build (it waits).
Without `--keep-residue` it mrpropers the shared tree, wiping the finished
build's residue; with `--keep-residue` it reconfigures in place and keeps it,
which is the start of a hand `make -C "$KERNEL_SRC"`.

## Cache

```
~/.cache/qmu/kernels/
  src/linux-6.6.75/            # shared source (all arches) → KERNEL_SRC
  src/linux-6.6.75.tar.xz
  .src-linux-6.6.75.lock
  6.6.75/x86_64/               # bzImage, vmlinux, .config, System.map, build.log,
                               # vmlinux-gdb.py, scripts/gdb/…, build/ (KDIR)
  6.6.75/arm64/                # Image, …
  6.1.75/x86_64-kconfig-1a2b3c4d5e6f/  # a --config-* build; kconfig-overlay = its settings
```

A cache hit requires **all** of: `KERNEL`, `vmlinux`, `.config`,
`vmlinux-gdb.py`, `scripts/gdb/vmlinux-gdb.py`, `scripts/gdb/linux/constants.py`
(when the source has `constants.py.in`), `KDIR/{Makefile,.config,Module.symvers,qmu-kmake}`
**and** `KERNEL_SRC/Makefile`. A missing piece logs `cached build is
incomplete; rebuilding debugger artifacts and module build dir` and runs a
full build — including for a kernel cached before kbuild shipped `KDIR`, and
when only the source tree was deleted, which re-downloads the tarball and
recompiles. `qmu prune
--build-residue` never removes `Makefile`, `.config`, `vmlinux`, `System.map`
or `arch/*/boot/`, so it keeps the hit intact; `rm -rf src/linux-<ver>` does
not. It only looks under `src/`, so `KDIR` is never touched. `--config-only`
hits on `.config` while `KERNEL_SRC/.config` is still that same config (any
later build of the version reconfigures the shared tree, and then it
regenerates).

A custom config is part of the cache identity: the `--config-*` settings,
canonicalised (one `SYM=VALUE` per symbol, sorted — so a fragment and the
equivalent flags are the same build), name the output directory
(`<arch>-kconfig-<sha256[:12]>`) and are stamped in its `kconfig-overlay`.
Every hit also requires the stamp to match: a stock build never serves a
custom request, a custom one never serves the stock request, and a shared
`--outdir` holding another config is rebuilt.

Build residue (`*.o`, `*.a`, `*.ko`, `*.mod*`, `*.symtypes`, `.*.cmd`,
`.tmp_vmlinux*`) is removed from the tree after every successful build unless
`--keep-residue`; kbuild never reuses it (mrproper on every build), so keep it
only for your own incremental `make -C "$KERNEL_SRC"` after patching.

## Toolchain selection

| Container | Ubuntu | GCC | Auto-selected for |
|---|---|---|---|
| `xenial` | 16.04 | 5 | 4.0–4.9 |
| `bionic` | 18.04 | 7 | 4.10–5.3 |
| `focal` | 20.04 | 9 | 5.4–5.19 |
| `jammy` | 22.04 | 11 | 6.0–6.6 |
| `noble` | 24.04 | 13 | 6.7 and later (7.x) |

Images are tagged `qmu-kbuild:<container>-<arch>` and built on first use with
`build-essential bc bison flex libelf-dev libssl-dev cpio kmod xz-utils` plus
only the arch's cross package (`gcc-multilib` for i386,
`gcc-aarch64-linux-gnu`, `gcc-arm-linux-gnueabi`, `gcc-arm-linux-gnueabihf`).
To rebuild one: `docker rmi qmu-kbuild:jammy-x86_64` then rerun kbuild.

## Config

Base: `defconfig` (x86_64, arm64), `i386_defconfig`, `multi_v7_defconfig` /
`vexpress_defconfig` (arm32 ≥5.0 / <5.0); x86 also merges `kvm_guest.config`.
Overlays, then the caller's `--config-*` settings (so they can override an
overlay, e.g. turn KASAN off), then `olddefconfig`. Each caller setting is
then checked in the resolved `.config`; one `olddefconfig` dropped (unmet
`depends on`), or a symbol no `Kconfig` file of the tree declares (a typo),
fails the run with exit 1 before anything is built. The
built-in overlays:

- storage `EXT4_FS ATA ATA_PIIX SATA_AHCI`; network `E1000 E1000E VIRTIO_NET`;
  `DEVTMPFS DEVTMPFS_MOUNT`; `MODULES MODULE_UNLOAD`; `IKCONFIG IKCONFIG_PROC`
  (`zcat /proc/config.gz` in the guest)
- debug `KALLSYMS KALLSYMS_ALL DEBUG_KERNEL MAGIC_SYSRQ DEBUG_INFO GDB_SCRIPTS`,
  `DEBUG_INFO_REDUCED` disabled, `DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT` on ≥5.18
- `KASAN` on x86_64 (≥4.0) and arm64 (≥4.15) only: `KASAN_GENERIC` on ≥5.11,
  `KASAN_OUTLINE` before. i386 and arm32 have no `HAVE_ARCH_KASAN`.

## Arch notes

| Arch | QEMU | Image | Launch |
|---|---|---|---|
| `x86_64` | `qemu-system-x86_64`, KVM on x86 hosts | `bzImage` | `qmu launch --kernel "$KERNEL"` |
| `i386` | `qemu-system-i386` | `bzImage` | `qmu launch --kernel "$KERNEL" --arch i386` |
| `arm64` | `qemu-system-aarch64`, TCG | `Image` | `qmu launch --kernel "$KERNEL" --arch aarch64 --cmdline "console=ttyAMA0 root=/dev/vda rw" -- -M virt -cpu cortex-a57` |
| `arm32`/`arm32hf` | `qemu-system-arm`, TCG | `zImage` | `-M virt -cpu cortex-a15` with an MMIO virtio-blk drive; kernel is identical, only the cross ABI (vermagic, userspace) differs |

Extra QEMU args go after `--` (there is no `--extra-args` flag), and the
built-in profiles carry an x86 cmdline, so ARM needs `--cmdline`. Full
recipes, the arch-aware `qmu.toml` and pry rebasing:
`skill://qmu/reference/cross-arch.md`.

## Out-of-tree modules (`KDIR`)

`KDIR` (`<outdir>/build`) is exported from the build container right after the
kernel build: the linux-headers file set (top and arch `Makefile*`,
`include/`, `scripts/` with the host tools the container compiled,
`arch/<arch>/include` — plus `arch/arm/include/asm/opcodes.h` on arm64, which
4.x arm64 headers include — `module.lds`, `objtool` where built), the build's
`.config`, and `Module.symvers` — `vmlinux.symvers` on 5.10+, the one 4.x–5.9
write while linking vmlinux, else written by `make modules`. It covers the
core kernel's exports (modules that need another module's exports set
`KBUILD_EXTRA_SYMBOLS`). It is per arch and survives later builds of other
arches, which is exactly what `KERNEL_SRC` does not. Before kbuild accepts the
export it builds a trivial module against it in the container; an export that
cannot is a failed build (exit 1), never a cache hit.

`KDIR/qmu-kmake` runs `make -C "$KDIR" M="$PWD" ARCH=… CROSS_COMPILE=…` in
the `qmu-kbuild` image that built the kernel (`KDIR` mounted read-only, the
module directory read-write): the same GCC as the kernel — a host GCC of
another version is a silent ABI risk — and the libc the host tools were
linked against. Extra arguments go to make. The image must still exist
(`docker image ls qmu-kbuild`); a removed one only comes back with a kbuild
run that builds (`--no-cache`), since a cache hit never starts Docker.

```bash
eval "$(tools/kbuild.sh --version 6.6.75 --arch arm64)"
mkdir oops && cd oops
cat > oops.c <<'EOF'
#include <linux/module.h>
static int __init oops_init(void) { *(volatile int *)0 = 0; return 0; }
module_init(oops_init);
MODULE_DESCRIPTION("null write in init: a survivable Oops");
MODULE_LICENSE("GPL");
EOF
echo 'obj-m += oops.o' > Kbuild
"$KDIR/qmu-kmake" modules            # → oops.ko, vermagic = the cached kernel's
qmu push oops.ko /root/oops.ko --vm arm66
qmu exec --vm arm66 'insmod /root/oops.ko'  # exit 1, crash_detected + crash + hint: insmod died in the Oops
qmu status --vm arm66                       # guest: crashed — the report is retained, the guest still serves
qmu crash --vm arm66                        # Internal error: Oops … pc : oops_init+…
```

## GDB helpers

`VMLINUX_GDB` is the build-root loader copied beside `scripts/gdb/` (with
generated `scripts/gdb/linux/constants.py` on kernels that have
`constants.py.in`). kbuild runs `make scripts_gdb` when the Makefile has that
target, else `make prepare`; a failure there fails the build. DWARF records
`/src`, so `set substitute-path /src $KERNEL_SRC` maps sources to the retained
tree.

## Recovery

| Symptom | Cause | Fix |
|---|---|---|
| exit 1, `build.log` shows `-Werror=attribute-alias` or similar | GCC newer than the kernel expects | `--container <older>`; below `xenial` there is nothing — the kernel needs GCC 5 |
| exit 1, `build.log` ends in an internal compiler error or unknown option | GCC older than the kernel expects | `--container <newer>` |
| `docker build` apt errors (status 100) | mirror hiccup while building the toolchain image | retry; or `--container <other>` |
| `curl: (22)` on download | version not on the mirror | check `https://cdn.kernel.org/pub/linux/kernel/v<major>.x/`; `QMU_KBUILD_MIRROR=https://mirrors.edge.kernel.org/pub/linux/kernel` |
| `waiting for another kbuild invocation…` for a long time | another invocation of the same version holds the lock (a full build is minutes) | `fuser -v $CACHE/kernels/.src-linux-<ver>.lock`; wait, or kill that invocation (its container is reaped) |
| `kbuild: error: failed to acquire the linux-<ver> source-tree lock` (exit 2) | cache on a filesystem without `flock(2)` | `QMU_CACHE_DIR=/local/path` |
| `cached build is incomplete; rebuilding` on a kernel you built before | one of the required products or `src/linux-<ver>/Makefile` is gone | let it rebuild; afterwards never delete `src/` by hand — use `qmu prune --build-residue` |
| no KASAN report in the guest | i386/arm32 (unsupported), or version below the floor | use x86_64 or arm64; `zcat /proc/config.gz \| grep KASAN` |
| arm64 guest prints nothing / panics at boot | x86 cmdline or machine type | `-M virt -cpu cortex-a57` after `--`, `console=ttyAMA0 root=/dev/vda`, an arm64 rootfs |
| `No space left on device` in Docker | Docker storage full | `docker system prune`; `qmu prune --build-residue` for the cache |
| `lx-*` commands refuse to load | loader moved away from `scripts/gdb/`, or `DEBUG_INFO_REDUCED` | source `$VMLINUX_GDB` in place; rebuild with kbuild (it disables reduced DWARF) |
