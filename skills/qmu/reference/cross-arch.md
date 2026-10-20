# Cross-arch quickstarts (aarch64 / arm32)

Companion to `skill://qmu`. Read this when the guest is not the host
architecture: ARM quickstarts, the arch-aware `qmu.toml`, multiarch GDB, the
host cross-toolchain table for `compile --host`, and KASLR rebasing per arch.

Booting a non-x86 guest needs three things the x86 defaults don't provide: the right
`qemu-system-*` binary (`--arch`), a `virt` machine + CPU model (`-- -M virt -cpu …`),
and an ARM console/root cmdline (`console=ttyAMA0 root=/dev/vda`). The built-in profiles
hard-code `console=ttyS0 root=/dev/sda` for x86, so cross-arch launches **must** either
override `--cmdline` or use an arch-aware `qmu.toml` (see below). Build the kernel and
rootfs with the `qmu-linux-kbuild` and `qmu-linux-rootfs` skills (`--arch arm64` / `--arch arm32`).

The implicit rootfs drive is arch-aware: `if=virtio` (PCI) on aarch64, and an
`if=none` drive plus `-device virtio-blk-device` (MMIO) on arm. Both mount
`/dev/vda` with no `--drive`, so never pass the rootfs drive by hand for these
two arches — an explicit `--drive` suppresses the implicit one and you take
over the whole block topology.

Do **not** put `earlyprintk=serial` on an ARM cmdline: arm64 has no
`earlyprintk` parameter, and qmu's unknown-parameter lint reports it on every
launch. The x86 profiles carry it because x86 does implement it.

**Multiarch GDB (required on x86 hosts).** Ubuntu's stock `gdb` is x86-only and pry
invokes `gdb`; an ARM target makes it fail with a truncated `g` packet. Put
`gdb-multiarch` on `PATH` as `gdb` before any pry command (pry then reports
`gdb: gdb-multiarch`):

```bash
mkdir -p /tmp/gdb-multiarch-bin
ln -sfn /usr/bin/gdb-multiarch /tmp/gdb-multiarch-bin/gdb
export PATH=/tmp/gdb-multiarch-bin:$PATH
```

## aarch64 (arm64)

```bash
# Outputs of the qmu-linux-kbuild / qmu-linux-rootfs skills (cache hits once built):
eval "$(tools/kbuild.sh --version 7.0 --arch arm64)"   # KERNEL VMLINUX CONFIG KERNEL_SRC VMLINUX_GDB KDIR
eval "$(tools/mkrootfs.sh --arch arm64)"               # ROOTFS SSH_KEY
# KERNEL_SRC (~/.cache/qmu/kernels/src/linux-7.0) is the version's shared source
# tree for `pry load --src`; it holds whichever arch was built last — build
# modules against KDIR (see "Out-of-tree modules" below), never against it.

qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch aarch64 --name arm70 --no-replace \
  --cmdline "console=ttyAMA0 root=/dev/vda rw net.ifnames=0" \
  -- -M virt -cpu cortex-a57                  # TCG: boot-to-SSH 20–60 s (measured 20–30 s), not ~7 s

qmu exec --vm arm70 "uname -a"          # … 7.0.0 … aarch64
qmu compile hello.c --run --vm arm70    # machine=aarch64, sizeof(void*)=8 (banner on stderr)
```

`qmu kbase` needs only SSH and readable `/proc/kallsyms` — no `--gdb`, no
stub, no pry bridge — so the rebase check below works on this plain VM; add
`--gdb` to the launch only when you intend to attach pry.

**KASLR rebase on arm64 — use `_text` (`qmu kbase`'s or `pry kbase`'s
`KBASE`), nothing else.** pry (0.1.0 and later) keys the slide to the `_text`
symbol, which is exactly what `qmu kbase`, `pry kbase` and `/proc/kallsyms`
report. Measured against a live 7.0 arm64
guest: `--base "$KBASE"` placed `__arm64_sys_newuname` at the kallsyms address;
`--base 0x$STEXT` (the runtime `_stext`, `0x10000` above `_text` because of the
`.head.text` gap) placed every symbol **`0x10000` too high** and breakpoints
missed. Older copies of this skill recommended `_stext` as a workaround for a
pry bug that is now fixed — do not follow them.

```bash
qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" --arch aarch64 --gdb \
  --name arm70 --no-replace --cmdline "console=ttyAMA0 root=/dev/vda rw net.ifnames=0" -- -M virt -cpu cortex-a57
qmu gdb --vm arm70 --symbols "$VMLINUX"                   # bridge qmu-arm70; vCPU halted
qmu cont --vm arm70                                       # attach halted the vCPU
eval "$(qmu kbase --vm arm70 --symbols "$VMLINUX")"       # KBASE, LINK_BASE, SLIDE
pry --instance qmu-arm70 load "$VMLINUX" --base "$KBASE" --src "$KERNEL_SRC"
pry --instance qmu-arm70 break set __arm64_sys_newuname   # arm64 syscall wrapper prefix
pry --instance qmu-arm70 continue --background
qmu exec --vm arm70 "uname -r"                            # hits the breakpoint; exec returns in ~1 s, guest_state: paused
pry --instance qmu-arm70 wait --timeout 10                # the reliable stop primitive
```

For `lx-*` scripts and `$lx_current()`, the arm64 kernel must be built with **full**
`DEBUG_INFO` (not `DEBUG_INFO_REDUCED`, the arm64 defconfig default, which makes lx scripts
refuse to load). Current `qmu-linux-kbuild` disables the reduced variant, but a kernel
cached before that change still carries it — check
`grep DEBUG_INFO_REDUCED "$CONFIG"` and rebuild with `--no-cache` if it says `=y`.

`pry kbase` (pry #66) works here and needs no SSH: on the halted guest it maps
the VBAR handler back through `vectors`, accepts the base only once the guest's
`linux_banner` there matches the vmlinux, and rebases the loaded vmlinux
(measured on 7.0 arm64 right after `qmu gdb`: `found by: VBAR handler … =
vectors`, the same `_text` as `qmu kbase` and kallsyms, `&commit_creds` equal
to its kallsyms address, and an `__arm64_sys_newuname` breakpoint fired). It
needs the vmlinux loaded (`qmu gdb --symbols`) and the kernel booted, and exits
1 (`could not determine the kernel base`) rather than guess; `qmu kbase` is the
SSH route.

## arm32 (armv7l)

The arm32 `virt` machine uses virtio over **MMIO**. qmu attaches the rootfs as an MMIO
`virtio-blk-device` by default, but it does **not** wire up an MMIO NIC, so networking
needs `--no-net` plus a manual `-netdev`/`virtio-net-device` pair. Pick the SSH port
yourself with `--ssh-port N` and use the same `N` in the `hostfwd`:

```bash
eval "$(tools/kbuild.sh --version 7.0 --arch arm32)"   # multi_v7; KERNEL=…/zImage
eval "$(tools/mkrootfs.sh --arch arm32)"

qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch arm --gdb --name arm32-70 --no-replace --no-net --ssh-port 10131 \
  --cmdline "console=ttyAMA0 root=/dev/vda rw net.ifnames=0" \
  -- -M virt -cpu cortex-a15 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10131-:22 \
  -device virtio-net-device,netdev=net0

qmu exec --vm arm32-70 "uname -a"          # … 7.0.0 … armv7l
qmu compile hello.c --run --vm arm32-70    # sizeof(void*)=4
```

**The hostfwd-matching trap.** `--no-net` suppresses qmu's own NIC and its
port forward; the manual `hostfwd=…:N-:22` is the only route to guest `:22`,
and qmu will connect to whatever port it *recorded* for the VM. If those two
numbers differ, `qmu exec` does not fail cleanly: on a shared host it can
connect to **another VM's** sshd on the recorded port and report success
against the wrong kernel, and `status` can show `SSH: ready` for a foreign
listener. Always pass `--ssh-port N` with `--no-net` and reuse `N` in the
`hostfwd`; never hard-code `10021`, which collides with the first auto-allocated
VM on the host. `--no-net` without `--ssh-port` records **no** SSH endpoint at
all (SSH commands then refuse with the `--no-net` reason instead of probing a
port that may belong to someone else), so the explicit `--ssh-port` is what
makes the manual NIC usable. A *second* guest port (gdbserver, a service)
on a machine where qmu's own NIC works needs none of this: `--forward
[HOST:]HPORT:GPORT` adds the `hostfwd` to qmu's NIC and records it
(`launch.md`); with `--no-net` it is refused, so add the extra `hostfwd=`
to your own `-netdev` instead.

**Debug — `--slide 0`, not `--base`.** The `multi_v7` build typically loads with no KASLR
slide (`qmu kbase` shows link == runtime). `pry load --base` fails on this ELF
(`could not read the .text address … pass --slide`); use `--slide 0` instead. The uname
syscall symbol is `sys_newuname` (also `__se_sys_newuname`), **not** the `__arm_sys_*` /
`__arm64_sys_*` wrappers:

```bash
pry launch --connect localhost:1234
pry load "$VMLINUX" --slide 0 --src "$KERNEL_SRC"
pry break set sys_newuname
pry continue --background
qmu exec --vm arm32-70 "uname -r"          # hits the breakpoint
```

KASAN is **unsupported on arm32** upstream (no `HAVE_ARCH_KASAN`); use x86_64 or arm64 if you
need it. `nokaslr` is reported as unknown on arm32 because `arch/arm/` has no
KASLR at all — it really does nothing there.

## Out-of-tree modules (a survivable Oops on arm)

The kbuild configs carry no LKDTM, so the deterministic, root-reachable,
*survivable* Oops is a tiny `.ko`. Build it against the arch's `KDIR`, not
`KERNEL_SRC` — that tree is shared by every arch of the version and holds
whichever arch was built last. `"$KDIR/qmu-kmake"` runs make in the toolchain
image that built the kernel (same cross GCC, same `Module.symvers`):

```bash
mkdir oops && cd oops
cat > oops.c <<'EOF'
#include <linux/module.h>
static int __init oops_init(void) { *(volatile int *)0 = 0; return 0; }
module_init(oops_init);
MODULE_DESCRIPTION("null write in init: a survivable Oops");
MODULE_LICENSE("GPL");
EOF
echo 'obj-m += oops.o' > Kbuild
"$KDIR/qmu-kmake" modules                    # oops.ko for this arch, this kernel's vermagic
qmu push oops.ko /root/oops.ko --vm arm70
qmu exec --vm arm70 'insmod /root/oops.ko'  # exit 1 + crash_detected/crash: insmod died in the Oops
qmu crash --vm arm70                        # Internal error: Oops …; `status` says guest: crashed, still serving
```

A kernel cached before kbuild shipped `KDIR` is rebuilt once by the `eval`
above (`cached build is incomplete; rebuilding …`). Details:
`skill://qmu-linux-kbuild` → *Out-of-tree modules*.

## Arch-aware qmu.toml (skip the per-launch flags)

Baking the machine args, arch, and ARM cmdline into `qmu.toml` lets you launch with just
`qmu launch --name X --no-replace --kernel "$KERNEL"` — or flagless with the optional
`[boot] kernel`. Example for aarch64 (swap `cortex-a15`/`arm` for arm32,
and add the `--no-net --ssh-port N` + MMIO NIC args from the arm32 recipe):

```toml
[boot]
kernel = "/…/kernels/7.0/arm64/Image"   # optional: then plain `qmu launch --name X --no-replace` works

[machine]
arch = "aarch64"
extra_args = ["-M", "virt", "-cpu", "cortex-a57"]

[drive]
rootfs = "/…/rootfs/bookworm/arm64/rootfs.img"
format = "raw"

[ssh]
key = "/…/rootfs/bookworm/arm64/id_ed25519"

[profiles.exploit-dev]
cmdline = "console=ttyAMA0 root=/dev/vda rw net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"
```

The kbuild arm64 config has no LSMs, so `selinux=0 apparmor=0` are unclaimed
by that kernel; being profile-sourced they appear only in launch JSON
(`unknown_kernel_params_by_source.profile`), never on stderr. Without
`[boot] kernel`, `doctor` shows `[~] kernel: not configured` — `--kernel`
launches still work.

## Building on the host for a foreign guest (`compile --host`)

`qmu compile --host` compiles on the host with a toolchain chosen from the
**guest** arch recorded on the instance, then pushes the binary. It is the only
path when the guest has no gcc (kernelCTF images, vendor firmware rootfs,
minimal Debian), and it is several times faster than compiling inside a TCG
guest (measured on the bundled sample: 2.0 s host vs 10.5 s in an emulated
aarch64 guest; 1.7 s vs 5.7 s on arm32 — the ratio holds, the absolute numbers
vary with the host).

```bash
qmu compile exploit.c --host --run
qmu compile exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

| Guest arch | Tried, in order |
|------------|-----------------|
| host arch  | `cc`, `gcc` |
| `aarch64`  | `aarch64-linux-gnu-gcc` |
| `arm`      | `arm-linux-gnueabihf-gcc`, `arm-linux-gnueabi-gcc` |
| `i386`     | `i686-linux-gnu-gcc`, `i586-linux-gnu-gcc`, then `gcc -m32` |
| `x86_64`   | `x86_64-linux-gnu-gcc` |

If nothing is found, the error names what was tried, the package to install, and
`--cc`. `--cc` is honored verbatim and is deliberately **not** checked against the
guest arch, so an unmodelled toolchain (musl cross, clang, a wrapper script) works;
without `--host` it names the compiler run *in the guest* (default `gcc`). A VM whose instance record has **no**
recorded arch (written before qmu recorded it) is refused rather than guessed —
relaunch it, or pass `--cc`. `qmu doctor` adds `cross compiler for <arch>
(compile --host)` and `gdb-multiarch` rows when `[machine] arch` ≠ host arch
(`[~]` when missing, naming the `apt install` package).

Keep `-static` in `--cflags` (it is the default): a host-built dynamic binary must
match the guest's libc, and a static one sidesteps that entirely. The pushed
binary is `chmod +x`'d — `scp` does not preserve the mode.
