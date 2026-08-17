---
name: qmu-ubuntu-target
description: Build genuine Ubuntu targets (distro kernel + matching userland + debug symbols) and boot them under qmu to validate real kernel PoCs/exploits. Use when a result must be a statement about Ubuntu itself — n-day/CVE reproduction, exploit validation against a pinned kernel ABI, or checking whether a PoC survives Ubuntu's hardening — rather than against a self-built kernel. Covers ABI pinning, ddebs symbols, the fidelity-vs-debug profile contract, and the traps that make a PoC pass for the wrong reason.
---

# qmu-ubuntu-target

`tools/mktarget.sh` builds an **Ubuntu target**: Ubuntu's own `-generic` kernel
at a pinned ABI, its version-matched modules, its real userland and hardening
defaults, its `.config` and `System.map`, and optionally its `vmlinux` debug
symbols from ddebs — as one attributable matched set.

Use it when the answer has to be about **Ubuntu**. Use `qmu-linux-kbuild` +
`qmu-linux-rootfs` instead when you want to control the kernel source and config
(bug triage, KASAN, syzkaller repros).

The script ships in the qmu project's `tools/` directory and is not on `PATH`;
resolve it relative to the install location — from this skill's directory that is
`../../tools/mktarget.sh`, or from a checkout of the qmu repo just
`tools/mktarget.sh` (the form used below).

| | `kbuild.sh` + `mkrootfs.sh` | `mktarget.sh` |
|---|---|---|
| kernel | upstream kernel.org, your config | Ubuntu's `-generic`, Ubuntu's config |
| KASAN | yes | no (Ubuntu ships none) |
| LSMs | disabled by the profile | AppArmor + landlock + lockdown + yama, enforcing |
| answers | "is this a bug?" | "does this work on Ubuntu?" |

## Quick start

```bash
tools/mktarget.sh --list-abis                       # what can I pin?
eval $(tools/mktarget.sh --suite noble --kernel-abi ga)
qmu launch --config "$QMU_TOML" --kernel "$KERNEL" --profile "$PROFILE" --name ubu
qmu exec --vm ubu 'cat /etc/qmu-target.json'        # what am I actually running?
```

`--profile "$PROFILE"` is **not optional**. `qmu launch`'s `--profile` defaults
to `exploit-dev`, which passes `selinux=0 apparmor=0` — on an Ubuntu target that
silently deletes the LSM stack you are measuring. The script emits
`PROFILE=ubuntu-target` so this is one variable, not a thing to remember.

## Emitted variables

```
KERNEL  ROOTFS  SSH_KEY  CONFIG  SYSTEM_MAP  PROFILE  QMU_TOML  TARGET_MANIFEST
KERNEL_ABI  KERNEL_RELEASE  KERNEL_DEB_VERSION
VMLINUX   (only with --symbols)
INITRD    (only with --initramfs)
```

`VMLINUX` and `INITRD` are emitted only when `--symbols` / `--initramfs` was
passed on *this* run, even if an earlier run left the file in the output
directory — so testing for `$VMLINUX` is a reliable answer to "did I get symbols
this run", and the same holds for `$INITRD`.

All logs go to stderr; stdout is only the assignments, so `eval $(...)` is safe.

### Cache

`~/.cache/qmu/targets/ubuntu/<suite>/<arch>/<abi>-<flavour>[-relaxed][-<key>]/`

The `<key>` suffix appears only when a build-affecting option departs from the
defaults (`--headers`, `--packages`, `--size`, `--unpriv-user`, `--initramfs`,
`--no-modules-extra`, `--ssh-key`), so a default build keeps the predictable
short name and two legitimate variants stop evicting each other.

A directory counts as a cache hit only if it holds a completion stamp whose
build key matches this run and whose recorded artifact sizes still match. That
means an interrupted build is never served as a cached one, and a run whose
options — or whose resolved deb version — differ from the cached target rebuilds
instead of handing back an image that disagrees with the variables on stdout.

Adding `--symbols` to an already-built target fetches **only** the symbols and
leaves the rootfs exactly as it was. Only the kernel debs are version-pinned, so
a rebuild could pull a different `apparmor` or `procps` — asking for symbols
must not change the image a result was already measured on.

Cost: a cache hit is 1–8 s. It is not free and it is not offline: the ABI is
resolved against the archive *before* the cache is consulted, since for `ga` and
`latest` the resolved ABI is what names the directory. A fresh x86_64 target is a
couple of minutes; a cross-arch (arm64) one runs `apt` under `qemu-user` and
takes ~15 min the first time, then caches. `--relax-hardening` is a separate
image and so a separate build. The `Creating raw ext4 image` step is silent for
1–2 minutes while it exports ~1 GB — that is normal, not a hang.

If the archive cannot be read, the script **fails** rather than resolving from
whatever pockets did answer. A `-updates` fetch that times out used to look
identical to a `-updates` with no kernels in it, which quietly turned
`--kernel-abi latest` into `ga`.

## Pinning an ABI — the part that makes a result citable

**Always pin. Never use the floating `linux-image-generic` meta-package**, which
the script never installs: it moves with `-updates`, so the same command yields a
different kernel on a different day and a PoC result stops being attributable.

```bash
--kernel-abi ga                    # default: the release-pocket ABI (e.g. noble -> 6.8.0-31)
--kernel-abi latest                # highest ABI in -updates
--kernel-abi latest-with-symbols   # highest ABI that ALSO has a dbgsym  <- use when GDB matters
--kernel-abi 6.8.0-71              # exact
--kernel-version 6.8.0-53.55       # exact deb version, wins over --kernel-abi
```

`ga` is the default because the release pocket is **never pruned** and its ABI is
the one most likely to keep its debug symbols.

Two facts that will bite you otherwise:

- **`ddebs.ubuntu.com` prunes hard, and symbol availability is uncorrelated with
  recency.** At the time of writing, noble's release pocket had dbgsym for only
  `6.8.0-31`, `-updates` had `-111`/`-117`/`-124`, and the then-current `-136`
  and `-137` had **none**. `--list-abis` shows a DBGSYM column; `--symbols` on an
  ABI without one fails *before* building and names the ABIs that do have them.
- **The deb version is not the ABI doubled.** `6.8.0-31.31` but `6.8.0-53.55`,
  and `6.17.0-42` ships as both `.42` and `.42+1`. Never hand-build pool URLs;
  the script resolves through the archive index and records the exact version.

`noble` also carries HWE kernels well past 6.8 — 6.11, 6.14, 6.17 and 7.0 — so
`--suite noble --kernel-abi 7.0.0-14` is a legitimate 24.04 target.

## The three profiles, and which claims each supports

Shipped as built-ins in `config.py` and mirrored into the generated `qmu.toml`
with the arch-correct console and root device.

| profile | KASLR | LSMs | what a result here means |
|---|---|---|---|
| `ubuntu-target` | on | on | **the only profile under which "this PoC works on Ubuntu 24.04" is a valid claim** |
| `ubuntu-debug` | **off** (`nokaslr`) | on | reversing/GDB only. A working exploit here is *not* a working exploit on Ubuntu — KASLR bypass is a separate proof obligation. |
| `ubuntu-trigger` | on | on | triage: `panic_on_oops=1 panic_on_warn=1` so `qmu crash` yields one clean report. Not for exploitation. |

None of them carry `selinux=0 apparmor=0` (AppArmor *is* Ubuntu's LSM) or
`kasan.fault=panic` (inert and misleading on a KASAN-less distro kernel).

## Hardening: fidelity by default

The image ships Ubuntu's real values. Verified in-guest on noble GA:

```
kernel.kptr_restrict = 1                                  (procps)
kernel.dmesg_restrict = 1                                 (CONFIG_SECURITY_DMESG_RESTRICT=y)
kernel.perf_event_paranoid = 4                            (CONFIG_SECURITY_PERF_EVENTS_RESTRICT=y)
kernel.unprivileged_bpf_disabled = 2                      (CONFIG_BPF_UNPRIV_DEFAULT_OFF=y)
kernel.apparmor_restrict_unprivileged_userns = 1           (apparmor package)
vm.unprivileged_userfaultfd = 0                           (upstream default, not a distro file)
kernel.unprivileged_userns_clone = 1                      (a DECOY -- see below)
/sys/kernel/security/lsm -> lockdown,capability,landlock,yama,apparmor
101 AppArmor profiles loaded, 7 in enforce mode
```

### How the userns restriction actually fails — check the right thing

This is the trap most likely to produce a confidently wrong answer, because the
obvious probe reports the opposite of the truth.

`unshare(CLONE_NEWUSER)` **succeeds** on a fidelity target. AppArmor allows the
namespace to be created, transitions the task into the `unprivileged_userns`
profile, and then denies `CAP_SYS_ADMIN` — which `map_write()` needs. So the
namespace exists but is unusable, and the `EPERM` lands on the **`uid_map`
write**, not on `unshare()`:

```
[1] unshare(CLONE_NEWUSER)          OK          <-- checking only this misleads
[2] write "0 1000 1" > uid_map      EPERM       <-- the actual denial
[2] euid after mapping              65534       (never becomes 0)
[3] unshare(CLONE_NEWNET)           EPERM       (no CAP_SYS_ADMIN in the ns)
```

Guest audit log for the same event:

```
apparmor="AUDIT"  operation="userns_create" profile="unconfined"
                  target="unprivileged_userns"
apparmor="DENIED" operation="capable" profile="unprivileged_userns"
                  capability=21 capname="sys_admin"
```

So: **test the `uid_map` write, or just use `unshare -U -r`** (util-linux does
both steps and reports `write failed /proc/self/uid_map`). A PoC whose first line
is `unshare(CLONE_NEWUSER)` does not die on line 1 — it dies on line 2.

Two more decoys in the same area:

- **`kernel.unprivileged_userns_clone` reads `1`** on an Ubuntu target. It is a
  Debian-ism the Ubuntu kernel still exposes and it does **not** reflect the
  AppArmor restriction. Reading it gives the opposite of the truth;
  `kernel.apparmor_restrict_unprivileged_userns` is the one that matters.
- **Build the map string before you unshare.** After `unshare(CLONE_NEWUSER)`
  `getuid()` returns `65534`, so a probe that calls it afterwards writes
  `"0 65534 1"` and gets `EPERM` *even as root* — which looks exactly like the
  distro restriction.

### Relaxing it

`--relax-hardening` turns those sysctls off (and additionally sets
`vm.unprivileged_userfaultfd = 1`, since uffd is gated separately — see below).
It is recorded **four** ways so a relaxed run can never be mistaken for a
fidelity one: `hardening: "relaxed"` in `/etc/qmu-target.json`, an `/etc/motd`
banner, `QMU-TARGET-RELAXED` echoed to the serial log, and a `-relaxed` cache
directory so the two variants never share a build. The guest hostname also
becomes `qmu-ubuntu-relaxed`.

It builds a **separate image**, so it is a full build (a few minutes), not a
cache hit off the fidelity one.

`vm.unprivileged_userfaultfd = 0` is the *upstream kernel* default rather than an
Ubuntu sysctl file, so it blocks `userfaultfd()` independently of everything
above — for the unprivileged user *and* for root. If your PoC needs uffd for
heap grooming, that is a second, separate gate.

Do not reach for `--relax-hardening` to make a PoC work. A PoC that fails
because of one of these has told you something true about Ubuntu, and "works on
the relaxed image" means only "works once you have also defeated the AppArmor
userns restriction" — a separate proof obligation, same class as a KASLR bypass.

## Running a PoC as an unprivileged user

An LPE result measured as root is meaningless. The image has an unprivileged
`ubuntu` user at uid 1000. `--unpriv-user NAME` renames that account rather than
adding a second one, so the PoC user is uid 1000 whatever it is called. A name
that already exists at any other uid is refused rather than quietly relabelled —
including `nobody`, which noble ships at 65534 with `/usr/sbin/nologin`. `/root`
is `0700`, so the binary has to be copied out:

```bash
qmu compile ./poc.c --vm ubu
qmu exec --vm ubu 'install -m755 /root/poc /home/ubuntu/ && su ubuntu -c /home/ubuntu/poc'
```

## Debug symbols and GDB

```bash
eval $(tools/mktarget.sh --kernel-abi latest-with-symbols --symbols)
qmu launch --config "$QMU_TOML" --kernel "$KERNEL" --profile ubuntu-target --gdb --name ubu
qmu gdb --vm ubu --symbols "$VMLINUX"     # loads at ELF link-time addresses
qmu cont --vm ubu                          # gdb attach halts the vCPU
eval "$(qmu kbase --vm ubu --symbols "$VMLINUX")"
pry load "$VMLINUX" --base "$KBASE"
```

- The ddeb is ~1.9 GB unpacked; only `vmlinux` is stream-extracted, so it never
  lands on disk whole. `--symbols=full` also keeps the per-module debug tree.
- **KASLR is on** under `ubuntu-target`, so `qmu kbase` is the correct rebase
  path. It works despite `kptr_restrict=1` because `[ssh] user` is `root` and
  `/proc/kallsyms` gates on `CAP_SYSLOG`. It fails only if you point `[ssh] user`
  at a non-root account or something sets `kptr_restrict=2`.
- For a stable base while reversing, use `--profile ubuntu-debug` instead.
- Source-level debugging needs `set substitute-path` — the DWARF comp-dir is
  Ubuntu's builder path (recorded as `dwarf_comp_dir` in `target.json`). The
  matching source is `apt source linux` / `linux-source-*`; this tool does not
  fetch it. `lx-*` scripts additionally need `scripts/gdb/` from that tree, which
  the ddeb does not ship.
- If the ABI you need has no dbgsym, `qmu kbase` is impossible. `System.map-<ABI>`
  is always shipped but carries link-time addresses only, and `kbase` needs an
  ELF it can run `nm` on.

## Modules

`linux-modules-extra` is installed by default (110 MB). `nf_tables` is in the
base `linux-modules`, but `ksmbd`, `hfsplus` and `n_gsm` are **only** in `-extra`
— and many PoCs depend on autoload from an unprivileged context, which cannot
happen if the `.ko` is not on disk. The failure mode without it is silent ("the
PoC just doesn't trigger"). `--no-modules-extra` if you want the smaller image.

## Arch support

- **x86_64** — primary. Stock `/boot/vmlinuz` is a bzImage and boots directly.
- **arm64** — supported. `/boot/vmlinuz` is **plain gzip** (not a PE/zboot
  container, despite `CONFIG_EFI_ZBOOT=y`); the script decompresses it to a raw
  `Image` based on the magic bytes. Needs binfmt for cross-building:
  `docker run --rm --privileged tonistiigi/binfmt:latest --install all`.
- **armhf** — rejected. The kernel exists (`linux-image-<ABI>-generic`, no
  `unsigned` variant) but qmu's arm32 MMIO virtio-blk topology is unverified
  against an Ubuntu kernel.
- **i386** — rejected. Ubuntu has shipped no i386 kernel since 18.04.

## No initramfs

Not needed, and off by default. Ubuntu builds `EXT4_FS`, `VIRTIO_BLK`,
`VIRTIO_NET`, `VIRTIO_PCI`, `BLK_DEV_SD` and `ATA_PIIX` **in**, so qmu's existing
implicit drive lands on `/dev/sda` (x86_64) or `/dev/vda` (arm64) unaided. Only
`SATA_AHCI`, `E1000` and `E1000E` are modules. `--initramfs` generates one
anyway if you want it; failure to do so is non-fatal.

## Traps this tool exists to avoid

Each of these was observed live, and each makes a PoC pass or fail for the wrong
reason:

1. **`/.dockerenv` survives `docker export`.** It makes `systemd-detect-virt`
   report `docker`, whereupon AppArmor's own init logs "Not starting AppArmor in
   container" and loads **none** of its 101 profiles — while still exiting 0.
   Because Ubuntu 24.04's `unprivileged_userns` profile is what *grants*
   `userns create` to unconfined binaries, this flips unprivileged-userns
   availability. It cannot be removed inside the build (Docker bind-mounts it
   like `/etc/resolv.conf`), so it is stripped from the exported tarball.
2. **No `apparmor` package means no userns restriction.**
   `CONFIG_SECURITY_APPARMOR_RESTRICT_USERNS` is *not set* on 6.8.0-31; the
   `=1` comes entirely from `/usr/lib/sysctl.d/10-apparmor.conf`, shipped by the
   `apparmor` package, which `ubuntu:24.04` does not install. Likewise
   `kptr_restrict=1` comes from `procps`. The userland is part of the target.
3. **securityfs is not mounted without an initramfs.** systemd refuses to create
   mount units for API filesystems ("Cannot create mount unit for API file
   system /sys/kernel/security. Refusing.") and its fstab-generator skips `/sys`
   paths, so it takes a *service* unit. AppArmor still enforces without it, but
   `aa-status` and `/sys/kernel/security/lsm` report nothing — which reads as
   "no LSMs" and is exactly the wrong conclusion.
4. **The NIC is `ens3`, not `eth0`.** `udev` renames it despite `net.ifnames=0`.
   `mkrootfs.sh` hardcodes `eth0` and gets away with it only because its Debian
   image installs no `udev`. The setup script discovers the interface and prints
   what it found (`QMU-NET-READY iface=…`, `QMU-NET-LINKS …`) — the symptom of
   getting this wrong is an SSH timeout on a fully booted guest.
5. **No `/proc/config.gz`.** Ubuntu does not set `IKCONFIG`, so the emitted
   `$CONFIG` is the only way to read the target's config.

## Attribution

`target.json` (host, authoritative, includes `kernel_sha256`/`rootfs_sha256`) and
`/etc/qmu-target.json` (baked into the guest at build time) record suite, pocket,
arch, flavour, ABI, the kernel and dbgsym deb versions, archive release date,
hardening mode, and the unprivileged user. Quote the ABI and deb version when
reporting a result:

```bash
qmu exec --vm ubu 'cat /etc/qmu-target.json'
```

The kernel version alone does not attribute a *hardening* result. Whether an
unprivileged-userns PoC is blocked depends on the `apparmor` package — it ships
the only file that sets that sysctl — and `kptr_restrict` comes from `procps`,
so `target.json` also carries a `userland` object with those versions, and
`packages.tsv` beside it lists every installed package and version in the guest:

```bash
grep -E '^(apparmor|procps|systemd)\b' "$(dirname "$TARGET_MANIFEST")/packages.tsv"
```

## Verifying a fresh target

```bash
qmu exec --vm ubu 'uname -a; cat /proc/version_signature'
qmu exec --vm ubu 'cat /sys/kernel/security/lsm; aa-status | head -3'
qmu exec --vm ubu 'sysctl kernel.kptr_restrict kernel.dmesg_restrict \
    kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid \
    kernel.apparmor_restrict_unprivileged_userns'
# One modprobe per module: `modprobe a b c` treats b and c as PARAMETERS of a,
# so the single-command form verified nothing but nf_tables. Fails closed -- a
# missing module has to make the exec itself fail, or the check is decorative.
qmu exec --vm ubu 'for m in nf_tables ksmbd hfsplus n_gsm; do
    modprobe "$m" || { echo "MISSING $m" >&2; exit 1; }; echo "ok $m"
  done; lsmod | head'
qmu exec --vm ubu 'grep " _text$" /proc/kallsyms'   # differs across boots => KASLR live
qmu exec --vm ubu 'echo c > /proc/sysrq-trigger'; qmu crash --vm ubu
```

`echo c > /proc/sysrq-trigger` works despite Ubuntu's restricted `kernel.sysrq`
mask, because the write path bypasses it.
