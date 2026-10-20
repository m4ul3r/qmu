---
name: qmu-ubuntu-target
description: Build genuine Ubuntu targets (distro kernel at a pinned ABI + matching userland + optional ddebs symbols) and boot them under qmu to validate real kernel PoCs/exploits. Use when a result must be a statement about Ubuntu itself — CVE/n-day reproduction, exploit validation against a pinned kernel ABI, or checking whether a PoC survives Ubuntu's hardening — rather than about a self-built kernel. Covers ABI pinning, symbols, the fidelity-vs-debug profile contract, attribution, and the traps that make a PoC pass for the wrong reason.
---

# qmu-ubuntu-target

`tools/mktarget.sh` builds an **Ubuntu target**: Ubuntu's own `-generic`
kernel at a pinned ABI, its version-matched modules, its real userland and
hardening defaults, `.config` and `System.map`, optionally `vmlinux` from
ddebs — as one attributable set with a generated `qmu.toml`. Use it when the
answer has to be about Ubuntu. Use `qmu-linux-kbuild` + `qmu-linux-rootfs`
when you need to control the kernel source/config (KASAN, syzkaller repros).

The script is not on `PATH`: from a qmu checkout it is `tools/mktarget.sh`
(the form used below); from this skill's directory, `../../tools/mktarget.sh`.

| | `kbuild.sh` + `mkrootfs.sh` | `mktarget.sh` |
|---|---|---|
| kernel | kernel.org, your config | Ubuntu `-generic`, Ubuntu's config |
| KASAN | yes | no (Ubuntu ships none) |
| LSMs | disabled by the `exploit-dev` profile | AppArmor + landlock + lockdown + yama, enforcing |
| answers | "is this a bug?" | "does this work on Ubuntu?" |

## Decision table

| Need | Run |
|---|---|
| See which ABIs can be pinned, and which have symbols | `tools/mktarget.sh --list-abis` (table on **stderr**; `2>&1` to capture) |
| Default target: noble (24.04), x86_64, release-pocket ABI | `eval "$(tools/mktarget.sh)"` |
| Boot it with the right profile | `qmu launch --config "$QMU_TOML" --kernel "$KERNEL" --profile "$PROFILE" --name ubu --no-replace` |
| Exact ABI / exact deb version | `--kernel-abi 6.8.0-71` / `--kernel-version 6.8.0-53.55` (wins over `--kernel-abi`) |
| Newest kernel in `-updates` | `--kernel-abi latest`; newest that also has symbols: `--kernel-abi latest-with-symbols` |
| GDB against the target | `eval "$(tools/mktarget.sh --kernel-abi latest-with-symbols --symbols)"` → `VMLINUX` emitted |
| Add symbols to a target already built | rerun the same command with `--symbols`; only symbols are fetched, the rootfs is untouched |
| Another suite / HWE kernel | `--suite noble --kernel-abi 7.0.0-14` (noble carries 6.8/6.11/6.14/6.17/7.0); `--suite resolute --no-modules-extra` for 26.04 (no pocket of resolute ships `linux-modules-extra`; the script does not auto-skip it) |
| arm64 target | `--arch arm64` (needs binfmt; ~15 min first time) |
| Measure as root vs. unprivileged | the image has user `ubuntu` (uid 1000); `--unpriv-user NAME` renames it |
| Triage with one clean crash report | `--profile ubuntu-trigger` at launch (`panic_on_oops=1 panic_on_warn=1`) |
| Stable addresses while reversing | `--profile ubuntu-debug` at launch (`nokaslr`) — not a fidelity result |
| Turn the hardening sysctls off (separate image, full build) | `--relax-hardening` — never to "make a PoC work" |
| What exactly am I running? | `qmu exec --vm ubu 'cat /etc/qmu-target.json'`; host side: `cat "$TARGET_MANIFEST"` |
| Put a PoC into the image offline | `qmu rootfs inject "$ROOTFS" ./poc:/root --partition 0` (libguestfs; see Prerequisites) |

`--profile "$PROFILE"` (= `ubuntu-target`) is **not optional**: `qmu launch`
defaults to `exploit-dev`, whose cmdline carries `selinux=0 apparmor=0` and
would silently delete the LSM stack you are measuring. The generated
`qmu.toml` has no `[boot]` table, so `--kernel "$KERNEL"` is also required.

## Output contract

Stdout carries only `printf %q`-quoted assignments; logs go to stderr.

```
KERNEL  ROOTFS  SSH_KEY  CONFIG  SYSTEM_MAP  KERNEL_ABI  KERNEL_RELEASE
KERNEL_DEB_VERSION  PROFILE  QMU_TOML  TARGET_MANIFEST
VMLINUX   only with --symbols on THIS run (and a dbgsym existed)
INITRD    only with --initramfs on THIS run (and one was produced)
```

`VMLINUX`/`INITRD` are gated on the flag, not on the file: a file left by an
earlier run is not emitted, so `[[ -n "$VMLINUX" ]]` answers "did I get
symbols this run". `--list-abis` prints nothing on stdout.

| Exit | Meaning | Next |
|---|---|---|
| `0` | target built, refreshed, or served from cache | `qmu launch --config "$QMU_TOML" --kernel "$KERNEL" --profile "$PROFILE" …` |
| `2` | usage or resolution refusal, `mktarget: error: …` on stderr: unknown flag, unsupported `--arch`/`--flavour`/`--symbols` mode, `i386`/`arm32` (not supported — message names the kbuild+mkrootfs alternative), ABI not found (names the `--list-abis` command), archive index fetch fault (not an empty pocket — retry), `--symbols` on an ABI with no dbgsym (lists the ABIs that have one, **before** building), symbol extraction failed, `curl`/`docker` missing, SSH key problems | fix the named input; for symbols pick an ABI from the list or `--kernel-abi latest-with-symbols` |
| other non-zero | a build step failed under `set -e` (`docker build` of the image, `mke2fs` both paths); status is the tool's. Inside the Dockerfile, an `--unpriv-user` that already exists at another uid (e.g. `nobody`) fails the build with an explanation | rerun with `--verbose`; pick a user name that does not exist |

## Flags and environment

| Flag | Effect |
|---|---|
| `--suite SUITE` | Ubuntu suite (default `noble`); not validated locally — an unknown suite fails at index fetch |
| `--arch ARCH` | `x86_64` (default) or `arm64`; `i386` and `arm32`/`armhf` are refused with the reason |
| `--flavour F` | `generic` (default), `lowlatency`, `generic-64k` |
| `--kernel-abi SPEC` | `ga` (default: release pocket), `latest`, `latest-with-symbols`, or an exact ABI like `6.8.0-31` |
| `--kernel-version VER` | exact deb version (`6.8.0-31.31`); overrides `--kernel-abi` |
| `--list-abis` | print the ABI / deb version / pocket / DBGSYM table to stderr and exit 0 |
| `--symbols[=MODE]` | fetch ddebs symbols: `vmlinux` (default; one file stream-extracted from the ~1.9 GB ddeb) or `full` (also `usr/lib/debug/lib/modules/<rel>/`) |
| `--no-modules-extra` | skip `linux-modules-extra` (default installs it) |
| `--modules-extra` | install `linux-modules-extra` (the default); undoes an earlier `--no-modules-extra` — last one wins |
| `--headers` | install `linux-headers-<rel>` |
| `--initramfs` | generate an initrd and emit `INITRD=`; not needed — the boot drivers are built in |
| `--relax-hardening` | separate `-relaxed` image with the hardening sysctls off (see below) |
| `--unpriv-user NAME` | rename the uid-1000 account (default `ubuntu`) |
| `--size SIZE` | image size (default `4G`) |
| `--packages PKGS` | comma-separated extra apt packages |
| `--ssh-key PATH` | existing ed25519 key (needs `PATH.pub`) instead of a generated one |
| `--outdir DIR` | override the cache directory |
| `--no-cache` | rebuild even if the cached target is complete |
| `--verbose` | show Docker build output |

`QMU_CACHE_DIR` (default `~/.cache/qmu`, shared with kbuild/mkrootfs),
`QMU_TARGET_SIZE` (default size; `--size` wins), `QMU_DDEBS_MIRROR` (default
`http://ddebs.ubuntu.com`).

## Pinning an ABI — what makes a result citable

The floating `linux-image-generic` meta-package is never installed: it moves
with `-updates`, so the same command would yield a different kernel on a
different day. `ga` is the default because the release pocket is never pruned
and its ABI is the one most likely to keep its symbols.

- **ddebs prunes hard and symbol availability is uncorrelated with recency.**
  `--list-abis` has a `DBGSYM` column; `--symbols` on an ABI without one exits
  2 before building and lists the ABIs that have symbols.
- **The deb version is not the ABI doubled** (`6.8.0-31.31` but
  `6.8.0-53.55`; `6.17.0-42` ships as `.42` and `.42+1`). Never hand-build
  pool URLs; the script resolves through the archive index and records the
  exact version in `KERNEL_DEB_VERSION` and `target.json`.
- If any pocket index cannot be fetched the script exits 2 instead of
  resolving from the pockets that answered (a timed-out `-updates` would turn
  `latest` into `ga`).

## Cache

`~/.cache/qmu/targets/ubuntu/<suite>/<arch>/<abi>-<flavour>[-relaxed][-<key8>]/`
with `vmlinuz-<rel>`, `rootfs.img`, `id_ed25519[.pub]`, `config-<rel>`,
`System.map-<rel>`, `qmu.toml`, `target.json`, `packages.tsv`,
`.mktarget-stamp`, and with `--symbols` `vmlinux-<rel>`. The `<key8>` suffix
appears only when a build-affecting option differs from the defaults
(`--headers`, `--packages`, `--size`, `--unpriv-user`, `--initramfs`,
`--no-modules-extra`, `--ssh-key`), so a default build keeps the short name.

- A hit needs a stamp whose build key matches this run **and** whose recorded
  artifact sizes still match; an interrupted build or a changed resolved deb
  version rebuilds instead of returning an image that disagrees with stdout.
- `--symbols` is not in the build key: adding it to a cached target fetches
  only the symbols (`image is cached and intact; refetching symbols, leaving
  the rootfs as built`) — only the kernel debs are version-pinned, so a
  rebuild could pull a different `apparmor` or `procps`.
- A hit costs ~1–8 s and is not offline: the ABI is resolved against the
  archive first, because for `ga`/`latest` the resolved ABI names the
  directory. A fresh x86_64 target is a few minutes; arm64 runs `apt` under
  `qemu-user` (~15 min first time). `Creating raw ext4 image` is silent for
  1–2 minutes — not a hang.
- `--relax-hardening` is a separate image and a separate build.

## Attribution

`target.json` (`TARGET_MANIFEST`, host side, authoritative) records `suite`,
`pocket`, `arch`, `flavour`, `abi`, `kernel_release`, `kernel_deb_version`,
`kernel_image_package`, `archive_release_date`, `dbgsym_version`,
`dwarf_comp_dir`, `hardening` (`fidelity`|`relaxed`), `modules_extra`,
`headers`, `initramfs`, `unpriv_user`, `root_dev`, `console`,
`kernel_sha256`, `rootfs_sha256`, `build_key`, and `userland`
(`apparmor`, `procps`, `systemd`, `libc6`, `gcc`, `openssh-server` versions).
`/etc/qmu-target.json` in the guest is the subset without hashes/time.
`packages.tsv` beside the manifest lists every installed package and version.

Quote `abi` + `kernel_deb_version` + `hardening` + the `apparmor`/`procps`
versions when reporting: the kernel alone does not attribute a hardening
result (the userns sysctl comes from the `apparmor` package, `kptr_restrict`
from `procps`).

```bash
qmu exec --vm ubu 'cat /etc/qmu-target.json'
grep -E '^(apparmor|procps|systemd)\b' "$(dirname "$TARGET_MANIFEST")/packages.tsv"
```

## The three profiles

Generated into `QMU_TOML` as `[profiles.*]` with the arch-correct console and
root device (`console=ttyS0 root=/dev/sda` on x86_64, `ttyAMA0`/`/dev/vda` on
arm64), plus `earlyprintk=serial net.ifnames=0`.

| profile | KASLR | LSMs | a result here means |
|---|---|---|---|
| `ubuntu-target` | on | on | **the only profile under which "this PoC works on Ubuntu" is a valid claim** |
| `ubuntu-debug` | off (`nokaslr`) | on | reversing/GDB only; KASLR bypass is a separate proof obligation |
| `ubuntu-trigger` | on | on | `panic_on_oops=1 panic_on_warn=1`: one clean `qmu crash` report; triage, not exploitation |

None carries `selinux=0 apparmor=0` or `kasan.fault=panic`.

## Hardening: fidelity by default

In-guest values on noble GA:

```
kernel.kptr_restrict = 1                         (procps)
kernel.dmesg_restrict = 1                        (CONFIG_SECURITY_DMESG_RESTRICT=y)
kernel.perf_event_paranoid = 4                   (CONFIG_SECURITY_PERF_EVENTS_RESTRICT=y)
kernel.unprivileged_bpf_disabled = 2             (CONFIG_BPF_UNPRIV_DEFAULT_OFF=y)
kernel.apparmor_restrict_unprivileged_userns = 1 (apparmor package)
vm.unprivileged_userfaultfd = 0                  (upstream default)
kernel.unprivileged_userns_clone = 1             (a DECOY — see below)
/sys/kernel/security/lsm -> lockdown,capability,landlock,yama,apparmor
101 AppArmor profiles loaded, 7 in enforce mode
```

### Check the userns restriction the right way

`unshare(CLONE_NEWUSER)` **succeeds** on a fidelity target. AppArmor lets the
namespace be created, moves the task into the `unprivileged_userns` profile,
then denies `CAP_SYS_ADMIN`, so the `EPERM` lands on the **`uid_map` write**
(and on the next `unshare(CLONE_NEWNET)`), not on `unshare()`:

```
[1] unshare(CLONE_NEWUSER)          OK          <-- checking only this misleads
[2] write "0 1000 1" > uid_map      EPERM       <-- the actual denial
    euid after mapping              65534       (never becomes 0)
[3] unshare(CLONE_NEWNET)           EPERM
```

Audit log: `apparmor="AUDIT" operation="userns_create" … target="unprivileged_userns"`
then `apparmor="DENIED" operation="capable" profile="unprivileged_userns" capname="sys_admin"`.

Test the `uid_map` write, or use `unshare -U -r` (it reports `write failed
/proc/self/uid_map`). Two more decoys: `kernel.unprivileged_userns_clone`
reads `1` and does **not** reflect the AppArmor restriction
(`kernel.apparmor_restrict_unprivileged_userns` is the one that matters); and
`getuid()` after `unshare(CLONE_NEWUSER)` returns `65534`, so a probe that
builds the map string afterwards gets `EPERM` even as root — build it before
unsharing.

### `--relax-hardening`

Writes `/etc/sysctl.d/99-qmu-relax.conf` turning those sysctls off, sets
`kernel.yama.ptrace_scope = 0` and `vm.unprivileged_userfaultfd = 1`, and
records it four ways: `hardening: "relaxed"` in `/etc/qmu-target.json` and
`target.json`, an `/etc/motd` banner, `QMU-TARGET-RELAXED` on the serial
console, hostname `qmu-ubuntu-relaxed`, and a `-relaxed` cache directory.
`vm.unprivileged_userfaultfd = 0` on the fidelity image is the upstream
default and blocks `userfaultfd()` for root too — a PoC that needs uffd has a
second, separate gate. "Works on the relaxed image" means "works once the
AppArmor userns restriction is also defeated" — a separate proof obligation.

## Running a PoC as an unprivileged user

An LPE result measured as root is meaningless. The uid-1000 account is
`ubuntu` (or `--unpriv-user NAME`, which renames it; a name that already
exists at another uid — including `nobody`, 65534 — fails the build). Keep
`[ssh] user = "root"` (`kbase` needs it) and drop privileges per command with
`--user`: qmu runs `runuser -u ubuntu -- …` in `ubuntu`'s home, forwards the
program's exit status, and records `run_as: "ubuntu"` with `command` as given:

```bash
qmu compile ./poc.c --vm ubu --run --user ubuntu   # builds into /tmp (/root is 0700), runs as ubuntu
qmu exec --vm ubu --user ubuntu -- /tmp/poc arg1   # rerun without rebuilding
```

## Debug symbols and GDB

```bash
eval "$(tools/mktarget.sh --kernel-abi latest-with-symbols --symbols)"
qmu launch --config "$QMU_TOML" --kernel "$KERNEL" --profile ubuntu-target --gdb --name ubu --no-replace
qmu gdb --vm ubu --symbols "$VMLINUX"     # loads at ELF link-time addresses; halts the vCPU
qmu cont --vm ubu
eval "$(qmu kbase --vm ubu --symbols "$VMLINUX")"
pry load "$VMLINUX" --base "$KBASE"
```

- KASLR is on under `ubuntu-target`, so `qmu kbase` is the rebase path. It
  works under `kptr_restrict=1` because `[ssh] user` is `root` (`/proc/kallsyms`
  gates on `CAP_SYSLOG`); it fails with a non-root SSH user or
  `kptr_restrict=2`. For a stable base while reversing use `--profile ubuntu-debug`.
- Source-level debugging needs `set substitute-path`: the DWARF comp-dir is
  Ubuntu's builder path (`dwarf_comp_dir` in `target.json`); the source is
  `apt source linux` / `linux-source-*`, which this tool does not fetch.
  `lx-*` scripts also need `scripts/gdb/` from that tree (not in the ddeb).
- Without a dbgsym, `qmu kbase` is impossible: `System.map-<rel>` has
  link-time addresses only.

## Modules, arch, initramfs

- `linux-modules-extra` is installed by default (110 MB): `ksmbd`, `hfsplus`,
  `n_gsm` live only there; `nf_tables` is in base `linux-modules`. Without it a
  PoC relying on autoload "just doesn't trigger". `--no-modules-extra` for the
  smaller image.
- `x86_64`: `/boot/vmlinuz` is a bzImage, boots directly. `arm64`: Ubuntu's
  `/boot/vmlinuz` is plain gzip; the script decompresses it to a raw `Image`
  by magic; the generated `qmu.toml` carries `extra_args = ["-M", "virt",
  "-cpu", "cortex-a57"]`. Cross-builds need
  `docker run --rm --privileged tonistiigi/binfmt:latest --install all`.
- No initramfs by default: `EXT4_FS`, `VIRTIO_BLK`, `VIRTIO_NET`,
  `VIRTIO_PCI`, `BLK_DEV_SD`, `ATA_PIIX` are built in, so the implicit drive
  lands on `/dev/sda` (x86_64) / `/dev/vda` (arm64). `--initramfs` generates
  one anyway; failure to produce it is non-fatal (no `INITRD=`).

## Traps this tool exists to avoid

1. **`/.dockerenv` survives `docker export`.** It makes `systemd-detect-virt`
   say `docker`, AppArmor's init then loads **none** of its profiles while
   exiting 0 — flipping unprivileged-userns availability. It cannot be removed
   inside the build (bind-mounted), so it is stripped from the exported
   tarball before `mke2fs`.
2. **No `apparmor` package ⇒ no userns restriction.**
   `CONFIG_SECURITY_APPARMOR_RESTRICT_USERNS` is not set on 6.8.0-31; the `=1`
   comes from `/usr/lib/sysctl.d/10-apparmor.conf`, which `ubuntu:24.04` does
   not install. `kptr_restrict=1` comes from `procps`. The userland is part of
   the target.
3. **securityfs is not mounted without an initramfs.** systemd refuses a mount
   unit for `/sys/kernel/security`, so the target mounts it from a service.
   Without it `aa-status` and `/sys/kernel/security/lsm` report nothing —
   which reads as "no LSMs" and is wrong.
4. **The NIC is `ens3`, not `eth0`** (udev renames it despite
   `net.ifnames=0`). The setup script discovers the interface and prints
   `QMU-NET-READY iface=…` and `QMU-NET-LINKS …` to the console; the symptom of
   getting this wrong is an SSH timeout on a fully booted guest.
5. **No `/proc/config.gz`.** Ubuntu does not set `IKCONFIG`; `$CONFIG` is the
   only way to read the target's config.

## Prerequisites

Docker and `curl` (both are checked; missing ⇒ exit 2). binfmt for arm64 on
an x86 host. libguestfs with a readable appliance kernel **only** for offline
edits (`qmu rootfs inject|ls|cat|rm`, `qmu launch --inject`): Ubuntu hosts
ship `/boot/vmlinuz-*` as `0600`, so the appliance fails with "appliance closed
the connection unexpectedly"; `qmu doctor` reports it; fix with `sudo chmod
0644 /boot/vmlinuz-*` or `SUPERMIN_KERNEL=/var/tmp/vmlinuz` pointing at a
readable copy. The image is a whole-disk ext4 (label `qmu-ubuntu`), so every
offline command needs `--partition 0`. `qmu push`/`compile` over SSH need
none of this.

## Verifying a fresh target

```bash
qmu exec --vm ubu 'uname -a; cat /proc/version_signature'
qmu exec --vm ubu 'cat /sys/kernel/security/lsm; aa-status | head -3'
qmu exec --vm ubu 'sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.perf_event_paranoid kernel.apparmor_restrict_unprivileged_userns'
# one modprobe per module: `modprobe a b c` treats b and c as PARAMETERS of a
qmu exec --vm ubu 'for m in nf_tables ksmbd hfsplus n_gsm; do modprobe "$m" || { echo "MISSING $m" >&2; exit 1; }; echo "ok $m"; done'
qmu exec --vm ubu 'grep " _text$" /proc/kallsyms'   # differs across boots => KASLR live
qmu exec --vm ubu 'echo c > /proc/sysrq-trigger'   # exit 3 (crash report attached)
qmu crash --vm ubu                                 # exit 0 + report (exit 1 = none found)
```

`echo c > /proc/sysrq-trigger` works despite the restricted `kernel.sysrq`
mask (the write path bypasses it).

## Recovery

| Symptom | Cause | Fix |
|---|---|---|
| `aa-status` empty, `lsm` shows no apparmor | booted with `exploit-dev` (`apparmor=0`) | relaunch with `--profile "$PROFILE"`; confirm with `qmu status --vm ubu` cmdline |
| `mktarget: error: --symbols requested but no dbgsym exists for ABI …` (exit 2) | ddebs pruned that ABI | pick one from the printed list or `--kernel-abi latest-with-symbols` |
| `mktarget: error: ABI '…' not found` (exit 2) | typo or ABI not in any pocket for this suite/arch | `tools/mktarget.sh --suite <s> --arch <a> --list-abis 2>&1` |
| `mktarget: error: could not read the archive index` (exit 2) | mirror/network fault | retry; `QMU_DDEBS_MIRROR` only affects ddebs |
| `mktarget: error: debug-symbol extraction failed …` (exit 2) | ddebs infra fault; target unchanged | retry with `--verbose`, or drop `--symbols` |
| SSH timeout on a guest that booted | NIC naming or `[ssh] key` mismatch | `qmu log --vm ubu --grep 'QMU-NET'`; use `--config "$QMU_TOML"` so the key matches |
| unprivileged PoC "does nothing" | module only in `-extra`, or userns denial on `uid_map` | per-module `modprobe` check above; `unshare -U -r` |
| `unshare -U -r` succeeds for your probe | you ran it as root | `qmu exec --vm ubu --user ubuntu -- unshare -U -r id` |
| `qmu kbase` fails | non-root SSH user, `kptr_restrict=2`, or no `VMLINUX` | keep `[ssh] user = "root"`; `--symbols` on an ABI with dbgsym |
| rebuild happens though nothing changed | resolved deb version moved (`latest`), or options differ from the stamp | pin with `--kernel-abi <abi>` / `--kernel-version` |
| Docker build fails naming `--unpriv-user` | name exists at another uid | choose an unused name |
| `qmu rootfs inject` appliance error | libguestfs cannot read `/boot/vmlinuz-*` | see Prerequisites; `qmu doctor` |
