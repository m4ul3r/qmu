---
name: qmu-linux-rootfs
description: Build Debian rootfs images for QEMU exploit development via Docker (x86_64, i386, arm64, arm32). Produces a raw ext4 image plus a generated SSH key; root SSH is key-only. Use when `qmu launch` needs a rootfs, or a cross-arch rootfs, that pairs with a kbuild kernel.
---

# qmu-linux-rootfs

`tools/mkrootfs.sh` builds a Debian rootfs (systemd + sshd + gcc, static IP
for QEMU user-net) as a raw ext4 image and prints eval-able `ROOTFS=`/`SSH_KEY=`
assignments. It pairs with a kernel you built (`qmu-linux-kbuild`). For a
result that must be a statement about Ubuntu itself, use `qmu-ubuntu-target`
(`tools/mktarget.sh`) instead: this image boots under qmu's `exploit-dev`
profile, which disables the LSM stack.

The script is not on `PATH`: from a qmu checkout it is `tools/mkrootfs.sh` (the
form used below); from this skill's directory, `../../tools/mkrootfs.sh`.

## Decision table

| Need | Run |
|---|---|
| A rootfs for an x86_64 kernel (default: bookworm, 2G) | `eval "$(tools/mkrootfs.sh)"` |
| Build + boot in one go | `eval "$(tools/kbuild.sh --version 6.6.75)"; eval "$(tools/mkrootfs.sh)"; qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY"` |
| arm64 / arm32 / i386 rootfs | `eval "$(tools/mkrootfs.sh --arch arm64)"` (also `arm32`, `i386`; needs binfmt, see Prerequisites) |
| Extra packages / bigger image | `tools/mkrootfs.sh --packages "gdb,strace" --size 4G` (gets its own cache directory) |
| Use a key you already have | `tools/mkrootfs.sh --ssh-key ~/.ssh/qmu_ed25519` (`PATH.pub` must exist and be readable) |
| Older/newer Debian | `tools/mkrootfs.sh --release bullseye` (`bullseye`, `bookworm`, `trixie`, `sid`) |
| Force a rebuild (e.g. a legacy image whose sshd accepts any key) | `tools/mkrootfs.sh --no-cache` |
| Put the image somewhere specific | `tools/mkrootfs.sh --outdir /data/rootfs/bookworm` |
| Inspect the in-guest setup (sshd policy, keys) without Docker | `tools/mkrootfs.sh --emit-guest-setup ./setup.sh` |
| Put files into the image offline (no boot) | `qmu rootfs inject "$ROOTFS" ./exploit:/root --partition 0` or `qmu launch --inject ./exploit:/root --partition 0` |
| Check whether a cached image is key-only | `qmu rootfs cat "$ROOTFS" /etc/qmu-rootfs.json --partition 0` (missing file ⇒ legacy, any key works) |

## Output contract

Stdout carries only `printf %q`-quoted assignments; every log line, note and
build-tool chatter goes to stderr, on a cache hit and on a full build alike, so
`eval "$(tools/mkrootfs.sh …)"` is safe.

```
ROOTFS=/home/user/.cache/qmu/rootfs/bookworm/x86_64/rootfs.img
SSH_KEY=/home/user/.cache/qmu/rootfs/bookworm/x86_64/id_ed25519
```

`SSH_KEY` is the private key that is authorized in the image (the generated
one, or the `--ssh-key` path). `--emit-guest-setup` prints nothing on stdout.

| Exit | Meaning | Next |
|---|---|---|
| `0` | image built or served from cache; assignments on stdout | `qmu launch --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" …` |
| `2` | usage: `--help`, unknown flag, unsupported `--arch`/`--release`, missing/unreadable `--ssh-key` or `PATH.pub`, missing `id_ed25519.pub` next to a cached private key, `docker` not on PATH, binfmt missing for a cross-arch build. Message is `mkrootfs: error: …` on stderr | fix the named input; the error names the file or the `docker run … binfmt` command |
| other non-zero | a build step failed under `set -e` (`docker build`, both `mke2fs` paths, `docker export`); the status is the failing tool's | rerun with `--verbose` and read stderr; `docker build` apt errors are usually mirror hiccups — retry |

A failed build never leaves a half-written `rootfs.img`: the image is built as
`rootfs.img.part` and renamed only after `mke2fs` succeeds.

## Guest SSH policy: key-only root

- sshd authorizes **only** the key in `SSH_KEY`: `/root/.ssh/authorized_keys`
  (0600) holds that one public key, and `/etc/ssh/sshd_config.d/60-qmu.conf`
  sets `PermitRootLogin prohibit-password`, `PubkeyAuthentication yes`,
  `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `PermitEmptyPasswords no` (sshd takes the first value it sees, and the
  drop-in is included from line 1). Root's password is locked (`passwd -l`).
  A wrong key gets `Permission denied (publickey)`, which is what makes a port
  mix-up between two VMs fail instead of silently running on the wrong guest.
- The serial console autologs in as root (a `serial-getty@.service.d/autologin.conf`
  drop-in, so it covers `ttyS0` and `ttyAMA0`; `udev` is installed so
  `dev-ttyS0.device` becomes active); the guest hostname is `qmu-rootfs`.
  qmu's serial is log-only, so nothing in a qmu workflow depends on console
  login. An image whose serial log shows `localhost login:` predates the
  export fix (it still carries `/.dockerenv`, so systemd's getty generator
  takes the container branch) — rebuild it.
- Provenance: `/etc/qmu-rootfs.json` inside the image
  (`{"schema": 1, "sshd_policy": "key-only", "root_password": "locked",
  "console": "serial-autologin-root", "hostname": "qmu-rootfs", "release",
  "arch", "ssh_pubkey_sha256"}`), and `sshd_policy=key-only` in
  `<outdir>/.mkrootfs-stamp` (the console-login revision is folded into the
  stamp's `build_key=` digest, not a separate line). Read it from the host
  with `qmu rootfs cat "$ROOTFS" /etc/qmu-rootfs.json --partition 0` or in
  the guest with `qmu exec 'cat /etc/qmu-rootfs.json'`.

**Images built before this policy accept root with ANY key** (they ran
`passwd -d root` + `PermitEmptyPasswords yes`) and have neither the JSON file
nor an `sshd_policy=` stamp line. The sshd policy and the console-login
revision are both part of the build key, and **where** the rerun lands depends
on the build's shape: a default-shaped build (no `--packages`/`--size`/
`--ssh-key`, or an explicit `--outdir`) always uses the same directory, so its
old stamp is found and the image is rebuilt in place at the same `ROOTFS`
path; a non-default build is routed to a directory keyed by the digest
(`rootfs/<release>/<arch>-<digest8>`), so a changed digest selects a **new**
outdir — the old keyed directory is never consulted, prints no note, and keeps
its old image. In both cases re-`eval` the script's output: a consumer pinned
to a previously captured `ROOTFS` path keeps booting the old image.

| Cached image | What a rerun does | Command |
|---|---|---|
| stamped, no `sshd_policy=` line, default shape or `--outdir` | prints `note: cached image at … predates the key-only sshd policy (its sshd accepted root with ANY key …); rebuilding so only the qmu key is authorized`, then rebuilds in place | rerun the same `tools/mkrootfs.sh …` invocation |
| stamped `sshd_policy=key-only` but built before the export fix (key-only, yet `localhost login:` on serial), default shape or `--outdir` | prints `note: … was built with different options than requested (requested: … sshd-policy=key-only)` and rebuilds in place | rerun the same invocation |
| either of the above, built with non-default options | silent fresh build into a new keyed outdir; `ROOTFS` changes | rerun the same invocation and re-`eval` its output |
| unstamped (legacy default build) | serves it with `note: … has no completion stamp, so its --packages/--size/--ssh-key are UNVERIFIED and its sshd most likely accepts root with ANY key …` | `tools/mkrootfs.sh --no-cache` (add `--arch`/`--release` as used) |
| stamped by the current script | cache hit, no note | nothing |

## Flags and environment

| Flag | Effect |
|---|---|
| `--arch ARCH` | `x86_64` (default), `i386`, `arm64`, `arm32` |
| `--release REL` | `bookworm` (default), `bullseye`, `trixie`, `sid` |
| `--ssh-key PATH` | authorize this ed25519 private key instead of generating one; needs readable `PATH.pub` |
| `--packages PKGS` | comma-separated extra apt packages (order-insensitive in the cache key) |
| `--size SIZE` | image size (default `2G`) |
| `--outdir DIR` | write `rootfs.img`, key and stamp here instead of the cache path |
| `--no-cache` | rebuild even if a matching cached image exists |
| `--verbose` | show `docker build` output |
| `--emit-guest-setup PATH` | write the in-guest setup script to PATH and exit 0; no Docker |
| `-h`, `--help` | usage on stderr, exit 2 |

`QMU_CACHE_DIR` overrides `~/.cache/qmu` (shared with kbuild/mktarget);
`QMU_ROOTFS_SIZE` sets the default size (`--size` wins, and a non-`2G` value
routes to a keyed cache directory like any other non-default option).

## What is in the image

Debian `<release>-slim` + `systemd-sysv udev openssh-server gcc libc6-dev make
iproute2 ethtool kmod` + `--packages`. `qmu-net.service` (oneshot, before
`ssh.service`) disables NIC offload on `eth0`, sets `10.0.2.15/24` with gateway
`10.0.2.10`, and prints `QMU-NET-READY …` on the console. `/etc/fstab` mounts
the arch's root device. Raw ext4, label `qmu-root`, no partition table — every
offline `qmu rootfs …`/`qmu launch --inject` call needs `--partition 0`.

| Arch | Docker platform | Root device | Boot it with |
|---|---|---|---|
| `x86_64` | `linux/amd64` | `/dev/sda` | default profile (`root=/dev/sda`) |
| `i386` | `linux/386` | `/dev/sda` | `qmu launch --arch i386 …` |
| `arm64` | `linux/arm64` | `/dev/vda` | `--arch aarch64 --cmdline "console=ttyAMA0 root=/dev/vda rw" -- -M virt -cpu cortex-a57` |
| `arm32` | `linux/arm/v7` | `/dev/vda` | virt + virtio-MMIO drive; recipe in `skill://qmu/reference/cross-arch.md` |

```bash
eval "$(tools/kbuild.sh --version 6.6.75 --arch arm64)"
eval "$(tools/mkrootfs.sh --arch arm64)"
qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch aarch64 --cmdline "console=ttyAMA0 root=/dev/vda rw" \
  -- -M virt -cpu cortex-a57
```

## Cache rules

Layout: `~/.cache/qmu/rootfs/<release>/<arch>/` for a build with exactly the
default options; `<release>/<arch>-<key8>/` for any build that differs
(`--packages`, `--size`, `--ssh-key`, a non-`2G` `QMU_ROOTFS_SIZE`). Each holds
`rootfs.img`, `id_ed25519`, `id_ed25519.pub` and `.mkrootfs-stamp`.

- The build key hashes `arch`, `release`, `size`, the sorted package list, the
  `--ssh-key` public half (if given), `sshd_policy` and the console-login
  revision (`console_login=…`, bumped when the script's console setup changes). A hit needs
  `rootfs.img` **and** a stamp whose `build_key=` equals this run's. A
  generated key's public half is also re-checked against the stamp's
  `ssh_pubkey_sha256=`; replacing `id_ed25519*` in a cache directory rebuilds
  instead of handing back an image the new key cannot log into.
- A stamped mismatch is never served silently: stderr names the requested
  options (`requested: size=… packages=… ssh-key=… sshd-policy=key-only`) or
  the pre-policy/publish-in-progress reason, then the run rebuilds and replaces
  the image.
- Only a default-shape run may serve an **unstamped** directory, and it says
  so (UNVERIFIED note above). Non-default runs never see one.
- Publish is atomic: stamp poisoned with `build_key=publishing-<pid>`, image
  renamed into place, real stamp written. A `publishing-` stamp means a build
  died mid-publish; the next run rebuilds.
- Private key present but `id_ed25519.pub` missing ⇒ exit 2 with the repair
  command (`ssh-keygen -y -f DIR/id_ed25519 > DIR/id_ed25519.pub`).

Wire the key into a project config instead of passing `--ssh-key` every time:

```toml
[drive]
rootfs = "/home/user/.cache/qmu/rootfs/bookworm/x86_64/rootfs.img"
[ssh]
key = "/home/user/.cache/qmu/rootfs/bookworm/x86_64/id_ed25519"
```

## Prerequisites

- **Docker** (the build and the `mke2fs` helper both run in containers; if the
  helper fails the script falls back to `sudo mke2fs -d`).
- **binfmt_misc** for any arch the host cannot run natively (`arm32` always;
  `arm64` on x86 hosts): `docker run --rm --privileged tonistiigi/binfmt:latest --install all`
  once per host boot. Missing ⇒ exit 2 naming that command.
- **libguestfs with a readable appliance kernel** only for offline edits
  (`qmu rootfs inject|ls|cat|rm`, `qmu launch --inject`). Debian/Ubuntu ship
  `/boot/vmlinuz-*` as `0600`, which fails with "appliance closed the
  connection unexpectedly"; `qmu doctor` reports it. Fix: `sudo chmod 0644
  /boot/vmlinuz-*`, or point supermin at a copy:
  `sudo install -m 0644 /boot/vmlinuz-$(uname -r) /var/tmp/vmlinuz && export
  SUPERMIN_KERNEL=/var/tmp/vmlinuz SUPERMIN_KERNEL_VERSION=$(uname -r)
  SUPERMIN_MODULES=/lib/modules/$(uname -r)`. Building the image needs none
  of this.

## Recovery

| Symptom | Cause | Fix |
|---|---|---|
| `qmu exec` → `Permission denied (publickey)` / launch `ssh_status` not `ready` | key passed to qmu is not the one baked into this image | use the `SSH_KEY` printed with this `ROOTFS`; `qmu rootfs cat "$ROOTFS" /etc/qmu-rootfs.json --partition 0` shows `ssh_pubkey_sha256` to compare with `sha256sum "$SSH_KEY.pub"` |
| a foreign key logs in as root | legacy image (no `/etc/qmu-rootfs.json`) | `tools/mkrootfs.sh --no-cache` (same `--arch`/`--release`) |
| `mkrootfs: error: cannot run linux/arm64 containers` (exit 2) | binfmt not registered | `docker run --rm --privileged tonistiigi/binfmt:latest --install all` |
| `mkrootfs: error: SSH public key missing: …/id_ed25519.pub` (exit 2) | `.pub` deleted beside a cached private key | `ssh-keygen -y -f DIR/id_ed25519 > DIR/id_ed25519.pub` |
| `note: … was built with different options than requested` then a rebuild | stamp exists but options differ (e.g. a `--outdir` reused across option sets) | expected; use a separate `--outdir` per variant or let it rebuild |
| `Kernel panic … VFS: Unable to mount root fs` | wrong `root=` for the arch | x86: `root=/dev/sda`; arm64/arm32 virtio: `root=/dev/vda` in `--cmdline` |
| SSH never ready but `QMU-NET-READY` absent from `qmu log` | guest networking did not come up (wrong kernel NIC config or `--no-net`) | kernel needs `E1000`/`VIRTIO_NET` built in (kbuild does this); don't pair `--no-net` with SSH use |
| apt `No space left on device` in the build / packages missing | image too small | `tools/mkrootfs.sh --size 4G --packages …` |
| `qmu rootfs inject` → "appliance closed the connection unexpectedly" | libguestfs cannot read `/boot/vmlinuz-*` | see Prerequisites; `qmu doctor` |
| `qmu rootfs …` → image/partition errors on a mkrootfs image | default `--partition 1` on a partitionless image | add `--partition 0` |
