---
name: qmu-linux-rootfs
description: Build Debian rootfs images for QEMU exploit development via Docker buildx. Multi-arch (x86_64, i386, arm64, arm32), auto-generates SSH keys, produces raw ext4 images ready for qmu launch.
---

# qmu-linux-rootfs

Use this skill when the user needs a rootfs image for `qmu launch` and does not have one, needs a cross-architecture rootfs, or is setting up a fresh exploit-dev project. The script builds a Debian-based rootfs via Docker with systemd + SSH + networking pre-configured for qmu.

> **Testing a PoC against a real distro instead?** Use `qmu-ubuntu-target`
> (`tools/mktarget.sh`), which builds Ubuntu's own kernel at a pinned ABI plus a
> matching Ubuntu userland with its real hardening — AppArmor enforcing, KASLR on,
> distro sysctl defaults. This skill's Debian rootfs pairs with a kernel *you*
> built (`qmu-linux-kbuild`) and its default profile disables the LSM stack, so
> results from it are statements about your kernel, not about a distro.

The script ships in the qmu project's `tools/` directory. It is not on `PATH`; resolve it relative to the install location — from this skill's directory that is `../../tools/mkrootfs.sh`, or from a checkout of the qmu repo just `tools/mkrootfs.sh` (the form used in the examples below).

## Quick reference

```bash
# Build default x86_64 rootfs
tools/mkrootfs.sh

# Build and wire up with qmu
eval $(tools/mkrootfs.sh)
qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY"

# Cross-arch rootfs for arm64
tools/mkrootfs.sh --arch arm64

# Use an older Debian release
tools/mkrootfs.sh --release bullseye

# Add extra packages
tools/mkrootfs.sh --packages "gdb,strace,ltrace"

# Use an existing SSH key
tools/mkrootfs.sh --ssh-key ~/.ssh/qmu_id_rsa

# Force rebuild
tools/mkrootfs.sh --no-cache
```

## Output format

The script prints eval-able shell variables to stdout (all logs go to stderr):

```
ROOTFS=/home/user/.cache/qmu/rootfs/bookworm/x86_64/rootfs.img
SSH_KEY=/home/user/.cache/qmu/rootfs/bookworm/x86_64/id_ed25519
```

Stdout carries nothing but those assignments, on a cache hit and on a full
build alike: every log line, every note, and every build command's own output
(`docker build -q`'s image id, mke2fs's `Creating regular file …`) goes to
stderr. The paths are shell-quoted with `printf %q`, matching
`tools/kbuild.sh`, so an `--outdir` containing a space still survives the
`eval`.

## What's in the rootfs

A qmu-ready Debian base with everything needed for `qmu exec`, `qmu push`, and `qmu compile`:

- **Init:** systemd (boots to multi-user target)
- **SSH:** openssh-server, root login enabled, ed25519 key-based auth
- **Build tools:** gcc, libc6-dev, make (for `qmu compile`)
- **Networking:** iproute2, ethtool, kmod
- **qmu-net.service:** systemd oneshot that configures static IP 10.0.2.15/24 for QEMU user-net, disables NIC offload (e1000+slirp workaround), and prints "QMU-NET-READY" to serial console
- **Extra packages:** anything passed via `--packages`

Image is raw ext4, 2G by default (configurable with `--size`).

## Architecture details

| Arch | Docker platform | Root device | QEMU machine type |
|---|---|---|---|
| `x86_64` | `linux/amd64` | `/dev/sda` | default (PC/q35) |
| `i386` | `linux/386` | `/dev/sda` | default (PC) |
| `arm64` | `linux/arm64` | `/dev/vda` | virt (`-M virt -cpu cortex-a57`) |
| `arm32` | `linux/arm/v7` | `/dev/vda` | virt (`-M virt -cpu cortex-a15`) |

The fstab inside the rootfs is automatically set to the correct root device for the target arch.

Cross-arch builds require binfmt_misc QEMU user-mode emulators registered on the host. If missing, the script tells you how to register them.

## SSH key handling

- **Default (no `--ssh-key`):** Auto-generates an ed25519 keypair into the output directory alongside rootfs.img. Reused on subsequent cached runs — but the generated key's public half is recorded in the completion stamp and re-checked on every hit, so *replacing* `id_ed25519`/`id_ed25519.pub` in a cache directory busts the hit and rebuilds the image rather than handing back one the new key cannot log into. If the private half is present and the `.pub` is missing or unreadable, the run stops with an error naming that file (restore it with `ssh-keygen -y -f DIR/id_ed25519 > DIR/id_ed25519.pub`) instead of claiming the key changed.
- **With `--ssh-key PATH`:** Uses the provided private key; expects a readable `PATH.pub` alongside it.

Wire the key into qmu.toml:
```toml
[ssh]
key = "/home/user/.cache/qmu/rootfs/bookworm/x86_64/id_ed25519"
```

Or use CLI: `qmu launch --ssh-key "$SSH_KEY" ...`

## Full workflow (kernel + rootfs + qmu)

```bash
# 1. Build a kernel
eval $(tools/kbuild.sh --version 6.6.75)

# 2. Build a rootfs
eval $(tools/mkrootfs.sh)

# 3. Launch
qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY"

# 4. Use
qmu exec "uname -r"
qmu compile exploit.c --run
```

For arm64 (extra QEMU args go after `--`; there is no `--extra-args` flag, and the ARM
console/root cmdline must be set since the default profile is x86-only):
```bash
eval $(tools/kbuild.sh --version 6.6.75 --arch arm64)
eval $(tools/mkrootfs.sh --arch arm64)
qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch aarch64 --cmdline "console=ttyAMA0 root=/dev/vda rw" \
  -- -M virt -cpu cortex-a57
```

See the qmu skill's **Cross-arch quickstarts (aarch64 / arm32)** section for the complete
recipe, including the arm32 virtio-MMIO drive form and pry rebasing.

## Cache layout

```
~/.cache/qmu/rootfs/
  bookworm/
    x86_64/                       # default-argument builds (legacy path)
      rootfs.img        # raw ext4 image
      id_ed25519        # SSH private key (auto-generated)
      id_ed25519.pub    # SSH public key
      .mkrootfs-stamp   # records the build key + options
    x86_64-<key8>/                # builds that differ from the defaults
      rootfs.img                  # (--packages / --size / --ssh-key each
      id_ed25519                  #  select a variant keyed by those options)
      id_ed25519.pub
      .mkrootfs-stamp
    arm64/
      rootfs.img
      id_ed25519
      id_ed25519.pub
  bullseye/
    ...
```

A stamped cache hit requires an image plus a completion stamp whose recorded
build key matches the requested options. Default-argument runs may still serve
an *unstamped* directory — without any stamp check — but print a note that the
image's `--packages` / `--size` / `--ssh-key` are UNVERIFIED, naming the
possibilities rather than asserting one (a directory written before stamps
existed, or one whose stamp was removed) — pass `--no-cache` to force a
rebuild. An image built with different options is never silently returned:
non-default requests get their own keyed variant, and a stamped hit whose
recorded key differs names the mismatched options (image path rendered
shell-quoted) before rebuilding with the requested ones.

Partial builds can never be served as hits: the image is created under
`rootfs.img.part` and renamed into place only after mke2fs succeeds (the same
atomicity rule as the stamp), so an interrupted run leaves nothing at the
final path. Package lists are order-insensitive in the build key (`strace,htop`
and `htop,strace` share one cache entry), matching mktarget's normalization.

The image and its stamp are published as a *window*, not two independent
writes: the stamp is first replaced with a `build_key=publishing-<pid>` poison,
then the image is renamed into place, then the real stamp is written — each
write temp-file-then-rename. A run killed inside that window therefore leaves a
stamp that matches no request at all, so the next invocation reports that the
image was left by a build that died while publishing it and rebuilds, instead
of serving an image the surviving stamp only claimed to describe. A
`publishing-` build key in a cache directory means exactly that; a completed
build never leaves one.

The default shape is compared against the literal defaults (`2G`, no
`--packages`, no `--ssh-key`), so an env-overridden `QMU_ROOTFS_SIZE` also
routes to a keyed variant rather than the legacy path.

Use `--no-cache` to force a rebuild. Use `--outdir` to place output elsewhere.

## Prerequisites

- **Docker** with buildx support (Docker 19.03+)
- **binfmt_misc** for cross-arch builds:
  ```bash
  docker run --rm --privileged tonistiigi/binfmt:latest --install all
  ```
  Only needed once per host boot. Native-arch builds (x86_64 on x86_64) need no binfmt.

## Troubleshooting

**"cannot run linux/arm64 containers":**
binfmt_misc QEMU emulators not registered. Run:
```bash
docker run --rm --privileged tonistiigi/binfmt:latest --install all
```

**ext4 image creation fails:**
The script tries to create the ext4 image inside a helper Docker container (no sudo needed). If that fails, it falls back to `sudo mke2fs -d`. Ensure either Docker works or you have sudo access. The temporary extracted root used by the sudo fallback is removed whether the fallback succeeds or fails.

**SSH connection refused after boot:**
- Wait for "QMU-NET-READY" in serial log (`qmu log --tail 20`)
- Verify the SSH key in qmu.toml matches what was baked into the rootfs
- Check `qmu doctor` for SSH key issues

**Wrong root device (kernel panic: VFS unable to mount):**
- x86 kernels expect `root=/dev/sda` (default qmu profile)
- arm64/arm32 with virtio-blk need `root=/dev/vda` — override cmdline:
  ```bash
  qmu launch --cmdline "console=ttyAMA0 root=/dev/vda rw" ...
  ```

**Image too small (no space for packages):**
Increase with `--size`:
```bash
tools/mkrootfs.sh --size 4G --packages "gdb,valgrind,python3"
```
