#!/usr/bin/env bash
# Build Debian rootfs images for QEMU exploit development via Docker buildx.
#
# Supports x86_64, i386, arm64, arm32 via Docker multiarch (binfmt_misc).
# Produces a raw ext4 image with systemd + sshd + networking ready for qmu.
#
# Output is eval-able:  eval $(tools/mkrootfs.sh --arch arm64)
#                        qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS"
# STDOUT carries nothing but those VAR=value assignments, shell-quoted with
# printf %q (the same discipline as kbuild.sh) so a path with a space survives
# the eval. Every log line, every note, and every build command's own chatter
# goes to stderr -- a cache MISS used to leak `docker build -q`'s image id and
# mke2fs's "Creating regular file" onto stdout, which broke the eval above.
set -euo pipefail

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
CACHE="${QMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/qmu}"
ARCH="x86_64"
RELEASE="bookworm"
SIZE="${QMU_ROOTFS_SIZE:-2G}"
# Literal "2G", never "$SIZE": capturing the reference after the expansion
# above makes the DEFAULT_SHAPE check below tautological, so an env-overridden
# QMU_ROOTFS_SIZE would pass as a default-shaped build and get routed to the
# legacy unkeyed directory. mktarget.sh:606 compares against its '4G' literal
# for exactly this reason.
DEFAULT_SIZE="2G"
SSH_KEY_ARG=""
PACKAGES=""
OUTDIR_OVERRIDE=""
NO_CACHE=false
VERBOSE=false

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die()  { echo "mkrootfs: error: $*" >&2; exit 2; }
step() { echo "=== [$(date +%H:%M:%S)] $* ===" >&2; }
log()  { echo "mkrootfs: $*" >&2; }

usage() {
  cat >&2 <<'EOF'
Usage: mkrootfs.sh [OPTIONS]

Build a Debian rootfs image for QEMU exploit development via Docker.

Optional:
  --arch ARCH            Target architecture (default: x86_64)
                         Values: x86_64, i386, arm64, arm32
  --release RELEASE      Debian release (default: bookworm)
                         Values: bullseye, bookworm, trixie, sid
  --ssh-key PATH         Path to existing ed25519 private key
                         (default: auto-generates into output dir)
  --packages PKGS        Comma-separated extra apt packages to install
  --size SIZE            Image size (default: 2G)
  --outdir DIR           Override output directory
  --no-cache             Rebuild even if output exists
  --verbose              Show Docker build output
  --emit-guest-setup P   Write the in-guest setup script (sshd policy,
                         authorized_keys, console autologin, /etc/qmu-rootfs.json)
                         to P and exit; no Docker. For inspection and tests.
  Caching: builds that differ from the defaults (--packages, --size,
  --ssh-key) get their own cache directory keyed by those options;
  default-argument builds keep using the legacy unkeyed path.

  Guest SSH policy: root is KEY-ONLY (PermitRootLogin prohibit-password,
  PasswordAuthentication no, PermitEmptyPasswords no) and only the key this
  script generates or is given (--ssh-key) is authorized. Images built before
  this policy accepted root with ANY key; their stamp lacks sshd_policy=, so
  they are rebuilt on the next run (the serial console autologs in as root).

  -h, --help             Show this help

Environment:
  QMU_CACHE_DIR          Override ~/.cache/qmu (shared with kbuild)
  QMU_ROOTFS_SIZE        Default image size (overridden by --size)

Output (eval-able):
  ROOTFS=/path/to/rootfs.img
  SSH_KEY=/path/to/id_ed25519

Example:
  eval $(tools/mkrootfs.sh --arch arm64)
  qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY"
EOF
  exit 2
}

# ---------------------------------------------------------------------------
# parse args
# ---------------------------------------------------------------------------
EMIT_GUEST_SETUP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)       ARCH="$2"; shift 2 ;;
    --release)    RELEASE="$2"; shift 2 ;;
    --ssh-key)    SSH_KEY_ARG="$2"; shift 2 ;;
    --packages)   PACKAGES="$2"; shift 2 ;;
    --size)       SIZE="$2"; shift 2 ;;
    --outdir)     OUTDIR_OVERRIDE="$2"; shift 2 ;;
    --no-cache)   NO_CACHE=true; shift ;;
    --verbose)    VERBOSE=true; shift ;;
    --emit-guest-setup) EMIT_GUEST_SETUP="$2"; shift 2 ;;
    -h|--help)    usage ;;
    *)            die "unknown argument: $1" ;;
  esac
done

# ---------------------------------------------------------------------------
# in-guest setup script
#
# Everything that configures the guest beyond `apt-get install` lives in ONE
# POSIX sh script that the Dockerfile copies in and runs. It is generated
# here (not inlined in the Dockerfile) so `--emit-guest-setup` can hand it to
# a test that runs it against a scratch directory, with no Docker, and
# asserts on the files it produces: the sshd policy below is a security
# property, and a security property that only a multi-GB image build can
# exercise is one that regresses silently.
#
# Root SSH is key-only. This used to run `passwd -d root` together with
# PermitRootLogin yes and PermitEmptyPasswords yes, so sshd authenticated ANY
# client as root with no credential -- `ssh -i <some other VM's key>` logged
# in -- and a port mix-up between two VMs on one host (launch --no-net
# recording an SSH port it never bound, cross-arch audit P0) executed the
# command on the wrong guest with exit 0 and no warning at all. With the key
# enforced, the wrong VM refuses the wrong key.
#
# The settings go in sshd_config.d rather than through sed on sshd_config:
# sshd takes the FIRST value it sees for a keyword and bookworm's sshd_config
# Includes that directory from its first line, so these win outright, and a
# keyword absent from the main file (rather than merely commented) is still
# set -- which sed cannot promise.
#
# The serial console autologs in as root (template drop-in, so it covers
# ttyS0 on x86 and ttyAMA0 on arm alike): the harness / console use case
# never needed sshd's leniency, and root's password is locked so there is no
# second credential-free door.
# ---------------------------------------------------------------------------
GUEST_SETUP_NAME="qmu-guest-setup.sh"
write_guest_setup_script() {
  cat > "$1" <<'GUEST_SETUP'
#!/bin/sh
# qmu rootfs: in-guest setup. Generated by tools/mkrootfs.sh.
#
# Runs as root inside the rootfs container during `docker build`. With
# QMU_GUEST_ROOT=<dir> it writes the same files under <dir> instead and skips
# the commands that act on a live system (passwd, machine-id), which is how
# tests/test_mkrootfs_script.py checks the generated configuration.
#
# Inputs (environment): PUBKEY (one authorized_keys line), ROOT_DEV,
# QMU_RELEASE, QMU_ARCH, QMU_HOSTNAME (the name the export fixup writes to
# /etc/hostname; recorded in /etc/qmu-rootfs.json).
set -eu
: "${PUBKEY:?PUBKEY (authorized public key line) is required}"
: "${ROOT_DEV:?ROOT_DEV (guest root block device) is required}"
QMU_RELEASE="${QMU_RELEASE:-unknown}"
QMU_ARCH="${QMU_ARCH:-unknown}"
QMU_HOSTNAME="${QMU_HOSTNAME:-unknown}"
ROOT="${QMU_GUEST_ROOT:-}"

mkdir -p "$ROOT/root/.ssh" "$ROOT/etc/ssh/sshd_config.d" \
         "$ROOT/etc/systemd/system/serial-getty@.service.d"

# The generated/explicit key is the ONLY way in over SSH.
printf '%s\n' "$PUBKEY" > "$ROOT/root/.ssh/authorized_keys"
chmod 700 "$ROOT/root/.ssh"
chmod 600 "$ROOT/root/.ssh/authorized_keys"

# sshd policy: key-only root. First match wins in sshd, and the drop-in
# directory is Included from the first line of sshd_config, so these settings
# override anything the package's sshd_config says.
printf '%s\n' \
  '# qmu: root is key-only; see tools/mkrootfs.sh' \
  'PermitRootLogin prohibit-password' \
  'PubkeyAuthentication yes' \
  'PasswordAuthentication no' \
  'KbdInteractiveAuthentication no' \
  'PermitEmptyPasswords no' \
  > "$ROOT/etc/ssh/sshd_config.d/60-qmu.conf"
if [ -f "$ROOT/etc/ssh/sshd_config" ]; then
  if ! grep -q '^Include /etc/ssh/sshd_config.d/' "$ROOT/etc/ssh/sshd_config"; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$ROOT/etc/ssh/sshd_config"
  fi
else
  printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > "$ROOT/etc/ssh/sshd_config"
fi

# Serial console: log in as root without a prompt. A template drop-in applies
# to every serial-getty@ instance, so the console tty name does not matter.
printf '%s\n' \
  '[Service]' \
  'ExecStart=' \
  'ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM' \
  > "$ROOT/etc/systemd/system/serial-getty@.service.d/autologin.conf"

# /etc/hostname is NOT written here: docker bind-mounts it (and /etc/hosts)
# during RUN, so a write lands in the mount namespace and `docker export`
# ships the 0-byte bind file instead. Both are written by the export fixup
# (write_export_fixup_script in tools/mkrootfs.sh), alongside the removal of
# /.dockerenv, which is bind-mounted the same way.
printf '%s / ext4 defaults 0 1\n' "$ROOT_DEV" > "$ROOT/etc/fstab"

# Provenance, readable from the guest (`cat /etc/qmu-rootfs.json`) and from
# the host (`qmu rootfs cat <img> /etc/qmu-rootfs.json --partition 0`), so a
# cached image from before the key-only policy -- which has no such file --
# can be told apart from a hardened one.
pubkey_sha256="$(printf '%s\n' "$PUBKEY" | sha256sum | awk '{print $1}')"
printf '{"schema": 1, "generator": "qmu/tools/mkrootfs.sh", "release": "%s", "arch": "%s", "sshd_policy": "key-only", "root_password": "locked", "console": "serial-autologin-root", "hostname": "%s", "ssh_pubkey_sha256": "%s"}\n' \
  "$QMU_RELEASE" "$QMU_ARCH" "$QMU_HOSTNAME" "$pubkey_sha256" > "$ROOT/etc/qmu-rootfs.json"
chmod 644 "$ROOT/etc/qmu-rootfs.json"

if [ -z "$ROOT" ]; then
  passwd -l root
  systemd-machine-id-setup || true
fi
GUEST_SETUP
  chmod 755 "$1"
}

# ---------------------------------------------------------------------------
# post-export fixup
#
# Applied to the extracted tarball, just before mke2fs, in BOTH image paths
# (helper container and sudo fallback). The files it touches are exactly the
# ones docker bind-mounts during RUN, so no Dockerfile step can produce them:
#   * /.dockerenv (and /run/.containerenv) survive `docker export` and make
#     systemd-detect-virt report "docker" on the booted VM. systemd's getty
#     generator then takes the container branch: ttyS0 goes to
#     console-getty.service and serial-getty@ttyS0 -- the unit the autologin
#     drop-in above targets -- is never instantiated, so the serial console
#     shows `login:` against a locked root password and there is no way in.
#     mktarget.sh strips the same two files for the same reason.
#   * /etc/hostname exports as the 0-byte bind file, so the guest boots as
#     `localhost`; /etc/hosts likewise. Written here so `hostname` in the
#     guest matches the value stamped into /etc/qmu-rootfs.json.
# Generated as a file (not inlined in the helper's bash -c) so one script
# serves both paths and tests/test_mkrootfs_script.py can run it against a
# scratch tree.
# ---------------------------------------------------------------------------
GUEST_HOSTNAME="qmu-rootfs"
EXPORT_FIXUP_NAME="qmu-export-fixup.sh"
write_export_fixup_script() {
  cat > "$1" <<GUEST_FIXUP
#!/bin/sh
# qmu rootfs: post-export fixup. Generated by tools/mkrootfs.sh.
# Usage: sh $EXPORT_FIXUP_NAME <extracted-rootfs-dir>
set -eu
root="\${1:?extracted rootfs directory is required}"
[ -d "\$root/etc" ] || { echo "qmu-export-fixup: \$root/etc missing" >&2; exit 2; }
rm -f "\$root/.dockerenv" "\$root/run/.containerenv"
printf '%s\n' '$GUEST_HOSTNAME' > "\$root/etc/hostname"
printf '%s\n' \\
  '127.0.0.1 localhost' \\
  '127.0.1.1 $GUEST_HOSTNAME' \\
  '::1 localhost ip6-localhost ip6-loopback' \\
  > "\$root/etc/hosts"
GUEST_FIXUP
  chmod 755 "$1"
}

if [[ -n "$EMIT_GUEST_SETUP" ]]; then
  write_guest_setup_script "$EMIT_GUEST_SETUP"
  log "guest setup script written to $EMIT_GUEST_SETUP"
  exit 0
fi

# validate arch
case "$ARCH" in
  x86_64|i386|arm64|arm32) ;;
  *) die "unsupported --arch: $ARCH (expected: x86_64, i386, arm64, arm32)" ;;
esac

# validate release
case "$RELEASE" in
  bullseye|bookworm|trixie|sid) ;;
  *) die "unsupported --release: $RELEASE (expected: bullseye, bookworm, trixie, sid)" ;;
esac

# ---------------------------------------------------------------------------
# arch -> platform mapping
# ---------------------------------------------------------------------------
case "$ARCH" in
  x86_64) PLATFORM="linux/amd64"; ROOT_DEV="/dev/sda" ;;
  i386)   PLATFORM="linux/386";   ROOT_DEV="/dev/sda" ;;
  arm64)  PLATFORM="linux/arm64"; ROOT_DEV="/dev/vda" ;;
  arm32)  PLATFORM="linux/arm/v7"; ROOT_DEV="/dev/vda" ;;
esac

# ---------------------------------------------------------------------------
# SSH key (validated here, before the build key, which hashes the public half)
# ---------------------------------------------------------------------------
if [[ -n "$SSH_KEY_ARG" ]]; then
  [[ -f "$SSH_KEY_ARG" ]] || die "SSH private key not found: $SSH_KEY_ARG"
  [[ -f "${SSH_KEY_ARG}.pub" ]] || die "SSH public key not found: ${SSH_KEY_ARG}.pub"
  # Readability is checked here rather than at the `cat` on the build path: an
  # existing-but-unreadable public half is a permission fault, and reaching
  # that `cat` with one produces a raw `cat: Permission denied` and no
  # `mkrootfs: error:` line at all.
  [[ -r "${SSH_KEY_ARG}.pub" ]] || die "cannot read SSH public key ${SSH_KEY_ARG}.pub: check its permissions"
fi

# ---------------------------------------------------------------------------
# build key -- a digest of everything that changes the image produced
#
# Mirrors mktarget.sh: the cache directory name stays human-findable (release,
# arch), and every OTHER build-affecting input goes into this digest -- EXCEPT
# an auto-generated SSH key's public half, which cannot be hashed here: it
# doesn't exist until the build below creates it inside the very directory
# this digest names. The completion stamp separately records the sha256 of
# whichever public key actually got baked into the image (generated or
# explicit) and cache_hit() re-checks that value directly, so an image built
# with different --packages / --size / --ssh-key, or whose auto-generated key
# was swapped out from under a cache dir after the fact, is never silently
# served for a run asking for something else.
# ---------------------------------------------------------------------------
build_key_material() {
  echo "arch=$ARCH"
  echo "release=$RELEASE"
  echo "size=$SIZE"
  echo "packages=$(printf '%s' "$PACKAGES" | tr ',' ' ' | tr ' ' '\n' | sed '/^$/d' | sort -u | paste -sd, -)"
  if [[ -n "$SSH_KEY_ARG" ]]; then
    echo "ssh_pubkey=$(sha256sum -- "${SSH_KEY_ARG}.pub" | awk '{print $1}')"
  fi
  # Part of the digest on purpose: an image built before root SSH became
  # key-only answers to ANY key, and its stamp carries the old digest, so it
  # can never be served as a hardened one. Bump the value when the policy
  # changes again.
  echo "sshd_policy=$SSHD_POLICY"
  # Likewise: an image exported before the post-export fixup still carries
  # /.dockerenv, boots with no serial-getty@ (so no console login at all) and
  # as `localhost`; one without udev generates the unit but never starts it
  # (dev-ttyS0.device stays inactive). Bump when console-login readiness
  # changes again.
  echo "console_login=$CONSOLE_LOGIN_REV"
}
SSHD_POLICY="key-only"
CONSOLE_LOGIN_REV="1-dockerenv-hostname-udev"
BUILD_KEY="$(build_key_material | sha256sum | awk '{print $1}')"

# ---------------------------------------------------------------------------
# output directory
#
# Same DEFAULT_SHAPE/VARIANT scheme as mktarget.sh: the legacy unkeyed path
# keeps serving builds made with exactly the default arguments, so pre-existing
# caches stay valid. A build that differs from the defaults in any way gets its
# own directory keyed by the build digest, so alternating variants cache side
# by side instead of evicting each other. Correctness does not rest on this --
# the stamp check does -- it only stops two legitimate variants from sharing a
# directory.
# ---------------------------------------------------------------------------
DEFAULT_SHAPE=true
[[ "$SIZE"           == "$DEFAULT_SIZE" ]] || DEFAULT_SHAPE=false
[[ -z "$PACKAGES"    ]]                   || DEFAULT_SHAPE=false
[[ -z "$SSH_KEY_ARG" ]]                   || DEFAULT_SHAPE=false

if [[ -n "$OUTDIR_OVERRIDE" ]]; then
  OUTDIR="$OUTDIR_OVERRIDE"
else
  OUTDIR="$CACHE/rootfs/$RELEASE/$ARCH"
  [[ "$DEFAULT_SHAPE" == true ]] || OUTDIR="$CACHE/rootfs/$RELEASE/${ARCH}-${BUILD_KEY:0:8}"
fi
STAMP_OUT="$OUTDIR/.mkrootfs-stamp"

# An existing private half means this run will NOT regenerate the pair, so
# the public half gets read twice -- to re-check a stamped hit's recorded
# digest, and to bake into a rebuild. A missing or unreadable one is
# therefore a fault, and it is reported HERE, before the cache gate, because
# both alternatives are wrong answers: the gate would compare an empty digest
# and announce a CHANGED SSH KEY when nothing about the key changed, and the
# rebuild would die inside `cat` with a raw error and no `mkrootfs:` line.
if [[ -z "$SSH_KEY_ARG" && -f "$OUTDIR/id_ed25519" ]]; then
  if [[ ! -e "$OUTDIR/id_ed25519.pub" ]]; then
    die "SSH public key missing: $OUTDIR/id_ed25519.pub (its private half is already in that directory, so mkrootfs will not regenerate the pair; restore it with: ssh-keygen -y -f $OUTDIR/id_ed25519 > $OUTDIR/id_ed25519.pub)"
  fi
  if [[ ! -f "$OUTDIR/id_ed25519.pub" || ! -r "$OUTDIR/id_ed25519.pub" ]]; then
    die "cannot read $OUTDIR/id_ed25519.pub: check its permissions and that it is a regular file (its public half is needed to verify the cached image and to rebuild)"
  fi
fi

# ---------------------------------------------------------------------------
# cache gate
#
# A hit requires the image AND a stamp whose recorded build key equals this
# run's. Three deliberate exceptions, each of which must SAY so -- silence on a
# hit whose options may not match is exactly bug #51:
#   * --no-cache skips the gate entirely.
#   * a stamped image whose key differs from this run's gets named: the note
#     lists the requested options and the run rebuilds with them.
#   * a directory holding an image with no stamp at all. Its options are
#     unrecorded and unknown -- it may predate stamps (the old contract
#     routed EVERY build here regardless of options) or its stamp may have
#     been removed. A default-shaped request may still serve it (that keeps
#     pre-existing caches valid), but prints a note saying the options are
#     unverified, naming the possibilities rather than asserting one. Any
#     non-default request is routed to its own keyed directory above and
#     never sees an unstamped image.
# The stamp is published TWICE per build, each time atomically (temp file +
# rename) and each under its own temp name: a poison value immediately before
# the image's own publish, then the real one immediately after. A build that
# fails before the poison never touches the previous (image, stamp) pair, so
# it stays exactly as coherent as it was; a build that dies inside the publish
# window leaves a stamp that matches no request at all, which is a named
# mismatch and a rebuild -- never a stamp certifying an image it does not
# describe.
# ---------------------------------------------------------------------------
# A real build key is always a sha256 hex digest, so a value carrying this
# prefix can match no request. It is what the publish window writes, and
# reading one back means a previous build died mid-publish.
STAMP_PUBLISHING_KEY_PREFIX="publishing-"

MISMATCH_NOTE=""
LEGACY_NOTE=""
cache_hit() {
  [[ -f "$OUTDIR/rootfs.img" ]] || return 1
  if [[ -f "$STAMP_OUT" ]]; then
    local recorded
    recorded="$(sed -n 's/^build_key=//p' "$STAMP_OUT" | head -n1)"
    if [[ "$recorded" == "$BUILD_KEY" ]]; then
      # BUILD_KEY cannot cover an auto-generated key's public half (see the
      # comment above it), so a generating-mode hit re-checks the stamp's
      # recorded pubkey hash against whatever key is on disk right now. Gated
      # on -r and on a non-empty digest: an unreadable .pub is a permission
      # fault (reported before this gate), never a changed key.
      if [[ -z "$SSH_KEY_ARG" && -r "$OUTDIR/id_ed25519.pub" ]]; then
        local recorded_pubkey current_pubkey
        recorded_pubkey="$(sed -n 's/^ssh_pubkey_sha256=//p' "$STAMP_OUT" | head -n1)"
        current_pubkey="$(sha256sum -- "$OUTDIR/id_ed25519.pub" 2>/dev/null | awk '{print $1}')"
        if [[ -n "$recorded_pubkey" && -n "$current_pubkey" && "$recorded_pubkey" != "$current_pubkey" ]]; then
          MISMATCH_NOTE="$(printf 'cached image at %q was built with a different SSH key than the one now at %s (its public half changed since the build)' \
            "$OUTDIR/rootfs.img" "$OUTDIR/id_ed25519")"
          return 1
        fi
      fi
      return 0
    fi
    if [[ "$recorded" == "$STAMP_PUBLISHING_KEY_PREFIX"* ]]; then
      # The poison value names no build, so it is never rendered as an option
      # set. What it does say is exactly what happened.
      MISMATCH_NOTE="$(printf 'cached image at %q was left by a build that died while publishing it (its stamp still reads publish-in-progress), so the image on disk answers no known request' \
        "$OUTDIR/rootfs.img")"
      return 1
    fi
    if ! grep -q '^sshd_policy=' "$STAMP_OUT"; then
      MISMATCH_NOTE="$(printf 'cached image at %q predates the key-only sshd policy (its sshd accepted root with ANY key, so a port mix-up ran commands on the wrong VM); rebuilding so only the qmu key is authorized' \
        "$OUTDIR/rootfs.img")"
      return 1
    fi
    MISMATCH_NOTE="$(printf 'cached image at %q was built with different options than requested (requested: size=%s packages=%s ssh-key=%s sshd-policy=%s)' \
      "$OUTDIR/rootfs.img" "$SIZE" "${PACKAGES:-<none>}" "${SSH_KEY_ARG:-<generated>}" "$SSHD_POLICY")"
    return 1
  fi
  # No stamp: only the legacy default path may serve an unstamped image.
  if [[ "$DEFAULT_SHAPE" == true ]]; then
    LEGACY_NOTE="$(printf 'cached image at %q has no completion stamp, so its --packages/--size/--ssh-key are UNVERIFIED and its sshd most likely accepts root with ANY key (a cache directory written before option tracking and the key-only policy existed, or one whose stamp was removed; use --no-cache to rebuild a hardened image with the current request)' \
      "$OUTDIR/rootfs.img")"
    return 0
  fi
  return 1
}

if [[ "$NO_CACHE" == false ]] && cache_hit; then
  log "cached rootfs found at $OUTDIR/rootfs.img"
  [[ -z "$LEGACY_NOTE" ]] || log "note: $LEGACY_NOTE"
  printf 'ROOTFS=%q\n' "$OUTDIR/rootfs.img"
  if [[ -n "$SSH_KEY_ARG" ]]; then
    printf 'SSH_KEY=%q\n' "$SSH_KEY_ARG"
  elif [[ -f "$OUTDIR/id_ed25519" ]]; then
    printf 'SSH_KEY=%q\n' "$OUTDIR/id_ed25519"
  fi
  exit 0
fi
if [[ -n "$MISMATCH_NOTE" ]]; then
  log "note: $MISMATCH_NOTE"
  log "note: rebuilding with the requested options (previous image will be replaced)"
fi

mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------
if [[ -n "$SSH_KEY_ARG" ]]; then
  PRIVKEY="$SSH_KEY_ARG"
else
  PRIVKEY="$OUTDIR/id_ed25519"
  if [[ ! -f "$PRIVKEY" ]]; then
    step "Generating SSH keypair"
    ssh-keygen -t ed25519 -N '' -f "$PRIVKEY" -C "qmu-rootfs-$RELEASE-$ARCH" >/dev/null
  fi
fi
chmod 600 "$PRIVKEY"
PUBKEY_CONTENT="$(cat "${PRIVKEY}.pub")"

# Same atomicity rule as the stamp: the image is built under a .part name and
# renamed into place only on success, so an interrupted run can never leave a
# partial image at the final path for a later cache hit to serve.
rm -f -- "$OUTDIR/rootfs.img.part"

# ---------------------------------------------------------------------------
# Docker buildx / binfmt check
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  die "docker not found in PATH"
fi

HOST_ARCH="$(uname -m)"
NEED_BINFMT=false
case "$ARCH" in
  x86_64) [[ "$HOST_ARCH" != "x86_64" ]] && NEED_BINFMT=true ;;
  i386)   [[ "$HOST_ARCH" != "x86_64" ]] && NEED_BINFMT=true ;;
  arm64)  [[ "$HOST_ARCH" != "aarch64" ]] && NEED_BINFMT=true ;;
  arm32)  NEED_BINFMT=true ;;
esac

if [[ "$NEED_BINFMT" == true ]]; then
  if ! docker run --rm --platform "$PLATFORM" debian:${RELEASE}-slim true >/dev/null 2>&1; then
    die "cannot run $PLATFORM containers. Register binfmt_misc emulators:
  docker run --rm --privileged tonistiigi/binfmt:latest --install all"
  fi
fi

# ---------------------------------------------------------------------------
# build Docker image
# ---------------------------------------------------------------------------
EXTRA_PACKAGES="${PACKAGES//,/ }"
IMAGE_TAG="qmu-rootfs:${RELEASE}-${ARCH}"

DOCKER_QUIET=""
if [[ "$VERBOSE" == false ]]; then
  DOCKER_QUIET="-q"
fi

step "Building rootfs container image ($IMAGE_TAG, platform $PLATFORM)"
local_ctx=""
CID=""
ROOTDIR=""

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [[ -n "$ROOTDIR" ]]; then
    sudo rm -rf -- "$ROOTDIR"
  fi
  if [[ -n "$CID" ]]; then
    docker rm "$CID" >/dev/null 2>&1
  fi
  if [[ -n "$local_ctx" ]]; then
    rm -rf -- "$local_ctx"
  fi
  exit "$status"
}
trap cleanup EXIT

local_ctx="$(mktemp -d)"
write_guest_setup_script "$local_ctx/$GUEST_SETUP_NAME"
write_export_fixup_script "$local_ctx/$EXPORT_FIXUP_NAME"

docker build $DOCKER_QUIET \
  --platform "$PLATFORM" \
  --build-arg "RELEASE=$RELEASE" \
  --build-arg "ARCH=$ARCH" \
  --build-arg "PUBKEY=$PUBKEY_CONTENT" \
  --build-arg "ROOT_DEV=$ROOT_DEV" \
  --build-arg "EXTRA_PACKAGES=$EXTRA_PACKAGES" \
  --build-arg "GUEST_SETUP=$GUEST_SETUP_NAME" \
  --build-arg "GUEST_HOSTNAME=$GUEST_HOSTNAME" \
  -t "$IMAGE_TAG" \
  -f - "$local_ctx" >&2 <<'DOCKERFILE'
ARG RELEASE=bookworm
FROM debian:${RELEASE}-slim
ARG RELEASE
ARG ARCH
ARG PUBKEY
ARG ROOT_DEV=/dev/sda
ARG EXTRA_PACKAGES=""
ARG GUEST_SETUP=qmu-guest-setup.sh
ARG GUEST_HOSTNAME=qmu-rootfs

# udev is required for the serial console: serial-getty@ttyS0 has
# BindsTo=dev-ttyS0.device, and without systemd-udevd that device unit never
# becomes active, so the (correctly generated) getty sits in "start waiting"
# forever and the console shows nothing after boot. systemd-sysv alone does
# not pull it in.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd-sysv udev openssh-server gcc libc6-dev make \
      iproute2 ethtool kmod \
      ${EXTRA_PACKAGES} \
 && rm -rf /var/lib/apt/lists/*

# authorized_keys, key-only sshd policy, console autologin, fstab,
# /etc/qmu-rootfs.json, locked root password -- see write_guest_setup_script
# in tools/mkrootfs.sh (and `mkrootfs.sh --emit-guest-setup` to read it).
# /etc/hostname, /etc/hosts and the removal of /.dockerenv happen after
# `docker export` (write_export_fixup_script): docker bind-mounts all three
# during RUN, so nothing written here reaches the exported layer.
COPY ${GUEST_SETUP} /tmp/qmu-guest-setup.sh
RUN QMU_RELEASE="$RELEASE" QMU_ARCH="$ARCH" QMU_HOSTNAME="$GUEST_HOSTNAME" sh /tmp/qmu-guest-setup.sh \
 && rm -f /tmp/qmu-guest-setup.sh

RUN printf '%s\n' \
 '[Unit]' \
 'Description=qmu static net + offload fixup' \
 'After=network-pre.target' \
 'Before=ssh.service network.target' \
 '[Service]' \
 'Type=oneshot' \
 'RemainAfterExit=yes' \
 'ExecStart=-/sbin/ethtool -K eth0 tx off rx off tso off gso off gro off sg off' \
 'ExecStart=-/sbin/ip link set eth0 up' \
 'ExecStart=-/sbin/ip addr add 10.0.2.15/24 dev eth0' \
 'ExecStart=-/sbin/ip route add default via 10.0.2.10' \
 'ExecStart=/bin/sh -c "echo QMU-NET-READY $(ip -4 -o addr show eth0) > /dev/console"' \
 '[Install]' \
 'WantedBy=multi-user.target' \
 > /etc/systemd/system/qmu-net.service \
 && systemctl enable qmu-net.service ssh
DOCKERFILE

# ---------------------------------------------------------------------------
# export container filesystem + create ext4 image
# ---------------------------------------------------------------------------
step "Exporting container filesystem"
CID="$(docker create --platform "$PLATFORM" "$IMAGE_TAG")"

step "Creating raw ext4 image ($SIZE)"
# Use a helper container to run mke2fs as root — avoids requiring sudo on host.
# The if/else form is required under `set -euo pipefail` so a failed helper
# pipeline can fall back to host sudo mke2fs instead of aborting immediately.
# Both paths run the export fixup on the extracted tree before mke2fs.
if docker export "$CID" | docker run --rm -i \
  -v "$OUTDIR:/output" \
  -v "$local_ctx:/qmu-ctx:ro" \
  debian:bookworm-slim \
  bash -c "
    mkdir /rootfs && tar -x -C /rootfs &&
    sh /qmu-ctx/$EXPORT_FIXUP_NAME /rootfs &&
    apt-get update -qq && apt-get install -y -qq e2fsprogs >/dev/null 2>&1 &&
    mke2fs -F -q -t ext4 -d /rootfs -L qmu-root /output/rootfs.img.part $SIZE
  " >&2; then
  :
else
  RC=$?
  log "ext4 image creation failed (exit $RC)"
  log "fallback: trying sudo mke2fs..."
  ROOTDIR="$(mktemp -d)"
  docker export "$CID" | sudo tar -x -C "$ROOTDIR" >&2
  sudo sh "$local_ctx/$EXPORT_FIXUP_NAME" "$ROOTDIR" >&2
  sudo mke2fs -F -q -t ext4 -d "$ROOTDIR" -L qmu-root \
    "$OUTDIR/rootfs.img.part" "$SIZE" >&2
  sudo chown "$(id -u):$(id -g)" "$OUTDIR/rootfs.img.part" >&2
fi

# Publish window. Poisoning the stamp HERE, before the image is renamed into
# place, is what keeps the pair honest. Between the two renames the directory
# holds the new image, and anything that kills the run in that gap
# (SIGINT/SIGTERM/OOM, ENOSPC or EIO on the stamp write -- which lands
# immediately after writing a multi-GB image -- an unclean shutdown) would
# otherwise leave the PREVIOUS stamp certifying an image it does not
# describe, and the next request for the shape that stamp names would be
# served at exit 0 with no note at all. Removing the stamp instead is not
# equivalent: an image with no stamp is served by the legacy default-shape
# exception as merely UNVERIFIED. A death after this write costs one rebuild.
{
  printf 'build_key=%s%s\n' "$STAMP_PUBLISHING_KEY_PREFIX" "$$"
  printf 'publish_started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$STAMP_OUT.publishing"
mv -f -- "$STAMP_OUT.publishing" "$STAMP_OUT"
mv -f -- "$OUTDIR/rootfs.img.part" "$OUTDIR/rootfs.img"

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
if [[ -f "$OUTDIR/rootfs.img" ]]; then
  # completion stamp -- the second and last of this build's two stamp
  # publishes (the first is the poison above). Its existence plus a matching
  # build key is what makes this directory a cache hit; it is assembled
  # beside the final name and renamed into place so even a kill during the
  # write cannot leave a partial stamp that parses, and so a publish over an
  # unwritable predecessor still succeeds (rename needs only the directory).
  {
    echo "build_key=$BUILD_KEY"
    echo "arch=$ARCH"
    echo "release=$RELEASE"
    echo "size=$SIZE"
    echo "packages=$PACKAGES"
    if [[ -n "$SSH_KEY_ARG" ]]; then
      echo "ssh_key=external:$SSH_KEY_ARG"
    else
      echo "ssh_key=generated:$OUTDIR/id_ed25519"
    fi
    echo "ssh_pubkey_sha256=$(sha256sum -- "${PRIVKEY}.pub" | awk '{print $1}')"
    echo "sshd_policy=$SSHD_POLICY"
    echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$STAMP_OUT.part"
  mv -f -- "$STAMP_OUT.part" "$STAMP_OUT"
  step "Rootfs ready: $OUTDIR/rootfs.img"
  printf 'ROOTFS=%q\n' "$OUTDIR/rootfs.img"
  printf 'SSH_KEY=%q\n' "$PRIVKEY"
else
  die "build appeared to succeed but $OUTDIR/rootfs.img not found"
fi
