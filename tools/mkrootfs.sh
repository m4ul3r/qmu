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
  Caching: builds that differ from the defaults (--packages, --size,
  --ssh-key) get their own cache directory keyed by those options;
  default-argument builds keep using the legacy unkeyed path.

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
    -h|--help)    usage ;;
    *)            die "unknown argument: $1" ;;
  esac
done

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
}
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
    MISMATCH_NOTE="$(printf 'cached image at %q was built with different options than requested (requested: size=%s packages=%s ssh-key=%s)' \
      "$OUTDIR/rootfs.img" "$SIZE" "${PACKAGES:-<none>}" "${SSH_KEY_ARG:-<generated>}")"
    return 1
  fi
  # No stamp: only the legacy default path may serve an unstamped image.
  if [[ "$DEFAULT_SHAPE" == true ]]; then
    LEGACY_NOTE="$(printf 'cached image at %q has no completion stamp, so its --packages/--size/--ssh-key are UNVERIFIED (a cache directory written before option tracking existed, or one whose stamp was removed; use --no-cache to force a rebuild with the current request)' \
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

docker build $DOCKER_QUIET \
  --platform "$PLATFORM" \
  --build-arg "RELEASE=$RELEASE" \
  --build-arg "PUBKEY=$PUBKEY_CONTENT" \
  --build-arg "ROOT_DEV=$ROOT_DEV" \
  --build-arg "EXTRA_PACKAGES=$EXTRA_PACKAGES" \
  -t "$IMAGE_TAG" \
  -f - "$local_ctx" >&2 <<'DOCKERFILE'
ARG RELEASE=bookworm
FROM debian:${RELEASE}-slim
ARG PUBKEY
ARG ROOT_DEV=/dev/sda
ARG EXTRA_PACKAGES=""

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd-sysv openssh-server gcc libc6-dev make \
      iproute2 ethtool kmod \
      ${EXTRA_PACKAGES} \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.ssh \
 && printf '%s\n' "$PUBKEY" > /root/.ssh/authorized_keys \
 && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys \
 && passwd -d root \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
 && echo qmu-rootfs > /etc/hostname \
 && printf '%s / ext4 defaults 0 1\n' "$ROOT_DEV" > /etc/fstab \
 && systemd-machine-id-setup || true

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
if docker export "$CID" | docker run --rm -i \
  -v "$OUTDIR:/output" \
  debian:bookworm-slim \
  bash -c "
    mkdir /rootfs && tar -x -C /rootfs &&
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
    echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$STAMP_OUT.part"
  mv -f -- "$STAMP_OUT.part" "$STAMP_OUT"
  step "Rootfs ready: $OUTDIR/rootfs.img"
  printf 'ROOTFS=%q\n' "$OUTDIR/rootfs.img"
  printf 'SSH_KEY=%q\n' "$PRIVKEY"
else
  die "build appeared to succeed but $OUTDIR/rootfs.img not found"
fi
