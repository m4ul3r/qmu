#!/usr/bin/env bash
# Build Debian rootfs images for QEMU exploit development via Docker buildx.
#
# Supports x86_64, i386, arm64, arm32 via Docker multiarch (binfmt_misc).
# Produces a raw ext4 image with systemd + sshd + networking ready for qmu.
#
# Output is eval-able:  eval $(tools/mkrootfs.sh --arch arm64)
#                        qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS"
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

# ---------------------------------------------------------------------------
# cache gate
#
# A hit requires the image AND a stamp whose recorded build key equals this
# run's. Three deliberate exceptions, each of which must SAY so -- silence on a
# hit whose options may not match is exactly bug #51:
#   * --no-cache skips the gate entirely.
#   * a stamped image whose key differs from this run's gets named: the note
#     lists the requested options and the run rebuilds with them.
#   * a directory written before stamps existed holds an image built under the
#     old contract, which routed EVERY build here regardless of options -- so
#     its options are unrecorded and unknown. A default-shaped request may
#     still serve it (that keeps pre-existing caches valid), but prints a note
#     saying the options are unverified. Any non-default request is routed to
#     its own keyed directory above and never sees a legacy image.
# The stamp is written exactly once, atomically (temp file + rename), right
# after the new image itself is published the same way. A build that fails
# before that point never touches the previous (image, stamp) pair, so it
# stays exactly as coherent as it was; a build that fails cannot manufacture
# a stamp that certifies an image it never finished.
# ---------------------------------------------------------------------------
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
      # recorded pubkey hash against whatever key is on disk right now.
      if [[ -z "$SSH_KEY_ARG" && -f "$OUTDIR/id_ed25519.pub" ]]; then
        local recorded_pubkey current_pubkey
        recorded_pubkey="$(sed -n 's/^ssh_pubkey_sha256=//p' "$STAMP_OUT" | head -n1)"
        current_pubkey="$(sha256sum -- "$OUTDIR/id_ed25519.pub" | awk '{print $1}')"
        if [[ -n "$recorded_pubkey" && "$recorded_pubkey" != "$current_pubkey" ]]; then
          MISMATCH_NOTE="$(printf 'cached image at %q was built with a different SSH key than the one now at %s (its public half changed since the build)' \
            "$OUTDIR/rootfs.img" "$OUTDIR/id_ed25519")"
          return 1
        fi
      fi
      return 0
    fi
    MISMATCH_NOTE="$(printf 'cached image at %q was built with different options than requested (requested: size=%s packages=%s ssh-key=%s)' \
      "$OUTDIR/rootfs.img" "$SIZE" "${PACKAGES:-<none>}" "${SSH_KEY_ARG:-<generated>}")"
    return 1
  fi
  # No stamp: only the legacy default path may serve an unstamped image.
  if [[ "$DEFAULT_SHAPE" == true ]]; then
    LEGACY_NOTE="$(printf 'cached image at %q has no completion stamp; it was built before option tracking existed, so its --packages/--size/--ssh-key are UNVERIFIED (use --no-cache to force a rebuild with the current request)' \
      "$OUTDIR/rootfs.img")"
    return 0
  fi
  return 1
}

if [[ "$NO_CACHE" == false ]] && cache_hit; then
  log "cached rootfs found at $OUTDIR/rootfs.img"
  [[ -z "$LEGACY_NOTE" ]] || log "note: $LEGACY_NOTE"
  echo "ROOTFS=$OUTDIR/rootfs.img"
  if [[ -n "$SSH_KEY_ARG" ]]; then
    echo "SSH_KEY=$SSH_KEY_ARG"
  elif [[ -f "$OUTDIR/id_ed25519" ]]; then
    echo "SSH_KEY=$OUTDIR/id_ed25519"
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
  if ! docker run --rm --platform "$PLATFORM" debian:${RELEASE}-slim true 2>/dev/null; then
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
  -f - "$local_ctx" <<'DOCKERFILE'
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
  "; then
  :
else
  RC=$?
  log "ext4 image creation failed (exit $RC)"
  log "fallback: trying sudo mke2fs..."
  ROOTDIR="$(mktemp -d)"
  docker export "$CID" | sudo tar -x -C "$ROOTDIR"
  sudo mke2fs -F -q -t ext4 -d "$ROOTDIR" -L qmu-root \
    "$OUTDIR/rootfs.img.part" "$SIZE"
  sudo chown "$(id -u):$(id -g)" "$OUTDIR/rootfs.img.part"
fi
mv -f -- "$OUTDIR/rootfs.img.part" "$OUTDIR/rootfs.img"

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
if [[ -f "$OUTDIR/rootfs.img" ]]; then
  # completion stamp -- written LAST, and only here. Its existence plus a
  # matching build key is what makes this directory a cache hit; it is
  # assembled beside the final name and renamed into place so even a kill
  # during the write cannot leave a partial stamp that parses.
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
  mv -f "$STAMP_OUT.part" "$STAMP_OUT"
  step "Rootfs ready: $OUTDIR/rootfs.img"
  echo "ROOTFS=$OUTDIR/rootfs.img"
  echo "SSH_KEY=$PRIVKEY"
else
  die "build appeared to succeed but $OUTDIR/rootfs.img not found"
fi
