#!/usr/bin/env bash
# Build a genuine Ubuntu *target* for PoC validation under qmu.
#
# Unlike tools/mkrootfs.sh (which builds a Debian rootfs to pair with a kernel
# from tools/kbuild.sh), this produces a matched set: Ubuntu's own -generic
# kernel at a pinned ABI, its version-matched modules, its real userland and
# hardening defaults, its .config and System.map, and optionally its debug
# symbols from ddebs.
#
# Fidelity is the point. A PoC result is only a statement about Ubuntu if the
# LSM stack, the KASLR, and the sysctl defaults are the real ones -- so nothing
# is relaxed unless --relax-hardening is passed, and that fact is recorded four
# ways so it cannot be mistaken for a fidelity run.
#
# Output is eval-able:
#   eval $(tools/mktarget.sh --suite noble --kernel-abi ga)
#   qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
#              --profile "$PROFILE"
set -euo pipefail

MKTARGET_VERSION="1"

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
CACHE="${QMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/qmu}"
ARCH="x86_64"
SUITE="noble"
FLAVOUR="generic"
KERNEL_ABI_SPEC="ga"
KERNEL_VERSION_PIN=""
SIZE="${QMU_TARGET_SIZE:-4G}"
SSH_KEY_ARG=""
PACKAGES=""
OUTDIR_OVERRIDE=""
NO_CACHE=false
VERBOSE=false
LIST_ABIS=false
SYMBOLS="none"          # none | vmlinux | full
MODULES_EXTRA=true
HEADERS=false
INITRAMFS=false
RELAX=false
UNPRIV_USER="ubuntu"

DDEBS_MIRROR="${QMU_DDEBS_MIRROR:-http://ddebs.ubuntu.com}"

# ---------------------------------------------------------------------------
# helpers -- every one of these writes to stderr. stdout carries ONLY the
# eval-able assignments (kbuild.sh:311 has the same rule; docker build -q
# prints a sha to stdout and would otherwise corrupt the block).
# ---------------------------------------------------------------------------
die()  { echo "mktarget: error: $*" >&2; exit 2; }
step() { echo "=== [$(date +%H:%M:%S)] $* ===" >&2; }
log()  { echo "mktarget: $*" >&2; }
warn() { echo "mktarget: warning: $*" >&2; }

usage() {
  cat >&2 <<'EOF'
Usage: mktarget.sh [OPTIONS]

Build a genuine Ubuntu target (kernel + rootfs + symbols) for PoC validation
under qmu.

Optional:
  --suite SUITE            Ubuntu suite (default: noble)
  --arch ARCH              x86_64 (default) or arm64
  --flavour FLAVOUR        generic (default), lowlatency, generic-64k
  --kernel-abi SPEC        ga (default) | latest | latest-with-symbols | 6.8.0-31
  --kernel-version VER     Exact deb version (e.g. 6.8.0-31.31); wins over
                           --kernel-abi
  --list-abis              Print the installable ABI table (with dbgsym
                           availability) and exit
  --symbols[=MODE]         Fetch debug symbols from ddebs. MODE is vmlinux
                           (default) or full. ~1.9 GB installed.
  --no-modules-extra       Skip linux-modules-extra (default: install it)
  --headers                Install linux-headers (default: no)
  --initramfs              Generate an initrd and emit INITRD= (default: no;
                           all boot-critical drivers are built in)
  --relax-hardening        Disable Ubuntu's kptr/dmesg/bpf/userns/perf
                           restrictions. Results are then NOT statements about
                           the real target.
  --unpriv-user NAME       Unprivileged PoC user (default: ubuntu)
  --size SIZE              Image size (default: 4G)
  --packages PKGS          Comma-separated extra apt packages
  --ssh-key PATH           Existing ed25519 private key (needs PATH.pub)
  --outdir DIR             Override output directory
  --no-cache               Rebuild even if the cached target is complete
  --verbose                Show Docker build output
  -h, --help               Show this help

Environment:
  QMU_CACHE_DIR            Override ~/.cache/qmu (shared with kbuild/mkrootfs)
  QMU_TARGET_SIZE          Default image size (overridden by --size)
  QMU_DDEBS_MIRROR         Override http://ddebs.ubuntu.com

Output (eval-able):
  KERNEL= ROOTFS= SSH_KEY= CONFIG= SYSTEM_MAP= KERNEL_ABI= KERNEL_RELEASE=
  KERNEL_DEB_VERSION= PROFILE= QMU_TOML= TARGET_MANIFEST=
  VMLINUX=   (only with --symbols, and only if a dbgsym exists)
  INITRD=    (only with --initramfs)

Examples:
  tools/mktarget.sh --list-abis
  eval $(tools/mktarget.sh --suite noble --kernel-abi ga)
  eval $(tools/mktarget.sh --kernel-abi latest-with-symbols --symbols)
EOF
  exit 2
}

# ---------------------------------------------------------------------------
# parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite)           SUITE="$2"; shift 2 ;;
    --arch)            ARCH="$2"; shift 2 ;;
    --flavour)         FLAVOUR="$2"; shift 2 ;;
    --kernel-abi)      KERNEL_ABI_SPEC="$2"; shift 2 ;;
    --kernel-version)  KERNEL_VERSION_PIN="$2"; shift 2 ;;
    --list-abis)       LIST_ABIS=true; shift ;;
    --symbols)         SYMBOLS="vmlinux"; shift ;;
    --symbols=*)       SYMBOLS="${1#*=}"; shift ;;
    --modules-extra)   MODULES_EXTRA=true; shift ;;
    --no-modules-extra) MODULES_EXTRA=false; shift ;;
    --headers)         HEADERS=true; shift ;;
    --initramfs)       INITRAMFS=true; shift ;;
    --relax-hardening) RELAX=true; shift ;;
    --unpriv-user)     UNPRIV_USER="$2"; shift 2 ;;
    --size)            SIZE="$2"; shift 2 ;;
    --packages)        PACKAGES="$2"; shift 2 ;;
    --ssh-key)         SSH_KEY_ARG="$2"; shift 2 ;;
    --outdir)          OUTDIR_OVERRIDE="$2"; shift 2 ;;
    --no-cache)        NO_CACHE=true; shift ;;
    --verbose)         VERBOSE=true; shift ;;
    -h|--help)         usage ;;
    *)                 die "unknown argument: $1" ;;
  esac
done

case "$SYMBOLS" in
  none|vmlinux|full) ;;
  *) die "unsupported --symbols mode: $SYMBOLS (expected: vmlinux, full)" ;;
esac

case "$FLAVOUR" in
  generic|lowlatency|generic-64k) ;;
  *) die "unsupported --flavour: $FLAVOUR (expected: generic, lowlatency, generic-64k)" ;;
esac

# ---------------------------------------------------------------------------
# arch validation and mapping
#
# Ubuntu ships no i386 kernel since 18.04 (noble binary-i386 has zero
# linux-image packages), and while armhf does have linux-image-<ABI>-generic
# (no "unsigned" variant), qmu's arm32 MMIO virtio-blk topology is unverified
# against an Ubuntu kernel and ddebs coverage on ports is too thin to build a
# workflow on. Reject both with the actual reason rather than a generic error.
# ---------------------------------------------------------------------------
case "$ARCH" in
  x86_64)
    PLATFORM="linux/amd64"; DEBARCH="amd64"; ROOT_DEV="/dev/sda"
    MIRROR="http://archive.ubuntu.com/ubuntu"; CONSOLE_TTY="ttyS0"
    QEMU_ARCH="x86_64"; MACHINE_EXTRA=""
    ;;
  arm64)
    PLATFORM="linux/arm64"; DEBARCH="arm64"; ROOT_DEV="/dev/vda"
    MIRROR="http://ports.ubuntu.com/ubuntu-ports"; CONSOLE_TTY="ttyAMA0"
    QEMU_ARCH="aarch64"; MACHINE_EXTRA='extra_args = ["-M", "virt", "-cpu", "cortex-a57"]'
    ;;
  i386)
    die "i386 has no Ubuntu kernel (noble binary-i386 ships zero linux-image
  packages; Ubuntu dropped i386 kernels after 18.04).
  For an i386 guest use: tools/kbuild.sh --arch i386 + tools/mkrootfs.sh --arch i386"
    ;;
  arm32|armhf)
    die "arm32 targets are not supported yet.
  Ubuntu does ship linux-image-<ABI>-generic for armhf (no 'unsigned' variant),
  but qmu's arm32 MMIO virtio-blk topology is unverified against an Ubuntu
  kernel and ddebs coverage on ports is too thin.
  For an arm32 guest use: tools/kbuild.sh --arch arm32 + tools/mkrootfs.sh --arch arm32"
    ;;
  *) die "unsupported --arch: $ARCH (expected: x86_64, arm64)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl not found in PATH"

# ---------------------------------------------------------------------------
# archive index fetching + ABI resolution
#
# Done host-side with curl over the pocket Packages.gz (~1-6 MB) so no docker
# is needed to answer --list-abis or to pin an ABI. Deb versions are not the
# ABI doubled predictably (6.8.0-31.31 but 6.8.0-53.55), so the version always
# comes from the index and is never reconstructed.
# ---------------------------------------------------------------------------
IDXDIR="$(mktemp -d)"
cleanup_idx() { [[ -n "${IDXDIR:-}" ]] && rm -rf -- "$IDXDIR"; }
trap cleanup_idx EXIT

# fetch_index <pocket> -> path to decompressed Packages, or empty on failure
fetch_index() {
  local pocket="$1" out="$IDXDIR/pkg-$1"
  if [[ -f "$out" ]]; then printf '%s' "$out"; return 0; fi
  local url="$MIRROR/dists/$pocket/main/binary-$DEBARCH/Packages.gz"
  if curl -sSfL --max-time 180 "$url" 2>/dev/null | gunzip > "$out" 2>/dev/null; then
    printf '%s' "$out"
  else
    rm -f -- "$out"
    printf ''
  fi
}

fetch_ddebs_index() {
  local pocket="$1" out="$IDXDIR/ddeb-$1"
  if [[ -f "$out" ]]; then printf '%s' "$out"; return 0; fi
  local url="$DDEBS_MIRROR/dists/$pocket/main/binary-$DEBARCH/Packages.gz"
  if curl -sSfL --max-time 180 "$url" 2>/dev/null | gunzip > "$out" 2>/dev/null; then
    printf '%s' "$out"
  else
    rm -f -- "$out"
    printf ''
  fi
}

# kernel_rows <packages-file> -> "<abi> <debversion> <pkgname>" per line
#
# Matches both linux-image-unsigned-<ABI>-<flavour> and the plain
# linux-image-<ABI>-<flavour> name (armhf has only the latter), preferring
# unsigned when both exist for the same ABI.
kernel_rows() {
  local pkgs="$1"
  [[ -n "$pkgs" && -f "$pkgs" ]] || return 0
  awk -v fl="$FLAVOUR" '
    function flush() {
      if (pkg != "" && ver != "") {
        if (pkg ~ "^linux-image-unsigned-[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+-" fl "$" ||
            pkg ~ "^linux-image-[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+-" fl "$") {
          abi = pkg
          sub(/^linux-image-unsigned-/, "", abi)
          sub(/^linux-image-/, "", abi)
          sub("-" fl "$", "", abi)
          print abi, ver, pkg
        }
      }
      pkg = ""; ver = ""
    }
    /^Package: /{ pkg = $2; next }
    /^Version: / { if (ver == "") ver = $2; next }
    /^[[:space:]]*$/ { flush(); next }
    END { flush() }
  ' "$pkgs" | sort -u
}

# dbgsym_abis <ddebs-packages-file> -> one ABI per line
dbgsym_abis() {
  local pkgs="$1"
  [[ -n "$pkgs" && -f "$pkgs" ]] || return 0
  awk -v fl="$FLAVOUR" '
    /^Package: / {
      pkg = $2
      if (pkg ~ "^linux-image-unsigned-[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+-" fl "-dbgsym$") {
        abi = pkg
        sub(/^linux-image-unsigned-/, "", abi)
        sub("-" fl "-dbgsym$", "", abi)
        print abi
      }
    }
  ' "$pkgs" | sort -u
}

POCKETS=("$SUITE" "$SUITE-updates" "$SUITE-security")

collect_raw_rows() {
  local p idx
  for p in "${POCKETS[@]}"; do
    idx="$(fetch_index "$p")"
    [[ -n "$idx" ]] || continue
    kernel_rows "$idx" | while read -r abi ver pkg; do
      printf '%s\t%s\t%s\t%s\n' "$abi" "$ver" "$pkg" "$p"
    done
  done
}

# One row per ABI. The same ABI legitimately appears up to four times -- both
# linux-image-unsigned-<ABI>-<flavour> and the plain linux-image-<ABI>-<flavour>
# exist, and -updates and -security carry the same build. Collapse to the best
# candidate: prefer the unsigned package (it is the raw, directly bootable
# vmlinuz), then the release pocket (never pruned), then the highest deb version
# (6.17.0-42 ships as both .42 and .42+1).
dedup_rows() {
  sort -t$'\t' -k1,1V -k2,2V |
  awk -F'\t' -v suite="$SUITE" '
    {
      abi = $1; ver = $2; pkg = $3; pocket = $4
      unsigned = (pkg ~ /^linux-image-unsigned-/) ? 0 : 1
      if      (pocket == suite)              prank = 0
      else if (pocket == suite "-updates")   prank = 1
      else                                   prank = 2
      score = unsigned "," prank
      if (!(abi in best) || score <= bestscore[abi]) {
        best[abi] = abi "\t" ver "\t" pkg "\t" pocket
        bestscore[abi] = score
      }
    }
    END { for (a in best) print best[a] }
  ' |
  sort -t$'\t' -k1,1V
}

collect_all_rows() { collect_raw_rows | dedup_rows; }

collect_all_dbgsym() {
  local p idx
  for p in "$SUITE" "$SUITE-updates" "$SUITE-security"; do
    idx="$(fetch_ddebs_index "$p")"
    [[ -n "$idx" ]] || continue
    dbgsym_abis "$idx"
  done
}

# ---------------------------------------------------------------------------
# --list-abis
# ---------------------------------------------------------------------------
if [[ "$LIST_ABIS" == true ]]; then
  step "Querying $MIRROR for $SUITE/$DEBARCH $FLAVOUR kernels"
  ROWS="$(collect_all_rows || true)"
  [[ -n "$ROWS" ]] || die "no $FLAVOUR kernels found for $SUITE/$DEBARCH at $MIRROR"
  DBG="$(collect_all_dbgsym || true)"
  {
    printf '%-14s %-18s %-18s %s\n' "ABI" "DEB VERSION" "POCKET" "DBGSYM"
    while IFS=$'\t' read -r abi ver pkg pocket; do
      [[ -n "$abi" ]] || continue
      # here-string, not a pipe: grep -q exits on first match, and the EPIPE
      # that gives the writer would flip this test under pipefail.
      if grep -qx -- "$abi" <<<"$DBG"; then has="yes"; else has="no"; fi
      printf '%-14s %-18s %-18s %s\n' "$abi" "$ver" "$pocket" "$has"
    done < <(printf '%s\n' "$ROWS")
  } >&2
  log "release pocket '$SUITE' is never pruned; '-updates' ABIs and their"
  log "dbgsym can disappear. --kernel-abi ga pins the release-pocket ABI."
  exit 0
fi

# ---------------------------------------------------------------------------
# resolve the ABI we are going to build
# ---------------------------------------------------------------------------
resolve_abi() {
  local rows dbg idx

  if [[ -n "$KERNEL_VERSION_PIN" ]]; then
    rows="$(collect_all_rows || true)"
    while IFS=$'\t' read -r abi ver pkg pocket; do
      if [[ "$ver" == "$KERNEL_VERSION_PIN" ]]; then
        printf '%s\t%s\t%s\t%s\n' "$abi" "$ver" "$pkg" "$pocket"; return 0
      fi
    done < <(printf '%s\n' "$rows")
    die "deb version '$KERNEL_VERSION_PIN' not found for $SUITE/$DEBARCH $FLAVOUR.
  Run: $0 --suite $SUITE --arch $ARCH --list-abis"
  fi

  case "$KERNEL_ABI_SPEC" in
    ga)
      # release pocket only -- deterministic forever, since release pockets are
      # never pruned, and the ABI most likely to still have a dbgsym.
      idx="$(fetch_index "$SUITE")"
      [[ -n "$idx" ]] || die "cannot fetch $MIRROR/dists/$SUITE/main/binary-$DEBARCH/Packages.gz"
      rows="$(kernel_rows "$idx" \
                | while read -r a v p; do printf '%s\t%s\t%s\t%s\n' "$a" "$v" "$p" "$SUITE"; done \
                | dedup_rows | tail -1)"
      [[ -n "$rows" ]] || die "no $FLAVOUR kernel in release pocket '$SUITE' for $DEBARCH"
      printf '%s\n' "$rows"
      ;;
    latest)
      rows="$(collect_all_rows | tail -1 || true)"
      [[ -n "$rows" ]] || die "no $FLAVOUR kernel found for $SUITE/$DEBARCH"
      printf '%s\n' "$rows"
      ;;
    latest-with-symbols)
      dbg="$(collect_all_dbgsym || true)"
      [[ -n "$dbg" ]] || die "no dbgsym found at $DDEBS_MIRROR for $SUITE/$DEBARCH $FLAVOUR"
      rows=""
      while IFS=$'\t' read -r abi ver pkg pocket; do
        [[ -n "$abi" ]] || continue
        if grep -qx -- "$abi" <<<"$dbg"; then
          rows="$abi	$ver	$pkg	$pocket"
        fi
      done < <(collect_all_rows | sort -V -u)
      [[ -n "$rows" ]] || die "no ABI has both a kernel and a dbgsym for $SUITE/$DEBARCH $FLAVOUR"
      printf '%s\n' "$rows"
      ;;
    *)
      # literal ABI, e.g. 6.8.0-31
      [[ "$KERNEL_ABI_SPEC" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]] ||
        die "unrecognised --kernel-abi: $KERNEL_ABI_SPEC
  Expected: ga | latest | latest-with-symbols | <major.minor.patch-abinum>"
      rows=""
      while IFS=$'\t' read -r abi ver pkg pocket; do
        if [[ "$abi" == "$KERNEL_ABI_SPEC" ]]; then
          # prefer the unsigned package name when both exist
          if [[ -z "$rows" || "$pkg" == linux-image-unsigned-* ]]; then
            rows="$abi	$ver	$pkg	$pocket"
          fi
        fi
      done < <(collect_all_rows)
      [[ -n "$rows" ]] || die "ABI '$KERNEL_ABI_SPEC' not found for $SUITE/$DEBARCH $FLAVOUR.
  Run: $0 --suite $SUITE --arch $ARCH --list-abis"
      printf '%s\n' "$rows"
      ;;
  esac
}

step "Resolving kernel ABI ($SUITE/$DEBARCH, flavour $FLAVOUR, spec '$KERNEL_ABI_SPEC')"
IFS=$'\t' read -r KABI KDEBVER KPKG KPOCKET <<<"$(resolve_abi)"
[[ -n "$KABI" && -n "$KDEBVER" ]] || die "ABI resolution failed"
KREL="$KABI-$FLAVOUR"
log "resolved: ABI=$KABI deb=$KDEBVER pkg=$KPKG pocket=$KPOCKET"

# dbgsym availability -- checked BEFORE building, so --symbols never discovers
# a missing ddeb after a 10-minute build.
DBGSYM_AVAILABLE=false
if [[ "$SYMBOLS" != "none" ]]; then
  DBG_ALL="$(collect_all_dbgsym || true)"
  if grep -qx -- "$KABI" <<<"$DBG_ALL"; then
    DBGSYM_AVAILABLE=true
    log "dbgsym available for $KABI (~1.9 GB unpacked; only vmlinux is extracted)"
  else
    {
      echo "mktarget: error: --symbols requested but no dbgsym exists for ABI $KABI."
      echo "  ddebs prunes aggressively and symbol availability is uncorrelated with"
      echo "  recency. ABIs that currently DO have symbols:"
      collect_all_dbgsym | sed 's/^/    /'
      echo "  Use --kernel-abi latest-with-symbols, or one of the ABIs above."
    } >&2
    exit 2
  fi
fi

# ---------------------------------------------------------------------------
# output directory + cache completeness
#
# The -relaxed suffix keeps a hardening-relaxed image from ever being served
# from cache to a fidelity request (or vice versa).
# ---------------------------------------------------------------------------
VARIANT="$KABI-$FLAVOUR"
[[ "$RELAX" == true ]] && VARIANT="$VARIANT-relaxed"

if [[ -n "$OUTDIR_OVERRIDE" ]]; then
  OUTDIR="$OUTDIR_OVERRIDE"
else
  OUTDIR="$CACHE/targets/ubuntu/$SUITE/$ARCH/$VARIANT"
fi

KERNEL_OUT="$OUTDIR/vmlinuz-$KREL"
CONFIG_OUT="$OUTDIR/config-$KREL"
SYSMAP_OUT="$OUTDIR/System.map-$KREL"
VMLINUX_OUT="$OUTDIR/vmlinux-$KREL"
INITRD_OUT="$OUTDIR/initrd.img-$KREL"
ROOTFS_OUT="$OUTDIR/rootfs.img"
TOML_OUT="$OUTDIR/qmu.toml"
MANIFEST_OUT="$OUTDIR/target.json"

emit_outputs() {
  printf 'KERNEL=%q\n'             "$KERNEL_OUT"
  printf 'ROOTFS=%q\n'             "$ROOTFS_OUT"
  printf 'SSH_KEY=%q\n'            "$PRIVKEY"
  printf 'CONFIG=%q\n'             "$CONFIG_OUT"
  printf 'SYSTEM_MAP=%q\n'         "$SYSMAP_OUT"
  printf 'KERNEL_ABI=%q\n'         "$KABI"
  printf 'KERNEL_RELEASE=%q\n'     "$KREL"
  printf 'KERNEL_DEB_VERSION=%q\n' "$KDEBVER"
  printf 'PROFILE=%q\n'            "ubuntu-target"
  printf 'QMU_TOML=%q\n'           "$TOML_OUT"
  printf 'TARGET_MANIFEST=%q\n'    "$MANIFEST_OUT"
  [[ -f "$VMLINUX_OUT" ]] && printf 'VMLINUX=%q\n' "$VMLINUX_OUT"
  [[ -f "$INITRD_OUT" ]]  && printf 'INITRD=%q\n'  "$INITRD_OUT"
  return 0
}

# Every emitted product must exist -- mkrootfs.sh's single-file `-f rootfs.img`
# check (mkrootfs.sh:116) reports a half-built target as cached, which is a bug
# pattern, not a shortcut.
cache_complete() {
  [[ -f "$KERNEL_OUT"   ]] &&
  [[ -f "$ROOTFS_OUT"   ]] &&
  [[ -f "$CONFIG_OUT"   ]] &&
  [[ -f "$SYSMAP_OUT"   ]] &&
  [[ -f "$TOML_OUT"     ]] &&
  [[ -f "$MANIFEST_OUT" ]] &&
  { [[ "$SYMBOLS" == "none" ]] || [[ -f "$VMLINUX_OUT" ]]; } &&
  { [[ "$INITRAMFS" == false ]] || [[ -f "$INITRD_OUT" ]]; }
}

# ---------------------------------------------------------------------------
# SSH key
# ---------------------------------------------------------------------------
if [[ -n "$SSH_KEY_ARG" ]]; then
  PRIVKEY="$SSH_KEY_ARG"
  [[ -f "$PRIVKEY" ]] || die "SSH private key not found: $PRIVKEY"
  [[ -f "${PRIVKEY}.pub" ]] || die "SSH public key not found: ${PRIVKEY}.pub"
else
  PRIVKEY="$OUTDIR/id_ed25519"
fi

if [[ "$NO_CACHE" == false ]] && cache_complete && [[ -f "$PRIVKEY" ]]; then
  log "cached target found at $OUTDIR"
  emit_outputs
  exit 0
fi

mkdir -p "$OUTDIR"

if [[ -z "$SSH_KEY_ARG" && ! -f "$PRIVKEY" ]]; then
  step "Generating SSH keypair"
  ssh-keygen -t ed25519 -N '' -f "$PRIVKEY" -C "qmu-target-$SUITE-$KREL-$ARCH" >/dev/null
fi
chmod 600 "$PRIVKEY"
PUBKEY_CONTENT="$(cat "${PRIVKEY}.pub")"

# ---------------------------------------------------------------------------
# docker / binfmt preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found in PATH"

HOST_ARCH="$(uname -m)"
NEED_BINFMT=false
case "$ARCH" in
  x86_64) [[ "$HOST_ARCH" != "x86_64"  ]] && NEED_BINFMT=true ;;
  arm64)  [[ "$HOST_ARCH" != "aarch64" ]] && NEED_BINFMT=true ;;
esac
if [[ "$NEED_BINFMT" == true ]]; then
  if ! docker run --rm --platform "$PLATFORM" "ubuntu:$SUITE" true 2>/dev/null; then
    die "cannot run $PLATFORM containers. Register binfmt_misc emulators:
  docker run --rm --privileged tonistiigi/binfmt:latest --install all"
  fi
fi

# ---------------------------------------------------------------------------
# assemble the kernel package list
#
# Fully-formed name=version strings so apt pins exactly. The image package name
# comes from the index ($KPKG), which handles the armhf-style plain
# linux-image-<ABI>-<flavour> naming without a second guess.
# ---------------------------------------------------------------------------
KPKGS="$KPKG=$KDEBVER linux-modules-$KREL=$KDEBVER"
[[ "$MODULES_EXTRA" == true ]] && KPKGS="$KPKGS linux-modules-extra-$KREL=$KDEBVER"
[[ "$HEADERS" == true ]]       && KPKGS="$KPKGS linux-headers-$KREL=$KDEBVER"
[[ "$INITRAMFS" == true ]]     && KPKGS="$KPKGS initramfs-tools"

EXTRA_PACKAGES="${PACKAGES//,/ }"
IMAGE_TAG="qmu-target:${SUITE}-${ARCH}-${VARIANT}"

DOCKER_QUIET=""
[[ "$VERBOSE" == false ]] && DOCKER_QUIET="-q"

RELAX_FLAG=0
[[ "$RELAX" == true ]] && RELAX_FLAG=1
INITRAMFS_FLAG=0
[[ "$INITRAMFS" == true ]] && INITRAMFS_FLAG=1

HOSTNAME_GUEST="qmu-ubuntu"
[[ "$RELAX" == true ]] && HOSTNAME_GUEST="qmu-ubuntu-relaxed"

HARDENING="fidelity"
[[ "$RELAX" == true ]] && HARDENING="relaxed"

BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# No early `exit` in awk and the curl failure is swallowed: an awk that stops
# reading makes curl die with 23 (failed writing body), which pipefail would
# turn into a fatal error for a purely informational field.
ARCHIVE_DATE="$( { curl -sSfL --max-time 60 "$MIRROR/dists/$KPOCKET/Release" 2>/dev/null || true; } \
  | awk -F': ' '/^Date: /{ if (d == "") d = $2 } END { print d }')"

# Baked into the guest at build time rather than injected afterwards: guestfish
# needs a libguestfs appliance that is routinely unavailable (mode-600 /boot
# kernels), and a stamp that silently fails to appear is worse than none. The
# host-side target.json is the authoritative copy and additionally carries the
# artifact hashes, which cannot be known before the image exists.
GUEST_STAMP="$(cat <<JSON
{
  "mktarget_version": "$MKTARGET_VERSION",
  "built_at": "$BUILT_AT",
  "distro": "ubuntu",
  "suite": "$SUITE",
  "pocket": "$KPOCKET",
  "arch": "$ARCH",
  "flavour": "$FLAVOUR",
  "abi": "$KABI",
  "kernel_release": "$KREL",
  "kernel_deb_version": "$KDEBVER",
  "kernel_image_package": "$KPKG",
  "archive_release_date": "${ARCHIVE_DATE:-unknown}",
  "hardening": "$HARDENING",
  "modules_extra": $MODULES_EXTRA,
  "unpriv_user": "$UNPRIV_USER",
  "note": "authoritative copy with artifact hashes is target.json in the build outdir"
}
JSON
)"

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
local_ctx=""
CID=""
ROOTDIR=""

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  [[ -n "$ROOTDIR"   ]] && sudo rm -rf -- "$ROOTDIR"
  [[ -n "$CID"       ]] && docker rm "$CID" >/dev/null 2>&1
  [[ -n "$local_ctx" ]] && rm -rf -- "$local_ctx"
  cleanup_idx
  exit "$status"
}
trap cleanup EXIT

local_ctx="$(mktemp -d)"

step "Building target container image ($IMAGE_TAG, platform $PLATFORM)"
docker build $DOCKER_QUIET \
  --platform "$PLATFORM" \
  --build-arg "SUITE=$SUITE" \
  --build-arg "KPKGS=$KPKGS" \
  --build-arg "KREL=$KREL" \
  --build-arg "PUBKEY=$PUBKEY_CONTENT" \
  --build-arg "ROOT_DEV=$ROOT_DEV" \
  --build-arg "CONSOLE_TTY=$CONSOLE_TTY" \
  --build-arg "EXTRA_PACKAGES=$EXTRA_PACKAGES" \
  --build-arg "UNPRIV_USER=$UNPRIV_USER" \
  --build-arg "RELAX=$RELAX_FLAG" \
  --build-arg "DO_INITRAMFS=$INITRAMFS_FLAG" \
  --build-arg "HOSTNAME_GUEST=$HOSTNAME_GUEST" \
  --build-arg "GUEST_STAMP=$GUEST_STAMP" \
  -t "$IMAGE_TAG" \
  -f - "$local_ctx" >&2 <<'DOCKERFILE'
ARG SUITE=noble
FROM ubuntu:${SUITE}
ARG KPKGS
ARG KREL
ARG PUBKEY
ARG ROOT_DEV=/dev/sda
ARG CONSOLE_TTY=ttyS0
ARG EXTRA_PACKAGES=""
ARG UNPRIV_USER=ubuntu
ARG RELAX=0
ARG DO_INITRAMFS=0
ARG HOSTNAME_GUEST=qmu-ubuntu
ARG GUEST_STAMP="{}"

ENV DEBIAN_FRONTEND=noninteractive

# Defang the postinst hooks that assume a real /boot and a bootloader.
# The structural fix is --no-install-recommends below: linux-image-unsigned
# lists grub and initramfs-tools only as Recommends, so without them
# /etc/kernel/postinst.d never exists and the trigger that would run
# update-grub / update-initramfs is never registered. policy-rc.d and
# kernel-img.conf are belt-and-braces for linux-base's linux-update-symlinks.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod +x /usr/sbin/policy-rc.d \
 && printf 'do_symlinks = no\nlink_in_boot = no\ndo_bootloader = no\n' \
      > /etc/kernel-img.conf

# The userland IS part of the target.
#   apparmor -- ships /usr/lib/sysctl.d/10-apparmor.conf, the ONLY source of
#               kernel.apparmor_restrict_unprivileged_userns=1. Without this
#               package the restriction is silently 0 and every
#               unprivileged-userns PoC succeeds for the wrong reason.
#   procps   -- ships 10-kernel-hardening.conf (kptr_restrict=1).
#   systemd-sysv + udev + dbus -- so systemd-sysctl actually applies sysctl.d.
# gcc/libc6-dev/make are for `qmu compile` and are an acknowledged, recorded
# fidelity break.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ${KPKGS} \
      apparmor apparmor-utils procps \
      systemd-sysv udev dbus \
      openssh-server sudo \
      gcc libc6-dev make \
      iproute2 ethtool kmod ca-certificates \
      ${EXTRA_PACKAGES} \
 && rm -rf /var/lib/apt/lists/*

RUN depmod -a "${KREL}" || true

RUN mkdir -p /root/.ssh \
 && printf '%s\n' "$PUBKEY" > /root/.ssh/authorized_keys \
 && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys \
 && passwd -d root \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
 && printf '%s / ext4 defaults 0 1\n' "$ROOT_DEV" > /etc/fstab \
 && systemd-machine-id-setup || true

# An unprivileged user is mandatory: without it every PoC runs as root and LPE
# results are meaningless. uid 1000 'ubuntu' already exists in the base image.
RUN if ! id -u "$UNPRIV_USER" >/dev/null 2>&1; then \
      useradd -m -s /bin/bash -u 1000 "$UNPRIV_USER"; \
    fi \
 && mkdir -p "/home/$UNPRIV_USER/.ssh" \
 && printf '%s\n' "$PUBKEY" > "/home/$UNPRIV_USER/.ssh/authorized_keys" \
 && chmod 700 "/home/$UNPRIV_USER/.ssh" \
 && chmod 600 "/home/$UNPRIV_USER/.ssh/authorized_keys" \
 && chown -R "$UNPRIV_USER:$UNPRIV_USER" "/home/$UNPRIV_USER" \
 && echo "$UNPRIV_USER:$UNPRIV_USER" | chpasswd

# Network, hostname and resolv.conf are all configured at BOOT, not here:
# docker bind-mounts /etc/resolv.conf and /etc/hostname during RUN, so anything
# written to them at build time is discarded by `docker export`.
#
# The interface is discovered rather than hardcoded to eth0. mkrootfs.sh
# hardcodes it and gets away with it on Debian, but that is an assumption about
# udev naming, not a guarantee -- and when it is wrong the only symptom is an
# SSH timeout with a fully booted guest, which is expensive to diagnose. The
# script reports what it actually found on the console either way.
#
# 10.0.2.3 is slirp's DNS and 10.0.2.10 its gateway (both wrong under
# net_backend=passt, exactly like the static route mkrootfs.sh also bakes in).
RUN printf '%s\n' \
 '#!/bin/sh' \
 'NAME="$1"' \
 'IFACE=$(ip -o link | awk -F": " "\$2 != \"lo\" {print \$2; exit}")' \
 '[ -n "$IFACE" ] || IFACE=eth0' \
 'IFACE=${IFACE%%@*}' \
 'ethtool -K "$IFACE" tx off rx off tso off gso off gro off sg off 2>/dev/null' \
 'ip link set "$IFACE" up' \
 'ip addr add 10.0.2.15/24 dev "$IFACE" 2>/dev/null' \
 'ip route add default via 10.0.2.10 2>/dev/null' \
 'rm -f /etc/resolv.conf' \
 'printf "nameserver 10.0.2.3\n" > /etc/resolv.conf' \
 'if [ -n "$NAME" ]; then printf "%s\n" "$NAME" > /etc/hostname; hostname "$NAME" 2>/dev/null; fi' \
 'echo "QMU-NET-READY iface=$IFACE $(ip -4 -o addr show "$IFACE" 2>/dev/null)" > /dev/console' \
 'echo "QMU-NET-LINKS $(ip -o link | tr "\n" "|")" > /dev/console' \
 > /usr/local/sbin/qmu-net-setup \
 && chmod +x /usr/local/sbin/qmu-net-setup

RUN printf '%s\n' \
 '[Unit]' \
 'Description=qmu static net + offload fixup' \
 'After=network-pre.target systemd-udevd.service' \
 'Before=ssh.service network.target' \
 '[Service]' \
 'Type=oneshot' \
 'RemainAfterExit=yes' \
 "ExecStart=/usr/local/sbin/qmu-net-setup ${HOSTNAME_GUEST}" \
 '[Install]' \
 'WantedBy=multi-user.target' \
 > /etc/systemd/system/qmu-net.service \
 && systemctl enable qmu-net.service \
 && systemctl enable ssh.service 2>/dev/null || true

# Serial autologin, so a boot failure is diagnosable without SSH.
RUN mkdir -p "/etc/systemd/system/serial-getty@${CONSOLE_TTY}.service.d" \
 && printf '%s\n' \
      '[Service]' \
      'ExecStart=' \
      'ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM' \
      > "/etc/systemd/system/serial-getty@${CONSOLE_TTY}.service.d/autologin.conf" \
 && systemctl enable "serial-getty@${CONSOLE_TTY}.service" 2>/dev/null || true

# Hardening relaxation -- opt-in only, and recorded so it cannot be mistaken
# for a fidelity run. /etc/sysctl.d/99-* is the override path that noble's own
# /usr/lib/sysctl.d/10-apparmor.conf documents.
RUN if [ "$RELAX" = "1" ]; then \
      printf '%s\n' \
        'kernel.kptr_restrict = 0' \
        'kernel.dmesg_restrict = 0' \
        'kernel.perf_event_paranoid = 1' \
        'kernel.unprivileged_bpf_disabled = 0' \
        'kernel.apparmor_restrict_unprivileged_userns = 0' \
        'kernel.yama.ptrace_scope = 0' \
        > /etc/sysctl.d/99-qmu-relax.conf; \
      printf '%s\n' \
        '*** qmu target built with --relax-hardening ***' \
        'Ubuntu hardening sysctls are DISABLED on this image.' \
        'Results here are NOT statements about the real Ubuntu target.' \
        > /etc/motd; \
      printf '%s\n' \
        '[Unit]' \
        'Description=qmu relaxed-hardening banner' \
        '[Service]' \
        'Type=oneshot' \
        'ExecStart=/bin/sh -c "echo QMU-TARGET-RELAXED hardening sysctls disabled > /dev/console"' \
        '[Install]' \
        'WantedBy=multi-user.target' \
        > /etc/systemd/system/qmu-relaxed.service; \
      systemctl enable qmu-relaxed.service; \
    fi

RUN if [ "$DO_INITRAMFS" = "1" ]; then \
      update-initramfs -c -k "${KREL}" || echo "mktarget: update-initramfs failed (non-fatal)" >&2; \
    fi

# securityfs is what backs /sys/kernel/security/lsm and `aa-status`. systemd
# ships sys-kernel-{config,debug,tracing}.mount but no securityfs unit -- on a
# real Ubuntu box it gets mounted from the initramfs, which this target
# deliberately does not have. Without it AppArmor still ENFORCES (the userns
# restriction works regardless), but the LSM stack is invisible to
# introspection, which reads as "no LSMs" and is exactly the wrong conclusion.
# It must be a *service*, not a .mount unit: systemd refuses to create mount
# units for API filesystems ("Cannot create mount unit for API file system
# /sys/kernel/security. Refusing."), reserving that path for its own internal
# mounting -- which in practice only happens from an initramfs, and this target
# deliberately has none. An /etc/fstab line does not work either; the
# fstab-generator skips /sys paths for the same reason.
#
# Ordered before apparmor.service so AppArmor can actually load its profiles.
# Note that AppArmor ENFORCES either way (the unprivileged-userns restriction
# works with securityfs unmounted); what this fixes is that the LSM stack is
# otherwise invisible to `aa-status` and /sys/kernel/security/lsm, which reads
# as "no LSMs" and is exactly the wrong conclusion to hand a PoC author.
RUN printf '%s\n' \
 '[Unit]' \
 'Description=qmu: mount securityfs' \
 'DefaultDependencies=no' \
 'Before=sysinit.target apparmor.service' \
 'ConditionPathExists=/sys/kernel/security' \
 '[Service]' \
 'Type=oneshot' \
 'RemainAfterExit=yes' \
 'ExecStart=-/bin/mount -t securityfs securityfs /sys/kernel/security' \
 '[Install]' \
 'WantedBy=sysinit.target' \
 > /etc/systemd/system/qmu-securityfs.service \
 && systemctl enable qmu-securityfs.service 2>/dev/null || true

RUN printf '%s\n' "$GUEST_STAMP" > /etc/qmu-target.json

# policy-rc.d must not ship inside the guest.
#
# /.dockerenv is NOT removed here -- it cannot be. Docker bind-mounts it during
# RUN (like /etc/resolv.conf and /etc/hostname), so an rm here affects the mount
# namespace, not the exported layer. It is stripped from the exported tarball
# instead, just before mke2fs. It matters because it makes systemd-detect-virt
# report "docker" on the booted VM, whereupon AppArmor's init logs "Not starting
# AppArmor in container" and loads NONE of its 102 profiles while still exiting
# 0 -- a silent fidelity break of exactly the kind this tool exists to prevent.
RUN rm -f /usr/sbin/policy-rc.d
DOCKERFILE

# ---------------------------------------------------------------------------
# extract kernel artifacts
# ---------------------------------------------------------------------------
step "Creating container and extracting kernel artifacts"
CID="$(docker create --platform "$PLATFORM" "$IMAGE_TAG")"

docker cp "$CID:/boot/vmlinuz-$KREL"    "$OUTDIR/vmlinuz-$KREL.raw" >/dev/null
docker cp "$CID:/boot/config-$KREL"     "$CONFIG_OUT" >/dev/null
docker cp "$CID:/boot/System.map-$KREL" "$SYSMAP_OUT" >/dev/null

if [[ "$INITRAMFS" == true ]]; then
  if docker cp "$CID:/boot/initrd.img-$KREL" "$INITRD_OUT" >/dev/null 2>&1; then
    log "initrd extracted: $INITRD_OUT"
  else
    warn "no initrd was produced; INITRD= will not be emitted (boot does not need one)"
  fi
fi

# arm64 /boot/vmlinuz is plain gzip (verified: 1f8b magic, despite
# CONFIG_EFI_ZBOOT=y Ubuntu does not ship a PE/zboot container here), and
# qemu-system-aarch64 -kernel wants the raw Image. x86_64 is a bzImage and is
# used verbatim. Decide on the magic bytes rather than on the arch, so a future
# change in either direction is handled.
MAGIC="$(od -An -tx1 -N2 "$OUTDIR/vmlinuz-$KREL.raw" | tr -d ' \n')"
if [[ "$MAGIC" == "1f8b" ]]; then
  step "Decompressing gzip kernel image -> raw Image"
  gunzip -c "$OUTDIR/vmlinuz-$KREL.raw" > "$KERNEL_OUT"
  rm -f "$OUTDIR/vmlinuz-$KREL.raw"
else
  mv "$OUTDIR/vmlinuz-$KREL.raw" "$KERNEL_OUT"
fi

# ---------------------------------------------------------------------------
# debug symbols from ddebs
#
# Stream-extracted: the ddeb is ~1.9 GB unpacked and we want exactly one file
# out of it, so it must never land in a container layer or on disk whole.
# ---------------------------------------------------------------------------
if [[ "$SYMBOLS" != "none" && "$DBGSYM_AVAILABLE" == true ]]; then
  step "Fetching debug symbols from $DDEBS_MIRROR (mode: $SYMBOLS)"
  KEEP_MODULES=0
  [[ "$SYMBOLS" == "full" ]] && KEEP_MODULES=1

  # Only list ddebs pockets that actually exist. ddebs carries <suite> and
  # <suite>-updates but NOT <suite>-security, and a sources.list entry for a
  # pocket with no Release file makes `apt-get update` fail hard ("does not
  # have a Release file"), which took the whole extraction down with it.
  DDEBS_POCKETS=""
  for p in "$SUITE" "$SUITE-updates" "$SUITE-security"; do
    if curl -sSfL --max-time 60 -o /dev/null "$DDEBS_MIRROR/dists/$p/Release" 2>/dev/null; then
      DDEBS_POCKETS="$DDEBS_POCKETS $p"
    fi
  done
  DDEBS_POCKETS="${DDEBS_POCKETS# }"
  [[ -n "$DDEBS_POCKETS" ]] || die "no usable ddebs pocket found at $DDEBS_MIRROR for $SUITE"
  log "ddebs pockets: $DDEBS_POCKETS"
  if docker run --rm --platform "$PLATFORM" \
      -v "$OUTDIR:/output" \
      -e "SUITE=$SUITE" -e "KREL=$KREL" -e "KDEBVER=$KDEBVER" \
      -e "FLAVOUR=$FLAVOUR" -e "KABI=$KABI" \
      -e "DDEBS_MIRROR=$DDEBS_MIRROR" -e "KEEP_MODULES=$KEEP_MODULES" \
      -e "DDEBS_POCKETS=$DDEBS_POCKETS" \
      "ubuntu:$SUITE" bash -c '
        set -eo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
          ubuntu-dbgsym-keyring curl libarchive-tools >/dev/null
        # http:// deliberately -- https://ddebs.ubuntu.com 301-redirects to it
        : > /etc/apt/sources.list.d/ddebs.list
        for p in $DDEBS_POCKETS; do
          printf "deb [signed-by=/usr/share/keyrings/ubuntu-dbgsym-keyring.gpg] %s %s main\n" \
            "$DDEBS_MIRROR" "$p" >> /etc/apt/sources.list.d/ddebs.list
        done
        apt-get update -qq
        PKG="linux-image-unsigned-${KREL}-dbgsym"
        URI=$(apt-get download --print-uris "${PKG}=${KDEBVER}" 2>/dev/null \
              | awk "{gsub(/^.|.\$/, \"\", \$1); print \$1}" | head -1)
        [ -n "$URI" ] || { echo "could not resolve ddeb URI for $PKG" >&2; exit 1; }
        echo "ddeb: $URI" >&2
        curl -sSfL "$URI" \
          | bsdtar -xOf - "data.tar*" \
          | bsdtar -xOf - "./usr/lib/debug/boot/vmlinux-${KREL}" \
          > "/output/vmlinux-${KREL}"
        [ -s "/output/vmlinux-${KREL}" ] || { echo "vmlinux extraction produced an empty file" >&2; exit 1; }
        if [ "$KEEP_MODULES" = "1" ]; then
          curl -sSfL "$URI" | bsdtar -xOf - "data.tar*" \
            | bsdtar -xf - -C /output "./usr/lib/debug/lib/modules/${KREL}" || true
        fi
      ' >&2; then
    log "vmlinux extracted: $VMLINUX_OUT"
  else
    # Fatal, not a warning. The dbgsym index was already checked above, so a
    # failure here is an infrastructure fault, and --symbols is a flag that
    # promises an artifact -- quietly emitting a target without it would let a
    # GDB session start against symbols the caller believes they asked for.
    rm -f "$VMLINUX_OUT"
    die "debug-symbol extraction failed for $KREL (dbgsym $KDEBVER exists in the index).
  Re-run with --verbose for the container output, or drop --symbols to build
  the target without them."
  fi
fi

DWARF_COMP_DIR=""
if [[ -f "$VMLINUX_OUT" ]] && command -v objdump >/dev/null 2>&1; then
  DWARF_COMP_DIR="$( { objdump --dwarf=info --dwarf-depth=1 "$VMLINUX_OUT" 2>/dev/null || true; } \
    | awk '/DW_AT_comp_dir/ { if (d == "") { sub(/.*:[[:space:]]*/, ""); d = $0 } } END { print d }')"
  [[ -n "$DWARF_COMP_DIR" ]] && log "DWARF comp_dir: $DWARF_COMP_DIR"
fi

# ---------------------------------------------------------------------------
# export container filesystem -> raw ext4 image
# ---------------------------------------------------------------------------
step "Creating raw ext4 image ($SIZE)"
# The if/else form is required under `set -euo pipefail` so a failed helper
# pipeline can fall back to host sudo mke2fs instead of aborting immediately.
if docker export "$CID" | docker run --rm -i \
  -v "$OUTDIR:/output" \
  "ubuntu:$SUITE" \
  bash -c "
    mkdir /rootfs && tar -x -C /rootfs &&
    rm -f /rootfs/.dockerenv /rootfs/run/.containerenv &&
    apt-get update -qq && apt-get install -y -qq e2fsprogs >/dev/null 2>&1 &&
    mke2fs -F -q -t ext4 -d /rootfs -L qmu-ubuntu /output/rootfs.img $SIZE
  " >&2; then
  :
else
  RC=$?
  log "ext4 image creation failed (exit $RC)"
  log "fallback: trying sudo mke2fs..."
  ROOTDIR="$(mktemp -d)"
  docker export "$CID" | sudo tar -x -C "$ROOTDIR" >&2
  sudo rm -f "$ROOTDIR/.dockerenv" "$ROOTDIR/run/.containerenv"
  sudo mke2fs -F -q -t ext4 -d "$ROOTDIR" -L qmu-ubuntu "$ROOTFS_OUT" "$SIZE" >&2
  sudo chown "$(id -u):$(id -g)" "$ROOTFS_OUT" >&2
fi

[[ -f "$ROOTFS_OUT" ]] || die "build appeared to succeed but $ROOTFS_OUT not found"

# ---------------------------------------------------------------------------
# manifest -- attribution. Also baked into the guest at /etc/qmu-target.json
# so `qmu exec 'cat /etc/qmu-target.json'` attributes a LIVE result.
# ---------------------------------------------------------------------------
step "Writing manifest and qmu.toml"

KERNEL_SHA="$(sha256sum "$KERNEL_OUT" | awk '{print $1}')"
ROOTFS_SHA="$(sha256sum "$ROOTFS_OUT" | awk '{print $1}')"
DBGVER="null"
[[ -f "$VMLINUX_OUT" ]] && DBGVER="\"$KDEBVER\""

cat > "$MANIFEST_OUT" <<JSON
{
  "mktarget_version": "$MKTARGET_VERSION",
  "built_at": "$BUILT_AT",
  "distro": "ubuntu",
  "suite": "$SUITE",
  "pocket": "$KPOCKET",
  "arch": "$ARCH",
  "debarch": "$DEBARCH",
  "flavour": "$FLAVOUR",
  "abi": "$KABI",
  "kernel_release": "$KREL",
  "kernel_deb_version": "$KDEBVER",
  "kernel_image_package": "$KPKG",
  "archive_release_date": "${ARCHIVE_DATE:-unknown}",
  "mirror": "$MIRROR",
  "dbgsym_version": $DBGVER,
  "dwarf_comp_dir": "${DWARF_COMP_DIR:-}",
  "hardening": "$HARDENING",
  "modules_extra": $MODULES_EXTRA,
  "headers": $HEADERS,
  "initramfs": $INITRAMFS,
  "unpriv_user": "$UNPRIV_USER",
  "root_dev": "$ROOT_DEV",
  "console": "$CONSOLE_TTY",
  "kernel_sha256": "$KERNEL_SHA",
  "rootfs_sha256": "$ROOTFS_SHA"
}
JSON

# ---------------------------------------------------------------------------
# generated qmu.toml
#
# main has no [boot] table (config.py:40-62 _FIXED_SCHEMA is
# machine/drive/ssh/gdb only, and _validate_toml rejects unknown top-level
# keys), so this file cannot describe the kernel -- pass --kernel "$KERNEL"
# and --profile "$PROFILE" explicitly. [profiles.*] IS valid, and carries the
# arch-correct console/root device.
# ---------------------------------------------------------------------------
CMDLINE_BASE="console=$CONSOLE_TTY root=$ROOT_DEV rw earlyprintk=serial net.ifnames=0"

cat > "$TOML_OUT" <<TOML
# Generated by tools/mktarget.sh -- Ubuntu $SUITE $KREL ($ARCH)
#
# Fidelity contract:
#   ubuntu-target  -- the ONLY profile under which "this PoC works on Ubuntu"
#                     may be claimed. KASLR on, full LSM stack, Ubuntu sysctl
#                     defaults. Nothing disabled.
#   ubuntu-debug   -- nokaslr, for reversing/GDB. A working exploit here is NOT
#                     a working exploit on Ubuntu; KASLR bypass is a separate
#                     proof obligation.
#   ubuntu-trigger -- KASLR and LSMs untouched, panics on the first oops/warn so
#                     \`qmu crash\` gets one clean report. Triage, not exploitation.
#
# main has no [boot] table, so the kernel must be passed on the command line:
#   qmu launch --config $TOML_OUT --kernel $KERNEL_OUT --profile ubuntu-target

[machine]
arch = "$QEMU_ARCH"
memory = "4G"
cpus = 2
$MACHINE_EXTRA

[drive]
rootfs = "$ROOTFS_OUT"
format = "raw"

[ssh]
key = "$PRIVKEY"
user = "root"

[profiles.ubuntu-target]
cmdline = "$CMDLINE_BASE"

[profiles.ubuntu-debug]
cmdline = "$CMDLINE_BASE nokaslr"

[profiles.ubuntu-trigger]
cmdline = "$CMDLINE_BASE panic_on_oops=1 panic_on_warn=1"
TOML

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
step "Target ready: $OUTDIR"
log "Ubuntu $SUITE $KREL ($KDEBVER, pocket $KPOCKET, hardening=$HARDENING)"
if [[ "$RELAX" == true ]]; then
  warn "=============================================================="
  warn "HARDENING RELAXED. This image's kptr/dmesg/bpf/userns/perf"
  warn "restrictions are OFF. Results are NOT statements about the"
  warn "real Ubuntu target. Guest hostname is '$HOSTNAME_GUEST'."
  warn "=============================================================="
fi
emit_outputs
