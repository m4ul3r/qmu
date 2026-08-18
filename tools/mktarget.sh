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

MKTARGET_VERSION="2"

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
  --relax-hardening        Disable the guest's kptr/dmesg/bpf/userns/perf/
                           ptrace_scope restrictions and enable unprivileged
                           userfaultfd. Results are then NOT statements about
                           the real target. Builds a SEPARATE image (-relaxed
                           cache dir), so expect a full build, not a cache hit.
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

INDEX_FAULT_FILE="$IDXDIR/index-fault"

# A fetch fault is RECORDED rather than raised on the spot. fetch_index runs
# inside command substitutions, several of them under `|| true`, where a `die`
# would only kill the subshell and be swallowed -- so the main shell checks this
# marker after every collection instead.
note_index_fault() { printf '%s\n' "$1" >> "$INDEX_FAULT_FILE"; }

assert_no_index_fault() {
  [[ -f "$INDEX_FAULT_FILE" ]] || return 0
  {
    echo "mktarget: error: could not read the archive index:"
    sed 's/^/    /' "$INDEX_FAULT_FILE"
    echo "  This is a fetch fault, not an empty pocket. Resolving an ABI from a"
    echo "  partial view of the archive would silently break the pin -- e.g."
    echo "  --kernel-abi latest returning the GA kernel because -updates timed"
    echo "  out -- so the build stops here rather than producing a result that"
    echo "  cannot be attributed. Retry when the mirror is reachable."
  } >&2
  exit 2
}

# _fetch_gz <url> <outfile>
#   0 -> fetched and decompressed
#   2 -> the server answered 404: this index legitimately does not exist
#   1 -> anything else (timeout, DNS, 5xx, truncated body)
#
# The 1/2 split is the point. Both used to collapse into "empty", so a
# -updates pocket that merely timed out looked identical to one with no
# kernels in it, and `--kernel-abi latest` would happily return the GA kernel
# as "latest". Retried on faults only; a 404 is definitive and returns at once.
_fetch_gz() {
  local url="$1" out="$2" attempt code
  # Separate `local`: all words of a `local` are expanded before the builtin
  # assigns any of them, so "$out.gz.part" on the line above would have expanded
  # $out from the enclosing scope (empty) and written ./.gz.part instead.
  local tmp="$out.gz.part"
  for attempt in 1 2 3; do
    code="$(curl -sSL --max-time 180 -o "$tmp" -w '%{http_code}' "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]] && gunzip -c "$tmp" > "$out" 2>/dev/null && [[ -s "$out" ]]; then
      rm -f -- "$tmp"
      return 0
    fi
    rm -f -- "$out" "$tmp"
    [[ "$code" == "404" ]] && return 2
    [[ "$attempt" -lt 3 ]] && sleep $((attempt * 2))
  done
  return 1
}

# fetch_index <pocket> -> path to decompressed Packages, or "" if the pocket
# genuinely has no index. A fetch fault records a fault marker and yields "",
# which assert_no_index_fault then turns into a hard failure in the main shell.
fetch_index() {
  local pocket="$1" out="$IDXDIR/pkg-$1" url rc=0
  if [[ -f "$out" ]]; then printf '%s' "$out"; return 0; fi
  if [[ -f "$IDXDIR/absent-pkg-$pocket" ]]; then printf ''; return 0; fi
  url="$MIRROR/dists/$pocket/main/binary-$DEBARCH/Packages.gz"
  _fetch_gz "$url" "$out" || rc=$?
  case "$rc" in
    0) printf '%s' "$out" ;;
    2) : > "$IDXDIR/absent-pkg-$pocket"
       warn "no binary-$DEBARCH index for pocket '$pocket' (404); treating it as empty"
       printf '' ;;
    *) note_index_fault "$url"
       printf '' ;;
  esac
}

# Absence is normal here, not an error: ddebs carries <suite> and
# <suite>-updates but no <suite>-security. A fault is still a fault.
fetch_ddebs_index() {
  local pocket="$1" out="$IDXDIR/ddeb-$1" url rc=0
  if [[ -f "$out" ]]; then printf '%s' "$out"; return 0; fi
  if [[ -f "$IDXDIR/absent-ddeb-$pocket" ]]; then printf ''; return 0; fi
  url="$DDEBS_MIRROR/dists/$pocket/main/binary-$DEBARCH/Packages.gz"
  _fetch_gz "$url" "$out" || rc=$?
  case "$rc" in
    0) printf '%s' "$out" ;;
    2) : > "$IDXDIR/absent-ddeb-$pocket"
       printf '' ;;
    *) note_index_fault "$url"
       printf '' ;;
  esac
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
  assert_no_index_fault
  [[ -n "$ROWS" ]] || die "no $FLAVOUR kernels found for $SUITE/$DEBARCH at $MIRROR"
  DBG="$(collect_all_dbgsym || true)"
  assert_no_index_fault
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
# Before trusting the answer: a pocket that faulted rather than being empty
# makes every resolution above unsound, most of all `latest`.
assert_no_index_fault
[[ -n "$KABI" && -n "$KDEBVER" ]] || die "ABI resolution failed"
KREL="$KABI-$FLAVOUR"
log "resolved: ABI=$KABI deb=$KDEBVER pkg=$KPKG pocket=$KPOCKET"

# dbgsym availability -- resolved lazily, by assert_dbgsym_available below.
#
# It is checked before any building, so --symbols never discovers a missing ddeb
# after a 10-minute build, but NOT before the cache gate: a run whose symbols are
# already cached needs nothing from ddebs, and probing anyway cost a pointless
# round-trip and could fail outright on a target whose dbgsym has since been
# pruned -- refusing to repair a manifest over symbols that are already on disk.
DBGSYM_AVAILABLE=false

assert_dbgsym_available() {
  DBG_ALL="$(collect_all_dbgsym || true)"
  assert_no_index_fault
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
}

# none < vmlinux < full
symbols_rank() {
  case "$1" in
    full)    printf '2' ;;
    vmlinux) printf '1' ;;
    *)       printf '0' ;;
  esac
}

# What the directory ACTUALLY holds, which is not the same as what this run
# asked for. A metadata-only repair invoked without --symbols must not erase the
# record of symbols still sitting there, or the next --symbols run redownloads
# 1.9 GB to recover what it never lost. Claims are backed by the files: a level
# is only recorded if the artifacts for it are present.
effective_symbols() {
  local want="$1"
  if [[ "$(symbols_rank "$want")" -ge 2 && -f "$VMLINUX_OUT" && -d "$MODDBG_OUT" ]]; then
    printf 'full'
  elif [[ "$(symbols_rank "$want")" -ge 1 && -f "$VMLINUX_OUT" ]]; then
    printf 'vmlinux'
  else
    printf 'none'
  fi
}

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
# The cache directory is named for the ABI, flavour and hardening only, because
# that is the part a human wants to find on disk. Every OTHER build-affecting
# input goes into this digest, which the completion stamp records and every
# cache hit re-checks. Without it the directory alone decided identity, so a run
# differing only in --headers / --packages / --size / --unpriv-user / --ssh-key,
# or one whose ABI now resolves to a NEWER deb version, was handed the old image
# while stdout advertised the newly requested parameters.
#
# --symbols is deliberately NOT in the digest: symbols are a side artifact next
# to the image rather than part of it, so adding them to an existing target must
# not force the rootfs to be rebuilt. The stamp tracks symbol completeness.
# ---------------------------------------------------------------------------
build_key_material() {
  printf 'mktarget\t%s\n'  "$MKTARGET_VERSION"
  printf 'suite\t%s\n'     "$SUITE"
  printf 'arch\t%s\n'      "$ARCH"
  printf 'flavour\t%s\n'   "$FLAVOUR"
  printf 'abi\t%s\n'       "$KABI"
  printf 'debver\t%s\n'    "$KDEBVER"
  printf 'imagepkg\t%s\n'  "$KPKG"
  printf 'relax\t%s\n'     "$RELAX"
  printf 'modext\t%s\n'    "$MODULES_EXTRA"
  printf 'headers\t%s\n'   "$HEADERS"
  printf 'initramfs\t%s\n' "$INITRAMFS"
  printf 'size\t%s\n'      "$SIZE"
  printf 'unpriv\t%s\n'    "$UNPRIV_USER"
  # order-insensitive: --packages a,b and --packages b,a build the same image
  printf 'packages\t%s\n' \
    "$(printf '%s' "${PACKAGES//,/ }" | tr ' ' '\n' | sed '/^$/d' | sort -u | paste -sd, -)"
  # Only an EXTERNALLY supplied key can disagree with what is baked into a
  # cached image; the generated key lives inside the output directory and is by
  # construction the one that directory's image already trusts.
  if [[ -n "$SSH_KEY_ARG" ]]; then
    printf 'sshpub\t%s\n' "$(awk '{print $1, $2}' "${SSH_KEY_ARG}.pub")"
  else
    printf 'sshpub\tgenerated\n'
  fi
}
BUILD_KEY="$(build_key_material | sha256sum | awk '{print $1}')"

# ---------------------------------------------------------------------------
# output directory
#
# The -relaxed suffix keeps a hardening-relaxed image from ever being served
# from cache to a fidelity request (or vice versa). A build that differs from
# the defaults in any other way gets its own directory keyed by the build
# digest, so alternating (say) --headers with a plain build caches both instead
# of rebuilding each time. Correctness does not rest on this -- the stamp check
# does -- it only stops two legitimate variants from evicting each other.
# ---------------------------------------------------------------------------
VARIANT="$KABI-$FLAVOUR"
[[ "$RELAX" == true ]] && VARIANT="$VARIANT-relaxed"

DEFAULT_SHAPE=true
[[ "$MODULES_EXTRA"  == true   ]] || DEFAULT_SHAPE=false
[[ "$HEADERS"        == false  ]] || DEFAULT_SHAPE=false
[[ "$INITRAMFS"      == false  ]] || DEFAULT_SHAPE=false
[[ "$SIZE"           == "4G"   ]] || DEFAULT_SHAPE=false
[[ "$UNPRIV_USER"    == ubuntu ]] || DEFAULT_SHAPE=false
[[ -z "$PACKAGES"    ]]           || DEFAULT_SHAPE=false
[[ -z "$SSH_KEY_ARG" ]]           || DEFAULT_SHAPE=false
[[ "$DEFAULT_SHAPE"  == true   ]] || VARIANT="$VARIANT-${BUILD_KEY:0:8}"

if [[ -n "$OUTDIR_OVERRIDE" ]]; then
  OUTDIR="$OUTDIR_OVERRIDE"
else
  OUTDIR="$CACHE/targets/ubuntu/$SUITE/$ARCH/$VARIANT"
fi

KERNEL_OUT="$OUTDIR/vmlinuz-$KREL"
CONFIG_OUT="$OUTDIR/config-$KREL"
SYSMAP_OUT="$OUTDIR/System.map-$KREL"
VMLINUX_OUT="$OUTDIR/vmlinux-$KREL"
MODDBG_OUT="$OUTDIR/usr/lib/debug/lib/modules/$KREL"
INITRD_OUT="$OUTDIR/initrd.img-$KREL"
ROOTFS_OUT="$OUTDIR/rootfs.img"
TOML_OUT="$OUTDIR/qmu.toml"
MANIFEST_OUT="$OUTDIR/target.json"
PACKAGES_OUT="$OUTDIR/packages.tsv"
STAMP_OUT="$OUTDIR/.mktarget-stamp"

if [[ -n "$SSH_KEY_ARG" ]]; then
  PRIVKEY="$SSH_KEY_ARG"
else
  PRIVKEY="$OUTDIR/id_ed25519"
fi

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
  # Both of these are gated on the FLAG, not merely on the file existing. An
  # artifact cached by an earlier run that asked for it would otherwise be
  # emitted by a run that did not, so the presence of $VMLINUX / $INITRD could
  # not answer "did I get this THIS run" -- which is exactly what the documented
  # contract invites callers to assume.
  [[ "$SYMBOLS"   != none && -f "$VMLINUX_OUT" ]] && printf 'VMLINUX=%q\n' "$VMLINUX_OUT"
  [[ "$INITRAMFS" == true && -f "$INITRD_OUT"  ]] && printf 'INITRD=%q\n'  "$INITRD_OUT"
  return 0
}

# stamp_get <field> -> value, or "" when the stamp has no such field
stamp_get() {
  [[ -f "$STAMP_OUT" ]] || return 0
  awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$STAMP_OUT"
}

# A cache hit must prove three things, each of which has produced a wrong answer
# in practice:
#
#   1. the build FINISHED.  The stamp is removed before a build starts and
#      written last, so an interrupted build can never look complete. The old
#      check tested `-f` on each product, which an aborted rebuild satisfies
#      with a mix of truncated new files and stale old ones.
#   2. it is the SAME build. The recorded build key must equal this run's.
#   3. the files are INTACT. Recorded byte sizes must still match -- that is
#      what catches a truncated artifact, which `-f` happily accepts and which
#      then boots into an unexplained kernel panic.
#
# Split from the symbol check below because the two have different remedies: a
# stale or damaged IMAGE has to be rebuilt, whereas missing SYMBOLS can be
# fetched onto the image already sitting there. The stamp keeps them in
# different row types for the same reason -- `artifact` rows describe the image
# and are walked here, `symbol` rows describe the debug files and are walked by
# cache_symbols_ok. Recording vmlinux as an `artifact` put it in this loop, so
# deleting or truncating just the symbols failed the IMAGE check and triggered a
# full rebuild -- replacing the very rootfs a result had been measured on, to
# repair a file that sits beside it.
cache_image_ok() {
  local stamp_ver stamp_key path want have

  [[ -f "$STAMP_OUT" ]] || return 1

  stamp_ver="$(stamp_get version)"
  [[ "$stamp_ver" == "$MKTARGET_VERSION" ]] || {
    log "cache rejected: stamp is from mktarget v${stamp_ver:-0}, this is v$MKTARGET_VERSION"
    return 1
  }

  stamp_key="$(stamp_get build_key)"
  [[ "$stamp_key" == "$BUILD_KEY" ]] || {
    log "cache rejected: cached target was built with different options"
    return 1
  }

  # Only files that cannot be produced without the container are checked here,
  # because failing this function costs a rootfs rebuild. Three classes exist:
  #
  #   image     kernel, rootfs, config, System.map, initrd, packages.tsv
  #             -- derived from the container, unrecoverable without one
  #   symbol    vmlinux, the module debug tree -- refetchable from ddebs
  #   meta      target.json, qmu.toml -- regenerable on the host from what is
  #             already on disk, so a damaged one is a rewrite, never a rebuild
  #
  # Symbol and meta paths are excluded BY PATH rather than by row label, because
  # stamps written by earlier versions filed all of them as `artifact` and an
  # intact stamp is never rewritten while it keeps hitting. A label-only rule
  # would leave every already-built target still rebuilding its measured rootfs
  # to repair a file sitting beside it -- exactly what this split prevents --
  # and bumping the stamp version to dodge that would discard those images
  # outright, which is worse.
  while IFS=$'\t' read -r _ path want; do
    [[ -n "$path" ]] || continue
    have="$(stat -c %s -- "$path" 2>/dev/null || echo missing)"
    [[ "$have" == "$want" ]] || {
      log "cache rejected: $path is $have bytes, stamp recorded $want"
      return 1
    }
  done < <(awk -F'\t' -v vm="$VMLINUX_OUT" -v tm="$TOML_OUT" -v mf="$MANIFEST_OUT" \
             '$1 == "artifact" && $2 != vm && $2 != tm && $2 != mf' "$STAMP_OUT")

  return 0
}

# target.json and qmu.toml are rewritten on every reuse pass, so any mismatch
# here is repaired rather than rebuilt.
#
# This is what makes an interrupted symbols upgrade survivable. That path keeps
# the old stamp on purpose, but it rewrites target.json first -- and the file
# grows when dbgsym_version and the DWARF fields appear. A kill between those
# two writes therefore left a manifest the old stamp disagreed with, and while
# the manifest was an image-class artifact that disagreement condemned the
# rootfs. Writing them atomically only narrows that window; taking them out of
# the image class removes it.
cache_meta_ok() {
  local path want have
  while IFS=$'\t' read -r _ path want; do
    [[ -n "$path" ]] || continue
    have="$(stat -c %s -- "$path" 2>/dev/null || echo missing)"
    [[ "$have" == "$want" ]] || {
      log "metadata stale: $path is $have bytes, stamp recorded $want"
      return 1
    }
  done < <(awk -F'\t' -v tm="$TOML_OUT" -v mf="$MANIFEST_OUT" \
             '$1 == "meta" || ($1 == "artifact" && ($2 == tm || $2 == mf))' "$STAMP_OUT")
  return 0
}

# The module debug tree is a directory, not a file, so the artifact-size list
# cannot describe it. Its shape is recorded separately -- object count and total
# bytes -- because a bare `-d` test passes on a tree whose every .ko has been
# deleted, and --symbols=full would then be a cache hit with no module symbols.
# One colon-joined field, not two tab-separated ones: stamp_get returns a single
# column, so a two-field value came back truncated and never matched what was
# recomputed -- which quietly meant --symbols=full could not hit its own cache
# and refetched 1.9 GB on every invocation.
moddbg_shape() {
  local n b
  n="$(find "$MODDBG_OUT" -name '*.ko*' -type f 2>/dev/null | wc -l)"
  b="$(du -sb "$MODDBG_OUT" 2>/dev/null | awk '{print $1}')"
  printf '%s:%s' "$n" "${b:-0}"
}

cache_symbols_ok() {
  local stamp_symbols want_shape path want have

  stamp_symbols="$(stamp_get symbols)"
  # Asking for fewer symbols than are cached is satisfied; asking for more is
  # not. `full` needs the module debug tree that a `vmlinux` run never fetched.
  case "$SYMBOLS:$stamp_symbols" in
    none:*|vmlinux:vmlinux|vmlinux:full|full:full) ;;
    *) log "cached target has symbols=${stamp_symbols:-none}, --symbols=$SYMBOLS was asked for"
       return 1 ;;
  esac

  # A run that did not ask for symbols has no opinion about them: a damaged
  # vmlinux beside the image is irrelevant to it and must not cost it a rebuild.
  [[ "$SYMBOLS" != none ]] || return 0

  # The mirror image of the exclusion in cache_image_ok: a legacy stamp files
  # vmlinux under `artifact`, and it still has to be validated here -- otherwise
  # cache_image_ok skips it and nothing checks it at all, and a damaged legacy
  # vmlinux would be handed back as if it were intact. A stamp rewritten by this
  # version uses `symbol`; both are accepted, and the first upgrade a legacy
  # target takes rewrites it into the new form.
  while IFS=$'\t' read -r _ path want; do
    [[ -n "$path" ]] || continue
    have="$(stat -c %s -- "$path" 2>/dev/null || echo missing)"
    [[ "$have" == "$want" ]] || {
      log "symbols rejected: $path is $have bytes, stamp recorded $want"
      return 1
    }
  done < <(awk -F'\t' -v vm="$VMLINUX_OUT" \
             '$1 == "symbol" || ($1 == "artifact" && $2 == vm)' "$STAMP_OUT")

  if [[ "$SYMBOLS" == full ]]; then
    [[ -d "$MODDBG_OUT" ]] || { log "symbols rejected: $MODDBG_OUT is missing"; return 1; }
    want_shape="$(stamp_get moddbg)"
    [[ "$want_shape" == "$(moddbg_shape)" ]] || {
      log "symbols rejected: module debug tree is $(moddbg_shape), stamp recorded $want_shape"
      return 1
    }
  fi
  return 0
}

# A cached image is only usable if its key still is. The gate tested `-f`, so a
# zero-byte or truncated private key was a cache HIT: the run exited 0 and
# emitted SSH_KEY pointing at a file no ssh will ever load, and the failure
# surfaced later as an unexplained connection refusal against a guest that had
# booted perfectly.
#
# Scope: only the key this script generated, which lives inside the output
# directory and is by construction the one baked into that directory's image.
# An externally supplied --ssh-key belongs to the caller and is never inspected,
# rewritten or regenerated here.
privkey_usable() {
  [[ -f "$PRIVKEY" ]] || return 1
  [[ -z "$SSH_KEY_ARG" ]] || return 0
  ssh-keygen -y -P '' -f "$PRIVKEY" >/dev/null 2>&1
}

# The public half is derivable from the private half, so a missing or mismatched
# .pub is repairable in place rather than a reason to discard a working target.
ensure_pubkey() {
  local derived
  [[ -z "$SSH_KEY_ARG" ]] || return 0
  derived="$(ssh-keygen -y -P '' -f "$PRIVKEY" 2>/dev/null)" || return 1
  if [[ ! -f "${PRIVKEY}.pub" ]] || ! grep -qF -- "$derived" "${PRIVKEY}.pub"; then
    warn "recovering ${PRIVKEY}.pub from the private key"
    printf '%s qmu-target-%s-%s-%s\n' "$derived" "$SUITE" "$KREL" "$ARCH" > "${PRIVKEY}.pub"
  fi
  return 0
}

# Repairing what sits AROUND the image must never rebuild the image. Rebuilding
# re-runs apt, and only the KERNEL debs are version-pinned -- the userland moves
# with the archive, so a rebuild triggered by a missing vmlinux or a half-written
# manifest could hand back a different rootfs, with a different apparmor or
# procps, than the one the PoC result was measured against. Whenever the image
# itself checks out, everything else is refetched or regenerated in place.
# The two repair reasons are tracked separately. Collapsing them into one flag
# meant a stale manifest on a target whose symbols were perfectly intact still
# re-downloaded the 1.9 GB ddeb, because the extraction step keyed off "are we
# reusing" rather than "are the symbols short".
#
# CACHED_SYMBOLS is captured here, before anything in the directory is
# rewritten: it is what the stamp claimed on entry, and it is how a repair pass
# knows which symbols it must not forget.
REUSE_IMAGE=false
REFRESH_SYMBOLS=true
CACHED_SYMBOLS=""
PRIOR_SYMBOL_ROWS=""
PRIOR_MODDBG=""
if [[ "$NO_CACHE" == false ]] && cache_image_ok && privkey_usable; then
  CACHED_SYMBOLS="$(stamp_get symbols)"
  # The prior symbol expectations, kept so a pass that does NOT validate them
  # can carry them forward untouched. Legacy `artifact` rows for vmlinux are
  # normalised to `symbol` on the way through.
  PRIOR_SYMBOL_ROWS="$(awk -F'\t' -v vm="$VMLINUX_OUT" -v OFS='\t' \
    '$1 == "symbol" || ($1 == "artifact" && $2 == vm) { print "symbol", $2, $3 }' \
    "$STAMP_OUT")"
  PRIOR_MODDBG="$(stamp_get moddbg)"
  symbols_state_ok=false
  meta_state_ok=false
  cache_symbols_ok && symbols_state_ok=true
  cache_meta_ok    && meta_state_ok=true

  if [[ "$symbols_state_ok" == true && "$meta_state_ok" == true ]]; then
    ensure_pubkey || die "cannot derive a public key from $PRIVKEY"
    log "cached target found at $OUTDIR"
    emit_outputs
    exit 0
  fi

  REUSE_IMAGE=true
  REFRESH_SYMBOLS="$([[ "$symbols_state_ok" == true ]] && printf 'false' || printf 'true')"
  if [[ "$REFRESH_SYMBOLS" == true ]]; then
    log "image is cached and intact; refetching symbols, leaving the rootfs as built"
  else
    log "image and symbols are cached and intact; regenerating metadata only"
  fi
fi

# Only now, and only if something actually has to come from ddebs.
if [[ "$SYMBOLS" != none && "$REFRESH_SYMBOLS" == true ]]; then
  assert_dbgsym_available
fi

mkdir -p "$OUTDIR"

# From here on the directory is mid-build and must never satisfy a cache hit,
# even if this process is killed between two docker cp calls.
#
# Not on the reuse path: nothing there invalidates the image, so a failed symbol
# fetch or metadata rewrite must not condemn a good target to a full rebuild.
# Keeping the old stamp is safe precisely because symbols and metadata are no
# longer image-class -- a stamp that disagrees with them asks for a repair, not
# a rootfs. The stamp is replaced atomically at the end either way.
[[ "$REUSE_IMAGE" == true ]] || rm -f -- "$STAMP_OUT"

if [[ -z "$SSH_KEY_ARG" ]]; then
  # An unusable leftover has to be cleared, not built around: `! -f` alone left
  # a zero-byte or truncated key in place, and the image was then baked with
  # whatever stale .pub happened to sit next to it.
  if [[ -f "$PRIVKEY" ]] && ! privkey_usable; then
    warn "generated key $PRIVKEY is unusable; regenerating the pair"
    rm -f -- "$PRIVKEY" "${PRIVKEY}.pub"
  fi
  if [[ ! -f "$PRIVKEY" ]]; then
    step "Generating SSH keypair"
    ssh-keygen -t ed25519 -N '' -f "$PRIVKEY" -C "qmu-target-$SUITE-$KREL-$ARCH" >/dev/null
  fi
fi
chmod 600 "$PRIVKEY"
ensure_pubkey || die "cannot derive a public key from $PRIVKEY"
[[ -f "${PRIVKEY}.pub" ]] || die "SSH public key not found: ${PRIVKEY}.pub"
PUBKEY_CONTENT="$(cat "${PRIVKEY}.pub")"

# ---------------------------------------------------------------------------
# docker / binfmt preflight
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found in PATH"

HOST_ARCH="$(uname -m)"

# The mke2fs helper must run on the HOST platform, not the target's. It only
# untars an exported filesystem and writes an ext4 image, which is entirely
# arch-independent -- but after a cross-arch target build the local
# `ubuntu:<suite>` tag points at the target-arch image, so an unqualified
# `docker run` would execute the helper under qemu-user and spend minutes
# emulating `tar` and `mke2fs` for no reason. (mkrootfs.sh avoids this only by
# accident, by hardcoding debian:bookworm-slim.)
HELPER_PLATFORM=()
case "$HOST_ARCH" in
  x86_64)  HELPER_PLATFORM=(--platform linux/amd64) ;;
  aarch64) HELPER_PLATFORM=(--platform linux/arm64) ;;
esac

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
#
# Every field here MUST be deterministic given the cache key. It is passed as a
# build-arg, so a value that changes between runs invalidates BuildKit's cache
# from the ARG declaration onward and re-runs the whole apt install -- which
# under qemu-user emulation for a cross-arch target costs ~12 minutes on every
# rebuild. `built_at` and the pocket's mutable `archive_release_date` therefore
# live only in the host-side target.json.
GUEST_STAMP="$(cat <<JSON
{
  "mktarget_version": "$MKTARGET_VERSION",
  "distro": "ubuntu",
  "suite": "$SUITE",
  "pocket": "$KPOCKET",
  "arch": "$ARCH",
  "flavour": "$FLAVOUR",
  "abi": "$KABI",
  "kernel_release": "$KREL",
  "kernel_deb_version": "$KDEBVER",
  "kernel_image_package": "$KPKG",
  "hardening": "$HARDENING",
  "modules_extra": $MODULES_EXTRA,
  "unpriv_user": "$UNPRIV_USER",
  "note": "authoritative copy, with build time and artifact hashes, is target.json in the build outdir"
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

pkgver() { awk -F'\t' -v p="$1" '$1 == p { print $2; exit }' "$PACKAGES_OUT"; }

# ===========================================================================
# BEGIN image build -- skipped entirely by a symbols-only upgrade
#
# The body below is left at its original indentation on purpose: it contains
# `<<'DOCKERFILE'`, JSON and TOML heredocs, and indenting a non-`<<-` heredoc
# injects the leading whitespace into the file it writes. The matching
# "END image build" marker closes this guard.
# ===========================================================================
if [[ "$REUSE_IMAGE" == false ]]; then

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

# Root SSH is key-only.
#
# This used to run `passwd -d root` (delete root's password) together with
# PermitRootLogin yes and PermitEmptyPasswords yes, which authenticated ANY
# local process as root in the guest with no credential at all -- the listener
# is loopback-only, so the blast radius was the host, but a target whose root
# account is open to every process on the box is not a controlled measurement.
# The keypair this script generates is the only way in.
#
# The settings go in sshd_config.d rather than through sed on sshd_config:
# sshd takes the FIRST value it sees for a keyword and noble's sshd_config
# Includes that directory from its first line, so these win outright, and a
# keyword that is absent from the main file (rather than merely commented) is
# still set -- which sed cannot promise.
RUN set -e; \
    mkdir -p /root/.ssh /etc/ssh/sshd_config.d; \
    printf '%s\n' "$PUBKEY" > /root/.ssh/authorized_keys; \
    chmod 700 /root/.ssh; \
    chmod 600 /root/.ssh/authorized_keys; \
    passwd -l root; \
    printf '%s\n' \
      'PermitRootLogin prohibit-password' \
      'PubkeyAuthentication yes' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication no' \
      'PermitEmptyPasswords no' \
      > /etc/ssh/sshd_config.d/60-qmu.conf; \
    if ! grep -q '^Include /etc/ssh/sshd_config.d/' /etc/ssh/sshd_config; then \
      sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; \
    fi; \
    printf '%s / ext4 defaults 0 1\n' "$ROOT_DEV" > /etc/fstab; \
    systemd-machine-id-setup || true

# An unprivileged user is mandatory: without it every PoC runs as root and LPE
# results are meaningless.
#
# The base image already owns uid 1000 as 'ubuntu', so `useradd -u 1000` for any
# other --unpriv-user died with "UID 1000 is not unique" and took the build with
# it; the existing account is renamed instead, which keeps "the unprivileged
# user is uid 1000" true whatever it is called. A system account is refused
# rather than silently relabelled "unprivileged", which would have made every
# LPE result meaningless in the opposite direction.
RUN set -e; \
    case "$UNPRIV_USER" in \
      ''|root) echo "mktarget: --unpriv-user must name a non-root user" >&2; exit 1 ;; \
    esac; \
    if id -u "$UNPRIV_USER" >/dev/null 2>&1; then \
      uid="$(id -u "$UNPRIV_USER")"; \
      if [ "$uid" -ne 1000 ]; then \
        echo "mktarget: --unpriv-user '$UNPRIV_USER' already exists at uid $uid, not 1000." >&2; \
        echo "  The PoC user is documented as uid 1000. Accepting anything else" >&2; \
        echo "  would label an arbitrary account 'the unprivileged user' -- noble's" >&2; \
        echo "  nobody (65534, /usr/sbin/nologin) is the case that motivates this." >&2; \
        echo "  Pick a name that does not exist and it will be created at 1000." >&2; \
        exit 1; \
      fi; \
    else \
      existing="$(getent passwd 1000 | cut -d: -f1)"; \
      if [ -n "$existing" ]; then \
        oldhome="$(getent passwd "$existing" | cut -d: -f6)"; \
        [ -n "$oldhome" ] && mkdir -p "$oldhome"; \
        usermod -l "$UNPRIV_USER" -d "/home/$UNPRIV_USER" -m "$existing"; \
        groupmod -n "$UNPRIV_USER" "$existing" 2>/dev/null || true; \
        usermod -s /bin/bash "$UNPRIV_USER"; \
      else \
        useradd -m -s /bin/bash -u 1000 "$UNPRIV_USER"; \
      fi; \
    fi; \
    mkdir -p "/home/$UNPRIV_USER/.ssh"; \
    printf '%s\n' "$PUBKEY" > "/home/$UNPRIV_USER/.ssh/authorized_keys"; \
    chmod 700 "/home/$UNPRIV_USER/.ssh"; \
    chmod 600 "/home/$UNPRIV_USER/.ssh/authorized_keys"; \
    chown -R "$UNPRIV_USER:" "/home/$UNPRIV_USER"; \
    echo "$UNPRIV_USER:$UNPRIV_USER" | chpasswd; \
    id "$UNPRIV_USER" >&2

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
        'vm.unprivileged_userfaultfd = 1' \
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

# ---------------------------------------------------------------------------
# userland package inventory
#
# The kernel version alone does not describe the target. Whether an
# unprivileged-userns PoC is blocked depends on the apparmor package (it ships
# the only sysctl that sets it), kptr_restrict on procps, and whether sysctl.d
# is applied at all on systemd -- so a manifest that records only the kernel
# cannot attribute the hardening behaviour it is being cited for.
#
# Read from the container's dpkg database host-side rather than by running
# dpkg-query in the image: for a cross-arch target that would be another
# qemu-user process, and this needs to be free.
# ---------------------------------------------------------------------------
step "Recording userland package inventory"
docker cp "$CID:/var/lib/dpkg/status" "$OUTDIR/.dpkg-status" >/dev/null
awk -F': ' '
  function flush() {
    if (pkg != "" && ver != "" && status ~ /(^| )installed$/) print pkg "\t" ver
    pkg = ""; ver = ""; status = ""
  }
  /^Package: /{ pkg    = $2; next }
  /^Version: /{ ver    = $2; next }
  /^Status: / { status = $2; next }
  /^[[:space:]]*$/ { flush(); next }
  END { flush() }
' "$OUTDIR/.dpkg-status" | sort -u > "$PACKAGES_OUT"
rm -f "$OUTDIR/.dpkg-status"
log "userland inventory: $(wc -l < "$PACKAGES_OUT") packages -> $PACKAGES_OUT"

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

fi
# ===========================================================================
# END image build
# ===========================================================================

# ---------------------------------------------------------------------------
# debug symbols from ddebs
#
# Stream-extracted: the ddeb is ~1.9 GB unpacked and we want exactly one file
# out of it, so it must never land in a container layer or on disk whole.
# ---------------------------------------------------------------------------
# REFRESH_SYMBOLS, not REUSE_IMAGE: a metadata-only repair leaves symbols that
# are already present and validated exactly where they are.
if [[ "$SYMBOLS" != "none" && "$REFRESH_SYMBOLS" == true && "$DBGSYM_AVAILABLE" == true ]]; then
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

        # Everything lands in staging first and is published only once BOTH
        # halves have succeeded. Writing vmlinux straight to its final name made
        # a failed vmlinux->full upgrade destructive: the partial write clobbered
        # a perfectly good cached vmlinux, and the next run then had to rebuild
        # the rootfs to recover a file the rootfs has nothing to do with.
        # The container owns the cleanup because it created these paths as root,
        # and the host cannot recurse into a root-owned staging tree.
        STAGE=/output/.symstage
        VMPART="/output/vmlinux-${KREL}.part"
        rm -rf "$STAGE"; mkdir -p "$STAGE"
        trap "rm -rf $STAGE $VMPART" EXIT

        curl -sSfL "$URI" \
          | bsdtar -xOf - "data.tar*" \
          | bsdtar -xOf - "./usr/lib/debug/boot/vmlinux-${KREL}" \
          > "$VMPART"
        [ -s "$VMPART" ] || { echo "vmlinux extraction produced an empty file" >&2; exit 1; }

        if [ "$KEEP_MODULES" = "1" ]; then
          # No `|| true` here. --symbols=full promises module debug info, and a
          # swallowed download or extraction failure handed back a target whose
          # module symbols silently did not exist -- discovered only once a GDB
          # session failed to resolve a symbol inside a module.
          curl -sSfL "$URI" | bsdtar -xOf - "data.tar*" \
            | bsdtar -xf - -C "$STAGE" "./usr/lib/debug/lib/modules/${KREL}"
          find "$STAGE/usr/lib/debug/lib/modules/${KREL}" -name "*.ko" -print -quit 2>/dev/null \
            | grep -q . || {
              echo "--symbols=full requested but the ddeb yielded no module debug objects" >&2
              exit 1
            }
        fi

        # publish
        mv -f "$VMPART" "/output/vmlinux-${KREL}"
        if [ "$KEEP_MODULES" = "1" ]; then
          mkdir -p /output/usr/lib/debug/lib/modules
          rm -rf "/output/usr/lib/debug/lib/modules/${KREL}"
          mv "$STAGE/usr/lib/debug/lib/modules/${KREL}" \
             "/output/usr/lib/debug/lib/modules/${KREL}"
        fi
      ' >&2; then
    log "vmlinux extracted: $VMLINUX_OUT"
  else
    # Fatal, not a warning. The dbgsym index was already checked above, so a
    # failure here is an infrastructure fault, and --symbols is a flag that
    # promises an artifact -- quietly emitting a target without it would let a
    # GDB session start against symbols the caller believes they asked for.
    #
    # Any previously cached vmlinux is deliberately left alone: this run
    # published nothing, so the target is exactly as it was before, and the
    # stamp still describes it. Deleting it here is what used to force the next
    # run to rebuild the rootfs.
    die "debug-symbol extraction failed for $KREL (dbgsym $KDEBVER exists in the index).
  Re-run with --verbose for the container output, or drop --symbols to build
  the target without them."
  fi
fi

# The symbol level this directory ends up holding, which the manifest and stamp
# must record -- as opposed to $SYMBOLS, which is only what this invocation
# asked for. A metadata repair run without --symbols records the cached level it
# found, so the symbols are not forgotten and re-downloaded next time; a run
# that fetched records whichever level is higher. Backed by the files either
# way, so a cached claim whose artifacts have since gone is not carried forward.
#
# $VMLINUX on stdout stays gated on $SYMBOLS in emit_outputs: what this run
# ASKED for and what the directory HOLDS are different questions, and callers
# rely on the first.
if [[ "$REUSE_IMAGE" == true && "$REFRESH_SYMBOLS" == false ]]; then
  # Nothing about the symbols was validated or refetched on this pass, so
  # nothing about them is re-measured. Recomputing here would ratify whatever
  # state the files happen to be in: a plain metadata repair over a truncated
  # vmlinux (or a module tree emptied of .ko files) would record the damaged
  # sizes as if they were correct, and the next --symbols request would then
  # accept the damage as a cache hit. Carrying the prior expectations forward
  # keeps that request able to detect the damage and refetch.
  STAMP_SYMBOLS="$CACHED_SYMBOLS"
else
  STAMP_SYMBOLS_WANT="$CACHED_SYMBOLS"
  if [[ "$(symbols_rank "$SYMBOLS")" -gt "$(symbols_rank "$STAMP_SYMBOLS_WANT")" ]]; then
    STAMP_SYMBOLS_WANT="$SYMBOLS"
  fi
  # A fresh build starts from nothing: a stale vmlinux left in the directory is
  # not evidence that this rebuild produced one.
  [[ "$REUSE_IMAGE" == true ]] || STAMP_SYMBOLS_WANT="$SYMBOLS"
  STAMP_SYMBOLS="$(effective_symbols "$STAMP_SYMBOLS_WANT")"
fi
[[ "$STAMP_SYMBOLS" == "$SYMBOLS" ]] || log "recording symbols=${STAMP_SYMBOLS:-none} (what the target holds)"

DWARF_COMP_DIR=""
if [[ "$STAMP_SYMBOLS" != "none" && -f "$VMLINUX_OUT" ]] && command -v objdump >/dev/null 2>&1; then
  DWARF_COMP_DIR="$( { objdump --dwarf=info --dwarf-depth=1 "$VMLINUX_OUT" 2>/dev/null || true; } \
    | awk '/DW_AT_comp_dir/ { if (d == "") { sub(/.*:[[:space:]]*/, ""); d = $0 } } END { print d }')"
  [[ -n "$DWARF_COMP_DIR" ]] && log "DWARF comp_dir: $DWARF_COMP_DIR"
fi

# ---------------------------------------------------------------------------
# export container filesystem -> raw ext4 image
# ---------------------------------------------------------------------------
if [[ "$REUSE_IMAGE" == true ]]; then
  log "rootfs left untouched (symbols/metadata refresh only)"
else
step "Creating raw ext4 image ($SIZE) -- exports ~1 GB and runs mke2fs, expect 1-2 min"
# The if/else form is required under `set -euo pipefail` so a failed helper
# pipeline can fall back to host sudo mke2fs instead of aborting immediately.
if docker export "$CID" | docker run --rm -i \
  "${HELPER_PLATFORM[@]}" \
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
fi

[[ -f "$ROOTFS_OUT" ]] || die "build appeared to succeed but $ROOTFS_OUT not found"

# ---------------------------------------------------------------------------
# manifest -- attribution. Also baked into the guest at /etc/qmu-target.json
# so `qmu exec 'cat /etc/qmu-target.json'` attributes a LIVE result.
# ---------------------------------------------------------------------------
step "Writing manifest and qmu.toml"

# Reusing an image does not rebuild it, so every field describing WHEN that
# image was made must keep its old value. Both are resolved fresh on each run
# and would otherwise be silently re-dated: `built_at` to now, and
# `archive_release_date` to whatever the pocket's Release file says today. The
# image was built against the archive as it stood at the earlier date, and that
# is the provenance a cited result depends on.
#
# The stamp is consulted first and the manifest only as a fallback, because the
# manifest is the file a repair pass exists to rewrite -- it may be the very
# thing that was truncated. Stamps written before these rows existed have
# neither, so the manifest still has to be tried.
if [[ "$REUSE_IMAGE" == true ]]; then
  PRIOR_BUILT_AT="$(stamp_get built_at)"
  PRIOR_ARCHIVE_DATE="$(stamp_get archive_release_date)"
  if [[ -z "$PRIOR_BUILT_AT" && -f "$MANIFEST_OUT" ]]; then
    PRIOR_BUILT_AT="$(awk -F'"' '/"built_at"/ { print $4; exit }' "$MANIFEST_OUT")"
  fi
  if [[ -z "$PRIOR_ARCHIVE_DATE" && -f "$MANIFEST_OUT" ]]; then
    PRIOR_ARCHIVE_DATE="$(awk -F'"' '/"archive_release_date"/ { print $4; exit }' "$MANIFEST_OUT")"
  fi
  [[ -n "$PRIOR_BUILT_AT" ]] && BUILT_AT="$PRIOR_BUILT_AT"
  [[ -n "$PRIOR_ARCHIVE_DATE" ]] && ARCHIVE_DATE="$PRIOR_ARCHIVE_DATE"
fi

KERNEL_SHA="$(sha256sum "$KERNEL_OUT" | awk '{print $1}')"
ROOTFS_SHA="$(sha256sum "$ROOTFS_OUT" | awk '{print $1}')"
DBGVER="null"
[[ "$STAMP_SYMBOLS" != "none" && -f "$VMLINUX_OUT" ]] && DBGVER="\"$KDEBVER\""

# Written via .part + rename. This does not carry the correctness argument --
# that rests on metadata being repairable rather than image-class -- but it does
# mean a kill mid-write leaves the previous manifest whole instead of a truncated
# one, which is worth the two extra lines.
cat > "$MANIFEST_OUT.part" <<JSON
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
  "rootfs_sha256": "$ROOTFS_SHA",
  "build_key": "$BUILD_KEY",
  "packages_manifest": "$PACKAGES_OUT",
  "userland": {
    "apparmor": "$(pkgver apparmor)",
    "procps": "$(pkgver procps)",
    "systemd": "$(pkgver systemd)",
    "libc6": "$(pkgver libc6)",
    "gcc": "$(pkgver gcc)",
    "openssh-server": "$(pkgver openssh-server)"
  }
}
JSON
mv -f "$MANIFEST_OUT.part" "$MANIFEST_OUT"

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

cat > "$TOML_OUT.part" <<TOML
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
mv -f "$TOML_OUT.part" "$TOML_OUT"

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# completion stamp -- written LAST, and only here
#
# Its existence is what makes a directory a cache hit, so everything above must
# have succeeded for one to appear. It is assembled beside the final name and
# renamed into place, so even a kill during this write cannot leave a partial
# stamp that parses.
# ---------------------------------------------------------------------------
{
  printf 'version\t%s\n'            "$MKTARGET_VERSION"
  printf 'build_key\t%s\n'          "$BUILD_KEY"
  printf 'symbols\t%s\n'            "$STAMP_SYMBOLS"
  printf 'kernel_deb_version\t%s\n' "$KDEBVER"
  # Recorded here as well as in the manifest, so a repair pass can restore the
  # image's provenance even when the manifest is the file that was damaged.
  printf 'built_at\t%s\n'             "$BUILT_AT"
  printf 'archive_release_date\t%s\n' "${ARCHIVE_DATE:-unknown}"
  # Image class: not reproducible without the container, so a mismatch here
  # really does mean rebuild. packages.tsv belongs with them -- it is read out
  # of the container's dpkg database and cannot be regenerated on the host.
  for f in "$KERNEL_OUT" "$ROOTFS_OUT" "$CONFIG_OUT" "$SYSMAP_OUT" "$PACKAGES_OUT"; do
    printf 'artifact\t%s\t%s\n' "$f" "$(stat -c %s -- "$f")"
  done
  # `meta`, not `artifact`: both are regenerated from what is already on disk on
  # every reuse pass, so a mismatch is a rewrite. Filing them as image artifacts
  # is what let an interrupted upgrade -- manifest rewritten, stamp not yet
  # renamed -- condemn the measured rootfs on the following run.
  for f in "$TOML_OUT" "$MANIFEST_OUT"; do
    printf 'meta\t%s\t%s\n' "$f" "$(stat -c %s -- "$f")"
  done
  # Recorded only when actually produced: --initramfs can legitimately yield no
  # initrd, and demanding one back would make that target rebuild forever.
  if [[ "$INITRAMFS" == true && -f "$INITRD_OUT" ]]; then
    printf 'artifact\t%s\t%s\n' "$INITRD_OUT" "$(stat -c %s -- "$INITRD_OUT")"
  fi
  # `symbol`, not `artifact`: these are checked by cache_symbols_ok, whose
  # remedy is a refetch, rather than by cache_image_ok, whose remedy is a
  # rootfs-replacing rebuild.
  # Only measurements this run actually took get recorded; anything it did not
  # validate or refetch is carried forward verbatim. Re-measuring an unchecked
  # file would bless whatever damage it has and make the next symbol request
  # accept it.
  if [[ "$SYMBOLS" != none && "$REFRESH_SYMBOLS" == true && -f "$VMLINUX_OUT" ]]; then
    printf 'symbol\t%s\t%s\n' "$VMLINUX_OUT" "$(stat -c %s -- "$VMLINUX_OUT")"
  elif [[ "$STAMP_SYMBOLS" != none && -n "$PRIOR_SYMBOL_ROWS" ]]; then
    printf '%s\n' "$PRIOR_SYMBOL_ROWS"
  fi
  # A directory cannot be described by the artifact-size list, and `-d` alone
  # passes on a tree whose every .ko has been deleted.
  if [[ "$SYMBOLS" == full && "$REFRESH_SYMBOLS" == true && -d "$MODDBG_OUT" ]]; then
    printf 'moddbg\t%s\n' "$(moddbg_shape)"
  elif [[ "$STAMP_SYMBOLS" == full && -n "$PRIOR_MODDBG" ]]; then
    printf 'moddbg\t%s\n' "$PRIOR_MODDBG"
  fi
} > "$STAMP_OUT.part"
mv -f "$STAMP_OUT.part" "$STAMP_OUT"

if [[ "$REUSE_IMAGE" == true ]]; then
  step "Cached target refreshed in place: $OUTDIR"
else
  step "Target ready: $OUTDIR"
fi
log "Ubuntu $SUITE $KREL ($KDEBVER, pocket $KPOCKET, hardening=$HARDENING)"
if [[ "$RELAX" == true ]]; then
  warn "=============================================================="
  warn "HARDENING RELAXED. This image's kptr/dmesg/bpf/userns/perf"
  warn "restrictions are OFF. Results are NOT statements about the"
  warn "real Ubuntu target. Guest hostname is '$HOSTNAME_GUEST'."
  warn "=============================================================="
fi
emit_outputs
