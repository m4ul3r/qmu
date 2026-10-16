#!/usr/bin/env bash
# fetch-hosttools.sh — fetch candidate dropbear/gdbserver/sftp-server helpers for a
# firmware VM from an Ubuntu container of the target architecture.
#
# Compatibility requires more than equal glibc labels: inspect ELF ABI, loader path,
# required symbol versions and transitive dependencies, then verify guest execution.
# Older-ABI helpers may work with newer firmware libc; matching versions is neither
# required nor sufficient. Never overwrite vendor libc to make a helper run.
# This fetches SSH/debugger tools and selected libraries, not shells/app utilities.
# Requires: docker + target-arch execution support (binfmt for cross-architecture
# containers). --out may be relative or absolute: it is created if missing and
# resolved to an absolute path before becoming the Docker bind source. Fetched
# files are written by the container and are root-owned on the host.
#
# Candidate Ubuntu release / glibc cheat sheet (verify actual fetched artifacts):
#   2.23 xenial(16.04) · 2.27 bionic(18.04) · 2.31 focal(20.04)
#   2.35 jammy(22.04)  · 2.39 noble(24.04)
# Identify the firmware libc/loader offline; version clues alone are not proof.
set -euo pipefail

# The glibc base set: libraries the firmware's own libc provides, so they are
# never copied into libs/ and never counted as missing. Matched against the
# *basename* with a version delimiter anchored right after the stem, so
# `libcrypt.so.1` / `libcrypt-2.27.so` are base but `libcrypto.so.3` is not.
BASE_LIB_RE='^(libc|libdl|libpthread|libm|librt|libcrypt|libutil|libresolv)[.-]|^ld-linux'

# EOL releases move to old-releases.ubuntu.com, which serves EVERY architecture
# under /ubuntu: the ports mirror's /ubuntu-ports path does not exist there.
rewrite_eol_sources() {   # FILE... (missing files are skipped)
  local f
  for f in "$@"; do
    [[ -e "$f" ]] || continue
    sed -i \
      -e 's|ports\.ubuntu\.com/ubuntu-ports|old-releases.ubuntu.com/ubuntu|g' \
      -e 's|ports\.ubuntu\.com/|old-releases.ubuntu.com/ubuntu/|g' \
      -e 's|[a-z.]*archive\.ubuntu\.com|old-releases.ubuntu.com|g' \
      -e 's|[a-z.]*security\.ubuntu\.com|old-releases.ubuntu.com|g' \
      "$f"
  done
}

# stdin: ldd output. stdout: unique absolute paths of resolved non-base libraries.
nonbase_library_paths() {
  local p
  awk '/=>/ && $3 ~ /^\//{print $3}' | sort -u | while read -r p; do
    [[ ${p##*/} =~ $BASE_LIB_RE ]] || printf '%s\n' "$p"
  done
}

# Every library the loader resolves for a copied ELF (binaries and libs/ alike)
# must ship in DIR/libs or belong to the base set; print the rest and fail.
check_dependency_completeness() {   # DIR
  local dir=$1 f need missing=""
  for f in "$dir"/dropbear "$dir"/dropbearkey "$dir"/gdbserver "$dir"/sftp-server "$dir"/libs/*; do
    [[ -f "$f" ]] || continue
    while read -r need; do
      [[ -e "$dir/libs/$need" ]] && continue
      [[ $need =~ $BASE_LIB_RE ]] && continue
      missing+="  ${f##*/}: $need"$'\n'
    done < <(ldd "$f" 2>/dev/null | awk '/=>/{print $1}')
  done
  if [[ -n "$missing" ]]; then
    printf 'ERROR: fetched helpers need libraries that are neither in libs/ nor glibc base:\n%s' "$missing" >&2
    return 1
  fi
  echo "== dependency completeness: ok (every NEEDED is in libs/ or glibc base) ==" >&2
}

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq 2>/dev/null || {
    rewrite_eol_sources /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list
    apt-get update -qq; }
  apt-get install -y -qq dropbear-bin gdbserver openssh-sftp-server >/dev/null
  # (`sed -n 1p` drains its input; `head -1` would SIGPIPE the producer under pipefail.)
  echo "== glibc in container ==" >&2; ldd --version | sed -n 1p >&2
  echo "== dropbear version (ed25519 needs >= 2018.76; else use ecdsa keys) ==" >&2
  dropbear -V 2>&1 | sed -n 1p >&2 || (dpkg -l dropbear-bin | tail -1 >&2)
  # binaries
  local DB DK GS SF
  DB=$(command -v dropbear || echo /usr/sbin/dropbear)
  DK=$(command -v dropbearkey || echo /usr/bin/dropbearkey)
  GS=$(command -v gdbserver || echo /usr/bin/gdbserver)
  SF=$(dpkg -L openssh-sftp-server | grep "sftp-server$" | sed -n 1p)
  cp "$DB" /output/dropbear; cp "$DK" /output/dropbearkey; cp "$GS" /output/gdbserver; cp "$SF" /output/sftp-server
  chmod 0755 /output/dropbear /output/dropbearkey /output/gdbserver /output/sftp-server
  # Copy every non-base library the loader resolves; verify them against the firmware too.
  mkdir -p /output/libs
  for b in "$DB" "$DK" "$GS" "$SF"; do ldd "$b" 2>/dev/null || true; done \
    | nonbase_library_paths \
    | while read -r L; do cp -Lv "$L" /output/libs/; done
  check_dependency_completeness /output
  echo "== fetched ==" >&2; ls -la /output /output/libs >&2
}

usage() { sed -n '2,20p' "$0"; echo "Usage: $0 --arch <arm64|amd64|arm/v7|386> --release <bionic|focal|jammy|noble|...> --out <dir>"; exit "${1:-0}"; }

main() {
  local ARCH=arm64       # docker --platform value: arm64, amd64, arm/v7, 386
  local RELEASE=bionic   # candidate Ubuntu release; verify compatibility with firmware
  local OUT="" SELF
  while [[ $# -gt 0 ]]; do case "$1" in
    --arch) ARCH="$2"; shift 2;;
    --release) RELEASE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --in-container) in_container; return;;
    -h|--help) usage 0;;
    *) echo "unknown arg: $1" >&2; usage 1;;
  esac; done
  [[ -n "$OUT" ]] || { echo "ERROR: --out required" >&2; usage 1; }
  mkdir -p "$OUT"
  # A relative -v source is a Docker *named volume*, not a bind mount: the host
  # dir would stay empty while the in-container listing reports success.
  OUT=$(cd "$OUT" && pwd -P)
  SELF=$(readlink -f "$0")

  echo ">> fetching dropbear/gdbserver/sftp-server for ubuntu:$RELEASE ($ARCH) into $OUT" >&2
  # This script is bind-mounted into the container and re-entered with
  # --in-container, so the fetch logic above is one copy, host-testable.
  docker run --rm --platform "linux/$ARCH" -v "$OUT:/output:rw" -v "$SELF:/qmu-fetch-hosttools.sh:ro" \
    "ubuntu:$RELEASE" bash /qmu-fetch-hosttools.sh --in-container
  echo ">> done. NOTE which of the libs/ your firmware already has (skip injecting those)." >&2
  echo ">> If dropbear < 2018.76, generate ECDSA (not ed25519) host+client keys." >&2
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
