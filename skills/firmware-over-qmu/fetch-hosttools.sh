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

ARCH=arm64          # docker --platform value: arm64, amd64, arm/v7, 386
RELEASE=bionic      # candidate Ubuntu release; verify compatibility with firmware
OUT=""
usage() { sed -n '2,20p' "$0"; echo "Usage: $0 --arch <arm64|amd64|arm/v7|386> --release <bionic|focal|jammy|noble|...> --out <dir>"; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --arch) ARCH="$2"; shift 2;;
  --release) RELEASE="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  -h|--help) usage 0;;
  *) echo "unknown arg: $1" >&2; usage 1;;
esac; done
[[ -n "$OUT" ]] || { echo "ERROR: --out required" >&2; usage 1; }
mkdir -p "$OUT"
# A relative -v source is a Docker *named volume*, not a bind mount: the host
# dir would stay empty while the in-container listing reports success.
OUT=$(cd "$OUT" && pwd -P)

echo ">> fetching dropbear/gdbserver/sftp-server for ubuntu:$RELEASE ($ARCH) into $OUT" >&2
docker run --rm --platform "linux/$ARCH" -v "$OUT:/output:rw" "ubuntu:$RELEASE" bash -c '
  set -e; export DEBIAN_FRONTEND=noninteractive
  # EOL releases move to old-releases; fall back automatically.
  apt-get update -qq 2>/dev/null || {
    sed -i "s|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g; s|ports.ubuntu.com|old-releases.ubuntu.com|g" /etc/apt/sources.list 2>/dev/null || true
    apt-get update -qq; }
  apt-get install -y -qq dropbear-bin gdbserver openssh-sftp-server >/dev/null
  echo "== glibc in container ==" >&2; ldd --version | head -1 >&2
  echo "== dropbear version (ed25519 needs >= 2018.76; else use ecdsa keys) ==" >&2
  dropbear -V 2>&1 | head -1 >&2 || (dpkg -l dropbear-bin | tail -1 >&2)
  # binaries
  DB=$(command -v dropbear || echo /usr/sbin/dropbear)
  DK=$(command -v dropbearkey || echo /usr/bin/dropbearkey)
  GS=$(command -v gdbserver || echo /usr/bin/gdbserver)
  SF=$(dpkg -L openssh-sftp-server | grep -m1 "sftp-server$")
  cp "$DB" /output/dropbear; cp "$DK" /output/dropbearkey; cp "$GS" /output/gdbserver; cp "$SF" /output/sftp-server
  chmod 0755 /output/dropbear /output/dropbearkey /output/gdbserver /output/sftp-server
  # Copy selected non-glibc deps; verify omitted libraries against the firmware too.
  mkdir -p /output/libs
  for b in "$DB" "$DK" "$GS" "$SF"; do ldd "$b" 2>/dev/null | awk "/=>/ && \$3 ~ /^\//{print \$3}"; done \
    | sort -u \
    | grep -vE "/(libc-|libc\.|libdl|libpthread|libm-|libm\.|librt|libcrypt|libutil|ld-linux)" \
    | while read -r L; do cp -Lv "$L" /output/libs/ 2>/dev/null || true; done
  echo "== fetched ==" >&2; ls -la /output /output/libs >&2
'
echo ">> done. NOTE which of the libs/ your firmware already has (skip injecting those)." >&2
echo ">> If dropbear < 2018.76, generate ECDSA (not ed25519) host+client keys." >&2
