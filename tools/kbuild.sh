#!/usr/bin/env bash
# Build Linux kernels (v4.x–latest) inside Docker for QEMU exploit development.
#
# Supports x86_64, i386, arm64, arm32, arm32hf via cross-compilation toolchains
# baked into Ubuntu-based Docker images. Picks the right Ubuntu/GCC version
# automatically based on the kernel version.
#
# Output is eval-able:  eval $(tools/kbuild.sh --version 6.6.75)
#                        qmu launch --kernel "$KERNEL"
set -euo pipefail

# ---------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------
CACHE="${QMU_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/qmu}"
MIRROR="${QMU_KBUILD_MIRROR:-https://cdn.kernel.org/pub/linux/kernel}"
ARCH="x86_64"
CONTAINER_OVERRIDE=""
OUTDIR_OVERRIDE=""
JOBS="$(nproc)"
NO_CACHE=false
CONFIG_ONLY=false
VERBOSE=false
VERSION=""

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
die()  { echo "kbuild: error: $*" >&2; exit 2; }
step() { echo "=== [$(date +%H:%M:%S)] $* ===" >&2; }
log()  { echo "kbuild: $*" >&2; }

version_ge() {
  local maj1=$1 min1=$2 maj2=$3 min2=$4
  (( maj1 > maj2 )) && return 0
  (( maj1 == maj2 && min1 >= min2 )) && return 0
  return 1
}

usage() {
  cat >&2 <<'EOF'
Usage: kbuild.sh --version VERSION [OPTIONS]

Build a Linux kernel inside Docker for QEMU exploit development.

Required:
  --version VERSION      Kernel version (e.g. 6.6.75, 4.19.320, 5.15.170)

Optional:
  --arch ARCH            Target architecture (default: x86_64)
                         Values: x86_64, i386, arm64, arm32, arm32hf
  --container TAG        Override auto-selected Ubuntu container
                         Values: xenial, bionic, focal, jammy, noble
  --outdir DIR           Override output directory
  --jobs N               Parallel build jobs (default: nproc)
  --no-cache             Rebuild even if output exists
  --config-only          Generate .config and exit (don't build)
  --verbose              Show Docker build + make output
  -h, --help             Show this help

Environment:
  QMU_CACHE_DIR          Override ~/.cache/qmu
  QMU_KBUILD_MIRROR      Kernel mirror (default: cdn.kernel.org)

Output (eval-able; --config-only outputs only CONFIG and does not generate debugger helpers):
  KERNEL=/path/to/bzImage
  VMLINUX=/path/to/vmlinux
  CONFIG=/path/to/.config
  KERNEL_SRC=/path/to/linux-source
  VMLINUX_GDB=/path/to/vmlinux-gdb.py
Example:
  eval $(tools/kbuild.sh --version 6.6.75 --arch arm64)
  qmu launch --kernel "$KERNEL"
EOF
  exit 2
}

# ---------------------------------------------------------------------------
# parse args
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2"; shift 2 ;;
    --arch)       ARCH="$2"; shift 2 ;;
    --container)  CONTAINER_OVERRIDE="$2"; shift 2 ;;
    --outdir)     OUTDIR_OVERRIDE="$2"; shift 2 ;;
    --jobs)       JOBS="$2"; shift 2 ;;
    --no-cache)   NO_CACHE=true; shift ;;
    --config-only) CONFIG_ONLY=true; shift ;;
    --verbose)    VERBOSE=true; shift ;;
    -h|--help)    usage ;;
    *)            die "unknown argument: $1" ;;
  esac
done

[[ -z "$VERSION" ]] && die "--version is required (e.g. --version 6.6.75)"

# validate version format: major.minor or major.minor.patch
if ! [[ "$VERSION" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]]; then
  die "invalid version format: $VERSION (expected: major.minor[.patch])"
fi
MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"

# validate arch
case "$ARCH" in
  x86_64|i386|arm64|arm32|arm32hf) ;;
  *) die "unsupported --arch: $ARCH (expected: x86_64, i386, arm64, arm32, arm32hf)" ;;
esac

# ---------------------------------------------------------------------------
# version -> container mapping
# ---------------------------------------------------------------------------
pick_container() {
  local maj=$1 min=$2
  if (( maj == 4 && min <= 9 )); then
    echo "xenial"
  elif (( maj == 4 )); then
    echo "bionic"
  elif (( maj == 5 && min <= 3 )); then
    echo "bionic"
  elif (( maj == 5 )); then
    echo "focal"
  elif (( maj == 6 && min <= 6 )); then
    echo "jammy"
  else
    echo "noble"
  fi
}

if [[ -n "$CONTAINER_OVERRIDE" ]]; then
  CONTAINER="$CONTAINER_OVERRIDE"
else
  CONTAINER="$(pick_container "$MAJOR" "$MINOR")"
fi

case "$CONTAINER" in
  xenial|bionic|focal|jammy|noble) ;;
  *) die "unsupported container: $CONTAINER (expected: xenial, bionic, focal, jammy, noble)" ;;
esac

KBUILD_IMAGE="qmu-kbuild:${CONTAINER}-${ARCH}"

# ---------------------------------------------------------------------------
# arch -> build variables
# ---------------------------------------------------------------------------
case "$ARCH" in
  x86_64)
    MAKE_ARCH="x86_64"
    CROSS_COMPILE=""
    MAKE_TARGET="bzImage"
    IMAGE_NAME="bzImage"
    IMAGE_SUBPATH="arch/x86/boot/bzImage"
    DEFCONFIG="defconfig"
    ;;
  i386)
    MAKE_ARCH="i386"
    CROSS_COMPILE=""
    MAKE_TARGET="bzImage"
    IMAGE_NAME="bzImage"
    IMAGE_SUBPATH="arch/x86/boot/bzImage"
    DEFCONFIG="i386_defconfig"
    ;;
  arm64)
    MAKE_ARCH="arm64"
    CROSS_COMPILE="aarch64-linux-gnu-"
    MAKE_TARGET="Image"
    IMAGE_NAME="Image"
    IMAGE_SUBPATH="arch/arm64/boot/Image"
    DEFCONFIG="defconfig"
    ;;
  arm32)
    MAKE_ARCH="arm"
    CROSS_COMPILE="arm-linux-gnueabi-"
    MAKE_TARGET="zImage"
    IMAGE_NAME="zImage"
    if version_ge "$MAJOR" "$MINOR" 5 0; then
      DEFCONFIG="multi_v7_defconfig"
    else
      DEFCONFIG="vexpress_defconfig"
    fi
    IMAGE_SUBPATH="arch/arm/boot/zImage"
    ;;
  arm32hf)
    MAKE_ARCH="arm"
    CROSS_COMPILE="arm-linux-gnueabihf-"
    MAKE_TARGET="zImage"
    IMAGE_NAME="zImage"
    if version_ge "$MAJOR" "$MINOR" 5 0; then
      DEFCONFIG="multi_v7_defconfig"
    else
      DEFCONFIG="vexpress_defconfig"
    fi
    IMAGE_SUBPATH="arch/arm/boot/zImage"
    ;;
esac

# ---------------------------------------------------------------------------
# output directory
# ---------------------------------------------------------------------------
if [[ -n "$OUTDIR_OVERRIDE" ]]; then
  OUTDIR="$OUTDIR_OVERRIDE"
else
  OUTDIR="$CACHE/kernels/$VERSION/$ARCH"
fi

SRCDIR="$CACHE/kernels/src/linux-$VERSION"

emit_config_output() {
  printf 'CONFIG=%q\n' "$OUTDIR/.config"
}

emit_build_outputs() {
  printf 'KERNEL=%q\n' "$OUTDIR/$IMAGE_NAME"
  printf 'VMLINUX=%q\n' "$OUTDIR/vmlinux"
  printf 'CONFIG=%q\n' "$OUTDIR/.config"
  printf 'KERNEL_SRC=%q\n' "$SRCDIR"
  printf 'VMLINUX_GDB=%q\n' "$OUTDIR/vmlinux-gdb.py"
}

config_cache_complete() {
  [[ -f "$OUTDIR/.config" ]]
}

build_cache_complete() {
  [[ -f "$OUTDIR/$IMAGE_NAME" ]] &&
  [[ -f "$OUTDIR/vmlinux" ]] &&
  [[ -f "$OUTDIR/.config" ]] &&
  [[ -f "$SRCDIR/Makefile" ]] &&
  [[ -f "$OUTDIR/vmlinux-gdb.py" ]] &&
  [[ -f "$OUTDIR/scripts/gdb/vmlinux-gdb.py" ]] &&
  [[ -f "$OUTDIR/scripts/gdb/linux/constants.py" ]]
}

if [[ "$NO_CACHE" == false ]]; then
  if [[ "$CONFIG_ONLY" == true ]] && config_cache_complete; then
    log "cached config found at $OUTDIR/.config"
    emit_config_output
    exit 0
  fi
  if [[ "$CONFIG_ONLY" == false ]] && build_cache_complete; then
    log "cached build found at $OUTDIR/$IMAGE_NAME"
    emit_build_outputs
    exit 0
  fi
  if [[ "$CONFIG_ONLY" == false && -e "$OUTDIR/$IMAGE_NAME" ]]; then
    log "cached build is incomplete; rebuilding debugger artifacts"
  fi
fi


mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# kernel source
# ---------------------------------------------------------------------------

if [[ ! -f "$SRCDIR/Makefile" ]]; then
  TARBALL="$CACHE/kernels/src/linux-$VERSION.tar.xz"
  if [[ ! -f "$TARBALL" ]]; then
    step "Downloading kernel $VERSION"
    mkdir -p "$CACHE/kernels/src"
    curl -fL --retry 3 -o "$TARBALL" \
      "$MIRROR/v${MAJOR}.x/linux-$VERSION.tar.xz"
  fi
  step "Extracting kernel source"
  tar xf "$TARBALL" -C "$CACHE/kernels/src"
  [[ -f "$SRCDIR/Makefile" ]] || die "extraction failed: $SRCDIR/Makefile not found"
fi

# ---------------------------------------------------------------------------
# Docker image
# ---------------------------------------------------------------------------
DOCKER_QUIET=""
if [[ "$VERBOSE" == false ]]; then
  DOCKER_QUIET="-q"
fi

arch_packages() {
  case "$ARCH" in
    i386)    echo "gcc-multilib" ;;
    arm64)   echo "gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu" ;;
    arm32)   echo "gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi" ;;
    arm32hf) echo "gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf" ;;
  esac
}

build_docker_image() {
  local ubuntu_tag gcc_ver python_pkg
  case "$CONTAINER" in
    xenial) ubuntu_tag="16.04"; gcc_ver="5";  python_pkg="python" ;;
    bionic) ubuntu_tag="18.04"; gcc_ver="7";  python_pkg="python3" ;;
    focal)  ubuntu_tag="20.04"; gcc_ver="9";  python_pkg="python3" ;;
    jammy)  ubuntu_tag="22.04"; gcc_ver="11"; python_pkg="python3" ;;
    noble)  ubuntu_tag="24.04"; gcc_ver="13"; python_pkg="python3" ;;
  esac

  local extra_pkgs
  extra_pkgs="$(arch_packages)"

  step "Building Docker image $KBUILD_IMAGE (Ubuntu $ubuntu_tag / GCC $gcc_ver / $ARCH)"
  local _ctx; _ctx=$(mktemp -d) && trap "rm -rf '$_ctx'" RETURN

  local extra_run=""
  if [[ -n "$extra_pkgs" ]]; then
    extra_run="RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${extra_pkgs} && rm -rf /var/lib/apt/lists/*"
  fi

  docker build $DOCKER_QUIET -t "$KBUILD_IMAGE" -f - "$_ctx" <<DOCKERFILE
FROM ubuntu:${ubuntu_tag}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential bc bison flex libelf-dev libssl-dev cpio kmod xz-utils \
      ${python_pkg} wget curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
${extra_run}
ENV KBUILD_BUILD_USER=qmu KBUILD_BUILD_HOST=kbuild
DOCKERFILE
}

if ! docker image inspect "$KBUILD_IMAGE" >/dev/null 2>&1; then
  build_docker_image
fi

# ---------------------------------------------------------------------------
# build inside container
# ---------------------------------------------------------------------------
step "Building kernel $VERSION ($ARCH) in $KBUILD_IMAGE — -j$JOBS"

DOCKER_TTY_FLAG=""
if [[ -t 1 ]] && [[ "$VERBOSE" == true ]]; then
  DOCKER_TTY_FLAG="-t"
fi

MAKE_VERBOSE=""
if [[ "$VERBOSE" == false ]]; then
  MAKE_VERBOSE="-s"
fi

GDB_TARGET=""
if [[ "$CONFIG_ONLY" == false ]]; then
  GDB_TARGET="scripts_gdb"
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e KBUILD_BUILD_USER=qmu -e KBUILD_BUILD_HOST=kbuild \
  -v "$SRCDIR:/src:rw" \
  -v "$OUTDIR:/output:rw" \
  -w /src \
  $DOCKER_TTY_FLAG \
  "$KBUILD_IMAGE" bash -euo pipefail -c "
    MAKE_ARCH='$MAKE_ARCH'
    CROSS_COMPILE='$CROSS_COMPILE'
    MAKE_TARGET='$MAKE_TARGET'
    IMAGE_SUBPATH='$IMAGE_SUBPATH'
    DEFCONFIG='$DEFCONFIG'
    JOBS='$JOBS'
    MAJOR='$MAJOR'
    MINOR='$MINOR'
    ARCH_ARG='$ARCH'
    CONFIG_ONLY='$CONFIG_ONLY'
    GDB_TARGET='$GDB_TARGET'
    MAKE_VERBOSE='$MAKE_VERBOSE'

    version_ge() {
      local maj1=\$1 min1=\$2 maj2=\$3 min2=\$4
      (( maj1 > maj2 )) && return 0
      (( maj1 == maj2 && min1 >= min2 )) && return 0
      return 1
    }

    echo \"container gcc: \$(gcc --version | head -1)\" >&2
    if [[ -n \"\$CROSS_COMPILE\" ]]; then
      echo \"cross compiler: \$(\${CROSS_COMPILE}gcc --version | head -1)\" >&2
    fi

    # clean previous build state
    make ARCH=\$MAKE_ARCH \$MAKE_VERBOSE mrproper

    # base defconfig
    make ARCH=\$MAKE_ARCH CROSS_COMPILE=\$CROSS_COMPILE \$MAKE_VERBOSE \$DEFCONFIG

    # kvm_guest.config for x86
    if [[ \"\$MAKE_ARCH\" == \"x86_64\" || \"\$MAKE_ARCH\" == \"i386\" ]]; then
      make ARCH=\$MAKE_ARCH CROSS_COMPILE=\$CROSS_COMPILE \$MAKE_VERBOSE kvm_guest.config 2>/dev/null || true
    fi

    # ---------------------------------------------------------------
    # config overlays
    # ---------------------------------------------------------------

    # base: storage
    ./scripts/config --enable EXT4_FS
    ./scripts/config --enable ATA
    ./scripts/config --enable ATA_PIIX
    ./scripts/config --enable SATA_AHCI

    # base: networking
    ./scripts/config --enable E1000
    ./scripts/config --enable E1000E
    ./scripts/config --enable VIRTIO_NET

    # base: device infra
    ./scripts/config --enable DEVTMPFS
    ./scripts/config --enable DEVTMPFS_MOUNT

    # base: debug
    ./scripts/config --enable KALLSYMS
    ./scripts/config --enable KALLSYMS_ALL
    ./scripts/config --enable DEBUG_KERNEL
    ./scripts/config --enable MAGIC_SYSRQ

    # base: modules
    ./scripts/config --enable MODULES
    ./scripts/config --enable MODULE_UNLOAD

    # base: introspection
    ./scripts/config --enable IKCONFIG
    ./scripts/config --enable IKCONFIG_PROC

    # KASAN (x86_64: >= 4.0; i386 unsupported — no HAVE_ARCH_KASAN on 32-bit x86;
    #        arm64: >= 4.15; arm32: unsupported)
    WANT_KASAN=false
    if [[ \"\$MAKE_ARCH\" == \"x86_64\" ]]; then
      version_ge \$MAJOR \$MINOR 4 0 && WANT_KASAN=true
    elif [[ \"\$MAKE_ARCH\" == \"arm64\" ]]; then
      version_ge \$MAJOR \$MINOR 4 15 && WANT_KASAN=true
    fi

    if [[ \"\$WANT_KASAN\" == true ]]; then
      ./scripts/config --enable KASAN
      if version_ge \$MAJOR \$MINOR 5 11; then
        ./scripts/config --enable KASAN_GENERIC
      else
        ./scripts/config --enable KASAN_OUTLINE
      fi
    fi

    # debug info
    ./scripts/config --enable DEBUG_INFO
    # Full type info is required for Linux's vmlinux-gdb.py / lx_current helpers.
    # Some arch defconfigs (notably arm64) default DEBUG_INFO_REDUCED=y, which
    # makes the lx scripts refuse to load ("Reduced debug information...").
    # Note: do not write dollar-lx_current in this double-quoted -c body — host
    # set -u expands it before docker runs.
    ./scripts/config --disable DEBUG_INFO_REDUCED
    if version_ge \$MAJOR \$MINOR 5 18; then
      ./scripts/config --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
    fi
    ./scripts/config --enable GDB_SCRIPTS

    # re-sync after overlays
    make ARCH=\$MAKE_ARCH CROSS_COMPILE=\$CROSS_COMPILE \$MAKE_VERBOSE olddefconfig

    if [[ \"\$CONFIG_ONLY\" == true ]]; then
      cp .config /output/.config
      echo 'config-only: .config written to /output/.config' >&2
      exit 0
    fi

    # build
    make ARCH=\$MAKE_ARCH CROSS_COMPILE=\$CROSS_COMPILE \
      \$MAKE_VERBOSE -j"\$JOBS" \$MAKE_TARGET \
      2>&1 | tee /output/build.log >&2
    make ARCH=\$MAKE_ARCH CROSS_COMPILE=\$CROSS_COMPILE \
      \$MAKE_VERBOSE \$GDB_TARGET \
      2>&1 | tee -a /output/build.log >&2

    # copy artifacts and preserve the upstream relative GDB-loader layout
    cp "\$IMAGE_SUBPATH" /output/
    cp vmlinux /output/vmlinux
    cp .config /output/.config
    rm -rf /output/scripts/gdb /output/vmlinux-gdb.py
    mkdir -p /output/scripts
    cp -a scripts/gdb /output/scripts/gdb
    # The build tree's vmlinux-gdb.py is typically a symlink into scripts/gdb.
    # Docker leaves that link as /src/scripts/gdb/... which is meaningless on
    # the host, so dereference into a real file next to scripts/gdb/. With
    # __file__ at the build-root path, the loader's sys.path insert of
    # dirname(__file__)+"/scripts/gdb" resolves correctly on the host.
    if [[ -e vmlinux-gdb.py || -L vmlinux-gdb.py ]]; then
      cp -L vmlinux-gdb.py /output/vmlinux-gdb.py
    else
      cp scripts/gdb/vmlinux-gdb.py /output/vmlinux-gdb.py
    fi
  "

RC=$?
if [[ $RC -ne 0 ]]; then
  log "build failed (exit $RC) — check $OUTDIR/build.log"
  exit 1
fi

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
if [[ "$CONFIG_ONLY" == true ]]; then
  config_cache_complete || die "build appeared to succeed but $OUTDIR/.config not found"
  emit_config_output
else
  if ! build_cache_complete; then
    required_products=(
      "$OUTDIR/$IMAGE_NAME"
      "$OUTDIR/vmlinux"
      "$OUTDIR/.config"
      "$SRCDIR/Makefile"
      "$OUTDIR/vmlinux-gdb.py"
      "$OUTDIR/scripts/gdb/vmlinux-gdb.py"
      "$OUTDIR/scripts/gdb/linux/constants.py"
    )
    for product in "${required_products[@]}"; do
      [[ -f "$product" ]] || die "build appeared to succeed but required product not found: $product"
    done
    die "build appeared to succeed but required products are incomplete"
  fi
  step "Build complete: $OUTDIR/$IMAGE_NAME"
  emit_build_outputs
fi
