#!/usr/bin/env bash
# Reproducible test-asset builder for qmu live testing.
#
# Produces, all under tests/assets/:
#   qmu_test.id_rsa{,.pub}   ed25519 keypair the guest trusts
#   bzImage  -> linux-<KVER>/arch/x86/boot/bzImage   (symlink)
#   vmlinux  -> linux-<KVER>/vmlinux                  (symlink, DWARF symbols)
#   rootfs.img                                        raw ext4, sshd + gcc + test key
#   uaf.ko                                            buggy LKM -> KASAN slab-UAF on insmod
# and tests/qmu.toml pointing at all of the above with absolute paths.
#
# The kernel + module are built inside a Debian bookworm container (GCC 12),
# because the host toolchain (GCC 16, -std=c23 default) cannot build 6.6.75.
# Idempotent: re-running skips steps whose output already exists.
set -euo pipefail

KVER="${KVER:-6.6.75}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ASSETS="$HERE"
TESTS_DIR="$(cd "$ASSETS/.." && pwd)"
SRC="$ASSETS/linux-$KVER"
JOBS="$(nproc)"
KBUILD_IMAGE="qmu-kbuild:bookworm"

step() { echo "=== [$(date +%H:%M:%S)] $* ==="; }

# ---------------------------------------------------------------------------
# 1. SSH keypair
# ---------------------------------------------------------------------------
if [[ ! -f "$ASSETS/qmu_test.id_rsa" ]]; then
  step "Generating SSH keypair"
  ssh-keygen -t ed25519 -N '' -f "$ASSETS/qmu_test.id_rsa" -C qmu-test
fi
chmod 600 "$ASSETS/qmu_test.id_rsa"
PUBKEY="$(cat "$ASSETS/qmu_test.id_rsa.pub")"

# ---------------------------------------------------------------------------
# 2. Kernel source
# ---------------------------------------------------------------------------
cd "$ASSETS"
if [[ ! -d "$SRC" ]]; then
  if [[ ! -f "linux-$KVER.tar.xz" ]]; then
    step "Downloading kernel $KVER"
    curl -fL --retry 3 -o "linux-$KVER.tar.xz" \
      "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KVER.tar.xz"
  fi
  step "Extracting kernel source"
  tar xf "linux-$KVER.tar.xz"
fi

# ---------------------------------------------------------------------------
# 3. Kernel build toolchain container (GCC 12 / C17 default)
# ---------------------------------------------------------------------------
if ! docker image inspect "$KBUILD_IMAGE" >/dev/null 2>&1; then
  step "Building kernel-build container image"
  docker build -t "$KBUILD_IMAGE" -f - "$ASSETS" <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential bc bison flex libelf-dev libssl-dev cpio kmod xz-utils python3 \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

# ---------------------------------------------------------------------------
# 4. Kernel config + build + buggy module — all inside the container so the
#    toolchain (and module vermagic) are consistent.
# ---------------------------------------------------------------------------
if [[ ! -f "$SRC/arch/x86/boot/bzImage" ]] || [[ ! -f "$ASSETS/uaf.ko" ]]; then
  step "Building kernel + module in container (GCC 12, -j$JOBS) — long step"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e KVER="$KVER" -e JOBS="$JOBS" \
    -e KBUILD_BUILD_USER=qmu -e KBUILD_BUILD_HOST=qmu-test \
    -v "$ASSETS:/work" -w "/work/linux-$KVER" \
    "$KBUILD_IMAGE" bash -euo pipefail -c '
      echo "container gcc: $(gcc --version | head -1)"
      if [[ ! -f arch/x86/boot/bzImage ]]; then
        make mrproper
        make defconfig
        make kvm_guest.config || true
        ./scripts/config \
          --enable EXT4_FS \
          --enable ATA --enable ATA_PIIX --enable SATA_AHCI \
          --enable E1000 --enable E1000E \
          --enable MAGIC_SYSRQ \
          --enable DEVTMPFS --enable DEVTMPFS_MOUNT \
          --enable KASAN --enable KASAN_GENERIC \
          --enable KALLSYMS --enable KALLSYMS_ALL \
          --enable DEBUG_KERNEL --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
          --enable GDB_SCRIPTS \
          --enable MODULES --enable MODULE_UNLOAD \
          --enable IKCONFIG --enable IKCONFIG_PROC
        make olddefconfig
        make -j"$JOBS" bzImage
        make -j"$JOBS" modules_prepare
      fi
      # Buggy module -> deterministic KASAN slab-use-after-free on insmod
      mkdir -p /tmp/uaf
      cat > /tmp/uaf/uaf.c <<EOF
#include <linux/module.h>
#include <linux/slab.h>
static int __init uaf_init(void)
{
	char *p = kmalloc(128, GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	kfree(p);
	pr_info("qmu-uaf: triggering use-after-free\n");
	p[0] = 0x41; /* KASAN: slab-use-after-free */
	return 0;
}
static void __exit uaf_exit(void) {}
module_init(uaf_init);
module_exit(uaf_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("qmu test: deliberate slab-use-after-free for KASAN");
EOF
      echo "obj-m += uaf.o" > /tmp/uaf/Makefile
      # modules_prepare does not emit Module.symvers; symbols (kfree, __asan_*,
      # ...) are all exported by the running kernel and resolve at insmod time,
      # and this kernel has neither MODVERSIONS nor MODULE_SIG, so build past the
      # missing-symvers undefined-symbol errors with KBUILD_MODPOST_WARN=1.
      make -C "/work/linux-$KVER" M=/tmp/uaf modules KBUILD_MODPOST_WARN=1 || true
      cp /tmp/uaf/uaf.ko /work/uaf.ko 2>/dev/null \
        || echo "WARNING: uaf.ko not built; live crash test will fall back to sysrq"
    '
fi
ln -sf "$SRC/arch/x86/boot/bzImage" "$ASSETS/bzImage"
ln -sf "$SRC/vmlinux" "$ASSETS/vmlinux"

# ---------------------------------------------------------------------------
# 5. Rootfs: docker image -> raw ext4
# ---------------------------------------------------------------------------
if [[ ! -f "$ASSETS/rootfs.img" ]]; then
  step "Building rootfs container image"
  # Quoted heredoc: nothing is expanded on the host. The pubkey comes in via a
  # build-arg, and runtime $(...) in the diag service is preserved literally.
  docker build --build-arg "PUBKEY=$PUBKEY" -t qmu-test-rootfs -f - "$ASSETS" <<'DOCKERFILE'
FROM debian:bookworm-slim
ARG PUBKEY
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd-sysv openssh-server gcc libc6-dev make iproute2 ethtool kmod \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /root/.ssh \
 && printf '%s\n' "$PUBKEY" > /root/.ssh/authorized_keys \
 && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys \
 && passwd -d root \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config \
 && echo qmu-test > /etc/hostname \
 && printf '/dev/sda / ext4 defaults 0 1\n' > /etc/fstab \
 && systemd-machine-id-setup || true
# Static networking via an explicit oneshot — no DHCP, no networkd matching
# ambiguity. QEMU user-net forwards hostfwd -> 10.0.2.15:22. e1000+slirp drops
# guest TX when checksum/segmentation offload is on, so disable offload first.
# The final ExecStart echoes the live state to the serial console (runs in the
# guest, since $(...) stays literal in this quoted heredoc) for SSH-less diag.
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

  step "Exporting container filesystem"
  CID="$(docker create qmu-test-rootfs)"
  ROOTDIR="$(mktemp -d)"
  docker export "$CID" | sudo tar -x -C "$ROOTDIR"
  docker rm "$CID" >/dev/null

  step "Creating raw ext4 image (2G)"
  sudo mke2fs -F -q -t ext4 -d "$ROOTDIR" -L qmu-root "$ASSETS/rootfs.img" 2G
  sudo chown "$(id -u):$(id -g)" "$ASSETS/rootfs.img"
  sudo rm -rf "$ROOTDIR"
fi

# ---------------------------------------------------------------------------
# 6. Generate tests/qmu.toml with absolute paths
# ---------------------------------------------------------------------------
step "Writing $TESTS_DIR/qmu.toml"
cat > "$TESTS_DIR/qmu.toml" <<TOML
# Generated by tests/assets/build.sh — qmu live-test configuration.
[machine]
arch = "x86_64"
memory = "2G"
cpus = 2

[drive]
rootfs = "$ASSETS/rootfs.img"
format = "raw"

[ssh]
key = "$ASSETS/qmu_test.id_rsa"
user = "root"
port_start = 10021

[gdb]
port_start = 1234
TOML

step "DONE — assets ready:"
ls -lhL "$ASSETS"/bzImage "$ASSETS"/rootfs.img "$ASSETS"/qmu_test.id_rsa "$ASSETS"/uaf.ko 2>/dev/null || true
echo "Kernel: $(readlink -f "$ASSETS/bzImage")"
echo "Try:  qmu launch --config '$TESTS_DIR/qmu.toml' --kernel '$ASSETS/bzImage'"
