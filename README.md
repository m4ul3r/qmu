# qmu

Agent-friendly QEMU VM management CLI for kernel research.

## Install

```bash
uv tool install -e .
qmu skill install
```

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage
qmu exec "uname -a"
qmu compile exploit.c --run
qmu crash
qmu kill
```

Run `qmu --help` for full usage.

## Harness mode (boot-and-die VMs)

For kernelCTF judge envs, syzkaller reproducers, and other VMs that boot from
kernel + initramfs + read-only rootfs, run a one-shot `init=` script, and halt:

```bash
qmu launch --harness \
  --name kctf-test \
  --kernel ./bzImage \
  --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,cache=none,aio=native,format=raw,discard=on' \
  --drive 'file=./flag,if=virtio,format=raw,readonly' \
  --cmdline 'console=ttyS0 root=/dev/vda1 rootfstype=ext4 ro init=/home/user/run.sh' \
  --memory 3.5G

qmu wait --vm kctf-test --timeout 60
qmu log  --vm kctf-test --tail 100
qmu crash --vm kctf-test
```

`--harness` implies `--no-wait-ssh` and `--no-net`, and skips the rootfs/SSH
key requirements. SSH-using commands (`push`, `pull`, `exec`, `compile`,
`dmesg`) error out with a clear message; serial-only commands (`log`, `crash`,
`wait`, `qmp`, `monitor`, `kill`) work as usual.

`qmu wait` blocks on QMP `STOP`/`SHUTDOWN`/`POWERDOWN` events, falling back to
PID-liveness polling. Exit code `0` on clean stop, `124` on `--timeout`.

## Rootfs injection (no root needed)

For read-only rootfs images, inject files via libguestfs (`apt install
libguestfs-tools` or `dnf install libguestfs-tools-c`):

```bash
qmu rootfs inject ./rootfs.img ./run.sh:/home/user/ ./exploit:/root/
qmu rootfs shell  ./rootfs.img --partition 1   # interactive guestfish
```

`GUEST` is interpreted as a directory; the local filename is preserved.
`--partition 0` selects the whole disk for unpartitioned images.
