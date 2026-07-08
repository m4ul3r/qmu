# qmu

Agent-friendly QEMU VM management CLI for kernel research.

## Install

```bash
uv tool install -e .
qmu skill install
```

`qmu skill install` symlinks the bundled skill into `~/.claude/skills/`. If `~/.codex/` exists, it also installs into `~/.codex/skills/`. Restart your agent to pick up the new skill.

## Quick Start

```bash
qmu config init                            # Drop a starter qmu.toml here, then edit the two `# CHANGE ME` lines
qmu doctor                                 # Verify rootfs / SSH key / QEMU all resolve
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

## Snapshots

```bash
qmu snapshot save clean
qmu snapshot list
qmu snapshot load clean
qmu snapshot delete clean
```

`snapshot save` uses QEMU's HMP `savevm`, which can only store *internal*
snapshots in a **writable qcow2** rootfs disk. The default `[drive] format =
"raw"` image (and the implicit `snapshot=on` overlay) cannot hold them, so
`snapshot save` fails out of the box — convert the rootfs and switch formats:

```bash
qemu-img convert -O qcow2 rootfs.img rootfs.qcow2   # then set [drive] format = "qcow2"
```

Snapshots also require **`--net-backend passt`** (or `[machine] net_backend =
"passt"`). The default `-net user` (slirp) backend can't be serialized by
`savevm`/`loadvm`, so snapshot state does not round-trip. `passt` is a rootless,
migration-capable slirp replacement (`apt install passt` / `pacman -S passt`;
`qmu doctor` checks it). Without both a qcow2 disk and passt, iterate by
relaunching instead of snapshotting.
