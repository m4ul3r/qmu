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
qmu crash --vm kctf-test                 # current guest epoch only
qmu crash --vm kctf-test --full-history  # retained-log forensics
```

`--harness` implies `--no-wait-ssh` and `--no-net`, and skips the rootfs/SSH
key requirements. SSH-using commands (`push`, `pull`, `exec`, `compile`,
`dmesg`) error out with a clear message; serial-only commands (`log`, `crash`,
`wait`, `qmp`, `monitor`, `kill`) work as usual.

`qmu wait` retains QMP `RESET`/`STOP`/`SHUTDOWN`/`POWERDOWN` events and
non-running QEMU states as observations, but reports `stopped:true` and exits
`0` only after the recorded QEMU process identity has exited. If `--timeout`
elapses while that process is still alive, it exits `124` with
`stopped:false` and preserves the latest QMP observation.

`qmu crash` searches only the current guest epoch by default. A successful
`snapshot load` or an observed guest reset advances that epoch, so an older
panic retained in the serial log is not presented as current. Use
`--full-history` only for forensics across previous epochs. JSON/NDJSON results
identify the selected `scope` (`current` or `history`) and report detection in
`crash_detected`.

## Runtime cleanup

```bash
qmu prune --runtime --older-than 86400
```

Idempotent, age-gated cleanup of **qmu-owned** runtime artifacts only (marked
automatic output spills and stale SSH ControlMaster sockets under the
centralized runtime root). It never scans arbitrary `/tmp/qmu-*` names. See
the qmu skill for ownership markers, root precedence (`QMU_TEMP_DIR` /
`XDG_RUNTIME_DIR` / platform temp), and safety boundaries.

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

**Ephemeral in-session rewind.** By default qmu attaches the configured rootfs
through a temporary `snapshot=on` COW overlay. HMP `savevm`/`loadvm` checkpoints
can therefore provide in-session rewind with a raw or qcow2 base. The base stays
unchanged, and the checkpoints disappear when the QEMU process exits.

**Durable internal snapshots.** Attach a writable qcow2 drive without
`snapshot=on`, for example:

```bash
qemu-img convert -O qcow2 rootfs.img rootfs.qcow2
qmu launch --kernel ./bzImage \
  --drive 'file=./rootfs.qcow2,format=qcow2'
```

Changing `[drive] format` alone is not durable because qmu still places the
configured rootfs behind its temporary overlay.

**Migration/loadvm networking compatibility.** The default user/slirp backend
often restores in-session checkpoints successfully. If `loadvm` reports slirp
section/footer errors for a particular QEMU/build/device combination, use native
passt only when the selected QEMU advertises it, or manually manage an external
passt process with QEMU's `stream` backend. Native passt is documented since
QEMU 10.1 but may be build-optional; qmu probes the capability instead of using
the version as the decision. qmu does not manage an external passt process.
