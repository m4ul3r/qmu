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

## One-shot runs

`qmu run` collapses `launch` → `exec` → `kill` into one command whose exit code
is the *guest command's*:

```bash
qmu run --kernel ./bzImage -- './exploit'
qmu run --kernel ./bzImage --keep -- 'id'     # leave the VM up afterwards
```

`0` guest command succeeded · `1` guest command failed (or the VM died before
SSH came up) · `3` kernel crash · `124` guest never became reachable, or the
command exceeded `--timeout` while the guest was still healthy.

On a clean run the VM is reaped and stdout matches what `qmu exec` would have
printed. Whenever anything is left to inspect — a crash, a survived kernel
report, a guest that never answered, a VM that died on boot — the VM is stopped
but its `.serial.log` and metadata are **preserved**, and the output names the
follow-up (`qmu crash --vm ID`, `qmu prune --vm ID`). Exit `3` requires a
terminal panic; a boot that only logged a WARNING is still `124`.

`run` takes launch's boot flags, minus `--harness`/`--no-wait-ssh` (it needs
SSH), and carries QEMU passthrough as a repeatable `--qemu-arg` because the
positional is the guest command: `--qemu-arg=-M --qemu-arg=virt`.

## Building on the host

`qmu compile --host` builds with a host toolchain for the *guest* arch and
pushes the binary, so the guest needs no gcc:

```bash
qmu compile exploit.c --host --run
qmu compile exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

Worth it whenever the rootfs ships no compiler (kernelCTF, vendor firmware,
minimal Debian) or the guest is emulated — measured on the bundled sample
against an emulated aarch64 guest: 1.2s on the host vs 6.3s in the guest.
The compiler is chosen from the instance's recorded arch (`aarch64` →
`aarch64-linux-gnu-gcc`), never the host's.

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
