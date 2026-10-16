# Snapshot internals

Companion to `skill://qmu`. The everyday commands (`qmu snapshot save|list|load|delete`)
and the rewind loop are in the main skill; this file covers what a snapshot
can and cannot capture, durability, networking compatibility, and the
post-load SSH behavior.

## What works out of the box

qmu attaches the configured rootfs through a temporary `snapshot=on` COW
overlay. That overlay **is a qcow2** (QEMU creates it under `/var/tmp/vl.*`), so
HMP `savevm`/`loadvm` checkpoints work with the default `raw` base and the
default user/slirp NIC — verified on QEMU 8.2.2: `snapshot save` ≈2.5 s,
`load` 1–4 s, state rewound, no slirp warning. The base image is never
modified. The overlay is discarded when the QEMU process exits, taking the
checkpoints **and every guest disk write of the session** with it: after
`kill` + relaunch the guest starts from the pristine image (a file written
before the kill is gone). Rewind (`load` + first `exec`, ≈1.6 s) versus
relaunch (`kill` + `launch` + first `exec`, ≈7 s) is the comparison that
matters; both discard disk state, only the rewind keeps the checkpoint.

`snapshot list` JSON is `snapshots: [{id, tag, vm_size, date, time,
vm_clock}]` straight from HMP `info snapshots`; `vm_size` is QEMU's
human-readable RAM-image size (for example `820 MiB` or `1.36 GiB`), not
an integer byte count. Fractional sizes remain visible to `list` and usable
by `save`/`delete`. Each checkpoint stores that image in the overlay under
`/var/tmp` — the cost of a `save` on a shared host.

## Durable internal snapshots

To keep snapshots across `kill`/relaunch, attach a writable qcow2 drive without
`snapshot=on`:

```bash
qemu-img convert -O qcow2 rootfs.img rootfs.qcow2
qmu launch --kernel ./bzImage \
  --drive 'file=./rootfs.qcow2,format=qcow2'
```

Changing `[drive] format` alone is not durable because qmu still places the
configured rootfs behind its temporary overlay. `savevm` needs an attached
snapshot-capable writable layer; harness configurations with only readonly
drives may not provide one.

## Networking compatibility

The default user/slirp backend restores in-session checkpoints on current
QEMU. If `loadvm` reports slirp section/footer errors for a particular
QEMU/build/device combination, use native passt only when the selected QEMU
advertises it (`[machine] net_backend = "passt"`; qmu probes the capability
rather than trusting the version, and refuses with a clear message — also
flagged by `qmu doctor` — when the QEMU cannot do it), or manually manage an
external passt process with QEMU's `stream` backend. qmu does not manage an
external passt process.

## After `snapshot load`

`snapshot load` tears down the VM's SSH ControlMaster (the multiplexed
connection that was alive when the snapshot was taken), so the first `qmu exec`
after a load connects fresh and is fast. Without that teardown the first SSH
command after a load stalls 15–20 s on the stale master's keepalive expiry
(exiting 124 or 4, sometimes with a one-off `Broken pipe`) — if you ever see
that symptom, `ssh -O exit` on the control socket under `$QMU_TEMP_DIR/ssh`
(or a second `qmu exec`) clears it.

A `load` whose HMP `loadvm` fails (typo'd name, incompatible device state)
**resumes the guest** instead of leaving it silently paused (`resumed: true`
in JSON; `guest_paused: true` with a `qmu cont` hint if the resume itself
failed). HMP error replies on `save`/`load`/`delete` are failures — exit 1,
`ok:false` with `error`, `error_type: "SnapshotError"` and `hint` (`qmu
snapshot list --vm X`) — and `save` confirms the tag in `info snapshots`
before reporting success. The success envelope of `load` is `{ok, message,
name}`; it carries no `resumed`/`ssh` key.

## Debugger interaction

`snapshot save` with software breakpoints armed bakes their `int3` bytes into
the image, and `snapshot load` leaves an attached debugger with a stale view.
See the coherence table in `skill://qmu/reference/debugging.md` before mixing
snapshots and pry.
