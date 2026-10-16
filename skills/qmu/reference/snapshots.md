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
modified, and the checkpoints disappear when the QEMU process exits.

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
`ok:false` with `error`/`error_type: "SnapshotError"` — and `save` confirms
the tag in `info snapshots` before reporting success.

## Debugger interaction

`snapshot save` with software breakpoints armed bakes their `int3` bytes into
the image, and `snapshot load` leaves an attached debugger with a stale view.
See the coherence table in `skill://qmu/reference/debugging.md` before mixing
snapshots and pry.
