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

## `snapshot save --timeout` and the unknown result

HMP `savevm` writes every non-zero guest page synchronously on QEMU's main
loop, so its cost is the guest's dirty RAM and the host's disk. Measured on
QEMU 8.2.2/NVMe with RAM fully dirtied: 1 GiB 4.9 s idle, ≈4 s under four
`dd oflag=direct` writers + ten CPU burners; 4 GiB 15.6 s idle, 22.2 s
loaded; a 4 GiB save into a 19 GB qcow2 that already held five snapshots
took ≈60 s. The default budget is therefore **60 s + 20 s per GiB of guest
RAM** (`-m 4G` → 140 s, `1G` → 80 s; unreadable size → 140 s), ≥ 3× the
loaded measurement; `qmu snapshot save X --vm V --timeout SECONDS` overrides
it.

When the budget expires the save has **not failed — its result is unknown**:
QEMU is still inside `savevm`, the tag usually lands later, and every QMP
command queues behind it until then. qmu reports exactly that: exit **124**
(the `wait` timeout code; not 4, the transport did not break), `ok: false`,
`error_type: "SnapshotError"`, `may_have_landed: true`, `timeout`, and a
`hint` naming the one command that settles it: `qmu snapshot list --vm V
--timeout 300` (twice the budget, ≥ 300 s), which waits for QEMU to answer
instead of dying at the 30 s `list` default while QEMU is still writing.
Text mode says the same on stderr (`[qmu] Error: snapshot save 'X' … did not
finish within Ns …`, `may_have_landed: true`, the hint). Do not retry the
save until the list answers; pass the longer `--timeout` next time. A proven
HMP failure (exit 1) carries `may_have_landed: false` — `save` cross-checks
`info snapshots` before it reports either way.

The qmu-side mechanics that make the follow-up safe: a client whose command
timed out closes its socket at once (the late reply would otherwise be read
as the answer to its next command), every command carries a client-unique
`id`, and a reply tagged with another client's `id` is dropped — QEMU hands
the abandoned `savevm` reply to whichever client holds the socket when it
finishes, which made `query-status` return `{}` and `snapshot list` say "No
snapshots." for a tag that was there. While QEMU is still saving, `status`
and `list` report `qmp: "busy"`, `qemu_status: "unknown"` — standalone because
QEMU greets the connection but does not answer `qmp_capabilities` within its
10 s floor, daemon-backed because QEMU stopped the vCPUs under the `savevm`
the daemon is carrying (never the debugger-halt `guest: "paused"` + `qmu cont`
signature; `savevm` resumes the guest itself). A successful `snapshot load`
starts a new crash scope for every reader at once — `status`, `list` and
`crash` all stop attributing a report from before the load.

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

**Every writable drive must hold snapshots, not just the root disk.** An
extra raw `-drive` (an app/data disk in `[machine] extra_args` or a second
`--drive`) without `snapshot=on`/`readonly=on` makes `save` (and `load`) fail
with `Device 'virtio1' is writable but does not support snapshots` — the
device name is QEMU's (`qmu monitor 'info block' --vm X` maps it to the
file). The `hint` names that drive and the fix: add `snapshot=on`
(session-only, like the rootfs overlay) or `readonly=on` to its `-drive`
spec, or convert it to qcow2 for durable snapshots.

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
command after a load can stall on the stale master until its `--timeout`
(exiting 124 or 4, sometimes with a one-off `Broken pipe`) — if you ever see
that symptom, `ssh -O exit` on the control socket under `$QMU_TEMP_DIR/ssh`
(or a second `qmu exec`) clears it.

The same teardown ends every guest command still running through that
master: a `qmu exec`/`run`/`compile --run`/`dmesg` in flight when another
pane loads (or saves, or resets) the VM is exit 4 with `ssh_error: true`,
`exit_code: null` and `severed_by: "snapshot load"` (`"snapshot save"`,
`"loadvm"`, `"savevm"`, `"system_reset"` for the other routes; `"guest
reboot"` when a new kernel boot banner appeared under it) — never the guest
program "exiting 255". Re-run it on the restored guest; a command started
detached in the guest does not survive a load either, since the load rewinds
its process too.

The guest wall clock resumes at the snapshot's save time and stays behind the
host by the time since the save (cumulative across loads; a guest with
reachable NTP will step forward). `qmu log` shows the host-side console,
which is never rewound: its tail can describe the discarded timeline, with
uptimes later than the restored guest's. Use `qmu crash`/`wait --pattern`,
which scope to the load.

A `load` whose HMP `loadvm` fails is exit 1, `ok:false` with `error`,
`error_type: "SnapshotError"`, `hint`, and three load-only keys: `resumed`,
`guest_paused`, `restore_state`. What qmu does next depends on how far
`loadvm` got (`restore_state`):

- `none` — nothing was restored. A tag absent from `info snapshots` is
  caught **before** `loadvm`, so the guest never stops (`resumed: false`,
  `guest_paused: false`, hint `Snapshot 'X' is not in the image of VM 'Y'.
  List what exists: qmu snapshot list --vm Y`). Only when QEMU itself refuses
  a *listed* tag pre-restore (a partial snapshot) does `loadvm` pause the
  guest first (`restore-vm`); qmu then resumes it (`resumed: true`;
  `guest_paused: true` only if that resume itself failed, with a `qmu cont
  --vm X --force` hint: nothing was restored, and plain `qmu cont` refuses
  `restore-vm`). The raw routes (`qmu monitor 'loadvm X'`, `qmu qmp
  human-monitor-command`) have no pre-check, so every refused tag pauses the
  guest there; qmu resumes it the same way, and their exit-1 `QMUError`
  envelope carries the same `restore_state`, `resumed`, `guest_paused`,
  `vm_id` and hint (#206). A running guest stays running on every route.
- `partial` / `unknown` — restoration had begun (an incompatible device set,
  e.g. an e1000 snapshot loaded into a virtio-net boot; `Missing section
  footer`, `error while loading state`). QEMU reverts the **disks before** it
  loads the vmstate, so the machine is now pre-snapshot devices over
  post-snapshot disks. qmu deliberately leaves it **paused**
  (`guest_paused: true`; `status` shows `guest: "paused"`, QEMU status
  `restore-vm`; `exec`/`push`/`pull`/`compile`/`dmesg` refuse with
  `guest_state: "paused"`) and the hint says `Do not resume it blindly with
  qmu cont`: recover with a known-good `qmu snapshot load <tag> --vm X` or
  `qmu kill --vm X` + `qmu launch`. `qmu cont --vm X` enforces this: against
  `qemu_status: "restore-vm"` it refuses (exit 1, no `cont` sent) and names
  the same two recoveries; `qmu cont --force` sends it anyway, for an
  operator who accepts an inconsistent machine — ordinary `paused`/`debug`
  halts are unaffected. The recovery load needs no `qmu cont`:
  QEMU alone would leave a `restore-vm` guest stopped (`loadvm` only restarts
  a guest that was running), so qmu issues `cont` in exactly that case and
  the success envelope says so (`resumed: true`, text `Guest resumed (it was
  stopped by a previous failed load).`); afterwards `status` is `serving` and
  `exec` works. A raw `qmu monitor 'loadvm X'` that fails
  the same way carries the same no-`cont` hint and `restore_state`; with a debugger attached the
  stale-session warning (#44) fires too, because a partial restore did rewind.

HMP error replies on `save`/`load`/`delete` are failures (same envelope), and
`save` confirms the tag in `info snapshots` before reporting success. The
success envelope of `load` is `{ok, message, name, resumed}` — `resumed` is
true only for the recovery case above (a raw `loadvm` that succeeds carries
the same `resumed` next to `output`/`result`); a guest the operator or a debugger
paused (`paused`/`debug`) stays paused after a successful load, as before. It
carries no `ssh` key. HMP error detection is anchored to the **start** of a
reply line (`Error: `, `unknown command: `, `Snapshot '…' does not exist`,
…), so a tag such as `Error:checkpoint` saves, lists and loads normally and
`qmu monitor 'info snapshots'` / `qmu qmp human-monitor-command` return 0
with it in the table.

## Debugger interaction

`snapshot save` taken while a debugger has the guest running bakes its
breakpoints' `int3` bytes into the image (under KVM); a save at a debugger
stop is clean, and with the bridge `qmu gdb` spawned attached qmu stops it
for the save and resumes it after (`breakpoints_lifted: true`). On a `--gdb`
VM the save's envelope says what the image holds as `breakpoints_in_image`
(`possible` with a warning / `lifted` with a note / `never` under TCG), on
the raw routes (`qmu monitor 'savevm X'`, `qmu qmp human-monitor-command`)
as on `snapshot save` (#227).
`snapshot load` leaves an attached debugger with a stale view, and on a KASLR
guest an image from an earlier boot restores that boot's kernel base: qmu
rebases (`pry kbase`) and re-syncs (`pry resync`) the bridge `qmu gdb`
spawned, reported as `debugger` in the envelope, and warns about any other
client. See the coherence table in `skill://qmu/reference/debugging.md`
before mixing snapshots and pry.
