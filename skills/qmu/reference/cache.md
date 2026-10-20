# Cache on disk and the `prune` modes

Companion to `skill://qmu`. The main skill lists the everyday `prune`/`cache`
commands; this file is the detail: what each prune mode touches, the `--dry-run`
and age-gate rules, and the cache subtrees outside `instances/`.

## Cache layout

`qmu prune` reaches `~/.cache/qmu/instances/` and the runtime root — **not** the
rest of the cache. `tools/kbuild.sh`, `tools/mkrootfs.sh` and `tools/mktarget.sh`
write `kernels/`, `rootfs/` and `targets/` into the same directory
(`$QMU_CACHE_DIR` overrides the root for all of them). Every `prune` result
carries an `unmanaged_cache` key naming the build caches it did not cover.

```bash
qmu cache du                  # per-subtree sizes + what is reclaimable
qmu cache ls --top 10         # biggest reclaimable source trees
qmu cache ls --bucket all     # including held-back and refused entries
```

Sizes are **allocated** blocks, not apparent size. `targets/` and `rootfs/` hold
sparse ext4 images, so `st_size` can exceed their physical allocation;
`apparent_bytes` is reported alongside for reference. `--format` for the `cache`
group goes before `cache` (`qmu --format json cache du`), not between `cache`
and `du`.

## Instance prunes (`--vm`, `--all`)

`qmu prune --vm <name>` removes a stopped VM's state files — including the
`.json` + `.serial.log` + `.qemu.log` that `kill` preserves when a crash
report is waiting, at any age; `--keep-logs` drops `.json` + `.qmp.sock` but
preserves `.serial.log` and `.qemu.log`. `qmu prune --all` does the same for
every stopped VM; qmu never recommends it, and on a shared host only
`--all --dry-run` is ever appropriate.

`prune --vm <name>` for a VM that no longer has any state (the normal case
right after a plain `qmu kill`, which already removed everything) is a clean
no-op: exit 0, `pruned: []`, `found: false`, and a note that there was
nothing to remove — so `kill && prune` cleanup scripts never see a spurious
failure (after `cleaned: true` there is nothing to prune; prune only after
`logs_preserved: true` or `--no-clean`). A typo'd name gets the same answer;
check `qmu list` if you expected state to exist.

**Remnants and the age gate.** If a VM's `.json` is gone but its logs remain,
`qmu list` still synthesizes an entry for it. A serial-log-only remnant
prunes at any age. Only a metadata-free remnant that still has a `.qemu.log`
or `.qmp.sock` is age-gated: `qmu prune --vm <id>` leaves one younger than
`--older-than` (default 24 h) alone, reports it under `held_back`
(`status: "held_back"` in `list`/`status`), and `--older-than 0` clears it
now — the same flag looks like a no-op on an ordinary stopped VM. `qmu list`
also distinguishes a remnant whose QEMU is still alive (`[ORPHANED — process
alive]`, `status: "orphaned"` in JSON) from a genuinely stopped one, so a
live orphan holding your rootfs can never present as "nothing running". Reap
it with `qmu prune --orphans` (use `--dry-run` first on a shared machine), or
with `qmu kill --vm <id>` — kill handles an orphaned remnant by signalling
its process and preserving the serial log. `qmu prune --all` names any
remnant the age gate held back rather than reporting "No stopped VMs to
prune" while `qmu list` still shows one.

**`held_reason` names why.** Every `held_back` answer (`status --vm X`,
`list` stopped rows, `prune --vm`/`--all` in both `--dry-run` and real mode)
carries `held_reason`: `age` — the gate above, cleared by `--older-than 0`;
`malformed-metadata` — the VM's `.json` exists but cannot be parsed and no
serial log corroborates it, so prune refuses it at **every** age (`--older-
than 0` is not the fix) and lists it under `refused[]` as `{vm_id, reason,
path}`; text says `metadata unreadable: <path> — repair or delete the .json
by hand, then prune`. `qmp-busy` — the remnant's socket still answers, so a
QEMU is alive behind it: reap it (`kill --vm`, `prune --orphans`) first.
`held_reason` is `null` for every state other than `held_back`.

## `--dry-run`

**`--dry-run` previews; it never acts.** Supported with `--vm`, `--all`,
`--orphans`, and `--build-residue`. It prints what would be removed or killed,
leaves everything in place, and reports `dry_run: true` with `pruned: []` plus
a `would_prune` / `would_kill` list in JSON — so a script can always tell a
preview from a real run. `--runtime` has no preview pass and rejects the flag
(exit 1, a `QMUError`, not argparse's 2) rather than acting under it. A real
prune reports `dry_run: false`.

## `--orphans`

Kills qmu-launched QEMUs that no instance record claims. It matches only QEMUs
launched by qmu, via the QMP socket path in their argv, so it can never touch an
unrelated QEMU — but on a shared host it **does** touch another agent's VM
whose record was lost (an `orphaned` entry in `qmu list` with a foreign name
is exactly that). Always `--dry-run` first there and read `would_kill[].vm_id`.

## `--runtime`

`qmu prune --runtime` removes only aged **marked** automatic output spills and
aged definitely stale direct `cm-*` Unix sockets under the runtime root. It
skips live/uncertain SSH controls, explicit `--out` files, unmarked lookalikes,
symlinks, and unrelated temp names (including arbitrary `/tmp/qmu-*`). Default
age is 86400 seconds; use `--older-than SECONDS` (non-negative). The command is
idempotent and never recursively deletes the runtime root.

## `--build-residue`

`kbuild.sh` builds in-tree, so `kernels/src/linux-*/` accumulates `*.o`, `*.a`,
`.*.cmd` and other intermediates. They carry no value to kbuild, which runs
`make mrproper` at the start of every containerised build:

```bash
qmu prune --build-residue --dry-run   # always preview first
qmu prune --build-residue
```

It **never** removes `vmlinux`, `vmlinux.unstripped`, `System.map`, `Makefile`,
`.config`, anything under `arch/*/boot/`, or any symlink. An interrupted build
may leave the only usable outputs in its source tree; residue cleanup preserves
those artifacts, but cache reuse still requires the builder's complete output
and helper contract.

Results are bucketed, and the buckets partition the total:

| Bucket | Meaning |
|---|---|
| `eligible` | will be removed |
| `held_back` | tree modified inside `--older-than`; may be mid-build. Once the build is done, a **smaller** `--older-than` (down to 600) releases it — a larger one only holds back more |
| `refused` | parent dir not writable, or referenced by an instance record |

`--older-than` defaults to 86400 and is **floored at 600s** for this mode:
kbuild bind-mounts the source tree read-write for the whole build, so a lower
value is refused rather than clamped. `qmu cache du`/`ls` accept any value (they
never delete) and annotate when you ask for one prune would refuse.

Prevent residue at the source with `tools/kbuild.sh --keep-residue` (default is
to clean after a successful build).
