---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

Use this skill when the user wants to boot, manage, or interact with QEMU VMs for kernel security research. qmu emits structured JSON or text output and handles the common pain points of QEMU-based kernel exploit development. Run `qmu --help` for full usage.

## Bootstrapping a new instance

A fresh project has no `qmu.toml`. Drive setup through these steps — do not hand-write a config:

1. **`qmu doctor`** — surfaces what's missing (prints a `qmu config init` tip if no config is found).
2. **`qmu config init`** — drops a host-arch-aware starter `qmu.toml` with `# CHANGE ME` lines.
3. **Edit the `# CHANGE ME` lines**: `[boot] kernel` → kernel image, `[drive] rootfs` → rootfs image path, `[ssh] key` → private key matching the rootfs (relative, absolute, and `~` paths all work).
4. **`qmu doctor`** again — confirm `rootfs image`, `SSH key`, `SSH key permissions` show `[+]`; fix any `[!]` before launching.
5. **Boot-and-die kernels** (kernelCTF judge envs, syzkaller reproducers): skip the `[drive]`/`[ssh]` edits, leave those tables blank, and launch with `qmu launch --harness ...` (see Harness mode).

Set `[boot] kernel` and the rest of the boot recipe in `qmu.toml` **before you
start iterating**. Every launch flag has a config key, so a complete `[boot]`
table reduces each subsequent boot to a bare `qmu launch` — flags then exist
only for the one-off deviation, not for restating the same eight arguments
dozens of times.

Project-local `./qmu.toml` is right for per-project rootfs/kernel paths; per-user defaults (e.g. your SSH key) belong in `~/.config/qmu/config.toml`.

## Configuration

Configuration combines built-in defaults with TOML sources and CLI flags. Resolution order, later wins:

1. Built-in defaults — arch=x86_64, memory=4G, cpus=2
2. Global config — `~/.config/qmu/config.toml`
3. Project config — `qmu.toml` found by walking up from CWD
4. CLI flags — `--rootfs`, `--memory`, `--arch`, etc.

```bash
qmu config show         # Resolved config and its sources
qmu config init         # Write starter qmu.toml in CWD
qmu config path         # Show config search paths
```

TOML settings are table-scoped. The accepted schema is:

- `[boot]`: `kernel`, `initrd`, `cmdline`, `profile`
- `[machine]`: `arch`, `memory`, `cpus`, `cpu`, `nic_model`, `net_backend`, `accel`, `extra_args`
- `[drive]`: `rootfs`, `format`
- `[ssh]`: `key`, `user`, `port_start`
- `[gdb]`: `port_start`
- `[profiles.<name>]`: `cmdline`; `[profiles] name = "..."` is also accepted

Every loaded global, project, or explicit `--config` file is validated before
its values are applied. Malformed TOML, unknown keys, misplaced keys, wrong
section shapes, and wrong value types fail with the source path and offending
key. For example, use `[machine] arch`, `[drive] rootfs`, and `[ssh] key`; flat
`arch`, `rootfs`, or `ssh_key` entries are invalid and the error names the
canonical destination.

Each layer may be empty or partial. `[drive]` and `[ssh]` are not universally
required: another layer or CLI flags may provide their values, and harness mode
intentionally runs without them. Later valid layers still win according to the
precedence above.

An invalid **global** config (`~/.config/qmu/config.toml`) is non-fatal: qmu
prints a one-line `[qmu] Warning:` naming the file and continues from built-in
defaults and any valid project/CLI layers, so a single stale global file never
bricks every command (including `qmu doctor`, which diagnoses it). An invalid
**project** (`qmu.toml`) or explicit `--config` file is fatal (exit 1) with the
source path and offending key.

Every subcommand validates the project/explicit layer before it runs — including
`kill`, `prune`, `crash`, `log` and `wait`, which answer from instance records. Only
`config`, `doctor`, `cache`, `rootfs`, `skill` and `version` are exempt (`config` and
`doctor` report the same fault themselves; the rest never read `qmu.toml`). So a broken
`qmu.toml` blocks VM cleanup too: fix the file, or run the command from a directory
outside the project — the project search walks up from CWD only.

`qmu config init` writes `[machine]` (arch/memory/cpus, with commented `cpu`/`nic_model`/`extra_args`), `[drive]`, `[ssh]`, `[gdb]`, three `[profiles.*]` blocks, and a commented harness-mode block. Notes:

- `[ssh] user` (default `root`) sets the guest login for `exec`/`push`/`pull`/`compile`; it is recorded on the VM at launch, so set it **before** `qmu launch`.
- SSH and GDB ports start at `10021` / `1234` (uncomment `port_start` to override).
- `arch` drives which `qemu-system-*` binary runs and whether KVM is enabled (only when guest arch == host). Use `extra_args` for arch-specific machine flags (e.g. aarch64 `-M virt -cpu cortex-a57`).
- Path values (`rootfs`, `ssh.key`, `--kernel`, `--initrd`) accept `~` expansion.
- Boot flags: `--append` ADDs parameters on top of the `[boot]` profile cmdline, `--cmdline` REPLACES it — details in Launching → `--append` vs `--cmdline`.

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage       # Boot a VM (defaults: 4G RAM, 2 CPUs, exploit-dev profile)
qmu exec "uname -a"                        # Run a command in the guest
qmu compile exploit.c --run                 # Push, compile, and run C in the guest
qmu crash                                   # Extract crash report (works even when SSH is dead)
qmu kill                                    # Stop the VM
```

One-shot, for a disposable VM — boot, run, reap in a single command:

```bash
qmu run --kernel /path/to/bzImage -- './exploit'
```

## One-shot runs (`qmu run`)

`qmu run` collapses `launch` → `exec` → `kill` into one call. **The exit code is
the guest command's**, mapped onto the same contract every other command uses:

| Exit | Meaning |
|------|---------|
| `0`  | guest command exited 0 |
| `1`  | guest command exited non-zero, or the VM died before SSH came up |
| `3`  | kernel crash / SSH transport loss (same discrimination as `exec`) |
| `124`| the guest never became reachable within `--ssh-timeout` |

```bash
qmu run --kernel ./bzImage -- './exploit'
qmu run --kernel ./bzImage --timeout 120 -- './exploit --spray'
qmu run --kernel ./bzImage --keep -- 'id'          # leave the VM up for follow-up
qmu run --kernel ./bzImage --profile exploit-test -- './exploit'
```

It takes every boot flag `launch` does, with three differences:

- **QEMU passthrough is `--qemu-arg`**, repeatable — the positional is spent on
  the guest command. Use the `=` form for values starting with a dash:
  `--qemu-arg=-M --qemu-arg=virt`. Cross-arch guests need this.
- **No `--harness` / `--no-wait-ssh`.** `run` executes a guest command over SSH,
  so a mode that guarantees no SSH cannot run one (argparse rejects both,
  exit 2). For boot-and-die kernels use `launch --harness` + `wait` + `crash`.
  (`--no-net` *is* accepted: it suppresses qmu's own NIC so a manual one can
  take over — see the arm32/MMIO recipe — so pair it with `--qemu-arg` and a
  matching `--ssh-port`.)
- **Reaping is conditional.** On a clean run the VM is fully removed and stdout
  is byte-identical to what `qmu exec` would have printed (so `qmu run ... | grep`
  works). The VM is stopped but the instance metadata and `.serial.log` are
  **preserved** whenever anything is left to inspect — a crash, a *survived*
  kernel report (a KASAN splat that let the command still exit 0), a guest that
  never answered, or a VM that died on boot — and the output names the follow-up:
  `qmu crash --vm ID`, `qmu prune --vm ID`.

Exit `3` requires a **terminal panic** (`Kernel panic - not syncing`). A boot
that only logged a WARNING or KASAN splat and then failed to start sshd is still
`124`, with the report shown under `kernel_warning` — a survived splat is not
evidence the kernel died, and reporting it as one would send you chasing a panic
that never happened.

```bash
$ qmu run --kernel ./bzImage -- 'echo c > /proc/sysrq-trigger'
SSH connection lost while running: echo c > /proc/sysrq-trigger

Crash from serial log:
[    5.952246] Kernel panic - not syncing: sysrq triggered crash
...
VM 'vm-10022' stopped (state preserved). Serial log: ~/.cache/qmu/instances/vm-10022.serial.log
Inspect: qmu log --vm vm-10022 --tail 200 | qmu crash --vm vm-10022
Clean up:  qmu prune --vm vm-10022
$ echo $?
3
```

## VM Lifecycle

### Launching

```bash
qmu launch                                                     # with [boot] kernel set in qmu.toml
qmu launch --kernel /path/to/bzImage
qmu launch --kernel /path/to/bzImage --profile trigger-test    # panic_on_warn=1
qmu launch --kernel /path/to/bzImage --gdb                     # enable GDB stub
qmu launch --kernel /path/to/bzImage --name myvm --memory 8G --cpus 4 --cpu host
qmu launch --append "slub_debug=- nokaslr"                     # ADD params to the profile
qmu launch --cmdline "console=ttyS0 root=/dev/sda custom=1"    # REPLACE the profile cmdline
```

**`--append` vs `--cmdline`.** `--cmdline` replaces the profile's command line
entirely, and every profile carries `root=/dev/sda`; a hand-written replacement
that omits it boots into an emergency shell with no obvious cause. Use
`--append` to add boot parameters on top of the profile. qmu warns on stderr
when a `--cmdline` without `root=` is paired with an attached rootfs.

**Profile vs `[boot] cmdline`.** A `[boot] cmdline` in `qmu.toml` is a full
override and normally beats the default profile. But an explicit CLI
`--profile` beats that config cmdline, and says so on stderr — otherwise
`--profile exploit-test` would be a silent no-op against any project whose
config sets a cmdline. CLI `--cmdline` still wins over both. When a full
override does apply, `qmu status` marks the profile `(NOT applied — cmdline was
overridden)` rather than printing a profile name whose parameters never
reached the kernel.

**`--profile` discards the whole config cmdline, and qmu names the casualties.**
The profile replaces that command line rather than merging with it, so anything
the config supplied and the profile does not is gone. qmu lists the dropped
params on stderr and calls out the ones that silently invalidate work:

```
[qmu] --profile exploit-test overrides the [boot] cmdline in qmu.toml for this launch.
[qmu]   dropped: nokaslr rw slub_debug=- init=/init.sh
[qmu]   note: 'nokaslr' is gone — every kernel address changes; hardcoded offsets will be wrong
[qmu]   note: 'init=/init.sh' is gone — the guest runs its default init, not your harness script
[qmu]   re-add any you still need with --append.
```

Re-add them with `--append` in the same launch. `nokaslr` is the one to watch:
a final-validation run under `--profile exploit-test` is exactly when you least
want KASLR quietly back on.

Advanced boot flags (initrd kernels, custom block/NIC topologies):

```bash
# kernel + initramfs + explicit read-only rootfs drive, no implicit rootfs:
qmu launch --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu launch --kernel ./bzImage --no-net            # -nic none; SSH commands won't work
qmu launch --kernel ./bzImage --nic-model e1000   # NIC model (default virtio-net-pci)
```

- `--initrd PATH` — attach an initramfs/initrd (`~` expansion works).
- `--drive SPEC` — raw QEMU `-drive` spec, repeatable. **Any `--drive` suppresses the implicit rootfs drive** — include the rootfs explicitly if you still need it.
- `--no-net` / `--nic-model MODEL` / `--cpu MODEL` — networking and CPU overrides.
- `--no-kvm` — force TCG emulation (sets `[machine] accel=tcg`; the config key
  also takes `auto`/`kvm`). KVM is otherwise auto-enabled when the guest arch
  matches the host and `/dev/kvm` exists. A useful lever when a **hardware
  watchpoint** doesn't fire on a write you expected: TCG isolates a possible KVM
  guest-debug limitation (but check the VA-alias cause first — see GDB
  Integration → coherence).

Profiles (LSMs disabled + KASAN in all three):
- `exploit-dev` (default) — no panic_on_warn
- `trigger-test` — adds `panic_on_warn=1` (validate bug triggers)
- `exploit-test` — adds `oops=panic` (final exploit validation). Note this is
  the boot-parameter spelling; `panic_on_oops=1` is sysctl-only and is silently
  ignored by the kernel.

Rootfs/SSH-key/other settings come from config; override with CLI flags. The drive uses `snapshot=on`, so the base image is never modified.

**Auto-replace.** Launching with a `--name` (or the default) that matches a running VM **replaces** it (kills the old one first) so a stale VM never blocks a fresh boot and QEMU processes don't leak. `--no-replace` makes that case a hard error (exit 1) naming the running pid — it does NOT launch alongside, because doing so would overwrite the first VM's metadata with the new pid and strand the original QEMU: untracked, still holding the rootfs, and unreachable by `qmu kill`.

### Multiple VMs

Each VM gets its own SSH port (from 10021+), QMP socket, and serial log. With one VM running, commands auto-select it; with several running, pick one with `--vm <id>`.

**Auto-selection, precisely.** Most commands (`status`, `exec`, `kill`, `gdb`, …)
consider only **running** VMs, so stopped remnants never make them ambiguous.
`log` and `crash` also accept a **stopped** VM — that is how a dead VM's serial
log stays readable — so they see more candidates. When they cannot narrow to
one, they pick **the single running VM** and say so:

```
$ qmu log
[qmu] Auto-selected the only running VM 'poc' (8 other VM(s) exist; use --vm <id> to pick one).
```

In JSON the same fact is `"vm": "poc"` plus `"autoselected": "..."`. Both
commands always report which VM they read, auto-selected or not — never assume
it from context. With **no** running VM and several stopped ones, they are
genuinely ambiguous and error, naming the first few candidates and pointing at
`qmu prune --all`.

`--vm`, `--format`, and `--out` are accepted **both before and after** the subcommand — `qmu --vm <id> exec "..."` and `qmu exec --vm <id> "..."` are equivalent. Examples below put them after the subcommand.

```bash
qmu launch --kernel ./bzImage-kasan --name kasan-vm
qmu exec --vm kasan-vm "uname -r"
qmu kill --vm kasan-vm
```

`launch` names the new VM with `--name`; it also accepts `--vm` as an alias so
the selector spelling is the same across every subcommand.

### VM state has two independent axes

`qmu list` reports both, because they vary independently — a VM can be orphaned
AND panicked at once, which is the normal outcome of a successful trigger on a
VM whose metadata was lost.

- **Existence** (`status` in JSON): `running`, `orphaned` (no metadata, process
  alive), `stopped`, `absent`.
- **Guest usability** (`guest` in JSON): `serving`; `paused` (vCPU halted —
  `qmu gdb` leaves every VM here until `qmu cont`); `crashed` (a crash report is
  retrievable **and the guest is still running**); `panicked` (a terminal
  `Kernel panic - not syncing` — the guest is gone); `unknown`.

`crashed` vs `panicked` matters because the label drives a destructive
decision. Under the default `exploit-dev` profile — which deliberately omits
`oops=panic` — an Oops kills only the faulting task and the guest keeps
serving, so a successful trigger usually lands on `crashed`. **Pull the report,
do not reap it.** Only `panicked` means the guest is actually gone. Use
`--profile exploit-test` (`oops=panic`) when you want a trigger to be terminal.

So `[running — GUEST PANICKED]`, `[running — crash report waiting]`, and
`[running — vCPU paused]` are all "running" on the first axis. `qmu status`
reports both axes too, and says which of the two crash states it found.

Every command that answers about a VM agrees with `list` about whether it
exists — `status`, `log`, `crash`, `prune`, `kill`, `wait`, and `exec` all
describe a stopped or orphaned VM rather than reporting it missing.

### Other lifecycle commands

```bash
qmu list                # List VMs with existence AND guest state (see below)
qmu status              # Detailed status (QMP state, SSH, kernel cmdline, ...); `qmu show` is an alias
qmu kill                # Graceful shutdown via QMP, falls back to SIGTERM
qmu kill --force        # SIGKILL
qmu kill --no-clean     # Stop but keep .serial.log + .json for forensics
qmu prune --vm <name>             # Remove a stopped VM's state files
qmu prune --all                   # Remove every stopped VM's state files
qmu prune --vm <name> --keep-logs # Drop .json + .qmp.sock but PRESERVE .serial.log and .qemu.log
qmu prune --orphans               # Kill qmu-launched QEMUs no instance record claims
qmu prune --orphans --dry-run     # ...list what that would kill, and kill nothing
qmu prune --all --dry-run         # preview an instance prune without removing anything
qmu prune --runtime --older-than 86400  # Age-gated prune of qmu-owned runtime artifacts
qmu prune --build-residue --dry-run     # preview reclaiming kernel build residue
qmu cache du                      # size every cache subtree; what is reclaimable
qmu cache ls --top 10             # biggest reclaimable source trees
```

`--keep-logs` preserves both `.serial.log` and `.qemu.log` (metadata and QMP sockets are still removed).

`qmu prune --runtime` removes only aged **marked** automatic output spills and aged definitely stale direct `cm-*` Unix sockets under the runtime root. It skips live/uncertain SSH controls, explicit `--out` files, unmarked lookalikes, symlinks, and unrelated temp names (including arbitrary `/tmp/qmu-*`). Default age is 86400 seconds; use `--older-than SECONDS` (non-negative). The command is idempotent and never recursively deletes the runtime root.

**`--dry-run` previews; it never acts.** Supported with `--vm`, `--all`,
`--orphans`, and `--build-residue`. It prints what would be removed or killed, leaves everything in
place, and reports `dry_run: true` with `pruned: []` plus a `would_prune` /
`would_kill` list in JSON — so a script can always tell a preview from a real
run. `--runtime` has no preview pass and rejects the flag rather than acting
under it. A real prune reports `dry_run: false`.

**Log-only remnants and the age gate.** If a VM's `.json` is gone but its logs
remain, `qmu list` still synthesizes an entry for it. Those remnants are
age-gated: `qmu prune --vm <id>` leaves one younger than `--older-than`
(default 24h) alone and tells you so — re-run with `--older-than 0` to clear it
now. `qmu list` also distinguishes a remnant whose QEMU is still alive
(`[ORPHANED — process alive]`, `status: "orphaned"` in JSON) from a genuinely
stopped one, so a live orphan holding your rootfs can never present as
"nothing running". Reap it with `qmu prune --orphans` (use `--dry-run` first on
a shared machine), or with `qmu kill --vm <id>` — kill handles an orphaned
remnant by signalling its process and preserving the serial log.

`qmu prune --all` names any remnant the age gate held back rather than
reporting "No stopped VMs to prune" while `qmu list` still shows one.

State files are **never silently removed** except by `qmu wait`'s harness auto-clean (below). After `kill --no-clean`, or a harness VM that powered off without `wait`, the `.serial.log` survives — read it with `qmu log`/`qmu crash`, then `qmu prune` when done. See [Files on disk](#files-on-disk).

## Cache on disk

`qmu prune` reaches `~/.cache/qmu/instances/` and the runtime root — **not** the
rest of the cache. `tools/kbuild.sh`, `tools/mkrootfs.sh` and `tools/mktarget.sh`
write `kernels/`, `rootfs/` and `targets/` into the same directory, and on a
working research box those are ~99.99% of the bytes. `qmu prune --all` can
report success while 30 GB sits untouched, so every `prune` result carries an
`unmanaged_cache` key naming what it did not cover.

```bash
qmu cache du                  # per-subtree sizes + what is reclaimable
qmu cache ls --top 10         # biggest reclaimable source trees
qmu cache ls --bucket all     # including held-back and refused entries
```

Sizes are **allocated** blocks, not apparent size. `targets/` and `rootfs/` hold
sparse ext4 images, so `st_size` overstates a real cache by ~70%; `apparent_bytes`
is reported alongside for reference.

**Reclaiming kernel build residue.** `kbuild.sh` builds in-tree, so
`kernels/src/linux-*/` accumulates `*.o`, `*.a`, `.*.cmd` and friends — commonly
more than half the cache. They carry no value to kbuild, which runs `make
mrproper` at the start of every containerised build:

```bash
qmu prune --build-residue --dry-run   # always preview first
qmu prune --build-residue
```

It **never** removes `vmlinux`, `vmlinux.unstripped`, `System.map`, `Makefile`,
`.config`, anything under `arch/*/boot/`, or any symlink. That is not caution for
its own sake: when kbuild's `make scripts_gdb` step fails (it does on 4.x, under
`pipefail`, before the artifact copy), the source tree holds the *only* copy of
that build's kernel. Reclaiming residue leaves the build a cache hit.

Results are bucketed, and the buckets partition the total:

| Bucket | Meaning |
|---|---|
| `eligible` | will be removed |
| `held_back` | tree modified inside `--older-than`; may be mid-build |
| `refused` | parent dir not writable, or referenced by an instance record |

`--older-than` defaults to 86400 and is **floored at 600s** for this mode:
kbuild bind-mounts the source tree read-write for the whole build, so a lower
value is refused rather than clamped. `qmu cache du`/`ls` accept any value (they
never delete) and annotate when you ask for one prune would refuse.

Prevent residue at the source with `tools/kbuild.sh --keep-residue` (default is
to clean after a successful build).

## Harness mode (boot-and-die kernels)

For kernels that boot, run a one-shot init, and halt (kernelCTF judge envs, syzkaller reproducers) — no SSH, no interactive guest. Launch with `--harness`, then block on `qmu wait`:

```bash
qmu launch --harness --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu wait                  # block until the recorded QEMU process exits (no timeout by default)
qmu wait --timeout 120    # give up after 120s
qmu wait --no-clean       # keep .serial.log after confirmed process exit

# Or block on serial output instead of exit — for a VM that keeps running:
qmu wait --pattern "=== results ===" --timeout 120
```

`--harness` implies `--no-wait-ssh` and `--no-net` and skips the rootfs/SSH-key requirement.

`qmu wait` without `--pattern` is the harness/judge primitive (with
`--pattern` it waits on serial output instead — see [the iterate
loop](#the-boot-and-check-iterate-loop)):
- **Exit 0** — the recorded QEMU process identity exited; the result carries the
  terminal crash (JSON `crash` field, null if none; text prints
  `Crash from serial log:`).
- **Exit 124** — `--timeout` elapsed while the QEMU process remained alive.
  Structured output has `ok:false`, `stopped:false`, and retains `qemu_status`,
  `last_event`, and `event_data`.
- QMP `RESET`, `STOP`, `SHUTDOWN`, and `POWERDOWN`, plus non-running states such
  as `paused`, `postmigrate`, and `guest-panicked`, are observations rather than
  proof that QEMU exited.

**`wait` auto-cleans harness VMs by default only after confirming that the
recorded QEMU process identity exited** (removes metadata + `.serial.log`)
unless you pass `--no-clean`. A live-PID timeout never auto-cleans. Read the
terminal crash from `wait`'s own output rather than a later `qmu crash` — after
a confirmed exit, the log may already be gone. Non-harness VMs are never
auto-cleaned by `wait`.

## The boot-and-check iterate loop

This is the loop you will run dozens of times when developing an exploit
against a VM with no working SSH. Use these commands rather than reaching
around qmu into `~/.cache/qmu/instances/`.

```bash
# 1. Build on the host, bake into the rootfs, and boot — one command.
qmu launch --name poc --inject ./exploit:/root/ --append "slub_debug=-"

# 2. Block until the guest prints its marker. Bounded, and it aborts early
#    on a kernel crash instead of hanging.
qmu wait --vm poc --pattern "=== results ===" --timeout 120

# 3. Pull just the interesting lines out of the serial log.
qmu log --vm poc --grep "leaked|OOB|UAF" --context 3
```

**Never poll the serial log by hand.** `until grep -q ... ~/.cache/qmu/
instances/<vm>.serial.log; do sleep 2; done` hangs forever if the guest panics
before printing the marker, and hangs forever if the VM dies. `qmu wait
--pattern` ends in all four cases with a distinct exit code:

- **Exit 0** — the pattern matched. JSON carries `matched_line`.
- **Exit 3** — a **terminal** kernel panic appeared first; the guest is gone
  and the marker can never arrive. The report is in `crash`. A *survived*
  crash (an Oops under the default `exploit-dev` profile, which has no
  `oops=panic`) does NOT abort — the guest is still running, so the wait
  continues. `--ignore-crash` suppresses even the terminal-panic abort; you
  rarely need it now, and pasting it reflexively is how a real panic gets
  missed.
- **Exit 1** — the VM exited without ever printing the pattern.
- **Exit 124** — `--timeout` elapsed with the VM still running.

`--pattern` is a Python regex matched per line, e.g. `--pattern "leaked
0x[0-9a-f]{16}"`. After a QMP `RESET` **that qmu observed** the scan starts at
the new guest epoch. Note the limit: epoch advancement needs qmu connected when
the reset fires, so a *guest-initiated* reboot between two commands (`panic=1`,
kexec, a harness calling `reboot`) is invisible and a pre-reboot marker can
still satisfy a wait. The guest-state axis does not share this limit — it
re-scopes on the kernel's own boot banner.

`qmu log` reads the same log after the fact:

```bash
qmu log --grep "BUG:|WARNING:" --context 5   # searches the WHOLE log
qmu log --grep "BUG:" --tail 200             # ...unless you narrow it on purpose
qmu log --full --out ./evidence.log          # whole log to a file for the record
```

**Scan scope.** A bare `qmu log` shows the last 50 lines. `--grep` searches the
**whole** log instead, because a filtered read scoped to the tail returns
confident false negatives — the crash you are looking for is usually not in the
last 50 lines. An explicit `--tail` still narrows it, and the result reports
which scope was searched (`scope` in JSON; named in the no-match message), so a
zero-match answer is never ambiguous.

`--full` ignores `--tail`; combined with `--out` it replaces `cp
~/.cache/qmu/instances/<vm>.serial.log ./evidence.log`.

**Do not pipe `--full` into `grep -c` under a JSON format.** The envelope wraps
the log in one JSON string, so a line count counts the envelope, not the log.
Use `--grep` (which counts for you, in `matches`), or `--format text`, or write
it with `--out` and grep the file.

**Unknown boot parameters.** `launch` (once SSH is up), `wait`, and `status`
report any boot parameter the kernel did not claim
(`unknown_kernel_params` in JSON, a stderr warning in text). This catches the
silent class of bug where a cmdline parameter looks right and does nothing —
`panic_on_oops=1` is a sysctl, not a boot parameter, so a profile built on it
never panics and a kernel-corrupting exploit reads as a clean run. The boot
form is `oops=panic`.

Three deliberate exclusions keep the warning worth reading:

- **Init-consumed** params (`root=`, `init=`, `console=`) always appear in the
  kernel's list and are never actionable.
- **Pre-parse** params are honored *before* the kernel's parameter table
  exists, so the kernel reports them as unknown while acting on them. **This is
  arch-specific and qmu gates it on the VM's arch.** On x86, `nokaslr` is read
  by the decompressor with no `__setup` entry to claim it — there it works, and
  you should not remove it on the strength of that kernel line; the same goes
  for `no5lvl`, `acpi*`, `earlyprintk`, `forcepae`, `edd`, and `mem_encrypt`.
  On **arm32 the opposite is true**: `arch/arm/` has no KASLR at all, so
  `nokaslr` there really does nothing and qmu reports it. arm64 never lists it
  (a do-nothing `early_param` claims it). An instance with no recorded arch
  suppresses only `quiet`/`debug`, so an unknown arch never hides a real dud.
- **Profile-supplied** params are reported on a separate, quieter `[qmu] Note:`
  line. They come from qmu's own profile rather than from anything you typed,
  and are usually unfixable by design (`apparmor=0` is unclaimed precisely
  because AppArmor is not compiled in). Only params *you* supplied get the loud
  warning.

JSON keeps the same split: `unknown_kernel_params_by_source.operator` is the
key to gate a script on — `unknown_kernel_params` stays as the flat list for
back-compat, but it includes the perpetual profile noise.

**Dotted params are a blind spot.** The kernel routes `foo.bar=x` to the
module-param path, so a dotted param never appears in that unknown-parameter
line at all — `kasan.faul=panic` is silently ignored at boot and invisible
afterwards. `launch` spell-checks dotted params against the names qmu knows and
warns on a near-miss; unrelated dotted params are left alone.

## File Transfer

```bash
qmu push exploit.c                  # → /root/ in guest
qmu push exploit.c /tmp/exploit.c   # → specific path
qmu pull /root/output.txt           # → CWD
qmu pull /root/output.txt ./results/
```

### Offline rootfs editing (no running VM, via libguestfs)

**When SSH is not up, this — not `sudo mount`/`cp`/`umount` — is how files get
into the guest.** To bake files into a rootfs **before** boot (e.g. a harness
rootfs with no SSH), or inspect one, use `qmu rootfs`, which operates on the
image file directly. Needs libguestfs (`guestfish`):

```bash
qmu rootfs inject ./rootfs.img ./exploit:/root ./run.sh:/   # each pair is LOCAL:GUEST, GUEST is a dir
qmu rootfs inject ./rootfs.img ./exploit:/root --partition 0   # whole-disk/partitionless image
qmu rootfs inject ./rootfs.img ./exploit:/new/dir --mkdir      # create GUEST if absent
qmu rootfs ls   ./rootfs.img /root                          # verify what actually landed
qmu rootfs cat  ./rootfs.img /root/run.sh                   # read a file back
qmu rootfs rm   ./rootfs.img /root/marker                   # delete (inject only adds)
qmu rootfs rm   ./rootfs.img /tmp/workdir --recursive        # directories
qmu rootfs shell ./rootfs.img                               # interactive guestfish
```

**GUEST must already exist.** `inject` errors if the destination directory is
missing, rather than creating it — a silent `mkdir` turns `./exploit:/rooot`
into a reported success while `/root/exploit` still holds the previous build,
which is precisely the stale-code failure injection is meant to rule out. Pass
`--mkdir` when you mean to create it. For the same reason `rm` errors on a path
that does not exist instead of `rm -f`'s silent success; `--force` opts back
into tolerating a missing path, and `--recursive` handles directories.

`qmu rootfs ls` and `cat` are read-only: they open the image `--ro` and work
while a VM is running, which is when you actually want to ask "did my inject
land?". `inject`, `rm`, and `shell` write, so they refuse an image a running VM
holds and name the VM to kill. If qmu reports no such VM but libguestfs still
cannot open the image, an **untracked** QEMU is holding it — `qmu prune
--orphans` finds and reaps those (it matches only QEMUs launched by qmu, via
the QMP socket path in their argv, so it can never touch an unrelated QEMU).

`--partition N` selects the partition (default `1`; `0` for whole-disk). Images
built by `qmu-linux-rootfs`, and Debian cloud images like `trixie.img`, are
whole-disk ext4 — they need `--partition 0`. If you get it wrong, the error
names the partitions guestfish actually found.

**Verify after injecting.** A failed inject leaves the previous iteration's
binary in place, so the next boot re-runs stale code while looking like a fresh
result. `qmu rootfs ls`/`cat` is how you rule that out.

`qmu launch --inject LOCAL:/guest/dir` runs the same injection against the
configured rootfs immediately before boot (after any existing VM of the same
name is killed, so it is safe to repeat), making the rebuild-and-reboot cycle a
single command. Repeat the flag for several files; `--partition` applies here too:

```bash
qmu launch --name poc --inject ./exploit:/root/ --inject ./init.sh:/ --partition 0
```

### libguestfs prerequisite

Everything in this section needs libguestfs, and it is frequently broken out of
the box: Debian/Ubuntu ship `/boot/vmlinuz-*` as mode `0600`, the supermin
appliance builds unprivileged, and the resulting failure is reported as an
opaque "appliance closed the connection unexpectedly". **Run `qmu doctor`
first** — it checks both `guestfish` and whether an appliance kernel is
readable, and prints the fix:

```bash
sudo chmod 0644 /boot/vmlinuz-*
# or, leaving system permissions alone:
sudo install -m 0644 /boot/vmlinuz-$(uname -r) /var/tmp/vmlinuz
export SUPERMIN_KERNEL=/var/tmp/vmlinuz \
       SUPERMIN_KERNEL_VERSION=$(uname -r) \
       SUPERMIN_MODULES=/lib/modules/$(uname -r)
```

## Guest Execution

```bash
qmu exec "uname -a"
qmu exec "cat /proc/slabinfo | grep kmalloc-192"
qmu exec "./exploit" --timeout 120
```

## Compile and Run

The primary exploit-dev workflow — push a C file, compile it in the guest, optionally run it:

```bash
qmu compile exploit.c                       # push + compile
qmu compile exploit.c --run                 # push + compile + run
qmu compile exploit.c --run --timeout 120
qmu compile exploit.c --cflags "-static -lpthread -DDEBUG"
```

Default CFLAGS: `-static -lpthread`.

### Building on the host (`--host`)

`--host` compiles on the **host** with a toolchain for the guest arch, then
pushes the binary. Reach for it when either of these is true:

- **The guest has no gcc.** kernelCTF images, most vendor firmware rootfs, and
  minimal Debian images ship no toolchain, so the default path cannot work at all.
- **The guest is emulated.** Compiling inside a TCG aarch64/arm guest is far
  slower than the host cross-compiler — measured on the bundled sample against an
  emulated aarch64 bookworm guest: **1.2s host vs 6.3s in-guest**, and the gap
  grows with the size of the source.

```bash
qmu compile exploit.c --host --run
qmu compile exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

The compiler is chosen from the **guest** arch recorded on the instance, not the
host's — an aarch64 VM gets `aarch64-linux-gnu-gcc` even though `gcc` is right
there. (A host-arch binary would fail in the guest as a bare "cannot execute
binary file", which reads like a guest problem rather than a missing toolchain.)
Selection order per arch:

| Guest arch | Tried, in order |
|------------|-----------------|
| host arch  | `cc`, `gcc` |
| `aarch64`  | `aarch64-linux-gnu-gcc` |
| `arm`      | `arm-linux-gnueabihf-gcc`, `arm-linux-gnueabi-gcc` |
| `i386`     | `i686-linux-gnu-gcc`, `i586-linux-gnu-gcc`, then `gcc -m32` |
| `x86_64`   | `x86_64-linux-gnu-gcc` |

If nothing is found, the error names what was tried, the package to install, and
`--cc`. `--cc` is honored verbatim and is deliberately **not** checked against the
guest arch, so an unmodelled toolchain (musl cross, clang, a wrapper script) works.

A VM whose instance record has **no** recorded arch (written before qmu recorded
it) is refused rather than guessed — relaunch it, or pass `--cc`. Falling back to
the host compiler there would hand a cross-arch guest a host-arch binary that
fails to exec, reported as a success.

`--cflags` is parsed with `shlex`, exactly like the guest shell would, so a
quoted flag survives: `--cflags '-static -DMSG="hello world"'`.

Keep `-static` in `--cflags` (it is the default): a host-built dynamic binary
must match the guest's libc, and a static one sidesteps that entirely. The pushed
binary is `chmod +x`'d — `scp` does not preserve the mode.

JSON results use the **same keys** on both paths, with `compiled_on`
(`"host"`/`"guest"`) recording which ran, so a consumer never has to branch.

> **Crash detection is best-effort.** When a guest command crashes the kernel, qmu attempts to pull the crash report from the serial log — both when the command exceeds `--timeout` and when SSH is torn down (rc=255) by a panic. This is best-effort: after **any** suspected panic, including a bare `[exit code: 255]`, always confirm with `qmu crash` (and `qmu log --tail 200`). Never rely on the exit code alone to detect a crash.
>
> A `--timeout` expiry is only treated as a possible crash when the guest has
> also stopped answering SSH. A command that simply ran long on a healthy guest
> exits **124** with `timed_out: true` — it is not reported as a kernel crash.

## Crash Extraction

The headline feature — works even when SSH is dead, and **after** a VM exits (state files survive until prune):

```bash
qmu crash                   # last crash in the current restored guest epoch
qmu crash --vm run-3        # current epoch; works on a stopped VM too
qmu crash --full-history    # retained-log forensics across snapshot/reset epochs
qmu log --tail 100          # raw serial tail, without provenance filtering
```

Command-attributed crashes from `exec` and `compile --run` are extracted only
from serial bytes appended after that command began. A stale panic already in
the log never sets `crash_detected` for the new command. Standalone `qmu crash`
defaults to the persisted current guest epoch; use `--full-history` explicitly
when older retained crashes are desired. In structured output, inspect
`crash_detected` and `scope`; `ok: true`/exit 0 means the selected crash query
found a report, not that the VM is healthy.

Detects KASAN, BUG/Oops, kernel panic, general protection fault, UBSAN, slab-use-after-free, and more. If `qmu crash` reports nothing but you suspect a panic, fall back to `qmu log --tail 200`.

## Snapshots

```bash
qmu snapshot save clean
qmu snapshot list
qmu snapshot load clean
qmu snapshot delete clean
```

**Ephemeral in-session rewind.** By default qmu attaches the configured rootfs through a temporary `snapshot=on` COW overlay. HMP `savevm`/`loadvm` checkpoints can therefore provide in-session rewind with a raw or qcow2 base. The base stays unchanged, and the checkpoints disappear when the QEMU process exits.

**Durable internal snapshots.** Attach a writable qcow2 drive without `snapshot=on`, for example:

```bash
qemu-img convert -O qcow2 rootfs.img rootfs.qcow2
qmu launch --kernel ./bzImage \
  --drive 'file=./rootfs.qcow2,format=qcow2'
```

Changing `[drive] format` alone is not durable because qmu still places the configured rootfs behind its temporary overlay.

**Migration/loadvm networking compatibility.** The default user/slirp backend often restores in-session checkpoints successfully. If `loadvm` reports slirp section/footer errors for a particular QEMU/build/device combination, use native passt only when the selected QEMU advertises it, or manually manage an external passt process with QEMU's `stream` backend. Native passt is documented since QEMU 10.1 but may be build-optional; qmu probes the capability instead of using the version as the decision. qmu does not manage an external passt process.

**Snapshot-rewind loop — fast in-session iteration:**
```bash
qmu launch --kernel ./bzImage --name dev
qmu push exploit /tmp/x
qmu snapshot save clean              # clean pre-PoC state
for i in 1 2 3 4 5; do
  qmu exec /tmp/x                    # run the PoC (may crash/corrupt the kernel)
  qmu log --tail 200 > runs/run-$i.log
  qmu snapshot load clean            # rewind to clean — far faster than a full reboot
done
```
After `snapshot load`, the first SSH command may print a one-off `Broken pipe` on stderr (the pre-snapshot SSH control connection was rewound); the command itself still succeeds. `savevm` needs an attached snapshot-capable writable layer; harness configurations with only readonly drives may not provide one.

## Kernel Logs

```bash
qmu dmesg              # full dmesg from guest (via SSH)
qmu dmesg --tail 50
```

For a VM with no SSH, read the serial console instead — `qmu log` takes the
same `--tail`, plus `--grep`/`--context`/`--full` (see [the iterate
loop](#the-boot-and-check-iterate-loop)).

## GDB Integration (with pry)

Explicit attach → continue → discover base → manual rebase workflow (no
implicit resume/re-halt, no automatic pry rebasing):

```bash
eval "$(tools/kbuild.sh --version 7.0 --arch x86_64)"
qmu launch --kernel "$KERNEL" --gdb --name debug-vm
qmu gdb --vm debug-vm --symbols "$VMLINUX"
# Attaching halted the guest; kbase will refuse to resume it implicitly.
qmu cont --vm debug-vm
eval "$(qmu kbase --vm debug-vm --symbols "$VMLINUX")"
pry load "$VMLINUX" --base "$KBASE"
```

**`qmu gdb --symbols`** launches pry connected to the GDB stub and loads the
ELF at its **link-time** addresses. Success reports `symbols_rebased:false`
and `symbol_base:"elf-link-time"`; the link-time warning is valid whether the
eventual KASLR slide is zero or nonzero. `kaslr_status` stays `"unknown"` —
the warning describes loading behavior, not guest KASLR configuration. qmu
never discovers a runtime base during `gdb` and never passes `--base` to pry.

**`qmu kbase --vm NAME --symbols VMLINUX`** reads local ELF `_text` (via
`nm`/`llvm-nm`) and runtime `_text` (via guest `/proc/kallsyms`), then prints
eval-able `KBASE`, `LINK_BASE`, and `SLIDE` (JSON/NDJSON use the same values as
hex-string fields). It requires normal guest SSH. It **does not** issue QMP
`cont`, resume/re-halt the guest, invoke pry, or apply a symbol base.

**Gotcha — `qmu gdb` halts the vCPU.** Attaching to the QEMU GDB stub halts
the guest CPU. Before `qmu exec`/`push`/`pull`/`compile`/`dmesg`/`kbase`
constructs an SSH client, qmu best-effort queries QMP; a positively observed
`paused` or `debug` state fails immediately with operational exit `1`, not an
SSH timeout or crash classification (`ssh_error:false`,
`crash_detected:false`). **Resume before SSH / kbase** with
`qmu cont --vm <id>` (or `pry continue`, or `qmu monitor cont`). If QMP
introspection is unavailable, qmu preserves the existing SSH path.

**kbase operational errors** (exit 1) include: harness/no-SSH instances,
unsupported or legacy (`arch=None`) architecture metadata, restricted
kallsyms (`kptr_restrict`), missing symbols/tools, and missing `_text`. A
paused/debugger-stopped guest returns exit 1 immediately with
`qmu cont`/`pry continue` guidance; kbase neither resumes nor re-halts it.

**Non-goals:** qmu never invokes `pry load --base` automatically — the
operator applies the reported base. Neither `gdb` nor `kbase` silently
resumes or re-halts the guest.

```bash
pry break set commit_creds
pry continue                # REQUIRED to resume before the parallel exec
# in parallel: qmu exec "./exploit"
pry backtrace
```

### Debugger↔VM coherence (which operations invalidate debug state)

The QEMU gdbstub protocol does **not** tell an attached client when the machine
changes underneath it, so several everyday qmu operations make the debugger's
view silently diverge from the guest — no error, wrong answer. qmu knows a VM
has a GDB stub (it was launched with `--gdb`) and warns on stderr at each such
event. Treat every warning below as: **the debug state you can see is now
suspect; re-establish it before trusting a register/memory read or a
breakpoint.**

| You run | What silently breaks | Recover |
|---|---|---|
| `qmu snapshot load` | Debugger keeps **pre-load** `$rip`/stop-reason and stale breakpoint/memory bookkeeping — it never re-syncs to the restored vCPU. | **Tear down the stale pry bridge first** (it survived the rewind, so a fresh `qmu gdb` would spawn a second — see #40), then reconnect and re-arm breakpoints before inspecting. |
| `qmu snapshot save` (breakpoints armed) | Software breakpoints are `int3` (`0xCC`) bytes; the save **bakes them into the image**. A later `load` + run traps at that address with no live breakpoint → guest Oops/panic that mimics your PoC crashing the kernel. | Clear breakpoints before saving a clean image; treat a post-load `int3` crash at a breakpointed function as a debugger artifact, not an exploit result. |
| `qmu qmp system_reset` / `qmu monitor system_reset` (or a guest reboot) | The gdbstub's breakpoint/watchpoint set is **dropped**; the client still lists them `[enabled]` but they never fire again (`hits=0`). | Re-set (re-arm) all breakpoints after the guest is back; confirm with a canary breakpoint you can prove is hit. |
| A **hardware watchpoint** doesn't fire on a write you can prove happened | A watchpoint triggers only on writes through the **watched virtual address**. A kernel write to the same bytes via a *different* mapping (heap/physmap alias — common in LPEs corrupting e.g. `modprobe_path`) won't trip a watchpoint set on the symbol's VA. This reads as a "silent miss" but is not KVM's fault. (Separately, some QEMU/KVM builds can drop gdbstub watchpoints.) | Suspect the alias first — watch the VA the write actually goes through. To rule out a KVM guest-debug limitation, retest with `qmu launch --no-kvm ...` (TCG). *Tested: on qemu 8.2.2 + KVM a `jiffies` watchpoint fired fine, so KVM alone does not disable watchpoints.* |

A **guest-initiated reboot** hits the same reset failure as the last row but is
not observable to qmu synchronously, so no warning fires: after any reboot,
assume breakpoints are gone until a canary confirms otherwise.

These warnings are keyed on the VM having a GDB stub; qmu additionally
suppresses them when it can positively confirm no client is connected, and errs
toward warning when it cannot tell. Auto re-sync / auto re-arm is a pry-side
capability qmu does not drive — the contract qmu enforces is "invalidate
loudly," not "fix it for you."

## Cross-arch quickstarts (aarch64 / arm32)

Booting a non-x86 guest needs three things the x86 defaults don't provide: the right
`qemu-system-*` binary (`--arch`), a `virt` machine + CPU model (`-- -M virt -cpu …`),
and an ARM console/root cmdline (`console=ttyAMA0 root=/dev/vda`). The built-in profiles
hard-code `console=ttyS0 root=/dev/sda` for x86, so cross-arch launches **must** either
override `--cmdline` or use an arch-aware `qmu.toml` (see below). Build the kernel and
rootfs with the `qmu-linux-kbuild` and `qmu-linux-rootfs` skills (`--arch arm64` / `--arch arm32`).

**Multiarch GDB (required on x86 hosts).** Ubuntu's stock `gdb` is x86-only and pry always
invokes `gdb`; an ARM target makes it fail with a truncated `g` packet. Put `gdb-multiarch`
on `PATH` as `gdb` before any pry command:

```bash
mkdir -p /tmp/gdb-multiarch-bin
ln -sfn /usr/bin/gdb-multiarch /tmp/gdb-multiarch-bin/gdb
export PATH=/tmp/gdb-multiarch-bin:$PATH
```

### aarch64 (arm64)

```bash
eval "$(tools/kbuild.sh --version 7.0 --arch arm64)"     # KERNEL=Image, VMLINUX, KERNEL_SRC
eval "$(tools/mkrootfs.sh --arch arm64)"                 # ROOTFS, SSH_KEY

qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch aarch64 --gdb --name arm70 \
  --cmdline "console=ttyAMA0 root=/dev/vda rw earlyprintk=serial net.ifnames=0" \
  -- -M virt -cpu cortex-a57

qmu exec --vm arm70 "uname -a"          # … 7.0.0 … aarch64
qmu compile hello.c --run --vm arm70    # machine=aarch64, sizeof(void*)=8
```

The arm64 `virt` machine exposes virtio over PCI, so the rootfs reaches `/dev/vda` through
a plain virtio drive. The implicit rootfs drive is made arch-aware by the arch-aware-drive
fix in PR #31 (issues #26/#28) — with that fix a default launch already lands on `/dev/vda`.
**Fallback if your qmu predates the fix** (implicit drive has no `if=virtio` and fails VFS
mount): pass the drive explicitly.

```bash
qmu launch --kernel "$KERNEL" --arch aarch64 --gdb --name arm70 \
  --drive "file=${ROOTFS},if=virtio,format=raw,snapshot=on" \
  --cmdline "console=ttyAMA0 root=/dev/vda rw earlyprintk=serial net.ifnames=0" \
  -- -M virt -cpu cortex-a57
```

**KASLR rebase — use `_stext`, not `_text`, on arm64.** `qmu kbase` and `/proc/kallsyms`
report `_text`, but `pry load --base` slides from the ELF executable-section base, which on
arm64 is `_stext` — `0x10000` above `_text` (the `.head.text` gap). Passing `_text` puts every
symbol `0x10000` low and breakpoints miss. Rebase on the runtime `_stext` until pry is fixed:

```bash
eval "$(qmu kbase --vm arm70 --symbols "$VMLINUX")"      # records _text-based KBASE/SLIDE
STEXT=$(qmu exec --vm arm70 \
  'echo 0 >/proc/sys/kernel/kptr_restrict; awk "/T _stext\$/{print \$1}" /proc/kallsyms')
pry launch --connect localhost:1234
pry load "$VMLINUX" --base "0x$STEXT" --src "$KERNEL_SRC"
pry break set __arm64_sys_newuname                        # arm64 syscall wrapper prefix
pry continue --background
qmu exec --vm arm70 "uname -r"                            # hits the breakpoint
```

For `lx-*` scripts and `$lx_current()`, the arm64 kernel must be built with **full**
`DEBUG_INFO` (not `DEBUG_INFO_REDUCED`, the arm64 defconfig default, which makes lx scripts
refuse to load). Current `qmu-linux-kbuild` disables the reduced variant; rebuild if your
kernel predates that. `pry kbase`'s VBAR fallback is unreliable here — prefer `qmu kbase`
or kallsyms.

### arm32 (armv7l)

The arm32 `virt` machine uses virtio over **MMIO**, so the rootfs reaches `/dev/vda` through
an MMIO `virtio-blk-device` rather than a PCI virtio drive. The arch-aware-drive fix in
PR #31 (issues #26/#28) attaches that MMIO block device by default, so a default launch
already lands on `/dev/vda`. Networking still needs manual MMIO flags — PR #31 does not wire
up the NIC — so keep the `-netdev`/`virtio-net-device` pair below:

```bash
eval "$(tools/kbuild.sh --version 7.0 --arch arm32)"     # KERNEL=zImage (multi_v7)
eval "$(tools/mkrootfs.sh --arch arm32)"                 # ROOTFS, SSH_KEY

qmu launch --kernel "$KERNEL" --rootfs "$ROOTFS" --ssh-key "$SSH_KEY" \
  --arch arm --gdb --name arm32-70 --no-net \
  --cmdline "console=ttyAMA0 root=/dev/vda rw net.ifnames=0" \
  -- -M virt -cpu cortex-a15 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10021-:22 \
  -device virtio-net-device,netdev=net0

qmu exec --vm arm32-70 "uname -a"          # … 7.0.0 … armv7l
qmu compile hello.c --run --vm arm32-70    # sizeof(void*)=4
```

`--no-net` disables qmu's own NIC so the MMIO `virtio-net-device` (with the `hostfwd` that
maps guest `:22`) is the only interface. **Match the SSH port:** with `--no-net` qmu still
auto-allocates an SSH port starting at `10021` but emits no forward of its own, so the manual
`hostfwd=…:10021-:22` must match that recorded port. If `10021` is already taken (e.g. a
concurrent VM) qmu records a different port than the `hostfwd`, so `qmu exec`/`qmu kbase`
connect to the wrong port and fail.

**Fallback if your qmu predates the PR #31 fix** (the implicit drive is not MMIO and boots to
`VFS: unable to mount root … unknown-block(0,0)`): attach the rootfs explicitly as an MMIO
device with `if=none` + `-device virtio-blk-device`:

```bash
qmu launch --kernel "$KERNEL" --arch arm --gdb --name arm32-70 --no-net \
  --drive "file=${ROOTFS},if=none,format=raw,id=hd0,snapshot=on" \
  --cmdline "console=ttyAMA0 root=/dev/vda rw net.ifnames=0" \
  -- -M virt -cpu cortex-a15 \
  -device virtio-blk-device,drive=hd0 \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:10021-:22 \
  -device virtio-net-device,netdev=net0
```

**Debug — `--slide 0`, not `--base`.** The `multi_v7` build typically loads with no KASLR
slide (`qmu kbase` shows link == runtime). `pry load --base` fails on this ELF
(`could not read the .text address … pass --slide`); use `--slide 0` instead. The uname
syscall symbol is `sys_newuname` (also `__se_sys_newuname`), **not** the `__arm_sys_*` /
`__arm64_sys_*` wrappers:

```bash
pry launch --connect localhost:1234
pry load "$VMLINUX" --slide 0 --src "$KERNEL_SRC"
pry break set sys_newuname
pry continue --background
qmu exec --vm arm32-70 "uname -r"          # hits the breakpoint
```

KASAN is **unsupported on arm32** upstream (no `HAVE_ARCH_KASAN`); use x86_64 or arm64 if you
need it.

### Arch-aware qmu.toml (skip the per-launch flags)

Baking the machine args, arch, and ARM cmdline into `qmu.toml` lets you launch with just
`qmu launch --kernel "$KERNEL"`. Example for aarch64 (swap `cortex-a15`/`arm` for arm32):

```toml
[machine]
arch = "aarch64"
extra_args = ["-M", "virt", "-cpu", "cortex-a57"]

[drive]
rootfs = "/…/rootfs/bookworm/arm64/rootfs.img"
format = "raw"

[ssh]
key = "/…/rootfs/bookworm/arm64/id_ed25519"

[profiles.exploit-dev]
cmdline = "console=ttyAMA0 root=/dev/vda rw earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"
```

## Raw QEMU Access

```bash
qmu qmp query-status                       # raw QMP command
qmu monitor "info registers"               # HMP command via QMP
qmu monitor "x /16xg 0xffffffff81000000"   # examine memory
qmu monitor "cont"                         # resume a paused/halted guest
```

## Output Formats, Result Contract, Exit Codes

All commands support `--format text|json|ndjson` (accepted before or after the subcommand).

**Universal contract.** Under `--format json`/`ndjson`, **every** command emits an object with an `"ok": <bool>` field on both success and every error path — check `ok` for a single, command-agnostic success predicate. Errors emit `{"ok": false, "error": "...", "error_type": "<ExceptionClassName>"}` to stdout. In text mode, errors print `[qmu] Error: ...` to stderr.

Use the exit code (not log scraping) to branch:

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Operational failure — no running VM, bad `--vm`, kernel not found, guest command non-zero, `doctor` unhealthy, a snapshot op failed, or `wait --pattern` outlived the VM (any `QMUError`) |
| `2`  | Usage / argument-parse error (argparse) |
| `3`  | Guest kernel crash — always corroborated by a fresh serial crash report (a bare dropped connection is `4`) |
| `4`  | QMP or SSH transport-layer failure (`QMPError`/`SSHError`), a dropped SSH/scp connection with NO fresh crash (guest merely unreachable — e.g. no sshd), or an internal/unexpected qmu error (the `main()` catch-all, a hung helper subprocess) |
| `124`| `qmu wait` timed out; `qmu run` gave up waiting for the guest to answer SSH; or an `exec`/`run`/`compile --run` guest command exceeded `--timeout` **while the guest was still reachable** |

Exit `3` is guest-side; an internal qmu/transport fault is `4`, so a tooling bug is never mistaken for a kernel panic. `exec`, `push`, and `pull` apply that rule identically: a lost connection returns `3` only when a fresh serial crash corroborates it, otherwise `4`. Branch on `3` to mean "the guest actually crashed"; check `crash_detected` in JSON for the same answer. (Matches `qmu --help`.)

**Output spilling.** Large outputs (>10k estimated tokens) auto-spill to a file under the centralized spill root, in precedence order: `$QMU_TEMP_DIR/spills`, then `$XDG_RUNTIME_DIR/qmu/spills` when that XDG runtime directory is absolute/existing/writable/searchable, then `<platform temp>/qmu/spills`. Automatic spills are marked with an adjacent ownership sidecar; explicit `--out` paths are never marked as qmu-owned. **Callers must continue consuming `artifact_path`** — never reconstruct spill names or paths. Read the path from the result envelope's `artifact_path` field or the `[qmu] Output spilled to <path>` stderr line. The envelope's `{"token_estimate": <int>, "estimator": "chars/4"}` is a tokenizer-agnostic heuristic for sizing only.

## Health Check

```bash
qmu doctor   # config sources, QEMU binary, rootfs, SSH key + perms, KVM, pry, running VMs, skill
```

Exits non-zero if no config is found (prints a `qmu config init` tip). SSH key existence and permissions are separate checks. `pry` is informational (only required for `qmu gdb`) — a missing `pry` does not fail the check.

## Files on disk

Each VM keeps state under `~/.cache/qmu/instances/` (or `$QMU_CACHE_DIR`). That is
only one of four subtrees in the cache — see [Cache on disk](#cache-on-disk) for the
rest, which `prune --vm/--all` does not touch.

| File                | Purpose                              | Removed by |
|---------------------|--------------------------------------|------------|
| `<name>.json`       | VM metadata (pid, ports, kernel)     | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.serial.log` | Serial console (read via `qmu log`)  | `kill`, `prune`, `wait` harness auto-clean — **kept** by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |
| `<name>.qmp.sock`   | QMP control socket                   | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.qemu.log`   | QEMU stdout/stderr log               | `kill`, `prune`, `wait` harness auto-clean — **kept** by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |

`qmu list` shows running and stopped VMs with a status marker so you can see what's recoverable.
`qmu cache du` does the same for the cache as a whole, including the `kernels/`,
`rootfs/` and `targets/` subtrees no instance command reports on.

## Known Limitations

- **Implicit snapshots are ephemeral** — the configured raw or qcow2 base is behind a temporary `snapshot=on` overlay, and in-session checkpoints disappear with the QEMU process.
- **Durable internal snapshots need a direct writable qcow2 drive** — attach it explicitly without `snapshot=on`; changing `[drive] format` alone remains temporary.
- **Network restore compatibility is QEMU/build/device dependent** — user/slirp often works; if `loadvm` names slirp/footer errors, use capability-advertised native passt or an operator-managed external passt + `stream` setup.
- **`qmu gdb` halts the guest** — resume with `qmu cont` / `pry continue` / `qmu monitor cont` before SSH commands (see GDB Integration).
  Before `exec`, `push`, `pull`, `compile`, `dmesg`, or `kbase` constructs an SSH client,
  qmu best-effort queries QMP. A positively observed debugger/manual stop
  (`paused` or `debug`) fails immediately with operational exit `1`, reports
  `ssh_error:false` and `crash_detected:false`, and gives
  `qmu cont --vm <id>` / `pry continue` recovery guidance. If QMP introspection is
  unavailable, qmu preserves the existing SSH path rather than creating a new
  command outage.
- **`qmu gdb --symbols` is link-time only** — symbols load at ELF link-time addresses
  (`symbols_rebased:false`). Discover the runtime base with `qmu kbase`, then apply
  it manually via `pry load ... --base "$KBASE"`. qmu never auto-rebases pry and
  never resumes/re-halts the guest for you.
- **Debug state does not survive `snapshot load`, `snapshot save`, or a reset** —
  the gdbstub protocol never tells the client the machine changed, so the debugger
  silently keeps a stale view. qmu warns on stderr at each event for a `--gdb` VM
  but only invalidates loudly; it does not auto re-sync or re-arm (that is pry's
  job). See GDB Integration → *Debugger↔VM coherence* for the per-operation table.
- **A hardware watchpoint that "silently misses"** is usually watching the wrong
  virtual address — a watchpoint fires only on writes through the VA it's set on,
  so a kernel write via a heap/physmap alias (common in LPEs hitting e.g.
  `modprobe_path`) won't trip it. Suspect that first. Some QEMU/KVM builds can also
  drop gdbstub watchpoints; `--no-kvm` (TCG) isolates that. (Tested: on qemu 8.2.2
  + KVM a `jiffies` watchpoint fired reliably — KVM alone does not disable them.)
- **Crash auto-extraction is best-effort** — confirm with `qmu crash` / `qmu log --tail 200` after any suspected panic (see Compile and Run).
- **Serial log is write-only** — no interactive console; use SSH for interactive work.
