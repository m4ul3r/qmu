---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

Use this skill when the user wants to boot, manage, or interact with QEMU VMs for kernel security research. qmu emits structured JSON or text output and handles the common pain points of QEMU-based kernel exploit development. Run `qmu --help` for full usage.

This file is the hot path. Longer reference material lives next to it and is
read on demand — `read skill://qmu/reference/<file>.md`:

| File | When to read it |
|---|---|
| `evidence-contract.md` | before promoting a matched marker or a green run into a claim, or handing off to another agent |
| `cross-arch.md` | aarch64/arm32 guests, arch-aware `qmu.toml`, multiarch gdb, `compile --host` toolchains |
| `debugging.md` | anything with pry: attach/halt semantics, rebasing, bridge lifecycle, what invalidates debug state |
| `wait.md` | `qmu wait`: bare-wait exit semantics for harness VMs, auto-clean, `-no-reboot`; `--pattern` line and scope rules |
| `snapshots.md` | durable snapshots, networking compatibility, post-load SSH behavior |
| `boot-params.md` | `--append`/`--cmdline`/profile precedence, the unknown-boot-parameter lint and its exclusions |
| `troubleshooting.md` | libguestfs setup, `rootfs inject` rules, config validation, VM auto-selection, output spilling, `doctor` rows |

## Working with other agents on one host

Several agents routinely share one host; each rule below was proven necessary:

- Launch with a unique `--name` **and `--no-replace`**: the default auto-replace
  kills whatever running VM has that name, including someone else's.
- Pass `--vm <id>` on **every** command. Auto-selection needs exactly one running
  VM, which never holds on a shared host, and the chooser's `prune --all` hint
  is destructive there. Never `prune --all`; `prune --orphans` only after `--dry-run`.
- Keep a private runtime root: `export QMU_TEMP_DIR=<private-root>/run` for
  launch, exec and transfers alike (short paths keep SSH multiplexing).
- Use private writable images, build outputs, scripts and receipts; share only
  identified read-only inputs. With `--no-net` + a manual NIC, pass `--ssh-port`
  explicitly or your commands can land on another VM's sshd.
- `pry` bridges are host-global: address yours with `pry --instance <pid>`.
- `qmu wait --pattern` exit 0 proves the regex matched, not that the claim in
  its text is true; without `--pattern`, exit 0 proves only that QEMU exited.
  The full operating contract (artifact identity, invalid vs negative runs,
  independent reproduction before handoff) is `reference/evidence-contract.md`.

## Bootstrapping a new instance

A fresh project has no `qmu.toml`. Drive setup through these steps — do not hand-write a config:

1. **`qmu doctor`** — surfaces what's missing (prints a `qmu config init` tip if no config is found).
2. **`qmu config init`** — drops a host-arch-aware starter `qmu.toml` with `# CHANGE ME` lines.
3. **Edit the `# CHANGE ME` lines** and **uncomment them**: `[boot] kernel` → kernel image, `[drive] rootfs` → rootfs image path, `[ssh] key` → private key matching the rootfs (absolute and `~` paths work; relative paths: `reference/troubleshooting.md` → *Config validation rules*).
4. **`qmu doctor`** again — confirm `kernel`, `rootfs image`, `SSH key`, `SSH key permissions` show `[+]`; fix any `[!]` before launching. A `[~]` row (e.g. `libguestfs`) is a warning for an optional capability.
5. **Boot-and-die kernels** (kernelCTF judge envs, syzkaller reproducers): skip the `[drive]`/`[ssh]` edits, leave those tables blank, and launch with `qmu launch --harness ...` (see Harness mode).

Set `[boot] kernel` and the rest of the boot recipe in `qmu.toml` **before you
start iterating**: every launch flag has a config key, so a complete `[boot]`
table reduces each boot to a bare `qmu launch`. Project-local `./qmu.toml` is
right for per-project paths; per-user defaults belong in
`~/.config/qmu/config.toml` (the starter writes an uncommented `[ssh] key` that
overrides the global one — comment it out if the global is what you mean).

## Configuration

Configuration combines built-in defaults with TOML sources and CLI flags. Resolution order, later wins:

1. Built-in defaults — arch=x86_64, memory=4G, cpus=2
2. Global config — `~/.config/qmu/config.toml`
3. Project config — `qmu.toml` found by walking up from CWD
4. CLI flags — `--rootfs`, `--memory`, `--arch`, etc.

```bash
qmu config show         # Resolved config and its sources
qmu config init         # Write starter qmu.toml in CWD (refuses to overwrite; created:false, exit 0)
qmu config path         # Show config search paths
```

TOML settings are table-scoped. The accepted schema is:

- `[boot]`: `kernel`, `initrd`, `cmdline`, `profile`
- `[machine]`: `arch`, `memory`, `cpus`, `cpu`, `nic_model`, `net_backend`, `accel`, `extra_args`
- `[drive]`: `rootfs`, `format`
- `[ssh]`: `key`, `user`, `port_start`
- `[gdb]`: `port_start`
- `[profiles.<name>]`: `cmdline`; `[profiles] name = "..."` is also accepted

Every loaded file is validated before use; unknown/misplaced keys and wrong
types fail naming the source path and key. A broken **global** config warns
and is skipped; a broken **project** or `--config` file is fatal (exit 1) for
every subcommand that reads config — including `kill`, `prune`, `crash`, `log`
and `wait` — so fix the file or run from outside the project. `--config PATH`
is registered only on `launch`, `run`, `status`/`show`, `list`, `log`,
`crash`, `doctor` and `config show`; elsewhere it is an argparse error (exit
2). Details: `reference/troubleshooting.md`.

`qmu config init` writes `[boot]` (`kernel`/`initrd`/`profile`/`cmdline`, all commented — the `kernel` line is the first `# CHANGE ME`), `[machine]` (arch/memory/cpus, with commented `cpu`/`accel`/`nic_model`/`net_backend`/`extra_args`), `[drive]` (rootfs/format), `[ssh]` (key/user, with commented `port_start`), `[gdb]` (commented `port_start`), three `[profiles.*]` blocks, and a commented harness-mode block. `[ssh] user` (default `root`) is recorded on the VM at launch, so set it **before** `qmu launch`; SSH/GDB ports start at `10021`/`1234` (`port_start` overrides); `arch` picks the `qemu-system-*` binary and whether KVM is enabled (guest arch == host only), with `extra_args` for machine flags (e.g. aarch64 `-M virt -cpu cortex-a57`); path values accept `~`.

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
| `124`| the guest never became reachable within `--ssh-timeout`, **or** the command outran `--timeout` (default 60 s) on a guest that was still answering |

```bash
qmu run --kernel ./bzImage -- './exploit'
qmu run --kernel ./bzImage --timeout 120 -- './exploit --spray'
qmu run --kernel ./bzImage --keep -- 'id'          # leave the VM up for follow-up
qmu run --kernel ./bzImage --profile exploit-test -- './exploit'
qmu run --name probe-1 --no-replace --kernel ./bzImage -- 'id'   # shared host: name it
```

It takes every boot flag `launch` does (including `--name`/`--no-replace`),
with three differences: QEMU passthrough is `--qemu-arg` (repeatable,
`--qemu-arg=-M --qemu-arg=virt` for dash-leading values) and every qmu flag,
including `--format`, must come **before** `--`; `--harness`/`--no-wait-ssh`
are rejected (exit 2) because `run` needs SSH — use `launch --harness` +
`wait` + `crash` for boot-and-die kernels; and reaping is conditional: a clean
run removes the VM and prints exactly what `qmu exec` would (trailing `[exit
code: N]` included, so `qmu run ... | grep` works), while anything left to
inspect — a crash, a *survived* kernel report, a guest that never answered, a
boot failure, a `--timeout` overrun — keeps the metadata and `.serial.log`
and names the follow-up (`qmu crash --vm ID`, `qmu prune --vm ID`). Exit `3`
requires a **terminal panic**; a boot that only logged a WARNING/KASAN splat
and then never started sshd is `124` with the report under `kernel_warning`.

## VM Lifecycle

### Launching

```bash
qmu launch                                                     # with [boot] kernel set in qmu.toml
qmu launch --kernel /path/to/bzImage
qmu launch --kernel /path/to/bzImage --profile trigger-test    # panic_on_warn=1
qmu launch --kernel /path/to/bzImage --gdb                     # enable GDB stub
qmu launch --kernel /path/to/bzImage --name myvm --no-replace --memory 8G --cpus 4 --cpu host
qmu launch --append "slub_debug=- nokaslr"                     # ADD params to the profile
qmu launch --cmdline "console=ttyS0 root=/dev/sda custom=1"    # REPLACE the profile cmdline
```

**Requested SSH readiness is part of launch success**: if its wait expires,
`launch` returns **4** (`SSHError`, `ok:false`) and retains the VM and logs —
inspect the reported `vm_id` with `log`/`status` rather than relaunching over
it. `--harness`/`--no-wait-ssh` skip readiness, so their exit 0 says nothing
about SSH, and `guest:serving` never proves the workload initialized.

**`--append` adds, `--cmdline` replaces.** Every profile carries `root=/dev/sda`;
a hand-written `--cmdline` that omits it boots into an emergency shell. A
config `[boot] cmdline` beats the default profile, an explicit CLI `--profile`
beats that config line (and lists the dropped params — `nokaslr` and `init=`
especially — on stderr; re-add them with `--append`), and CLI `--cmdline` wins
over both. `qmu status` says whether the named profile was actually applied
(`profile_applied` in JSON).
Full precedence and the casualty list: `reference/boot-params.md`.

Advanced boot flags (initrd kernels, custom block/NIC topologies):

```bash
# kernel + initramfs + explicit read-only rootfs drive, no implicit rootfs:
qmu launch --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu launch --kernel ./bzImage --no-net            # -nic none; SSH commands won't work
qmu launch --kernel ./bzImage --nic-model e1000   # NIC model (default virtio-net-pci)
qmu launch --kernel ./bzImage -- -no-reboot       # raw QEMU args only after `--`
```

- `--initrd PATH` — attach an initramfs/initrd (`~` expansion works).
- `--drive SPEC` — raw QEMU `-drive` spec, repeatable. **Any `--drive` suppresses the implicit rootfs drive**; a `--drive` image is not recorded as the VM's rootfs (holder checks, `status.rootfs`), so prefer `--rootfs` for a plain rootfs.
- `--no-net` / `--nic-model MODEL` / `--cpu MODEL` — networking and CPU overrides. `--no-net` without `--ssh-port` records **no** SSH endpoint (SSH commands refuse, naming the reason); with a manual NIC pass `--ssh-port N` and forward `N` yourself.
- `--no-kvm` — force TCG (`[machine] accel=tcg`); KVM is otherwise auto-enabled when guest arch == host and `/dev/kvm` exists, recorded as `kvm` in `launch`/`status`/`list` JSON (and in the `gdb` payload when true). KVM does **not** disable hardware watchpoints (`reference/debugging.md`).

Profiles (LSMs disabled, `kasan.fault=panic` in all three): `exploit-dev`
(default) — no `panic_on_warn`/`oops=panic`; `trigger-test` — adds
`panic_on_warn=1`; `exploit-test` — adds `oops=panic` (the boot spelling;
`panic_on_oops=1` is sysctl-only and silently ignored at boot). `--profile
bogus` lists the full set, including the distro-target `ubuntu-*` profiles.
The drive uses `snapshot=on`, so the base image is never modified.

**Auto-replace.** A `--name` (or the default) that matches a running VM
**replaces** it. `--no-replace` makes that a hard error (exit 1) naming the
running pid — it never launches alongside, which would strand the first QEMU.

### Multiple VMs

Each VM gets its own SSH port (from 10021+), QMP socket, and serial log. With
exactly one VM running, most commands auto-select it; `log`/`crash`/`wait
--pattern` also consider stopped VMs and say which one they picked
(`autoselected` in JSON). On a shared host always pass `--vm <id>`. `--vm`,
`--format`, and `--out` are accepted before or after the subcommand; on
`launch`/`run`, `--vm` is an alias for `--name`. Details:
`reference/troubleshooting.md` → *Auto-selection, precisely*.

### VM state has two independent axes

`qmu list` reports both, because they vary independently — orphaned AND
panicked at once is the normal outcome of a successful trigger on a VM whose
metadata was lost.

- **Existence** (`status` in JSON): `running`, `orphaned` (no metadata, process
  alive), `stopped`, `absent`.
- **Guest usability** (`guest` in JSON): `serving`; `paused` (vCPU halted —
  by `qmu gdb` until `qmu cont`, or by an unclean pry bridge death); `crashed`
  (a crash report is retrievable **and the guest is still running**);
  `panicked` (a terminal `Kernel panic - not syncing` — the guest is gone);
  `unknown`.

`crashed` vs `panicked` drives a destructive decision. Under `exploit-dev` an
Oops that KASAN did **not** detect (a plain `BUG:`/GPF/null deref in an
uninstrumented path) kills only the faulting task; the guest keeps serving and
lands on `crashed` — **pull the report, do not reap it.** But every profile
carries `kasan.fault=panic`, so a KASAN-detected bug (OOB, UAF — most triggers
on a KASAN kernel) is terminal: `Kernel panic - not syncing: kasan.fault=panic
set`, guest `panicked`. To survive a KASAN report, launch with `--append
kasan.fault=report`; use `--profile exploit-test` (`oops=panic`) to make
*every* Oops terminal. `[running — GUEST PANICKED]`, `[running — crash report
waiting]` and `[running — vCPU paused]` are all "running" on the first axis.
Every command that answers about a VM agrees with `list` about whether it
exists — `status`, `log`, `crash`, `prune`, `kill`, `wait`, and `exec` all
describe a stopped or orphaned VM rather than reporting it missing.
The SSH commands (`exec`, `push`, `pull`, `compile`, `dmesg`, `kbase`)
consult the guest axis first: against a `panicked` guest they refuse in under
a second — exit 1 (the panic is not fresh for *this* command), `guest_state:
"panicked"`, and `Read the report: qmu crash --vm X` / `Then reap it: qmu kill
--vm X` — and against any QMP `running:false` state (`paused`, `debug`,
`restore-vm`, …) with `guest_state: "paused"`.

### Other lifecycle commands

```bash
qmu list                # List VMs with existence AND guest state (see above)
qmu status              # Detailed status (QMP state, SSH, kernel cmdline, ...); `qmu show` is an alias
qmu kill                # Graceful shutdown via QMP, falls back to SIGTERM
qmu kill --force        # SIGKILL
qmu kill --no-clean     # Stop but keep .serial.log + .json for forensics
qmu prune --vm <name>             # Remove a stopped VM's state files (no-op after a plain kill)
qmu prune --vm <name> --keep-logs # Drop .json + .qmp.sock but PRESERVE .serial.log and .qemu.log
qmu prune --vm <name> --dry-run   # preview; every prune mode except --runtime takes --dry-run
qmu prune --orphans --dry-run     # list qmu-launched QEMUs no record claims; drop --dry-run to kill them
qmu prune --all                   # Remove every stopped VM's state files — NOT on a shared host
qmu prune --runtime --older-than 86400  # Age-gated prune of qmu-owned runtime artifacts
qmu prune --build-residue --dry-run     # preview reclaiming kernel build residue
qmu cache du                      # size every cache subtree; what is reclaimable
qmu cache ls --top 10             # biggest reclaimable source trees
```

`list` probes SSH for every running VM, so on a busy shared host it can take
15–60 s; `status --vm <id>` answers in well under a second.

`kill` removes metadata and logs by default, but keeps `.serial.log`/
`.qemu.log` when the guest axis is `crashed` or `panicked` (and says so,
pointing at `qmu crash --vm <id>`); `kill --no-clean` preserves everything.
Log-only remnants are age-gated against
`prune --vm` (default 24 h; `--older-than 0` clears now). Every prune mode,
the `--dry-run` envelope and `qmu cache`: `reference/cache.md`.

## Harness mode (boot-and-die kernels)

For kernels that boot, run a one-shot init, and halt (kernelCTF judge envs, syzkaller reproducers) — no SSH, no interactive guest. Launch with `--harness`, then block on `qmu wait`:

```bash
qmu launch --harness --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh' \
  -- -no-reboot                                           # a panic must not reboot-loop into a 124

qmu wait                  # block until the recorded QEMU process exits (no timeout by default)
qmu wait --timeout 120    # give up after 120s
qmu wait --no-clean       # keep .serial.log after confirmed process exit

# Or block on serial output instead of exit — for a VM that keeps running:
qmu wait --pattern '^=+ results =+$' --timeout 120
```

`--harness` implies `--no-wait-ssh` and `--no-net` and skips the rootfs/SSH-key
requirement (a config `[drive] rootfs` is still attached unless you pass
`--drive`/`--rootfs`; prefer `--harness --rootfs ./img` so the image stays
tracked). Bare `qmu wait` exits **0** when the recorded QEMU process exited
(JSON `crash` carries the terminal crash, null if none), **124** on timeout
with the process alive — including a guest that panicked and halted without
exiting, so check `crash` — and **4** on a QMP transport failure with the
process still alive. It auto-cleans harness VMs (metadata + `.serial.log`)
only after a confirmed exit unless `--no-clean`; read the crash from `wait`'s
own output, since a later `qmu crash` may find the log gone. Full semantics:
`reference/wait.md`.

## The boot-and-check iterate loop

This is the loop you will run dozens of times when developing an exploit
against a VM with no working SSH. Use these commands rather than reaching
around qmu into `~/.cache/qmu/instances/`. Apply
`reference/evidence-contract.md` before repeating a run or promoting a matched
marker into a milestone claim.

```bash
# 1. Build on the host, bake into the rootfs, and boot — one command.
qmu launch --name poc --no-replace --inject ./exploit:/root/ --append "slub_debug=-"

# 2. Block until the guest prints its marker. Bounded, and it aborts early
#    on a terminal kernel crash instead of hanging.
qmu wait --vm poc --pattern '^=+ results =+$' --timeout 120

# 3. Pull just the interesting lines out of the serial log.
qmu log --vm poc --grep "leaked|OOB|UAF" --context 3
```

**Never poll the serial log by hand.** `until grep -q ... serial.log; do sleep
2; done` hangs forever if the guest panics before the marker or the VM dies
(and never poll a *debugged* VM by re-attaching pry — every attach halts the
guest). `qmu wait --pattern` ends in all four cases with a distinct exit code:

- **Exit 0** — the pattern matched. JSON carries `matched_line`.
- **Exit 3** — a **terminal** kernel panic appeared first; the guest is gone
  and the marker can never arrive. The report is in `crash`. A *survived*
  crash (a non-KASAN Oops under `exploit-dev`) does NOT abort — the guest is
  still running, so the wait continues. `--ignore-crash` suppresses even the
  terminal-panic abort; pasting it reflexively is how a real panic gets missed.
- **Exit 1** — the VM exited without the pattern and without terminal-panic
  evidence (a survived Oops/KASAN report remains in `crash` as context).
- **Exit 124** — `--timeout` elapsed with the VM still running.

**Markers must be anchored and line-shaped.** `--pattern` is a Python regex
matched per **complete line**: an unanchored `"results"` also matches the
kernel's echo of the command line, so anchor it (`'^=+ results =+$'`); and a
fragment with no trailing newline (`login:`, a `printf` without `\n`) is
withheld on a running VM and **cannot match** until something ends the line.
The scan starts at the later of the recorded guest epoch and the latest
kernel boot banner and reports that boundary (`scan_offset`/`scan_scope`);
a guest `dmesg` replay reproduces the banner and moves it. With explicit
`--vm`, stopped VMs' retained logs are inspected too. Details:
`reference/wait.md`.

`qmu log` reads the same log after the fact:

```bash
qmu log --grep "BUG:|WARNING:" --context 5   # searches the WHOLE log
qmu log --grep "BUG:" --tail 200             # ...unless you narrow it on purpose
qmu log --full --out ./evidence.log          # whole log to a file for the record
```

A bare `qmu log` shows the last 50 lines; `--grep` searches the **whole** log
(a tail-scoped filtered read returns confident false negatives); an explicit
`--tail` still narrows it, and the result names the scope searched (`scope`
in JSON). `--full` ignores `--tail`; with `--out` it replaces copying the file
by hand. Do not pipe `--full` into `grep -c` under a JSON format (the envelope
wraps the log in one string) — use `--grep` (it counts in `matches`).

**Unknown boot parameters.** `launch` (once SSH is up) and `wait` — not
`status` — report any boot parameter the kernel did not claim
(`unknown_kernel_params`; gate on `unknown_kernel_params_by_source.operator`,
the `profile` bucket is perpetual noise like `apparmor=0`). This catches
`panic_on_oops=1` (a sysctl — the boot form is `oops=panic`). Pre-parse params
such as x86 `nokaslr` are not reported because they work despite being
unclaimed; dotted params (`kasan.faul=panic`) are spell-checked by `launch`
because the kernel never reports them. Full rules: `reference/boot-params.md`.

## File Transfer

```bash
qmu push exploit.c                  # → /root/ in guest
qmu push exploit.c /tmp/exploit.c   # → specific path (a trailing / means "into this dir")
qmu pull /root/output.txt           # → CWD
qmu pull /root/output.txt ./results/
```

`push` transfers a single regular file (archive directories first). A caller
error — missing local file, directory, missing remote path, scp exit ≠ 255 —
is exit 1 (`error_type: "SCPFileError"`), so exit 4 keeps meaning "the
transport dropped or timed out".

### Offline rootfs editing (no running VM, via libguestfs)

**When SSH is not up, this — not `sudo mount`/`cp`/`umount` — is how files get
into the guest.** `qmu rootfs` operates on the image file directly (needs
libguestfs; `qmu doctor` checks it and prints the `chmod 0644 /boot/vmlinuz-*`
/ `SUPERMIN_KERNEL=` fix when the appliance kernel is unreadable):

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

**GUEST must already exist** — `inject` errors on a missing destination
directory (`--mkdir` opts in) and `rm` on a missing path (`--force` tolerates
it), so a typo cannot report success while the previous build stays in place;
**verify after every inject** with `qmu rootfs ls`/`cat`. `ls`/`cat` are
read-only and work while a VM runs; `inject`/`rm`/`shell` refuse an image a
running VM holds. `--partition N` defaults to `1`; `qmu-linux-rootfs` and
Debian cloud images are whole-disk ext4 → `--partition 0`. `qmu launch
--inject LOCAL:/guest/dir` runs the same injection against the configured
rootfs right before boot (repeatable; `--partition` applies):

```bash
qmu launch --name poc --inject ./exploit:/root/ --inject ./init.sh:/ --partition 0
```

Rationale, edge cases and the libguestfs fix: `reference/troubleshooting.md`.

## Guest Execution

```bash
qmu exec "uname -a"
qmu exec "cat /proc/slabinfo | grep kmalloc-192"
qmu exec "./exploit" --timeout 120          # default --timeout 30
```

Text output is the guest's stdout, then `[stderr] …` lines and a trailing
`[exit code: N]`; JSON carries `vm_id`, `exit_code` (null when the command
did not finish), `stdout`, `stderr`. The exit code is the guest's (`exit 255`
is reported as 255, not a crash), `124` on a `--timeout` overrun of a guest
that still answers, `3` on a transport loss corroborated by a fresh serial
crash, `4` on a transport loss without one, and `1` with `guest_state:
"paused"` when the vCPU was halted (by a debugger stop, including one that
fires mid-command). Non-UTF-8 guest output is delivered with U+FFFD
replacement, never a `UnicodeDecodeError`.

## Compile and Run

The primary exploit-dev workflow — push a C file, compile it in the guest, optionally run it:

```bash
qmu compile exploit.c                       # push + compile
qmu compile exploit.c --run                 # push + compile + run
qmu compile exploit.c --run --timeout 120
qmu compile exploit.c --cflags "-static -lpthread -DDEBUG=1"
qmu compile exploit.c --cflags '-static -DMSG=\"hello\"'   # string-valued define, both paths
```

Default CFLAGS: `-static -lpthread`. `--cflags` is a list of shell flags —
the guest path splices it verbatim into the remote `gcc` line (word-split by
the guest shell, so `\"` reaches gcc as `"`), the `--host` path splits it with
`shlex`. Both examples above compile on both paths; a define whose value
contains a space (`-DMSG="hello world"`) survives neither.

**`--host`** compiles on the host with a cross toolchain chosen from the
**guest** arch recorded on the instance, then pushes the binary — the only
path when the guest has no gcc (kernelCTF images, firmware rootfs) and several
times faster than compiling inside a TCG guest. Toolchain table, `--cc`, and
the no-recorded-arch refusal: `reference/cross-arch.md`. JSON shares the core
keys on both paths (`compile_cmd`, `compile_exit`, `compiled`, `run_*`,
`compiled_on`); the host path adds `compiler` and `guest_arch`.

```bash
qmu compile exploit.c --host --run
qmu compile exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

**Crash detection is best-effort.** On a `--timeout` overrun or an SSH
teardown (rc=255) qmu pulls the report from the serial log; a `--timeout`
expiry on a guest that still answers SSH is **124** with `timed_out: true`,
not a crash. After **any** suspected panic, including a bare `[exit code:
255]`, confirm with `qmu crash` (and `qmu log --tail 200`). A `panic=N` guest
reboots instead of staying down; the crash is still exit 3 with the report,
but later output belongs to a new boot.

## Crash Extraction

The headline feature — works even when SSH is dead, and **after** a VM exits (state files survive until prune):

```bash
qmu crash                   # last crash in the current restored guest epoch
qmu crash --vm run-3        # current epoch; works on a stopped VM too
qmu crash --full-history    # retained-log forensics across snapshot/reset epochs
qmu log --tail 100          # raw serial tail, without provenance filtering
```

Command-attributed crashes from `exec` and `compile --run` are extracted only
from serial bytes appended after that command began; a stale panic already in
the log never sets `crash_detected` for the new command. Standalone `qmu crash`
defaults to the persisted current guest epoch; `--full-history` reaches older
retained crashes. In structured output, inspect `crash_detected` and `scope`;
`ok: true`/exit 0 means the query found a report, not that the VM is healthy.
"No crash" is a result-style failure: exit 1, `ok:false`, no `error` field.
Detects KASAN, BUG/Oops, kernel panic, GPF, UBSAN, slab-use-after-free, and
more; if it reports nothing but you suspect a panic, `qmu log --tail 200`.

## Snapshots

```bash
qmu snapshot save clean
qmu snapshot list
qmu snapshot load clean
qmu snapshot delete clean
```

In-session `savevm`/`loadvm` checkpoints work out of the box with the default
raw rootfs behind qmu's `snapshot=on` overlay and the default user/slirp NIC;
they disappear when QEMU exits. A snapshot name must be a single token.

**Snapshot-rewind loop — fast in-session iteration:**
```bash
qmu launch --kernel ./bzImage --name dev --no-replace
qmu push exploit /tmp/x --vm dev
qmu snapshot save clean --vm dev          # clean pre-PoC state
for i in 1 2 3 4 5; do
  qmu exec /tmp/x --vm dev                # run the PoC (may crash/corrupt the kernel)
  qmu log --tail 200 --vm dev > runs/run-$i.log
  qmu snapshot load clean --vm dev        # rewind to clean — far faster than a full reboot
done
```

`snapshot load` tears down the stale SSH ControlMaster (first post-load `exec`
is fast, no `Broken pipe`); a failed `load` resumes the guest; HMP error
replies (`load`/`delete` of a missing name, a malformed `save` name) are
failures with `error`/`error_type`. Durable qcow2 snapshots, passt, and the
debugger interaction (`int3` bytes get baked into a save):
`reference/snapshots.md`.

## Kernel Logs

```bash
qmu dmesg              # full dmesg from guest (via SSH)
qmu dmesg --tail 50
```

For a VM with no SSH, read the serial console instead — `qmu log` takes the
same `--tail`, plus `--grep`/`--context`/`--full` (see the iterate loop).

## GDB Integration (with pry)

Explicit attach → continue → discover base → manual rebase → arm → resume →
trigger → wait. qmu never resumes, re-halts, or rebases for you:

```bash
eval "$(tools/kbuild.sh --version 7.0 --arch x86_64)"
qmu launch --kernel "$KERNEL" --gdb --name debug-vm --no-replace
qmu gdb --vm debug-vm --symbols "$VMLINUX"      # spawns a pry bridge; the vCPU is now HALTED
qmu cont --vm debug-vm                          # resume so SSH works (kbase needs it)
eval "$(qmu kbase --vm debug-vm --symbols "$VMLINUX")"   # KBASE, LINK_BASE, SLIDE; stdout is eval-safe
pry load "$VMLINUX" --base "$KBASE"             # first pry touch after qmu cont HALTS again
pry break set __x64_sys_newuname                # trigger-specific canary, not commit_creds
pry continue --background                       # REQUIRED before any qmu exec
qmu exec --vm debug-vm "uname -r"
pry wait --timeout 10                           # the reliable stop primitive (pry status can lag)
pry backtrace
```

**Attaching halts the vCPU** (`qmu gdb`, `pry launch --connect`), and so does
the first pry command after a `qmu cont`; SSH commands against a halted guest
refuse fast (exit 1, `guest_state: "paused"`). `qmu gdb --symbols` loads at
link-time addresses; `qmu kbase` prints the runtime base and you apply it.
Resume through one authority per stop (pry *or* qmu). Bridge lifecycle on a
shared host (`Multiple bridge instances`, `pry kill --instance`, reconnecting
with `pry launch --connect localhost:<gdb_port>`), the KASLR re-slide after
`system_reset`, watchpoints under KVM, and the Debugger↔VM coherence table:
`reference/debugging.md` — read it before the first `qmu gdb`.

## Cross-arch guests (aarch64 / arm32)

ARM guests need `--arch`, `-- -M virt -cpu …`, and an ARM cmdline
(`console=ttyAMA0 root=/dev/vda`); the implicit rootfs drive is already
arch-aware. The quickstarts, the arch-aware `qmu.toml`, multiarch gdb, the
`--no-net`/`--ssh-port` recipe for arm32 MMIO networking, and per-arch KASLR
rebasing (`--base "$KBASE"` on arm64, `--slide 0` on arm32) are in
`reference/cross-arch.md`.

## Raw QEMU Access

```bash
qmu qmp query-status                       # raw QMP command
qmu qmp device_del --args '{"id": "net0"}' # QMP arguments as a JSON object (see `qmu qmp --help`)
qmu monitor "info registers"               # HMP command via QMP
qmu monitor "x /16xg 0xffffffff81000000"   # examine memory
qmu monitor "cont"                         # resume a paused/halted guest
qmu qmp system_reset                       # reboots the guest; drops gdbstub breakpoints, re-slides KASLR
```

## Output Formats, Result Contract, Exit Codes

All commands support `--format text|json|ndjson` (accepted before or after the subcommand; for `run`, before `--`).

**Envelope.** Under `--format json`/`ndjson`, every command that gets past
argument parsing emits one object with `"ok": <bool>` — the single,
command-agnostic success predicate. `ok:false` comes in two shapes:

- **Exception paths** (`QMUError`/`QMPError`/`SSHError`/internal): `{"ok":
  false, "error": "...", "error_type": "<ExceptionClassName>"}`; text mode
  prints `[qmu] Error: …`, `[qmu] QMP error: …` or `[qmu] SSH error: …` on
  **stderr**.
- **Result-style failures** — the command ran and the answer is "no": a
  non-zero guest exit or `--timeout` overrun on `exec`/`run`/`compile --run`,
  `exec` transport loss (exit 3/4), `wait --pattern` no-match/timeout
  (`matched:false`, `reason`), `crash` with no report (`crash_detected:false`).
  These carry **domain fields, not `error`/`error_type`**, and text mode
  prints the report on **stdout** with no prefix. The paused/panicked refusal
  of an SSH command is the hybrid: JSON `guest_state`/`qemu_status` without
  `error`, text `[qmu] Error: …` on stderr.
- Argparse errors (exit 2) print usage on stderr in text mode; under a JSON
  format they emit `{"ok": false, "error": …, "error_type": "UsageError",
  "usage": …}` on stdout.

Branch on the exit code and `ok`, never on the presence of `error`.

Use the exit code (not log scraping) to branch:

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Operational failure — no running VM, bad `--vm`, kernel not found, guest command non-zero, `doctor` unhealthy, a snapshot op failed, `wait --pattern` outlived the VM, a paused/panicked guest refusal, a `push`/`pull` caller error (any `QMUError`) |
| `2`  | Usage / argument-parse error (argparse) ONLY — a bad flag *combination* that qmu itself rejects (`prune --runtime --dry-run`) is `1` |
| `3`  | Guest kernel crash — always corroborated by a fresh serial crash report (a bare dropped connection is `4`) |
| `4`  | QMP or SSH transport-layer failure (`QMPError`/`SSHError`), including requested `launch` SSH-readiness timeout; a dropped SSH/scp connection with NO fresh crash; a QEMU error reply to `qmu qmp`; or an internal/unexpected qmu error |
| `124`| `qmu wait` timed out; `qmu run` gave up waiting for the guest to answer SSH; or an `exec`/`run`/`compile --run` guest command exceeded `--timeout` **while the guest was still reachable** |

Exit `3` is guest-side; an internal qmu/transport fault is `4`, so a tooling
bug is never mistaken for a kernel panic. `exec`, `push`, and `pull` apply that
rule identically: a lost connection returns `3` only when a fresh serial crash
corroborates it, otherwise `4`; `crash_detected` in JSON gives the same answer.
(Matches `qmu --help`.)

**Output spilling.** Outputs over ~10k estimated tokens go to a file under
`$QMU_TEMP_DIR/spills` (or the XDG/platform temp fallback); stdout becomes a
pointer envelope with `artifact_path` (also echoed as `[qmu] Output spilled to
<path>` on stderr). Always consume `artifact_path`; never reconstruct spill
paths. `--out PATH` forces a file. Details: `reference/troubleshooting.md`.

## Health Check

```bash
qmu doctor   # config sources, kernel, QEMU binary, rootfs, SSH key + perms, KVM, pry, libguestfs, running VMs, skill links
```

Exits 1 when a gating row is `[!]` or no config is found (prints a `qmu config
init` tip). `pry` is informational and `libguestfs` is a non-blocking `[~]`
(offline inject is optional). `doctor` cannot see cross toolchains or
`gdb-multiarch`.

## Files on disk

Each VM keeps state under `~/.cache/qmu/instances/` (or `$QMU_CACHE_DIR`) — one
of four cache subtrees; `reference/cache.md` covers the rest, which
`prune --vm/--all` does not touch.

| File                | Purpose                              | Removed by |
|---------------------|--------------------------------------|------------|
| `<name>.json`       | VM metadata (pid, ports, kernel, arch, kvm) | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.serial.log` | Serial console (read via `qmu log`)  | `kill` (only when the guest is neither `crashed` nor `panicked`), `prune`, `wait` harness auto-clean — **kept** by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |
| `<name>.qmp.sock`   | QMP control socket                   | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.qemu.log`   | QEMU stdout/stderr log               | same rule as `.serial.log` |

`qmu list` shows running and stopped VMs with a status marker so you can see what's recoverable;
`launch`/`status`/`list` JSON report `arch`, `kvm`, `cmdline` and `profile_applied`.
The serial log is write-only — there is no interactive console; use SSH for interactive work.
