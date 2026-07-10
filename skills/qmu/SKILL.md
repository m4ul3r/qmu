---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

Use this skill when the user wants to boot, manage, or interact with QEMU VMs for kernel security research. qmu emits structured JSON or text output and handles the common pain points of QEMU-based kernel exploit development. Run `qmu --help` for full usage.

## Bootstrapping a new instance

A fresh project has no `qmu.toml`. Drive setup through these steps — do not hand-write a config:

1. **`qmu doctor`** — surfaces what's missing (prints a `qmu config init` tip if no config is found).
2. **`qmu config init`** — drops a host-arch-aware starter `qmu.toml` with two `# CHANGE ME` lines.
3. **Edit the two `# CHANGE ME` lines**: `[drive] rootfs` → rootfs image path, `[ssh] key` → private key matching the rootfs (relative, absolute, and `~` paths all work).
4. **`qmu doctor`** again — confirm `rootfs image`, `SSH key`, `SSH key permissions` show `[+]`; fix any `[!]` before launching.
5. **Boot-and-die kernels** (kernelCTF judge envs, syzkaller reproducers): skip step 3, leave `[drive]`/`[ssh]` blank, and launch with `qmu launch --harness ...` (see Harness mode).

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

- `[machine]`: `arch`, `memory`, `cpus`, `cpu`, `nic_model`, `net_backend`, `extra_args`
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

`qmu config init` writes `[machine]` (arch/memory/cpus, with commented `cpu`/`nic_model`/`extra_args`), `[drive]`, `[ssh]`, `[gdb]`, three `[profiles.*]` blocks, and a commented harness-mode block. Notes:

- `[ssh] user` (default `root`) sets the guest login for `exec`/`push`/`pull`/`compile`; it is recorded on the VM at launch, so set it **before** `qmu launch`.
- SSH and GDB ports start at `10021` / `1234` (uncomment `port_start` to override).
- `arch` drives which `qemu-system-*` binary runs and whether KVM is enabled (only when guest arch == host). Use `extra_args` for arch-specific machine flags (e.g. aarch64 `-M virt -cpu cortex-a57`).
- Path values (`rootfs`, `ssh.key`, `--kernel`, `--initrd`) accept `~` expansion.

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage       # Boot a VM (defaults: 4G RAM, 2 CPUs, exploit-dev profile)
qmu exec "uname -a"                        # Run a command in the guest
qmu compile exploit.c --run                 # Push, compile, and run C in the guest
qmu crash                                   # Extract crash report (works even when SSH is dead)
qmu kill                                    # Stop the VM
```

## VM Lifecycle

### Launching

```bash
qmu launch --kernel /path/to/bzImage
qmu launch --kernel /path/to/bzImage --profile trigger-test    # panic_on_warn=1
qmu launch --kernel /path/to/bzImage --gdb                     # enable GDB stub
qmu launch --kernel /path/to/bzImage --name myvm --memory 8G --cpus 4 --cpu host
qmu launch --kernel /path/to/bzImage --cmdline "console=ttyS0 root=/dev/sda custom=1"
```

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

Profiles (LSMs disabled + KASAN in all three):
- `exploit-dev` (default) — no panic_on_warn
- `trigger-test` — adds `panic_on_warn=1` (validate bug triggers)
- `exploit-test` — adds `panic_on_oops=1` (final exploit validation)

Rootfs/SSH-key/other settings come from config; override with CLI flags. The drive uses `snapshot=on`, so the base image is never modified.

**Auto-replace.** Launching with a `--name` (or the default) that matches a running VM **replaces** it (kills the old one first) so a stale VM never blocks a fresh boot and QEMU processes don't leak. Pass `--no-replace` to fail instead.

### Multiple VMs

Each VM gets its own SSH port (from 10021+), QMP socket, and serial log. With one VM running, commands auto-select it; with several, pick one with `--vm <id>`.

`--vm`, `--format`, and `--out` are accepted **both before and after** the subcommand — `qmu --vm <id> exec "..."` and `qmu exec --vm <id> "..."` are equivalent. Examples below put them after the subcommand.

```bash
qmu launch --kernel ./bzImage-kasan --name kasan-vm
qmu exec --vm kasan-vm "uname -r"
qmu kill --vm kasan-vm
```

### Other lifecycle commands

```bash
qmu list                # List VMs (running + stopped) with status markers
qmu status              # Detailed status (QMP state, SSH, kernel cmdline, ...)
qmu kill                # Graceful shutdown via QMP, falls back to SIGTERM
qmu kill --force        # SIGKILL
qmu kill --no-clean     # Stop but keep .serial.log + .json for forensics
qmu prune --vm <name>             # Remove a stopped VM's state files
qmu prune --all                   # Remove every stopped VM's state files
qmu prune --vm <name> --keep-logs # Drop .json + .qmp.sock but PRESERVE .serial.log and .qemu.log
qmu prune --runtime --older-than 86400  # Age-gated prune of qmu-owned runtime artifacts
```

`--keep-logs` preserves both `.serial.log` and `.qemu.log` (metadata and QMP sockets are still removed).

`qmu prune --runtime` removes only aged **marked** automatic output spills and aged definitely stale direct `cm-*` Unix sockets under the runtime root. It skips live/uncertain SSH controls, explicit `--out` files, unmarked lookalikes, symlinks, and unrelated temp names (including arbitrary `/tmp/qmu-*`). Default age is 86400 seconds; use `--older-than SECONDS` (non-negative). The command is idempotent and never recursively deletes the runtime root.

State files are **never silently removed** except by `qmu wait`'s harness auto-clean (below). After `kill --no-clean`, or a harness VM that powered off without `wait`, the `.serial.log` survives — read it with `qmu log`/`qmu crash`, then `qmu prune` when done. See [Files on disk](#files-on-disk).

## Harness mode (boot-and-die kernels)

For kernels that boot, run a one-shot init, and halt (kernelCTF judge envs, syzkaller reproducers) — no SSH, no interactive guest. Launch with `--harness`, then block on `qmu wait`:

```bash
qmu launch --harness --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu wait                  # block until the recorded QEMU process exits (no timeout by default)
qmu wait --timeout 120    # give up after 120s
qmu wait --no-clean       # keep .serial.log after confirmed process exit
```

`--harness` implies `--no-wait-ssh` and `--no-net` and skips the rootfs/SSH-key requirement.

`qmu wait` is the harness/judge primitive:
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

## File Transfer

```bash
qmu push exploit.c                  # → /root/ in guest
qmu push exploit.c /tmp/exploit.c   # → specific path
qmu pull /root/output.txt           # → CWD
qmu pull /root/output.txt ./results/
```

### Offline rootfs editing (no running VM, via libguestfs)

To bake files into a rootfs **before** boot (e.g. a harness rootfs with no SSH), or inspect one, use `qmu rootfs` — operates on the image file directly. Needs libguestfs (`guestfish`):

```bash
qmu rootfs inject ./rootfs.img ./exploit:/root ./run.sh:/   # each pair is LOCAL:GUEST, GUEST is a dir
qmu rootfs inject ./rootfs.img ./exploit:/root --partition 0   # whole-disk/partitionless image
qmu rootfs shell ./rootfs.img                               # interactive guestfish
```

`--partition N` selects the partition (default `1`; `0` for whole-disk).

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

> **Crash detection is best-effort.** When a guest command crashes the kernel, qmu attempts to pull the crash report from the serial log — both when the command exceeds `--timeout` and when SSH is torn down (rc=255) by a panic. This is best-effort: after **any** suspected panic, including a bare `[exit code: 255]`, always confirm with `qmu crash` (and `qmu log --tail 200`). Never rely on the exit code alone to detect a crash.

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
| `1`  | Operational failure — no running VM, bad `--vm`, kernel not found, guest command non-zero, `doctor` unhealthy, or a snapshot op failed (any `QMUError`) |
| `2`  | Usage / argument-parse error (argparse) |
| `3`  | Guest kernel crash, or SSH transport loss under a panic |
| `4`  | QMP or SSH transport-layer failure (`QMPError`/`SSHError`), or an internal/unexpected qmu error (the `main()` catch-all, a hung helper subprocess) |
| `124`| `qmu wait` timed out |

Exit `3` is guest-side; an internal qmu/transport fault is `4`, so a tooling bug is never mistaken for a kernel panic. (Matches `qmu --help`.)

**Output spilling.** Large outputs (>10k estimated tokens) auto-spill to a file under the centralized spill root, in precedence order: `$QMU_TEMP_DIR/spills`, then `$XDG_RUNTIME_DIR/qmu/spills` when that XDG runtime directory is absolute/existing/writable/searchable, then `<platform temp>/qmu/spills`. Automatic spills are marked with an adjacent ownership sidecar; explicit `--out` paths are never marked as qmu-owned. **Callers must continue consuming `artifact_path`** — never reconstruct spill names or paths. Read the path from the result envelope's `artifact_path` field or the `[qmu] Output spilled to <path>` stderr line. The envelope's `{"token_estimate": <int>, "estimator": "chars/4"}` is a tokenizer-agnostic heuristic for sizing only.

## Health Check

```bash
qmu doctor   # config sources, QEMU binary, rootfs, SSH key + perms, KVM, pry, running VMs, skill
```

Exits non-zero if no config is found (prints a `qmu config init` tip). SSH key existence and permissions are separate checks. `pry` is informational (only required for `qmu gdb`) — a missing `pry` does not fail the check.

## Files on disk

Each VM keeps state under `~/.cache/qmu/instances/` (or `$QMU_CACHE_DIR`):

| File                | Purpose                              | Removed by |
|---------------------|--------------------------------------|------------|
| `<name>.json`       | VM metadata (pid, ports, kernel)     | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.serial.log` | Serial console (read via `qmu log`)  | `kill`, `prune`, `wait` harness auto-clean — **kept** by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |
| `<name>.qmp.sock`   | QMP control socket                   | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.qemu.log`   | QEMU stdout/stderr log               | `kill`, `prune`, `wait` harness auto-clean — **kept** by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |

`qmu list` shows running and stopped VMs with a status marker so you can see what's recoverable.

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
- **Crash auto-extraction is best-effort** — confirm with `qmu crash` / `qmu log --tail 200` after any suspected panic (see Compile and Run).
- **Serial log is write-only** — no interactive console; use SSH for interactive work.
