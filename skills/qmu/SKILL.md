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
qmu prune --vm <name> --keep-logs # Drop .json + .qmp.sock but PRESERVE .serial.log
```

State files are **never silently removed** except by `qmu wait`'s harness auto-clean (below). After `kill --no-clean`, or a harness VM that powered off without `wait`, the `.serial.log` survives — read it with `qmu log`/`qmu crash`, then `qmu prune` when done. See [Files on disk](#files-on-disk).

## Harness mode (boot-and-die kernels)

For kernels that boot, run a one-shot init, and halt (kernelCTF judge envs, syzkaller reproducers) — no SSH, no interactive guest. Launch with `--harness`, then block on `qmu wait`:

```bash
qmu launch --harness --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu wait                  # block until the VM stops (no timeout by default)
qmu wait --timeout 120    # give up after 120s
qmu wait --no-clean       # keep .serial.log after stop
```

`--harness` implies `--no-wait-ssh` and `--no-net` and skips the rootfs/SSH-key requirement.

`qmu wait` is the harness/judge primitive:
- **Exit 0** — VM stopped cleanly; the result **carries the crash** (JSON `crash` field, null if none; text prints `Crash from serial log:`).
- **Exit 124** — `--timeout` elapsed, VM still running.

**`wait` auto-cleans harness VMs by default** (removes metadata + `.serial.log` on stop) unless you pass `--no-clean`. So **read the crash from `wait`'s own output** rather than a later `qmu crash` — the log may already be gone. Non-harness VMs are never auto-cleaned by `wait`.

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
qmu crash                   # extract last KASAN/BUG/Oops/panic from serial log
qmu crash --vm run-3        # works on a stopped VM too
qmu log --tail 100          # last 100 lines of serial console
```

Detects KASAN, BUG/Oops, kernel panic, general protection fault, UBSAN, slab-use-after-free, and more. If `qmu crash` reports nothing but you suspect a panic, fall back to `qmu log --tail 200`.

## Snapshots

Save/restore VM state within a session. Snapshots are ephemeral (a temporary COW overlay; lost when the VM exits — the base image stays clean):

```bash
qmu snapshot save clean
qmu snapshot list
qmu snapshot load clean
qmu snapshot delete clean
```

**Snapshots need a qcow2 rootfs disk.** `savevm` stores *internal* snapshots, which QEMU can only write into a **writable qcow2** disk. The default `[drive] format = "raw"` image (and the implicit `snapshot=on` overlay) cannot hold them, so `qmu snapshot save` fails out of the box. Convert the rootfs and switch formats: `qemu-img convert -O qcow2 rootfs.img rootfs.qcow2`, then set `[drive] format = "qcow2"`.

**Snapshots also need the `passt` network backend.** The default `-net user` (slirp) backend can't be serialized by `savevm` (QEMU writes a corrupt section), so `loadvm` fails with `Section footer error` / `Missing section footer for slirp` and does **not** restore — `qmu snapshot load` returns a **non-zero exit code** in this case. Launch with **`--net-backend passt`** (or set `[machine] net_backend = "passt"`) to use [passt](https://passt.top/), a rootless, migration-capable slirp replacement: with it, `save`/`load` round-trip while SSH keeps working. Needs the `passt` binary on PATH (`qmu doctor` checks it; `apt install passt` / `pacman -S passt`).

**Snapshot-rewind loop (with passt) — the fast way to run a crash-prone PoC repeatedly:**
```bash
qmu launch --kernel ./bzImage --net-backend passt --name dev
qmu push exploit /tmp/x
qmu snapshot save clean              # clean pre-PoC state
for i in 1 2 3 4 5; do
  qmu exec /tmp/x                    # run the PoC (may crash/corrupt the kernel)
  qmu log --tail 200 > runs/run-$i.log
  qmu snapshot load clean            # rewind to clean — far faster than a full reboot
done
```
After `snapshot load`, the first SSH command may print a one-off `Broken pipe` on stderr (the pre-snapshot SSH control connection was rewound); the command itself still succeeds. Harness-mode VMs have no qcow2 drive, so `savevm` fails there unless you pass an explicit `--drive`.

**Without passt, iterate by relaunching instead of snapshotting:**
1. `qmu launch --kernel ...`
2. `qmu compile exploit.c --run` (may crash)
3. `qmu crash` (confirm — extraction is best-effort)
4. `qmu kill` then `qmu launch ...` for a fresh known-good VM; edit and repeat from 2.

## Kernel Logs

```bash
qmu dmesg              # full dmesg from guest (via SSH)
qmu dmesg --tail 50
```

## GDB Integration (with pry)

```bash
qmu launch --kernel /path/to/bzImage --gdb
qmu gdb --symbols /path/to/vmlinux         # launches pry connected to the GDB stub
```

**Gotcha — `qmu gdb` halts the vCPU.** Attaching to the QEMU GDB stub halts the guest CPU, so every `qmu exec`/`push`/`pull`/`compile`/`dmesg` fails with a banner/connect timeout (guest-side rc=255 — frozen guest, not a qmu exit code, not a crash). **Resume before SSH commands** with `qmu cont` (or `pry continue`, or `qmu monitor cont`). If `qmu exec` starts timing out right after `qmu gdb`, the guest is almost certainly paused.

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

**Output spilling.** Large outputs (>10k estimated tokens) auto-spill to a file under `$TMPDIR/qmu-spills/` (default `/tmp/qmu-spills/`). **Do not reconstruct the path** — read it from the result envelope's `artifact_path` field or the `[qmu] Output spilled to <path>` stderr line. The envelope's `{"token_estimate": <int>, "estimator": "chars/4"}` is a tokenizer-agnostic heuristic for sizing only.

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
| `<name>.qemu.log`   | QEMU stderr; rarely useful           | Never removed by qmu — delete by hand |

`qmu list` shows running and stopped VMs with a status marker so you can see what's recoverable.

## Known Limitations

- **Snapshots require a qcow2 rootfs AND `--net-backend passt`** — `savevm` needs a writable qcow2 disk (the default `format = "raw"` image cannot store internal snapshots, so `snapshot save` fails), and the default slirp backend can't be serialized (so `loadvm` fails and `snapshot load` returns non-zero). Convert to qcow2 and use passt for a working `save`/`load` loop, or relaunch instead (see Snapshots).
- **Snapshots are ephemeral** — a temporary COW overlay, gone when the VM exits (by design; base image stays clean).
- **`qmu gdb` halts the guest** — resume with `qmu cont` / `pry continue` / `qmu monitor cont` before SSH commands (see GDB Integration).
- **Crash auto-extraction is best-effort** — confirm with `qmu crash` / `qmu log --tail 200` after any suspected panic (see Compile and Run).
- **Serial log is write-only** — no interactive console; use SSH for interactive work.
