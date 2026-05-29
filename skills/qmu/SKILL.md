---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

Use this skill when the user wants to boot, manage, or interact with QEMU VMs for kernel security research. The tool provides structured JSON or text output and handles the common pain points of QEMU-based kernel exploit development.

## Configuration

qmu uses TOML config files for machine settings (arch, rootfs, SSH key, profiles). Resolution order (later wins):

1. **Built-in defaults** — arch=x86_64, memory=4G, cpus=2
2. **Global config** — `~/.config/qmu/config.toml`
3. **Project config** — `qmu.toml` found by walking up from CWD
4. **CLI flags** — `--rootfs`, `--memory`, `--arch`, etc.

```bash
qmu config show         # Show resolved config and sources
qmu config init         # Create starter qmu.toml in current directory
qmu config path         # Show config file search paths
```

Example `qmu.toml`:
```toml
[machine]
arch = "x86_64"         # determines qemu-system-{arch} binary
memory = "4G"
cpus = 2
# extra_args = ["-M", "virt", "-cpu", "cortex-a57"]  # for aarch64

[drive]
rootfs = "/path/to/rootfs.img"
format = "raw"

[ssh]
key = "/path/to/ssh.id_rsa"
user = "root"           # SSH login user — honored by exec/push/pull (default: root)
port_start = 10021

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda selinux=0 apparmor=0 kasan.fault=panic"
```

The `arch` field drives which `qemu-system-*` binary is used and whether KVM is enabled (only when guest arch matches host). Use `extra_args` for arch-specific machine flags. The `[ssh] user` field sets the guest login user for `exec`/`push`/`pull`/`compile`; it is recorded on the VM at launch time, so change it before `qmu launch` (default `root`).

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage       # Boot a VM (defaults: 4G RAM, 2 CPUs, exploit-dev profile)
qmu doctor                                  # Verify everything is healthy
qmu exec "uname -a"                        # Run a command in the guest
qmu compile exploit.c --run                 # Push, compile, and run C code in guest
qmu crash                                   # Extract crash report (works even when SSH is dead)
qmu kill                                    # Stop the VM
```

## VM Lifecycle

### Launching a VM

```bash
qmu launch --kernel kernels/linux-v6.6.75/arch/x86/boot/bzImage
qmu launch --kernel /path/to/bzImage --profile trigger-test    # panic_on_warn=1
qmu launch --kernel /path/to/bzImage --gdb                     # Enable GDB stub
qmu launch --kernel /path/to/bzImage --name myvm --memory 8G --cpus 4
qmu launch --kernel /path/to/bzImage --cmdline "console=ttyS0 root=/dev/sda custom=1"
```

Boot profiles:
- `exploit-dev` (default): LSMs disabled, KASAN enabled, no panic_on_warn
- `trigger-test`: adds panic_on_warn=1 — validate bug triggers
- `exploit-test`: adds panic_on_oops=1 — final exploit validation

Rootfs, SSH key, and other settings come from `qmu.toml` config. Override any setting with CLI flags (e.g. `--rootfs`, `--arch`). The drive uses `snapshot=on` so the base image is never modified.

### Multiple VMs

Each VM gets its own SSH port (auto-allocated from 10021+), QMP socket, and serial log. When only one VM is running, commands auto-select it. With multiple VMs, select one with `--vm <id>`.

**Important — flag placement matters.** `--vm` (like `--format` and `--out`) is a per-subcommand flag. It must appear **after** the subcommand, not before it. `qmu --vm <id> exec ...` is rejected by argparse (`error: argument subcommand: invalid choice: '<id>'`, exit 2). Always put `--vm`/`--format`/`--out` after the subcommand name.

```bash
qmu launch --kernel /path/to/bzImage-kasan --name kasan-vm
qmu launch --kernel /path/to/bzImage-nokasan --name exploit-vm
qmu exec --vm kasan-vm "uname -r"
qmu compile --vm exploit-vm exploit.c --run
qmu kill --vm kasan-vm
```

### Other lifecycle commands

```bash
qmu list                # List all running VMs with SSH/GDB port info
qmu status              # Detailed status (QMP state, SSH, kernel cmdline, etc.)
qmu kill                # Graceful shutdown via QMP, falls back to SIGTERM
qmu kill --force        # SIGKILL
```

## File Transfer

```bash
qmu push exploit.c                          # Push to /root/ in guest
qmu push exploit.c /tmp/exploit.c           # Push to specific path
qmu pull /root/output.txt                   # Pull to current directory
qmu pull /root/output.txt ./results/        # Pull to specific local path
```

## Guest Execution

```bash
qmu exec "uname -a"
qmu exec "dmesg | tail -50"
qmu exec "cat /proc/slabinfo | grep kmalloc-192"
qmu exec "./exploit" --timeout 120          # Long-running with custom timeout
```

If a command crashes the kernel and SSH dies, qmu makes a **best-effort** attempt to extract the crash report from the serial log and include it in the output. This auto-extraction fires both when the command exceeds qmu's `--timeout` and when the SSH connection is torn down (rc=255) by a panic. It is best-effort only: after **any** suspected panic — including a bare `[exit code: 255]` — always run `qmu crash` (and `qmu log --tail 200`) to confirm. Do not rely solely on the exit code to detect a crash.

## Compile and Run

The `compile` command is the primary exploit development workflow — it pushes a C file, compiles it in the guest, and optionally runs it:

```bash
qmu compile exploit.c                       # Push + compile only
qmu compile exploit.c --run                 # Push + compile + execute
qmu compile exploit.c --run --timeout 120   # With custom execution timeout
qmu compile exploit.c --cflags "-static -lpthread -DDEBUG"   # Custom compiler flags
```

Default CFLAGS: `-static -lpthread`

If the exploit crashes the kernel during `--run`, qmu makes a best-effort attempt to extract the crash report from the serial log. As with `exec`, always run `qmu crash` after any suspected panic to confirm — do not trust the exit code alone.

## Crash Extraction

The most important feature for kernel exploit development — works even when SSH is dead:

```bash
qmu crash              # Extract last KASAN/BUG/Oops/panic from serial log
qmu log --tail 100     # View last 100 lines of serial console
qmu log --tail 500     # More context
```

Detected crash patterns: KASAN reports, BUG/Oops, kernel panic, general protection fault, UBSAN, slab-use-after-free, and more. If `qmu crash` reports nothing but you suspect a panic, fall back to `qmu log --tail 200` to read the raw serial log directly.

## Snapshots

Save and restore VM state within a session. Snapshots are ephemeral (lost when the VM exits):

```bash
qmu snapshot save clean        # Save VM state
qmu snapshot list              # List saved snapshots
qmu snapshot load clean        # Restore a saved state
qmu snapshot delete clean      # Remove a snapshot
```

**Limitation — snapshot load is incompatible with the default networking.** qmu's default `-net user`
(slirp) backend cannot be serialized by `savevm`, so `savevm` prints slirp warnings and `loadvm`
typically fails with `Section footer error` / `Missing section footer for slirp` and does **not** restore
the VM (SSH stays dead afterward). `qmu snapshot load` now returns a **non-zero exit code** and a stderr
message when `loadvm` reports such an error — check the exit code, do not assume success. For reliable
crash iteration with the default networking, prefer **relaunching** the VM over snapshot restore.

Recommended iteration loop (relaunch-based, robust):
1. `qmu launch --kernel ...`
2. `qmu compile exploit.c --run` — may crash the kernel
3. `qmu crash` — read the crash (always confirm; auto-extraction is best-effort)
4. `qmu kill` then `qmu launch --kernel ...` — fresh known-good VM
5. Edit the exploit, repeat from step 2

(If you have configured a snapshot-compatible NIC via `extra_args`, the `snapshot save`/`snapshot load`
loop can replace step 4 — but verify `qmu exec` works after `snapshot load`, and always check the exit
code of `snapshot load`, before relying on it.)

## Kernel Logs

```bash
qmu dmesg                  # Full dmesg from guest (via SSH)
qmu dmesg --tail 50        # Last 50 lines of dmesg
```

## GDB Integration (with pry)

Launch a VM with GDB stub enabled, then connect pry:

```bash
qmu launch --kernel /path/to/bzImage --gdb
qmu gdb --symbols /path/to/vmlinux         # Launches pry connected to GDB stub
```

**Gotcha — `qmu gdb` halts the vCPU.** Attaching to the QEMU GDB stub halts the guest CPU. While the CPU
is halted, every `qmu exec`/`push`/`pull`/`compile`/`dmesg` will fail with a banner/connect timeout
(exit 255) because sshd is frozen. **Resume the guest before running SSH-based commands** with
`qmu cont` (or `pry continue`, or `qmu monitor cont`). If `qmu exec` starts timing out right after
`qmu gdb`, the guest is almost certainly paused — resume it first.

Now use pry commands for kernel debugging:
```bash
pry break set commit_creds
pry continue                # REQUIRED to resume the halted guest before the parallel exec below
# In parallel: qmu exec "./exploit"
pry backtrace
pry print current_cred
```

## Raw QEMU Access

Escape hatches for direct QEMU control:

```bash
qmu qmp query-status                       # Raw QMP command
qmu qmp query-block                        # Query block devices
qmu monitor "info registers"               # HMP command via QMP
qmu monitor "info mem"                     # Memory mappings
qmu monitor "x /16xg 0xffffffff81000000"   # Examine memory
qmu monitor "cont"                         # Resume a paused/halted guest (e.g. after qmu gdb)
```

## Output Formats

All commands support `--format text|json|ndjson` (placed **after** the subcommand, like `--vm`):

```bash
qmu status --format json          # Machine-readable status
qmu exec "uname -a" --format json # Structured output with exit code
qmu list --format json            # List as JSON array
```

Large outputs (>10k estimated tokens) are automatically spilled to a file under `$TMPDIR/qmu-spills/`
(default `/tmp/qmu-spills/` when `TMPDIR` is unset) to prevent context overflow. **Do not hardcode or
reconstruct the spill directory** — the exact file path is always reported in the result envelope's
`artifact_path` field and on the `[qmu] Output spilled to <path>` stderr line. Read it from there.

The spill envelope reports `{"token_estimate": <int>, "estimator": "chars/4"}` — the token figure is a
tokenizer-agnostic chars-per-token heuristic, not an authoritative model token count. Treat it as an
approximation for sizing only.

## Health Check

```bash
qmu doctor      # Checks: QEMU binary, rootfs, SSH key, KVM, pry, running VMs, skill
```

`pry` is reported as an informational check (it is only required for `qmu gdb`); a missing `pry` does not
fail the overall health check.

## Known Limitations

- **Snapshot load is incompatible with the default networking**: with `-net user` (slirp),
  `savevm`/`loadvm` cannot serialize NIC state; `loadvm` fails (`Section footer error` /
  `Missing section footer for slirp`) and does not restore the VM. `qmu snapshot load` returns a non-zero
  exit code and a stderr message in this case. Prefer relaunching the VM for crash iteration (see
  Snapshots), or configure a migratable NIC via `extra_args`.
- **Snapshots are ephemeral**: `savevm`/`loadvm` use a temporary COW overlay. Snapshots disappear when the
  VM exits. This is by design — the base image stays clean.
- **`qmu gdb` halts the guest**: attaching the debugger pauses the vCPU; resume with `qmu cont` /
  `pry continue` / `qmu monitor cont` before running SSH-based commands.
- **Crash auto-extraction is best-effort**: it fires when a command exceeds `--timeout`, or returns
  rc=255 and a liveness probe finds SSH no longer reachable (a genuine guest exit 255 with the VM still
  up is left as a normal result). Always confirm with `qmu crash` / `qmu log --tail 200` after a suspected panic.
- **Serial log is write-only**: The serial console is captured to a log file. There is no interactive
  console mode — use SSH for interactive work.
