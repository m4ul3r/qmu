---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

Use this skill when the user wants to boot, manage, or interact with QEMU VMs for kernel security research. The tool provides structured JSON or text output and handles the common pain points of QEMU-based kernel exploit development.

## Bootstrapping a new instance

A fresh project has no `qmu.toml`. Drive every new setup through these steps — do not hand-write a config from scratch.

1. **`qmu doctor`** — surfaces what's missing. If no config file is found, it prints `Tip: run 'qmu config init' ...`.
2. **`qmu config init`** — drops a starter `qmu.toml` in the current directory. The template is host-arch aware and contains two `# CHANGE ME` lines.
3. **Edit the two `# CHANGE ME` lines**:
   - `[drive] rootfs` → path to a kernel rootfs image (relative, absolute, or `~`-prefixed all work).
   - `[ssh] key` → private key matching the keys baked into the rootfs.
4. **`qmu doctor`** again — confirm `rootfs image`, `SSH key`, and `SSH key permissions` all show `[+]`. Fix any `[!]` before launching.
5. **For boot-and-die kernels** (kernelCTF judge envs, syzkaller reproducers): skip steps 3 — leave `[drive]` / `[ssh]` blank in the template (or delete them) and launch with `qmu launch --harness ...`. See the harness-mode block at the bottom of the generated `qmu.toml` for the exact invocation.

Project-local config (`./qmu.toml`) is right for per-project rootfs/kernel paths. Per-user defaults that apply across projects (e.g., your SSH key) belong in `~/.config/qmu/config.toml`.

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

Example `qmu.toml` (matches what `qmu config init` writes):
```toml
[machine]
arch = "x86_64"                  # determines qemu-system-{arch} binary
memory = "4G"
cpus = 2
# cpu = "host"                   # passes -cpu to QEMU; "host" is recommended with KVM
# extra_args = ["-M", "virt", "-cpu", "cortex-a57"]  # for aarch64

[drive]
rootfs = "./rootfs.img"          # CHANGE ME
format = "raw"

[ssh]
key = "~/.ssh/qmu_id_rsa"        # CHANGE ME — `~` expansion works
user = "root"                    # SSH login user — honored by exec/push/pull (default: root)
port_start = 10021

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda selinux=0 apparmor=0 kasan.fault=panic"
```

The `arch` field drives which `qemu-system-*` binary is used and whether KVM is enabled (only when guest arch matches host). Use `extra_args` for arch-specific machine flags. Path values (`rootfs`, `ssh.key`, `--kernel`, `--initrd`) accept `~` expansion. The `[ssh] user` field sets the guest login user for `exec`/`push`/`pull`/`compile`; it is recorded on the VM at launch time, so change it before `qmu launch` (default `root`).

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
qmu list                # List VMs (running and stopped) with status markers
qmu status              # Detailed status (QMP state, SSH, kernel cmdline, etc.)
qmu kill                # Graceful shutdown via QMP, falls back to SIGTERM
qmu kill --force        # SIGKILL
qmu kill --no-clean     # Stop the process but keep .serial.log + .json for forensics
qmu prune --vm <name>   # Remove a stopped VM's state files
qmu prune --all         # Remove every stopped VM's state files
```

State files persist after a VM exits (e.g. harness boot-and-die, or `kill --no-clean`) — they're never silently removed. Read them with `qmu log --vm <name>` / `qmu crash --vm <name>`, then `qmu prune` when done.

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

The most important feature for kernel exploit development — works even when SSH is dead, and works **after** a VM has exited (state files survive until you prune them):

```bash
qmu crash                       # Extract last KASAN/BUG/Oops/panic from serial log
qmu log --tail 100              # View last 100 lines of serial console
qmu log --tail 500              # More context
qmu crash --vm run-3            # Works on a stopped VM too — no need for it to be running
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

### Snapshot loop for repeated runs

When you need to run an exploit many times to measure reliability, rewinding via `loadvm` is much faster than rebooting the kernel each time:

```bash
qmu launch --kernel ./bzImage --name dev
qmu push exploit /tmp/x
qmu snapshot save clean

for i in 1 2 3 4 5; do
  qmu snapshot load clean         # rewinds kernel + FS overlay
  qmu exec '/tmp/x'
  qmu log --tail 200 > runs/run-$i.log
done
```

This only works for exploit-dev VMs (rootfs-backed, mounted with `snapshot=on`). Harness-mode VMs have no qcow2 drive, so `savevm` fails — pass an explicit `--drive` if you need snapshots there.

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
qmu doctor      # Checks: config sources, QEMU binary, rootfs, SSH key + perms, KVM, pry, running VMs, skill
```

If no config file is found, doctor prints `Tip: run 'qmu config init' ...` and exits non-zero. SSH key existence and permissions are reported as separate checks. `pry` is reported as an informational check (only required for `qmu gdb`); a missing `pry` does not fail the overall health check.

## Files on disk

Each VM keeps its state files under `~/.cache/qmu/instances/` (or `$QMU_CACHE_DIR`):

| File                  | Purpose                                   | Lifetime                                   |
|-----------------------|-------------------------------------------|--------------------------------------------|
| `<name>.json`         | VM metadata (pid, ports, kernel, etc.)    | Until `qmu kill` or `qmu prune`            |
| `<name>.serial.log`   | Serial console output (read with `qmu log`) | Until `qmu kill` or `qmu prune`          |
| `<name>.qmp.sock`     | QMP control socket                         | Only meaningful while VM is running        |
| `<name>.qemu.log`     | QEMU's stderr; rarely useful              | Until `qmu prune`                          |

These files are **never silently removed**. After a harness VM powers off (or you call `kill --no-clean`), the `.serial.log` stays on disk and `qmu log --vm <name>` / `qmu crash --vm <name>` work. Use `qmu prune --vm <name>` (or `qmu prune --all`) to clean up explicitly. `qmu list` shows both running and stopped VMs with a status marker so you can see what's recoverable.

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
