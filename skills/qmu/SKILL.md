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
user = "root"
port_start = 10021

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda selinux=0 apparmor=0 kasan.fault=panic"
```

The `arch` field drives which `qemu-system-*` binary is used and whether KVM is enabled (only when guest arch matches host). Use `extra_args` for arch-specific machine flags.

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage       # Boot a VM (defaults: 4G RAM, 2 CPUs, exploit-dev profile)
qmu doctor                                  # Verify everything is healthy
qmu exec "uname -a"                        # Run a command in the guest
qmu compile exploit.c --run                 # Push, compile, and run C code in guest
qmu crash                                   # Extract crash report (works even when SSH is dead)
qmu snapshot save clean                     # Save VM state
qmu snapshot load clean                     # Restore VM state
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

Each VM gets its own SSH port (auto-allocated from 10021+), QMP socket, and serial log. When only one VM is running, commands auto-select it. With multiple VMs, use `--vm <id>`:

```bash
qmu launch --kernel /path/to/bzImage-kasan --name kasan-vm
qmu launch --kernel /path/to/bzImage-nokasan --name exploit-vm
qmu --vm kasan-vm exec "uname -r"
qmu --vm exploit-vm compile exploit.c --run
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

If SSH dies during execution (kernel crash), qmu automatically extracts the crash report from the serial log and includes it in the output.

## Compile and Run

The `compile` command is the primary exploit development workflow — it pushes a C file, compiles it in the guest, and optionally runs it:

```bash
qmu compile exploit.c                       # Push + compile only
qmu compile exploit.c --run                 # Push + compile + execute
qmu compile exploit.c --run --timeout 120   # With custom execution timeout
qmu compile exploit.c --cflags "-static -lpthread -DDEBUG"   # Custom compiler flags
```

Default CFLAGS: `-static -lpthread`

If the exploit crashes the kernel during `--run`, the crash report is automatically extracted from the serial log.

## Crash Extraction

The most important feature for kernel exploit development — works even when SSH is dead:

```bash
qmu crash              # Extract last KASAN/BUG/Oops/panic from serial log
qmu log --tail 100     # View last 100 lines of serial console
qmu log --tail 500     # More context
```

Detected crash patterns: KASAN reports, BUG/Oops, kernel panic, general protection fault, UBSAN, slab-use-after-free, and more.

## Snapshots

Save and restore VM state within a session. Snapshots are ephemeral (lost when VM exits) but ideal for exploit iteration:

```bash
qmu snapshot save clean        # Save after boot, before exploit
qmu snapshot list              # List saved snapshots
qmu snapshot load clean        # Restore to known-good state after crash
qmu snapshot delete clean      # Remove a snapshot
```

Typical workflow:
1. `qmu launch --kernel ...`
2. `qmu snapshot save clean`
3. `qmu compile exploit.c --run` — crashes kernel
4. `qmu crash` — read the crash
5. `qmu snapshot load clean` — restore, SSH comes back
6. Edit exploit, repeat from step 3

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

Now use pry commands for kernel debugging:
```bash
pry break set commit_creds
pry continue
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
```

## Output Formats

All commands support `--format text|json|ndjson`:

```bash
qmu status --format json          # Machine-readable status
qmu exec "uname -a" --format json # Structured output with exit code
qmu list --format json            # List as JSON array
```

Large outputs (>10k tokens) are automatically spilled to `/tmp/qmu-spills/` to prevent context overflow.

## Health Check

```bash
qmu doctor      # Checks: QEMU binary, rootfs, SSH key, KVM, running VMs, skill
```

## Known Limitations

- **Snapshots are ephemeral**: `savevm`/`loadvm` use a temporary COW overlay. Snapshots disappear when the VM exits. This is by design — the base image stays clean.
- **SSH may be slow after snapshot load**: The guest's network stack needs a moment to recover. If `qmu exec` fails immediately after `qmu snapshot load`, wait 1-2 seconds and retry.
- **Serial log is write-only**: The serial console is captured to a log file. There is no interactive console mode — use SSH for interactive work.
