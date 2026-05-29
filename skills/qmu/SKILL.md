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

Example `qmu.toml` (this is exactly what `qmu config init` writes, header comments elided):
```toml
[machine]
arch = "x86_64"
# arch = "aarch64"  # set this if cross-emulating
memory = "4G"
cpus = 2
# cpu = "host"                   # passes -cpu to QEMU; "host" is recommended with KVM
# nic_model = "virtio-net-pci"   # or "e1000", "rtl8139", ...
# extra_args = ["-M", "virt", "-cpu", "cortex-a57"]  # for aarch64

[drive]
rootfs = "./rootfs.img"          # CHANGE ME — path to a kernel rootfs image
format = "raw"

[ssh]
key = "~/.ssh/qmu_id_rsa"        # CHANGE ME — private key matching the rootfs
user = "root"
# port_start = 10021

[gdb]
# port_start = 1234

[profiles.exploit-dev]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic"

[profiles.trigger-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_warn=1 kasan.fault=panic"

[profiles.exploit-test]
cmdline = "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 panic_on_oops=1 kasan.fault=panic"
```

The generated file also appends a commented **Harness mode** block (see the Harness section below). The `[ssh] user` field sets the guest login user for `exec`/`push`/`pull`/`compile`; it is recorded on the VM at launch time, so change it before `qmu launch` (default `root`). SSH and GDB port allocation start at `10021` and `1234` respectively (uncomment `port_start` to override).

The `arch` field drives which `qemu-system-*` binary is used and whether KVM is enabled (only when guest arch matches host). Use `extra_args` for arch-specific machine flags. Path values (`rootfs`, `ssh.key`, `--kernel`, `--initrd`) accept `~` expansion.

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
qmu launch --kernel /path/to/bzImage --cpu host                # set QEMU -cpu model (e.g. host, max, qemu64)
```

Advanced boot flags (handy for harness/initrd kernels and custom block/NIC topologies):

```bash
# Boot from kernel + initramfs + an explicit, read-only rootfs drive, no implicit rootfs:
qmu launch --kernel ./bzImage \
  --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu launch --kernel ./bzImage --no-net                         # disable networking entirely (-nic none)
qmu launch --kernel ./bzImage --nic-model e1000                # override NIC model (default: virtio-net-pci)
qmu launch --kernel ./bzImage --drive 'file=a.img,...' --drive 'file=b.img,...'  # repeatable; suppresses the implicit rootfs drive
```

- `--initrd PATH` — attach an initramfs/initrd image (`~` expansion works).
- `--drive SPEC` — raw QEMU `-drive` spec, repeatable. Supplying any `--drive` **suppresses the implicit rootfs drive**, so include the rootfs explicitly if you still need it.
- `--no-net` — boot with `-nic none` (no guest networking; SSH-based commands will not work).
- `--nic-model MODEL` — pick the emulated NIC (`virtio-net-pci`, `e1000`, `rtl8139`, ...).
- `--cpu MODEL` — pass a QEMU `-cpu` model.

Boot profiles:
- `exploit-dev` (default): LSMs disabled, KASAN enabled, no panic_on_warn
- `trigger-test`: adds panic_on_warn=1 — validate bug triggers
- `exploit-test`: adds panic_on_oops=1 — final exploit validation

Rootfs, SSH key, and other settings come from `qmu.toml` config. Override any setting with CLI flags (e.g. `--rootfs`, `--arch`). The drive uses `snapshot=on` so the base image is never modified.

**Auto-replace on launch.** Launching with a `--name` (or the default name) that matches an already-running VM **replaces** it: qmu kills the existing VM first, then boots the new one on the same name. This is the default so a stuck or stale VM never blocks a fresh boot and QEMU processes don't leak across launches. Pass `--no-replace` to instead fail if a VM with that name is already running.

### Multiple VMs

Each VM gets its own SSH port (auto-allocated from 10021+), QMP socket, and serial log. When only one VM is running, commands auto-select it. With multiple VMs, select one with `--vm <id>`.

**Flag placement is flexible.** `--vm`, `--format`, and `--out` are accepted **both before and after** the subcommand. `qmu --vm <id> exec "..."` and `qmu exec --vm <id> "..."` are equivalent (both exit 0). Use whichever reads better; the examples below put them after the subcommand by convention.

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
qmu prune --vm <name> --keep-logs   # Drop .json + .qmp.sock but PRESERVE .serial.log
```

`prune --keep-logs` removes the metadata (`.json`) and dead socket (`.qmp.sock`) while keeping the `.serial.log` on disk, so `qmu crash`/`qmu log` against that log file still work afterward (the VM no longer appears in `qmu list`, since the metadata is gone).

State files persist after a VM exits via the **non-`wait`** paths — `kill --no-clean`, or a harness VM that powered off without `qmu wait` reaping it — and on those paths they are never silently removed: read them with `qmu log --vm <name>` / `qmu crash --vm <name>`, then `qmu prune` when done. The one exception is `qmu wait`, which **auto-cleans** harness VMs by default once they stop (see Harness mode below) — in that case read the crash from `wait`'s own output, or pass `wait --no-clean` to keep the `.serial.log`.

## Harness mode (boot-and-die kernels)

For kernels that boot, run a one-shot init, and halt (kernelCTF judge envs, syzkaller reproducers) there is no SSH and no interactive guest. Launch with `--harness`, then block on `qmu wait`:

```bash
qmu launch --harness \
  --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'

qmu wait                       # block until the VM stops (no timeout by default)
qmu wait --timeout 120         # give up after 120s
qmu wait --no-clean            # keep .serial.log after stop for later qmu crash/qmu log
```

`--harness` implies `--no-wait-ssh` and `--no-net`, and skips the rootfs/SSH-key requirement, so it works with no `[drive]`/`[ssh]` config.

`qmu wait` is the harness/judge primitive. Its exit code and output:
- **Exit 0** — the VM stopped cleanly (powered off / process exited). The result already **carries the crash**: in JSON the `crash` field holds the extracted report (null if none), and text mode prints `Crash from serial log:` followed by it.
- **Exit 124** — the `--timeout` elapsed and the VM is still running.

**`wait` auto-cleans harness VMs by default.** When the VM stops, `wait` removes its metadata (and the `.serial.log`) unless you passed `--no-clean`. Because of this, **read the crash from `wait`'s own output** rather than running `qmu crash` afterward — the log may already be gone. Pass `--no-clean` if you need the `.serial.log` to survive for a later `qmu crash`/`qmu log`. (Non-harness VMs are never auto-cleaned by `wait`.)

## File Transfer

```bash
qmu push exploit.c                          # Push to /root/ in guest
qmu push exploit.c /tmp/exploit.c           # Push to specific path
qmu pull /root/output.txt                   # Pull to current directory
qmu pull /root/output.txt ./results/        # Pull to specific local path
```

### Offline rootfs editing (no running VM, via libguestfs)

When you need to bake files into a rootfs image **before** boot (e.g. harness rootfs that has no SSH), or inspect one without booting, use `qmu rootfs`. These operate on the image file directly and need no running VM:

```bash
# Copy local files/dirs into the image. Each pair is LOCAL:GUEST where GUEST is a directory:
qmu rootfs inject ./rootfs.img ./exploit:/root ./run.sh:/
qmu rootfs inject ./rootfs.img ./exploit:/root --partition 0   # whole-disk image (no partition table)

# Drop into an interactive guestfish shell on the image:
qmu rootfs shell ./rootfs.img
```

`inject` takes the image path, then one or more `LOCAL:GUEST` pairs (`GUEST` must be an existing directory in the image). `--partition N` selects the partition (default `1`; use `0` for a whole-disk/partitionless image). Both require libguestfs (`guestfish`) on the host.

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
because sshd is frozen (the guest-side SSH return code is 255 — this is the frozen guest, not a qmu exit
code, and not a kernel crash). **Resume the guest before running SSH-based commands** with
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

All commands support `--format text|json|ndjson` (accepted both before and after the subcommand, like `--vm`):

```bash
qmu status --format json          # Machine-readable status
qmu exec "uname -a" --format json # Structured output with exit code
qmu list --format json            # List as JSON array
```

**Universal result contract.** Under `--format json` (or `ndjson`), **every** command emits a JSON object with an `"ok": <bool>` field — both on success and on every error path. Check `ok` for a single, command-agnostic success predicate; the exit code (see below) tells you *how* it failed. Errors emit `{"ok": false, "error": "<message>", "error_type": "<ExceptionClassName>"}` to stdout. In text mode, errors instead print `[qmu] Error: ...` to stderr.

### Exit codes

Every command follows one exit-code map. Use the code (not log scraping) to branch:

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Operation failed — guest command returned non-zero, `doctor` unhealthy, or a snapshot op failed |
| `2`  | Usage / argument-parse error, or a runtime `QMUError`/`QMPError`/`SSHError` (e.g. no running VM, bad `--vm`, SSH/SCP failure, QMP error) |
| `3`  | Guest kernel crash, or SSH transport loss (the connection dropped under a panic) |
| `4`  | Internal/unexpected qmu error — the `main()` catch-all and infra-subprocess failures (e.g. a `pry`/`gdb` subprocess hang) |
| `124`| `qmu wait` timed out (`--timeout` elapsed, VM still running) |

Exit `3` specifically signals a guest-side crash/transport loss; an internal qmu fault (a hung helper subprocess, an unexpected exception) is `4`, so a tooling bug is never mistaken for a kernel panic.

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

| File                  | Purpose                                     | Removed by                                                                 |
|-----------------------|---------------------------------------------|----------------------------------------------------------------------------|
| `<name>.json`         | VM metadata (pid, ports, kernel, etc.)      | `kill`, `prune`, `prune --keep-logs`, and `wait`'s harness auto-clean       |
| `<name>.serial.log`   | Serial console output (read with `qmu log`) | `kill`, `prune`, and `wait`'s harness auto-clean — but **kept** by `kill --no-clean`, `prune --keep-logs`, and `wait --no-clean` |
| `<name>.qmp.sock`     | QMP control socket                          | `kill`, `prune`, `prune --keep-logs`, and `wait`'s harness auto-clean       |
| `<name>.qemu.log`     | QEMU's stderr; rarely useful                | Never removed by qmu — neither `kill` nor `prune` touch it; delete it by hand if needed |

Outside `wait`'s default harness auto-clean (see Harness mode), state files are **never silently removed**: after a harness VM powers off without `wait`, or after `kill --no-clean`, the `.serial.log` stays on disk and `qmu log --vm <name>` / `qmu crash --vm <name>` work. Clean up explicitly with `qmu prune --vm <name>` (or `qmu prune --all`), or `qmu prune --vm <name> --keep-logs` to drop metadata while keeping the serial log. `qmu list` shows both running and stopped VMs with a status marker so you can see what's recoverable.

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
