---
name: firmware-over-qmu
description: Boot an extracted Linux firmware's own filesystem under qmu (full-system QEMU) to dynamically audit its userland binaries — kernel selection, rootfs repack, and injecting verified-compatible SSH/gdbserver so qmu exec/push/pull work. Use for firmware RE/vuln-research on ARM/x86 Linux embedded images (head units, routers, IoT) where you want to run/debug the real binaries, not just static-RE them.
---

# firmware-over-qmu

Use this when you have an **extracted, mountable Linux firmware rootfs** and need
to run its original userland under qmu. A generic kernel provides a useful
boot/access lane, not board emulation: a vendor kernel targeting absent SoC
devices generally cannot boot on QEMU `virt`. Do not promise an unavailable
board model or silently replace a convergence request with shell access.

## Goal and fidelity boundary

Agree the goal and benign completion operation at intake:

| Lane | Evidence required | Limit |
|---|---|---|
| Original-userland access | Boot evidence and an actual host-side SSH connection | Access only; not vendor service readiness |
| Isolated component experiment | Identified component/input/helper and an observed benign operation, with all substitutes declared | Scoped to the experiment, not the original provider or full system |
| Relevant vendor init/service convergence | Relevant original activation/decision path, service readiness, and the agreed benign exchange from a clean VM | Missing hardware dependencies may block this goal; generic-kernel access does not complete it |

For a convergence request, the third lane remains the main completion contract.
Original-system ground truth is often unavailable. Even a converged emulation
does not independently establish hardware equivalence.
If no exact benign exchange or original readiness producer with verified success
semantics is known, mark convergence intake **incomplete**. Do not substitute an
arbitrary marker, process presence or SSH handshake.
An original-init diagnostic run can locate a blocker without being a test of an
undefined vendor operation.


A different firmware starts a new evidence scope. Re-identify its boot chain,
partitions, ABI, helpers and benign completion operation; do not inherit another
target's device aliases, init adapters, provider models or approvals. Preserve
prior run scripts, manifests and receipts as historical evidence rather than
editing them into the new recipe. Build the current recipe from the identified
inputs and current worktree, using qmu's normal private-runtime setup instead
of a target-specific transport workaround.

**Baseline adaptations need explicit user approval at intake, or before later
promotion.** A missing dependency names a blocker; it does not authorize
manufacturing a successful response. Models, callback stubs, and synthetic peers
may support separate, explicitly limited experiments. A hardware-facing model
may join the main baseline only after explicit approval; approval authorizes an
adaptation, not a claim that it matches unobserved hardware. Keep a blocked main
goal separate from a passed isolated experiment.

Apply qmu's **Evidence and handoff contract** (`read
skill://qmu/reference/evidence-contract.md`): identify artifacts by revision or
digest, keep writable worker state private, use unique VM names with
`--no-replace` and explicit `--vm`, and preserve a discoverable same-host recipe
and linked receipts. Report milestone/state/strongest observation/substitutions
and limits/receipt/next distinguishing check or blocker. Routine repairs are
autonomous; interrupt only for changes to the proof question, relevant original
behavior, destructive/shared state, or user-only prerequisites. Another attempt
must name its hypothesis, changed variable, and distinguishing observation;
stop the blocked lane when no such observation is available.

Before an emulation milestone or handoff is complete, a fresh independent agent
must review its exact scope/evidence and reproduce the benign operation from a
clean VM. A warm-only result is scoped evidence, not reproducible completion.
Missing exercise markers, failed observation channels, collisions, or stale
artifact identity make a run invalid/inconclusive, not negative. Changed scope
or bound evidence invalidates approval and requires renewed review/reproduction;
preserve limitations and corrections through handoff.

## The method (six phases)

### 1. Identify the target (decides everything downstream)
Mount the firmware read-only, then from the rootfs:
```bash
file <mnt>/sbin/init                 # arch (aarch64 / x86-64 / arm / ...) + interpreter
readlink <mnt>/lib*/ld-*.so*         # version clue, not compatibility proof; inspect the actual libc too
ls <mnt>/boot <mnt>/lib/modules      # kernel version (also: strings <Image> | grep 'Linux version')
ls <mnt>/lib/systemd/systemd \
   <mnt>/etc/init.d <mnt>/etc/inittab  # relevant activation graph for convergence
find <mnt> -iname 'sshd' -o -iname 'dropbear*'  # is there already an SSH server? (usually not)
```
Record **arch/ELF ABI**, **libc/loader identity**, **kernel version/config**, and
**rootfs partition**. Inventory the original boot image and initramfs (including
early `/init`), additional partition/device-to-mount mappings, symlink targets,
early proc/sys/dev/tmpfs mounts, root transition, kernel arguments, and the
vendor init/service chain. Preserve identified originals read-only. For a
convergence baseline, carry required original initramfs through `[boot] initrd`
and account for every early-boot dependency; direct `init=/sbin/init` may skip
essential preparation. The shell-init access lane deliberately bypasses this
chain and must say so.

Check for an embedded kernel config (`IKCFG_ST`); module inventories are clues,
not a complete reconstruction of build options or vendor behavior.

### 2. Build a generic kernel for QEMU `virt`/`q35`
Use the qmu-linux-kbuild skill. The firmware's **major.minor** is a starting
point, not a userspace/vendor-module compatibility guarantee. Build a generic
(not vendor-SoC) config and verify the required features rather than assuming
defconfig supplies them:
```bash
tools/kbuild.sh --version <maj.min.patch> --arch <arm64|x86_64|...>
```
Required built-in (verify in the produced `.config`, must be `=y` not `=m`, since your custom
modules aren't installed in the image): `EXT4_FS`, `VIRTIO_BLK`, `VIRTIO_NET`, `VIRTIO_PCI`,
`PCI_HOST_GENERIC` (arm64), `DEVTMPFS`+`_MOUNT`, serial console (`SERIAL_AMBA_PL011_CONSOLE`
on arm64 / `SERIAL_8250_CONSOLE` on x86), `UNIX98_PTYS`, `BINFMT_ELF`.
Follow the kernel skill for current build/helper handling. Record the builder
result and artifact/config identities; kernel compilation alone does not prove
that the complete requested build succeeded.

### 3. Repack the rootfs (no loopback, golden image untouched)
```bash
sudo mke2fs -q -t ext4 -L fwroot -d <mnt> -O ^has_journal -F fw-root.img 4G
sudo e2fsck -fn fw-root.img            # sanity
```
`-d` populates ext4 directly from the read-only mount, preserving ownership/perms/symlinks —
no root mount of the source needed. Size it a bit above the used space (headroom for writes).

### 4. Inject the interaction layer (this is the non-obvious part)
Firmware may lack both SSH and a usable shell. qmu's serial is log-only, so
inventory prerequisites **offline before injection**, using file/shebang/ELF
interpreter and dependency inspection rather than executing foreign binaries
on the host:

| Consumer | Required inventory |
|---|---|
| Both templates | Executable `/bin/bash` (their shebang requires Bash, not just a BusyBox `sh`), its loader/shared libraries, `mount`, and `sleep` |
| Probe template | `uname`, `sed`, `ldd`, `sync`, `poweroff`, `halt`; representative target and its dependency closure |
| Network template | `mkdir`, `chmod`, `ip` supporting the shown link/address/route/query options, and `dropbear` |
| SSH commands/transfers | `/bin/sh`, the account's configured login shell, `dropbearkey`, `sftp-server` at Dropbear's compiled path, their ELF loaders/libraries, and utilities used by the intended benign command |
| Dependency inspection/debugging | `ldd` itself may be a script: inspect its shebang, interpreter, helper commands and loader paths; inspect `gdbserver` dependencies separately |

Check executable modes, symlink destinations, mountpoints and command lookup
under each template's actual `PATH`/library path. The probe does not include
`/opt/qmu-tools/bin` in `PATH`. Missing access prerequisites require real,
identified compatible additions in the private access image, not success stubs
or replacements for original service providers. Do not overwrite vendor libc.

**Matching a libc version is neither required nor sufficient.** Check machine,
ELF class/ABI, interpreter path, required symbol versions and transitive
libraries, then verify actual execution in the isolated guest. Older-ABI helpers
may work with newer libc. Equal version labels alone also do not establish
compatibility.
Ubuntu releases are candidate sources (bionic 2.27, focal 2.31, jammy 2.35,
noble 2.39); verify the fetched artifacts, not just the release name.

The fetcher requires Docker and target-architecture execution support (binfmt
for cross-architecture containers). Use an **absolute output path**, because it
is passed directly as a Docker bind source:
```bash
skills/firmware-over-qmu/fetch-hosttools.sh --arch <arm64|amd64|arm/v7> \
   --release <bionic|focal|jammy|noble> --out "$PWD/fw-tools"
```
It fetches `dropbear`, `dropbearkey`, `gdbserver`, `sftp-server` and selected
non-glibc libraries, **not shells or application utilities**; its library filter
is not a complete compatibility check. Source any missing prerequisites
separately, record their provenance, and verify required symbols even when a
same-named library already exists. Keep helper libraries scoped to the access
tools rather than globally replacing vendor libraries.
Inject offline into the private image with `debugfs`:
```bash
# fw-tools -> /opt/qmu-tools/{bin,lib}; sftp-server -> its verified compiled path
# pubkey -> <account-home>/.ssh/authorized_keys; init -> /qmu-net-init.sh
sudo debugfs -w -f inject.cmds fw-root.img      # write ...; then: sif <path> mode 0100755
```
Do not trust `debugfs` exit status alone: inode commands can print errors while
returning zero. Before publishing a usable image or preparation success, inspect
diagnostics and verify the actual image: dump each injected regular file and
compare its hash, type, mode and uid/gid; check required directories, account
permissions and symlink destinations. Inventory directories before `mkdir`.
Retain failed staged images and raw receipts; never launch them as successful
preparations or overwrite the original image to repair an injection mistake.

Read the account home and login shell from `/etc/passwd`. For key authentication,
the home, `.ssh`, and `authorized_keys` must have acceptable ownership (account
or root) and not be group/other-writable: typically home `0700` or `0755`,
`.ssh` `0700`, key file `0600`. A home at `0775` can be rejected even with correct
key-file modes. Check parent-directory safety and daemon diagnostics too.
Repair only the selected account paths in the isolated access image; never
blanket-chmod the original rootfs or silently promote permission changes.

Classify each injected change: **boot/access adapters** (shell init, SSH tools,
mount preparation), **synthetic peers** (modeled counterparts),
**instrumentation** (observation changes), or **behavior-changing replacements**
(including successful callback stubs). Record limits even for adapters and
instrumentation; they can affect timing or activation. Preserve the relevant
original decision path for convergence, rather than bypassing its unmet
dependencies. A unit file being present, a unit being enabled, a running process,
service readiness, and a successful benign exchange are distinct evidence levels.

Templates: `templates/qmu-net-init.sh` configures networking then attempts
foreground dropbear; `templates/qmu-probe-init.sh` inspects dependency resolution.
Copy, replace the probe's synthetic `/usr/lib/libexample.so` with an identified
library or binary, adjust other firmware-specific paths, and inject. Both bypass
vendor init: they provide intermediate evidence, not vendor init/service convergence.
The templates require Bash. If a private adapter instead uses BusyBox ash,
`exec daemon; fail` does not preserve PID1 when execution fails. Keep ash as PID1,
start the foreground-mode daemon as a child, wait for it, and park with its exit
status on failure. Exercise that failure path with the actual guest shell.


### 5. Boot
qmu is x86-defaulted; for other arches you MUST supply the machine + an aarch64/arm cmdline.
Start with `qmu config init` as described in the qmu skill, then set the common
boot inputs in `qmu.toml` **before the first launch**:
```toml
[boot]
kernel = "Image"
[drive]
rootfs = "fw-root.img"
format = "raw"
[machine]
arch = "aarch64"                    # picks qemu-system-aarch64
memory = "2G"
cpu = "cortex-a57"                  # example QEMU-supported CPU, not SoC equivalence
extra_args = ["-M", "virt"]         # aarch64 has no default machine — REQUIRED
[ssh]
key  = "/abs/path/fw_id_ecdsa"      # see gotcha on key type
user = "root"
```
Kernel and supplied initrd paths must be regular files. Omit the initrd key when
the lane intentionally has none; `initrd = ""` is not an omission. Failed QMP
startup reports include a bounded final QEMU-output tail before transient launch
artifacts are removed; preserve the command's error receipt for diagnosis.

```bash
# dependency inspection first (non-interactive, read serial):
qmu launch --harness \
  --cmdline 'console=ttyAMA0 root=/dev/vda rw init=/qmu-probe-init.sh' --name fw-probe --no-replace
qmu log --vm fw-probe      # inspect dependency output and failure markers too

# then interactive (SSH): drop --harness so qmu adds hostfwd + waits for SSH
qmu launch \
  --cmdline 'console=ttyAMA0 root=/dev/vda rw init=/qmu-net-init.sh net.ifnames=0' \
  --ssh-timeout 240 --name fw-access --no-replace
```
Run from the directory containing `qmu.toml`; both launches use its existing
configured rootfs. Harness mode does not require a rootfs, but still attaches
one when configured and present. For aarch64, the implicit `if=virtio` drive is
at `/dev/vda` (whole-disk image, no partition suffix), with `snapshot=on` keeping
the base image pristine. For x86, set `arch = "x86_64"`, remove the ARM CPU and
`extra_args`, and use `console=ttyS0 root=/dev/sda`; qmu's CPU/KVM defaults apply.

Use a unique worker-specific name in place of `fw-probe`/`fw-access` when
concurrent. Keep common kernel and disk inputs in the config recipe; only
phase-specific init/cmdline and operational choices stay on launch commands.
Follow the qmu skill's worker-state isolation rules, including retained
interpreter state. Snapshot-backed writes disappear at shutdown: include
offline injection and any required redeployment in the cold-start recipe.
For a network-isolated campaign, config `extra_args` do **not** replace qmu's
default NIC. A restricted backend added there still requires `--no-net` and a
matching SSH port; a no-network baseline needs `--harness` or `--no-net`. Check
the effective launch/run arguments before starting the VM. Keep complete boot
inputs in the config, but never advertise a bare no-flags launch as safe when
role-specific networking flags are required.


A quiet serial console is not evidence of success or failure. Inventory console
selection and log suppression in the original boot chain. A separate run with
`ignore_loglevel`, or removal of diagnostic redirection in a private init copy,
is disclosed observation instrumentation: record the exact change and its
possible timing effects, rather than silently changing the baseline. When a
command fails, capture its invocation, shell/loader availability and diagnostics
before attributing failure to hardware or inventing a replacement provider.

| Serial marker | What it establishes |
|---|---|
| `QMU-BOOT-OK` | The probe init reached its identification output; no dependency or service claim |
| `QMU-BOOT-DONE` | `ldd` exited 0 with non-whitespace output and no `=> not found` dependency; not functional loading/init |
| `QMU-PROBE-FAILED: <diagnostic>` | Dependency command failure (with status), unresolved dependencies, or empty evidence; PID1 parks without success/shutdown |
| `QMU-NET-CONFIGURED <observation>` | Required loopback/interface/address/route commands succeeded and `eth0` was observed with `inet 10.0.2.15/24`; not SSH readiness |
| `QMU-NET-FAILED: <stage>` | Required setup, address query/observation, or daemon exec failed; PID1 parks |

The network template uses strict one-shot address/route `add`: an existing
address or route reported as an error is failure, not silently repaired.
Network configuration can succeed before `dropbear-exec` fails; the earlier
configuration observation remains true but does not prove SSH access.
SSH readiness is qmu's actual **host-side connection check**, not a serial
marker. When requested SSH readiness times out, launch returns `4` (SSH/
infrastructure failure) and `ok:false`, retaining the VM, logs and SSH
status/detail for diagnosis; `124` remains a wait/run timeout outcome.
`--no-wait-ssh` and `--harness` skip that check; successful launch then makes no
SSH-readiness claim. After readiness, perform a benign `qmu --vm fw-access exec
-- 'printf "%s\n" QMU-ACCESS-CHECK'` and, if transfers are required, push/pull a
known harmless file and compare its bytes. Record outcomes, not just connection.

Template failure parks PID1 to preserve diagnostics: inspect serial output and
stop the failed lane rather than waiting indefinitely. `qmu wait --vm fw-probe
--pattern QMU-BOOT-DONE --timeout 30` can inspect retained stopped logs, so a
fast successful probe need not still be running. Preserve its metadata/logs;
matching uses the recorded epoch/latest-boot scope. Exit `0` proves only a
pattern match; inspect accompanying dependency/failure evidence and bind the
receipt to that VM and boot. No match follows normal panic/death/timeout
outcomes, not an assumed negative experiment. Bare wait remains running-only
and establishes QEMU process termination, not exercise evidence. Follow the
qmu skill's marker/boot-epoch limits.
Dependency inspection and shell-only init remain intermediate for convergence:
activate the relevant original services, observe readiness, and perform the
agreed benign operation, then apply the independent clean-VM handoff gate.

### 6. Audit
```bash
qmu --vm fw-access exec -- 'LD_LIBRARY_PATH=/usr/lib64 <cmd>'  # original userland, not service convergence
qmu --vm fw-access push <local> <guest>       # needs sftp-server injected (phase 4)
qmu --vm fw-access pull <guest> <local>
```
**Benign harnesses — build outside the guest when it has no toolchain.**
`qmu compile` runs `gcc` in the guest. Prefer an identified firmware SDK/sysroot,
or a candidate container toolchain whose output passes the same loader,
symbol-version and guest-execution checks as the access helpers. An older
container may work with newer firmware libc; matching a release label is not
proof. Reuse an identified build image rather than fetching packages each run:
```dockerfile
# Candidate arm64 toolchain; verify output compatibility.
FROM --platform=linux/arm64 ubuntu:18.04
RUN apt-get update -qq && apt-get install -y -qq gcc libc6-dev file
```
```bash
docker run --rm --platform linux/arm64 -v "$PWD:/work" --workdir /work fw-xbuild:bionic-arm64 \
  gcc -O0 -rdynamic -o harness harness.c -ldl        # exports harness symbols
qmu --vm fw-access push ./harness /tmp/harness && qmu --vm fw-access exec -- 'LD_LIBRARY_PATH=/usr/lib64 /tmp/harness'
```
A `dlopen` harness can support an isolated benign component experiment. A
missing callback (`undefined symbol`) identifies an unmet provider dependency.
A declared stub may permit that narrow experiment, but cannot count as the
original provider's successful behavior. Keep it separate from the baseline
unless explicitly approved under the fidelity boundary above; neither loading
the library nor a stub's success return proves service convergence.

**Extra partitions:** identify each image and expected mountpoint before boot.
For a config-first recipe, append an app disk to the existing
`[machine] extra_args`, for example `"-drive",
"file=/abs/path/app.img,if=virtio,format=raw,readonly=on"`, keeping the existing
machine arguments and implicit `[drive] rootfs`. Do not switch to a lone
`--drive` for the app disk: **any `--drive` suppresses the configured rootfs**.
When choosing explicit drives instead, list the root disk first
and every additional disk, with explicit read-only or snapshot policy. Verify
the resulting guest device mapping rather than assuming `/dev/vdb`; map mounts
and symlinks to the original expected paths for convergence. Mounting elsewhere
or bypassing the original activation sequence is an access/inspection adaptation.
Userspace debugging — run gdbserver in **stdio mode over the SSH pipe** (no port, no tunnel,
no background process, so it works under sandboxes that block persistent forwards):
```bash
gdb-multiarch -q -ex 'set architecture <arch>' \
  -ex 'target remote | ssh -i <key> -p <ssh_port> -o BatchMode=yes root@127.0.0.1 \
        LD_LIBRARY_PATH=/opt/qmu-tools/lib:/usr/lib64 /opt/qmu-tools/bin/gdbserver - /usr/bin/<target>'
# then: break/continue/stepi/x/info sharedlibrary. `gdbserver --attach <pid>` for a live process.
```
The process stops at the ld.so entry (libs not yet mapped); `continue` to a breakpoint past
rtld to see `info sharedlibrary`. (qmu's `--gdb`/`gdb` is the QEMU stub for the *kernel*, not
userspace.) Stripped binaries: load symbols from your BNDB/IDA analysis or a `.symtab` sidecar.

## Gotchas
- **`--vm` vs `--name`:** `--name` names the instance at `launch`; every other verb selects it
  with the global `--vm` flag (`qmu --vm fw exec ...`).
- **SSH key/host-key algorithm follows the sourced dropbear.** Old dropbear (bionic 2017.75)
  predates ed25519 → "No matching algo hostkey" and client-key rejection. Use **ecdsa-nistp256**
  for BOTH host keys (`dropbear -R` makes rsa+ecdsa) and the client key
  (`ssh-keygen -t ecdsa`). Newer dropbear (≥2018.76) can use ed25519.
- **`qmu push`/`pull` need `sftp-server`** at dropbear's compiled path (often `/usr/lib/sftp-server`).
  A “No such file” error can also mean a missing interpreter/loader or dangling symlink; inspect these before assuming only the server file is absent.
- **Dangling `/tmp`.** Firmware `/tmp` is often a symlink to a tmpfs systemd would mount
  (`/var/volatile/tmp`, `/run`, ...). Under bare init it doesn't exist → push to `/tmp` fails
  with "No such file or directory". The init template recreates it.
- **Kernel networking must be built-in.** `VIRTIO_NET`/`VIRTIO_PCI`/`PCI_HOST_GENERIC` `=m`
  won't load (your modules aren't in the image). Rebuild `=y` if defconfig didn't set them.
- **Cross-emulation is TCG** (no KVM unless guest arch == host arch). Allow for
  slower boot with an appropriate `--ssh-timeout`; elapsed time is not readiness evidence.
- **musl / non-glibc firmware:** use a compatible target toolchain/sysroot or
  verified static helpers. Static linking removes runtime shared-libc lookup,
  not kernel ABI, shell, account configuration, utility or runtime-file requirements.
