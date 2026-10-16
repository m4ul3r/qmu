# Launch flags, profiles, VM state axes, and lifecycle rules

Companion to `skill://qmu`. The everyday launch lines are in the main skill;
this file is every flag, the launch result, the two state axes in depth, and
the `kill`/`prune`/`list` rules.

## Launch flags

```bash
qmu launch --name X --no-replace --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'
qmu launch --name X --no-replace --no-net                  # -nic none; no SSH endpoint recorded
qmu launch --name X --no-replace --nic-model e1000         # default virtio-net-pci
qmu launch --name X --no-replace --no-kvm                  # force TCG ([machine] accel=tcg)
qmu launch --name X --no-replace --ssh-timeout 120         # default 60 s
qmu launch --name X --no-replace -- -no-shutdown           # raw QEMU args only after --
```

- `--kernel`/`--initrd`/`--cmdline`/`--profile` have `[boot]` config keys;
  every other flag has its `[machine]`/`[drive]`/`[ssh]` key. CLI beats config.
- `--drive SPEC` (repeatable) suppresses the implicit rootfs drive and is not
  recorded as the VM's rootfs (holder checks, `status.rootfs`); prefer
  `--rootfs` for a plain image.
- `--no-net` without `--ssh-port` records **no** SSH endpoint (`ssh:
  "none"`); SSH commands refuse naming the reason. With a manual NIC pass
  `--ssh-port N` and forward `N` yourself.
- `--no-kvm` forces TCG; KVM is otherwise auto-enabled when guest arch == host
  and `/dev/kvm` exists, recorded as `kvm` in `launch`/`status`/`list` JSON.
  KVM does **not** disable hardware watchpoints (`debugging.md`).
- `--no-reboot` passes `-no-reboot`: a panic under `panic=N` exits QEMU
  instead of rebooting into a fresh boot that buries the report. CLI only
  (no config key).
- `--inject LOCAL:/guest/dir` (repeatable; `--partition`, `--mkdir`) runs the
  offline injection before boot. Every target — image, local file, guest
  directory — is validated read-only **before** a same-named running VM is
  killed; a bad target leaves the old VM running.
- `--ssh-timeout`: on expiry `launch` exits 4 (`SSHError`) and retains the VM;
  `run` reaps it and exits 124. A serial log still empty after ~10 s fails
  earlier with `ssh_status: "no-console-output"` (exit 4, VM retained), naming
  the expected `console=` for the arch.
- `--harness` implies `--no-wait-ssh --no-net`, skips the rootfs/SSH-key
  requirement, allocates no SSH port (`wait.md`).

## Launch result

`launch --format json`: `vm_id`, `pid`, `ssh_port`, `gdb_port`, `ssh_status`
(`ready` · `skipped` · `no-console-output` · `timeout (VM may still be
booting)` · `n/a (harness)` · `none (--no-net, no --ssh-port)`), `kvm`,
`arch`, `cmdline`, `profile`, `profile_applied`, `rootfs`, `serial_log`,
`qemu_log`, `qmp_socket`, `warnings: [str]`, `config_sources: [paths]`
(global → project/explicit order), `replaced: {"vm_id", "pid"} | null`,
`unknown_kernel_params`, `unknown_kernel_params_by_source` (`boot-params.md`).

`warnings[]` mirrors every stderr warning: profile-override casualty list,
dotted-param typo, `--cmdline` without `root=`, ignored broken global config,
harness attached-rootfs note, replace note, and the arch-cmdline lint:

- `'console=ttyS0' names an x86 serial port; on <arch> QEMU's virt console is ttyAMA0 …`
- `'root=/dev/sda' names a SCSI/SATA disk; qmu attaches the rootfs as virtio on <arch>, where it is /dev/vda …` (aarch64/arm; skipped with `--drive`)
- `'console=ttyAMA0' names an ARM PL011 UART; on x86_64 the serial console is ttyS0 …`

`launch`/`run` print `[qmu] config: <path>` on stderr when a project or
`--config` file applied. The first QMP connect after launch retries transient
resets for up to 3 s while QEMU is alive.

## Profiles

All three disable LSMs and carry `kasan.fault=panic`: `exploit-dev`
(default) — no `panic_on_warn`/`oops=panic`; `trigger-test` — adds
`panic_on_warn=1`; `exploit-test` — adds `oops=panic` (the boot spelling;
`panic_on_oops=1` is sysctl-only and silently ignored at boot). `--profile
bogus` lists the full set, including the `ubuntu-*` profiles. Every profile
carries `root=/dev/sda`; a hand-written `--cmdline` that omits it boots into
an emergency shell. The rootfs is attached `snapshot=on`, so the base image is
never modified. Precedence of `--append`/`--cmdline`/config/profile:
`boot-params.md`.

## Auto-replace

A `--name` (or the default) matching a running VM **replaces** it, and
`replaced` names the old VM. `--no-replace` makes that exit 1 naming the
running pid — it never launches alongside, which would strand the first QEMU.

## Multiple VMs and auto-selection

Each VM gets its own SSH port (from 10021), QMP socket and serial log. With
exactly one VM running most commands auto-select it; `log`/`crash`/`wait
--pattern` also consider stopped VMs and report `autoselected`. On a shared
host always pass `--vm`. On `launch`/`run`, `--vm` is an alias for `--name`.
Precisely: `troubleshooting.md` → *Auto-selection*.

## The two state axes

`list`, `status` and bare `wait` report both; they vary independently
(orphaned AND panicked is the normal outcome of a trigger on a VM whose
metadata was lost).

**Existence** (`status`): `running` · `orphaned` (no metadata, process
alive) · `stopped` · `absent`. Every command that answers about a VM agrees
with `list` — `status`, `log`, `crash`, `prune`, `kill`, `wait`, `exec` all
describe a stopped or orphaned VM rather than reporting it missing.

**Guest usability** (`guest`), in precedence order:

- `panicked` — `Kernel panic - not syncing` in the current boot; the guest is
  gone and reaping is correct. `status` does not probe SSH (`ssh:
  "skipped"`, text `SSH: port N (not probed: guest panicked)`).
- `paused` — QMP `running: false`: `qmu gdb` until `qmu cont`, a debugger
  stop, an unclean bridge death, `restore-vm`.
- `crashed` — a report is retrievable AND the guest still serves. Under
  `exploit-dev` an Oops KASAN did **not** detect (plain `BUG:`/GPF/null deref
  in an uninstrumented path) kills only the faulting task. Pull the report; do
  not reap.
- `serving` — positive evidence: sshd answered, or (no SSH endpoint / not
  probed) console output in the current boot.
- `unknown` — otherwise, with `guest_detail`: `SSH down, 0 bytes of console
  output`, `no SSH, 0 bytes of console output`, `QMP busy, SSH not probed,
  1234 bytes of console output`. A wrong-arch cmdline (empty serial, no SSH)
  is `unknown`, never `serving`. Text: `Guest: unknown (…)` / `[running —
  guest unknown (…)]`.

Both crash reads are scoped to the latest kernel boot banner, so a previous
boot's panic never labels a healthy rebooted guest as gone.

**QMP** (`qmp`): `connected` · `busy` (another client holds QEMU's single QMP
slot — a bare `wait` from an older qmu, a debugger bridge, a wedged `savevm`)
· `unreachable` · null (stopped). When not `connected`, `qemu_status` is
`unknown` and nothing QMP-derived is claimed. `kill` under a held socket
skips the graceful `quit` after 1 s and signals (≈1 s, not 14 s). `list`'s
concurrent probe may report a held slot as `unreachable` rather than `busy`;
`status --vm X` is the precise read.

KASAN-detected bugs are terminal under every profile (`kasan.fault=panic`);
`--append kasan.fault=report` survives them; `--profile exploit-test`
(`oops=panic`) makes every Oops terminal.

## `list`, `kill`, `prune`

```bash
qmu list                                 # existence + guest state; probes SSH, 15-60 s on a busy host
qmu status --vm X                        # < 1 s
qmu kill --vm X                          # QMP quit → SIGTERM; `bridge_reaped`, `logs_preserved`
qmu kill --vm X --force                  # SIGKILL
qmu kill --vm X --no-clean               # keep .serial.log + .json
qmu prune --vm X                         # stopped VM's state files; no-op after a plain kill
qmu prune --vm X --keep-logs             # drop .json + .qmp.sock, keep logs
qmu prune --vm X --older-than 0          # clear a log-only remnant now (default gate 24 h)
qmu prune --orphans --dry-run            # would_kill[] with vm_id; drop --dry-run to kill
qmu prune --all                          # NOT on a shared host
```

`kill` removes metadata and logs by default but keeps `.serial.log`/
`.qemu.log` when the guest is `crashed` or `panicked` (`logs_preserved:
true`, pointing at `qmu crash --vm X`); it also reaps the pry bridge `qmu gdb`
spawned. Log-only remnants are age-gated against `prune --vm` and named under
`held_back`. Every prune mode, `--dry-run`, `cache du/ls`: `cache.md`.

## Files on disk

| File | Purpose | Removed by |
|---|---|---|
| `<name>.json` | metadata (pid, ports, kernel, arch, kvm, bridge pid) | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.serial.log` | serial console (`qmu log`) | `kill` (only when the guest is neither `crashed` nor `panicked`), `prune`, `wait` harness auto-clean — kept by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean` |
| `<name>.qmp.sock` | QMP control socket | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean |
| `<name>.qemu.log` | QEMU stdout/stderr | same rule as `.serial.log` |
