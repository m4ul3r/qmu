# Launch flags, profiles, VM state axes, and lifecycle rules

Companion to `skill://qmu`. The everyday launch lines are in the main skill;
this file is every flag, the launch result, the two state axes in depth, and
the `kill`/`prune`/`list` rules.

## Launch flags

```bash
qmu launch --name X --no-replace --harness --kernel ./bzImage --initrd ./ramdisk.img \
  --rootfs ./rootfs.img --cmdline 'console=ttyS0 root=/dev/sda ro init=/run.sh'
qmu launch --name X --no-replace --drive 'file=./disk.qcow2,format=qcow2'   # take over the block topology
qmu launch --name X --no-replace --no-net                  # -nic none; no SSH endpoint recorded
qmu launch --name X --no-replace --nic-model e1000         # default virtio-net-pci
qmu launch --name X --no-replace --no-kvm                  # force TCG ([machine] accel=tcg); boot 20–60 s for current kernels
                                                           # 4.x kernel + bookworm rootfs under TCG: ~2 min (sshd waits for the
                                                           # old kernel's entropy pool past a 90 s systemd timeout) — pass --ssh-timeout 180
qmu launch --name X --no-replace --ssh-timeout 120         # default 60 s
qmu launch --name X --no-replace --forward 2345 --forward 8080:80   # extra guest TCP ports
qmu launch --name X --no-replace -- -no-shutdown           # raw QEMU args only after --
```

- `--kernel`/`--initrd`/`--cmdline`/`--profile` have `[boot]` config keys;
  every other flag has its `[machine]`/`[drive]`/`[ssh]` key. CLI beats config.
- `--rootfs IMG` is the implicit disk: `/dev/sda` on x86_64, `/dev/vda`
  (virtio) on aarch64/arm; a whole-disk image takes no partition suffix. It
  is recorded as the VM's rootfs (holder checks, `status.rootfs`). `--drive
  SPEC` (repeatable) suppresses the implicit drive and is not recorded;
  prefer `--rootfs` for a plain image.
- `--no-net` without `--ssh-port` records **no** SSH endpoint (`ssh:
  "none"`); SSH commands refuse naming the reason. With a manual NIC pass
  `--ssh-port N` and forward `N` yourself.
- `--forward [HOST:]HPORT:GPORT` (repeatable; config `[machine] forwards =
  ["2345", "8080:80"]`, the flag replaces the list) adds a `hostfwd` for guest
  TCP port GPORT to qmu's own NIC — a long-lived `gdbserver
  127.0.0.1:2345 …`, an HTTP service under test — instead of an `ssh -L` qmu
  does not manage or a `--no-net` manual NIC. HOST defaults to `127.0.0.1`; a
  bare `GPORT` auto-allocates the host port under the same port lock as SSH.
  The mapping is recorded on the VM: `forwards: [{"host", "host_port",
  "guest_port"}]` in `launch`/`status`/`list` JSON, `Forward: 127.0.0.1:10022
  -> guest:2345` in text. A pinned port already in use is exit 1 naming it;
  `--forward` with `--no-net`/`--harness` (no qmu NIC) or `net_backend=passt`
  is exit 1, never silently dropped; a malformed spec is exit 2. It dies with
  the VM. The guest service must listen on an address slirp reaches
  (`0.0.0.0` or the guest's `10.0.2.15`; `127.0.0.1` in the guest is not
  forwarded to).
- `--no-kvm` forces TCG; KVM is otherwise auto-enabled when guest arch == host
  and `/dev/kvm` exists, recorded as `kvm` in `launch`/`status`/`list` JSON.
  KVM does **not** disable hardware watchpoints (`debugging.md`).
- `--no-reboot` passes `-no-reboot`: a panic under `panic=N` exits QEMU
  instead of rebooting into a fresh boot that buries the report. It changes
  what happens *after* the panic only — bare `wait` returns 3 at the panic
  line either way. Config key: `[machine] no_reboot = true` (the flag wins;
  `qmu config show` names the layer on its `No-reboot:` row). `--reboot`
  clears a config `true` for one launch (reboot-behaviour tests); a launch
  whose `-no-reboot` came from a config file says so in `warnings[]` and on
  stderr (`-no-reboot from [machine] no_reboot in project …`).
- `--inject LOCAL:/guest/dir` (repeatable; `--partition`, `--mkdir`) runs the
  offline injection before boot. Every target — image, local file, guest
  directory — is validated read-only **before** a same-named running VM is
  killed; a bad target leaves the old VM running.
- `--ssh-timeout`: on expiry both `launch` and `run` exit **124** with the
  same envelope (`ok: false`, `timed_out: true`, `ssh_error: true`,
  `error_type: "TimeoutError"`, `error`, `hint`); `launch` retains the VM
  (`ssh_status: "timeout"`, `qmu status --vm X` still answers), `run` stops it
  with state preserved. Not exit 4: nothing broke, the guest may still be
  booting — `qmu log --vm X --tail 50`, `qmu status --vm X`, or relaunch with
  a longer `--ssh-timeout`. A serial log still empty ~10 s after QEMU started
  the vCPUs (QMP `running: true`) fails
  earlier with `ssh_status: "no-console-output"` (exit 4, VM retained), naming
  the expected `console=` for the arch. An sshd that answers and refuses the
  recorded `[ssh] user`/key (`Permission denied`) ends the wait after ~5 s
  with `ssh_status: "auth-failed"`, exit 4, `error_type: "SSHAuthError"`,
  `ssh_user`, `ssh_key`, VM retained — the guest booted; relaunch with a user/key the
  image accepts (`root` for qmu rootfs; run unprivileged with `exec --user`).
- `--harness` implies `--no-wait-ssh --no-net`, skips the rootfs/SSH-key
  requirement, allocates no SSH port (`wait.md`). A config `[drive] rootfs`
  is still attached; the launch note names the source: `Harness mode:
  attached rootfs <p> (from --rootfs; …)` or `(from [drive] rootfs in project <qmu.toml>; …)`.

## Launch result

`launch --format json`: `vm_id`, `pid`, `ssh_port`, `ssh_user` (the account
SSH commands log in as; null without an SSH endpoint), `forwards`,
`gdb_port`, `ssh_status`
(`ready` · `skipped` · `no-console-output` · `timeout` · `auth-failed` ·
`n/a (harness)` · `none (--no-net, no --ssh-port)`), `kvm`,
`arch`, `cmdline`, `profile`, `profile_applied`, `rootfs`, `serial_log`,
`qemu_log`, `qmp_socket`, `warnings: [str]`, `config_sources: [paths]`
(global → project/explicit order), `replaced: {"vm_id", "pid"} | null`,
`unknown_kernel_params`, `unknown_kernel_params_by_source` (`boot-params.md`).

`warnings[]` mirrors every stderr warning: profile-override casualty list,
dotted-param typo, `--cmdline` without `root=`, ignored broken global config,
harness attached-rootfs note, replace note, and the arch-cmdline lint. The
profile-sourced unknown-parameter note (`apparmor=0`, `selinux=0`) is JSON-only
(`unknown_kernel_params_by_source.profile`), never printed:

- `'console=ttyS0' names an x86 serial port; on <arch> QEMU's virt console is ttyAMA0 …`
- `'root=/dev/sda' names a SCSI/SATA disk; qmu attaches the rootfs as virtio on <arch>, where it is /dev/vda …` (aarch64/arm; skipped with `--drive`)
- `'console=ttyAMA0' names an ARM PL011 UART; on x86_64 the serial console is ttyS0 …`
- `'root=/dev/vda' names a virtio disk; qmu attaches the rootfs as a plain IDE/SATA drive on x86_64, where it is /dev/sda …` (x86_64; skipped with `--drive`)

`launch`/`run` print `[qmu] config: <path>` on stderr when a project or
`--config` file applied. The first QMP connect after launch retries transient
resets/refusals for up to 3 s while QEMU is alive, and a retry that fired is
reported — `warnings[]` gains `QMP connect retried N× (ECONNRESET)` (stderr
`[qmu] QMP connect retried …`) — so it is never absorbed silently. Evidence:
one field hit (`~/qmu-audit/crashpaths` receipt 2, `[Errno 104] Connection
reset by peer` with ~10 agents launching at once); 0 retries in 24/24
`--no-net` + 11 netted concurrent launches (3×8, wave 6). A launch that
reports it is healthy; three or more in `warnings[]` across a batch means
the host is saturated.

A QEMU that accepts the QMP connection but has not reached its main loop
(host load, a slow TCG start — no greeting in 2 s, or no `qmp_capabilities`
answer in 10 s) is waited for, up to 30 s: a fresh VM has no other QMP
client, so this is never contention. A handshake that completed late adds
`QMP connect retried N× over Ts (no QMP answer yet: QEMU still
initialising)`; one that never completed **retains** the live VM with `QMP
did not complete its handshake within 30s of launch, but QEMU (pid N) is
alive …` in `warnings[]`, and the SSH wait decides the exit as usual
(`ready`, `no-console-output` 4, timeout 124 — VM kept in each). Its
no-console window only opens once QMP answers with the vCPUs running: until
then nothing has executed, so a wait that ends first is the timeout (124)
with an `error` saying QEMU is still initialising — never a `console=`
verdict. A launch that
fails after QEMU started (exited immediately, QMP refused) is rolled back;
its `ok: false` envelope still carries `vm_id`, every lint already printed in
`warnings[]`, and a hint that says the VM is gone (never `qmu status --vm
<vm_id>`). While a slow handshake is waited for, the port-allocation lock
stays held (QEMU binds its SSH/gdb ports only after the QMP listener), so a
concurrent launch on the same cache waits behind it — `Waited Ns for the
port-allocation lock` in its `warnings[]` — and is never handed the slow
VM's port.

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

Each VM gets its own SSH port (from 10021; ports are recycled across agents
as soon as a VM dies), QMP socket and serial log. Concurrent workers may
launch at once: port allocation holds `flock` on `<cache>/instances/ports.lock`
from the free-port probe until QEMU has bound (first QMP answer), so eight
netted launches get eight distinct ports (24/24, wave 6); a wait ≥ 1 s on
that lock is reported (`Waited N.Ns for the port-allocation lock …`), and a
bind failure that survives all 3 retries names the lock as held — a foreign
listener owns the port. With exactly one VM running
most commands auto-select it, print `[qmu] Auto-selected the only running VM
'X' (pass --vm to pin it).` on stderr and set `autoselected: true`; `log`/
`crash`/`wait --pattern` also consider stopped VMs. `QMU_REQUIRE_VM=1` makes
every auto-selection exit 1 instead. On a shared host always pass `--vm`. On
`launch`/`run`, `--vm` is an alias for `--name`. Precisely:
`troubleshooting.md` → *Auto-selection*.

## The two state axes

`list`, `status` and bare `wait` report both; they vary independently
(orphaned AND panicked is the normal outcome of a trigger on a VM whose
metadata was lost).

**Existence** (`status`): `running` · `orphaned` (no metadata, process
alive) · `stopped` · `held_back` (metadata-free remnant the prune age gate
withheld) · `absent`. Every command that answers about a VM agrees with
`list` — `status`, `log`, `crash`, `prune`, `kill`, `wait`, `exec` all
describe a stopped or orphaned VM rather than reporting it missing. `status
--vm X` on a non-running VM is exit 0: `{ok: true, vm_id, status, guest,
pid, pid_alive, serial_log, qemu_log, logs_retained, crash_detected,
harness}` — `guest` is `null` for `stopped`/`held_back` and the live
classification for `orphaned` (its QEMU still runs; text keeps the
"orphaned remnant … pid N" prose). Text: `VM 'X' is stopped (logs retained;
crash report waiting: qmu crash --vm X)` / `(logs retained: qmu log --vm X;
remove with: qmu prune --vm X)` / `(no logs retained)`. Only an absent name
is exit 1. `list` JSON rows carry the same `ssh` words as `status` (`ready`
· `down` · `auth-failed` · `none` · `skipped` · `skipped (debugger attached)`
· `n/a (harness)`), `ssh_user`, `forwards`, `ssh_probe_ms` (the probe's wall time in ms; null when no
probe was sent — also on the `status` envelope and in the status text `SSH:
port N (ready, probe 87 ms)`, followed by `SSH user: root`), `logs_retained`,
`crash_detected`; a stopped row's `guest` is null. `ssh: "auth-failed"`
means sshd answered and refused `ssh_user` (the guest is `serving`;
`status` adds a relaunch `hint`, list text `ssh=N(auth-failed as USER)`).

**Guest usability** (`guest`), in precedence order:

- `panicked` — `Kernel panic - not syncing` in the current boot; the guest is
  gone and reaping is correct. `status` does not probe SSH (`ssh:
  "skipped"`, text `SSH: port N (not probed: guest panicked)`). `sysrq-c` is
  a direct `panic()` under every profile — it never demonstrates `crashed`.
- `paused` — QMP `running: false`. Read `qemu_status` to pick the recovery:
  `paused`/`debug` (`qmu gdb` until `qmu cont`, a debugger stop, an unclean
  bridge death) resume with `qmu cont --vm X` / `pry continue`; `restore-vm`
  (a `snapshot load` that failed mid-restore, `restore_state: "partial"` /
  `"unknown"`) must **not** be resumed — `qmu cont` refuses it (exit 1; a
  `--force` override exists for operators who accept an inconsistent
  machine); recover with a known-good `qmu snapshot load` or `kill` +
  relaunch (`snapshots.md`). `crash_detected` is reported **independently**
  of `guest`: a guest paused after a survived report is `guest: "paused"`,
  `crash_detected: true` in `status` and `list`, and `qmu crash --vm X`
  returns that report — `paused` never hides it.
- `crashed` — a report is retrievable AND the guest still serves. Under
  `exploit-dev` an Oops KASAN did **not** detect (plain `BUG:`/GPF/null deref
  in an uninstrumented path) kills only the faulting task. Pull the report; do
  not reap.
- `serving` — positive evidence: sshd answered, or (no SSH endpoint / not
  probed, e.g. harness) console output in the current boot. Bare `wait`
  reports it the same way while QEMU runs, and `guest: null` once it exited.
- `unknown` — otherwise, with `guest_detail`: `SSH down, 0 bytes of console
  output`, `no SSH, 0 bytes of console output`, `QMP busy, SSH not probed,
  1234 bytes of console output`. A wrong-arch cmdline (empty serial, no SSH)
  is `unknown`, never `serving`. Text: `Guest: unknown (…)` / `[running —
  guest unknown (…)]`.

Both crash reads are scoped to the latest kernel boot banner, so a previous
boot's panic never labels a healthy rebooted guest as gone.

**QMP** (`qmp`): `connected` · `busy` (another client holds QEMU's single QMP
slot — a debugger bridge, a wedged `savevm`; bare `wait` never holds it) ·
`unreachable` · `"skipped"` (`list` did not consult QMP, e.g. a stopped VM) ·
null (stopped, in bare `wait` only). A stopped `status` **omits** `qmp`,
`qemu_status` and `ssh` altogether — they describe a live QEMU — so check for
the key, not for `null`. When not `connected`, `qemu_status` is `unknown` and
nothing QMP-derived is claimed. `kill` under a held socket skips the graceful
`quit` after 1 s and signals (≈1 s, not 14 s). `status --vm X` and `list`
classify a held slot identically (`qmp: "busy"`, `qemu_status: "unknown"`,
each spending its ~2 s QMP budget). `list` row schema: a running row carries `qmp` and
`qemu_status` (the same values `status` reports; `unknown` whenever `qmp`
is not `connected`); a stopped/orphaned/held-back row has `qmp: "skipped"`
and **no** `qemu_status` (nor `qmp_socket`) key — never `qemu_status:
null` — so test for key presence. With a
gdb client attached, `status`/
`list` skip the SSH probe (`ssh: "skipped (debugger attached)"`; text `port N
(not probed: debugger attached; a login would trip breakpoints)`, list
`ssh=PORT(not probed: debugger attached)`) because the probe's `uname` would
trip user breakpoints.

KASAN-detected bugs are terminal under every profile (`kasan.fault=panic`);
`--append kasan.fault=report` survives them; `--profile exploit-test`
(`oops=panic`) makes every Oops terminal.

## `list`, `kill`, `prune`

```bash
qmu list                                 # existence + guest state; probes SSH (ControlMaster=no), a few seconds on a busy host
qmu status --vm X                        # typically sub-second; ~2 s under a held QMP slot, ≤ 2.4 s wall when the SSH port accepts but never answers (probe capped at 2.25 s; `ssh_probe_ms` says how long the probe took). A TCG guest (`kvm: false`) gets an 8 s probe (8.25 s cap): an emulated sshd takes 4–6 s to log in on a loaded host and read as `down` under the KVM budget. Exit 0 on a stopped VM (status: "stopped")
qmu kill --vm X                          # QMP quit → SIGTERM; `bridge_reaped`, `logs_preserved`; closes the ControlMaster
qmu kill --vm X --force                  # SIGKILL
qmu kill --vm X --no-clean               # keep .json + .serial.log
qmu prune --vm X                         # stopped VM's state files (kill-preserved logs included); no-op after a plain kill
qmu prune --vm X --keep-logs             # drop .json + .qmp.sock, keep logs
qmu prune --vm X --older-than 0          # clear a metadata-free .qemu.log/.qmp.sock remnant now (default gate 24 h)
qmu prune --orphans --dry-run            # would_kill[] with vm_id; drop --dry-run to kill (reaps other agents' lost VMs too)
```

`kill` removes metadata and logs by default but keeps `.json`, `.serial.log`
and `.qemu.log` when the guest is `crashed` or `panicked` (`logs_preserved:
true`, pointing at `qmu crash --vm X`); it also reaps the pry bridge `qmu gdb`
spawned (`bridge_reaped`). `kill --vm X` on an already-stopped VM is a clean
no-op for QEMU — exit 0, `already_stopped: true`, `logs_retained`, text `VM
'X' is already stopped; state retained (remove with: qmu prune --vm X)` — but
it still reaps a recorded bridge whose stub died with QEMU (`bridge_reaped:
true`, text `Reaped its recorded debugger bridge.`), so a `qmp quit` or a
guest-side halt no longer strands a pry process. `prune --vm X` removes a
stopped VM with its record, or a serial-log-only remnant, at any age; only a
metadata-free `.qemu.log`/`.qmp.sock` remnant is age-gated (`held_back`,
`held_reason: "age"`, `--older-than 0`). A remnant whose `.json` is
unreadable is also `held_back` but with `held_reason: "malformed-metadata"`
and under prune's `refused[]` — no age clears it; repair or delete the
`.json` by hand (`cache.md`). Such a remnant is still *visible*: `list` shows it as
`stopped` (`profile=? kernel=?`, the coarse existence word `list` uses for
every non-running record), while `status --vm X` (exit 0) and `prune --vm X`
refine that to `held_back` until `--older-than 0` — `status` never says
"not found" for a name `list` displays. `list` text marks a stopped VM whose
report is still on disk `[stopped — crash report retained]`. qmu never
recommends `prune --all`. Every prune mode, `--dry-run`, `cache du/ls`:
`cache.md`.

## Files on disk

| File | Purpose | Removed by |
|---|---|---|
| `<name>.json` | metadata (pid, ports, kernel, arch, kvm, bridge pid) | `kill` (unless logs are preserved), `prune`, `prune --keep-logs`, `wait` harness auto-clean (of an exit that wait saw) |
| `<name>.serial.log` | serial console (`qmu log`) | `kill` (only when the guest is neither `crashed` nor `panicked`), `prune`, `wait` harness auto-clean of an exit the wait saw (`process_exited`) — kept by `kill --no-clean`, `prune --keep-logs`, `wait --no-clean`, and never removed by a `wait` on a VM already stopped (`already_stopped`) |
| `<name>.qmp.sock` | QMP control socket | `kill`, `prune`, `prune --keep-logs`, `wait` harness auto-clean (of an exit that wait saw) |
| `<name>.qemu.log` | QEMU stdout/stderr | same rule as `.serial.log` |
