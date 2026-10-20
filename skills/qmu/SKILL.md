---
name: qmu
description: Use the local qmu CLI to manage QEMU VMs for kernel exploit development. Handles VM lifecycle, file transfer, guest execution, snapshots, serial crash extraction, and GDB integration via pry. Prefer this skill for booting VMs, pushing/compiling/running exploits, extracting crash reports, and snapshot management.
---

# qmu

qmu boots and drives QEMU VMs for kernel research. Every command exits with a
contract code and, under `--format json`, prints one `{"ok": bool, ...}`
object. Pass `--vm <id>` on every command and `--name <id> --no-replace` on
every launch — the host is shared. `qmu <sub> --help` is authoritative.

## What do I want to do?

| I want to… | Run | Then check |
|---|---|---|
| set up a fresh project | `qmu config init` → edit the three `# CHANGE ME` lines → `qmu doctor` | every `[!]` row fixed; exit 0 |
| boot a VM | `qmu launch --name X --no-replace` (with `[boot] kernel` in `qmu.toml`) | exit 0, `ssh_status: "ready"`, `warnings: []` |
| run one command in the guest | `qmu exec --vm X "cmd"` | exit 0 if the guest command exited 0, else 1 (its code is JSON `exit_code`); stdout = guest stdout |
| boot + run + reap in one call | `qmu run --name X --no-replace -- './exploit'` | same 0/1 mapping (`exit_code`); `vm_id` for leftovers |
| compile and run a C exploit | `qmu compile --vm X exploit.c --run` | `compile_exit`, `run_exit`, `crash_detected` |
| copy a file in / out | `qmu push --vm X ./f /root/` · `qmu pull --vm X /root/out ./` | exit 0; 1 = caller error (`SCPFileError`), 3 = the guest panicked mid-transfer (fresh `crash`), 4 = transport |
| see what a VM is doing | `qmu status --vm X` (`qmu list` for all) | `status` (existence) and `guest` (usability); a stopped VM is exit 0, `status: "stopped"`, `guest: null` |
| get the crash report | `qmu crash --vm X` | `crash_detected: true`; else `qmu log --vm X --tail 200`. Save it: `qmu crash --vm X --format text --out report.txt` |
| block until a serial marker | `qmu wait --vm X --pattern '=+ results =+$' --timeout 120` | 0 match · 3 panic · 1 VM died · 124 timeout |
| boot-and-die kernel (no SSH) | `qmu launch --harness --no-reboot --name X --no-replace --kernel ./bzImage --initrd ./rd.img --rootfs ./rootfs.img` → `qmu wait --vm X` | 0 exited (`console_tail[]` is the receipt) · 3 panic (`crash`) |
| put files into an image offline | `qmu rootfs inject ./rootfs.img ./exploit:/root/ --partition 0` → `qmu rootfs ls ./rootfs.img /root --partition 0` | the file is listed. Pass the same `--partition` to **both** commands: `0` = whole-disk image with no partition table (the mkrootfs/cloud default); the default `1` = `/dev/sda1` of a partitioned image, and `ls` without it exits 1 (`Partition /dev/sda1 was not found`) after a successful inject |
| rewind instead of rebooting | `qmu snapshot save clean --vm X` … `qmu snapshot load clean --vm X` | exit 0; `SnapshotError` → `reference/snapshots.md` |
| debug with gdb | `qmu launch --gdb --name X --no-replace` → `qmu gdb --vm X --symbols vmlinux` → `qmu cont --vm X` | read `reference/debugging.md` first |
| stop a VM | `qmu kill --vm X` | `logs_preserved: true` means a report is waiting in `qmu crash --vm X`; already stopped → exit 0, `already_stopped: true` |
| clean up state files | `qmu prune --vm X --dry-run` then without `--dry-run` | `pruned[]`; removes kill-preserved logs at any age; never `prune --all` on a shared host |
| diagnose the host/config | `qmu doctor` | `[!]` rows are blocking; `[~]`/`[i]` are not |

## Exit codes

Branch on the exit code and `ok`, never on the presence of `error`.

| Code | Meaning | JSON key to read | Next command |
|---|---|---|---|
| `0` | success; for `wait --pattern` the regex matched, for bare `wait` QEMU exited | `ok: true`; `matched_line`, `reason` | continue |
| `1` | operation failed: guest command non-zero, no/bad `--vm` (or `--vm` omitted under `QMU_REQUIRE_VM=1`), `doctor` unhealthy, `SnapshotError`, `SCPFileError`, `ConfigError`, paused/panicked guest refusal, `wait --pattern` outlived the VM, `crash` found nothing | `error_type` (exception paths) or domain keys (`exit_code`, `guest_state`, `crash_detected`, `reason`) | run the `hint` (every `ok: false` envelope has one, result-specific: guest exit N → its `stderr`, `qmu exec --vm X 'dmesg \| tail -n 30'`; `crash` none → `qmu log --vm X --tail 200` / `--full-history`; `doctor` → fix the `[!]` rows, each `checks[]` row carries its own `hint`); for a refusal, `qmu crash --vm X` / `qmu cont --vm X` |
| `2` | usage error (argparse) ONLY; `error_type: "UsageError"` under JSON | `usage`, `hint` | fix the flags — e.g. quote the guest command |
| `3` | guest kernel crash, always corroborated by a fresh serial crash report | `crash`, `crash_detected: true`. The guest axis (`guest` on `wait`/`status`) can be either: `"panicked"` for a terminal `Kernel panic - not syncing`, `"crashed"` when the report was **survived** (KASAN `fault=report`, an Oops) but the SSH transport dropped | `qmu crash --vm X`, then `qmu status --vm X`: `qmu kill --vm X` only on `guest: "panicked"`; on `"crashed"` do **not** reap |
| `4` | transport/infra: `SSHError`/`QMPError`, `no-console-output`, dropped SSH with NO fresh crash, `wait --pattern` `inconclusive`, internal error | `error_type` + `hint` (exception paths); a guest-command envelope has **no** `error_type` — read `ssh_error: true`, `crash_detected: false`, `hint`; `inconclusive`, `ssh_status` | `qmu status --vm X`, `qmu log --vm X --tail 200` |
| `124` | timeout: `wait` elapsed, `launch`/`run` `--ssh-timeout` expired before SSH answered (`launch` keeps the VM, `ssh_status: "timeout"`), `exec`/`run`/`compile --run` outran `--timeout` on a reachable guest, `snapshot save` outran its budget (result **unknown**, not failed) | `timed_out: true`, `error_type: "TimeoutError"` + `hint` on an SSH timeout, `reason: "timeout"`, partial `stdout`/`stderr`; `may_have_landed: true` + `hint` on a save; `hint` on every one | raise `--timeout`/`--ssh-timeout` (the `hint` names which); `qmu log --vm X --tail 50` after a launch or `wait` timeout; check `crash` on a bare `wait`; after a save, `qmu snapshot list --vm X --timeout 300` |

Detail (envelope shapes, `hint`/`warnings[]`, result-style failures, spilling, `--out`): `reference/output-contract.md`.

## Recovery: symptom → meaning → command

| Symptom | Meaning | Do |
|---|---|---|
| `guest: "panicked"` (`[running — GUEST PANICKED]`) | terminal `Kernel panic - not syncing`; the guest is gone, QEMU still runs | `qmu crash --vm X`, then `qmu kill --vm X` (logs kept); `list` later shows `[stopped — crash report retained]` |
| `guest: "crashed"` | an Oops killed one task; the guest still serves | `qmu crash --vm X`; do **not** reap |
| `guest: "paused"`, `qemu_status: "paused"` / `"debug"` | vCPU halted by `qmu gdb`, a debugger stop, a `snapshot load` into a debug stop (can survive a *clean* `pry kill`), or an unclean bridge death; `crash_detected` is independent — `paused` + `crash_detected: true` means a report is waiting | `qmu cont --vm X` (or `pry continue`); `qmu crash --vm X` if `crash_detected` |
| `guest: "paused"`, `qemu_status: "restore-vm"` (after a `snapshot load` with `restore_state: "partial"` / `"unknown"`) | the load failed mid-restore: disks already rewound under un-restored devices/RAM; qmu left it paused on purpose | **never** `cont` (`qmu cont` refuses this state, exit 1); recover with `qmu snapshot load <known-good> --vm X` (resumes it) or `qmu kill --vm X` + relaunch. `qmu cont --force --vm X` only if you accept an inconsistent machine |
| `guest: "unknown"` + `guest_detail` | no positive evidence of a serving guest (`SSH down, 0 bytes of console output`) | `qmu log --vm X --tail 50`; wrong `console=`/arch? see `warnings[]` |
| `qmp: "busy"`, `qemu_status: "unknown"` | another client holds QEMU's single QMP slot (debugger bridge; a `savevm` still running after `snapshot save` exited 124; bare `wait` never holds it) | wait for it; `qmu kill --vm X` still works (signals after 1 s) |
| `qmp: "unreachable"` with pid alive | socket gone or hung | `qmu status --vm X` again; `qmu kill --vm X` falls back to signals |
| `ssh: "n/a (harness)"` / `ssh: "none"` (launch `ssh_status`: `"n/a (harness)"` / `"none (--no-net, no --ssh-port)"` — match the prefix) / SSH command refuses naming no endpoint | `n/a (harness)`: `--harness`, no SSH port by design. `none`: `--no-net` without `--ssh-port` | use `log`/`wait`/`crash`/`qmp`; for SSH relaunch **without** `--harness` (it ignores `--ssh-port`), or add `--ssh-port N` to a `--no-net` launch |
| `ssh: "skipped"` / `"skipped (debugger attached)"` | guest paused/panicked, or a gdb client is attached (the probe's `uname` would trip breakpoints), so SSH was not probed | see the `guest` row above; `pry wait` for the stop |
| `snapshot save` exit 124, `may_have_landed: true` | the save outran its budget (default 60 s + 20 s/GiB RAM); QEMU is probably still writing it and QMP queues behind it | `qmu snapshot list --vm X --timeout 300` (waits, shows whether the tag landed); do not retry the save until it answers; next time `--timeout N` |
| `ssh_status: "no-console-output"` (launch exit 4) | serial log still empty after 10 s: wrong `console=` or `-M`/`-cpu` for the arch | VM is retained: `qmu log --vm X`; fix the cmdline (`ttyS0` x86, `ttyAMA0` arm) |
| `ssh_status: "timeout"`, `timed_out: true` (launch exit 124) | `--ssh-timeout` expired with the guest still booting; nothing broke | VM is retained: `qmu log --vm X --tail 50`, `qmu status --vm X` re-probes SSH, or relaunch with a longer `--ssh-timeout` |
| `[qmu] Warning: 'console=…' names …` / `'root=/dev/sda' names …` | arch-cmdline lint (also in launch `warnings[]`) | fix before trusting a silent console |
| `[!] kernel: ./bzImage (CHANGE ME placeholder; not found)` | the starter `qmu.toml` was never edited | set `[boot] kernel`; `[!]` rows drive exit 1 |
| `Hint: quote the guest command … or put -- before it` (exit 2) | unquoted dash-word in `exec`/`run` | `qmu exec --vm X 'uname -a'` or `qmu exec --vm X -- uname -a` |
| `inconclusive: true` (`wait --pattern`, exit 4) | the serial log could not be read; not a no-match | fix the log path/permissions; never record as negative |
| `logs_preserved: true` from `kill` | a crash report is waiting; `.json` + logs stay, `status --vm X` is exit 0 `status: "stopped"` | `qmu crash --vm X`; `qmu prune --vm X` when done (not age-gated) |
| `held_back` in `prune`/`status`, `held_reason: "age"` | a metadata-free `.qemu.log`/`.qmp.sock` remnant younger than `--older-than` (24 h); `list` shows it `[stopped]` (`profile=? kernel=?`); kill-preserved logs are never held back | `qmu prune --vm X --older-than 0` |
| `held_reason: "malformed-metadata"`, `prune` lists it under `refused[]` (`{vm_id, reason, path}`) | the VM's `.json` is unreadable and no serial log corroborates it; **not** age-gated — `--older-than 0` cannot clear it, by design | repair or delete the named `.json` by hand, then `qmu prune --vm X` |
| `held_reason: "qmp-busy"` | the remnant's socket still answers: a QEMU is alive behind it | reap it first (`qmu kill --vm X` / `qmu prune --orphans`), then prune |
| `reason: "already_stopped"` (bare `wait`, exit 0) | QEMU had exited before the wait began | read `crash` and `console_tail[]` from this result |
| `error_type: "SCPFileError"` (exit 1) | missing local file, a directory, bad remote dir | fix the path; archive directories first |
| `error_type: "SnapshotError"` (exit 1) | HMP refused; on `load` read `restore_state`: `none` → nothing restored (a missing tag is caught before `loadvm`, guest never stopped; `resumed: true` only if QEMU refused a listed tag); `partial`/`unknown` → disks already rewound, guest **left paused** on purpose (`guest_paused: true`) | `none`: run the `hint` (`qmu snapshot list --vm X`); `partial`/`unknown`: load a known-good tag or `kill` + `launch` — never a blind `qmu cont`; `reference/snapshots.md` |
| `error_type: "ConfigError"`, `errors[]` | every schema problem in the file, with `source`/`key`/`hint` | fix all listed keys; cleanup commands are blocked until it parses (or run them from outside the project dir) |
| `A debugger client is already attached to port N (pry bridge pid P)` | the stub serves one client; `qmu gdb` spawned nothing | reuse it (`pry --instance qmu-X`, the `bridge_instance_id`) or `pry kill --instance qmu-X` |
| `[qmu] Output spilled to <path> (~N tokens)` | result exceeded ~10k tokens; text shows a preview capped at 40 lines **and** 4096 bytes, then `[qmu] Preview: first A of B bytes (…)` | read `<path>` (`artifact_path` under JSON) |

## Bootstrap a project

```bash
qmu doctor            # [!] = blocking, [~] = warning, [i] = info; "Run: qmu config init" if no config
qmu skill install     # fixes a "[~] skills: … stale (linked to another checkout)" doctor row; prints one line per changed link — installed | relinked … (was <old target>) | replaced — and tallies current ones, which it leaves untouched
qmu config init       # starter qmu.toml; the three `# CHANGE ME` lines are live (no uncommenting)
qmu doctor            # kernel, initrd, rootfs image, rootfs sshd policy ([~] permissive = any key logs in as root; rebuild with tools/mkrootfs.sh), SSH key, SSH key permissions (no group/other bits — 0644 is [!]: OpenSSH refuses the key) all [+]
qmu config path       # which global/project file qmu reads, and whether each exists
qmu config show       # resolved values, each tagged [built-in | global | project | --config | flag]
qmu doctor --config ./other.toml --format json   # --config also on launch/run/status/list/log/crash/config show
```

Edit `[boot] kernel`, `[drive] rootfs`, `[ssh] key` (relative paths resolve
from the config file's directory; `~` works). Boot-and-die kernels skip
`[drive]`/`[ssh]` — `doctor` marks them `[~] not needed for --harness boots`.
`config show --format json` reports *resolution*, so it is `ok: true` even
when a file is missing — branch on `paths.<key>.exists` (`boot.kernel`,
`drive.rootfs`, `ssh.key`); `doctor --format json` reports *health*: every
row carries `status`, `blocking` and `hint` (the fix). Config layering, the
full schema, `ConfigError`, `config show` JSON (`sources` per key, `layers`,
`paths`): `reference/troubleshooting.md`.

## Launch and lifecycle

```bash
qmu launch --name X --no-replace                                    # [boot] kernel from qmu.toml
qmu launch --name X --no-replace --kernel ./bzImage --profile trigger-test   # panic_on_warn=1
qmu launch --name X --no-replace --append "slub_debug=- nokaslr"    # ADD params
qmu launch --name X --no-replace --cmdline "console=ttyS0 root=/dev/sda nokaslr"  # REPLACE cmdline
qmu launch --name X --no-replace --gdb --memory 8G --cpus 4 --cpu host
qmu launch --name X --no-replace --inject ./exploit:/root/ --partition 0   # bake a file in first
qmu launch --name X --no-replace --no-reboot                        # panic exits QEMU instead of rebooting
qmu list                                   # existence + guest state for every VM (a snapshot, not a diff base)
qmu status --vm X                          # typically sub-second (~2 s under a held QMP slot, ≤ 2.4 s wall when the SSH port accepts but never answers (probe capped at 2.25 s) — `ssh_probe_ms` says); `qmu show` is an alias; exit 0 on a stopped VM too
qmu kill --vm X                            # QMP quit, then SIGTERM; keeps .json + logs when a report is waiting
qmu kill --vm X --no-clean                 # keep .json + .serial.log for forensics
qmu prune --vm X --dry-run                 # preview; then drop --dry-run (kill-preserved logs go at any age)
qmu prune --orphans --dry-run              # qmu-launched QEMUs no record claims — including other agents' VMs
```

Launch success includes SSH readiness: exit 4 (`SSHError`) retains the VM for
`qmu log --vm X`. JSON carries `vm_id`, `ssh_status`, `warnings[]` (every
stderr warning), `config_sources[]`, `replaced` (`{vm_id, pid}` or null),
`kvm`, `profile_applied`, `unknown_kernel_params_by_source.operator` (gate on
this; the `profile` bucket is JSON-only and never printed on stderr).
`--append` adds, `--cmdline` replaces (keep `root=`); a CLI `--profile`
overrides a config `[boot] cmdline` and lists the dropped params. `--inject`
validates image, file and guest dir before touching a same-named running VM.
Default `--name` replaces a running VM of that name; `--no-replace` makes it
exit 1. TCG boots (arm on x86, `--no-kvm`) reach SSH in 20–60 s instead of
~7 s. Flags, profiles, `--drive`, `--no-net`, `--no-kvm`, the two state
axes, `kill`/`prune` rules: `reference/launch.md`.

`status --vm X` on a non-running VM (killed with logs, `wait --no-clean`, a
log-only remnant) is a **description**, exit 0: `status: "stopped" |
"held_back"` with `guest: null`, or `"orphaned"` with the live `guest`
classification of its still-running QEMU; plus `pid_alive`, `logs_retained`,
`crash_detected`, `harness`. A stopped `status` has **no** `qmp`, `qemu_status`
or `ssh` keys (they describe a live QEMU; bare `wait` reports `qmp: null`
instead) — test for presence, not `null`. Text: `VM 'X' is stopped (logs
retained; crash report waiting: qmu crash --vm X)`. Only an absent name is
exit 1. `kill --vm X` on a stopped VM is exit 0 with `already_stopped: true`
and still reaps a recorded pry bridge (`bridge_reaped: true`)
(`qmu prune --vm X` removes the state). `list` marks such a VM `[stopped —
crash report retained]`; its JSON rows carry `ssh`, `logs_retained`,
`crash_detected`, and `qmp: "skipped"` when QMP was not consulted.

**Two state axes, never collapsed.** `status` (existence): `running` ·
`orphaned` · `stopped` · `held_back` · `absent`. `guest` (usability, running
VMs only; `null` once QEMU has exited): `serving` · `paused` · `crashed` ·
`panicked` · `unknown`. `serving` needs positive evidence (sshd answered, or
— with no SSH endpoint, e.g. harness — console output in this boot);
otherwise `unknown` with a `guest_detail`. Under the default `exploit-dev` profile
a KASAN-detected bug is terminal (`kasan.fault=panic` → `panicked`); a plain
non-KASAN Oops lands on `crashed` and must not be reaped (`sysrq-c` is a
direct `panic()`, never `crashed`). `--profile exploit-test` makes every Oops
terminal; `--append kasan.fault=report` survives KASAN reports.

## Iterate loop (no working SSH needed)

```bash
qmu launch --name poc --no-replace --inject ./exploit:/root/ --append "slub_debug=-"
qmu wait --vm poc --pattern '=+ results =+$' --timeout 120    # 0 match, 3 panic, 1 died, 124 timeout
qmu log --vm poc --grep "leaked|OOB|UAF" --context 3           # --grep searches the WHOLE log
qmu log --vm poc --full --out ./evidence.log                   # whole log to a file
```

Never hand-poll the serial log (`until grep …; do sleep; done` hangs on a
panic or a dead VM). Anchor the marker's **tail** (`'=+ results =+$'`): an
unanchored word also matches the kernel's echo of the cmdline, and `^` never
matches a marker sharing its line with a printk timestamp (`/dev/kmsg`) or
the newline-less `login:` prompt — a spurious 124. The scan starts at the
latest boot banner (`scan_offset`/`scan_scope`). An unterminated fragment
(`login:`) matches once the console idles for one poll. A *survived* Oops
does not abort the wait; `--ignore-crash` suppresses even the terminal
abort — do not paste it reflexively. Exit 0 proves the regex matched, not
the claim in its text (`reference/evidence-contract.md`). Full rules:
`reference/wait.md`.

## Guest commands

```bash
qmu exec --vm X "uname -a"                           # quote the command
qmu exec --vm X -- uname -a                          # or put -- before it
qmu exec --vm X "./exploit" --timeout 120            # flags before or after; default 30 s
qmu compile --vm X exploit.c --run --timeout 120     # push + gcc in guest + run (CFLAGS -static -lpthread)
qmu compile --vm X exploit.c --host --run            # cross-compile on the host, push the binary
qmu push --vm X exploit.c /tmp/exploit.c             # one regular file; trailing / = into that dir
qmu pull --vm X /root/output.txt ./results/
qmu dmesg --vm X --tail 50                           # guest dmesg over SSH; no SSH → qmu log
```

Text mode: stdout is the guest's stdout **only**, byte-exact (no decode, no
added newline — `printf x` is one byte, `0xff` passes through), **streamed
as the guest writes it** (progress shows before exit or `--timeout`; ndjson
gets `chunk` events, json stays buffered); guest stderr goes to stderr live,
then `[exit code: N]` only when N ≠ 0 (`exec true` prints nothing); `compile
--run`'s `Compiled and ran X:` banner is on stderr too. JSON: `vm_id`,
`exit_code` (null if unfinished), `stdout`, `stderr` (UTF-8 with U+FFFD;
`stdout_lossy: true` / `stderr_lossy: true` present exactly when a byte was
replaced), `timed_out`, `crash_detected`, `crash`. One argument is passed to
the guest shell verbatim; several are shell-quoted and joined; an unquoted
dash-word (`uname -a`) is exit 2 with a hint. `--timeout` keeps the partial
output (exit 124 for `exec`, `run` and `compile --run` alike — `run_exit:
null`, `timed_out: true`, `hint` says the guest still answers SSH; the remote
command is not killed). A panic mid-command is exit 3 within a second (serial
watcher), not after the SSH keepalive; a debugger stop mid-command (QMP
`running:false`) aborts within ~1 s with the exit 1 `guest_state: "paused"`
envelope the preflight uses; every SSH command refuses a `panicked`/`paused`
guest in under a second (exit 1, `guest_state`). `compile --host`, `--cflags`,
`--cc`: `reference/guest-commands.md`, `reference/cross-arch.md`.

## One-shot runs

```bash
qmu run --name X --no-replace -- './exploit'                  # launch → exec → kill
qmu run --name X --no-replace --timeout 120 --keep -- './exploit --spray'   # --keep leaves it up
qmu run --name X --no-replace --kernel ./bzImage --profile exploit-test -- './exploit'
```

Exit 0 when the guest command exited 0, 1 when it exited non-zero (the guest's
own code is JSON `exit_code`, never qmu's exit); `3` terminal panic; `124` the
guest never answered SSH within `--ssh-timeout` or the command outran
`--timeout` (default 60 s). A clean run reaps the VM; anything left to inspect (crash,
survived report under `kernel_warning`, timeout, boot failure) keeps it and
prints `Inspect: qmu log --vm X --tail 200, or qmu crash --vm X` / `Clean up:
qmu prune --vm X` on stderr. Raw QEMU args: `--qemu-arg=-M --qemu-arg=virt`.
`--harness`/`--no-wait-ssh` are exit 2 (`run` needs SSH). ≈7 s end to end.

## Crash triage

```bash
qmu crash --vm X                 # last crash in the current boot; works on a stopped VM
qmu crash --vm X --format text --out report.txt   # save the plain report (--out honours --format: JSON = envelope)
qmu crash --vm X --full-history  # across snapshot/reset epochs and earlier boots
qmu log --vm X --tail 200        # raw serial tail when crash finds nothing
qmu kill --vm X                  # after reading; .json + logs stay (logs_preserved: true)
qmu prune --vm X                 # finally drop the retained state (no age gate)
```

`crash` exit 0/`crash_detected: true` means a report was found, not that the VM
is healthy; "no crash" is exit 1 with `crash_detected: false` and no `error`.
Detects KASAN, BUG/Oops, panic, GPF, UBSAN, slab UAF and more. Command-
attributed crashes (`exec`, `compile --run`) use only bytes after it began.

## Harness mode (boot-and-die kernels)

```bash
qmu launch --harness --no-reboot --name X --no-replace --kernel ./bzImage --initrd ./ramdisk.img \
  --rootfs ./rootfs.img --cmdline 'console=ttyS0 root=/dev/sda ro init=/run.sh'
qmu wait --vm X --timeout 300          # 0 QEMU exited (console_tail[]), 3 panic while QEMU runs (crash), 124, 4
qmu wait --vm X --pattern '=+ DONE =+$' --timeout 300    # explicit success receipt (matched_line)
qmu wait --vm X --no-clean             # keep .json + .serial.log after a confirmed exit
qmu log --vm X --tail 100              # SSH commands refuse; serial/QMP commands work
qmu kill --vm X && qmu prune --vm X    # reap a panicked-but-running VM, then drop its remnant
```

`--harness` implies `--no-wait-ssh --no-net` and skips the rootfs/SSH-key
requirement. A config `[drive] rootfs` is still attached (launch says
`attached rootfs <p> (from --rootfs; …)` / `(from [drive] rootfs in project
<qmu.toml>; …)`); pass `--rootfs ./img` for the image you mean. The implicit/`--rootfs` disk is
`/dev/sda` on x86_64 and `/dev/vda` on arm; whole-disk images (mkrootfs,
cloud) take no partition suffix. Bare `wait` polls QMP every 0.5 s with
short-lived connections; its JSON carries `reason` (`process_exited` ·
`already_stopped` · `terminal_panic` · `timeout`), `stopped`, `crash`,
`console_tail[]` (last 20 scanned lines, every outcome), `guest` (`serving`
while a running guest has console output; `null` once QEMU exited),
`guest_detail`, `qmp`, `last_event`. A panic returns **3** at the panic line
whether or not `--no-reboot` is set; `--no-reboot` only decides what happens
next (QEMU exits under `panic=N` instead of rebooting into a fresh boot that
buries the report), so a second `wait` then reports `already_stopped` + the
`crash`. Exit 3 leaves QEMU running: `qmu kill --vm X` keeps the report,
`qmu prune --vm X` drops it. A confirmed exit auto-cleans a harness VM
(`.json` + `.serial.log`) unless `--no-clean` — read `crash`/`console_tail`
from `wait`'s own output. Semantics: `reference/wait.md`.

## Snapshot-rewind loop

```bash
qmu launch --name dev --no-replace
qmu push --vm dev ./exploit /tmp/x
qmu snapshot save clean --vm dev            # in-session checkpoint (default raw image works); budget 60 s + 20 s/GiB, `--timeout N` overrides; exit 124 = unknown, see reference/snapshots.md
for i in 1 2 3; do
  qmu exec --vm dev /tmp/x --format json --out runs/run-$i.json   # the PoC's stdout/stderr/crash
  qmu snapshot load clean --vm dev          # rewind; first exec after load is fast
done
qmu snapshot list --vm dev                  # id, tag, vm_size, date, time, vm_clock
qmu snapshot delete clean --vm dev
```

Record `exec`'s output, not `qmu log`: an SSH-driven PoC writes nothing to
the serial console (post-load the log only gains a benign `clocksource`
line). Checkpoints die with QEMU — and so does **all guest disk state**: the
default `snapshot=on` overlay is discarded on `kill`, so a relaunch starts
from the pristine image. A name is one token; a failed `load`/`delete` is
exit 1 `SnapshotError` with a `hint` (`qmu snapshot list --vm X`); a missing
tag is refused before `loadvm` and never stops the guest (`restore_state:
"none"`), while a `load` that failed mid-restore leaves it paused
(`guest_paused: true`, `restore_state: "partial"`) because the disks are
already rewound — do not `cont` it. Durable qcow2 snapshots, passt, and the baked-`int3` debugger
trap: `reference/snapshots.md`.

## Debug with pry

```bash
qmu launch --kernel "$KERNEL" --gdb --name dbg --no-replace
qmu gdb --vm dbg --symbols "$VMLINUX"           # spawns a pry bridge (bridge_pid); vCPU HALTED
qmu cont --vm dbg                               # resume so SSH works
eval "$(qmu kbase --vm dbg --symbols "$VMLINUX")"   # KBASE, LINK_BASE, SLIDE
pry load "$VMLINUX" --base "$KBASE"             # first pry touch after qmu cont halts again
pry break set __x64_sys_newuname
pry continue --background                       # REQUIRED before any qmu exec
qmu exec --vm dbg "uname -r"
pry wait --timeout 10
pry backtrace
```

Attaching halts the vCPU; SSH commands against a halted guest refuse (exit 1,
`guest_state: "paused"`), and one stopped mid-command aborts within ~1 s with
the same envelope. `qmu kbase` needs only SSH and `/proc/kallsyms` — no
`--gdb`, no bridge. While a gdb client is attached, `status`/`list` skip
their SSH probe (`ssh: "skipped (debugger attached)"`): that probe runs
`uname`, which would trip `__x64_sys_newuname`. Address your bridge with
`pry --instance qmu-<vm>` (`bridge_instance_id`; `bridge_pid` also works) on
a shared host. `snapshot save/load`, `system_reset` and `kill` invalidate
debugger state (stderr warnings) — the coherence table, KASLR re-slide,
watchpoints under KVM: `reference/debugging.md`. ARM guests:
`reference/cross-arch.md`.

## Raw QEMU access

```bash
qmu qmp query-status --vm X
qmu qmp device_del --vm X --args '{"id": "net0"}'
qmu monitor "info registers" --vm X
qmu monitor "x /16xg 0xffffffff81000000" --vm X
qmu qmp system_reset --vm X                # drops gdbstub breakpoints, re-slides KASLR
```

An HMP reply that *is* an error (`unknown command: …`, a line starting `Error: `)
is exit 1 `QMUError`; the same words inside data (a snapshot tagged
`Error:checkpoint`, a register dump) are output, exit 0 (text verbatim; JSON `output`).

## Shared-host rules

- Unique `--name` **and `--no-replace`** on every launch; `--vm` on every
  other command. Auto-selection picks the single running VM — a transient
  state another agent creates at any moment — and is never silent: stderr
  `[qmu] Auto-selected the only running VM 'X' (pass --vm to pin it).` plus
  JSON `autoselected: true`. `export QMU_REQUIRE_VM=1` turns it into exit 1
  (`--vm is required: QMU_REQUIRE_VM is set`) so a dropped `--vm` can never
  act on a sibling's VM.
- Never `prune --all` (qmu never recommends it; its no-running-VM hints name
  `qmu prune --vm <id>`, with `--all --dry-run` only as a preview).
  `prune --orphans` reaps **other agents'** record-less qmu VMs too — only
  after `--dry-run`.
- Every vm-less listing (`list`, `doctor`'s running count) is a snapshot of
  a host others are changing; never diff two listings to infer what *you*
  did — check `--vm X`.
- Isolation proof is ports/PIDs/`boot_id`, never `hostname -I`: slirp gives
  every guest `10.0.2.15`. SSH ports are recycled across agents within
  seconds of a VM dying — never cache a port outside qmu; `status --vm X`
  is the only current answer.
- `export QMU_TEMP_DIR=<private-root>/run` for launch, exec and transfers
  (keeps SSH multiplexing; the control-socket budget is 107 bytes on Linux).
  `kill` closes the VM's ControlMaster; `list`/`status`/`launch` probes
  never spawn one.
- Private writable images, build outputs and receipts; share only read-only
  inputs. With `--no-net` + a manual NIC pass `--ssh-port` explicitly.
- `pry` bridges are host-global: `pry --instance qmu-<vm>` (or `<pid>`).
- A matched marker or a green run is not a verified claim: `reference/evidence-contract.md`.

## Files on disk, the daemon, and MCP

State lives under `~/.cache/qmu/instances/` (`$QMU_CACHE_DIR`): `<name>.json`, `<name>.serial.log` (read via `qmu log`;
write-only — use SSH), `<name>.qmp.sock`, `<name>.qemu.log`. `kill` removes all four unless the guest is `crashed`/`panicked`
or `--no-clean` (then `prune --vm X`). Prune modes: `reference/cache.md`.
A per-user **daemon** (`<cache>/daemon.sock`, autostarted, idles out after 600 s) owns each running VM's one QMP connection: it observes
RESET/STOP/SHUTDOWN (`status`: `qmp: daemon`, `guest_epoch_source: observed`), proxies QMP so concurrent commands never see `busy`, and
wakes `wait` without polling; `QMU_DAEMON=off` disables it per process: `reference/daemon.md`. `qmu mcp serve` exposes every subcommand as an
MCP tool (`qmu_<sub>` / `qmu_<group>_<sub>`, plus `qmu_argv` for a raw argv) returning this same envelope with `qmu_exit` (the qmu process exit code) added, guest `exit_code` untouched — register once with `claude mcp add qmu -- qmu mcp serve`: `reference/mcp.md`.

## Reference files

Read on demand with `read skill://qmu/reference/<file>.md`:

| File | When |
|---|---|
| `reference/output-contract.md` | envelope shapes, result-style failures, `UsageError`, spilling, `--out`, `qmu --version` |
| `reference/launch.md` | every launch flag, profiles, `--drive`/`--no-net`/`--no-kvm`, state axes in depth, `kill`/`prune`/`list` rules |
| `reference/guest-commands.md` | `exec`/`run`/`compile`/`push`/`pull`/`dmesg` detail, `--cflags`, `rootfs inject/ls/cat/rm`, mkrootfs key-only SSH |
| `reference/wait.md` | bare `wait` semantics, `--pattern` scope and line rules, auto-clean |
| `reference/troubleshooting.md` | config layering/schema/validation, `config show`, `doctor` rows, libguestfs fix, auto-selection |
| `reference/evidence-contract.md` | before promoting a matched marker or a green run into a claim |
| `reference/boot-params.md` | `--append`/`--cmdline`/profile precedence, unknown-parameter lint |
| `reference/snapshots.md` | durable snapshots, passt, post-load behavior |
| `reference/debugging.md` | pry attach/halt semantics, bridge lifecycle, Debugger↔VM coherence |
| `reference/cross-arch.md` | aarch64/arm32 guests, `compile --host` toolchains, multiarch gdb |
| `reference/cache.md` | cache layout, `prune` modes, `cache du/ls` |
| `reference/daemon.md` | the per-user daemon: what it owns, autostart/`QMU_DAEMON`, `daemon status/stop`, stale socket |
| `reference/mcp.md` | `qmu mcp serve`: registration, tool naming, envelope + `qmu_exit`, resources, progress, limits |
