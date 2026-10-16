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
| run one command in the guest | `qmu exec --vm X "cmd"` | exit code = guest's; stdout = guest stdout |
| boot + run + reap in one call | `qmu run --name X --no-replace -- './exploit'` | exit code = guest's; `vm_id` for leftovers |
| compile and run a C exploit | `qmu compile --vm X exploit.c --run` | `compile_exit`, `run_exit`, `crash_detected` |
| copy a file in / out | `qmu push --vm X ./f /root/` · `qmu pull --vm X /root/out ./` | exit 0; 1 = caller error, 4 = transport |
| see what a VM is doing | `qmu status --vm X` (`qmu list` for all) | `status` (existence) and `guest` (usability) |
| get the crash report | `qmu crash --vm X` | `crash_detected: true`; else `qmu log --vm X --tail 200` |
| block until a serial marker | `qmu wait --vm X --pattern '^=+ results =+$' --timeout 120` | 0 match · 3 panic · 1 VM died · 124 timeout |
| boot-and-die kernel (no SSH) | `qmu launch --harness --no-reboot --name X --no-replace --kernel ./bzImage --initrd ./rd.img` → `qmu wait --vm X` | exit 0 + `crash` in `wait`'s own output |
| put files into an image offline | `qmu rootfs inject ./rootfs.img ./exploit:/root/` → `qmu rootfs ls ./rootfs.img /root` | the file is listed |
| rewind instead of rebooting | `qmu snapshot save clean --vm X` … `qmu snapshot load clean --vm X` | exit 0; `SnapshotError` → `reference/snapshots.md` |
| debug with gdb | `qmu launch --gdb --name X --no-replace` → `qmu gdb --vm X --symbols vmlinux` → `qmu cont --vm X` | read `reference/debugging.md` first |
| stop a VM | `qmu kill --vm X` | `logs_preserved: true` means a report is waiting in `qmu crash --vm X` |
| clean up state files | `qmu prune --vm X --dry-run` then without `--dry-run` | `pruned[]`; never `prune --all` on a shared host |
| diagnose the host/config | `qmu doctor` | `[!]` rows are blocking; `[~]`/`[i]` are not |

## Exit codes

Branch on the exit code and `ok`, never on the presence of `error`.

| Code | Meaning | JSON key to read | Next command |
|---|---|---|---|
| `0` | success; for `wait --pattern` the regex matched, for bare `wait` QEMU exited | `ok: true`; `matched_line`, `reason` | continue |
| `1` | operation failed: guest command non-zero, no/bad `--vm`, `doctor` unhealthy, `SnapshotError`, `SCPFileError`, `ConfigError`, paused/panicked guest refusal, `wait --pattern` outlived the VM, `crash` found nothing | `error_type` (exception paths) or domain keys (`exit_code`, `guest_state`, `crash_detected`, `reason`) | read the `hint`; for a refusal, `qmu crash --vm X` / `qmu cont --vm X` |
| `2` | usage error (argparse) ONLY; `error_type: "UsageError"` under JSON | `usage`, stderr hint | fix the flags — e.g. quote the guest command |
| `3` | guest kernel crash, always corroborated by a fresh serial crash report | `crash`, `crash_detected: true`, `guest: "panicked"` | `qmu crash --vm X` → `qmu kill --vm X` |
| `4` | transport/infra: `SSHError`/`QMPError`, launch SSH-readiness timeout, `no-console-output`, dropped SSH with NO fresh crash, `wait --pattern` `inconclusive`, internal error | `error_type`, `inconclusive`, `ssh_status` | `qmu status --vm X`, `qmu log --vm X --tail 200` |
| `124` | timeout: `wait` elapsed, `run` never reached SSH, `exec`/`run`/`compile --run` outran `--timeout` on a reachable guest | `timed_out: true`, `reason: "timeout"`, partial `stdout`/`stderr` | raise `--timeout`; check `crash` on a bare `wait` |

Detail (envelope shapes, result-style failures, spilling): `reference/output-contract.md`.

## Recovery: symptom → meaning → command

| Symptom | Meaning | Do |
|---|---|---|
| `guest: "panicked"` (`[running — GUEST PANICKED]`) | terminal `Kernel panic - not syncing`; the guest is gone, QEMU still runs | `qmu crash --vm X`, then `qmu kill --vm X` (logs kept) |
| `guest: "crashed"` | an Oops killed one task; the guest still serves | `qmu crash --vm X`; do **not** reap |
| `guest: "paused"` | vCPU halted (`qmu gdb`, debugger stop, unclean bridge death) | `qmu cont --vm X` (or resume through pry) |
| `guest: "unknown"` + `guest_detail` | no positive evidence of a serving guest (`SSH down, 0 bytes of console output`) | `qmu log --vm X --tail 50`; wrong `console=`/arch? see `warnings[]` |
| `qmp: "busy"`, `qemu_status: "unknown"` | another client holds QEMU's single QMP slot (old `wait`, debugger bridge, wedged `savevm`) | wait for it; `qmu kill --vm X` still works (signals after 1 s) |
| `qmp: "unreachable"` with pid alive | socket gone or hung (a concurrent `list` can also report this for a slot another client holds) | `qmu status --vm X` again; `qmu kill --vm X` falls back to signals |
| `ssh: "none"` / SSH command refuses naming no endpoint | `--harness` or `--no-net` without `--ssh-port` | use `log`/`wait`/`crash`/`qmp`; relaunch with `--ssh-port N` |
| `ssh: "skipped"` | guest paused/panicked, so SSH was not probed | see the `guest` row above |
| `ssh_status: "no-console-output"` (launch exit 4) | serial log still empty after 10 s: wrong `console=` or `-M`/`-cpu` for the arch | VM is retained: `qmu log --vm X`; fix the cmdline (`ttyS0` x86, `ttyAMA0` arm) |
| `[qmu] Warning: 'console=…' names …` / `'root=/dev/sda' names …` | arch-cmdline lint (also in launch `warnings[]`) | fix before trusting a silent console |
| `[!] kernel: ./bzImage (CHANGE ME placeholder; not found)` | the starter `qmu.toml` was never edited | set `[boot] kernel`; `[!]` rows drive exit 1 |
| `Hint: quote the guest command … or put -- before it` (exit 2) | unquoted dash-word in `exec`/`run` | `qmu exec --vm X 'uname -a'` or `qmu exec --vm X -- uname -a` |
| `inconclusive: true` (`wait --pattern`, exit 4) | the serial log could not be read; not a no-match | fix the log path/permissions; never record as negative |
| `logs_preserved: true` from `kill` | a crash report is waiting | `qmu crash --vm X`; `qmu prune --vm X --older-than 0` when done |
| `held_back` in `prune` | a log-only remnant younger than `--older-than` (24 h) | `qmu prune --vm X --older-than 0` |
| `reason: "already_stopped"` (bare `wait`, exit 0) | QEMU had exited before the wait began | read `crash` from this result |
| `error_type: "SCPFileError"` (exit 1) | missing local file, a directory, bad remote dir | fix the path; archive directories first |
| `error_type: "SnapshotError"` (exit 1) | HMP refused (`load`/`delete` of a missing name, bad `save` name); guest resumed | `qmu snapshot list --vm X`; `reference/snapshots.md` |
| `error_type: "ConfigError"`, `errors[]` | every schema problem in the file, with `source`/`key`/`hint` | fix all listed keys; cleanup commands are blocked until it parses |
| `A debugger client is already attached to port N (pry bridge pid P)` | the stub serves one client; `qmu gdb` spawned nothing | reuse it (`pry --instance P`) or `pry kill --instance P` |
| `[qmu] Output spilled to <path> (~N tokens)` | result exceeded ~10k tokens; text shows the first 40 lines | read `<path>` (`artifact_path` under JSON) |

## Bootstrap a project

```bash
qmu doctor            # [!] = blocking, [~] = warning, [i] = info; "Run: qmu config init" if no config
qmu config init       # starter qmu.toml; the three `# CHANGE ME` lines are live (no uncommenting)
qmu doctor            # kernel, rootfs image, SSH key, SSH key permissions all [+]
qmu config show       # resolved values, each tagged [built-in | global | project | --config | flag]
```

Edit `[boot] kernel`, `[drive] rootfs`, `[ssh] key` (relative paths resolve
from the config file's directory; `~` works). Boot-and-die kernels skip
`[drive]`/`[ssh]` — `doctor` marks them `[~] not needed for --harness boots`.
Config layering, the full schema, `ConfigError`, `config show` JSON (`sources`
per key, `layers`, `paths`): `reference/troubleshooting.md`.

## Launch and lifecycle

```bash
qmu launch --name X --no-replace                                    # [boot] kernel from qmu.toml
qmu launch --name X --no-replace --kernel ./bzImage --profile trigger-test   # panic_on_warn=1
qmu launch --name X --no-replace --append "slub_debug=- nokaslr"    # ADD params
qmu launch --name X --no-replace --cmdline "console=ttyS0 root=/dev/sda nokaslr"  # REPLACE cmdline
qmu launch --name X --no-replace --gdb --memory 8G --cpus 4 --cpu host
qmu launch --name X --no-replace --inject ./exploit:/root/ --partition 0   # bake a file in first
qmu launch --name X --no-replace --no-reboot                        # panic exits QEMU instead of rebooting
qmu list                                   # existence + guest state for every VM
qmu status --vm X                          # fast (<1 s); `qmu show` is an alias
qmu kill --vm X                            # QMP quit, then SIGTERM; keeps logs when a report is waiting
qmu kill --vm X --no-clean                 # keep .json + .serial.log for forensics
qmu prune --vm X --dry-run                 # preview; then drop --dry-run
qmu prune --orphans --dry-run              # qmu-launched QEMUs no record claims (would_kill[].vm_id)
```

Launch success includes SSH readiness: exit 4 (`SSHError`) retains the VM for
`qmu log --vm X`. JSON carries `vm_id`, `ssh_status`, `warnings[]` (every
stderr warning), `config_sources[]`, `replaced` (`{vm_id, pid}` or null),
`kvm`, `profile_applied`, `unknown_kernel_params_by_source.operator` (gate on
this; the `profile` bucket is noise). `--append` adds, `--cmdline` replaces
(keep `root=`); a CLI `--profile` overrides a config `[boot] cmdline` and
lists the dropped params. `--inject` validates image, file and guest dir
before touching a same-named running VM. Default `--name` replaces a running
VM of that name; `--no-replace` makes it exit 1. Flags, profiles, `--drive`,
`--no-net`, `--no-kvm`, the two state axes, `kill`/`prune` rules:
`reference/launch.md`.

**Two state axes, never collapsed.** `status` (existence): `running` ·
`orphaned` · `stopped` · `absent`. `guest` (usability): `serving` · `paused`
· `crashed` · `panicked` · `unknown`. `serving` needs positive evidence
(sshd answered, or console output in this boot); otherwise `unknown` with a
`guest_detail`. Under the default `exploit-dev` profile a KASAN-detected bug
is terminal (`kasan.fault=panic` → `panicked`); a plain non-KASAN Oops lands
on `crashed` and must not be reaped. `--profile exploit-test` makes every
Oops terminal; `--append kasan.fault=report` survives KASAN reports.

## Iterate loop (no working SSH needed)

```bash
qmu launch --name poc --no-replace --inject ./exploit:/root/ --append "slub_debug=-"
qmu wait --vm poc --pattern '^=+ results =+$' --timeout 120   # 0 match, 3 panic, 1 died, 124 timeout
qmu log --vm poc --grep "leaked|OOB|UAF" --context 3           # --grep searches the WHOLE log
qmu log --vm poc --full --out ./evidence.log                   # whole log to a file
```

Never hand-poll the serial log (`until grep …; do sleep; done` hangs on a
panic or a dead VM). Anchor the marker (`'^=+ results =+$'`): an unanchored
word also matches the kernel's echo of the cmdline. The scan starts at the
latest boot banner (`scan_offset`/`scan_scope`). An unterminated fragment
(`login:`) matches once the console idles for one poll. A *survived* Oops
does not abort the wait; `--ignore-crash` suppresses even the terminal
abort — do not paste it reflexively. Exit 0 proves the regex matched, not the
claim in its text (`reference/evidence-contract.md`). Full rules:
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

Text mode: stdout is the guest's stdout **only**; guest stderr goes to
stderr, followed by `[exit code: N]` only when N ≠ 0 (`exec true` prints
nothing). JSON: `vm_id`, `exit_code` (null if unfinished), `stdout`,
`stderr`, `timed_out`, `crash_detected`, `crash`. One argument is passed to
the guest shell verbatim; several are shell-quoted and joined; an unquoted
dash-word (`uname -a`) is exit 2 with a hint. `--timeout` keeps the partial
output (exit 124; the remote command is not killed). A panic mid-command is
exit 3 within a second (serial watcher), not after the SSH keepalive. Against
a `panicked`/`paused` guest every SSH command refuses in under a second (exit
1, `guest_state`). `compile --host`, `--cflags` quoting, `--cc`:
`reference/guest-commands.md` and `reference/cross-arch.md`.

## One-shot runs

```bash
qmu run --name X --no-replace -- './exploit'                  # launch → exec → kill
qmu run --name X --no-replace --timeout 120 --keep -- './exploit --spray'   # --keep leaves it up
qmu run --name X --no-replace --kernel ./bzImage --profile exploit-test -- './exploit'
```

Exit code is the guest command's: `0`/`1`; `3` terminal panic; `124` the guest
never answered SSH within `--ssh-timeout` or the command outran `--timeout`
(default 60 s). A clean run reaps the VM; anything left to inspect (crash,
survived report under `kernel_warning`, timeout, boot failure) keeps it and
prints `Inspect: qmu log --vm X --tail 200, or qmu crash --vm X` / `Clean up:
qmu prune --vm X` on stderr. Raw QEMU args: `--qemu-arg=-M --qemu-arg=virt`.
`--harness`/`--no-wait-ssh` are exit 2 (`run` needs SSH). ≈7 s end to end.

## Crash triage

```bash
qmu crash --vm X                 # last crash in the current boot; works on a stopped VM
qmu crash --vm X --full-history  # across snapshot/reset epochs and earlier boots
qmu log --vm X --tail 200        # raw serial tail when crash finds nothing
qmu kill --vm X                  # after reading; logs stay (logs_preserved: true)
qmu prune --vm X --older-than 0  # finally drop the retained logs
```

`crash` exit 0/`crash_detected: true` means a report was found, not that the
VM is healthy; "no crash" is exit 1 with `crash_detected: false` and no
`error`. Detects KASAN, BUG/Oops, panic, GPF, UBSAN, slab UAF and more.
Command-attributed crashes (`exec`, `compile --run`) use only bytes appended
after the command began.

## Harness mode (boot-and-die kernels)

```bash
qmu launch --harness --no-reboot --name X --no-replace --kernel ./bzImage --initrd ./ramdisk.img \
  --drive 'file=./rootfs.img,if=virtio,readonly,format=raw' \
  --cmdline 'console=ttyS0 root=/dev/vda1 ro init=/run.sh'
qmu wait --vm X --timeout 300          # 0 exited (crash in this output), 3 panicked-but-running, 124, 4
qmu wait --vm X --no-clean             # keep .serial.log after a confirmed exit
qmu log --vm X --tail 100              # SSH commands refuse; serial/QMP commands work
```

`--harness` implies `--no-wait-ssh --no-net` and skips the rootfs/SSH-key
requirement (a config `[drive] rootfs` is still attached; prefer `--harness
--rootfs ./img`). `--no-reboot` stops a `panic=N` kernel from rebooting into a
fresh boot that buries the report. Bare `wait` polls QMP every 0.5 s with
short-lived connections; its JSON carries `reason` (`process_exited` ·
`already_stopped` · `terminal_panic` · `timeout`), `stopped`, `crash`,
`guest`, `guest_detail`, `qmp`, `last_event`. Exit 3 = terminal panic while
QEMU still runs (`qmu kill --vm X` keeps the report). Harness VMs are
auto-cleaned only after a confirmed exit — read `crash` from `wait`'s own
output. Semantics: `reference/wait.md`.

## Snapshot-rewind loop

```bash
qmu launch --name dev --no-replace
qmu push --vm dev ./exploit /tmp/x
qmu snapshot save clean --vm dev            # in-session checkpoint (works with the default raw image)
for i in 1 2 3; do
  qmu exec --vm dev /tmp/x
  qmu log --vm dev --tail 200 --out runs/run-$i.log
  qmu snapshot load clean --vm dev          # rewind; first exec after load is fast
done
qmu snapshot list --vm dev
qmu snapshot delete clean --vm dev
```

Checkpoints die with QEMU; a name is one token; a failed `load` resumes the
guest (`resumed: true`). Durable qcow2 snapshots, passt, and the baked-`int3`
debugger trap: `reference/snapshots.md`.

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
`guest_state: "paused"`). Address your bridge with `pry --instance <pid>` on
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

## Shared-host rules

- Unique `--name` **and `--no-replace`** on every launch; `--vm` on every
  other command (auto-selection needs exactly one running VM).
- Never `prune --all`; `prune --orphans` only after `--dry-run`.
- `export QMU_TEMP_DIR=<private-root>/run` for launch, exec and transfers
  (keeps SSH multiplexing; the control-socket budget is 107 bytes on Linux).
- Private writable images, build outputs and receipts; share only read-only
  inputs. With `--no-net` + a manual NIC pass `--ssh-port` explicitly.
- `pry` bridges are host-global: `pry --instance <pid>`.
- A matched marker or a green run is not a verified claim:
  `reference/evidence-contract.md`.

## Files on disk

State lives under `~/.cache/qmu/instances/` (`$QMU_CACHE_DIR`):
`<name>.json` (metadata), `<name>.serial.log` (read via `qmu log`),
`<name>.qmp.sock`, `<name>.qemu.log`. `kill` removes all four unless the guest
is `crashed`/`panicked` (logs kept) or `--no-clean`; `prune --vm` removes the
rest (`--keep-logs` spares the logs). The serial log is write-only — use SSH
for interactive work. Cache subtrees and every prune mode: `reference/cache.md`.

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
