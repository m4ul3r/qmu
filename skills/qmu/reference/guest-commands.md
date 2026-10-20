# Guest commands: `exec`, `run`, `compile`, `push`/`pull`, `dmesg`, `rootfs`

Companion to `skill://qmu`. The one-line forms are in the main skill; this
file is the argv rules, the envelope keys, the crash/timeout behaviour, and
the offline `rootfs` tools.

## Command argv (`exec`, `run`)

One positional argument is handed to the guest shell verbatim — quote it to
use pipes and redirects. Several arguments are shell-quoted and joined
(`qmu exec --vm X echo hi` runs `echo hi`). Unquoted dash-words belong to qmu
unless they follow a bare `--`, so `qmu exec --vm X uname -a` is exit 2 with
`Hint: quote the guest command ('uname -a') or put -- before it (qmu exec --
uname -a); qmu flags may appear anywhere.` qmu flags (`--vm`, `--timeout`,
`--format`, `--out`) may appear before or after the command.

```bash
qmu exec --vm X 'cat /proc/slabinfo | grep kmalloc-192'
qmu exec --vm X -- uname -a
qmu exec --vm X "./exploit" --timeout 120 --format json
```

## Running as an unprivileged user (`--user`)

"Can an unprivileged user do X" is answered with `--user NAME` on `exec`,
`run` and `compile --run`: qmu logs in as the VM's SSH user (keep it `root`)
and drops to NAME with `runuser -u NAME -- sh -c '<command>'` (`su -s /bin/sh
NAME -c …` on a BusyBox guest without `runuser`), starting in NAME's home
directory (`/` if it has none). The exit status is the command's (`exit 7` →
`exit_code: 7`); wherever an envelope carries `command` (`run`, a timeout, a
lost session) it is the command as given, not the wrapper; `run_as` names the
account on every path (it is the SSH user when `--user` is absent). `compile
--run --user NAME` builds into `/tmp/`
instead of `/root/` (unreadable to NAME); `--user` without `--run` is exit 1.
The account must exist in the image (`runuser: user NAME does not exist` is
the guest's own stderr, exit 1).

```bash
qmu exec --vm X --user nobody -- id                     # uid=65534(nobody) …
qmu compile --vm X poc.c --run --user ubuntu --timeout 60
```

Do not set `[ssh] user` to an unprivileged account for this: it is fixed at
launch, and an account sshd refuses ends `launch` with `ssh_status:
"auth-failed"` (below).

## `exec` result

JSON keys present on **every** path that started the command: `vm_id`,
`exit_code` (null when the command did not finish), `ssh_error`,
`crash_detected`, `run_as` (the account the command ran as: `--user`, else
the SSH user). The rest depend on the path (the preflight refusals are
below):

| path | qmu exit | extra keys |
|---|---|---|
| command finished (any guest code) | 0 / 1 | `stdout`, `stderr`, `kernel_warning_detected`, `kernel_warning` (the kernel report the command produced — a *survived* KASAN/WARNING/Oops — or `null`), `hint` only when non-zero |
| `--timeout` expired, guest still answers | 124 | `timed_out: true`, `timeout`, `command`, partial `stdout`/`stderr`, `hint` |
| transport lost / terminal panic | 3 (fresh report) / 4 | `command`, `crash` (report or `null`), `hint`, partial `stdout`/`stderr` |
| vCPU halted mid-command | 1 | `command`, `guest_state`, `qemu_status`, `hint`, partial `stdout`/`stderr` |

A report the guest **survived** is attributed to the command only through
`kernel_warning_detected`/`kernel_warning`: on that path `crash_detected` is
`false` and there is no `crash` key, so under `kasan.fault=report` branch on
`kernel_warning_detected`. `timed_out` and `command` are absent from a
finished command's envelope (read `env.get("timed_out")`). `stdout_lossy`/
`stderr_lossy: true` appear only when invalid UTF-8 was replaced.

qmu's own exit is **not** the guest's: it is 0 when the guest command
exited 0 and 1 when it exited non-zero, with the guest's code preserved only
in `exit_code` (`exit 255` → qmu exit 1, `exit_code: 255`, `ok: false`,
`ssh_error: false`, `crash_detected: false` — not a crash; 3 always needs a
fresh serial report). The reserved codes 2/3/4/124 are never guest values.
A kernel report printed while the command ran — on every path, including a
completed command whose guest survived an Oops — is `crash_detected: true`
with the report in `crash`: the same event `status` calls `crashed` and `qmu
crash` returns (the command's exit stays 0/1 when it completed). A completed
command (and `run`'s boot failure) also keeps the older `kernel_warning` /
`kernel_warning_detected` keys, carrying the same report.

- Output is **streamed**: in text mode guest stdout/stderr reach the host's
  stdout/stderr as the guest writes them (`for i in 1 2 3; do echo $i; sleep
  1; done` prints one line per second, not three after 3 s), byte-exact, with
  `[exit code: N]` after the command ends; `--format ndjson` emits
  `{"event": "chunk", "stream": …, "data": …}` lines before the final
  envelope; `--format json` buffers. Partial output on `--timeout` / a panic
  is therefore already on the terminal when the 124 / 3 narrative arrives.
  Detail, `--out` and the spill cut-over: `output-contract.md` → *Streaming*.
- `--timeout` (default 30 s; `run` 60 s): on expiry the envelope keeps the
  `stdout`/`stderr` captured so far, `exit_code: null`, `timed_out: true`,
  exit 124 — whether or not the guest still answers. One readiness probe
  (≤2.25 s, the one `status` runs) sets `ssh_error: true` and the hint when
  it does not (a `kasan_multi_shot` report flood wedges the console, a hang),
  and `crash` carries the newest report the command provoked; only a terminal
  panic (3) or a halted vCPU (1) outranks the timeout. A held QMP
  slot (debugger bridge, another command) does not defeat the deadline: the
  watcher's QMP probe runs off the deadline thread, so the result is 124
  within ~N+0.3 s of the command starting (the pre-command QMP preflight may
  itself spend its 2 s busy budget first), plus that probe. The budget wins outright: a guest
  command that finishes *after* the deadline — even while that bounded probe
  was blocked — is still 124, `timed_out: true`, never a late `ok: true`.
- The deadline kills the guest command's session: the command dies of
  SIGPIPE on its next stdout/stderr write (a command that stays silent, or a
  child it backgrounded, survives). A debugger stop does **not** (below).
  Detach anything that must outlive the step regardless: `qmu exec --vm X
  'setsid nohup ./poc > /root/poc.log 2>&1 < /dev/null &'`, then read
  `/root/poc.log`.
- A kernel panic while the command runs is reported as exit 3 as soon as the
  serial log shows `Kernel panic - not syncing` (sub-second), with the partial
  `stdout`/`stderr` on the crash envelope — without waiting on ssh or a
  re-probe.
- A dropped transport with no fresh crash report is exit 4 (`ssh_error:
  true`, `crash_detected: false`). So is ssh never reaching the guest at all
  (`Connection timed out during banner exchange` right after a boot or
  reboot): `exit_code: null`, text `SSH could not connect; the command was
  not started`, safe to re-run — never "the guest command exited 255".
- A guest that stops answering without a panic or a halt (wedged) holds the
  command until `--timeout` (124); ssh itself never gives up on silence.
- sshd refusing the VM's recorded `[ssh] user`/key (`Permission denied
  (publickey,…)`) is exit 4 `error_type: "SSHAuthError"` with `ssh_status:
  "auth-failed"`, `ssh_user`, `ssh_key` and a relaunch `hint` — on `exec`,
  `compile`, `dmesg`, `push`/`pull` alike — never "unreachable".
- Against a `panicked` or `paused` guest (any QMP `running: false` state) the
  command refuses in under a second: exit 1, `guest_state: "panicked" |
  `"paused"`, `hint` naming `qmu crash --vm X` / `qmu kill --vm X` or `qmu cont
  --vm X` (for `qemu_status: "restore-vm"` the hint is a known-good `snapshot
  load` or `kill` + relaunch instead — never `cont`). A debugger stop that
  fires mid-command returns within ~1 s with the same `paused` envelope —
  never a keepalive wait — and the output that reached the host
  before the stop (bytes the guest wrote just before it may still be in the
  guest). For `exec`, `run` and `compile --run` the command is **left
  running**: qmu keeps its SSH session open (`text`: `vCPU halted while
  running (command left running)`) and a detached helper appends its further
  output to the file named by `detached_output`, so the trigger continues
  after `pry continue` / `qmu cont` (measured with a 130 s halt; the
  connection stays up however long the vCPU is stopped, at most 16 MiB of output is
  kept). What still ends it is the SSH connection going away: `snapshot
  load`, a reset and `kill` drop the ControlMaster — use the `setsid nohup`
  form for a trigger that must survive those. `compile`'s gcc step and
  `dmesg` are aborted (their session closed).
- Text mode: `reference/output-contract.md` → *Guest-command text mode*.

## `run`

`qmu run` collapses `launch` → `exec` → `kill`; it takes every `launch` flag
(`--name`/`--no-replace`/`--forward` included) plus `--timeout`, `--keep`, `--user`, and
`--qemu-arg` (repeatable; `--qemu-arg=-M --qemu-arg=virt` for dash-leading
values). `--harness`/`--no-wait-ssh` are exit 2: `--harness is not accepted:
run executes a guest command over SSH; for boot-and-die kernels use launch
--harness + wait + crash`.

| Exit | Meaning |
|---|---|
| `0` | guest command exited 0; VM reaped |
| `1` | guest command non-zero, or the VM died before SSH came up |
| `3` | terminal kernel panic (same discrimination as `exec`) |
| `4` | sshd answered and refused the `[ssh] user`/key (`error_type: "SSHAuthError"`, `ssh_status: "auth-failed"`; within ~5 s, not after `--ssh-timeout`) |
| `124` | guest never answered SSH within `--ssh-timeout`, or the command outran `--timeout` |

A clean run prints exactly what `exec` prints. Anything left to inspect — a
crash, a *survived* report (`crash_detected: true`, `crash`, exit unchanged),
a guest that never answered, a boot failure, a timeout — keeps the metadata
and `.serial.log` and prints on stderr `VM 'X' stopped (state preserved)…`,
`Inspect: qmu log --vm X --tail 200, or qmu crash --vm X`, `Clean up: qmu
prune --vm X`. Exit 3 requires a terminal panic; a boot that only logged a
WARNING and never started sshd is 124 with `crash_detected: true` and the
report in `crash`. `run -- id` ≈ 7 s end to end.

## `compile`

```bash
qmu compile --vm X exploit.c                        # push + gcc in the guest
qmu compile --vm X exploit.c --run --timeout 120
qmu compile --vm X exploit.c --cflags "-static -lpthread -DDEBUG=1"
qmu compile --vm X exploit.c --cflags '-static -DMSG=\"hello\"'   # string define, both paths
qmu compile --vm X exploit.c --host --run           # host cross toolchain, push the binary
qmu compile --vm X poc.c --run -- /tmp/target 1 DATA  # argv for the program
qmu compile --vm X exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

Default CFLAGS `-static -lpthread`. `--cflags` is spliced verbatim into the
remote `gcc` line (guest shell word-splits it, so `\"` reaches gcc as `"`);
the `--host` path splits it with `shlex`. A define whose value contains a
space (`-DMSG="hello world"`) survives neither. `--host` picks a cross
toolchain from the guest arch recorded on the instance — the only path when
the guest has no gcc, and several times faster than compiling inside a TCG
guest (`cross-arch.md`). Arguments after the source (put `--` first when one
starts with a dash) are the program's argv under `--run`, **one argument
each** (shell-quoted, so `'two words'` stays one); they are refused (exit 1)
without `--run`. JSON: `compile_cmd`, `compile_exit`, `compiled`,
`compiled_on`, `run_exit`, `run_stdout`, `run_stderr`, `run_args`,
`crash_detected`; the host path adds `compiler`, `guest_arch`. `--timeout`
bounds the **run**: on
expiry the exit is 124 (not 4) with `timed_out: true`, `run_exit: null`, the
partial `run_stdout`/`run_stderr`, `ssh_error` from one readiness probe, and a
`hint` (`Guest command exceeded --timeout (Ns) but the guest is still
answering SSH …` when it is). A report the run provoked is `crash_detected`/
`crash` exactly as for `exec`. A lost transport during
`--run` likewise keeps `run_exit: null` with the partial streams
(`run_stdout_lossy` when bytes were replaced). Text mode prints `Compiled and
ran X:` on stderr and the run's stdout on stdout, byte-exact and streamed as
the program writes it (compile diagnostics are not streamed).

After **any** suspected panic, including a bare `[exit code: 255]`, confirm
with `qmu crash --vm X`. A `panic=N` guest reboots instead of staying down;
the crash is still exit 3 with the report, but later output belongs to a new
boot.

## `push` / `pull`

```bash
qmu push --vm X exploit.c                  # → /root/
qmu push --vm X exploit.c /tmp/exploit.c   # destination file name
qmu push --vm X exploit.c /tmp/            # trailing / = into that directory
qmu pull --vm X /root/output.txt           # → CWD
qmu pull --vm X /root/output.txt ./results/
```

`push` transfers ONE regular file (archive directories first). A caller error
— missing local file, a directory, missing remote directory, permission
denied, any scp exit ≠ 255 — is exit 1 with `error_type: "SCPFileError"`, so
exit 4 keeps meaning the transport dropped or timed out. A terminal panic
appended to the serial log since the step began is that step's outcome:
exit 3 with `crash`, exactly as for `exec` — a sysrq panic in the middle of
a multi-GiB `push` aborts scp within a second and returns the report, not a
bare `SSHAborted`/exit 4. The same rule covers every watched SSH step of
`compile` (source push, in-guest `gcc`, host-build delivery and `chmod`). An
scp *timeout* with no fresh panic stays 4 `SSHError`; a halted vCPU is the
paused envelope, exit 1. All carry `vm_id`.

A guest with no SFTP server (Dropbear/BusyBox firmware: `sh:
/usr/libexec/sftp-server: No such file or directory`; an OpenSSH sshd whose
`sftp-server` is missing, which the client reports only as a bare `scp:
Connection closed`; an sshd without `Subsystem sftp`) is retried once in the
legacy protocol (`scp -O`), which such guests speak; nothing to configure.
A dropped or refused connection names itself and is not retried. Only when
the retry fails too is it an error, naming both attempts (exit 1
`SCPFileError` when the guest has no `scp` either, with a hint to inject one).

## `dmesg`

`qmu dmesg --vm X [--tail N]` reads the guest's dmesg over SSH; text prints
`(empty dmesg)` / `[dmesg failed, exit N] …` on stderr. With no SSH read the
serial console instead: `qmu log --vm X --tail N` (`--grep`/`--context`/
`--full` too).

## Offline rootfs editing (`qmu rootfs`, libguestfs)

When SSH is not up, this — not `sudo mount`/`cp`/`umount` — is how files get
into the guest. It needs libguestfs; `qmu doctor` checks it
(`troubleshooting.md` → *libguestfs prerequisite*).

```bash
qmu rootfs inject ./rootfs.img ./exploit:/root ./run.sh:/      # LOCAL:GUEST, GUEST is a DIRECTORY
qmu rootfs inject ./rootfs.img ./exploit:/root --partition 0   # whole-disk image (mkrootfs, cloud images)
qmu rootfs inject ./rootfs.img ./exploit:/new/dir --mkdir      # create GUEST if absent
qmu rootfs ls   ./rootfs.img /root                             # verify what landed
qmu rootfs cat  ./rootfs.img /root/run.sh                      # byte-exact
qmu rootfs rm   ./rootfs.img /root/marker                      # GUEST_PATH is the file itself
qmu rootfs rm   ./rootfs.img /tmp/workdir --recursive
qmu rootfs rm   ./rootfs.img /root/maybe --force               # tolerate a missing path
qmu rootfs shell ./rootfs.img                                  # interactive guestfish
```

- `inject`: GUEST is a directory (with or without trailing `/`); the local
  filename is kept, so `./exploit:/root` lands at `/root/exploit`. Exactly
  the paths this injection copied are re-owned to root (`0:0`) with `lchown`
  — a symlink is re-owned itself, never its target, so a dangling link or a
  link to an existing guest file is fine — and each non-link path then gets
  its source mode back, **special bits included** (a `6755` fixture lands as
  `6755`, not `0755`). Files already in the destination from the image or an
  earlier inject keep their owner. JSON `injected[]` items carry `path`
  (landed path) and `owner`; text `LOCAL -> /landed/path (owner 0:0)`. Exit
  1 — nothing written — when the image, a LOCAL file, or (without `--mkdir`)
  the GUEST directory does not exist, or a running VM holds the image. A
  silent `mkdir` would turn `./exploit:/rooot` into a reported success while
  the stale binary stays in place: **verify after every inject** with
  `ls`/`cat`.
- `ls`: text is `mode uid gid size mtime name [-> target]` per entry (no
  `total` line), sorted by name; JSON `entries[]` of `{name, type, mode, uid,
  gid, size, mtime, target?, name_bytes_b64?, target_bytes_b64?}`. Names and
  link targets are exact bytes end to end — newlines, carriage returns,
  quotes, backslashes, non-ASCII and a target such as `/etc/passwd` all come
  back as written (a CR-named and an LF-named file are two distinct
  entries, never merged or duplicated). When a name/target is not valid
  UTF-8, `name`/`target` is a lossy U+FFFD decode and `name_bytes_b64` /
  `target_bytes_b64` carries the exact bytes; both keys are absent
  otherwise. Text mode escapes control characters (`\r`, `\n`, `\t`, else
  `\xNN`) and shows U+FFFD for non-UTF-8.
- `cat`: text is the file's exact bytes (no added newline; binary passes
  through; large output spills to a `.bin`); JSON `content`, `size`,
  `encoding` (`utf-8` or `base64`).
- `rm`: exit 1 on a missing path unless `--force` (reported under `missing`),
  or a directory without `--recursive`.
- `ls`/`cat` are read-only and work while a VM runs; `inject`/`rm`/`shell`
  refuse an image a running VM holds and name the VM to kill. `ls` is one
  guestfish session (~1.5 s: the appliance boot is the whole cost; it used
  to boot twice).
- `--partition N` defaults to `1`; images from `tools/mkrootfs.sh`,
  `qmu-linux-rootfs` and Debian cloud images are whole-disk ext4 →
  `--partition 0`. A wrong value errors naming the partitions found.

`qmu launch --inject LOCAL:/guest/dir` runs the same injection against the
configured rootfs right before boot (repeatable; `--partition`/`--mkdir`
apply; targets are validated before any running VM is replaced).

## mkrootfs images and SSH

Images from `tools/mkrootfs.sh` accept root over SSH **by key only**
(`PermitRootLogin prohibit-password`, `PasswordAuthentication no`, root
password locked); only the generated or `--ssh-key` key is authorized. The
serial console auto-logs in as root. The image carries `/etc/qmu-rootfs.json`
(`sshd_policy: "key-only"`) and the build stamp `sshd_policy=key-only`. A
cached image built before that policy is permissive: rerun
`tools/mkrootfs.sh` (an unstamped legacy image needs `--no-cache`).
`qmu doctor` checks the configured `[drive] rootfs` when libguestfs works,
by measurement rather than by the stamp alone: `[~] rootfs sshd policy:
permissive — root's password is empty and sshd_config sets
PermitEmptyPasswords yes and PermitRootLogin yes, …` (JSON `sshd_policy:
"permissive"`, non-blocking) is the legacy setup — **any** key then logs in
as root, so a sibling VM's key reaches your guest. A current image is `[+]
key-only`; a `tools/mktarget.sh` target (`/etc/qmu-target.json`) is `[+]
key-only (tools/mktarget.sh target, …)`; an image neither tool built is
`[i] unknown — no qmu stamp …`, with no claim either way. `--emit-guest-setup
PATH` writes the guest setup script for inspection.
