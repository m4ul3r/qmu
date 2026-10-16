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

## `exec` result

JSON: `vm_id`, `command`, `exit_code` (null when the command did not finish),
`stdout`, `stderr`, `timed_out`, `ssh_error`, `crash_detected`, `crash`,
`hint`. The exit code is the guest's (`exit 255` is 255, not a crash).

- `--timeout` (default 30 s; `run` 60 s): on expiry the envelope keeps the
  `stdout`/`stderr` captured so far, `exit_code: null`, `timed_out: true`,
  exit 124. The remote command is **not** killed in the guest.
- A kernel panic while the command runs is reported as exit 3 as soon as the
  serial log shows `Kernel panic - not syncing` (sub-second), with the partial
  `stdout`/`stderr` on the crash envelope — not after the SSH keepalive
  (15 s) and re-probes.
- A dropped transport with no fresh crash report is exit 4 (`ssh_error:
  true`, `crash_detected: false`).
- Against a `panicked` or `paused` guest (any QMP `running: false` state) the
  command refuses in under a second: exit 1, `guest_state: "panicked" |
  "paused"`, `hint` naming `qmu crash --vm X` / `qmu kill --vm X` or `qmu cont
  --vm X`. A debugger stop that fires mid-command gives the same `paused`.
- Text mode: `reference/output-contract.md` → *Guest-command text mode*.

## `run`

`qmu run` collapses `launch` → `exec` → `kill`; it takes every `launch` flag
(`--name`/`--no-replace` included) plus `--timeout`, `--keep`, and
`--qemu-arg` (repeatable; `--qemu-arg=-M --qemu-arg=virt` for dash-leading
values). `--harness`/`--no-wait-ssh` are exit 2: `--harness is not accepted:
run executes a guest command over SSH; for boot-and-die kernels use launch
--harness + wait + crash`.

| Exit | Meaning |
|---|---|
| `0` | guest command exited 0; VM reaped |
| `1` | guest command non-zero, or the VM died before SSH came up |
| `3` | terminal kernel panic (same discrimination as `exec`) |
| `124` | guest never answered SSH within `--ssh-timeout`, or the command outran `--timeout` on a reachable guest |

A clean run prints exactly what `exec` prints. Anything left to inspect — a
crash, a *survived* report (`kernel_warning`), a guest that never answered, a
boot failure, a timeout — keeps the metadata and `.serial.log` and prints on
stderr `VM 'X' stopped (state preserved)…`, `Inspect: qmu log --vm X --tail
200, or qmu crash --vm X`, `Clean up: qmu prune --vm X`. Exit 3 requires a
terminal panic; a boot that only logged a WARNING and never started sshd is
124 with the report under `kernel_warning`. `run -- id` ≈ 7 s end to end.

## `compile`

```bash
qmu compile --vm X exploit.c                        # push + gcc in the guest
qmu compile --vm X exploit.c --run --timeout 120
qmu compile --vm X exploit.c --cflags "-static -lpthread -DDEBUG=1"
qmu compile --vm X exploit.c --cflags '-static -DMSG=\"hello\"'   # string define, both paths
qmu compile --vm X exploit.c --host --run           # host cross toolchain, push the binary
qmu compile --vm X exploit.c --host --cc 'clang --target=aarch64-linux-gnu'
```

Default CFLAGS `-static -lpthread`. `--cflags` is spliced verbatim into the
remote `gcc` line (guest shell word-splits it, so `\"` reaches gcc as `"`);
the `--host` path splits it with `shlex`. A define whose value contains a
space (`-DMSG="hello world"`) survives neither. `--host` picks a cross
toolchain from the guest arch recorded on the instance — the only path when
the guest has no gcc, and several times faster than compiling inside a TCG
guest (`cross-arch.md`). JSON: `compile_cmd`, `compile_exit`, `compiled`,
`compiled_on`, `run_exit`, `run_stdout`, `run_stderr`, `crash_detected`; the
host path adds `compiler`, `guest_arch`. A lost transport during `--run` adds
`run_exit: null` with the partial `run_stdout`/`run_stderr`. Text mode prints
`Compiled and ran X:` on stderr and the run's stdout on stdout.

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
exit 4 keeps meaning the transport dropped or timed out (and 3, a fresh
crash). Both carry `vm_id`.

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
  filename is kept, so `./exploit:/root` lands at `/root/exploit`. Injected
  paths are owned by root (`0:0`), mode bits preserved. JSON `injected[]`
  items carry `path` (landed path) and `owner`; text `LOCAL -> /landed/path
  (owner 0:0)`. Exit 1 — nothing written — when the image, a LOCAL file, or
  (without `--mkdir`) the GUEST directory does not exist, or a running VM
  holds the image. A silent `mkdir` would turn `./exploit:/rooot` into a
  reported success while the stale binary stays in place: **verify after
  every inject** with `ls`/`cat`.
- `ls`: text is `mode uid gid size mtime name [-> target]` per entry (no
  `total` line); JSON `entries[]` of `{name, type, mode, uid, gid, size,
  mtime, target?}`.
- `cat`: text is the file's exact bytes (no added newline; binary passes
  through; large output spills to a `.bin`); JSON `content`, `size`,
  `encoding` (`utf-8` or `base64`).
- `rm`: exit 1 on a missing path unless `--force` (reported under `missing`),
  or a directory without `--recursive`.
- `ls`/`cat` are read-only and work while a VM runs; `inject`/`rm`/`shell`
  refuse an image a running VM holds and name the VM to kill.
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
`--emit-guest-setup PATH` writes the guest setup script for inspection.
