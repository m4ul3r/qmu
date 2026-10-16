# `qmu wait`: harness exit semantics and `--pattern` scoping

Companion to `skill://qmu`. The launch recipe and the one-line forms are in the
main skill; this file is the exact exit semantics of `qmu wait` without
`--pattern`, the auto-clean rule, the disk/`-no-reboot` details, and the
line/scope rules that decide whether `--pattern` can ever match.

## `--pattern` matching rules

`--pattern` is a Python regex matched per **complete line**:

- **Anchor it.** An unanchored marker (`--pattern "results"`) also matches the
  kernel's echo of the command line (`[    0.000000] Command line: … run=results`
  — verified live: that is the line an unanchored wait matched) and any log
  line that mentions the word. Use
  `--pattern '^=+ results =+$'` (or `'^=+ QMU-BOOT-DONE =+$'` for the firmware
  probe template).
- **A line needs its newline.** A line is only offered to the matcher once its
  terminator has arrived. On a running VM a prompt-style fragment with no
  trailing newline (`login:`, a `printf` without `\n`) is withheld and cannot
  match until something ends the line (measured: `printf NOEOL-MARKER
  >/dev/ttyS0` → exit 124; a later `printf '\n'` → exit 0 with
  `matched_line: "localhost login: NOEOL-MARKER"`). Always `echo` the marker
  with a newline. On a stopped VM (explicit `--vm`), the final unterminated
  line is flushed and can match.
- **Scan scope.** The scan starts at the later of the recorded guest epoch and
  the latest timestamped kernel boot banner (`serial.current_boot_offset`),
  so earlier-boot evidence is excluded even when the reboot was not observed
  over QMP. The result names that boundary — `scan_offset` and `scan_scope`
  (`boot-banner` or `epoch`) in JSON, "scanned from byte N" in text — so a
  marker that fell before it is never a silent miss. One thing moves the
  boundary that is not a reboot: a guest that replays `dmesg` to the console
  reproduces the timestamped banner verbatim — print your marker *after* any
  such dump, or start the wait before it. The boundary is fixed at the start
  of the wait; it is not a live reboot monitor.
- **Stopped VMs.** With explicit `--vm`, pattern waiting also inspects
  retained stopped logs (including log-only remnants) and returns the same
  match/no-match outcomes without auto-cleaning them. A missing/unreadable
  retained log is an inconclusive error, not evidence the operation failed.
  Without a selector, only running instances are candidates, so an old
  stopped VM cannot silently satisfy a new wait.
- **Debugged VMs.** Never poll a debugged VM by re-attaching pry
  (`pry launch --connect` in a loop) — every attach halts the guest.
  `qmu wait --pattern` and `qmu log --grep` never touch the gdbstub.

## Harness mode

`--harness` implies `--no-wait-ssh` and `--no-net` and skips the rootfs/SSH-key
requirement. It does **not** boot without a disk: a config `[drive] rootfs` is
still attached unless you pass `--drive`/`--rootfs`. Prefer `--harness --rootfs
./rootfs.img` when the image is a plain rootfs — it stays tracked (holder
checks for `rootfs inject`, `status.rootfs`); an explicit `--drive` image is
not recorded as the VM's rootfs. SSH commands (`push`/`pull`/`exec`/`compile`/
`dmesg`/`kbase`) error immediately on a harness VM; serial/QMP commands
(`log`/`crash`/`wait`/`qmp`/`monitor`/`kill`) work.

Pass `-- -no-reboot` for a kernel whose panic would otherwise reboot-loop
(`panic=N` on the cmdline): without it a panicking harness guest comes back up
and `wait` ends in `124` with `crash: null` instead of reporting the panic.

## `qmu wait` without `--pattern`

Blocks on QMP `STOP`/`SHUTDOWN`/`POWERDOWN` events with PID-liveness fallback:

- **Exit 0** — the recorded QEMU process identity exited; the result carries the
  terminal crash (JSON `crash` field, null if none; text prints
  `Crash from serial log:`).
- **Exit 124** — `--timeout` elapsed while the QEMU process remained alive —
  including a guest that panicked and halted without exiting; check `crash`.
  Structured output has `ok:false`, `stopped:false`, and retains `qemu_status`,
  `last_event`, and `event_data`.
- **Exit 4** — QMP transport failed while the recorded process remained alive.
  A connection can close just before normal process exit, so qmu allows up to
  one second of identity polling, capped by the remaining `--timeout`. EOF alone
  is never success, and a persistent transport failure never cleans the live VM.
- QMP `RESET`, `STOP`, `SHUTDOWN`, and `POWERDOWN`, plus non-running states such
  as `paused`, `postmigrate`, and `guest-panicked`, are observations rather than
  proof that QEMU exited.
- A VM stopped by `qmu kill` while it was being waited on reports the QMP
  loss as exit 1/4 rather than a clean exit 0; treat that as "someone killed
  it", not as a harness result.

**`wait` auto-cleans harness VMs by default only after confirming that the
recorded QEMU process identity exited** (removes metadata + `.serial.log`)
unless you pass `--no-clean`. A live-PID timeout never auto-cleans. Read the
terminal crash from `wait`'s own output rather than a later `qmu crash` — after
a confirmed exit, the log may already be gone. Non-harness VMs are never
auto-cleaned by `wait`.
