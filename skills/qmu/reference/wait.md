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
- **Fragments match only once the console idles.** A complete line is
  offered to the matcher as soon as its newline arrives. A trailing fragment
  with no newline (`login:`, a `printf` without `\n`) is withheld while the
  console is still being written and offered only after one idle poll
  (0.25 s) — measured: `printf NOEOL-MARKER >/dev/ttyS0` then `wait --pattern
  'NOEOL-MARKER$'` → exit 0 with `matched_line: "localhost login:
  NOEOL-MARKER"`. Prefer `echo` with a newline so the match does not depend
  on console idleness. On a stopped VM (explicit `--vm`), the final
  unterminated line is flushed and can match.
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
still attached unless you pass `--drive`/`--rootfs`, and the launch note
names which (`Harness mode: attached rootfs <p> (from --rootfs; …)` / `(from
[drive] rootfs in project <qmu.toml>; …)`). Prefer `--harness --rootfs ./rootfs.img` when the image is a plain
rootfs — it stays tracked (holder checks for `rootfs inject`, `status.rootfs`);
an explicit `--drive` image is not recorded as the VM's rootfs. The implicit/
`--rootfs` disk is `/dev/sda` on x86_64 and `/dev/vda` on aarch64/arm; a
whole-disk image (mkrootfs, cloud) takes no partition suffix, so the cmdline
is `root=/dev/sda ro init=/run.sh`. SSH commands (`push`/`pull`/`exec`/
`compile`/`dmesg`/`kbase`) error immediately on a harness VM; serial/QMP
commands (`log`/`crash`/`wait`/`qmp`/`monitor`/`kill`) work.

`--no-reboot` does not change how a panic is reported: bare `wait` returns 3
(`terminal_panic`, `crash` populated) at the panic line with or without it,
and before any `panic=N` timer fires. It decides what happens *next*: with
`--no-reboot` QEMU exits once the timer expires (a second `wait` reports
`already_stopped` with the same `crash`); without it the guest reboots into
a fresh boot whose banner moves the scan scope past the report, so a `wait`
started *after* the reboot sees a healthy boot and ends in `124` with `crash:
null`. Pass it for every `panic=N` kernel. After exit 3 the VM is still
running: `qmu kill --vm X` (report kept) then `qmu prune --vm X`; a
`--no-clean` remnant is also removed by `qmu prune --vm X`.

## `qmu wait` without `--pattern`

Bare `wait` holds no QMP connection: it polls every 0.5 s with one
short-lived `query-status` plus a PID-liveness check, so it never occupies
QEMU's single QMP slot. Every result carries `vm_id`, `reason`, `stopped`,
`crash`, `console_tail` (the last 20 lines of the scanned scope, on every
outcome), `guest`, `guest_detail`, `qmp` (`connected` · `busy` ·
`unreachable` · null once stopped), `qemu_status`, `last_event`,
`event_data`, `elapsed`, `cleaned`. `guest` is `serving` while a running
harness guest has console output in this boot and `null` once QEMU has
exited (never `"unknown"` for an exited VM). Text mode prints the tail under
`Console tail:` when QEMU exited without a crash — that, or `matched_line`
from a `--pattern` wait, is the receipt for a successful harness run.

| Exit | `reason` | Meaning |
|---|---|---|
| `0` | `process_exited` | the recorded QEMU process identity exited during the wait; `crash` carries the terminal crash (null if none; text prints `Crash from serial log:`, otherwise `Console tail:`); `guest: null` |
| `0` | `already_stopped` | QEMU had exited before the wait began (explicit `--vm`); `crash` and `console_tail` are read from the retained log scoped to its last boot; `guest: null`; harness auto-clean still honoured |
| `3` | `terminal_panic` | `Kernel panic - not syncing` while QEMU still runs: `stopped: false`, `guest: "panicked"`, `crash` populated. `qmu kill --vm X` preserves the report for `qmu crash --vm X` |
| `124` | `timeout` | `--timeout` elapsed with the process alive; `ok: false`, `stopped: false` |
| `4` | — | `QMPError`: QMP unreachable for more than 1 s with the pid alive (EOF alone is never success; a persistent failure never cleans the live VM) |

- QMP events are not observed. `last_event` reports status **transitions**
  under the event name QEMU would have sent (`SHUTDOWN`, `STOP`,
  `GUEST_PANICKED`, `RUNNING`) with `event_data: {"source": "query-status",
  "from", "to"}`. A guest-initiated reboot is observed via the serial boot
  banner: `last_event: "RESET"`, `event_data: {"source": "boot-banner",
  "offset": N}`. Non-running states (`paused`, `postmigrate`,
  `guest-panicked`) are observations, not proof that QEMU exited.
- Under QMP contention the wait continues with `qmp: "busy"`, `qemu_status:
  "unknown"` (text: `QMP: busy (held by another client — another qmu command
  such as wait/status, or a debugger bridge), so QEMU's status was not
  observed.`); each busy poll costs the 2 s greeting timeout, so `--timeout`
  can overshoot by up to 2 s, and `--timeout 0` under a held slot is 124.
  A `savevm` still running after `snapshot save` exited 124 is the other
  source of `busy` (QEMU greets, then holds `qmp_capabilities` for up to the
  10 s floor); `124` means the same thing on both commands — the window
  closed, the operation is not disproved (`snapshots.md`).
  The reported `qemu_status` describes the **last** probe: once that probe
  was busy it is `unknown`, never a `running` carried over from an earlier
  connected poll. Before returning `timeout`, the wait rescans the serial log
  once more, so a panic that lands during the final (possibly 2 s busy) probe
  is still exit 3 `terminal_panic` with `crash`, not 124 with the report
  buried in `console_tail`.
- A VM stopped by `qmu kill` while it was being waited on reports the loss as
  exit 1/4 rather than a clean exit 0; treat that as "someone killed it".
- No command prints the profile-sourced unknown-parameter note; `launch`
  keeps it in JSON only. Operator-param warnings still appear on `launch`.

**`wait` auto-cleans harness VMs only after confirming that the recorded QEMU
process identity exited** (removes `.json` + `.serial.log`) unless you pass
`--no-clean`. A live-PID timeout or a terminal panic never auto-cleans. Read
the terminal crash and `console_tail` from `wait`'s own output rather than a
later `qmu crash`/`qmu log` — after a confirmed exit, the log may already be
gone. Non-harness VMs are never auto-cleaned by `wait`. `wait --help` documents
only the `--pattern` codes; the bare-wait table above is the contract.

## `--pattern` outcomes

| Exit | Meaning |
|---|---|
| `0` | matched; `matched_line`, `scan_offset`, `scan_scope` |
| `3` | a terminal panic appeared first (`crash`); a *survived* Oops does not abort; `--ignore-crash` suppresses even the terminal abort |
| `1` | the VM exited without the pattern and without terminal-panic evidence (a survived report stays in `crash`) |
| `124` | `--timeout` elapsed with the VM running |
| `4` | `inconclusive: true`: the serial log is missing or unreadable (`error`, `error_type`, `serial_log`; text `[qmu] Error: Cannot inspect serial log … inconclusive.` on stderr). Never the exit 1 of a genuine no-match |
