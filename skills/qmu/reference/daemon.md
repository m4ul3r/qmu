# The qmu daemon (per-user supervisor)

QEMU serves **one** QMP client. Before the daemon every qmu command opened
its own short-lived connection, so concurrent commands contended (`qmp:
busy`) and nobody was connected long enough to *see* events — a
guest-initiated reboot had to be inferred from the kernel's boot banner and
a `wait --pattern` polled the log at 250 ms. The daemon holds each running
VM's single QMP connection, consumes its event stream, keeps the VM record's
guest epoch current, and lets any number of commands read cached state or
proxy a command through that one connection.

## What it owns

- **One QMP connection per watched VM**, with a reader thread. `RESET`
  persists the observed guest epoch (`guest_epoch_serial_offset` = serial-log
  size at the event, `guest_epoch_source: "observed"`) and tears down the
  VM's SSH ControlMaster; `STOP`/`RESUME` update the cached run-state;
  socket EOF **confirmed by PID identity** marks the VM exited and reaps a
  recorded pry bridge (a `SHUTDOWN` event alone only updates `qemu_status`);
  `GUEST_PANICKED` marks it panicked.
- **One serial tick** (100 ms, an `os.stat` per watched log, a scan only on
  growth) that wakes `wait` subscribers.
- **Proxying**: `qmu qmp`, `monitor`, `snapshot`, `cont`, `kbase`, the
  `status`/`exec` preflight — every handler's QMP call — rides the daemon's
  connection under a per-VM lock when the daemon watches the VM. Eight
  concurrent `status` calls during a `wait` are eight cache reads, never a
  `busy`.

What changes in output when the daemon serves a VM: `status`/`list` report
`qmp: "daemon"` (text `QMP: daemon (boot scope: observed epoch, byte N)`),
plus `guest_epoch_source: "observed"|"banner"`, `guest_epoch_serial_offset`
and `boot_offset` on `status`. `observed` means a RESET was witnessed and the
guest scope is anchored on it — a panic from the boot before it is out of
scope on every command; `banner` means the newest kernel boot banner decided,
exactly as the standalone path does. With the layer off the output shape is
unchanged (none of those keys appear).

`wait` (bare and `--pattern`) blocks on the daemon socket and is woken by the
tick/event stream — the client does not poll. Verdicts, exit codes and the
JSON shape are identical to the standalone loop (`qmp: "daemon"` in the bare
wait's envelope); `last_event` is the real QMP event name. While a wait is
in flight the daemon also streams a `progress` event (elapsed, scanned byte)
at most once per second; the CLI ignores it, the MCP façade relays it to its
client (`reference/mcp.md`).

## Ownership rule: a subscribed `wait` is never stranded

The daemon keeps a VM's watch until its recorded process is **positively
gone** (PID + start-time, the same identity every command uses). A QMP
`SHUTDOWN` event alone is never treated as death. Two consequences:

- **`kill` quits *through* the daemon** (the `quit` rides the daemon's own
  connection; `--force` skips `quit` and the socket EOF does the same job),
  so the watch itself sees the exit and every in-flight `wait` on that VM
  gets its terminal transition at once: bare `wait` **0 / `process_exited`**,
  `wait --pattern` **1 / `process_exited`** (the marker never came). Before
  this rule `kill` released the watch first and both waiters burned their
  whole `--timeout` (124, `stopped: false`, `last_event: SHUTDOWN`) on a VM
  that was already dead (#118). `kill --no-clean`, a clean kill and
  `--force` behave identically here, and a wait with no `--timeout` ends
  too.
- **Release is complete when answered.** An explicit release
  (`daemon_client.unwatch(vm)`, which a `--replace` launch does before it
  kills the namesake, or the daemon stopping — `daemon stop`, idle exit, the
  build-id respawn) answers only after the daemon's QMP reader is shut down
  and joined, so a fresh standalone client gets QEMU's greeting immediately
  (no 2 s `QMPBusyError`, #119) — and every `wait` subscribed to that VM is
  answered `released` (after a `{"kind": "released"}` event) instead of
  being left behind. The wait is **not over**: the client finishes it
  standalone on PID liveness for the rest of its deadline — bare `wait`
  polls as under `QMU_DAEMON=off` (`qmp` then reports what *it* observed,
  e.g. `connected`), `--pattern` rescans from the same `scan_offset` — with
  the same verdicts and exit codes, and the result says so in `warnings[]`:
  `Note: the daemon released VM 'X' mid-wait (an explicit unwatch or a
  daemon shutdown); the wait finished standalone on PID liveness.` That
  process does not hand the VM back to the daemon for the rest of the
  command; the next command re-adopts it.

A RESET observed during a daemon-backed `wait` under an attached debugger
adds the debugger-coherence warning (`reference/debugging.md`) to the
wait's own result — stderr once, `warnings[]` once — never to the
daemon's log alone (#121).

## Autostart, opt-out, lifecycle

- Spawned on demand by the first command that needs it (`launch` hands the
  new VM over once its first QMP connect succeeded; `status`/`list`/`wait`
  adopt a VM they find unwatched). `[daemon] autostart = false` disables the
  spawn; `QMU_DAEMON=off` disables the whole layer for one process (no
  connect, no spawn) — use it in scripts that must leave no process behind.
  `QMU_DAEMON=require` makes an unreachable daemon an error (exit 1).
- One daemon per cache dir (`QMU_CACHE_DIR`), as `<cache>/daemon.sock`;
  `<cache>/daemon.json` records pid, /proc start-time, build id and socket
  path; stdio goes to `<cache>/daemon.log`.
- Exits by itself after `[daemon] idle_exit` seconds (default 600; 0 =
  never) with no running watched VM and no client connected.
- **Build id**: the daemon reports a hash of the package path plus the newest
  source mtime; a client built from newer sources (an editable install you
  just edited — `touch src/qmu/__init__.py` is enough) asks it to shut down
  and respawns it, re-adopting every running VM. `qmu daemon status` flags a
  `STALE build`.
- At startup the daemon adopts every live instance record it finds.

## `qmu daemon …`

| Command | Effect |
|---|---|
| `daemon status` | `running` with pid, uptime, build id, socket, idle budget, client count and the watched VMs (`qemu_status`/`last_event`/`exited`/`panicked`); or `not running (<reason>)`: `not running`, `stale record`, `disabled (QMU_DAEMON=off)`, `unresponsive`. Never spawns. JSON `running`, `mode`, `build_current`, `vms[]`. |
| `daemon start` | spawn detached if none serves this cache dir (`started`/`already_running`). |
| `daemon stop` | ask it to exit (releases every QMP connection); a record whose socket does not answer gets SIGTERM. |
| `daemon run` | the foreground server `start` spawns; `--idle-exit N`. |

`qmu doctor` carries a `daemon` row (`[+] running …`, `[i] not running` is
the normal idle state, `[~] unavailable` points at `daemon.log`).

## Troubleshooting

- **`qmp: busy` under `QMU_DAEMON=off`** while a daemon watches that VM: the
  daemon holds the slot. Either drop the override (the command then reads
  the daemon's state) or `qmu daemon stop` first.
- **Stale socket** (`daemon.sock` present, nothing answers): the client
  checks the record's pid + start-time, unlinks the stale socket/record and
  respawns. `qmu daemon status` says `stale record`; `qmu daemon stop`
  SIGTERMs a wedged pid.
- **Nothing spawns**: `qmu doctor` → `daemon` row; `cat <cache>/daemon.log`.
  A broken project `qmu.toml` refuses `daemon run` like every other verb, so
  the client falls back to the standalone path silently — fix the config.
- **Scripts that must not spawn processes**: `export QMU_DAEMON=off`. The
  test suite does this in its autouse fixture; only `tests/test_daemon*.py`
  opt back in.
- A VM watched by a daemon that was killed with SIGKILL is simply re-adopted
  by the next daemon (the record carries the epoch); nothing is lost but the
  events between the two.
