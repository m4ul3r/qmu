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
  `SHUTDOWN`/socket EOF mark the VM exited and reap a recorded pry bridge;
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
wait's envelope); `last_event` is the real QMP event name.

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
