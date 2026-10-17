# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`qmu` is an agent-friendly QEMU VM management CLI for kernel research (exploit
dev, kernelCTF, syzkaller repros). It wraps `qemu-system-*`, QMP, and system
`ssh`/`scp` behind a single command whose every output can be rendered as a
machine-readable JSON envelope. The consumer is usually another AI agent, so the
exit-code contract and the `{"ok": ...}` JSON shape are load-bearing, not
cosmetic — preserve them when changing handlers.

## Commands

```bash
uv tool install -e .            # editable install; the `qmu` entry point is qmu.cli:main
uv sync                         # install dev deps (pytest) into .venv

.venv/bin/python -m pytest -q               # full suite
.venv/bin/python -m pytest tests/test_x.py -q          # one file
.venv/bin/python -m pytest tests/test_x.py::test_y -q  # one test

qmu skill install               # symlink skills/* into ~/.claude/skills (and ~/.codex / ~/.agents if present); re-run from the checkout you work in — links pointing at another checkout are reported `relinked` with their old target, links already right as `current` (untouched)
```

There is no lint/format config; match surrounding style. `pyproject.toml`
sets `addopts = "--ignore=tests/assets"` and `norecursedirs` for
`tests/assets`/`tests/eval-report` because vendored kernel trees under there
ship their own `test_*.py` — never let those get collected.

The editable install resolves `qmu` through a `.pth` pointing at `src/`, so
source edits take effect immediately with no reinstall; dogfood with
`.venv/bin/qmu ...`.

## Architecture

### CLI is a command package with a strict one-way dependency DAG

```
mcp_server.py  ->  cli.py  ->  commands/{lifecycle,guest,qmp_cmds,meta,daemon_cmds,mcp_cmds}  ->  _cliutil.py  ->  domain modules
```

- `cli.py` is *only* `invoke()`/`main()`: it builds the argparse tree (calling
  each module's `_add_*` registrar in display order), dispatches, renders the
  returned `Result` and maps handler exceptions to exit codes. No handlers
  live here.
- `commands/lifecycle.py` — launch, kill, prune, wait, list, status, doctor.
- `commands/guest.py` — push, pull, exec, compile, dmesg, crash, log (SSH- and
  serial-facing).
- `commands/qmp_cmds.py` — snapshot, gdb, cont, qmp (raw), monitor (HMP).
- `commands/meta.py` — config, rootfs, skill, version.
- `commands/daemon_cmds.py` — daemon run/start/stop/status.
- `commands/mcp_cmds.py` — `mcp serve` (runs `mcp_server.serve_stdio`).
- `mcp_server.py` — the MCP façade, *above* `cli.py` (see below).
- `_cliutil.py` — shared helpers (`Result`/`render`, `_kill_vm`, arg-option
  registrars, config resolution, QMP/SSH context). Bottom of the DAG; never
  imports `cli` or `commands.*`.

Each command module imports its collaborators (`choose_instance`, `_make_ssh`,
`launch_vm`, `save_snapshot`, …) **directly into its own namespace**. This is
what makes them patchable: tests patch the *owning* command module, e.g.
`monkeypatch.setattr(lifecycle, "choose_instance", ...)` for `status`, or
`guest._make_ssh` for `exec` — not `cli.*`. Patching works because each
`_add_*` looks up the handler name at `main()`-call time, so a test that patches
a module attribute before calling `cli.main([...])` is seen by dispatch.

### MCP façade (`mcp_server.py`, `commands/mcp_cmds.py`)

`qmu mcp serve` is a renderer substitute over the CLI, not a second command
layer, and two rules keep it that way: **it never renders and it never
re-implements a handler.** The tool list is walked out of `cli.build_parser()`
at startup — one tool per argparse leaf, `qmu_<sub>` / `qmu_<group>_<sub>`,
schema from the actions (`type`/`choices`/`nargs`/store-true, `help` first
sentence), `--format`/`--out` omitted — so a new `_add_*` leaf is a new tool
with no edit in `mcp_server.py` (`tests/test_mcp.py` walks the parser
independently and diffs). Excluded on purpose: `mcp`, `daemon run`, `skill
install`, `rootfs shell`. A call becomes argv (options, then `--`, then
positionals in order — one string is one token, the `exec`/`run` rule) and
runs `cli.main(["--format", "json", *argv])` with `sys.stdout` captured
per worker thread (`_ThreadStdout`); the captured JSON, parsed back and
given `exit_code`, is the result. That is why the envelope, the `UsageError`
shape, spill pointers and `warnings[]` are byte-identical to the CLI's:
they *are* the CLI's. Errors are results (`isError` mirrors `ok`), never
protocol errors. `qmu_argv` passes a raw argv through (refusing the managed
`--format`/`--out`); `qmu://vms` and `qmu://vm/{id}/log` are `list` and
`log --tail 200` through the same path. Tool calls run concurrently in
worker threads, which is why `instance._autoselected_vm` and
`config._global_config_warnings` are `ContextVar`s, not module globals.
Progress: `daemon_client.progress_sink` (a ContextVar, default no-op) is
set per call; the daemon-backed `wait` (`lifecycle._daemon_wait_request`)
calls `daemon_client.report_progress(elapsed, scanned, note)` on each
daemon `progress` (≤1/s) or QMP event, and the façade relays it as
`notifications/progress`. Keep tool descriptions to one sentence:
`mcp_server.schema_cost()` measures the serialised `tools/list` (~5.4k
tokens for 38 tools); trim descriptions, never tools, if it grows past ~12k.

### Exit-code contract (see the epilog in `cli.py:main`)

`0` success · `1` operation failed (guest non-zero, doctor unhealthy, snapshot
failed, no crash found, operational QMUError) · `2` usage/argparse ONLY · `3`
guest kernel crash · `4` infra/internal (QMP/SSH failures, unexpected errors,
`wait --pattern` on an unreadable log → `inconclusive: true`, launch
`no-console-output`) · `124` timeout (`wait`, `launch`/`run` `--ssh-timeout`
expiring before the guest answered SSH — **both** 124 with one envelope shape
(`timed_out: true`, `ssh_error: true`, `error_type: "TimeoutError"`, `hint`);
`launch` retains the VM, `ssh_status: "timeout"` (#72: it used to be the
transport class 4 while `run` said 124) — a guest command outrunning
`--timeout` on a reachable guest, `snapshot save` outrunning its budget —
result unknown, `may_have_landed: true`). `QMUError -> 1`,
`QMPError`/`SSHError -> 4`, the catch-all `-> 4`. Never let a raw traceback
escape to the agent.

**Every exception-path `ok: false` envelope carries `hint`** (#74).
`QMUError(msg, hint="…")` (and every subclass) carries the raise site's
recovery; `_emit_error` writes it, else the `error_type` default from
`_cliutil._DEFAULT_HINTS` (MRO walk, `qmu doctor` catch-all; usage errors get
`qmu <sub> --help` in `cli._emit_usage_error`). Text mode prints `[qmu]
Hint:` only for a site-specific hint so text stays quiet. Give a new `raise
QMUError(` a hint when the SKILL.md recovery table has a matching row.

**Exit `3` requires a corroborating fresh serial crash report.** A dropped SSH
or scp connection alone is `4` (guest merely unreachable — a VM running no sshd
produces one on every `exec`). `exec`, `push`, and `pull` apply this
discrimination identically; they used to disagree, which reported a missing
daemon in the kernel-crash class that callers branch on to mean "the exploit
crashed the kernel".

`qmu wait --pattern` maps its four terminal states onto the same codes: match
`-> 0`, **terminal-panic**-before-match `-> 3`, VM-died-before-match `-> 1`,
timeout `-> 124`. A survived crash does not abort — the guest still runs, so
the marker can still arrive, and aborting on it made callers paste
`--ignore-crash` onto every wait, which is how a real panic gets missed.
It exists so agents stop hand-rolling `until grep -q ... serial.log; do sleep;
done`, which cannot terminate on either of the middle two.

### Output rendering (`_cliutil.Result`, `_cliutil.render`, `output.py`)

Handlers never write stdout. Every handler **returns** a frozen
`Result(data=<dict>, text=<str|list>, stem=..., exit_code=...)`; `cli.main`
renders it with `render(args, result) -> int`, which owns the one `--format`
fork. `cli.invoke(argv) -> Result` is parse + config gate + dispatch with no
rendering and handler exceptions propagating — the seam for in-process
callers (MCP façade, daemon); `main` = `invoke` + `render` + the
exception→exit-code mapping. The byte-exact paths (`exec`/`run`/`dmesg`/
`rootfs cat`) set `raw=<bytes>` instead of `text`; refusals (`refusal=True`,
built by `_refusal`) put `text` on stderr as `[qmu] Error:` lines with
nothing on stdout; `notes` are text-mode stderr trailers (guest stderr, `[exit
code: N]`); `warnings` are stderr text written after the output in every
mode (debugger-coherence warnings, follow-up hints — `result.warn(...)`) AND,
under json/ndjson, the envelope's `warnings: [str]` (#74) — prefix-stripped
(`envelope_warning`), merged with any `warnings` the handler put in `data`
(launch's), deduplicated. A warning that fires before the handler — the
broken-global-config notice in the dispatch gate — is recorded by
`config.global_config_warnings()` (never written there) and attached by
`cli._dispatch` (`result.warn(...)`) or `_emit_error` on the failure path, so
`invoke()` callers get it on the Result and nothing is lost to stderr-only.
Debugger-coherence warnings on the raw `qmp`/`monitor` routes travel the same
way (`_after_mutation(..., warnings)`); never `sys.stderr.write` a warning
from a handler. `Result.silent_exit(n)` renders nothing (group help, `rootfs
shell`, `skill install`). Work that must precede the output (reaping, epoch
persistence) happens before the `return`; text that must follow it rides in
`warnings`. Text mode renders `text`; `json`/`ndjson` render `data` as a
`{"ok": bool, ...}` envelope. Results whose estimated size exceeds
`DEFAULT_SPILL_TOKEN_LIMIT` (~10k tokens, chars/4) are spilled to a file under
the spill root (`$QMU_TEMP_DIR/spills`, else XDG/platform temp). json/ndjson
stdout becomes an artifact-pointer envelope; text stdout becomes `[qmu] Output
spilled to <path> (~N tokens)` plus the first 40 lines, never JSON, because
`--format text` promises text. `--out` forces a file: json/ndjson print the
pointer envelope, text prints one line `[qmu] Output written to <path> (<N>
bytes, exit <code>)` (`output.text_out_pointer`, #71b — it used to print the
JSON envelope). A pointer's `ok`/exit is the **operation's** result, not "the
artifact was written": a failed guest command rendered through text `--out`
says `exit 7` exactly as the JSON path says `ok: false` + `exit_code` (#108)
— never let a byte-artifact helper default to success.

**Streamed guest output (#71a) is the one sanctioned exception to "handlers
never write stdout".** `SSHClient.run(..., on_chunk=)` relays every drained
read (`ssh._watch_child`, raw bytes, no line assembly, the post-kill drain
included so a timeout/abort still relays its partial output). `guest.
_stream_sink(args, stem)` picks the relay for the format: `_TextStreamSink`
writes stdout chunks to `sys.stdout.buffer` and stderr chunks to
`sys.stderr.buffer` as they arrive (`--out` streams into the file; past
`STREAM_SPILL_BYTES` the remainder is diverted to a spill file that holds
the whole output, pointer + `Preview … streamed above` trailer last);
`_NdjsonStreamSink` prints `{"event":"chunk","stream","data"}` lines
(surrogateescape) before the ordinary envelope; json gets `None` (buffered).
`_run_guest_command(..., sink=)` threads it to `run` and keeps guest stderr
out of `notes` when the sink already relayed it; `_guest_result(...,
sink=)` calls `sink.finish` (un-relayed remainder — nothing for the real
client, everything for a fake that never called `on_chunk` — then the crash/
timeout `text`, then the pointer) and returns `Result(streamed=True)`, which
`render` honours by skipping stdout and still writing `notes`/`warnings`.
Only the exec phase streams: `compile`'s gcc/chmod steps and `dmesg` pass no
sink. Fakes keep working because `run(**kwargs)` may ignore `on_chunk`; a
test that asserts *liveness* must relay chunks itself (`StreamingSSH` in
`tests/test_exec_command.py`, `_StreamingServingSSH` in the matrix).

### Instance lifecycle & PID-recycling guard (`instance.py`, `vm.py`)

A `VMInstance` (dataclass) is persisted as JSON under `~/.cache/qmu/instances/`
alongside `<vm_id>.qmp.sock`, `<vm_id>.serial.log`, and `<vm_id>.qemu.log`.
Writes are atomic (tempfile + `os.replace`). Liveness uses `instance_alive()`,
which compares the process's `/proc/<pid>/stat` start-time (`pid_start`, captured
at launch) against the recorded value so a recycled PID after a reboot is not
mistaken for a live VM — prefer it over bare `is_pid_alive()` anywhere a stale
instance JSON might name a reused PID. `list_stopped_instances()` also
synthesizes records from orphan `.serial.log` files. `launch_vm()` auto-allocates
free ports under `vm.PortAllocationLock` — an `flock` on
`<instances_dir>/ports.lock` held from `find_free_port` until QEMU has bound
(first QMP connect) — so concurrent launchers probing from the same
`ssh_port_start` cannot pick the same port (#113). The 3× retry on a bind
failure stays as a backstop for a foreign listener; its exhaustion message
names the lock so the reader does not blame qmu's own concurrency.

### VM state has TWO orthogonal axes

Never collapse them into one enum.

- **Existence** — `instance.classify_vm(vm_id)` → `running` / `orphaned` /
  `held_back` / `stopped` / `absent`. Answers "is there a record and/or a
  process". This is the single authority; a command that answers about a
  `vm_id` must route through it. `status`/`kill` once used `choose_instance`
  (running-only) while `list`/`log` used `find_instance`, which is why
  "not found" kept being reported for VMs `qmu list` was displaying.
  `held_back` carries a `held_reason` (`age` / `malformed-metadata` /
  `qmp-busy`; `null` elsewhere) because only `age` is cleared by
  `--older-than 0`: an unparseable `.json` with no serial log is refused at
  every age (prune reports it under `refused[]`) and the fix is a hand
  repair/delete of the file — advertising the age hint there sent the reader
  in a loop (#109).
- **Guest usability** — `lifecycle._guest_state(inst)` → `serving` / `paused` /
  `crashed` / `panicked` / `unknown`. The predicate is **usability**, never
  "is a crash retrievable" — those diverge, and conflating them is a bug that
  shipped once. Precedence, in order:
  - `panicked` — `serial.has_terminal_panic()` found `Kernel panic - not
    syncing`; the guest is gone and reaping is correct. SSH is not probed.
  - `paused` — QMP `running:false`; where `qmu gdb` leaves every VM until
    `qmu cont`. The axis is coarse on purpose; `qemu_status` carries QEMU's
    own word, and one value is load-bearing: **`restore-vm`** is a `snapshot
    load` that failed mid-restore (#87, disks rewound, devices not). `qmu
    cont` refuses it (exit 1, `guest_state: "paused"`, `qemu_status`,
    recovery hint) unless `--force`; the SSH-command refusal and the skill's
    recovery table hand out the same two recoveries (known-good load, or
    kill + relaunch), never `cont` (#110). Add a `restore-vm` row to the
    matrix for any new command that answers about a paused guest.
  - `crashed` — a report is retrievable AND the guest still serves. Under the
    default `exploit-dev` profile (deliberately no `oops=panic`) an Oops kills
    only the faulting task, so this is the common outcome of a trigger. It is
    neither `serving` (a report is waiting) nor `panicked` (**do not reap it**).
  - `serving` — **positive evidence only**: sshd answered, or (no SSH endpoint
    / not probed) the current boot wrote to its console. A vCPU that merely
    runs is not evidence — an aarch64 guest booted with an x86 cmdline runs
    forever, writes nothing, and was reported `serving` for exactly that reason.
  - `unknown` — nothing positive; `guest_detail` names what was checked
    (`SSH down, 0 bytes of console output`).

  The guest axis is defined for a running QEMU only: once the process has
  exited (`status` on a stopped VM, bare `wait` after `process_exited`/
  `already_stopped`) the key is `null`, never `"unknown"`. A running harness
  guest with console bytes is `serving` — bare `wait` reports it the same way
  `status` does. The SSH probe is also skipped when
  `debug.debug_session_present(inst)` (`ssh: "skipped (debugger attached)"`):
  the probe runs `uname` in the guest, which trips a `__x64_sys_newuname`
  breakpoint with no trigger from the operator. Readiness probes run with
  `ControlMaster=no` so `list`/`status`/`launch` never leave a mux master
  behind; `kill` closes the VM's master before signalling QEMU.

  Both crash reads are scoped to `max(recorded epoch,
  serial.last_boot_offset())`. `guest_epoch_serial_offset` only advances on an
  **observed** QMP RESET, so a guest-initiated reboot between two commands is
  invisible to it and a previous-boot panic would otherwise label a healthy
  guest as gone — instructing a destructive action on working state. The
  kernel's own boot banner is the log-local ground truth.

  All three readers — the guest axis, `qmu crash`, and `wait --pattern` —
  share `serial.current_boot_offset(log_path, epoch_offset)` as the one
  scope primitive (`qmu crash --full-history` scans from 0), and
  `wait --pattern` reports the boundary it used (`scan_offset`/`scan_scope`).
  The one residual blind spot is a `dmesg` replay echoed to the console,
  which reproduces the timestamped banner and moves the boundary past any
  marker printed before it.

The cross product is real — orphaned+panicked is the everyday outcome of a
triggered crash on a VM whose metadata was lost — so adding `paused`/`panicked`
as existence-enum values would force `orphaned+panicked`, `stopped+…` and grow
combinatorially. `list` must report both; it used to consult neither QMP nor
crash detection and presented a panicked VM identically to a healthy one.
`list` marks a stopped VM whose report is still on disk `[stopped — crash
report retained]` and reports `qmp: "skipped"` (never null) when it did not
consult QMP.

**A non-running VM is described, not refused.** `status --vm X` on a
stopped/orphaned-remnant/held-back VM is exit 0 with `status`, `guest: null`,
`pid_alive`, `logs_retained`, `crash_detected`; `kill --vm X` on a stopped VM
is exit 0 with `already_stopped: true`. Only an absent name goes through
`describe_non_running()` → exit 1.

**Auto-selection is never silent.** Every command that falls back to the
single running VM prints `[qmu] Auto-selected the only running VM 'X' (pass
--vm to pin it).` on stderr and sets JSON `autoselected: true`; with
`QMU_REQUIRE_VM=1` in the environment it is exit 1 instead (`--vm is
required: QMU_REQUIRE_VM is set`). No message anywhere recommends `prune
--all`; the no-running-VM hints for `log`/`crash` name `qmu prune --vm <id>`
(and `--all --dry-run` only as a preview).

### Crash vs. transport-loss disambiguation (`guest.py`, `ssh.py`, `serial.py`)

`ssh` exits 255 both for a legitimate guest `exit(255)` and for a dropped
transport (kernel panic). Handlers disambiguate with `_transport_lost()` (a
liveness re-probe, retried once) plus `extract_crash()` on the serial log. Only
emit the strong "kernel may have crashed" wording (exit 3) when a crash report
was actually extracted; otherwise report "unreachable" and exit 4.
`serial.extract_crash` walks backward to the *last* crash event and deliberately
keeps interior end-markers (a `panic_on_warn` epilogue) from truncating the
report. A soft `---[ end trace ]---` stays interior only while every line
between it and a following fatal panic is itself die() epilogue (register
re-dump, `Modules linked in:`, `note: … exited`); ordinary kernel output in
between proves the first event ended, so a resumed WARNING is never bridged
into a later unrelated panic.

Every guest command passes `abort_when=panicked` to `SSHClient.run`, a serial
watcher polled while the child runs: a terminal panic raises `SSHAborted` with
the output collected so far, so exec/compile/dmesg/run report exit 3 within a
second instead of after the 15 s ssh keepalive plus re-probes. Text mode
(`_run_guest_command`) prints guest stdout only on stdout; guest stderr and
`[exit code: N]` (non-zero only) go to stderr so pipelines see guest bytes.

### Serial-pattern waiting (`serial.SerialTail`, `lifecycle._wait_for_pattern`)

`SerialTail` is an offset-carrying line reader over a log QEMU is still writing.
It withholds a trailing fragment with no newline so a matcher never sees half a
line; `peek_fragment()` exposes it on an idle poll (so a `login:` prompt can
match once the console goes quiet) and `flush()` releases it for the final
pass. `_wait_for_pattern` takes *one extra scan* after `instance_alive()` goes
false (the `saw_dead` flag): the guest can print its marker and exit between a
scan and the liveness check, and dropping that line would turn a success into
a spurious exit 1. A missing/unreadable log is exit 4 with `inconclusive:
true`, never the exit 1 of a genuine no-match.

### Bare `wait` and QMP contention (`lifecycle._query_qmp`, `qmp.QMPBusyError`)

QEMU serves one QMP client. A `wait` that held the socket for its whole
duration made every concurrent `status`/`kill` hang or lie, so bare `wait`
polls every 0.5 s with one short-lived `query-status` (`_query_qmp`) plus a
PID-liveness check; QMP *events* are not observed and `last_event` reports
status transitions under the event name QEMU would have sent (a guest reboot
is seen through the serial boot banner as `RESET`). `_QMPProbe.state` is
`connected` / `busy` (accepted but never greeted — `QMPBusyError`) /
`unreachable`; anything not `connected` claims nothing QMP-derived
(`qemu_status: "unknown"`). `kill` under a held socket skips the graceful
`quit` after 1 s and signals. Bare `wait` exits `3` (`reason:
"terminal_panic"`) when the serial log shows a terminal panic while QEMU still
runs, and `0` with `reason: "already_stopped"` when the pid had already gone.

### Config resolution (`config.py`)

Layered: built-in defaults < global (`~/.config/qmu/config.toml`) < project
(nearest `qmu.toml` walking up from CWD, or `--config`) < CLI flags. A broken
*global* config warns and is skipped; a broken *project/explicit* config is
fatal. Validation collects **every** schema problem of a file before raising:
`ConfigError` carries `errors` (`[{source, key, message, hint}]`) and the
envelope mirrors the first problem as `source`/`key`/`hint`, so an agent fixes
the file in one round trip instead of one key per run. Profiles (kernel
cmdlines) from config extend/override the built-in
`exploit-dev`/`trigger-test`/`exploit-test`. `use_kvm()` only enables `-enable-kvm`
when guest arch == host arch and `/dev/kvm` exists.

The `[boot]` table (`kernel`/`initrd`/`cmdline`/`profile`) means a project
`qmu.toml` can describe an entire boot, so repeated launches need no flags.
Those four flow through the *same* `_resolve_config_from_args` flag_map as
`rootfs`/`memory`/etc., so flag-beats-config layering is uniform — `_handle_launch`
must read `config.kernel`/`config.initrd`/`config.cmdline`/`config.profile`, never
`args.*`, or the config layer is silently skipped. `_MIGRATION_DESTINATIONS`
carries hints for the wrong guesses (`[vm]`, bare `kernel`, `append`). An
explicit CLI `--profile` clears a config `[boot] cmdline` (otherwise the flag is
a silent no-op) and names the params that drop out — `nokaslr` especially, whose
loss moves every kernel address.

Every launch flag has a config key. Boolean flags (`--no-kvm` → `accel=tcg`,
`--no-reboot` → `[machine] no_reboot`) cannot ride the value `flag_map` —
copying a store_true's `False` would shadow a `true` in qmu.toml — so
`_resolve_config_from_args` adds them as overrides only when set. The schema
kind for such keys is `boolean` (`_validate_value`).

### Launch warnings and `doctor` taxonomy (`lifecycle.py`)

`_prepare_boot` accumulates every launch-time warning in a `_BootPrep`
(`warnings`, `config_sources`, `replaced`) via `_note()`; stderr keeps the
lines for text readers and the launch envelope mirrors them as `warnings[]`,
because an agent in `--format json` otherwise had to regex the other stream to
learn that `--profile` dropped `nokaslr`. New launch-time lints go through
`_note`, never a bare `sys.stderr.write`. `_warn_arch_cmdline_mismatch` is the
arch/`console=`/`root=` lint; the SSH wait fails early with
`ssh_status: "no-console-output"` when the serial log is still empty after
~10 s, since a wrong-arch guest otherwise runs forever and answers nobody.

`doctor` rows are `_doctor_row(check, status, detail)` with `status` in
`ok|fail|warn|info` → glyph `[+] [!] [~] [i]`; `blocking` is `status == "fail"`
and nothing else, and `ok` ⇔ no `fail` row. Choose the status by consequence:
`fail` only when launch cannot work (missing configured kernel/initrd/rootfs/key,
invalid global config); `warn` for optional capabilities (libguestfs, cross
toolchains, key permissions, a rootfs whose `/etc/qmu-rootfs.json` lacks
`sshd_policy=key-only` — read via `rootfs.read_stamp`, guestfish `--ro`, only
after the libguestfs row is `ok`); `info` for cache/pry/skills and checks that
could not run (`not checked (<reason>)`).

### The daemon layer (`daemon.py`, `daemon_client.py`, `commands/daemon_cmds.py`)

QEMU serves one QMP client, so per-command connections contended (`busy`) and
nobody was connected long enough to see events. `qmu daemon run` is a
per-cache-dir supervisor: one QMP connection + reader thread per watched VM
(`RESET` → persist the observed epoch through a re-read record,
`guest_epoch_source: "observed"`, drop the SSH ControlMaster; `STOP`/`RESUME`
→ cached `running`; socket EOF confirmed by PID identity → `exited` +
`debug.reap_bridge_on_exit`; `GUEST_PANICKED` → `panicked`), one 100 ms serial
tick that scans only on
growth and wakes `wait` subscribers, and a newline-JSON protocol (`ping`,
`watch`, `unwatch`, `vm_state`, `qmp`, `wait`, `shutdown`; streaming ops send
`{"id", "event"}` lines first). The client (`daemon_client.connect`) discovers
it via `<cache>/daemon.json` (pid + /proc start-time, build id, socket path),
autostarts it detached unless `QMU_DAEMON=off` or `[daemon] autostart=false`,
and falls back to the standalone path silently on any failure (`require`
errors instead). **Every handler path keeps working with the layer off** —
that is the contract, and `tests/test_state_agreement_matrix.py` pins that
`QMU_DAEMON=off` output carries none of the daemon-only keys.

- `_cliutil._qmp_ctx` returns a `DaemonQMP` whose `connect()` proxies through
  the daemon when it watches the VM (and that watch is not `qmp_lost`) and is
  a plain `QMPClient` otherwise; tests that patch `_qmp_ctx` are unaffected.
  `lifecycle._daemon_state` is the one seam `status`/`list`/`wait` read cached
  state through (`qmp: "daemon"`, `_QMPProbe.daemon`); `launch` calls
  `_watch_in_daemon` after `launch_vm`.
- **Ownership rule (#118, #119): a subscribed `wait` is never stranded, and
  release is complete when answered.** The daemon keeps a watch until the
  recorded PID identity is gone — `instance_alive` is the only authority for
  `exited`; a QMP `SHUTDOWN` alone never is. `kill` therefore does **not**
  unwatch first: `_kill_vm`'s `quit` rides the daemon's connection via
  `_qmp_ctx`, the EOF-then-PID check in `_on_qmp_closed` marks the watch
  `exited`, and every in-flight bare/pattern wait gets `process_exited`
  (0 / 1). `kill` once released the watch before signalling and both
  waiters burned their whole timeout (124) on a dead VM. When ownership ends
  while the process lives — `unwatch` (`_release_from_daemon`, used by the
  `--replace` launch) or the daemon stopping (`_cleanup` drains
  `_waits_in_flight` for `SHUTDOWN_RELEASE_SECONDS`) — the watch is marked
  `released`, each `wait` op answers `reason: "released"` after a
  `{"kind": "released"}` event, and the client (`_daemon_wait_request` raises
  `_WaitReleased`) finishes the wait in `_wait_standalone` /
  `_pattern_wait_standalone` with the original `start`/`deadline`, after
  `daemon_client.mark_released` so the same process cannot re-adopt the VM.
  `unwatch` answers only after `_EventQMP.close()` has `shutdown(SHUT_RDWR)`
  + joined the reader (`QMPClient.close()` shuts down too): a `close()` while
  a reader is parked in `recv` keeps the fd — and QEMU's one slot — open until
  the reader wakes, so a fresh client got no greeting for 2 s (`QMPBusyError`).
- **Warnings observed mid-wait ride the Result (#121).** The RESET
  debugger-coherence warning seen by `_daemon_wait_request.on_event` or the
  standalone `scan_console` is appended once to a `warnings` list and
  attached via `_finish_wait(..., warnings=)` → `Result.warn`, so `render`
  writes it to stderr exactly once and the json/ndjson envelope carries it in
  `warnings[]`; never `sys.stderr.write` from inside a wait loop.
- **Build id respawn**: the daemon reports `sha256(package dir + newest *.py
  mtime)[:16]`; a client that sees a different id sends `shutdown` and
  respawns, because editable installs change under a long-lived process.
  Expect `qmu daemon status` to show a new pid after any source edit.
- **Test isolation rule**: `tests/conftest.py` sets `QMU_DAEMON=off` and calls
  `daemon_client.reset()` for every test. Only `tests/test_daemon*.py` run
  the layer, in-process (`Daemon(cache, idle_exit=0)` against a fake QMP
  server) except one real `daemon start`/`stop` round trip. A test that
  needs daemon behaviour must set `QMU_DAEMON=require` itself — never leave
  a detached daemon behind.
- The per-process memos (`_spawn_failed`, `_unwatchable`) exist because one
  command calls `_qmp_ctx`/`_observe_guest` several times; without them a
  failed spawn cost 2 s per call and a busy adoption 1 s per call.

### Harness mode

`--harness` = boot-and-die VMs (kernelCTF/syzkaller): implies `--no-wait-ssh` +
`--no-net`, skips the rootfs/SSH-key requirement, allocates no SSH port. SSH
commands (`push`/`pull`/`exec`/`compile`/`dmesg`) then error via `_require_ssh`;
serial/QMP commands (`log`/`crash`/`wait`/`qmp`/`monitor`/`kill`) work. `qmu wait`
polls `query-status` + PID liveness (see *Bare `wait`* above) and auto-cleans a
harness VM only after the recorded pid is positively gone. Every bare-`wait`
result carries `console_tail` (last 20 lines of the scanned scope) so a
successful run whose log is about to be auto-cleaned still has a receipt;
text prints it under `Console tail:` when QEMU exited without a crash. A
panic is exit 3 at the panic line regardless of `--no-reboot`; the flag only
keeps a `panic=N` kernel from rebooting over its own report afterwards.
`--no-reboot` and `[machine] no_reboot` meet on `config.no_reboot` (the flag
is a store_true, so like `--no-kvm` it becomes an override only when set) and
`build_qemu_command` reads it from the config, never from a kwarg (#76). The
launch note names the disk's source (`from --rootfs` vs `from [drive] rootfs
in project <qmu.toml>`).

### Debugger↔VM coherence (`debug.py`)

The QEMU gdbstub protocol never tells an attached client that the machine
changed underneath it, so qmu operations that mutate VM reality make the
debugger's view silently diverge — the same wrong-answer-with-no-error class as
the crash/transport and state-axis bugs above. qmu owns the lifecycle events and
knows a VM has a stub (`gdb_port is not None`), so `debug.py` enforces the half
of the contract the protocol doesn't: **invalidate loudly.** It does NOT drive
pry, so it warns rather than auto re-syncing/re-arming (that is a pry-side
capability).

- `debug_session_present(inst)` is the gate for divergences a *live* client
  would see: true when `gdb_port` is set AND `gdb_client_attached()` cannot
  positively rule out a connected client. The attach probe parses
  `/proc/net/tcp{,6}` for an ESTABLISHED socket on the gdb port; it returns
  `None` (can't tell → treated as present, fail-safe) rather than `False` on
  any read failure, because a missed divergence is the whole bug. The same
  probe is what makes `qmu gdb` refuse (exit 1, naming the bridge pid) instead
  of spawning a second bridge against an occupied stub — on a positive `True`
  only; `None` falls through so an unreadable `/proc` never locks the debugger
  out.
- `snapshot save` deliberately uses the weaker `debug_stub_present(inst)`
  (`gdb_port` alone): a debugger that already detached can have left `int3`
  bytes behind, and the save captures them whether or not anyone is attached
  now. A save on a `--gdb` VM therefore always warns; the skill documents this
  as the one exception to attached-client suppression — do not "fix" it by
  switching that call to the session gate.
- Warnings fire on exactly the mutation events, via `Result.warn(...)` — stderr
  in every mode plus the envelope's `warnings[]` under json/ndjson (#74), so
  the stdout JSON stays one object: `snapshot save` (#45, baked-in `int3`s),
  `snapshot load` (#44, stale vCPU/bookkeeping), `qmp`/`monitor system_reset`
  (#46, dropped breakpoint set), and `kill` (#40, stranded pry bridge). The
  KVM-watchpoint warning (#39) is the exception: it rides in the `qmu gdb`
  **stdout** payload next to the existing symbol warnings, keyed on the recorded
  `VMInstance.kvm`, so `gdb`'s clean-stderr contract holds.
- KVM opt-out (#39): `config.accel` (`auto`/`kvm`/`tcg`) gates `use_kvm()`; the
  `--no-kvm` launch flag maps to `accel=tcg` through the same `_resolve_config_
  from_args` layering as every other flag. `VMInstance.kvm` records the effective
  decision at launch so `gdb` warns without re-deriving host state.

A warning keyed on `gdb_port` alone would be noisy on the snapshot-rewind fast
path when no debugger is attached; the attach probe is what keeps it quiet in
that common case while still warning whenever a client is (or might be) present.
Guest-*initiated* reboots are invisible to a one-shot command, so those stay
doc-only (skill: *Debugger↔VM coherence*). This is the qmu-side stopgap layer of
umbrella #48; auto re-sync/re-arm and true pry-bridge reap need pry-side work.
`exec`/`compile --run`/`dmesg` watch QMP while the SSH command runs and abort
within ~1 s of `running:false` (a breakpoint stop), emitting the same paused
envelope the preflight uses (exit 1) instead of waiting out the SSH keepalive.

## Gotchas

- **Snapshots work out of the box with the default raw rootfs and slirp.**
  qmu's `snapshot=on` overlay is itself a qcow2, so HMP `savevm`/`loadvm`
  store in-session checkpoints there (verified on QEMU 8.2.2: save ≈2.5s,
  load 1–4s, no slirp warning); they vanish with the QEMU process. Durable
  snapshots need an explicit writable qcow2 `--drive` without `snapshot=on`.
  `net_backend=passt` is an opt-in for QEMU builds whose slirp state fails
  to restore, gated on a capability probe — not a prerequisite. `snapshot
  load` tears down the SSH ControlMaster so the first post-load `exec` does
  not stall on the rewound connection.
- **A `snapshot save` that outran its budget is an UNKNOWN result, never a
  failure.** HMP `savevm` runs synchronously on QEMU's main loop; when the
  client gives up, QEMU keeps writing and the tag usually lands minutes later
  with every QMP command queued behind it (#73). The default budget is
  `snapshot.savevm_timeout()`: 60 s + 20 s per GiB of guest RAM, ≥ 3× the
  measured loaded cost (4 GiB fully-dirty RAM under dd + CPU load: 22 s;
  into a 19 GB qcow2 with five snapshots: ≈60 s); `--timeout` overrides it.
  On expiry the handler returns **124** with `may_have_landed: true` and a
  hint naming `snapshot list --vm X --timeout N` — not 4, which claims the
  transport broke, and not 1, which claims the save failed. Three
  `QMPClient` properties make the follow-up safe and must stay: `execute`
  closes the socket on timeout (`QMPTimeoutError`); every command carries a
  client-unique `id` and `_recv_response` drops a reply tagged with another
  client's id — QEMU delivers the abandoned `savevm` reply to whichever
  client holds the socket next, which made `query-status` return `{}` and
  `snapshot list` say "No snapshots." (audit D7); and the handshake budget
  covers `qmp_capabilities`, which a wedged main loop holds after greeting
  at once (`QMPBusyError`, not a raw socket timeout). `snapshot list
  --timeout` raises `greeting_timeout` before connecting so the named
  follow-up outlasts the save.
- **The SSH readiness probe's cap is `ConnectTimeout + PROBE_GRACE_SECONDS`
  (2.5 s), and `status`/`list` report it as `ssh_probe_ms`.** OpenSSH bounds
  the banner exchange by `ConnectTimeout`, but not the key exchange after a
  banner: a listener that sends `SSH-2.0-…` and then hangs holds `ssh` for
  60 s+, so the subprocess cap is the only bound there (#77). The old
  `timeout + 3` made every such port cost `list`/`status` 5 s per VM.
- **`rootfs inject` treats GUEST as a directory** (with or without a trailing
  slash); the local filename is preserved. A missing GUEST directory is an
  ERROR unless `--mkdir` — silently creating it turns a typo'd destination into
  a reported success while the stale binary stays put. It shells out to
  `guestfish`; if libguestfs can't build its appliance (e.g. mode-600 `/boot`
  kernels), point it at a fixed appliance via `SUPERMIN_KERNEL` or
  `LIBGUESTFS_PATH`. `qmu doctor` checks both the binary and appliance-kernel
  readability. Ownership normalization is `lchown` over exactly the paths the
  injection landed (enumerated from the *source* tree), followed by a `chmod`
  back to the source mode on every non-link — `chown` follows symlinks and
  clears setuid/setgid, and a merge must not re-own pre-existing guest files
  (#95/#96/#97). Generated guestfish scripts quote with
  `rootfs.guestfish_quote`, never `shlex.quote`: guestfish's tokenizer is not
  a POSIX shell (#98), and `ls` output is NUL-framed so names/targets
  containing the old separator or newlines come back exact (#99). The
  guestfish transport is **bytes-only** (`rootfs._invoke`): never add
  `text=True` to a guestfish call — universal newlines fold `\r` into `\n`
  before the NUL framing is split, which merged a CR-named and an LF-named
  file into one duplicated entry (#111). Non-UTF-8 names decode lossily with
  `name_bytes_b64`/`target_bytes_b64` carrying the exact bytes.
- **A failed `loadvm` is not always resumable.** QEMU reverts the block layer
  before it loads the vmstate, so a load that fails *after* restoration began
  (`snapshot.loadvm_restore_state` → `partial`/`unknown`) leaves pre-snapshot
  devices over post-snapshot disks; `qmu cont` there runs an inconsistent
  machine (#87). Only a pre-restore refusal (`none`: missing tag, bad name) is
  resumed; the others are deliberately left paused with `guest_paused: true`
  and a hint that excludes `cont`. HMP failure detection (`qmp.hmp_failed`)
  anchors QEMU's error frames to the start of a line, so error words inside
  data (a tag named `Error:checkpoint`, a register dump) are not failures
  (#86). Mutation bookkeeping (epoch persist) runs *before* the success
  envelope is written, so a persistence failure never follows `ok:true` with a
  second JSON object (#88).
- **Guest streams are bytes.** `exec`/`run`/`compile --run`/`dmesg` text mode
  writes guest stdout through `sys.stdout.buffer` exactly as captured (no
  decode, no added newline); JSON carries the lossy decode plus
  `stdout_lossy`/`stderr_lossy: true` only when U+FFFD replaced something
  (#80). The text spill preview is bounded by `TEXT_SPILL_HEAD_LINES` **and**
  `TEXT_SPILL_HEAD_BYTES` — a single 200 000-byte line is one "line" (#100).
  `_classify_transfer_failure` routes the SCP watcher's `SSHAborted` through
  the same panic/paused/transport split as `exec`, so a panic mid-`push` is
  exit 3 with the report, not 4 (#89).
- **A stopped `status` omits `qmp`/`qemu_status`/`ssh`** rather than
  emitting `null` (bare `wait` does emit `qmp: null`); `list` keeps the coarse
  existence word `stopped` for every non-running record while `status`/`prune`
  refine a metadata-free `.qemu.log`/`.qmp.sock` remnant to `held_back` —
  pinned by the matrix, documented in the skill; do not "unify" one side to
  match the other without changing both and the rows (#104/#106).
- When editing handlers, keep behavior verbatim-stable unless intentionally
  changing it — the suite pins the exit codes, the JSON envelope keys, and the
  crash/transport wording.
- **A flag that promises not to act must not act, on every path it accepts.**
  `prune --dry-run` was implemented for `--orphans` only and silently ignored
  by `--vm`/`--all`, which then deleted the `.serial.log` files `kill
  --no-clean` exists to preserve. When adding a mode-scoped flag, either
  implement it for every mode the parser accepts it on or reject it explicitly
  — never let it fall through to the destructive path.
- **Never report "not found" for something another command displays.** This
  class recurred across `prune --vm`, `prune --all`, `kill`, `status`, `wait`,
  and `exec`, each time sending the reader to `rm` in the cache directory for a
  VM `qmu list` was showing them. `status`/`kill` describe a non-running VM
  with exit 0; only an absent name uses `lifecycle.describe_non_running()`.
- **`prune --vm` is not age-gated for anything `kill` preserved.** A stopped
  VM with its record, and a serial-log-only remnant, prune at any age; only a
  metadata-free `.qemu.log`/`.qmp.sock` remnant is `held_back` by
  `--older-than`. Docs that say `--older-than 0` for kill-preserved logs are
  wrong, not the tool.
- **stderr is for the operator, JSON is for scripts.** The profile-sourced
  unknown-kernel-param note (`apparmor=0` from `exploit-dev`) lives only in
  `unknown_kernel_params_by_source.profile`; `compile --run`'s `Compiled and
  ran …` banner goes to stderr so stdout is the program's stdout (as `exec`).
  `SnapshotError` and every `doctor` row carry a machine-readable `hint`; the
  `doctor` skills row prints a one-line `summary` (JSON `detail` keeps the
  paths; `detail_paths` splits installed/missing/stale).
- **`tests/test_state_agreement_matrix.py` is the guard for that whole class.**
  Seven rounds of dogfooding produced the same defect shape — a fix improves one
  path's message and leaves its siblings contradicting it — always on one of
  four axes: preview vs real, branch vs branch, text vs JSON, subcommand vs
  subcommand. Per-fix rules do not catch it; the matrix does. Adding an
  observable state, or a command that reports on one, means adding a row. Its
  fixtures must include a *decoy running VM*: without one `choose_instance`
  short-circuits to "No running VMs" and the invariant assertion never exercises
  the "VM 'X' not found. Running: …" branch the real CLI produces.

## Tests

The autouse `isolate_qmu_env` fixture (`tests/conftest.py`) redirects
`QMU_CACHE_DIR`/`QMU_CONFIG_DIR`/`TMPDIR` at per-test temp dirs so the suite
never touches the developer's real state. When adding a test that patches a CLI
collaborator, patch it on the command module that owns the handler under test
(see the DAG note above), not on `cli`.

Unit doubles cannot see two whole classes of defect: anything that depends on
live QMP state, and anything that depends on a real panicking guest. Both
produced findings that a green suite had missed — verify state/exit-code changes
against a real VM as well as the seams.
