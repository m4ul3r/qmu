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

qmu skill install               # symlink skills/* into ~/.claude/skills (and ~/.codex if present)
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
cli.py  ->  commands/{lifecycle,guest,qmp_cmds,meta}  ->  _cliutil.py  ->  domain modules
```

- `cli.py` is *only* `main()`: it builds the argparse tree (calling each
  module's `_add_*` registrar in display order) and maps handler exceptions to
  exit codes. No handlers live here.
- `commands/lifecycle.py` — launch, kill, prune, wait, list, status, doctor.
- `commands/guest.py` — push, pull, exec, compile, dmesg, crash, log (SSH- and
  serial-facing).
- `commands/qmp_cmds.py` — snapshot, gdb, cont, qmp (raw), monitor (HMP).
- `commands/meta.py` — config, rootfs, skill, version.
- `_cliutil.py` — shared helpers (`_emit`/`_output`, `_kill_vm`, arg-option
  registrars, config resolution, QMP/SSH context). Bottom of the DAG; never
  imports `cli` or `commands.*`.

Each command module imports its collaborators (`choose_instance`, `_make_ssh`,
`launch_vm`, `save_snapshot`, …) **directly into its own namespace**. This is
what makes them patchable: tests patch the *owning* command module, e.g.
`monkeypatch.setattr(lifecycle, "choose_instance", ...)` for `status`, or
`guest._make_ssh` for `exec` — not `cli.*`. Patching works because each
`_add_*` looks up the handler name at `main()`-call time, so a test that patches
a module attribute before calling `cli.main([...])` is seen by dispatch.

### Exit-code contract (see the epilog in `cli.py:main`)

`0` success · `1` operation failed (guest non-zero, doctor unhealthy, snapshot
failed, no crash found, operational QMUError) · `2` usage/argparse ONLY · `3`
guest kernel crash · `4` infra/internal (QMP/SSH failures, unexpected errors)
· `124` wait timeout. `QMUError -> 1`, `QMPError`/`SSHError -> 4`, the catch-all
`-> 4`. Never let a raw traceback escape to the agent.

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

### Output rendering (`output.py`)

Every handler funnels its result through `_emit(args, data=<dict>, text=<str|list>, stem=...)`.
Text mode renders `text`; `json`/`ndjson` render `data` as a `{"ok": bool, ...}`
envelope. Results whose estimated size exceeds `DEFAULT_SPILL_TOKEN_LIMIT`
(~10k tokens, chars/4) are spilled to a file under `$TMPDIR/qmu-spills` and the
stdout is replaced with an artifact-pointer envelope. `--out` forces a file.

### Instance lifecycle & PID-recycling guard (`instance.py`, `vm.py`)

A `VMInstance` (dataclass) is persisted as JSON under `~/.cache/qmu/instances/`
alongside `<vm_id>.qmp.sock`, `<vm_id>.serial.log`, and `<vm_id>.qemu.log`.
Writes are atomic (tempfile + `os.replace`). Liveness uses `instance_alive()`,
which compares the process's `/proc/<pid>/stat` start-time (`pid_start`, captured
at launch) against the recorded value so a recycled PID after a reboot is not
mistaken for a live VM — prefer it over bare `is_pid_alive()` anywhere a stale
instance JSON might name a reused PID. `list_stopped_instances()` also
synthesizes records from orphan `.serial.log` files. `launch_vm()` auto-allocates
free ports and retries up to 3× on a launch-time bind race (find_free_port has a
TOCTOU window that it deliberately does not try to close).

### VM state has TWO orthogonal axes

Never collapse them into one enum.

- **Existence** — `instance.classify_vm(vm_id)` → `running` / `orphaned` /
  `held_back` / `stopped` / `absent`. Answers "is there a record and/or a
  process". This is the single authority; a command that answers about a
  `vm_id` must route through it. `status`/`kill` once used `choose_instance`
  (running-only) while `list`/`log` used `find_instance`, which is why
  "not found" kept being reported for VMs `qmu list` was displaying.
- **Guest usability** — `lifecycle._guest_state(inst)` → `serving` / `paused` /
  `crashed` / `panicked` / `unknown`. The predicate is **usability**, never
  "is a crash retrievable" — those diverge, and conflating them is a bug that
  shipped once. Precedence, in order:
  - `panicked` — `serial.has_terminal_panic()` found `Kernel panic - not
    syncing`; the guest is gone and reaping is correct.
  - `paused` — QMP `running:false`; where `qmu gdb` leaves every VM until
    `qmu cont`.
  - `crashed` — a report is retrievable AND the guest still serves. Under the
    default `exploit-dev` profile (deliberately no `oops=panic`) an Oops kills
    only the faulting task, so this is the common outcome of a trigger. It is
    neither `serving` (a report is waiting) nor `panicked` (**do not reap it**).
  - `serving` / `unknown`.

  Both crash reads are scoped to `max(recorded epoch,
  serial.last_boot_offset())`. `guest_epoch_serial_offset` only advances on an
  **observed** QMP RESET, so a guest-initiated reboot between two commands is
  invisible to it and a previous-boot panic would otherwise label a healthy
  guest as gone — instructing a destructive action on working state. The
  kernel's own boot banner is the log-local ground truth.

  **Known, scoped separately:** `qmu crash` and `wait --pattern` still use the
  raw epoch, so both can still be satisfied by pre-reboot content. Predates the
  guest axis; not fixed here.

The cross product is real — orphaned+panicked is the everyday outcome of a
triggered crash on a VM whose metadata was lost — so adding `paused`/`panicked`
as existence-enum values would force `orphaned+panicked`, `stopped+…` and grow
combinatorially. `list` must report both; it used to consult neither QMP nor
crash detection and presented a panicked VM identically to a healthy one.

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

### Serial-pattern waiting (`serial.SerialTail`, `lifecycle._wait_for_pattern`)

`SerialTail` is an offset-carrying line reader over a log QEMU is still writing.
It withholds a trailing fragment with no newline so a matcher never sees half a
line, and `flush()` releases it for the final pass. `_wait_for_pattern` takes
*one extra scan* after `instance_alive()` goes false (the `saw_dead` flag): the
guest can print its marker and exit between a scan and the liveness check, and
dropping that line would turn a success into a spurious exit 1.

### Config resolution (`config.py`)

Layered: built-in defaults < global (`~/.config/qmu/config.toml`) < project
(nearest `qmu.toml` walking up from CWD, or `--config`) < CLI flags. A broken
*global* config warns and is skipped; a broken *project/explicit* config is
fatal. Profiles (kernel cmdlines) from config extend/override the built-in
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

### Harness mode

`--harness` = boot-and-die VMs (kernelCTF/syzkaller): implies `--no-wait-ssh` +
`--no-net`, skips the rootfs/SSH-key requirement, allocates no SSH port. SSH
commands (`push`/`pull`/`exec`/`compile`/`dmesg`) then error via `_require_ssh`;
serial/QMP commands (`log`/`crash`/`wait`/`qmp`/`monitor`/`kill`) work. `qmu wait`
blocks on QMP `STOP`/`SHUTDOWN`/`POWERDOWN` events with PID-liveness fallback.

## Gotchas

- **Snapshots need a qcow2 disk AND `net_backend=passt`.** HMP `savevm` can't
  store internal snapshots in the default `raw` image / `snapshot=on` overlay,
  and slirp (`-net user`) state can't be serialized by `savevm`/`loadvm`.
  `qmu snapshot save` fails out of the box by design; the handler emits the
  actionable hint.
- **`rootfs inject` treats GUEST as a directory** (with or without a trailing
  slash); the local filename is preserved. A missing GUEST directory is an
  ERROR unless `--mkdir` — silently creating it turns a typo'd destination into
  a reported success while the stale binary stays put. It shells out to
  `guestfish`; if libguestfs can't build its appliance (e.g. mode-600 `/boot`
  kernels), point it at a fixed appliance via `SUPERMIN_KERNEL` or
  `LIBGUESTFS_PATH`. `qmu doctor` checks both the binary and appliance-kernel
  readability.
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
  VM `qmu list` was showing them. Use `lifecycle.describe_non_running()`.
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
