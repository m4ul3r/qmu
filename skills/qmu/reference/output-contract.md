# Output formats, result envelope, exit codes, spilling

Companion to `skill://qmu`. The exit-code table is in the main skill; this
file is the shape of what each command prints and how to branch on it.

## Formats

All commands take `--format text|json|ndjson`, accepted before or after the
subcommand (`qmu --format json status --vm X` ≡ `qmu status --vm X --format
json`). `--vm` and `--out` are accepted in both positions too. `qmu --version`
(and `qmu version`) prints `qmu <ver>`; under `--format json` given before it,
`{"ok": true, "version": "…"}`.

## The envelope

Under `json`/`ndjson`, every command that gets past argument parsing emits one
object with `"ok": <bool>` — the single, command-agnostic success predicate.
`ok: false` comes in three shapes:

- **Exception paths** (`QMUError`, `ConfigError`, `QMPError`, `SSHError`,
  `SnapshotError`, `SCPFileError`, internal): `{"ok": false, "error": "…",
  "error_type": "<ExceptionClassName>", "hint": "…"}` plus, for `ConfigError`,
  `source`, `key` and `errors: [{source, key, message, hint}]` for every
  problem in the file. Text mode prints `[qmu] Error: …`, `[qmu] QMP error:
  …` or `[qmu] SSH error: …` on **stderr**.
- **Result-style failures** — the command ran and the answer is "no": a
  non-zero guest exit or `--timeout` overrun on `exec`/`run`/`compile --run`
  (`exit_code`, `timed_out`), transport loss (exit 3/4, `ssh_error`,
  `crash_detected`), `wait --pattern` no-match/timeout (`matched: false`,
  `reason`), bare `wait` timeout (`reason: "timeout"`, `stopped: false`),
  `crash` with no report (`crash_detected: false`). These carry **domain
  fields, not `error`/`error_type`**, and text mode prints the report on
  **stdout** with no prefix. The paused/panicked refusal of an SSH command is
  the hybrid: JSON `guest_state`/`qemu_status` without `error`, text `[qmu]
  Error: …` on stderr. The one result-style failure that *does* carry
  `error`/`error_type` is an expired `--ssh-timeout` on `launch`/`run`
  (exit 124, `error_type: "TimeoutError"`, `timed_out: true`, `ssh_error:
  true`, `hint`): the same shape for both verbs, so a caller branches once.
- **Usage errors** (exit 2): text prints argparse usage on stderr; a JSON
  format emits `{"ok": false, "error": …, "error_type": "UsageError",
  "usage": …, "hint": …}` on stdout. `run --harness` is this class.

**Every `ok: false` envelope carries `hint`**, whichever of the three shapes
produced it — the next command to run. On an exception path a raise site that
knows the recovery names it (`qmu log --vm X --tail 50`, `relaunch with
--ssh-port N`); otherwise the hint is the `error_type` default:
`SSHError` → `qmu status --vm X; qmu log --vm X --tail 50`,
`QMPError` → `qmu status --vm X` (`QMPBusyError`: retry when the other
client finishes; `QMPTimeoutError`: retry with a larger `--timeout`),
`ConfigError` → `qmu config show` / `qmu doctor`, `UsageError` → `qmu <sub>
--help`, anything else → `qmu status --vm X for VM state; qmu doctor for the
host environment` (doctor checks the host, never a guest path or a VM's
state — a transfer the guest filesystem refused names the guest path and the
`qmu exec … ls -ld` that inspects it instead).
A result-style failure sets its hint at the producer, specific to the
outcome: a guest exit N → `see stderr; qmu exec --vm X 'dmesg | tail -n 30'`
(or `qmu crash --vm X` when a kernel report was captured during the command),
a guest `--timeout` → raise it, `crash` with no current report → `qmu log --vm
X --tail 200` / `qmu crash --vm X --full-history`, `doctor` unhealthy → the
failing rows and their per-row `hint`s, `wait` timeout → raise `--timeout` /
`qmu log --vm X --tail 50`, `compile` failure → `compile_stderr` /
`--cflags`/`--host-build`, `prune --orphans` kill failure → the pid and `ps`.
None of these send you to `qmu doctor`: it checks the host, not the guest or
the caller's arguments. The renderer backstops any `ok: false` that reached it
without a hint with the neutral `qmu status --vm X; qmu log --vm X --tail 50`
— a safety net for a producer that forgot, never the intended answer (the
test matrix pins that the known producers do not rely on it). Text mode prints
`[qmu] Hint: …` after an error line only for a site-specific exception hint,
never for a type default; result-style hints are JSON-only (text mode already
prints the report and its `[exit code: N]`/follow-up notes).

**`warnings: [str]`** rides in every json/ndjson envelope that has
something to warn about — launch-time lints, the debugger-coherence warnings
(`snapshot save`/`load`, `qmp`/`monitor system_reset`, `kill` with a stranded
pry bridge; after a load or reset under qmu's own bridge, a teardown or
breakpoints left unarmed — the `debugger` object says what qmu did, see
`reference/debugging.md`), the `ignoring global config` notice from a broken
`~/.config/qmu/config.toml` (it fires in the config gate before the handler,
and still lands in the envelope — on success and on an `ok: false` one
alike). The same lines go to stderr in every mode, `[qmu] Warning:`-prefixed,
for a human tailing the terminal; the envelope entries are the bare
messages, deduplicated, in the order they fired. A clean command has no
`warnings` key (launch always has the list, `[]` when clean).

Every path emits **exactly one** object. A mutation whose QEMU side succeeded
but whose qmu bookkeeping then failed (`qmu qmp system_reset` / `qmu monitor
system_reset` with an unwritable instance directory) is exit 4 with a single
`{ok: false, error, error_type: "<raw exception class, e.g. PermissionError>",
result|output: <the QMP reply>, guest_mutated: true, hint}` — never an
`ok: true` object followed by a failure object; text mode prints nothing on
stdout and `[qmu] Error: …` on stderr. `guest_mutated: true` is the flag that
says the reset did happen even though the command failed.

Branch on the exit code and `ok`, never on the presence of `error`.

## Guest-command text mode

`exec`, `compile --run`, `dmesg`, `run`: stdout is the guest's stdout, **byte
for byte** — no decode, no added newline (`printf x` arrives as the single
byte `78`; a `0xff` byte passes through; `qmu exec … > out.txt` is
checksum-comparable with what the guest wrote). Guest stderr goes to host
stderr verbatim, followed by `[exit code: N]` **only when N ≠ 0**; `exec true`
prints nothing at all. `compile --run`'s `Compiled and ran X:` banner,
`dmesg`'s `(empty dmesg)` / `[dmesg failed, exit N]`, the report of a crash
the guest survived during the command (`Kernel crash report from command
serial output (the guest kept running):`), and `run`'s `VM 'x' stopped (state
preserved)… / Inspect: … / Clean up: …` lines are all on stderr. The
ssh-lost / timeout / paused narrative stays on stdout, preceded by whatever
guest stdout was captured (a newline is inserted between the two only then).
Guest `\r\n` is not translated. JSON cannot hold raw bytes, so its `stdout`/
`stderr` are a UTF-8 decode with U+FFFD replacement and carry
`stdout_lossy: true` / `stderr_lossy: true` (`run_stdout_lossy` under
`compile`; `text_lossy` for `dmesg`, whose stdout key is `text`) exactly when
something was replaced — read text mode or `--out` for the real bytes (a
spilled guest-output artifact is `.txt`, bytes verbatim).

### Streaming (`exec`, `run`, `compile --run`)

Guest output is relayed **as it arrives**, not when the command ends: a
long-running exploit's progress lines show up at ~the moment the guest
prints them, and are still there after a `--timeout` (exit 124) or a
mid-command panic (exit 3, the crash narrative follows what was already
printed). What is relayed is the raw read (no line assembly), flushed per
chunk. `compile --run` streams only the program's run; compile/chmod
diagnostics stay in the envelope.

- **text**: guest stdout chunks → stdout, guest stderr chunks → stderr, live;
  the `[exit code: N]` trailer and other notes follow on stderr once the
  command ends (on a fresh line if the guest's stderr ended without one).
  Bytes are identical to the buffered rendering (`| sha256sum` matches).
  `--out FILE` streams into the file as chunks arrive and prints the
  `[qmu] Output written to …` line at the end. Without `--out`, output up to
  the spill budget (40 000 bytes of stdout) streams inline; the chunk that
  crosses it diverts the **rest** to a spill file, the file holds the whole
  output (prefix included, `.txt`, bytes verbatim), and the stream closes
  with `[qmu] Output spilled to <path> (~N tokens)` / `[qmu] Preview: first
  40000 of B bytes (C omitted) streamed above` — pointer *after* the preview,
  unlike a buffered spill.
- **ndjson**: each chunk is one line `{"event": "chunk", "stream":
  "stdout"|"stderr", "data": "<text>"}` — `data` is the bytes decoded as
  UTF-8 with `surrogateescape` (JSON-escaped, so undecodable bytes survive as
  lone surrogates and a chunk may end mid-character); intermediate lines
  carry `event` and **no** `ok`. The last line is the normal envelope (`ok`,
  full `stdout`/`stderr`, …), so a reader that ignores `event` lines sees
  exactly the json result.
- **json**: unchanged — one buffered envelope.

## Exit 3 vs 4

Exit `3` is guest-side and always corroborated by a fresh serial crash report;
an internal qmu/transport fault is `4`, so a tooling bug is never mistaken for
a kernel panic. `exec`, `push`, `pull`, `compile`, `dmesg` and `run` apply the
rule identically: a lost connection is `3` only when a fresh crash corroborates
it (`crash_detected: true`), otherwise `4`. A guest `exit 255` is qmu exit 1
with `exit_code: 255`, not a crash. A VM running no sshd produces a `4` on
every `exec`.

## Output spilling

Results over ~10k estimated tokens (chars/4) are written to a file under the
spill root — `$QMU_TEMP_DIR/spills`, else `$XDG_RUNTIME_DIR/qmu/spills`, else
`<platform temp>/qmu/spills` — and stdout is replaced:

- **text**: `[qmu] Output spilled to <path> (~N tokens)`, then a preview
  bounded by **both** 40 lines and 4096 bytes (so one 200 000-byte line shows
  4096 bytes, not all of it), then `[qmu] Preview: first A of B bytes (C
  omitted; L of M lines)`; no JSON envelope. A *streamed* guest command
  (`exec`/`run`/`compile --run`) has already put its first 40 000 bytes on
  stdout when the budget is crossed, so there the pointer and `Preview: …
  streamed above` trailer come **last** (see *Streaming*).
- **json/ndjson**: a pointer envelope `{"ok", "artifact_path", "format",
  "bytes", "sha256", "token_estimate", "estimator": "chars/4", "summary"}`
  plus, copied from the result when it has them, its outcome keys `vm_id`,
  `exit_code`, `compile_exit`, `run_exit`, `timed_out`, `crash_detected`,
  `ssh_error`, `inconclusive`, `may_have_landed`, `error_type` and `hint` —
  so a spilled `ok: false` still tells exit 7 from a panic, a lost transport
  or a timeout, and still names the next command, without opening the file.

Both also print `[qmu] Output spilled to <path>` on stderr. Always consume the
printed path / `artifact_path`; never reconstruct spill names. `--out PATH`
forces a file; the file holds the result rendered in `--format`, so `qmu
crash --vm X --format text --out report.txt` saves the plain report while
`--format json --out` saves the `{"ok", "crash", …}` envelope with escaped
newlines. What stdout shows is per format: json/ndjson print the pointer
envelope above; **text prints one line**, `[qmu] Output written to <path>
(<N> bytes, exit <code>)` — `exit <code>` when the guest exit code is known,
`failed` when only `ok: false` is, nothing on success — never JSON (#71).
The pointer's `ok`/exit is the **operation's** result, never "the file was
written": a guest command that exited non-zero rendered through text `--out`
says `exit 7`, the process exit stays 1 (`[exit code: N]` still on stderr),
and JSON `--out` carries `ok: false` plus the same outcome keys (`exit_code`
is `null` on a timeout, as in the result) next to the artifact keys —
the artifact still holds the exact captured bytes either way. An automatic
text spill prints only the `[qmu] Output spilled to …` pointer and preview
(no envelope), so there the failure is the process exit plus the stderr
trailer. Branch on the exit code or `ok`, never on the presence of
`artifact_path`.
`rootfs cat` spills binary content to a `.bin`. Aged automatic spills are
reclaimed by `qmu prune --runtime` (`reference/cache.md`).
