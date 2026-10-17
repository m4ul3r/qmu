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
  "error_type": "<ExceptionClassName>"}` plus, for `ConfigError`, `source`,
  `key`, `hint` (first problem) and `errors: [{source, key, message, hint}]`
  for every problem in the file. Text mode prints `[qmu] Error: …`, `[qmu]
  QMP error: …` or `[qmu] SSH error: …` on **stderr**.
- **Result-style failures** — the command ran and the answer is "no": a
  non-zero guest exit or `--timeout` overrun on `exec`/`run`/`compile --run`
  (`exit_code`, `timed_out`), transport loss (exit 3/4, `ssh_error`,
  `crash_detected`), `wait --pattern` no-match/timeout (`matched: false`,
  `reason`), bare `wait` timeout (`reason: "timeout"`, `stopped: false`),
  `crash` with no report (`crash_detected: false`). These carry **domain
  fields, not `error`/`error_type`**, and text mode prints the report on
  **stdout** with no prefix. The paused/panicked refusal of an SSH command is
  the hybrid: JSON `guest_state`/`qemu_status` without `error`, text `[qmu]
  Error: …` on stderr.
- **Usage errors** (exit 2): text prints argparse usage on stderr; a JSON
  format emits `{"ok": false, "error": …, "error_type": "UsageError",
  "usage": …}` on stdout. `run --harness` is this class.

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
`dmesg`'s `(empty dmesg)` / `[dmesg failed, exit N]`, a survived `Kernel
warning from command serial output:` block, and `run`'s `VM 'x' stopped (state
preserved)… / Inspect: … / Clean up: …` lines are all on stderr. The
ssh-lost / timeout / paused narrative stays on stdout, preceded by whatever
guest stdout was captured (a newline is inserted between the two only then).
Guest `\r\n` is not translated. JSON cannot hold raw bytes, so its `stdout`/
`stderr` are a UTF-8 decode with U+FFFD replacement and carry
`stdout_lossy: true` / `stderr_lossy: true` (`run_stdout_lossy` under
`compile`; `text_lossy` for `dmesg`, whose stdout key is `text`) exactly when
something was replaced — read text mode or `--out` for the real bytes (a
spilled guest-output artifact is `.txt`, bytes verbatim).

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
  omitted; L of M lines)`; no JSON envelope.
- **json/ndjson**: a pointer envelope `{"ok", "artifact_path", "format",
  "bytes", "sha256", "token_estimate", "estimator": "chars/4", "summary"}`.

Both also print `[qmu] Output spilled to <path>` on stderr. Always consume the
printed path / `artifact_path`; never reconstruct spill names. `--out PATH`
forces a file and prints the pointer envelope (as JSON, in every format); the
file holds the result rendered in `--format`, so `qmu crash --vm X --format
text --out report.txt` saves the plain report while `--format json --out`
saves the `{"ok", "crash", …}` envelope with escaped newlines.
The pointer envelope's `ok` is the **operation's** result, never "the file
was written": a guest command that exited non-zero rendered through text
`--out` reports `ok: false` plus `exit_code` (present only when known —
omitted on a timeout, where it is null) next to the artifact keys, the
process exit stays 1 (`[exit code: N]` still on stderr), and JSON `--out`
carries the same `ok: false` — the artifact still holds the exact captured
bytes either way. An automatic text spill prints only the `[qmu] Output
spilled to …` pointer and preview (no envelope), so there the failure is the
process exit plus the stderr trailer. Branch on the exit code or `ok`, never
on the presence of `artifact_path`.
`rootfs cat` spills binary content to a `.bin`. Aged automatic spills are
reclaimed by `qmu prune --runtime` (`reference/cache.md`).
