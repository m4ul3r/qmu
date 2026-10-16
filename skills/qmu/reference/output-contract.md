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

Branch on the exit code and `ok`, never on the presence of `error`.

## Guest-command text mode

`exec`, `compile --run`, `dmesg`, `run`: stdout is the guest's stdout, byte
for byte (a trailing newline is added if missing). Guest stderr goes to host
stderr verbatim, followed by `[exit code: N]` **only when N ≠ 0**; `exec true`
prints nothing at all. `compile --run`'s `Compiled and ran X:` banner,
`dmesg`'s `(empty dmesg)` / `[dmesg failed, exit N]`, a survived `Kernel
warning from command serial output:` block, and `run`'s `VM 'x' stopped (state
preserved)… / Inspect: … / Clean up: …` lines are all on stderr. The
ssh-lost / timeout / paused narrative stays on stdout, preceded by whatever
guest stdout was captured. Guest `\r\n` is not translated. Non-UTF-8 guest
output arrives with U+FFFD replacement, never a `UnicodeDecodeError`.

## Exit 3 vs 4

Exit `3` is guest-side and always corroborated by a fresh serial crash report;
an internal qmu/transport fault is `4`, so a tooling bug is never mistaken for
a kernel panic. `exec`, `push`, `pull`, `compile`, `dmesg` and `run` apply the
rule identically: a lost connection is `3` only when a fresh crash corroborates
it (`crash_detected: true`), otherwise `4`. A guest `exit 255` is reported as
255, not a crash. A VM running no sshd produces a `4` on every `exec`.

## Output spilling

Results over ~10k estimated tokens (chars/4) are written to a file under the
spill root — `$QMU_TEMP_DIR/spills`, else `$XDG_RUNTIME_DIR/qmu/spills`, else
`<platform temp>/qmu/spills` — and stdout is replaced:

- **text**: `[qmu] Output spilled to <path> (~N tokens)` followed by the first
  40 lines of the text; no JSON envelope.
- **json/ndjson**: a pointer envelope `{"ok", "artifact_path", "format",
  "bytes", "sha256", "token_estimate", "estimator": "chars/4", "summary"}`.

Both also print `[qmu] Output spilled to <path>` on stderr. Always consume the
printed path / `artifact_path`; never reconstruct spill names. `--out PATH`
forces a file and prints the pointer envelope (as JSON, in every format).
`rootfs cat` spills binary content to a `.bin`. Aged automatic spills are
reclaimed by `qmu prune --runtime` (`reference/cache.md`).
