# The MCP façade (`qmu mcp serve`)

`qmu mcp serve` is the same CLI behind an MCP server: every subcommand is a
tool, every tool returns the `--format json` envelope this skill documents,
and nothing is re-implemented on the way. Use it when the host speaks MCP
natively; keep using the CLI from a shell when it does not — the two never
disagree, because the tool call *is* the CLI call.

## Registration

```
claude mcp add qmu -- qmu mcp serve
```

Generic stdio config (any host that takes a JSON server entry):

```json
{"mcpServers": {"qmu": {"command": "qmu", "args": ["mcp", "serve"]}}}
```

The server runs in the **host's working directory**, and that CWD is where
`qmu.toml` is looked up (walking upward, as the CLI does): register it from
the project directory, or pass `config: "/path/qmu.toml"` on the tools that
take `--config`. `QMU_CACHE_DIR`/`QMU_DAEMON` and the other environment
knobs apply to the server process exactly as to the CLI.

## Tool naming (derived, never hand-listed)

The tool list is walked out of the real argparse tree at startup: a leaf
subcommand `qmu <sub>` is `qmu_<sub>`; a grouped one `qmu <group> <sub>` is
`qmu_<group>_<sub>` — `qmu_launch`, `qmu_exec`, `qmu_snapshot_save`,
`qmu_rootfs_ls`, `qmu_daemon_status`. An alias (`status`/`show`) is one
tool. Not exposed: `mcp serve` itself, `daemon run` (the foreground
server), `skill install` (host mutation) and `rootfs shell` (interactive).

Arguments are the subcommand's own flags and positionals, keyed by their
argparse name with `-` as `_` and the leading `--` dropped:

| CLI | Tool argument |
|---|---|
| `--vm X` | `vm: "X"` |
| `--no-replace` (store-true) | `no_replace: true` |
| `--timeout 30` (`float`/`int`) | `timeout: 30` (number / integer) |
| `--net-backend passt` (choices) | `net_backend: "passt"` (enum) |
| `--inject A:/b --inject C:/d` (repeatable) | `injects: ["A:/b", "C:/d"]` |
| `--qemu-arg -M --qemu-arg pc` (dash-leading values) | `extra: ["-M", "pc"]` — every valued option is sent as one `--flag=value` token, so a value starting with `-` is never read as a flag |
| positional `name` | `name: "clean"` (required unless the CLI makes it optional) |
| `--symbols F` (argparse `required=True`) | `symbols: "F"`, listed in the schema's `required` like a positional |
| `exec`/`run`/`monitor` command | `command: "uname -a"` — **one string is one guest token**, exactly the CLI rule; a list is spread |

`--format` and `--out` are not arguments: the façade always runs
`--format json` and returns the result inline. Descriptions are the first
sentence of each `--help` line; `qmu <sub> --help` and this skill remain
the full reference.

`qmu_argv` takes `argv: [...]` (everything after `qmu`) for anything the
derived tools do not express, or when you already know the CLI syntax.
`--format`/`--out` are **managed** there too, at parse level rather than
by spelling: the argv goes through the real parser (argparse
abbreviations such as `--for=text` or `--ou PATH` are accepted exactly as
on the CLI), then `format` is forced to `json` and `out` to none before
dispatch, so no spelling switches the renderer or writes a file — the
managed envelope comes back regardless.

## Result: the envelope plus `qmu_exit`

Each call returns the CLI's JSON envelope as `structuredContent`, with
**`qmu_exit`** added — the process exit code `qmu` would have returned,
because MCP has no exit codes. Domain keys are never touched: `exit_code`
is still the **guest command's** code on `exec`/`run` (`37` for `exit 37`,
`null` when `--timeout` expired with `timed_out: true` and `qmu_exit: 124`),
and absent where the CLI has none. The text content is a status line
(`ok=true qmu_exit=0`, or the `error_type: error` and `hint` on failure)
followed by the compact JSON. `isError` mirrors `ok`. Branch on `ok` and
`qmu_exit` exactly as the *Exit codes* table says — never on a transport
error, because there is none:

- an operational failure is `{"ok": false, "error": …, "error_type": …,
  "hint": …, "qmu_exit": 1}` (`QMPError`/`SSHError`/internal: `4`; a
  corroborated kernel crash: `3`; a timeout: `124`), the same keys
  `qmu --format json` prints;
- a bad or missing argument is `error_type: "UsageError"`, `qmu_exit: 2`,
  with `usage` and the CLI's `hint` (`qmu <sub> --help`);
- `warnings[]`, `autoselected`, `crash`, `exit_code`, `stdout`/`stderr` and
  every other domain key are untouched;
- output that is not an envelope (only reachable via `qmu_argv`: `--help`,
  a group's help) is `{"ok": true, "qmu_exit": 0, "stdout": "<text>"}`
  when the exit was 0, and `{"ok": false, "error_type": "NoEnvelope"
  (or "UsageError" on 2), "error", "hint", "qmu_exit", "stdout"?}`
  otherwise.


A result larger than the spill threshold comes back as the same **pointer
envelope** the CLI prints (`spilled: true`, `artifact_path`, a preview):
read the file. There is no byte streaming over MCP — `exec`/`run` output is
delivered when the command ends, and `ndjson` chunk events do not exist
here.

## Resources

| URI | Content |
|---|---|
| `qmu://vms` | the `qmu list` envelope (`vms[]`) |
| `qmu://vm/{vm_id}/log` | the `qmu log --vm {vm_id} --tail 200` envelope (`log` holds the text) |

Both are JSON text and go through the same handlers as the tools, so an
unknown `vm_id` is the `log` handler's `QMUError` envelope, not a protocol
error.

## Progress

`qmu_wait` (bare and `--pattern`) reports progress while it blocks when the
client supplied a progress token: one `notifications/progress` per second
with `progress` = elapsed seconds (no total) and `message` =
`waiting on <vm> (<N> B scanned)`; a QMP event observed meanwhile adds a
`QMP <NAME> on <vm>` message. The events come from the daemon
(`reference/daemon.md`); with `QMU_DAEMON=off` the wait still works but
reports no progress. Long tools are not cut short by the façade — the
command's own `--timeout`/`--ssh-timeout` govern, as on the CLI; set the
host's per-request timeout accordingly for a long `wait`.

Tool calls run concurrently (a `qmu_exec` can write the marker a
`qmu_wait` is blocking on), each in its own context: `autoselected` and
`warnings[]` belong to the call that produced them.

## Limits

- No byte streaming; large results are spill pointers (above).
- CWD determines `qmu.toml`; the server does not change directory per call.
- Everything qmu writes to stderr (auto-selection notes, debugger-coherence
  warnings) is the server's stderr — the host shows it as server log; the
  same lines ride in the envelope's `warnings[]` where the CLI puts them.
- Interactive leaves (`rootfs shell`) and the foreground daemon are not tools.

Schema cost: the serialised `tools/list` (38 tools) is ~21.6k characters,
roughly 5.4k tokens — a third of this skill — and is paid once per session.
