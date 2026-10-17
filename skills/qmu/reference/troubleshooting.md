# Troubleshooting and reference details

Companion to `skill://qmu`. Longer-form detail the main skill points at:
libguestfs setup, config validation rules, VM auto-selection, output spilling,
and the `doctor` rows.

## libguestfs prerequisite (offline `rootfs inject`, `launch --inject`)

Everything that edits an image offline needs libguestfs (`guestfish`), and it
is frequently broken out of the box: Debian/Ubuntu ship `/boot/vmlinuz-*` as
mode `0600`, the supermin appliance builds unprivileged, and the resulting
failure is reported as an opaque "appliance closed the connection
unexpectedly". **Run `qmu doctor` first** — it checks both `guestfish` and
whether an appliance kernel is readable, and prints the fix:

```bash
sudo chmod 0644 /boot/vmlinuz-*
# or, leaving system permissions alone:
sudo install -m 0644 /boot/vmlinuz-$(uname -r) /var/tmp/vmlinuz
export SUPERMIN_KERNEL=/var/tmp/vmlinuz \
       SUPERMIN_KERNEL_VERSION=$(uname -r) \
       SUPERMIN_MODULES=/lib/modules/$(uname -r)
```

The `libguestfs` row is a non-blocking **warning** (`[~]`): `qmu doctor` exits
0 on a host where everything but offline inject works, and the row still names
the fix.

`qmu rootfs ls` and `cat` are read-only (they open the image `--ro`) and work
while a VM is running. `inject`, `rm`, and `shell` write, so they refuse an
image a running VM holds and name the VM to kill. If qmu reports no such VM but
libguestfs still cannot open the image, an **untracked** QEMU is holding it —
`qmu prune --orphans --dry-run` finds those (it matches only QEMUs launched by
qmu, via the QMP socket path in their argv). A VM launched with an explicit
`--drive` for the image is tracked by `qmu list` but is *not* detected as the
holder; kill it by name.

### Why `inject` refuses a missing GUEST directory, and `rm` a missing path

A silent `mkdir` would turn `./exploit:/rooot` into a reported success while
`/root/exploit` still holds the previous build — precisely the stale-code
failure injection is meant to rule out. Pass `--mkdir` when you mean to create
it. For the same reason `rm` errors on a path that does not exist instead of
`rm -f`'s silent success; `--force` tolerates a missing path (and still lists
it under `removed`), and `--recursive` handles directories. A failed inject
leaves the previous iteration's binary in place, so the next boot re-runs stale
code while looking like a fresh result — `qmu rootfs ls`/`cat` after every
inject is how you rule that out.

`--partition N` selects the partition (default `1`; `0` for whole-disk). Images
built by `qmu-linux-rootfs`, and Debian cloud images like `trixie.img`, are
whole-disk ext4 — they need `--partition 0`. If you get it wrong, the error
names the partitions guestfish actually found.

## Config layering and schema

Resolution order, later wins: built-in defaults (arch=x86_64, memory=4G,
cpus=2) → global `~/.config/qmu/config.toml` → project `qmu.toml` found by
walking up from CWD (or `--config PATH`) → CLI flags. `--config` is
registered only on `launch`, `run`, `status`/`show`, `list`, `log`, `crash`,
`doctor` and `config show`; elsewhere it is an argparse error (exit 2).

TOML settings are table-scoped. The accepted schema is:

- `[boot]`: `kernel`, `initrd`, `cmdline`, `profile`
- `[machine]`: `arch`, `memory`, `cpus`, `cpu`, `nic_model`, `net_backend`, `accel`, `no_reboot`, `extra_args`
- `[drive]`: `rootfs`, `format`
- `[ssh]`: `key`, `user`, `port_start`
- `[gdb]`: `port_start`
- `[daemon]`: `autostart`, `idle_exit` (the per-user supervisor — `daemon.md`)
- `[profiles.<name>]`: `cmdline`; `[profiles] name = "..."` is also accepted

`qmu config init` writes `[boot]` (`kernel` live as the first `# CHANGE ME`; `initrd`/`profile`/`cmdline` commented), `[machine]` (arch/memory/cpus, with commented `cpu`/`accel`/`no_reboot`/`nic_model`/`net_backend`/`extra_args`), `[drive]` (rootfs/format — rootfs is the second `# CHANGE ME`), `[ssh]` (key — the third `# CHANGE ME` — and user, with commented `port_start`), `[gdb]` (commented `port_start`), `[daemon]` (commented `autostart`/`idle_exit`), three `[profiles.*]` blocks, and a commented harness-mode block. It refuses to overwrite an existing file (`created: false`, exit 0). `[ssh] user` (default `root`) is recorded on the VM at launch, so set it **before** `qmu launch`; SSH/GDB ports start at `10021`/`1234` (`port_start` overrides); `arch` picks the `qemu-system-*` binary and whether KVM is enabled (guest arch == host only), with `extra_args` for machine flags (e.g. aarch64 `-M virt -cpu cortex-a57`); path values accept `~`. Per-user defaults belong in the global file; the starter's uncommented `[ssh] key` overrides it.

## Config validation rules

Every loaded global, project, or explicit `--config` file is validated before
its values are applied. Malformed TOML, unknown keys, misplaced keys, wrong
section shapes, and wrong value types fail with the source path and offending
key. Flat `arch`, `rootfs`, or `ssh_key` entries are invalid and the error
names the canonical destination (`[machine] arch`, `[drive] rootfs`, `[ssh] key`).

Each layer may be empty or partial. `[drive]` and `[ssh]` are not universally
required: another layer or CLI flags may provide their values, and harness mode
intentionally runs without them.

An invalid **global** config (`~/.config/qmu/config.toml`) is non-fatal: qmu
prints `[qmu] Warning: ignoring global config: …` naming the file and every
problem, and continues from built-in defaults and any valid project/CLI
layers. `qmu doctor` then reports it as a `[!] global config` row — it does
not say "no config found", and `qmu config init` will not clear it, because
that writes a *project* file. An invalid **project** (`qmu.toml`) or explicit
`--config` file is fatal: exit 1, `error_type: "ConfigError"`. **All schema
problems of a file are reported in one run**: text prints one `Invalid config
<path>: key '…': …` line per problem and the recovery paragraph last; JSON
adds `source`, `key`, `hint` (first problem) and `errors: [{source, key,
message, hint}]`.

Every subcommand validates the project/explicit layer before it runs —
including `kill`, `prune`, `crash`, `log` and `wait`, which answer from
instance records. Only `config`, `doctor`, `cache`, `rootfs`, `skill` and
`version` are exempt (`config` and `doctor` report the same fault themselves;
the rest never read `qmu.toml`). So a broken `qmu.toml` blocks VM cleanup too:
fix the file, or run the command from a directory outside the project — the
project search walks up from CWD only. Do **not** reach for `--config` as the
way out: only `launch`, `run`, `status`/`show`, `list`, `log`, `crash`,
`doctor` and `config show` register that flag, so `qmu kill --vm X --config
good.toml` is an argparse error (exit 2), not a recovery.

Relative paths in a config file (`kernel`, `rootfs`, `initrd`, `ssh.key`)
resolve relative to **that config file's directory**, like every other
project-config tool, so `qmu launch` from a subdirectory finds the same files
the file names; `~` and absolute paths resolve as written; CLI flags resolve
against the CWD. Error messages name the resolved absolute path and the config
source that set it.

The starter `qmu.toml` writes an **uncommented** `[ssh] key = "~/.ssh/qmu_id_rsa"`,
which overrides a global `~/.config/qmu/config.toml` key; comment it out if
the per-user global is the one you mean.

## `config show` and `config path`

`qmu config path` prints the global and project paths with `(not found)` /
`(none found — searched up from CWD)`; JSON `global_config`,
`global_config_exists`, `project_config` (null when none). It answers "which
file is qmu reading?" before anything is launched.

`config show` text: a `Layers:` line (`built-in defaults -> global <path> ->
project <path>`), then one row per setting ending with its layer tag
`[built-in | global <path> | project <path> | --config <path> | flag]`; path
rows show `<as written> -> <resolved>` and `(not found)`; `Accel:`, `NIC
model:`, `Net backend:`, `Extra args:` are always present; profiles one per
line with their layer. JSON: `boot`, `machine` (`arch`, `memory`, `cpus`,
`cpu`, `nic_model`, `net_backend`, `accel`, `extra_args`), `drive`, `ssh`,
`gdb`, `profiles`, `sources` (`{dotted key: layer}`), `layers` (ordered list),
`paths` (`boot.kernel`, `boot.initrd`, `drive.rootfs`, `ssh.key` → `{written,
resolved, exists}` or null when unset). `config show` reports *resolution*,
not health: it is `ok: true` with a missing kernel — branch on
`paths.<key>.exists`, or run `doctor`, whose rows are the health verdict.

## Auto-selection, precisely

Most commands (`status`, `exec`, `kill`, `gdb`, …) consider only **running** VMs,
so stopped remnants never make them ambiguous. `log`, `crash` and `wait
--pattern` also accept a **stopped** VM — that is how a dead VM's serial log
stays readable — so they see more candidates. Whenever a command settles on
the single running VM without `--vm`, it says so — never silently:

```
$ qmu log
[qmu] Auto-selected the only running VM 'poc' (pass --vm to pin it).
```

(`log`/`crash` picking the only VM on disk when it is stopped say `the only
VM (stopped) 'poc'` instead.)

In JSON the same fact is `"autoselected": true` next to the VM name (`vm` for
`log`/`crash`, `vm_id` elsewhere). Every command reports which VM it acted
on, auto-selected or not — never assume it from context. `QMU_REQUIRE_VM=1`
in the environment turns every
auto-selection into exit 1 (`--vm is required: QMU_REQUIRE_VM is set`,
`error_type: QMUError`); export it on a shared host so a forgotten `--vm`
cannot kill or exec into a sibling's VM during the moments when theirs is the
only one running. With **no** running VM and several stopped ones, `log`/
`crash` are genuinely ambiguous and error, naming the first few candidates
and pointing at `qmu prune --vm <id>` (and `qmu prune --all --dry-run` only
as a preview); qmu never recommends a bare `prune --all`. With several
running VMs the error is `Multiple VMs running. Specify one with --vm <id>:`
plus the list.

`--vm`, `--format`, and `--out` are accepted **both before and after** the
subcommand — `qmu --vm <id> exec "..."` and `qmu exec --vm <id> "..."` are
equivalent. On `launch`/`run`, `--vm` is an alias for `--name` (it names the
new VM; if both are given `--name` wins). The global `--vm` help string
"auto-selects if only one" does not apply there, nor to `doctor`/`config`/
`rootfs`, which accept and ignore it.

## Output spilling

Large outputs (>10k estimated tokens) auto-spill to a file under the
centralized spill root, in precedence order: `$QMU_TEMP_DIR/spills`, then
`$XDG_RUNTIME_DIR/qmu/spills` when that XDG runtime directory is
absolute/existing/writable/searchable, then `<platform temp>/qmu/spills`.
Automatic spills are marked with an adjacent ownership sidecar; explicit
`--out` paths are never marked as qmu-owned. **Callers must consume the
printed path** — never reconstruct spill names. Under `--format text` stdout
is `[qmu] Output spilled to <path> (~N tokens)` followed by the first 40
lines of the text; under json/ndjson (and with `--out`, in every format) a
pointer envelope with `artifact_path` replaces the result. The same `[qmu]
Output spilled to <path>` line goes to stderr in every mode. The envelope's
`{"token_estimate": <int>, "estimator": "chars/4"}` is a tokenizer-agnostic
heuristic for sizing only. Shapes: `output-contract.md`.

## `doctor` rows

Glyphs: `[+]` ok · `[!]` gating failure (drives exit 1) · `[~]` non-blocking
warning · `[i]` informational. JSON rows are `{check, status: ok|fail|warn|
info, detail, blocking: bool, hint: str}` — `hint` is the fix as a runnable
command or setting (`""` when there is nothing to fix) — and `ok` ⇔ no `fail`
row. `doctor` exits 1 only when a `[!]` row is present; a missing config is
`[~] config: No qmu.toml or <global path> found. Run: qmu config init` with
exit 0 (the `Tip: run qmu config init` line appears only when no
project/`--config` layer loaded). `doctor --config PATH` checks that file.

| Row | Verdict |
|---|---|
| `config` | `[+]` layers that applied; `[~]` none found / every file rejected |
| `global config` | `[!]` when `~/.config/qmu/config.toml` exists but is invalid (it was skipped; `qmu config init` writes a *project* file and will not clear it) |
| `kernel` | `[+]` regular file; `[!]` configured but missing — `<as written> (not found) — resolves to <abs> [<layer>]`, `CHANGE ME placeholder;` when the starter literal is unedited; `[~]` not configured (`--kernel`/`--harness` launches still work) |
| `initrd` | same shape: `[+]` regular file; `[!]` configured but missing (launch fails with `Initrd not found`); `[i] initrd: not configured` (optional) |
| `rootfs image`, `SSH key` | `[!]` missing/unconfigured only when `[boot] kernel` is set and the boot is not harness-shaped (`initrd` set, no `rootfs`); otherwise `[~] … not needed for --harness boots` |
| `SSH key permissions` | `[!]` (blocking, `chmod 600 <key>` hint) when a key you own has any group/other bit (`mode=644 is group/other-accessible — OpenSSH refuses it (UNPROTECTED PRIVATE KEY FILE)`) or is unreadable; `[+]` for `0600`, `0400`, `0700` or a key another user owns |
| `qemu-system-<arch>`, `KVM` | `[!]` binary missing / `accel=kvm` without `/dev/kvm`; `[i]` disabled by `accel=tcg` |
| `cross compiler for <arch> (compile --host)`, `gdb-multiarch` | only when `[machine] arch` ≠ host arch; `[~]` when missing, naming `apt install gcc-<triple>` / `apt install gdb-multiarch` |
| `libguestfs` | `[~]` with the appliance fix (above) |
| `rootfs sshd policy` | only when `[drive] rootfs` exists: `[+] key-only` (stamp `/etc/qmu-rootfs.json` says `sshd_policy=key-only`); `[~] permissive (image predates key-only sshd; rebuild with tools/mkrootfs.sh)` for a missing/other stamp — root logs in with **any** key (JSON `sshd_policy: "permissive"`, hint `rebuild the image with tools/mkrootfs.sh`); `[i] not checked (<reason>)` when libguestfs cannot open the image (read-only, whole-disk, ~1.5 s) |
| `running VMs` | `[i] N running [+ M orphaned (no instance record)] under <instances dir>`; JSON `running`/`orphaned` ints, hint `qmu prune --orphans --dry-run` when orphans exist. A snapshot — other agents change it within seconds |
| `skills` | text `[+] N skills × M roots installed` (or `…: N installed, M missing, K stale … (run: qmu skill install)`) — the JSON `summary`; JSON `detail` keeps the full path list and `detail_paths: {installed, missing, stale}` splits it. `qmu skill install` then reports each link as `installed` (nothing was there), `relinked` (pointed at another checkout — JSON `previous_target` names it), `replaced` (a real dir/file was removed) or `current` (already right; left untouched, tallied not listed); JSON carries `links[]` and `counts` |
| `pry`, `passt`, `cache` | `[i]`/`[+]`, never gating |
| `daemon` | `[+] running (pid N, watching M VM(s), idle exit Ns)`; `[i] not running (autostarts on the next VM command)` is the normal idle state; `[i] disabled (QMU_DAEMON=off)`; `[~] unavailable: stale record / unresponsive` points at `daemon.log` (hint `qmu daemon status`). `doctor` never spawns it. JSON `running`, `mode` |
