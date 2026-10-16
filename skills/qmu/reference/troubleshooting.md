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
prints a one-line `[qmu] Warning:` naming the file and continues from built-in
defaults and any valid project/CLI layers. `qmu doctor` then reports it as a
`[~] global config` row naming the file and the parse error — it does not say
"no config found", and `qmu config init` will not clear it, because that writes
a *project* file. An invalid **project** (`qmu.toml`) or explicit `--config`
file is fatal (exit 1) with the source path and offending key.

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
the per-user global is the one you mean. `qmu config show` prints the resolved
values but not `nic_model`/`net_backend`/`accel`.

## Auto-selection, precisely

Most commands (`status`, `exec`, `kill`, `gdb`, …) consider only **running** VMs,
so stopped remnants never make them ambiguous. `log`, `crash` and `wait
--pattern` also accept a **stopped** VM — that is how a dead VM's serial log
stays readable — so they see more candidates. When they cannot narrow to one,
they pick **the single running VM** and say so:

```
$ qmu log
[qmu] Auto-selected the only running VM 'poc' (8 other VM(s) exist; use --vm <id> to pick one).
```

In JSON the same fact is `"vm": "poc"` plus `"autoselected": "..."`. Both
commands always report which VM they read, auto-selected or not — never assume
it from context. With **no** running VM and several stopped ones, they are
genuinely ambiguous and error, naming the first few candidates and pointing at
`qmu prune --all` — do not run that on a shared host. On a shared host there is
never exactly one running VM, so auto-selection is never usable there: pass
`--vm` on every command.

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
`--out` paths are never marked as qmu-owned. **Callers must continue consuming
`artifact_path`** — never reconstruct spill names or paths. Read the path from
the result envelope's `artifact_path` field or the `[qmu] Output spilled to
<path>` stderr line; under `--format text` the pointer envelope itself is
printed as JSON on stdout. The envelope's `{"token_estimate": <int>,
"estimator": "chars/4"}` is a tokenizer-agnostic heuristic for sizing only.

## `doctor` rows

`qmu doctor` reports: config sources, QEMU binary, rootfs image, SSH key and
its permissions (separate rows), KVM, pry, libguestfs, running VMs, and the
installed skill links. Exits 1 when a gating row is `[!]` or no config is found
(it prints a `qmu config init` tip). `pry` is informational (only required for
`qmu gdb`).
`doctor` also has a `kernel` row — the resolved `[boot] kernel` must exist and
be a regular file (`[+]`), a missing one is gating (`[!]`), and an unconfigured
one is an informational `[~]` since `--kernel`/`--harness` launches still work.
It does not check cross toolchains or `gdb-multiarch`.
