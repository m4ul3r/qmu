# GDB integration with pry

Companion to `skill://qmu`. Read this before attaching a debugger: the gdbstub
halt semantics, the attach → resume → rebase → arm → wait order, bridge
lifecycle on a shared host, and the operations that silently invalidate
debugger state (Debugger↔VM coherence).

## The core flow

Explicit attach → continue → discover base → manual rebase → arm → resume →
trigger → wait. qmu never resumes, re-halts, or rebases for you.

```bash
KERNEL=./bzImage VMLINUX=./vmlinux                # the paired kernel + unstripped ELF (kbuild outputs)
qmu launch --kernel "$KERNEL" --gdb --name debug-vm --no-replace
qmu gdb --vm debug-vm --symbols "$VMLINUX"      # spawns a pry bridge; vCPU is now HALTED
qmu cont --vm debug-vm                          # resume so SSH (and kbase) work
eval "$(qmu kbase --vm debug-vm --symbols "$VMLINUX")"   # KBASE, LINK_BASE, SLIDE — SSH + kallsyms only
pry --instance qmu-debug-vm load "$VMLINUX" --base "$KBASE"   # first pry touch after qmu cont: HALTS again
pry --instance qmu-debug-vm break set __x64_sys_newuname      # trigger-specific canary (see below)
pry --instance qmu-debug-vm continue --background             # REQUIRED before any qmu exec
qmu exec --vm debug-vm "uname -r"               # trigger; returns in ~1 s with guest_state: paused once the bp fires
pry --instance qmu-debug-vm wait --timeout 10   # blocks until the stop; the reliable primitive
pry --instance qmu-debug-vm backtrace
```

**The trigger survives the stop.** When the breakpoint fires, `exec` returns
but leaves the command running: its SSH session stays open for as long as the
vCPU is halted (the connection's keepalive never gives up on a silent guest;
a 130 s halt was measured), and what it prints afterwards goes to the file in
`detached_output` (`cat` it after `pry continue`). Only the SSH connection
going away ends it — `snapshot load`, a reset and `kill` drop it. For a
trigger that must survive a rewind as well, start it fully detached and read
its log:

```bash
qmu exec --vm debug-vm 'setsid nohup /root/poc > /root/poc.log 2>&1 < /dev/null &'
pry --instance qmu-debug-vm wait --timeout 30   # inspect, then pry continue --background
qmu exec --vm debug-vm 'cat /root/poc.log'
```

`qmu kbase`'s stdout is eval-safe: it prints `KEY=value` lines or nothing, and
a refusal (VM paused, no SSH, panicked guest) goes to **stderr** as `[qmu]
Error: …` with exit 1, so a bare `eval "$(qmu kbase …)"` is a no-op on failure
with the message still visible (`KBASE` stays unset — test for it).
`--format json` reports `ok:false`, `guest_state:"paused"`, `qemu_status`.

**`qmu gdb --symbols`** launches pry connected to the GDB stub and loads the
ELF at its **link-time** addresses. Success reports `symbols_rebased:false`
and `symbol_base:"elf-link-time"`; the link-time warning is valid whether the
eventual KASLR slide is zero or nonzero. `kaslr_status` stays `"unknown"` —
the warning describes loading behavior, not guest KASLR configuration. qmu
never discovers a runtime base during `gdb` and never passes `--base` to pry.
The payload also carries `kvm` (recorded at launch) and, under KVM, a
`kvm_watchpoint_warning` (see the watchpoint row below), plus the spawned
bridge as `bridge_pid`. `qmu gdb` against a VM that already has an attached
client fails fast with exit 1 naming that client (`pry kill --instance
qmu-<vm>` or `<pid>` to detach it) and spawns nothing.

**`qmu kbase --vm NAME --symbols VMLINUX`** reads local ELF `_text` (via
`nm`/`llvm-nm`) and runtime `_text` (via guest `/proc/kallsyms`), then prints
eval-able `KBASE`, `LINK_BASE`, and `SLIDE` (JSON/NDJSON use the same values as
hex-string fields). It needs **only** normal guest SSH and readable kallsyms —
not `--gdb`, not a stub, not a pry bridge; it works on a plain VM. It **does
not** issue QMP `cont`, resume/re-halt the guest, invoke pry, or apply a
symbol base. Operational errors (exit 1) include: harness/no-SSH instances,
unsupported or legacy (`arch=None`) architecture metadata, restricted
kallsyms (`kptr_restrict`), missing symbols/tools, missing `_text`, and a
paused/debugger-stopped guest (returned immediately with `qmu cont`/`pry
continue` guidance). On arm64 pass `KBASE` as-is: pry keys the slide to
`_text`, so `KBASE` is the right base there too (details and the `_stext`
anti-pattern in `skill://qmu/reference/cross-arch.md`).

## Halt-on-attach, and who resumes

- **Attaching halts the vCPU.** `qmu gdb` and `pry launch --connect` both
  stop the guest (gdbstub `target remote` = vCPU stop) until an explicit
  resume: `qmu cont`, `pry continue`, or `qmu monitor cont`.
- **After `qmu cont`, the first pry command that touches the target halts it
  again** — `pry load`, `pry status`, `pry registers` all do (measured: QMP
  `running` → one `pry status` → `paused`). GDB still believes the target is
  stopped, and the gdbstub stops the VM on any packet received while running.
  So the order above is not optional: `qmu cont` exists to let `kbase` read
  kallsyms over SSH; after `pry load` the VM is halted again and only
  `pry continue` makes it serve SSH.
- **One resume authority per stop.** Resume through *either* pry or qmu for a
  given stop, never both: `qmu cont` after a pry-observed stop leaves GDB's
  view stale (`Cannot execute this command while the target is running` on
  the next inspect). Recover with `pry interrupt`, then continue through pry.
- **SSH commands refuse a halted guest fast.** Before `exec`/`push`/`pull`/
  `compile`/`dmesg`/`kbase` builds an SSH client, qmu queries QMP; any
  `running:false` state (`paused`, `debug`, `restore-vm`, `prelaunch`, …)
  fails in ~0.1 s with exit 1, `guest_state:"paused"`, `qemu_status`,
  `ssh_error:false`, `crash_detected:false` and a `qmu cont` / `pry continue`
  hint — except `restore-vm` (a failed mid-restore `snapshot load`), whose
  hint is a known-good `snapshot load` or `kill` + relaunch and which `qmu
  cont` itself refuses (`snapshots.md`); text mode prints `[qmu] Error: VM 'X' is debug (vCPU halted).` on
  stderr (the word is QEMU's status name: `debug` for a breakpoint stop,
  `paused` after `qmu gdb`/`stop`). A breakpoint that fires **during**
  `exec`/`compile --run`/`dmesg` is caught by the same QMP watch within ~1 s
  and returns the identical paused envelope (exit 1, `exit_code:null`, the
  output that reached the host before the stop), never exit 4 "VM may be
  unreachable" and never after the SSH keepalive. `exec`/`run`/`compile
  --run` leave the command running (text `vCPU halted while running (command
  left running): <cmd>`, JSON `detached_output`: the file its further output
  goes to); `compile`'s gcc step and `dmesg` are aborted (`SSH connection lost
  while running: <cmd>`). `pry wait` then shows the stop.
- **qmu's own SSH probe runs `uname`.** `status`/`list`/`launch` readiness
  probes execute `uname` in the guest, so a `__x64_sys_newuname` breakpoint
  fires on a `qmu status` with no trigger of yours. `status`/`list` therefore
  skip the probe while a gdb client is attached (`ssh: "skipped (debugger
  attached)"`); with no client attached (bridge torn down, breakpoints baked
  into a snapshot) the
  probe runs and can trip the canary — read `pry status`, not `guest_detail`,
  when a `uname` stop appears that you did not send.
- **Choose a trigger-specific canary.** `commit_creds` fires on every `execve`
  in the guest, so it is hit by unrelated guest activity before your trigger
  connects and your own `qmu exec` is then refused with `is debug`. Use the
  syscall your trigger makes (`__x64_sys_newuname` + `uname -r`). For the same
  reason, delete or condition hot-syscall breakpoints (`__x64_sys_getpid`,
  `commit_creds`, …) before resuming for guest commands — every `qmu exec`
  pays a syscall path.

## Waiting and polling

- **`pry wait --timeout N` is the stop-detection primitive.** `pry status` is a
  ~0.75 s snapshot that can lag a hit: in one of five measured trials it
  reported `running` for 41 s while the vCPU had been halted at the
  breakpoint and `pry wait` returned the hit immediately.
- **Never spawn `pry launch --connect` in a poll loop.** Every attach halts
  the guest, so a loop freezes the workload on each iteration and the
  symptom reads as "the exploit hung". Reuse the one bridge (`pry wait`), or
  observe from the qmu side — `qmu wait --pattern`, `qmu log --grep` — which
  never touches the stub.
- `pry interrupt` answers `not interrupted (inferior is stopped)` when the
  target is already at a stop; that reply is trustworthy where `pry status`
  may not be.
- pry cannot see a kernel panic: the bridge reports `running` while the guest
  sits in the panic loop. `qmu status --vm X` (`guest: "panicked"`) is the
  authority.

## Bridge lifecycle on a shared host

Each successful `qmu gdb` spawns a pry bridge (a gdb process) that outlives the VM.
`pry doctor` lists every bridge on the host — including other agents' — and a
bare `pry` command with more than one alive errors with `Multiple bridge
instances running (pids: A, B). Use --instance <pid>`.

- **Address your bridge by name.** `qmu gdb`'s payload carries
  `bridge_instance_id: "qmu-<vm>"` next to `bridge_pid`; `pry --instance
  qmu-<vm> …` is stable across a kill/relaunch cycle where the pid is not.
  Another agent's `pry launch` mid-flow otherwise turns every bare `pry`
  command of yours into the multiple-instances error. `pry doctor` does not
  show which port a bridge is on, so with several unnamed bridges `ss -tnp |
  grep :<gdb_port>` is the fallback.
- **After `qmu kill` + relaunch**, `qmu kill` reaps the bridge that `qmu gdb`
  spawned for that VM (`bridge_reaped: true` in kill's JSON; `false` when
  there was nothing to reap or the bridge was hand-started). A bridge you
  started by hand (`pry launch --connect`) still points at the dead stub;
  qmu prints a stderr note at `kill` time when such a client was attached.
  Recovery: `pry doctor` → `pry --instance <id> status` (the stale one fails
  with `RuntimeError: Remote target disappeared without an exit code or
  termination signal; reconnect before inspecting or resuming the target`,
  exit 1; the live one reports `stopped`/`running`) → `pry kill --instance
  <stale>`.
- **A clean `pry kill` detaches, but do not assume it resumed the vCPU.**
  From an ordinary breakpoint stop the detach lets QEMU resume and the VM
  is `serving` again. After a `qmu snapshot load` into a debug stop the
  outcome is not fixed: a clean kill (`Killed GDB`, `pry doctor` →
  `instances: none`) has left the VM `Guest: paused`, `qemu_status:
  "paused"` (#133), and on QEMU 8.2.2 it has also resumed the rewound guest
  straight into whatever the load restored (a baked-in `int3` → `guest:
  "panicked"`, see the table below). An **unclean** bridge death (`kill
  -9`, a crash) does not detach, so the vCPU stays halted and looks the same
  — `paused` with an empty `pry doctor` is therefore **not** proof of an
  unclean death. Either way: **check `qmu status --vm <id>` after `pry
  kill`**; `qmu cont --vm <id>` resumes a paused one.
- **Reconnect after a bridge death** with `pry launch --connect
  localhost:<gdb_port> --symbols "$VMLINUX" --instance-id <name>` (the port
  is in `qmu status`); that attach halts the guest again, so finish with
  `pry continue`.

## Hardware watchpoints

A watchpoint fires only on writes through the **watched virtual address**. A
kernel write to the same bytes via a different mapping (heap/physmap alias —
common in LPEs corrupting e.g. `modprobe_path`) does not trip a watchpoint set
on the symbol's VA. That reads as a silent miss but is not KVM's fault:
measured on qemu 8.2.2, a `jiffies` watchpoint fired within a second under
**both** KVM and TCG (`qmu launch --no-kvm`). Suspect the alias first and watch
the VA the write actually goes through; `--no-kvm` is the retest lever for a
QEMU/KVM build that drops gdbstub watchpoints, not a required setting.
(`launch --help` for `--no-kvm` says the same.)

## Debugger↔VM coherence (which operations invalidate debug state)

The QEMU gdbstub protocol does **not** tell an attached client when the machine
changes underneath it, so several everyday qmu operations make the debugger's
view silently diverge from the guest — no error, wrong answer. qmu knows a VM
has a GDB stub (it was launched with `--gdb`) and warns on stderr at each such
event. Treat every warning below as: **the debug state you can see is now
suspect; re-establish it before trusting a register/memory read or a
breakpoint.**

| You run | What silently breaks | Recover |
|---|---|---|
| `qmu snapshot load` | The bridge's connection survives the rewind but its view is the **pre-load** vCPU state (stale `$rip`/stop reason) and stale breakpoint/memory bookkeeping, presented as current. The stderr warning says exactly this. | Do what the warning says: tear the stale bridge down first (`pry kill --instance qmu-<vm>`), then reconnect with `pry launch --connect localhost:<gdb_port> --symbols "$VMLINUX" --instance-id qmu-<vm>` — or a fresh `qmu gdb`, which is refused with exit 1 (`A debugger client is already attached to port N (pry bridge pid P)`) until the stale bridge is gone — and re-arm every breakpoint before trusting a register or memory read. After a load into a debug stop, a clean `pry kill` may or may not resume the vCPU (see *Bridge lifecycle*): check `qmu status --vm <id>`, and `qmu cont --vm <id>` only if it is `paused` (after a fresh `qmu gdb`, `qmu cont` is its documented next step anyway). |
| `qmu snapshot save` (breakpoints armed) | Software breakpoints are `int3` (`0xCC`) bytes; the save **bakes them into the image**. A later `load` + run traps at that address with no live breakpoint → `Oops: int3` at the breakpointed symbol, `Kernel panic - not syncing: Fatal exception in interrupt` — mimicking your PoC crashing the kernel (reproduced live). | Clear breakpoints before saving a clean image; treat a post-load `int3` crash at a breakpointed function as a debugger artifact, not an exploit result. This warning fires on **every** save of a `--gdb` VM, attached client or not (see below) — it is not a bug when no debugger is connected. |
| `qmu qmp system_reset` / `qmu monitor system_reset` (or a guest reboot) | The gdbstub's breakpoint/watchpoint set is **dropped**; the client still lists them `[enabled]` but they never fire again (`hits=0`). **KASLR re-slides on the reboot**, so the symbols loaded in pry are wrong too — re-arming by symbol name without reloading lands on the old address, silently (`hits=0`, no error). | `qmu kbase` again → `pry load "$VMLINUX" --base "$KBASE"` again → then re-set every breakpoint; confirm with a canary you can prove is hit. |
| A **hardware watchpoint** doesn't fire on a write you can prove happened | Wrong virtual address (alias), see above. | Watch the VA the write goes through; `--no-kvm` only to rule out a KVM guest-debug limitation. |

A **guest-initiated reboot** hits the same reset failure as the reset row but is
not observable to qmu synchronously, so no warning fires: after any reboot,
assume breakpoints are gone and the base has moved until a canary confirms
otherwise.

These warnings are keyed on the VM having a GDB stub; qmu additionally
suppresses them when it can positively confirm no client is connected, and errs
toward warning when it cannot tell. **Exception: `snapshot save`.** A debugger
that already detached can have left `int3` bytes in guest memory, and the save
captures them whether or not anyone is attached now, so the save warning is
keyed on the stub alone and always fires for a `--gdb` VM (the exit stays 0
and the stdout envelope is untouched). Auto re-sync / auto re-arm is a pry-side
capability qmu does not drive — the contract qmu enforces is "invalidate
loudly," not "fix it for you."

## Non-goals

qmu never invokes `pry load --base` automatically — the operator applies the
reported base. Neither `gdb` nor `kbase` silently resumes or re-halts the
guest. `qmu gdb --help`, `kbase --help` and `cont --help` carry no epilog; this
file is the reference.
