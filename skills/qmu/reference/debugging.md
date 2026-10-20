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
but leaves the command running: its SSH session stays open (a 120 s halt was
measured), and what it prints afterwards goes to the file in
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
client fails fast with exit 1 and spawns nothing. When the client is the
bridge `qmu gdb` spawned (its process owns the client end of the stub
connection), the refusal names it (`pry bridge pid P`; reuse it as `pry
--instance qmu-<vm>` or detach with `pry kill --instance P`). Any other
client — hand-started, or one that took the stub after qmu's bridge
disconnected (then the refusal says qmu's bridge is alive but not connected)
— is not reachable as `qmu-<vm>`, so the refusal says it is not qmu's and
points at `pry doctor` → `pry --instance <pid> info target` (the one
connected to `remote localhost:<gdb_port>`) → reuse it under its own name or
`pry kill --instance <pid>`. `qmu kill` then still reaps qmu's bridge and
notes the stranded client.

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
  Recovery: `pry doctor` (it lists the stale bridge as `status=ok` like any
  other) → `pry --instance <id> status` on each. The stale one ends one of
  two ways, depending on how QEMU went away: after `qmu kill` (an orderly
  quit, which makes QEMU's gdbstub report the "process" exited, `W00`) it
  says `state: exited` / `reason: exited (code 0)` with exit 0; after a QEMU
  that died without that packet (`kill -9`, a crash) it fails with
  `RuntimeError: Remote target disappeared without an exit code or
  termination signal; reconnect before inspecting or resuming the target`,
  exit 1. A live one reports `stopped`/`running`. Then `pry kill --instance
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

| You run | What silently breaks | Recover (each run as written against a live bridge) |
|---|---|---|
| `qmu snapshot load` | The bridge's connection survives the rewind. Frame and registers are re-read and current, but a bridge that was at a stop keeps reporting the **pre-load stop reason** (`reason: breakpoint #1 hit` while `frame: amd_e400_idle`). **KVM:** breakpoints it had inserted while the guest ran are **no longer in guest RAM** (`0xcc` → `0x53` at the address): still listed `[enabled]`, they never fire (`uname` runs through). **TCG:** breakpoints live in QEMU, not guest RAM, so they keep firing after the load (measured, no re-arm). | **KVM:** addresses did not move, so re-arm in place: `pry --instance qmu-<vm> interrupt` (`not interrupted (inferior is stopped)` at a stop is fine), then `pry --instance qmu-<vm> continue --background` — GDB re-inserts every breakpoint when it resumes (`0xcc` back; the canary fires: `reason: breakpoint #1 hit`). Loading a `possible` image brings its `int3`s back and nothing tracks them (measured: `0xcc` stayed through `pry interrupt`, even with a breakpoint re-set at that address): load a `lifted` image or reboot instead. **TCG:** nothing to re-arm; trust the frame, not the reason, until the next stop. A second `qmu gdb` is refused with exit 1 (`A debugger client is already attached to port N (pry bridge pid P)`), never a second bridge. |
| `qmu snapshot save` | Under KVM a software breakpoint is an `int3` (`0xCC`) byte in guest RAM **whenever GDB has the target running**; GDB lifts its breakpoints at a stop. A save taken while the debugger runs the guest **bakes them into the image**; a later `load` + run traps at that address with no live breakpoint → `Oops: int3` at the breakpointed symbol, `Kernel panic - not syncing: Fatal exception in interrupt` — mimicking your PoC crashing the kernel. Measured at the breakpoint address of four images: saved running `0xcc`; at a breakpoint stop, after `pry interrupt`, and by the recovery below `0x53` (clean). Under TCG breakpoints never reach guest RAM. | `breakpoints_in_image` says which, from QEMU's run state read **before and after** the save (savevm resumes a running guest before it returns, so a breakpoint hit right after it reads `debug` for an image taken while running — measured with `0xcc` in the image; both reads must agree): `"possible"` (stderr **warning**: QEMU was `running`, the state moved across the save, or `paused` with no debugger stop qmu could confirm), `"lifted"` (stderr **note**: QEMU `debug`, or `paused` and the bridge `qmu gdb` spawned, as the attached client, reports `stopped`), `"never"` (TCG; nothing printed). For a clean image save at a stop: `pry --instance qmu-<vm> interrupt` → `qmu snapshot save --vm <vm> <tag>` (→ `"lifted"`) → `pry --instance qmu-<vm> continue --background`. `int3`s nothing tracks survive even a save at a stop: a breakpoint deleted while the guest runs (m4ul3r/pry#56), or one a `possible` image brought back on load. Treat a post-load `int3` crash at a breakpointed function as a debugger artifact, not an exploit result. |
| `qmu qmp system_reset` / `qmu monitor system_reset`, or a **guest reboot** (`panic=N`, a watchdog, a triple fault, `sysrq b`) | **KVM:** the gdbstub's breakpoint/watchpoint set is **dropped**; the client still lists them `[enabled]` but they never fire again (`hits` frozen). **TCG:** QEMU keeps them at their old addresses — with `nokaslr` they keep firing (measured, no re-arm). **KASLR re-slides on the reboot** (`0xffffffff93400000` → `0xffffffff8d400000`), so the symbols loaded in pry are wrong too and, under either accelerator, the breakpoints sit where nothing runs. A reset that lands while the debugger is **at a stop** leaves the vCPU halted at the reset vector (QEMU `prelaunch`, `EIP=0000fff0`), and `pry continue` does not start it (KVM and TCG alike: no console output after 20 s). | If the warning says the guest is still halted, `qmu cont --vm <vm>` first (it boots; GDB still believes it is stopped). Then, once SSH answers: `eval "$(qmu kbase --vm <vm> --symbols "$VMLINUX")"` (needs the guest running) → `pry --instance qmu-<vm> interrupt` → `pry --instance qmu-<vm> load "$VMLINUX" --base "$KBASE"` → `pry --instance qmu-<vm> continue --background`. The breakpoints already set re-resolve to the new base — no re-set (the canary fired at `0xffffffff8d7d3680`, its new address; under TCG at `0xffffffff8b9d3680`). `pry load` while the target still runs leaves them `<PENDING>` (m4ul3r/pry#57), hence the interrupt first. On a `nokaslr` guest addresses do not move: under KVM `interrupt` → `continue --background` alone re-arms; under TCG there is nothing to re-arm unless the reset landed at a stop (then the same two commands after `qmu cont`). |
| A **hardware watchpoint** doesn't fire on a write you can prove happened | Wrong virtual address (alias), see above. | Watch the VA the write goes through; `--no-kvm` only to rule out a KVM guest-debug limitation. |

The recoveries above name `qmu-<vm>`, the bridge `qmu gdb` spawned; so do the
warnings, but only while that bridge is the attached client — its process
owns the client end of the stub connection. For a hand-started client, or
one that took the stub after qmu's bridge disconnected, they print `<id>`
instead (its pid or `--instance-id`, from `pry doctor`).

A **guest-initiated reboot** is announced too, though no qmu command caused
it: its kernel boot banner lands in the serial log, and the next command that
resolves the VM (`status`, `kbase`, `exec`, `gdb`, `snapshot`, `qmp`, `wait`,
…) puts the reset warning — worded `its guest rebooted by itself` — in its
`warnings[]` and on stderr, **once**: the command after it is quiet, and so is
the one after a bare `wait` that already reported the reboot in-band. The VM
record keeps the generation the debugger was last told about
(`debugger_epoch_offset`); `qmu gdb`, a reset, a load and each announcement
move it.

These warnings are keyed on the VM having a GDB stub; qmu additionally
suppresses them when it can positively confirm no client is connected, and errs
toward warning when it cannot tell. **Exception: `snapshot save`.** A debugger
that detached uncleanly can have left `int3` bytes in guest memory, and the save
captures them whether or not anyone is attached now, so the save's verdict is
keyed on the stub and QEMU's run state alone: every save of a `--gdb` VM under
KVM carries `breakpoints_in_image` and a warning or a note (the exit stays 0).
`paused` is what an interrupt, a fresh attach and a QMP `stop` all leave (QEMU
reports a QMP `stop` to the client as `SIGINT`, and an attached GDB lifts its
breakpoints then too — measured `0xcc` → `0x41`), but only the client knows
whether it took that stop: qmu asks `pry status` of the bridge it spawned when
that bridge is the attached client — and only while QEMU is already paused,
because a pry command against a target GDB believes stopped halts a running
VM — and says `possible` for any other client. Auto re-sync / auto re-arm is
a pry-side capability qmu does not drive — the contract qmu enforces is
"invalidate loudly," not "fix it for you."

## Non-goals

qmu never invokes `pry load --base` automatically — the operator applies the
reported base. Neither `gdb` nor `kbase` silently resumes or re-halts the
guest. `qmu gdb --help`, `kbase --help` and `cont --help` carry no epilog; this
file is the reference.
