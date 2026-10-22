# GDB integration with pry

Companion to `skill://qmu`. Read this before attaching a debugger: the gdbstub
halt semantics, the attach → resume → rebase → arm → wait order, bridge
lifecycle on a shared host, and the operations that silently invalidate
debugger state (Debugger↔VM coherence).

## The core flow

Explicit attach → discover base → rebase → arm → resume → trigger → wait.
Outside the coherence events below (a load, a reset or a save under the
bridge `qmu gdb` spawned), qmu never resumes, re-halts, or rebases for you.

```bash
KERNEL=./bzImage VMLINUX=./vmlinux                # the paired kernel + unstripped ELF (kbuild outputs)
qmu launch --kernel "$KERNEL" --gdb --name debug-vm --no-replace
qmu gdb --vm debug-vm --symbols "$VMLINUX"      # spawns a pry bridge; vCPU is now HALTED
pry --instance qmu-debug-vm kbase               # validated runtime _text, no SSH; rebases the loaded vmlinux
pry --instance qmu-debug-vm break set __x64_sys_newuname      # trigger-specific canary (see below)
pry --instance qmu-debug-vm continue --background             # REQUIRED before any qmu exec
qmu exec --vm debug-vm "uname -r"               # trigger; returns in ~1 s with guest_state: paused once the bp fires
pry --instance qmu-debug-vm wait --timeout 10   # blocks until the stop; the reliable primitive
pry --instance qmu-debug-vm backtrace
```

`pry kbase` (pry #66) reads the IDT[0] (x86-64) or VBAR (arm64) handler of
the halted guest, maps it back through the vmlinux's symbol table, and exits 0
only once the guest's `linux_banner` at that base matches the file; it then
rebases the loaded vmlinux itself (measured on x86-64 6.1 and arm64 7.0: the
same `_text` as `qmu kbase` and kallsyms). It needs the kernel booted and its
vmlinux loaded, and exits 1 (`could not determine the kernel base`) rather
than guess. The SSH route instead: `pry --instance qmu-debug-vm continue
--background` (no breakpoint is set yet, so nothing is armed), `eval "$(qmu
kbase --vm debug-vm --symbols "$VMLINUX")"` (KBASE, LINK_BASE, SLIDE — SSH +
kallsyms only), `pry --instance qmu-debug-vm load "$VMLINUX" --base "$KBASE"`
(on the running target pry stops it, loads, and resumes it), then the same
`break set` (likewise on a running target). Resume through the bridge, not
with `qmu cont` (next section).

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
`--format json` reports `ok:false`, `guest_state:"paused"`, `qemu_status`. A
breakpoint that fires **while** `qmu kbase` reads kallsyms — its own read
(`kallsyms_open`), or sshd setting up the session (`commit_creds` ←
`__sys_setgid`) — is reported the same way within ~1 s, stdout still empty
(#234; measured: exit 1 in 2.3–3.2 s wall, `nm` of a 7.0 KASAN vmlinux
included, where it used to be exit 4 `SSH command timed out after 10.0s`).

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
paused/debugger-stopped guest, before the read or during it (with the same
resume hint as the other SSH commands, below). On arm64 pass `KBASE` as-is: pry keys the slide to
`_text`, so `KBASE` is the right base there too (details and the `_stext`
anti-pattern in `skill://qmu/reference/cross-arch.md`).

## Halt-on-attach, and who resumes

- **Attaching halts the vCPU.** `qmu gdb` and `pry launch --connect` both
  stop the guest (gdbstub `target remote` = vCPU stop) until an explicit
  resume. Resume through the debugger: `pry --instance qmu-<vm> continue
  --background` (GDB inserts its breakpoints when it resumes). `qmu gdb`'s
  own warning says the same.
- **`qmu cont` (or `qmu monitor cont`) resumes QEMU behind GDB's back.** GDB
  still believes the target is stopped, with every breakpoint lifted (`0x41`
  at a breakpoint after `qmu cont` from a breakpoint stop, and the canary ran
  through, under KVM and TCG alike), and its next command halts the guest again, silently: measured
  after `qmu gdb` → `qmu cont`, every pry command run against the running
  guest — `pry status`, `registers`, `break list`, `load`, `kbase`, even
  `interrupt` (`not interrupted (inferior is stopped)`) — left QEMU `paused`,
  and `pry status` reports the old stop reason at the new frame (`reason:
  breakpoint #1 hit`, `frame: amd_e400_idle`; pry #100). `qmu cont` on a VM a
  debugger holds (`debug`, or `paused` under the `qmu gdb` bridge) therefore
  carries a `warnings[]` entry. Either way `pry --instance qmu-<vm> continue
  --background` gets back in agreement: the guest runs with `0xcc` at the
  breakpoint and the canary fires, whether a pry command had re-halted it or
  not (from a breakpoint stop it takes up to ~2 s: GDB first steps the vCPU
  off the stop, and QEMU reads `paused` meanwhile — measured 3 of 3). `pry
  kbase` needs no resume at all.
- **One resume authority per stop: the debugger.** `qmu cont` is for a halt
  no debugger holds (a QMP `stop`, the `paused` an unclean bridge death can
  leave, a reset that left the vCPU in `prelaunch`) — never for `debug`
  with no client on the stub: that is a breakpoint a dead debugger left in
  RAM, which `qmu cont` re-runs (*Bridge lifecycle*, below).
- **SSH commands refuse a halted guest fast.** Before `exec`/`push`/`pull`/
  `compile`/`dmesg`/`kbase` builds an SSH client, qmu queries QMP; any
  `running:false` state (`paused`, `debug`, `restore-vm`, `prelaunch`, …)
  fails in ~0.1 s with exit 1, `guest_state:"paused"`, `qemu_status`,
  `ssh_error:false`, `crash_detected:false` and a resume hint — `pry
  --instance <id> continue --background` when a debugger holds the stop
  (`debug`, which only a gdbstub stop produces, or `paused` under the `qmu
  gdb` bridge; `<id>` is `qmu-<vm>` for that bridge), saying why not `qmu
  cont`; `qmu gdb` then `pry continue` when QEMU is at `debug` with no client
  attached (an orphaned breakpoint, *Bridge lifecycle*); otherwise `qmu cont` — except `restore-vm` (a failed mid-restore `snapshot load`), whose
  hint is a known-good `snapshot load` or `kill` + relaunch and which `qmu
  cont` itself refuses (`snapshots.md`); text mode prints `[qmu] Error: VM 'X' is debug (vCPU halted by a debugger).` on
  stderr (the word is QEMU's status name: `debug` for a breakpoint stop,
  `paused` after `qmu gdb`/`stop`). A breakpoint that fires **during**
  `exec`/`compile`/`push`/`pull`/`dmesg`/`kbase` is caught by the same QMP
  watch within ~1 s and returns the identical paused envelope (exit 1,
  `exit_code:null`, the output that reached the host before the stop), never
  exit 4 "VM may be unreachable" and never after the SSH keepalive.
  `exec`/`run`/`compile --run` leave the command running (text `vCPU halted
  while running (command left running): <cmd>`, JSON `detached_output`: the
  file its further output goes to); `compile`'s gcc step, `dmesg` and
  `kbase` are aborted (`SSH connection lost while running: <cmd>`). `pry
  wait` then shows the stop.
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
  never touches the stub. A `--pattern` wait whose guest halts at a
  breakpoint/watchpoint/step stop (QEMU `debug`) ends there instead of
  burning its `--timeout` (#235): exit 1, `reason: "debugger_stop"`,
  `guest_state: "paused"`, `qemu_status`, and a `hint` naming `pry --instance
  <id> wait` and the debugger's resume (measured on a 7.0 KASAN guest with
  a `__x64_sys_syncfs` canary: halted before the wait → exit 1 in 0.3–0.4 s;
  a detached `sleep 2; sync -f /` job → exit 1 at 1.8–2.0 s, daemon on and
  off; it used to be 124 after the whole `--timeout`, hinting "raise
  --timeout"). Resume, then rerun the wait: it rescans the boot, so the
  marker printed after the resume matched at once (`elapsed: 0.002`). Any
  other halt (`paused`) may be qmu's own stop or yours about to end, so the
  wait goes on and a timeout that ends halted names the halt and its resume
  (`wait.md`).
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
- **An unclean death while the guest ran orphans its breakpoints (#237).**
  GDB had its `int3`s in guest RAM, and QEMU keeps them in its gdbstub's
  list with no client attached: the next guest call into such a function
  halts the vCPU in `debug` (measured: `kill -9` of the bridge's GDB,
  `pry doctor` → `instances: none`, `0xcc` still at `__x64_sys_syncfs`, and
  `qmu exec 'sync -f /'` → exit 1, `qemu_status: "debug"` in 1.2 s). `qmu
  cont` cannot resume that: the vCPU re-runs the `int3` and is back in
  `debug` at once, so `cont` exits 1 (`resumed: false`, `status: "debug"`,
  "did not stay resumed … halted again at once") — it used to say `resumed
  (status: debug)`, exit 0. `qmu status`/`list` (`guest_detail`: `halted at
  a breakpoint no debugger owns …`, and a `hint` on `status`), every SSH
  command's paused refusal and `cont` name the case and what clears it:
  attach a debugger, `qmu gdb --vm <id> --symbols "$VMLINUX"` — QEMU drops a
  gone client's breakpoints and writes the original bytes back when a new
  one connects (measured `0xcc` → `0xf3`) — then `pry --instance qmu-<id>
  continue --background` (`guest: "serving"`, and the halted `exec`'s
  `detached_output` got its `after-orphan` line). qmu calls a `debug` stop
  orphaned only when `/proc/net/tcp` shows positively no client on the stub.
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
has a GDB stub (it was launched with `--gdb`) and which pry bridge it spawned.
After a `snapshot load` or a qmu-issued `system_reset` it **drives that bridge**
while it is the attached client (`pry kbase` on a KASLR guest, then `pry
resync`, or a teardown that says why — see *What qmu does to the bridge it
spawned* below), and it stops that bridge across a `snapshot save` of a
running KVM guest; for any other client, and for a guest-initiated reboot, it
warns on stderr. Treat every warning below as: **the debug state you can see
is now suspect; re-establish it before trusting a register/memory read or a
breakpoint.** The recoveries in the table are what you run for a client qmu
does not drive (qmu's own drive replaces them for its bridge).

| You run | What silently breaks | Recover (each run as written against a live bridge) |
|---|---|---|
| `qmu snapshot load` | The bridge's connection survives the rewind. Frame and registers are re-read and current, but a bridge that was at a stop keeps reporting the **pre-load stop reason** (`reason: breakpoint #1 hit` while `frame: amd_e400_idle`). **KVM:** breakpoints it had inserted while the guest ran are **no longer in guest RAM** (`0xcc` → `0x53` at the address): still listed `[enabled]`, they never fire (`uname` runs through). **TCG:** breakpoints live in QEMU, not guest RAM, so the load leaves them in force at the addresses they were set at. **KASLR:** the image restores the kernel at the base of the boot it was saved in, which is not the debugger's base once the guest was reset or rebooted since the save, and qmu does not record which boot a tag came from (measured: an image from a boot at `0xffffffff85e00000` loaded into one at `0xffffffff92000000`; re-armed in place, the canary stayed dead, and under TCG the untouched breakpoint too). | **KASLR guest, KVM or TCG:** rebase, then re-arm: `pry --instance qmu-<vm> kbase` (no SSH; rebases the loaded vmlinux to the restored kernel) → `pry --instance qmu-<vm> resync` (`1 armed, 0 not armed`; the canary fired at `0xffffffff860667b0`, under TCG at `0xffffffff910667b0`), or `eval "$(qmu kbase --vm <vm> --symbols "$VMLINUX")"` → `pry --instance qmu-<vm> resync --base "$KBASE"`. A same-boot image takes the same two commands (`kbase` then says `already loaded at this slide`). **`nokaslr`, KVM:** addresses did not move, so re-arm in place: `pry --instance qmu-<vm> interrupt` (`not interrupted (inferior is stopped)` at a stop is fine), then `pry --instance qmu-<vm> continue --background` — GDB re-inserts every breakpoint when it resumes (`0xcc` back; the canary fires: `reason: breakpoint #1 hit`). **`nokaslr`, TCG:** nothing to re-arm; trust the frame, not the reason, until the next stop. A `possible` image brings its `int3`s back, also at a site whose breakpoint was deleted before the load (`0xcc` right after it). **KVM:** `pry --instance <id> resync` (pry #83) writes the symbol file's bytes back over every trap no breakpoint owns in the code it can map and lists each under `stray_traps` (measured with a hand-started client: `guest_bytes: "cc"`, `elf_bytes: "41"`, `repaired: true`, `0x41` after it, and `sync -f /` ran clean); qmu's own load does that for the `qmu gdb` bridge and names every repair (below). A `lifted` image or a reboot is the fallback only for a trap in code no loaded symbol file maps. A second `qmu gdb` is refused with exit 1 (`A debugger client is already attached to port N (pry bridge pid P)`), never a second bridge. |
| `qmu snapshot save` | Under KVM a software breakpoint is an `int3` (`0xCC`) byte in guest RAM **whenever GDB has the target running**; GDB lifts its breakpoints at a stop. A save taken while the debugger runs the guest **bakes them into the image**; a later `load` + run traps at that address with no live breakpoint → `Oops: int3` at the breakpointed symbol, `Kernel panic - not syncing: Fatal exception in interrupt` — mimicking your PoC crashing the kernel. Measured at the breakpoint address of four images: saved running `0xcc`; at a breakpoint stop, after `pry interrupt`, and by the recovery below `0x53` (clean). Under TCG breakpoints never reach guest RAM. | With the bridge `qmu gdb` spawned attached and the guest running under KVM, qmu does it itself: `pry interrupt` → save → `pry continue --background`, reported as `breakpoints_lifted: true` and `debugger.action: "stopped_for_save"` on every save route (measured: `0xcc` in RAM before the save, `0x41` in the image, the canary fired after). `breakpoints_in_image` says what the image holds, from QEMU's run state read **before and after** the save (savevm resumes a running guest before it returns, so a breakpoint hit right after it reads `debug` for an image taken while running — measured with `0xcc` in the image; both reads must agree): `"possible"` (stderr **warning**: QEMU was `running`, the state moved across the save, or `paused` with no debugger stop qmu could confirm), `"lifted"` (stderr **note**: QEMU `debug`, or `paused` and the bridge `qmu gdb` spawned, as the attached client, reports `stopped`), `"never"` (TCG; nothing printed). For a clean image under another client save at a stop: `pry --instance <id> interrupt` → `qmu snapshot save --vm <vm> <tag>` → `pry --instance <id> continue --background` (measured: `0x41` in the image). qmu can ask only the bridge it spawned whether it took a stop, so that save still reads `"possible"`, with a warning of its own: QEMU was `paused` before and after the save, and if your debugger took that stop (its interrupt, or a QMP `stop` it saw as `SIGINT`) the image holds none of its breakpoints; it names `pry resync` after a load for a trap left anyway, never the save-at-a-stop recovery again. A breakpoint deleted while the guest runs takes its byte with it (pry stops the target for the delete: `0xcc` → `0x41`); the `int3` nothing tracks is one a `possible` image brought back on load that no `pry resync` has repaired since, and it survives even a save at a stop. Treat a post-load `int3` crash at a breakpointed function as a debugger artifact, not an exploit result. |
| `qmu qmp system_reset` / `qmu monitor system_reset`, or a **guest reboot** (`panic=N`, a watchdog, a triple fault, `sysrq b`) | **KVM:** the new boot loads the kernel over the `int3`s of **software** breakpoints; the client still lists them `[enabled]` but they never fire again (`hits` frozen). **Hardware** breakpoints and watchpoints are not in guest RAM and stay armed at their addresses: with `nokaslr` they keep firing with no re-arm (measured: a `break set --hardware` breakpoint hit after a `sysrq b` reboot, `hits=2`; a watchpoint trapped on the boot's own `sethostname` after a `system_reset`), and on a KASLR guest they stay at the old addresses, which the re-slid kernel no longer runs as those functions. **TCG:** QEMU keeps them at their old addresses — with `nokaslr` they keep firing (measured, no re-arm). **KASLR re-slides on the reboot** (`0xffffffff93400000` → `0xffffffff8d400000`), so the symbols loaded in pry are wrong too and, under either accelerator, the breakpoints sit where nothing runs. A reset that lands while the debugger is **at a stop** leaves the vCPU halted at the reset vector (QEMU `prelaunch`, `EIP=0000fff0`), and `pry continue` does not start it (KVM and TCG alike: no console output after 20 s). | If the warning says the guest is still halted, `qmu cont --vm <vm>` first (it boots; GDB still believes it is stopped). Then, once the new kernel has booted (`qmu wait --vm <vm> --pattern 'login:'`): `pry --instance qmu-<vm> kbase` (no SSH) → `pry --instance qmu-<vm> resync`, or, once SSH answers, `eval "$(qmu kbase --vm <vm> --symbols "$VMLINUX")"` → `pry --instance qmu-<vm> resync --base "$KBASE"`. Both stop and resume a running target themselves (pry #61: `pry load`/`resync` on a running target no longer leaves breakpoints `<PENDING>`), and breakpoints set by symbol or file:line re-resolve to the new base — no re-set (measured: the canary fired at `0xffffffff98e667b0` after `kbase` + `resync`, at `0xffffffffa60667b0` after a `sysrq b` and `qmu kbase` + `resync --base`, under TCG at `0xffffffff956667b0`). A breakpoint set at a **raw address** (`*0x…`) does not (#238): it stays at the old address — `unreadable`, or armed in whatever code the moved kernel put there — and no `pry resync`, `--base` included, moves it. Delete it and set it again at the address − the old slide + the new one (pry #112 names it as `rebased_address` when it knows the slide the address was set at; measured: `*0xffffffff838b01c4` after a reset from slide `0x1e00000` to `0x3200000` → `break delete 2`, `break set '*0xffffffff84cb01c4'`, and the canary hit there). `pry break set --rebase` is no way around it: on a kernel target it finds no module base (`Module 'vmlinux' not found`, measured), and where it does it resolves to a raw `*0x…` when the breakpoint is set (pry's code). After a halted reset they leave it stopped, since GDB believed it stopped all along: finish with `pry --instance qmu-<vm> continue --background`. On a `nokaslr` guest addresses do not move, but under KVM the re-arm must also wait for the boot (#204): run right after the reset, `interrupt` → `continue --background` left `0x41` at the breakpoint and the canary dead, and `pry resync` reports it `unreadable` (`0 armed, 1 not armed`). Once `qmu wait --vm <vm> --pattern 'login:'` matched, `pry --instance qmu-<vm> resync` re-armed it (`1 armed`, `0xcc` back, the canary fired; after a halted reset, `qmu cont` first and `continue --background` after, as above). Under TCG there is nothing to re-arm unless the reset landed at a stop (then `interrupt` → `continue --background` after `qmu cont`). |
| A **hardware watchpoint** doesn't fire on a write you can prove happened | Wrong virtual address (alias), see above. | Watch the VA the write goes through; `--no-kvm` only to rule out a KVM guest-debug limitation. |

The recoveries above name `qmu-<vm>`, the bridge `qmu gdb` spawned; so do the
warnings, but only while that bridge is the attached client — its process
owns the client end of the stub connection. After a load, a reset or a save
of a running KVM guest that bridge is driven instead (below), so in practice
the `qmu-<vm>` wording is what a guest-initiated reboot prints. For a
hand-started client, or one that took the stub after qmu's bridge
disconnected, the warnings print `<id>`
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
VM — and says `possible` for any other client, with a warning of its own when
QEMU was `paused` before and after the save: if your debugger took that stop,
the image holds none of its breakpoints (#229). A running guest under the
bridge qmu spawned is stopped for the save first (below), so its saves read
`lifted`.

### What qmu does to the bridge it spawned (`debugger` in the envelope)

A bridge counts as qmu's when `qmu gdb` spawned it, its recorded pid and start
time still match, and its process owns the client end of the stub connection
(the same test the warnings use for `qmu-<vm>`). A client you started with
`pry launch`, or one that took the stub after qmu's bridge disconnected, is
never driven: it gets the warnings above. The routes are `snapshot load`,
`monitor loadvm`, `qmp human-monitor-command loadvm`, the three
`system_reset` routes, and the three save routes (`snapshot save`, `monitor
savevm`, `qmp human-monitor-command savevm`).

| Event | qmu's action |
|---|---|
| load succeeded | Every re-sync runs at a stop qmu holds: `pry interrupt --hold`, then `pry resync`, then `pry continue --release`, which resumes the target when the stop is qmu's (see *Who resumes* and *qmu's stop is a hold* below). On a nokaslr guest that is all (the restored image is mapped). On a KASLR guest (no `nokaslr` on the recorded cmdline) the image restores the kernel at the base of the boot it was saved in, which a reset or reboot since the save has moved (#200), so qmu rebases at that stop first: `pry interrupt --hold`, `pry kbase`, `pry resync`, then `pry continue --release` (measured: rebased `0x1a000000` → `0xc200000`, the canary fired at the restored kernel's address). The stop comes first because `pry kbase` and `pry resync` each stop a running target and resume it, and that resume re-inserts every breakpoint at the address the bridge has, successful or not (measured before this order: a failed `pry kbase` left `0xcc` at the old address and the canary fired). A target that was already at a debugger stop is re-synced (and rebased) there and not resumed (the release leaves it at its stop). If `pry kbase` cannot validate a base (e.g. `no kernel symbol file is loaded`), the target stays at that stop with none of its breakpoints in guest RAM (measured: `0x41` at the breakpoint, `exec` refused with `guest_state: "paused"`), `not_resynced` with `interrupted: true`, `resumed: false`, `held: true`: qmu's hold stays in place (a plain `pry continue` is refused until it is released, and a `pry wait` in flight keeps waiting), and the warning gives both ways on: `pry continue --release` if the image is from this boot, else rebase first (`pry load <vmlinux>` if needed, `pry kbase`, `pry resync`; or `qmu cont`, `qmu kbase`, `pry resync --base $KBASE --symbols <vmlinux>`), then `pry continue --release`. If the re-sync fails, the bridge is torn down — unless it only ran out of time or QEMU exited under it (*When a drive step fails*, below); if qmu cannot find `pry` on its own PATH, the bridge is left alone (`not_resynced`). |
| load failed mid-restore (`restore_state: "partial"`/`"unknown"`) | Nothing, to any client: `pry continue`, a re-sync of a target pry believes running, or a detach can each resume the half-restored machine. The warning says so; load a known-good snapshot first (that re-syncs), or `qmu kill`. |
| reset, QEMU `running` after it | qmu waits until the new boot's console shows the **end of kernel init** (`Freeing unused kernel image (initmem) memory` / `Write protecting the kernel read-only data` / `Run /sbin/init as init process`) or a getty's **`login:` prompt**, which comes later and which a `quiet` console (or a `loglevel=` of 6 or less) still prints where it hides the end-of-init lines (#205: a `quiet` nokaslr reset re-synced after `waited_seconds: 2.91`, 5.5 s for the whole command, and the canary fired; it used to block 30 s and arm nothing). Then it re-syncs at a stop it holds exactly as for a load: `pry interrupt --hold`, on a KASLR guest `pry kbase` (the re-slid base, read through the IDT with no SSH and validated against the vmlinux, pry #66), `pry resync`, `pry continue --release`. The banner alone is too early: the new kernel still patches its own text (alternatives, return thunks, static keys), and a breakpoint armed on a patched site trips the patcher (`missing return thunk` WARNING from `apply_returns`, which then reads as a guest crash). Measured on KVM: init done and armed ≈2 s after the reset (KASLR: rebased `0xc200000` → `0x1a000000`, the canary fired in the new boot, no crash reported); under TCG the same after a slower boot. If `pry kbase` cannot validate a base, the target stays at qmu's held stop with no breakpoint in guest RAM (`not_resynced`, `interrupted: true`, `resumed: false`, `held: true`; the warning's rebase steps end in `pry continue --release` — a breakpoint set at a raw address does not follow a rebase and is set again). If neither shows within 30 s (a `quiet` console with no getty on it, a slow or stuck boot; the reason names the cmdline's `quiet`/`loglevel=` when it has one) or `pry` is not on qmu's PATH, qmu arms nothing and leaves the bridge alone (`not_resynced`) with the manual recovery, which waits for the boot too (#204). A boot-time hit of the canary (e.g. `__x64_sys_newuname`, which systemd calls) stops the guest in the debugger like any hit. |
| reset of a guest the debugger had halted (QEMU not `running` after it) | **Torn down.** The vCPU sits at the reset vector (`prelaunch`), where no kernel address is readable: `pry resync` reports every breakpoint `unreadable` and `pry continue` fails (`Command aborted`, measured). A clean detach lets QEMU run the guest, so it boots (measured 7 of 8 times); once it stayed halted until `qmu cont`, and the warning says to `qmu cont` it first when `qmu status` shows it `paused`. |
| save of a guest QEMU reports `running`, under KVM (#201) | `pry interrupt --hold`, so GDB lifts its breakpoints from guest RAM; the save at that stop; then `pry continue --release`, which resumes the target when the stop is qmu's (*Who resumes*). A target that stopped by itself (a breakpoint hit between QEMU's `running` and the interrupt: QEMU `debug` after it) is the operator's stop: saved there, not resumed (the release leaves it there), and a `warnings[]` entry says the guest is halted with `pry --instance qmu-<vm> continue --background`. A save that outran its budget leaves the bridge stopped and qmu's hold in place (resuming would put the breakpoints back into RAM QEMU may still be saving) and its warning names the resume, `pry continue --release` once `qmu snapshot list` shows the tag; a failed save still gives the bridge back. If the stop fails, the save runs with the guest running and warns. Under TCG nothing is done (breakpoints never reach guest RAM). |

**Who resumes (#226).** qmu resumes only a stop it made: QEMU said `running`
right before its `pry interrupt --hold`, and is not at a gdbstub stop (`debug`: a
breakpoint, watchpoint or step) right after it. pry's answer (`will_resume`
under the hold, `interrupted` without one) is only
GDB's belief, and after `qmu gdb` → `qmu cont` (QMP `cont` resumes the vCPU
behind GDB's back) GDB believes the target is stopped: the bridge's first
packet halts the running guest (`paused`) and pry answers that it stopped
nothing, so its release resumes nothing. qmu used to take that at its word and leave a guest
that was running halted after a save, a load and a KASLR reset; it now
releases the hold and resumes it through the bridge (`pry continue
--background`, `stale_stop: true`), which also re-inserts
the breakpoints set since `qmu gdb` (measured after `qmu gdb` → `pry kbase`
→ `break set __x64_sys_syncfs` → `qmu cont`: `0x41` at the breakpoint and
`sync -f /` ran through; after the save `0xcc` and the canary fired; QEMU
`running` and `exec` answering after each of save, load and KASLR reset). A
breakpoint hit between the two reads is left as the operator's stop
(measured with a `__x64_sys_clock_nanosleep` breakpoint under a `sleep
0.45` loop: 8 of 10 saves found QEMU `debug` after the interrupt and left it
there with the warning).

**When a drive step fails (#233, #236).** `pry resync` reads and decodes
every code section of the loaded vmlinux for stray traps, so it takes longer
the bigger the image and the busier the host: 9.7–23 s on a 7.0 KASAN
vmlinux (52.8 MiB of text; 6.3 s by hand at load 14, and a whole KASLR reset
drive took 21.6 s at load 18.5 here). qmu gives it 120 s (`--timeout 120`,
pry's own op limit); the 20 s it used to give tore healthy bridges down. A
resync that still runs out of time says nothing about the bridge: it is
**kept** (`not_resynced`, `timed_out: true`), its symbols already at the
kernel's base (nokaslr, or the base `pry kbase` validated, which the
envelope carries as `kbase`), and a stop qmu made is resumed as after a
re-sync, so GDB re-inserts its breakpoints; the warning says the resync ran
out of time (not pry's error text) and names `pry --instance qmu-<vm> resync
--timeout 600`, which verifies them and repairs stray traps (measured with
the budget forced to 3 s on a KASLR reset: bridge kept, the canary fired at
the new base, and the named resync then reported `1 armed`; the code before
this tore the same bridge down). If QEMU itself exits while qmu drives the
bridge (a SIGKILL, a concurrent `qmu kill`), the drive says so instead of
handing out a reattach to a VM that is gone: `torn_down`, `qemu_exited:
true`, `reason: "QEMU exited during the re-sync after <event>; the VM is
stopped (…)"`, the bridge reaped, and a warning pointing at `qmu status`,
`qmu crash` and `qmu log` (measured: QEMU `kill -9`ed one second into a
driven KASLR `snapshot load`; the load still answers `ok: true`, its rewind
having landed). A step that fails while QEMU's QMP no longer answers waits up
to 3 s for its process to finish exiting first: a 2 GiB KASAN guest still
had its `/proc` entry when pry reported the stub gone.

**Raw-address breakpoints after a rebase (#238).** When the `pry kbase` qmu
ran moved the symbols (`kbase.apply.previous_slide` → `kbase.slide`) — also
when the `pry resync` after it ran out of time, whose own `pry resync
--timeout` recovery would leave such a breakpoint where it is — qmu
reads `pry break list` at its stop and names every breakpoint set at a raw
address (`*0x…`) in one `warnings[]` entry: it stayed at its old address,
no `pry resync` moves it, and the same instruction is now at old − previous
slide + slide (pry's `rebased_address` when pry knows the slide the address
was set at, else that sum, qualified), with `pry --instance qmu-<vm> break
delete N` and `break set '*<new>'` (flags kept: `--hardware`, `--temporary`,
`--condition`). It no longer appends "re-run `pry resync` once that code is
mapped", which can never work for one.

JSON (`--format json`): `debugger` carries `action` (`resynced` /
`torn_down` / `not_resynced` / `stopped_for_save`), `event`, `bridge_pid`,
`bridge_instance_id`, `held` whenever qmu stopped the bridge (`true`: the
stop was a `pry interrupt --hold`; `false`: this pry has no hold and qmu
used the public `pry interrupt`, see *qmu's stop is a hold* below), and

- `resynced`: `resync` — `pry resync --format json` exactly as pry returns it
  (`state`, `run_state`, `breakpoints[]` with per-location `status`/`detail`,
  `summary.{armed,not_armed,elf_mismatch,…}`); on a KASLR guest `kbase` —
  `pry kbase --format json` as pry returns it (`base`, `slide`, `method`,
  `validated`, `apply`), plus `interrupted: true` and `resumed` when qmu
  made the stop the re-sync ran at (`stale_stop: true` when the bridge
  believed the target stopped while QEMU ran it; `resume_error` and a
  warning if `pry continue` failed); a reset adds `waited_seconds`. pry's
  own `run_state` describes only what pry did at qmu's stop. Locations not armed
  produce one `warnings[]` entry naming them, and raw-address breakpoints a
  rebase left behind one of their own (above). Armed locations over code that
  differs from the symbol file (`elf_match: false`) are the kernel's own
  boot-time patching (the breakpoint is where you set it), since the symbols
  sit at the kernel's base — `nokaslr`, or the base `pry kbase` validated: a
  text note only. **Stray traps** (#230): pry's resync (pry #83) also writes
  the symbol file's bytes over every trap in mapped code that no breakpoint
  owns (`resync.stray_traps[]`, `summary.stray_traps`/`stray_repaired`);
  qmu names each one it touched — address and function, guest → ELF bytes,
  repaired or not — in the receipt and in one `warnings[]` entry, because
  that is kernel text rewritten: after a load most likely an `int3` a
  `possible` save baked into the image, after a reset (none is expected)
  possibly code the kernel patched that pry took for a trap (pry #88). A
  crash in one of those functions afterwards is a debugger artifact. Text
  mode prints the receipt (the `pry kbase` line, then
  `Re-synced the pry bridge qmu-<vm> …: N armed, M not armed; target S.`
  — `K stray trap(s), R repaired;` before `target` when pry found any —
  plus one line per location and per stray trap) on stderr, never on stdout; `target running
  (qmu resumed it)` after a re-sync at qmu's stop. `state: "stopped"` (a load
  into a debug stop) means resume with `pry --instance qmu-<vm> continue
  --background`; qmu does not resume it (a warning says so when QEMU ran the
  guest right before qmu's interrupt).
- `torn_down`: `reason`, `bridge_reaped`, and `breakpoints_dropped` (`pry break
  list --format json` as read just before the teardown, `null` if the bridge
  could not answer), plus a `warnings[]` entry with the reattach steps (`qmu
  gdb`, which leaves the guest halted, `pry kbase` on a KASLR guest, the
  breakpoints again, and `pry --instance qmu-<vm> continue --background`:
  GDB arms breakpoints only when it resumes). `qemu_exited: true` when QEMU
  exited under the drive: the warning then points at `qmu status`/`qmu
  crash`/`qmu log`, never at a reattach.
- `not_resynced`: `reason`; when qmu could not re-sync for a reason of its
  own (no `pry`, no end of the boot on the console) the bridge is untouched and `warnings[]`
  carries why plus the same recovery a client qmu does not drive gets. When
  `pry kbase` could not validate a base, the data also carries `held`,
  `interrupted` (qmu took the stop) and `resumed: false`: the target is at a
  debugger stop with no breakpoint in guest RAM, and the one warning names
  how to rebase and resume it — with `held: true` and a stop pry made, qmu's
  hold is still in place, and the resume is `pry --instance qmu-<vm>
  continue --release` (a plain `pry continue` is refused until then; a hold
  whose release would resume nothing is given back at once). A `pry resync` that ran out of time adds
  `timed_out: true`, `interrupted`, `resumed` (and `kbase`,
  `waited_seconds`, `stale_stop`, `resume_error` as for `resynced`); its one
  warning names the `pry resync --timeout` to run.
- `stopped_for_save`: `interrupted` (false when the target had stopped by
  itself at a breakpoint, QEMU `debug`; then a warning says it is left
  halted), `stale_stop: true` when the bridge believed the target stopped
  while QEMU ran it, `resumed`, and `resume_error` when giving the bridge
  back failed (then a warning says the guest is halted in the debugger). Every
  save route (`snapshot save`, `monitor savevm`, `qmp human-monitor-command
  savevm`) adds `breakpoints_lifted: true` next to `breakpoints_in_image:
  "lifted"` (#227).
- Where a stop was not qmu's (the operator's, which qmu leaves in place),
  qmu still releases its hold; if that release fails the data carries
  `release_error` and a warning names `pry --instance qmu-<vm> continue
  --release`, since a held bridge refuses every other resume.

**qmu's stop is a hold (#228).** The stop qmu takes for a save, a load or a
reset is `pry interrupt --hold` (pry #108), and it gives it back with `pry
continue --release`: a `pry wait` or foreground `pry continue` running on
`qmu-<vm>` at that moment keeps waiting through qmu's stop and returns the
next real stop (`breakpoint #1 hit`), and `pry status` says `reason: held`
while qmu holds it. The public `pry interrupt` qmu used before ended such a
wait with exit 0 and `reason: signal SIGINT` at whatever the vCPU was
running, a stop qmu resumed a moment later. The text receipt says the wait
was kept (`qmu held that stop …`).

**A pry without the hold** (from before pry #108, or a bridge an older pry
spawned: `pry interrupt --hold` is an unknown flag or op) gets the public
bracket instead — `pry interrupt`, then `pry continue --background` for a
stop qmu made — so the save is still clean and the bridge still re-synced;
the envelope says `held: false`, and the text receipt says the operation
ended any `pry wait` or foreground `pry continue` on `qmu-<vm>` with a
`reason: signal SIGINT` stop that was qmu's, not a hit: `pry wait` again,
or update pry (and re-run `qmu gdb` so the bridge is the new pry's). Any
other refusal of the hold (one already held) is a failed stop, never
retried as the public interrupt that would end the waiters.

The operation's own result and exit code are unchanged either way: a load,
reset or save that succeeded is `ok: true`, exit 0, whatever happened to the
bridge — also when QEMU exited under the drive (`qemu_exited: true`).

## Non-goals

qmu rebases only the bridge it spawned, and only after a load or reset it
issued (`pry kbase`, validated against the vmlinux); any other bridge's base
is the operator's to apply. Neither `gdb` nor `kbase` silently resumes or
re-halts the guest. A drive resumes only a stop it made (QEMU `running`
before its interrupt and at no breakpoint stop after it); the rebase
of a KASLR load or reset takes a stop too and resumes it only once the
symbols sit at a validated base — a rebase `pry kbase` could not validate
keeps that stop. qmu does not resume a
target its re-sync found stopped. `qmu gdb --help` and `cont --help` carry
no epilog, and `kbase --help` only names how a stop during its read is
reported; this file is the reference.
