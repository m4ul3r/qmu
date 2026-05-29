# qmu live-test transcript

Real boot of linux-6.6.75 (KASAN, MAGIC_SYSRQ, DWARF) + Debian bookworm rootfs
(sshd + gcc 12.2) under QEMU 11 / KVM, driven entirely through the `qmu` CLI.
Each block is a verbatim invocation + output + exit code. Config: tests/qmu.toml.
Boot-to-SSH-ready: ~6.5s. Guest root mounted rw via /etc/fstab.

## Lifecycle / introspection

### $ qmu list
```
Running VMs:
  live  pid=181518  ssh=10021(ok)  profile=exploit-dev  kernel=bzImage
[exit=0]
```

### $ qmu list --format json
```
[
  {
    "gdb_port": null,
    "kernel": "/home/m4ul3r/Documents/qmu/tests/assets/linux-6.6.75/arch/x86/boot/bzImage",
    "pid": 181518,
    "profile": "exploit-dev",
    "ssh_port": 10021,
    "ssh_ready": true,
    "vm_id": "live"
  }
]
[exit=0]
```

### $ qmu status --vm live
```
VM 'live'
  PID:       181518
  QMP:       connected
  QEMU:      running
  SSH:       port 10021 (ready)
  Kernel:    /home/m4ul3r/Documents/qmu/tests/assets/linux-6.6.75/arch/x86/boot/bzImage
  Rootfs:    /home/m4ul3r/Documents/qmu/tests/assets/rootfs.img
  Memory:    2G
  CPUs:      2
  Profile:   exploit-dev
  Cmdline:   console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic
  Serial:    /home/m4ul3r/.cache/qmu/instances/live.serial.log
  Started:   2026-05-29T03:10:50.240916+00:00
[exit=0]
```

### $ qmu status --vm live --format json
```
{
  "cmdline": "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 selinux=0 apparmor=0 kasan.fault=panic",
  "cpus": 2,
  "gdb_port": null,
  "kernel": "/home/m4ul3r/Documents/qmu/tests/assets/linux-6.6.75/arch/x86/boot/bzImage",
  "memory": "2G",
  "pid": 181518,
  "profile": "exploit-dev",
  "qemu_status": "running",
  "qmp": "connected",
  "rootfs": "/home/m4ul3r/Documents/qmu/tests/assets/rootfs.img",
  "serial_log": "/home/m4ul3r/.cache/qmu/instances/live.serial.log",
  "ssh": "ready",
  "ssh_port": 10021,
  "started_at": "2026-05-29T03:10:50.240916+00:00",
  "vm_id": "live"
}
[exit=0]
```

## Guest execution (text + json, exit-code propagation)

### $ qmu exec --vm live uname -a
```
Linux localhost 6.6.75 #1 SMP PREEMPT_DYNAMIC Fri May 29 02:48:27 UTC 2026 x86_64 GNU/Linux
[exit=0]
```

### $ qmu exec --vm live cat /proc/slabinfo | grep -m1 kmalloc-128
```
dma-kmalloc-128        0      0    256   16    1 : tunables    0    0    0 : slabdata      0      0      0
[exit=0]
```

### $ qmu exec --vm live echo to-stderr 1>&2; echo to-stdout; exit 3
```
to-stdout
[stderr] to-stderr
[exit code: 3]
[exit=1]
```

### $ qmu exec --vm live uname -r --format json
```
{
  "exit_code": 0,
  "stderr": "",
  "stdout": "6.6.75\n"
}
[exit=0]
```

## File transfer

### $ qmu push --vm live /tmp/qmu_push_test.txt /root/pushed.txt
```
Pushed /tmp/qmu_push_test.txt -> guest:/root/pushed.txt
[exit=0]
```

### $ qmu exec --vm live cat /root/pushed.txt
```
qmu-push-payload
[exit=0]
```

### $ qmu exec --vm live echo pulled-from-guest > /root/out.txt
```
[exit code: 0]
[exit=0]
```

### $ qmu pull --vm live /root/out.txt /tmp/qmu_pulled.txt
```
Pulled guest:/root/out.txt -> /tmp/qmu_pulled.txt
[exit=0]
```

### local: cat /tmp/qmu_pulled.txt
```
pulled-from-guest
```

## Compile and run (the headline workflow)

### $ qmu compile --vm live tests/exploit-samples/hello.c --run
```
Compiled and ran hello.c:
qmu-compile-ok uid=0
[exit code: 0]
[exit=0]
```

### $ qmu compile --vm live tests/exploit-samples/hello.c --run --format json
```
{
  "compile_cmd": "gcc -static -lpthread -o /root/hello /root/hello.c",
  "compile_exit": 0,
  "compile_stderr": "",
  "compile_stdout": "",
  "compiled": true,
  "run_exit": 0,
  "run_stderr": "",
  "run_stdout": "qmu-compile-ok uid=0\n",
  "source": "tests/exploit-samples/hello.c"
}
[exit=0]
```

## Kernel logs

### $ qmu dmesg --vm live --tail 6
```
[    2.160115] ip (108) used greatest stack depth: 26472 bytes left
[    2.161657] e1000: eth0 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: RX
[    2.167980] e2scrub_all (104) used greatest stack depth: 26104 bytes left
[    2.373315] random: crng init done
[   30.274811] sshd (197) used greatest stack depth: 25760 bytes left
[   32.017380] sshd (234) used greatest stack depth: 25752 bytes left
[exit=0]
```

### $ qmu log --vm live --tail 4
```
Debian GNU/Linux 12 localhost console

localhost login: [   30.274811] sshd (197) used greatest stack depth: 25760 bytes left
[   32.017380] sshd (234) used greatest stack depth: 25752 bytes left
[exit=0]
```

## Raw QEMU access

### $ qmu qmp --vm live query-status
```
{
  "running": true,
  "status": "running"
}
[exit=0]
```

### $ qmu monitor --vm live info status
```
VM status: running
[exit=0]
```

## Snapshots (save clean state before crash)

### $ qmu snapshot save --vm live clean
```
warning: Slirp: Save of field slirp_bootpclient/macaddr failed
warning: Slirp: Save of field slirp/bootp_clients failed
[exit=0]
```

### $ qmu snapshot list --vm live
```
Snapshots:
  --  clean  size=486 MiB  2026-05-28 23:11:52
[exit=0]
```

### $ qmu snapshot list --vm live --format json
```
[
  {
    "date": "2026-05-28",
    "id": "--",
    "tag": "clean",
    "time": "23:11:52",
    "vm_clock": "0000:01:01.992",
    "vm_size": "486 MiB"
  }
]
[exit=0]
```

## Crash extraction (real KASAN slab-use-after-free via insmod uaf.ko)

### $ qmu push --vm live tests/assets/uaf.ko /root/uaf.ko
```
Pushed tests/assets/uaf.ko -> guest:/root/uaf.ko
[exit=0]
```

### $ qmu exec --vm live "insmod /root/uaf.ko" --timeout 30  (triggers KASAN panic)
```
[exit code: 255]
qmu exec --vm live "insmod /root/uaf.ko" --timeout 30  0.21s user 0.05s system 1% cpu 19.830 total
[exit=1]
```

### $ qmu crash --vm live
```
[   86.646174] ---[ end Kernel panic - not syncing: kasan.fault=panic set ... ]---
[exit=0]
```

> FINDING (exec): the insmod that panicked the kernel returned a bare `[exit code: 255]`
> after ~20s with NO crash auto-extraction. SSH keepalive (ServerAliveCountMax) closed the
> connection with rc=255, which is not a TimeoutExpired, so cli.py `_handle_exec`'s crash
> path was bypassed.
>
> FINDING (crash): `qmu crash` returned only the `---[ end Kernel panic ... ]---` line. The
> full KASAN report is present in the serial log (BUG: KASAN: slab-use-after-free in uaf_init,
> Call Trace, RIP). serial.py CRASH_START_PATTERNS match "Kernel panic" as a substring, so the
> end-trace banner is mis-detected as the crash START and only that one line is captured.

## Snapshot recovery after panic (load clean -> SSH should return)

### $ qmu snapshot load --vm live clean
```
Missing section footer for slirp
Error: Section footer error, section_id: 1
[exit=0]
```

### $ qmu exec --vm live echo RECOVERED; uname -r; dmesg | tail -1
```
[stderr] Connection timed out during banner exchange
[exit code: 255]
[exit=1]
```

> FINDING (snapshot): `qmu snapshot load clean` printed `Missing section footer for slirp /
> Error: Section footer error` and did NOT restore the VM (SSH stayed dead), yet exited 0.
> Cause: savevm cannot serialize the `-net user` (slirp) state qmu configures. The documented
> save->crash->load iteration loop is broken with qmu's default networking, and the failure is
> reported as success (exit 0).

## Output spilling (>10k tokens auto-spills to /tmp/qmu-spills)

### $ qmu exec --vm live "cat /proc/kallsyms"  (huge output)
```
[qmu] Output spilled to /tmp/claude-1000/qmu-spills/20260529/exec-031429.txt
{
  "artifact_path": "/tmp/claude-1000/qmu-spills/20260529/exec-031429.txt",
  "bytes": 7694055,
  "format": "text",
  "ok": true,
  "sha256": "6713311ce1ca8dadc408609eca0deef6bfdd95532cd45ec17fd68f228725791c",
  "summary": {
    "chars": 7694054,
    "kind": "string"
  },
  "tokenizer": "o200k_base",
  "tokens": 2564873
}
[exit=0]
```

### $ ls /tmp/qmu-spills/*/  (spill artifact created?)
```
"/tmp/qmu-spills/": No such file or directory (os error 2)
```

## GDB integration (pry attaches to the stub)

### $ qmu gdb --vm live --symbols tests/assets/vmlinux
```
pry connected to VM 'live' GDB stub on port 1234
[exit=0]
```

## Crash extraction #2: plain sysrq panic (non-KASAN)

### $ qmu exec --vm live "echo c > /proc/sysrq-trigger" --timeout 20
```
[stderr] Connection timed out during banner exchange
[exit code: 255]
[exit=1]
```

### $ qmu crash --vm live
```
No crash detected in serial log.
[exit=0]
```

### raw serial: lines around the sysrq panic
```
```

## Error / edge cases (agent-facing)

### $ qmu --vm live list
```
usage: qmu [-h]
           {launch,kill,list,status,doctor,config,snapshot,push,pull,exec,compile,dmesg,crash,log,gdb,qmp,monitor,skill,version} ...
qmu: error: argument subcommand: invalid choice: 'live' (choose from 'launch', 'kill', 'list', 'status', 'doctor', 'config', 'snapshot', 'push', 'pull', 'exec', 'compile', 'dmesg', 'crash', 'log', 'gdb', 'qmp', 'monitor', 'skill', 'version')
[exit=2]
```

### $ qmu status --vm nosuchvm
```
[qmu] Error: VM 'nosuchvm' not found. Running: live
[exit=2]
```

### $ qmu exec uname -a
```
[qmu] Error: No running VMs. Start one with: qmu launch --kernel <bzImage>
[exit=2]
```

### $ qmu crash
```
[qmu] Error: No running VMs. Start one with: qmu launch --kernel <bzImage>
[exit=2]
```

> NOTE: the sysrq attempt above was CONFOUNDED — the preceding `qmu gdb` (pry) attached to the
> GDB stub and left the CPU halted, so `qmu exec` could not reach sshd (banner timeout) and the
> sysrq write never ran. Gotcha: `qmu gdb` can leave the VM paused. Clean redo below (no gdb).

## Crash extraction #2 (clean, no gdb): plain sysrq panic

### $ qmu exec --vm live "echo c > /proc/sysrq-trigger" --timeout 20
```
[exit code: 255]
[exit=1]
```

### $ qmu crash --vm live
```
[    6.673365] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---
[exit=0]
```

### raw serial: actual panic lines present in log
```
491:localhost login: [    6.664139] sysrq: Trigger a crash
492:[    6.664354] Kernel panic - not syncing: sysrq triggered crash
527:[    6.673365] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---
```
