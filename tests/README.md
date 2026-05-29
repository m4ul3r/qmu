# qmu tests

This directory holds **live-test assets** and the **agent-usability evaluation** for qmu.

## Assets (`assets/`)

Everything is built reproducibly by `assets/build.sh` — large artifacts are
git-ignored (see `assets/.gitignore`); the script is the source of truth.

```bash
./tests/assets/build.sh        # ~15-25 min first run (kernel build + rootfs)
```

It produces:

| Artifact | What it is |
|----------|------------|
| `assets/qmu_test.id_rsa{,.pub}` | ed25519 keypair the guest trusts |
| `assets/bzImage` | linux-6.6.75, built-in EXT4/ATA/AHCI/E1000 (no initramfs), KASAN, DWARF, `MAGIC_SYSRQ` |
| `assets/vmlinux` | matching uncompressed image with DWARF symbols (for `qmu gdb`) |
| `assets/rootfs.img` | raw ext4 Debian rootfs: sshd + test key + `gcc` (for `qmu compile`) |
| `assets/uaf.ko` | buggy LKM — deterministic KASAN slab-use-after-free on `insmod` |
| `qmu.toml` | generated config with absolute paths to the above |

## Running the live test

```bash
qmu launch --config tests/qmu.toml --kernel tests/assets/bzImage
qmu exec --vm <id> "uname -a"
qmu compile tests/exploit-samples/hello.c --run
# crash path:
qmu push tests/assets/uaf.ko && qmu exec "insmod /root/uaf.ko"   # -> KASAN panic
qmu crash
```

The full deterministic live sequence is captured to `live-transcript.md`, which
the evaluation workflow consumes (so analysis agents never race on the shared VM).

## Evaluation

The agent-usability evaluation runs as a multi-agent workflow that audits qmu
across five dimensions (doc/impl consistency, agent ergonomics, correctness,
live effectiveness, test design), adversarially verifies each finding, and
synthesizes a prioritized report plus draft fixes under `eval-report/`.
