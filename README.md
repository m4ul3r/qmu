# qmu

Agent-friendly QEMU VM management CLI for kernel research.

## Install

```bash
uv tool install -e .
qmu skill install
```

## Quick Start

```bash
qmu launch --kernel /path/to/bzImage
qmu exec "uname -a"
qmu compile exploit.c --run
qmu crash
qmu kill
```

Run `qmu --help` for full usage.
