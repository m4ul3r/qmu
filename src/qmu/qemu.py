from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


_NETDEV_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True)
class QEMUNetdevCapabilities:
    binary: str
    path: str | None
    backends: frozenset[str]
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.path is not None

    def supports(self, backend: str) -> bool:
        return self.error is None and backend in self.backends


def probe_qemu_netdevs(
    binary: str,
    *,
    timeout: float = 5.0,
) -> QEMUNetdevCapabilities:
    path = shutil.which(binary)
    if path is None:
        return QEMUNetdevCapabilities(
            binary=binary,
            path=None,
            backends=frozenset(),
            error=f"Selected QEMU binary '{binary}' was not found in PATH",
        )

    argv = [path, "-netdev", "help"]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return QEMUNetdevCapabilities(
            binary=binary,
            path=path,
            backends=frozenset(),
            error=f"Capability probe '{binary} -netdev help' timed out after {timeout} seconds",
        )
    except OSError as exc:
        return QEMUNetdevCapabilities(
            binary=binary,
            path=path,
            backends=frozenset(),
            error=f"Capability probe could not run '{binary} -netdev help': {exc}",
        )

    output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if result.returncode != 0:
        detail = output.strip() or "no diagnostic output"
        return QEMUNetdevCapabilities(
            binary=binary,
            path=path,
            backends=frozenset(),
            error=(
                f"Capability probe '{binary} -netdev help' exited with status "
                f"{result.returncode}: {detail}"
            ),
        )

    backends = frozenset(
        line.strip()
        for line in output.splitlines()
        if _NETDEV_NAME.fullmatch(line.strip())
    )
    return QEMUNetdevCapabilities(
        binary=binary,
        path=path,
        backends=backends,
    )


def native_passt_problem(caps: QEMUNetdevCapabilities) -> str | None:
    if caps.error is not None:
        return (
            f"Cannot verify native passt support for selected QEMU "
            f"'{caps.binary}': {caps.error}. Use net_backend=user or --no-net "
            "until the selected QEMU can be probed."
        )
    if caps.supports("passt"):
        return None
    return (
        f"The selected QEMU '{caps.binary}' does not advertise the native "
        "'-netdev passt' backend. Native passt is documented since QEMU 10.1 "
        "but may be build-optional. Use net_backend=user/--net-backend user, "
        "--no-net, or select a QEMU build that advertises passt. An externally "
        "managed passt process with QEMU's stream backend is an operator-owned "
        "alternative; qmu does not manage that process."
    )
