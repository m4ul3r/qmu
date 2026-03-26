from __future__ import annotations

import subprocess
import time
from pathlib import Path


class SSHError(RuntimeError):
    pass


class SSHClient:
    """Wraps system ssh/scp for guest communication."""

    def __init__(
        self,
        port: int,
        key_path: str,
        host: str = "localhost",
        user: str = "root",
    ):
        self.port = port
        self.key_path = key_path
        self.host = host
        self.user = user

    def _ssh_base(self) -> list[str]:
        return [
            "ssh",
            "-i", self.key_path,
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3",
            "-o", "LogLevel=ERROR",
        ]

    def _scp_base(self) -> list[str]:
        return [
            "scp",
            "-i", self.key_path,
            "-P", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR",
        ]

    def _target(self) -> str:
        return f"{self.user}@{self.host}"

    def is_ready(self, timeout: int = 2) -> bool:
        """Check if SSH is responding."""
        cmd = self._ssh_base() + [
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=yes",
            self._target(),
            "true",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout + 3,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def wait_ready(self, timeout: int = 60, poll_interval: float = 1.0) -> bool:
        """Block until SSH is ready or timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_ready(timeout=2):
                return True
            time.sleep(poll_interval)
        return False

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        check: bool = False,
    ) -> tuple[int, str, str]:
        """Run a command in the guest. Returns (exit_code, stdout, stderr)."""
        cmd = self._ssh_base() + [self._target(), command]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if check and result.returncode != 0:
                raise SSHError(
                    f"Command failed (exit {result.returncode}): {command}\n"
                    f"stderr: {result.stderr.strip()}"
                )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            raise SSHError(
                f"SSH command timed out after {timeout}s: {command}"
            ) from exc

    def push(self, local_path: str, remote_path: str = "/root/") -> None:
        """Copy a file to the guest."""
        local = Path(local_path)
        if not local.exists():
            raise SSHError(f"Local file not found: {local_path}")
        cmd = self._scp_base() + [
            str(local),
            f"{self._target()}:{remote_path}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise SSHError(f"SCP push failed: {result.stderr.strip()}")

    def pull(self, remote_path: str, local_path: str = ".") -> None:
        """Copy a file from the guest."""
        cmd = self._scp_base() + [
            f"{self._target()}:{remote_path}",
            local_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise SSHError(f"SCP pull failed: {result.stderr.strip()}")
