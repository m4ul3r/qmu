from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from .instance import QMUError
from .paths import ssh_control_path


class SSHError(RuntimeError):
    """An ssh/scp invocation that did not complete normally.

    `stdout`/`stderr` carry whatever the child had produced when it was
    stopped (a `--timeout` overrun, an abort on a serial-log panic). A
    long-running exploit prints progress; throwing that away with the
    exception reported a timeout as if the command had printed nothing.
    """

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class SSHAborted(SSHError):
    """`SSHClient.run` stopped the child because `abort_when` fired."""


class SCPFileError(QMUError):
    """A transfer the *filesystem* refused — not the transport.

    A missing local file, a directory where a file was expected, a remote path
    that does not exist, a permission denial: scp reports these with a non-255
    exit code and the connection was fine. They are caller errors in the
    operational class (exit 1), never the transport/infra class (exit 4) an
    agent reads as "retry or relaunch" — looping on a typo. The scp wording is
    preserved so the reason stays visible.
    """

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _control_opts() -> list[str]:
    """Return current bounded ControlMaster options, or disable multiplexing."""
    try:
        path = ssh_control_path()
    except OSError:
        return []
    if path is None:
        return []
    return [
        "-o", "ControlMaster=auto",
        "-o", "ControlPersist=60",
        "-o", f"ControlPath={path}",
    ]


# Markers written by the *local* ssh/scp client (not the guest) when the
# transport is lost — e.g. the guest kernel panicked and the connection was
# dropped by the keepalive. ssh exits 255 in these cases.
SSH_TRANSPORT_ERROR_MARKERS = (
    "Connection timed out during banner exchange",
    "Connection reset by peer",
    "Connection closed by remote host",
    "Connection refused",
    "client_loop: send disconnect",
    "kex_exchange_identification",
    "Timeout, server",
    "banner exchange",
    "Broken pipe",
)


def is_transport_failure(rc: int, stderr: str) -> bool:
    """True if (rc, stderr) look like an ssh transport loss rather than a
    guest process exit. ssh exits 255 on transport failure; we additionally
    require a recognizable transport marker on stderr so a guest that genuinely
    returns exit(255) is not misclassified."""
    if rc != 255:
        return False
    return any(m in stderr for m in SSH_TRANSPORT_ERROR_MARKERS)


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
        ] + _control_opts()

    def _scp_base(self) -> list[str]:
        return [
            "scp",
            "-i", self.key_path,
            "-P", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR",
        ] + _control_opts()

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

    def close_control_master(self, timeout: float = 5.0) -> bool:
        """Tear down the multiplexed ControlMaster for this guest, if any.

        The master connection outlives the command that opened it
        (`ControlPersist=60`). After the guest's TCP state is rewound or reset
        underneath it (`snapshot load`, `system_reset`), the next command
        reuses the stale master and stalls for the keepalive window before
        reporting a `Broken pipe`. Closing it first makes the next command
        open a fresh connection. Returns True when a master was closed; False
        when multiplexing is off or no master was alive — never raises.
        """
        if not _control_opts():
            return False
        cmd = self._ssh_base() + ["-O", "exit", self._target()]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0

    def run(
        self,
        command: str,
        timeout: float = 30.0,
        check: bool = False,
        *,
        abort_when: Callable[[], bool] | None = None,
        poll_interval: float = 0.5,
    ) -> tuple[int, str, str]:
        """Run a command in the guest. Returns (exit_code, stdout, stderr).

        `abort_when` is polled every `poll_interval` seconds while the child
        runs; when it returns True the child is killed and :class:`SSHAborted`
        is raised with the output collected so far. The caller watches the
        serial log with it: a guest that panics mid-command drops the
        transport, but ssh only notices after the keepalive window
        (`ServerAliveInterval × ServerAliveCountMax` = 15 s) while the panic
        is on disk within ~100 ms. A `--timeout` overrun raises
        :class:`SSHError` carrying the partial output the same way.

        The pipes are drained by a select loop rather than `communicate()`:
        under ControlMaster the ssh child hands its stdout/stderr to the mux
        master, which keeps them open until the remote command ends, so a
        `communicate()` after `kill()` blocked for the rest of the remote
        command's lifetime (a `--timeout 2` on `sleep 10` returned after
        10 s). Output is collected as bytes and decoded lossily at the end:
        guest output is arbitrary bytes (a leak primitive dumping raw memory
        is the everyday case), and a strict decode threw the whole result
        away as an internal error.
        """
        cmd = self._ssh_base() + [self._target(), command]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
        chunks: dict[int, list[bytes]] = {out_fd: [], err_fd: []}
        sel = selectors.DefaultSelector()
        for pipe in (proc.stdout, proc.stderr):
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ)

        def drain(wait: float) -> None:
            for key, _ in sel.select(timeout=wait):
                try:
                    data = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if data:
                    chunks[key.fd].append(data)
                else:
                    sel.unregister(key.fileobj)

        deadline = time.monotonic() + timeout
        next_poll = time.monotonic() + poll_interval
        aborted = False
        try:
            while sel.get_map():
                now = time.monotonic()
                if now >= deadline:
                    break
                if abort_when is not None and now >= next_poll:
                    if abort_when():
                        aborted = True
                        break
                    next_poll = now + poll_interval
                wake = min(deadline, next_poll) if abort_when is not None else deadline
                drain(max(wake - now, 0.0))
            else:
                # Both pipes hit EOF: the child is exiting; give it the rest
                # of the budget to actually go.
                try:
                    proc.wait(timeout=max(deadline - time.monotonic(), 0.1))
                except subprocess.TimeoutExpired:
                    pass
            completed = proc.poll() is not None
            if not completed:
                proc.kill()
                proc.wait()
                # Whatever is already in the pipes is still the guest's output.
                drain(0.0)
        finally:
            sel.close()
            proc.stdout.close()
            proc.stderr.close()

        stdout = b"".join(chunks[out_fd]).decode("utf-8", errors="replace")
        stderr = b"".join(chunks[err_fd]).decode("utf-8", errors="replace")
        if aborted:
            raise SSHAborted(
                f"SSH command aborted (guest kernel panicked): {command}",
                stdout=stdout,
                stderr=stderr,
            )
        if not completed:
            raise SSHError(
                f"SSH command timed out after {timeout}s: {command}",
                stdout=stdout,
                stderr=stderr,
            )
        if check and proc.returncode != 0:
            raise SSHError(
                f"Command failed (exit {proc.returncode}): {command}\n"
                f"stderr: {stderr.strip()}"
            )
        return proc.returncode, stdout, stderr

    def push(self, local_path: str, remote_path: str = "/root/") -> None:
        """Copy a file to the guest."""
        local = Path(local_path)
        if not local.exists():
            raise SCPFileError(f"Local file not found: {local_path}")
        if local.is_dir():
            raise SCPFileError(
                f"push transfers single files only; {local_path!r} is a "
                "directory (archive it first, e.g. tar)"
            )
        cmd = self._scp_base() + [
            str(local),
            f"{self._target()}:{remote_path}",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=30
            )
        except subprocess.TimeoutExpired as exc:
            raise SSHError(
                f"SCP push timed out after 30s: {local_path} -> {remote_path}"
            ) from exc
        _raise_scp_failure("push", result)

    def pull(self, remote_path: str, local_path: str = ".") -> None:
        """Copy a file from the guest."""
        cmd = self._scp_base() + [
            f"{self._target()}:{remote_path}",
            local_path,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=30
            )
        except subprocess.TimeoutExpired as exc:
            raise SSHError(
                f"SCP pull timed out after 30s: {remote_path} -> {local_path}"
            ) from exc
        _raise_scp_failure("pull", result)


def _raise_scp_failure(operation: str, result: subprocess.CompletedProcess) -> None:
    """Map a failed scp to the error class its exit code proves.

    scp exits 255 only when ssh itself failed (transport dropped, banner
    timeout, control-master hiccup) — that stays SSHError, carrying the
    returncode/stderr evidence the callers use to tell a crash from a merely
    unreachable guest. Any other non-zero code came from scp's file handling
    on a working connection and is a caller/filesystem error.
    """
    if result.returncode == 0:
        return
    message = f"SCP {operation} failed: {result.stderr.strip()}"
    if result.returncode == 255:
        raise SSHError(
            message, returncode=result.returncode, stderr=result.stderr
        )
    raise SCPFileError(
        message, returncode=result.returncode, stderr=result.stderr
    )
