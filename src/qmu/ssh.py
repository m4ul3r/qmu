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


def _watch_child(
    proc: subprocess.Popen,
    pipes: list,
    *,
    timeout: float,
    abort_when: Callable[[], bool] | None,
    poll_interval: float = 0.5,
) -> tuple[list[str], bool, bool]:
    """Drain `pipes` until the child exits, the budget expires or `abort_when`
    fires. Returns (decoded output per pipe, completed, aborted); a child that
    did not complete has been killed.

    `abort_when` is polled every `poll_interval` seconds while the child runs.
    The pipes are drained by a select loop rather than `communicate()`: under
    ControlMaster the ssh child hands its stdout/stderr to the mux master,
    which keeps them open until the remote command ends, so a `communicate()`
    after `kill()` blocked for the rest of the remote command's lifetime (a
    `--timeout 2` on `sleep 10` returned after 10 s). Output is collected as
    bytes and decoded lossily at the end: guest output is arbitrary bytes (a
    leak primitive dumping raw memory is the everyday case), and a strict
    decode threw the whole result away as an internal error.
    """
    chunks: dict[int, list[bytes]] = {pipe.fileno(): [] for pipe in pipes}
    sel = selectors.DefaultSelector()
    for pipe in pipes:
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
            # Every pipe hit EOF: the child is exiting; give it the rest of
            # the budget to actually go.
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
        for pipe in pipes:
            pipe.close()

    # `chunks` preserves the order of `pipes`.
    output = [
        b"".join(parts).decode("utf-8", errors="replace") for parts in chunks.values()
    ]
    return output, completed, aborted


class SSHClient:
    """Wraps system ssh/scp for guest communication."""

    # Budget for one push/pull transfer.
    scp_timeout: float = 30.0

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

    def _ssh_base(self, *, multiplex: bool = True) -> list[str]:
        base = [
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
        if multiplex:
            return base + _control_opts()
        return base + ["-o", "ControlMaster=no"]

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
        """Check if SSH is responding.

        The probe is deliberately NOT multiplexed (`ControlMaster=no`, no
        `ControlPath`): `list`/`status`/launch run it against every serving VM
        on the host, and under `ControlMaster=auto` each probe spawned a
        persistent `ssh [mux]` master (ControlPersist 60) for VMs the caller
        never commands — including other users' — under the caller's
        QMU_TEMP_DIR. `run`/`push`/`pull` keep the shared master.
        """
        cmd = self._ssh_base(multiplex=False) + [
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
        serial log and QMP with it: a guest that panics mid-command drops the
        transport, but ssh only notices after the keepalive window
        (`ServerAliveInterval × ServerAliveCountMax` = 15 s) while the panic
        is on disk within ~100 ms; a halted vCPU never drops it at all. A
        `--timeout` overrun raises :class:`SSHError` carrying the partial
        output the same way. See :func:`_watch_child` for the drain.
        """
        cmd = self._ssh_base() + [self._target(), command]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr), completed, aborted = _watch_child(
            proc,
            [proc.stdout, proc.stderr],
            timeout=timeout,
            abort_when=abort_when,
            poll_interval=poll_interval,
        )
        if aborted:
            raise SSHAborted(
                f"SSH command aborted by qmu (guest panicked or halted): {command}",
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

    def push(
        self,
        local_path: str,
        remote_path: str = "/root/",
        *,
        abort_when: Callable[[], bool] | None = None,
    ) -> None:
        """Copy a file to the guest. `abort_when` as in :meth:`run`."""
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
        result = self._scp(
            cmd,
            operation="push",
            direction=f"{local_path} -> {remote_path}",
            abort_when=abort_when,
        )
        _raise_scp_failure("push", result)

    def pull(
        self,
        remote_path: str,
        local_path: str = ".",
        *,
        abort_when: Callable[[], bool] | None = None,
    ) -> None:
        """Copy a file from the guest. `abort_when` as in :meth:`run`."""
        cmd = self._scp_base() + [
            f"{self._target()}:{remote_path}",
            local_path,
        ]
        result = self._scp(
            cmd,
            operation="pull",
            direction=f"{remote_path} -> {local_path}",
            abort_when=abort_when,
        )
        _raise_scp_failure("pull", result)

    def _scp(
        self,
        cmd: list[str],
        *,
        operation: str,
        direction: str,
        abort_when: Callable[[], bool] | None,
    ) -> subprocess.CompletedProcess:
        """Run scp under `scp_timeout`, polling `abort_when` like :meth:`run`.

        A transfer is an ssh session too: sshd's login path makes the same
        syscalls a shell does, so a breakpoint armed for `exec` fires under
        scp as well, and an unwatched transfer sat out the whole budget before
        a bare timeout said nothing about the debugger. scp's stdout carries
        nothing and is not read.
        """
        timeout = self.scp_timeout
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        (stderr,), completed, aborted = _watch_child(
            proc, [proc.stderr], timeout=timeout, abort_when=abort_when
        )
        if aborted:
            raise SSHAborted(f"SCP {operation} aborted by qmu: {direction}", stderr=stderr)
        if not completed:
            raise SSHError(f"SCP {operation} timed out after {timeout:g}s: {direction}")
        return subprocess.CompletedProcess(cmd, proc.returncode, "", stderr)


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
