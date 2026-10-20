from __future__ import annotations

import os
import re
import selectors
import subprocess
import sys
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
    """`SSHClient.run` stopped waiting because `abort_when` fired.

    Normally the child was killed. `detached_output` is set when the caller
    asked to detach instead (`detach_to`): the ssh child — and with it the
    remote command's session — was left running, and a detached helper
    drains the command's further output into that file.
    """

    def __init__(self, message: str, *, detached_output: Path | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.detached_output = detached_output


class SSHAuthError(SSHError):
    """sshd answered and refused the login qmu tried (#158).

    Positive evidence that the guest booted and its sshd serves: only the
    account (`[ssh] user`, recorded on the VM at launch) or the key does not
    match the image. Reporting it as a boot timeout or a lost transport sent
    the reader to `qmu log` (a healthy boot) or to a longer `--ssh-timeout`,
    neither of which can help. Exit 4 like every SSHError; the envelope names
    the user and key and says `ssh_status: "auth-failed"`.
    """

    def __init__(
        self,
        message: str,
        *,
        user: str,
        key_path: str | None,
        stderr: str = "",
        hint: str | None = None,
    ) -> None:
        super().__init__(message, returncode=255, stderr=stderr)
        self.user = user
        self.key_path = key_path
        self.hint = hint

    def envelope_fields(self) -> dict[str, object]:
        return {
            "ssh_status": PROBE_AUTH_FAILED,
            "ssh_error": True,
            "ssh_user": self.user,
            "ssh_key": self.key_path,
        }


class GuestText(str):
    """Guest output as text for JSON, carrying the exact bytes for text mode.

    The str value is the lossy UTF-8 decode (U+FFFD for undecodable bytes) so
    envelopes stay JSON strings and callers can `rstrip`/search it; `raw` is
    what the guest actually wrote, which text mode copies to stdout verbatim
    (`exec 'printf "\\xff"'` used to arrive as `ef bf bd 0a`). `lossy` records
    that the decode replaced something, so a JSON consumer knows the string
    is not the output.
    """

    raw: bytes
    lossy: bool

    def __new__(cls, raw: bytes) -> GuestText:
        try:
            decoded, lossy = raw.decode("utf-8"), False
        except UnicodeDecodeError:
            decoded, lossy = raw.decode("utf-8", errors="replace"), True
        self = super().__new__(cls, decoded)
        self.raw = raw
        self.lossy = lossy
        return self


def guest_bytes(text: str) -> bytes:
    """The exact bytes behind guest output; a plain str (a test double, a
    message qmu composed) is UTF-8."""
    return text.raw if isinstance(text, GuestText) else text.encode("utf-8")


def guest_lossy(text: str) -> bool:
    return isinstance(text, GuestText) and text.lossy


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
        hint: str | None = None,
    ) -> None:
        super().__init__(message, hint=hint)
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


# What `ssh` itself prints when sshd answered and every authentication method
# failed (`root@localhost: Permission denied (publickey,password).`) or the
# server gave up on the attempts. The parenthesised method list is the
# client's, so a guest-side "Permission denied" (a file it could not open)
# does not match.
SSH_AUTH_FAILURE_MARKERS = (
    "Permission denied (",
    "Too many authentication failures",
)

# Readiness-probe outcomes (`SSHClient.probe`). `auth-failed` is sshd
# answering and refusing the login: up, but not usable with this user/key.
PROBE_READY = "ready"
PROBE_AUTH_FAILED = "auth-failed"
PROBE_DOWN = "down"


def is_auth_failure(rc: int, stderr: str) -> bool:
    """True if (rc, stderr) are ssh's own report of a refused login."""
    return rc == 255 and any(m in stderr for m in SSH_AUTH_FAILURE_MARKERS)


def probe_refused_auth(ssh: object) -> bool:
    """Whether `ssh`'s last readiness probe was refused at authentication.

    Read through getattr because callers hold whatever `_make_ssh` returned,
    which the test suite replaces with doubles that only answer `is_ready`.
    """
    return getattr(ssh, "last_probe", None) == PROBE_AUTH_FAILED


# Bytes a detached command's drainer keeps; past this it reads and discards,
# so a chatty command neither fills the disk nor blocks on a full pipe.
DETACHED_OUTPUT_CAP = 16 * 1024 * 1024

# The drainer: argv is (output path, cap, fd...). It owns the read ends of the
# ssh child's stdout/stderr pipes after qmu has gone, so the session stays
# open — the remote command never sees its stdout close — until the command
# ends (EOF on every pipe). Raw bytes, both streams interleaved in arrival
# order, as a terminal would show them.
_DRAIN_SOURCE = r"""
import os, select, sys
path, cap, fds = sys.argv[1], int(sys.argv[2]), [int(a) for a in sys.argv[3:]]
for fd in fds:
    os.set_blocking(fd, True)
written = 0
with open(path, "ab") as out:
    while fds:
        for fd in select.select(fds, [], [])[0]:
            data = os.read(fd, 65536)
            if not data:
                fds.remove(fd)
                os.close(fd)
                continue
            keep = data[: max(cap - written, 0)]
            if keep:
                out.write(keep)
                out.flush()
                written += len(keep)
"""


def _spawn_drainer(fds: list[int], path: Path) -> None:
    subprocess.Popen(
        [sys.executable, "-c", _DRAIN_SOURCE, str(path), str(DETACHED_OUTPUT_CAP),
         *(str(fd) for fd in fds)],
        pass_fds=tuple(fds),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _watch_child(
    proc: subprocess.Popen,
    pipes: list,
    *,
    timeout: float,
    abort_when: Callable[[], bool] | None,
    poll_interval: float = 0.5,
    on_chunk: Callable[[str, bytes], None] | None = None,
    detach_to: Callable[[], Path | None] | None = None,
) -> tuple[list[bytes], bool, bool, Path | None]:
    """Drain `pipes` until the child exits, the budget expires or `abort_when`
    fires. Returns (raw output per pipe, completed, aborted, detached); a
    child that did not complete has been killed — unless the abort detached
    it. `completed` means the child exited
    *within* the budget: the deadline is checked first, so a child that
    finished while the loop was blocked in `abort_when` after the deadline
    had already passed still counts as timed out (its output is kept).

    `abort_when` is polled every `poll_interval` seconds while the child runs;
    it must return promptly (the loop is single-threaded, so a predicate that
    blocks also stalls the drain and the deadline). The pipes are drained by a
    select loop rather than `communicate()`: under ControlMaster the ssh child
    hands its stdout/stderr to the mux master, which keeps them open until
    the remote command ends, so a `communicate()` after `kill()` blocked for
    the rest of the remote command's lifetime (a `--timeout 2` on `sleep 10`
    returned after 10 s). Output is returned as bytes: guest output is
    arbitrary bytes (a leak primitive dumping raw memory is the everyday
    case) and the caller decides how to present them.

    `on_chunk(stream, data)` is called with every read as it is drained —
    `stream` is `"stdout"`/`"stderr"` by which of `proc`'s pipes produced it,
    `data` the raw bytes, no line assembly — so a caller can relay a
    long-running command's progress live instead of only when it ends. The
    same bytes are still accumulated and returned. The final drain after a
    kill reaches it too, so partial output on a timeout/abort is relayed
    before the exception carries it. A callback that raises (a reader that
    closed the pipe) kills the child first: the drain loop is the only thing
    reaping it.

    `detach_to` is asked once when `abort_when` fires: a path means "do not
    kill". The child is left running and a detached drainer
    (:func:`_spawn_drainer`) takes over the pipes and appends whatever else
    arrives to that file, so the remote command keeps its session instead of
    dying of SIGPIPE on its next write. `detached` is that path, or None.
    """
    names = {pipe.fileno(): "stdout" if pipe is proc.stdout else "stderr" for pipe in pipes}
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
                if on_chunk is not None:
                    on_chunk(names[key.fd], data)
            else:
                sel.unregister(key.fileobj)

    deadline = time.monotonic() + timeout
    next_poll = time.monotonic() + poll_interval
    aborted = False
    timed_out = False
    detached: Path | None = None
    try:
        while sel.get_map():
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                break
            if abort_when is not None and now >= next_poll:
                if abort_when():
                    aborted = True
                    if detach_to is not None:
                        detached = detach_to()
                    break
                # The predicate may have blocked (a bounded QMP probe against
                # a held socket): re-sample before trusting the budget. The
                # child may have exited during that wait, but after the
                # deadline, and the timeout must win over `proc.poll()`.
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
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
        completed = not timed_out and proc.poll() is not None
        if not completed and detached is not None:
            # Whatever already arrived is the caller's; the rest is the
            # drainer's, which inherits the read ends still open.
            drain(0.0)
            _spawn_drainer([key.fd for key in sel.get_map().values()], detached)
        elif not completed:
            proc.kill()
            proc.wait()
            # Whatever is already in the pipes is still the guest's output.
            drain(0.0)
        elif detached is not None:
            # The command finished on its own before the abort could act:
            # nothing left to detach.
            detached.unlink(missing_ok=True)
            detached = None
    except BaseException:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        raise
    finally:
        sel.close()
        for pipe in pipes:
            pipe.close()

    # `chunks` preserves the order of `pipes`.
    output = [b"".join(parts) for parts in chunks.values()]
    return output, completed, aborted, detached


# Margin added to a readiness probe's `ConnectTimeout` before the ssh child is
# killed. OpenSSH applies ConnectTimeout to the banner exchange as well as to
# the TCP connect (`Connection timed out during banner exchange`, one of
# SSH_TRANSPORT_ERROR_MARKERS), so the client itself gives up at `timeout`;
# this only covers process start and teardown. It used to be 3 s, which made a
# port that accepts TCP but never speaks (a half-booted guest, a foreign
# listener) cost `list`/`status` 5 s per VM (#77); 0.5 s put the whole
# `status` command at 2.62 s wall (probe 2.5 s + CLI/daemon overhead) against
# a 2.6 s end-to-end budget, so the probe itself is capped at 2.25 s.
PROBE_GRACE_SECONDS = 0.25

# How much longer a probe waits once sshd has accepted the userauth service
# (`SSH2_MSG_SERVICE_ACCEPT`): the server is up, and only its verdict on the
# login is outstanding. A refusal is not always fast — an image with
# `PermitEmptyPasswords yes` + PAM runs the `none` method through pam_unix's
# fail delay first, and a non-existent `[ssh] user` came back after 4.2 s
# (measured, bookworm rootfs), past the connect budget. Killing the probe
# there reported "down" for a guest whose sshd was answering (#158). A port
# that never completes the handshake never reaches this phase, so the #77
# bound for it is unchanged.
PROBE_AUTH_GRACE_SECONDS = 5.0
_AUTH_PHASE_MARKER = b"SSH2_MSG_SERVICE_ACCEPT received"
_PROBE_CHATTER = (
    "debug", "Warning: Permanently added", "Authenticated to", "Transferred:",
    "Bytes per second",
)


class SSHClient:
    """Wraps system ssh/scp for guest communication."""

    # Budget for one push/pull transfer.
    scp_timeout: float = 30.0

    # What the last readiness probe saw (`PROBE_*`), None before any; and
    # ssh's stderr from it, which names the refused methods on auth-failed.
    last_probe: str | None = None
    last_probe_stderr: str = ""

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
        # Set once a transfer found no SFTP server in the guest and the
        # legacy protocol worked, so a second transfer in the same command
        # goes straight to `scp -O` (#148).
        self.scp_legacy = False

    def _ssh_base(self, *, multiplex: bool = True, log_level: str = "ERROR") -> list[str]:
        # ssh keeps the FIRST value of a repeated -o, so a caller that needs
        # another LogLevel (the probe reads the handshake phase) sets it here.
        base = [
            "ssh",
            "-i", self.key_path,
            "-p", str(self.port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3",
            "-o", f"LogLevel={log_level}",
        ]
        if multiplex:
            return base + _control_opts()
        return base + ["-o", "ControlMaster=no"]

    def _scp_base(self) -> list[str]:
        return [
            "scp",
            *(["-O"] if self.scp_legacy else []),
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
        """Check if SSH is responding within `timeout` seconds; see :meth:`probe`."""
        return self.probe(timeout) == PROBE_READY

    def probe(self, timeout: int = 2) -> str:
        """One readiness probe: `ready`, `auth-failed` or `down` (`PROBE_*`).

        `auth-failed` is sshd answering and refusing this user/key — the
        guest is up, and no amount of waiting changes the answer (#158). The
        outcome and ssh's own error lines are kept on `last_probe`/
        `last_probe_stderr` for callers that only asked `is_ready`.

        The probe is deliberately NOT multiplexed (`ControlMaster=no`, no
        `ControlPath`): `list`/`status`/launch run it against every serving VM
        on the host, and under `ControlMaster=auto` each probe spawned a
        persistent `ssh [mux]` master (ControlPersist 60) for VMs the caller
        never commands — including other users' — under the caller's
        QMU_TEMP_DIR. `run`/`push`/`pull` keep the shared master.

        `timeout` is the budget up to authentication: ssh's own
        ConnectTimeout bounds both the TCP connect and the banner exchange,
        and the subprocess cap is only PROBE_GRACE_SECONDS beyond it. A probe
        still running at the cap whose (debug) stderr shows the server
        accepted the userauth service gets PROBE_AUTH_GRACE_SECONDS more for
        the verdict.
        """
        cmd = self._ssh_base(multiplex=False, log_level="DEBUG1") + [
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=yes",
            self._target(),
            "true",
        ]
        proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            try:
                _, raw = proc.communicate(timeout=timeout + PROBE_GRACE_SECONDS)
            except subprocess.TimeoutExpired as exc:
                if _AUTH_PHASE_MARKER not in (exc.stderr or b""):
                    raise
                _, raw = proc.communicate(timeout=PROBE_AUTH_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.last_probe, self.last_probe_stderr = PROBE_DOWN, ""
            return PROBE_DOWN
        # Keep what LogLevel=ERROR would have shown: the debug trace and the
        # INFO/VERBOSE chatter it brings along are only for the phase check.
        stderr = "\n".join(
            line for line in (raw or b"").decode("utf-8", errors="replace").splitlines()
            if line.strip() and not line.startswith(_PROBE_CHATTER)
        )
        if proc.returncode == 0:
            outcome = PROBE_READY
        elif is_auth_failure(proc.returncode, stderr):
            outcome = PROBE_AUTH_FAILED
        else:
            outcome = PROBE_DOWN
        self.last_probe, self.last_probe_stderr = outcome, stderr
        return outcome

    def auth_error(self, stderr: str | None = None) -> SSHAuthError:
        """The SSHAuthError for a refused login, naming the user and key."""
        detail = (self.last_probe_stderr if stderr is None else stderr).strip()
        reason = "; ".join(line.strip() for line in detail.splitlines() if line.strip())
        return SSHAuthError(
            f"sshd on port {self.port} answered but refused user "
            f"'{self.user}' with key {self.key_path}"
            + (f": {reason}" if reason else ""),
            user=self.user,
            key_path=self.key_path,
            stderr=detail,
        )

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
        on_chunk: Callable[[str, bytes], None] | None = None,
        detach_to: Callable[[], Path | None] | None = None,
    ) -> tuple[int, GuestText, GuestText]:
        """Run a command in the guest. Returns (exit_code, stdout, stderr).

        stdout/stderr are :class:`GuestText`: str for the envelope, with the
        exact bytes on `.raw` for text mode.

        `abort_when` is polled every `poll_interval` seconds while the child
        runs; when it returns True the child is killed and :class:`SSHAborted`
        is raised with the output collected so far. The caller watches the
        serial log and QMP with it: a guest that panics mid-command drops the
        transport, but ssh only notices after the keepalive window
        (`ServerAliveInterval × ServerAliveCountMax` = 15 s) while the panic
        is on disk within ~100 ms; a halted vCPU never drops it at all. When
        `detach_to` returns a path at that moment the child is left running
        instead (see :func:`_watch_child`) and the exception carries the path
        as `detached_output`. A
        `--timeout` overrun raises :class:`SSHError` carrying the partial
        output the same way. `on_chunk` relays each drained read as it
        arrives (see :func:`_watch_child`); the returned/raised output is the
        same bytes in full.
        """
        cmd = self._ssh_base() + [self._target(), command]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout_raw, stderr_raw), completed, aborted, detached = _watch_child(
            proc,
            [proc.stdout, proc.stderr],
            timeout=timeout,
            abort_when=abort_when,
            poll_interval=poll_interval,
            on_chunk=on_chunk,
            detach_to=detach_to,
        )
        stdout, stderr = GuestText(stdout_raw), GuestText(stderr_raw)
        if aborted:
            raise SSHAborted(
                f"SSH command aborted by qmu (guest panicked or halted): {command}",
                stdout=stdout,
                stderr=stderr,
                detached_output=detached,
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
            raise SCPFileError(
                f"Local file not found: {local_path}",
                hint=f"Check the local path: ls -l {local_path}",
            )
        if local.is_dir():
            raise SCPFileError(
                f"push transfers single files only; {local_path!r} is a "
                "directory (archive it first, e.g. tar)",
                hint=f"tar czf <archive>.tgz -C {local_path} . ; then push the archive",
            )
        self._transfer(
            [str(local), f"{self._target()}:{remote_path}"],
            operation="push",
            direction=f"{local_path} -> {remote_path}",
            abort_when=abort_when,
        )

    def pull(
        self,
        remote_path: str,
        local_path: str = ".",
        *,
        abort_when: Callable[[], bool] | None = None,
    ) -> None:
        """Copy a file from the guest. `abort_when` as in :meth:`run`."""
        self._transfer(
            [f"{self._target()}:{remote_path}", local_path],
            operation="pull",
            direction=f"{remote_path} -> {local_path}",
            abort_when=abort_when,
        )

    def _transfer(
        self,
        paths: list[str],
        *,
        operation: str,
        direction: str,
        abort_when: Callable[[], bool] | None,
    ) -> None:
        """One scp transfer, retried once in the legacy protocol when the
        guest has no SFTP server (#148).

        OpenSSH ≥ 9.0 `scp` speaks SFTP by default; a Dropbear/BusyBox guest
        ships only the legacy `scp` binary, so the remote side dies at once
        (`sh: /usr/libexec/sftp-server: No such file or directory`) on a
        perfectly healthy transport. `-O` is what the guest does speak.
        """
        result = self._scp(
            self._scp_base() + paths,
            operation=operation, direction=direction, abort_when=abort_when,
        )
        sftp_refusal: str | None = None
        if (
            result.returncode != 0
            and not self.scp_legacy
            and sftp_unavailable(result.returncode, result.stderr)
        ):
            sftp_refusal = result.stderr
            self.scp_legacy = True
            result = self._scp(
                self._scp_base() + paths,
                operation=operation, direction=direction, abort_when=abort_when,
            )
        self._raise_scp_failure(operation, result, sftp_refusal=sftp_refusal)

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
        (stderr_raw,), completed, aborted, _ = _watch_child(
            proc, [proc.stderr], timeout=timeout, abort_when=abort_when
        )
        stderr = GuestText(stderr_raw)
        if aborted:
            raise SSHAborted(f"SCP {operation} aborted by qmu: {direction}", stderr=stderr)
        if not completed:
            raise SSHError(f"SCP {operation} timed out after {timeout:g}s: {direction}")
        return subprocess.CompletedProcess(cmd, proc.returncode, "", stderr)

    def _raise_scp_failure(
        self,
        operation: str,
        result: subprocess.CompletedProcess,
        *,
        sftp_refusal: str | None = None,
    ) -> None:
        """Map a failed scp to the error class its exit code proves.

        scp exits 255 only when ssh itself failed (transport dropped, banner
        timeout, control-master hiccup) — that stays SSHError, carrying the
        returncode/stderr evidence the callers use to tell a crash from a
        merely unreachable guest — unless ssh says the login was refused,
        which is :class:`SSHAuthError`. Any other non-zero code came from
        scp's file handling on a working connection and is a caller/
        filesystem error. `sftp_refusal` is the first attempt's stderr when
        the legacy-protocol retry is what failed here.
        """
        if result.returncode == 0:
            return
        if is_auth_failure(result.returncode, result.stderr):
            raise self.auth_error(result.stderr)
        message = f"SCP {operation} failed: {result.stderr.strip()}"
        hint = None
        if sftp_refusal is not None:
            message = (
                f"SCP {operation} failed: the guest refused the SFTP session "
                f"({_first_line(sftp_refusal)}) and the legacy-protocol retry "
                f"(scp -O) failed: {result.stderr.strip()}"
            )
            if _SCP_MISSING.search(result.stderr):
                hint = (
                    "The guest has neither an SFTP server nor an scp binary: "
                    "inject one into the rootfs (qmu launch --inject / qmu rootfs "
                    "inject; the firmware-over-qmu skill covers static tools)"
                )
        if result.returncode == 255:
            raise SSHError(
                message, returncode=result.returncode, stderr=result.stderr
            )
        raise SCPFileError(
            message, returncode=result.returncode, stderr=result.stderr, hint=hint
        )


# The remote side of an SFTP-mode scp could not start an SFTP server: no
# `sftp-server` binary (Dropbear/BusyBox: `sh: /usr/libexec/sftp-server: No
# such file or directory`) or no `Subsystem sftp` in sshd_config.
_SFTP_UNAVAILABLE_MARKERS = ("sftp-server", "subsystem request failed")

# The guest shell could not find `scp` for a legacy-protocol transfer.
_SCP_MISSING = re.compile(r"\bscp: (?:not found|command not found|No such file)")


def sftp_unavailable(rc: int, stderr: str) -> bool:
    """True when an scp failure is the guest lacking an SFTP server.

    Dropbear forwards the shell's complaint about the missing binary. OpenSSH
    sshd does not: with its `sftp-server` gone, the client's whole report is
    `scp: Connection closed` (measured, bookworm sshd 9.2 under host scp
    9.6). That exact line alone — no transport marker (a dropped or refused
    connection names itself), no login refusal — is the server closing the
    session before SFTP began.
    """
    if any(m in stderr for m in _SFTP_UNAVAILABLE_MARKERS):
        return True
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return rc == 255 and lines == ["scp: Connection closed"]


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")
