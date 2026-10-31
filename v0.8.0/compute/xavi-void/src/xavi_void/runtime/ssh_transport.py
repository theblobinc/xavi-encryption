"""Fail-closed SSH carrier for remote Xavi Void evaluator workers.

SSH is transport, not execution authority.  The remote protocol, evaluator key
custody, transcript/replay checks, PQ authentication, and witnessed receipts
remain separate layers.  This module only provides a deterministic, host-key-
verified carrier for the line-oriented worker protocol.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import select
import shlex
import subprocess
from typing import Any, Callable, IO, Mapping, Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id


_HOST_RE = re.compile(r"^[A-Za-z0-9_.:@-]+$")


class SSHTransportError(RuntimeError):
    """The SSH carrier or remote worker failed closed."""


def _validate_token(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is required")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{label} contains a forbidden control character")
    return value


@dataclass(frozen=True, slots=True)
class SSHTransportPolicy:
    """Deterministic SSH policy for one remote evaluator process.

    Host-key checking is always strict.  ``known_hosts_file=None`` means use the
    OpenSSH default known-hosts database; an explicit path pins the carrier to a
    dedicated test-lab or deployment known-hosts file.
    """

    host: str
    remote_command: tuple[str, ...]
    port: int = 22
    known_hosts_file: Path | None = None
    identity_file: Path | None = None
    connect_timeout_seconds: int = 8
    server_alive_interval_seconds: int = 15
    server_alive_count_max: int = 3
    ssh_binary: str = "ssh"

    def __post_init__(self) -> None:
        host = _validate_token(self.host, "SSH host")
        if host.startswith("-") or _HOST_RE.fullmatch(host) is None:
            raise ValueError("SSH host is not a safe host/alias token")
        if not self.remote_command:
            raise ValueError("remote_command is required")
        for index, token in enumerate(self.remote_command, start=1):
            _validate_token(token, f"remote command token {index}")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("SSH port is outside 1..65535")
        if int(self.connect_timeout_seconds) < 1:
            raise ValueError("SSH connect timeout must be positive")
        if int(self.server_alive_interval_seconds) < 1:
            raise ValueError("SSH server-alive interval must be positive")
        if int(self.server_alive_count_max) < 1:
            raise ValueError("SSH server-alive count must be positive")
        _validate_token(self.ssh_binary, "SSH binary")
        for label, path in (("known_hosts_file", self.known_hosts_file), ("identity_file", self.identity_file)):
            if path is not None:
                text = str(path)
                _validate_token(text, label)
                if not Path(text).is_absolute():
                    raise ValueError(f"{label} must be an absolute path")

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema": "xavi-void-ssh-transport-v1",
            "host": self.host,
            "port": int(self.port),
            "remote_command": list(self.remote_command),
            "host_key_policy": "strict-explicit-known-hosts" if self.known_hosts_file else "strict-openssh-known-hosts",
            "identity_policy": "explicit-identities-only" if self.identity_file else "openssh-config",
            "batch_mode": True,
            "pty": False,
            "forwarding": False,
            "authority": "carrier-only",
        }

    def commitment(self) -> str:
        return content_id(
            "XAVI-VOID/SSH-TRANSPORT/v1",
            canonical_bytes(self.descriptor()),
        )

    def argv(self) -> tuple[str, ...]:
        argv: list[str] = [
            self.ssh_binary,
            "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ClearAllForwardings=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", f"ConnectTimeout={int(self.connect_timeout_seconds)}",
            "-o", f"ServerAliveInterval={int(self.server_alive_interval_seconds)}",
            "-o", f"ServerAliveCountMax={int(self.server_alive_count_max)}",
        ]
        if self.known_hosts_file is not None:
            argv += ["-o", f"UserKnownHostsFile={self.known_hosts_file}"]
        if self.identity_file is not None:
            argv += ["-o", "IdentitiesOnly=yes", "-i", str(self.identity_file)]
        if int(self.port) != 22:
            argv += ["-p", str(int(self.port))]
        # OpenSSH sends the remote command through a remote shell.  shlex.join
        # produces one safely quoted command string from already validated tokens;
        # callers never provide an opaque shell snippet.
        argv += [self.host, shlex.join(self.remote_command)]
        return tuple(argv)


PopenFactory = Callable[..., subprocess.Popen[str]]


class SSHWorkerTransport:
    """Line-oriented request/response carrier for ``worker_sidecar`` over SSH."""

    def __init__(
        self,
        policy: SSHTransportPolicy,
        *,
        response_timeout_seconds: float = 30.0,
        popen_factory: PopenFactory = subprocess.Popen,
    ) -> None:
        if response_timeout_seconds <= 0:
            raise ValueError("response timeout must be positive")
        self.policy = policy
        self.response_timeout_seconds = float(response_timeout_seconds)
        self._process = popen_factory(
            policy.argv(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            shell=False,
        )
        if self._process.stdin is None or self._process.stdout is None:
            raise SSHTransportError("SSH process did not expose worker pipes")

    @property
    def transport_commitment(self) -> str:
        return self.policy.commitment()

    def _readline(self) -> str:
        stream = self._process.stdout
        assert stream is not None
        try:
            fileno = stream.fileno()
        except (AttributeError, OSError):
            return stream.readline()
        ready, _, _ = select.select([fileno], [], [], self.response_timeout_seconds)
        if not ready:
            raise SSHTransportError("remote worker response timed out")
        return stream.readline()

    def _stderr_excerpt(self, limit: int = 4096) -> str:
        if self._process.poll() is None or self._process.stderr is None:
            return ""
        try:
            return self._process.stderr.read(limit).strip()
        except Exception:
            return ""

    def call(self, op: str, **payload: Any) -> Any:
        _validate_token(op, "worker operation")
        if self._process.poll() is not None:
            detail = self._stderr_excerpt()
            raise SSHTransportError(f"SSH worker already exited{': ' + detail if detail else ''}")
        request: dict[str, Any] = {"op": op}
        request.update(payload)
        line = json.dumps(request, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"
        assert self._process.stdin is not None
        try:
            self._process.stdin.write(line)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise SSHTransportError("failed to send request to SSH worker") from exc
        raw = self._readline()
        if not raw:
            detail = self._stderr_excerpt()
            raise SSHTransportError(f"SSH worker returned EOF{': ' + detail if detail else ''}")
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SSHTransportError("SSH worker returned malformed JSON") from exc
        if not isinstance(response, Mapping) or not isinstance(response.get("ok"), bool):
            raise SSHTransportError("SSH worker returned a malformed response envelope")
        if response["ok"] is not True:
            error = str(response.get("error") or "remote worker rejected request")
            raise SSHTransportError(error)
        if "result" not in response:
            raise SSHTransportError("SSH worker response omitted result")
        return response["result"]

    def capabilities(self) -> Mapping[str, Any]:
        result = self.call("capabilities")
        if not isinstance(result, Mapping):
            raise SSHTransportError("remote capabilities are not an object")
        return result

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        try:
            self.call("close")
        except SSHTransportError:
            pass
        try:
            self._process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            try:
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2.0)

    def __enter__(self) -> "SSHWorkerTransport":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
