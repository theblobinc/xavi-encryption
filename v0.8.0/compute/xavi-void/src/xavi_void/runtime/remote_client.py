"""Carrier-agnostic client for the Xavi Void remote evaluator worker protocol.

The client deliberately does not trust a carrier (SSH, PQ channel, message bus)
as execution authority.  It verifies protocol commitments locally and exposes
transport identity only as evidence that can be bound into higher-level receipts.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .remote_protocol import RemoteMessage


class WorkerRPC(Protocol):
    def call(self, op: str, **payload: Any) -> Any: ...


class RemoteWorkerClientError(RuntimeError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: object, *, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RemoteWorkerClientError(f"{label} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RemoteWorkerClientError(f"{label} is not canonical base64") from exc


@dataclass(frozen=True, slots=True)
class RemoteWorkerIdentity:
    provider: str
    device: str
    key_id: str
    transport_commitment: str | None


class RemoteWorkerClient:
    """Typed facade over the line-oriented remote worker RPC envelope."""

    def __init__(self, rpc: WorkerRPC) -> None:
        self.rpc = rpc
        self._identity: RemoteWorkerIdentity | None = None

    @property
    def transport_commitment(self) -> str | None:
        value = getattr(self.rpc, "transport_commitment", None)
        return str(value) if isinstance(value, str) and value else None

    def capabilities(self, *, refresh: bool = False) -> RemoteWorkerIdentity:
        if self._identity is not None and not refresh:
            return self._identity
        raw = self.rpc.call("capabilities")
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("remote worker capabilities are not an object")
        if raw.get("role") != "remote-worker":
            raise RemoteWorkerClientError("remote endpoint is not a remote-worker role")
        if raw.get("cryptographic") is not True:
            raise RemoteWorkerClientError("remote worker is not a cryptographic provider")
        if raw.get("has_client_secret") is not False:
            raise RemoteWorkerClientError("remote evaluator must not hold client secret material")
        provider = raw.get("provider")
        device = raw.get("device")
        key_id = raw.get("key_id")
        if not all(isinstance(value, str) and value for value in (provider, device, key_id)):
            raise RemoteWorkerClientError("remote worker identity fields are incomplete")
        self._identity = RemoteWorkerIdentity(
            provider=provider,
            device=device,
            key_id=key_id,
            transport_commitment=self.transport_commitment,
        )
        return self._identity

    def protocol_accept(self, message: RemoteMessage) -> str:
        expected = message.commitment()
        raw = self.rpc.call("protocol_accept", message=_b64e(message.encode()))
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("protocol_accept result is not an object")
        observed = raw.get("commitment")
        if observed != expected:
            raise RemoteWorkerClientError("remote protocol commitment does not match local transcript")
        return expected

    def protocol_snapshot(self) -> Mapping[str, Any]:
        raw = self.rpc.call("protocol_snapshot")
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("remote protocol snapshot is not an object")
        return raw

    def protocol_restore(self, snapshot: Mapping[str, Any]) -> None:
        raw = self.rpc.call("protocol_restore", snapshot=dict(snapshot))
        if not isinstance(raw, Mapping) or raw.get("restored") is not True:
            raise RemoteWorkerClientError("remote protocol restore was not acknowledged")

    def execute_shake(self, session_id: str, request: bytes) -> bytes:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id is required")
        if not isinstance(request, bytes) or not request:
            raise ValueError("encrypted request bytes are required")
        raw = self.rpc.call("execute_shake", session_id=session_id, request=_b64e(request))
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("execute_shake result is not an object")
        return _b64d(raw.get("response"), label="encrypted worker response")

    def metrics(self) -> Mapping[str, Any]:
        raw = self.rpc.call("metrics")
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("remote metrics are not an object")
        return raw

    def resident_stats(self) -> Mapping[str, Any]:
        raw = self.rpc.call("resident_stats")
        if not isinstance(raw, Mapping):
            raise RemoteWorkerClientError("remote resident stats are not an object")
        return raw

    def close(self) -> None:
        closer = getattr(self.rpc, "close", None)
        if callable(closer):
            closer()
