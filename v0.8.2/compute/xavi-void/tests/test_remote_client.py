from __future__ import annotations

import base64

import pytest

from xavi_void.math.types import Ordinal
from xavi_void.runtime.remote_client import RemoteWorkerClient, RemoteWorkerClientError
from xavi_void.runtime.remote_protocol import MessageType, RemoteMessage


class _RPC:
    transport_commitment = "xvoid:shake256-512:transport"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def call(self, op, **payload):
        self.calls.append((op, payload))
        response = self.responses.pop(0)
        if callable(response):
            return response(op, payload)
        return response

    def close(self):
        self.closed = True


def test_remote_worker_identity_requires_evaluator_only_crypto_role():
    rpc = _RPC([{
        "role": "remote-worker",
        "provider": "tfhe",
        "cryptographic": True,
        "has_client_secret": False,
        "key_id": "key-1",
        "device": "cuda",
    }])
    client = RemoteWorkerClient(rpc)
    identity = client.capabilities()
    assert identity.provider == "tfhe"
    assert identity.device == "cuda"
    assert identity.key_id == "key-1"
    assert identity.transport_commitment == rpc.transport_commitment
    assert client.capabilities() is identity
    assert len(rpc.calls) == 1


@pytest.mark.parametrize("patch", [
    {"role": "other"},
    {"cryptographic": False},
    {"has_client_secret": True},
    {"key_id": ""},
])
def test_remote_worker_identity_fails_closed(patch):
    raw = {
        "role": "remote-worker",
        "provider": "tfhe",
        "cryptographic": True,
        "has_client_secret": False,
        "key_id": "key-1",
        "device": "cpu",
    }
    raw.update(patch)
    with pytest.raises(RemoteWorkerClientError):
        RemoteWorkerClient(_RPC([raw])).capabilities()


def test_protocol_accept_binds_remote_ack_to_local_message_commitment():
    message = RemoteMessage(MessageType.CREATE_SESSION, "session-1", Ordinal(1), None, b"")
    expected = message.commitment()
    rpc = _RPC([{"commitment": expected}])
    client = RemoteWorkerClient(rpc)
    assert client.protocol_accept(message) == expected
    op, payload = rpc.calls[0]
    assert op == "protocol_accept"
    assert base64.b64decode(payload["message"], validate=True) == message.encode()


def test_protocol_accept_rejects_mismatched_remote_commitment():
    message = RemoteMessage(MessageType.CREATE_SESSION, "session-1", Ordinal(1), None, b"")
    with pytest.raises(RemoteWorkerClientError, match="does not match"):
        RemoteWorkerClient(_RPC([{"commitment": "wrong"}])).protocol_accept(message)


def test_execute_shake_preserves_ciphertext_bytes_and_rejects_bad_base64():
    ciphertext = b"encrypted-response\x00\xff"
    rpc = _RPC([{"response": base64.b64encode(ciphertext).decode("ascii")}])
    client = RemoteWorkerClient(rpc)
    assert client.execute_shake("session-1", b"encrypted-request") == ciphertext
    op, payload = rpc.calls[0]
    assert op == "execute_shake"
    assert payload["session_id"] == "session-1"
    assert base64.b64decode(payload["request"], validate=True) == b"encrypted-request"

    with pytest.raises(RemoteWorkerClientError, match="canonical base64"):
        RemoteWorkerClient(_RPC([{"response": "%%%"}])).execute_shake("session-1", b"x")


def test_snapshot_restore_metrics_and_close_are_carrier_agnostic():
    snapshot = {"schema": "xavi-void-remote-protocol-snapshot-v1", "sessions": {}}
    rpc = _RPC([snapshot, {"restored": True}, {"calls": 4}, {"resident": 2}])
    client = RemoteWorkerClient(rpc)
    assert client.protocol_snapshot() == snapshot
    client.protocol_restore(snapshot)
    assert client.metrics() == {"calls": 4}
    assert client.resident_stats() == {"resident": 2}
    client.close()
    assert rpc.closed is True
