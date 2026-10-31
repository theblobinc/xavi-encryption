#!/usr/bin/env python3
"""Crash-safe independent rollback-domain anchors for replay chronology.

The replay anchor uses a two-phase v2 protocol. ``prepare`` reserves exactly one
claim id for the next sequence and is idempotent for that same claim. ``commit``
advances the durable high-water mark. This lets local replay state recover from
a crash between external and local durability without allowing a completed
claim to be silently replayed after a full local snapshot rollback.
"""
from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

REQUEST_SCHEMA = "XAVI-DUO/REPLAY-ANCHOR-REQUEST/v2"
RECEIPT_SCHEMA = "XAVI-DUO/REPLAY-ANCHOR-RECEIPT/v2"
MAX_RESPONSE_BYTES = 64 * 1024


class ReplayAnchorError(RuntimeError):
    pass


class ReplayRollbackDetected(ReplayAnchorError):
    pass


class ReplayClaimConflict(ReplayRollbackDetected):
    pass


def replay_anchor_key(project_id: str, session_id: str) -> str:
    if not isinstance(project_id, str) or not project_id or len(project_id) > 128:
        raise ReplayAnchorError("invalid replay anchor project id")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        raise ReplayAnchorError("invalid replay anchor session id")
    digest = hashlib.sha256((project_id + "\x00" + session_id).encode("utf-8")).hexdigest()
    return "replay:sha256:" + digest


def replay_claim_id(project_id: str, session_id: str, sequence: int, message_id: str, expires_at: int) -> str:
    if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
        raise ReplayAnchorError("invalid replay message id")
    body = {
        "schema": "XAVI-DUO/REPLAY-CLAIM-ID/v2",
        "project_id": project_id,
        "session_id": session_id,
        "sequence": int(sequence),
        "message_id": message_id,
        "expires_at": int(expires_at),
        "authority": False,
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(b"XAVI-DUO/replay-claim/v2\x00" + raw).hexdigest()


def validate_replay_receipt(row: dict, *, operation: str, key_id: str, sequence: int, claim_id: str) -> dict:
    if not isinstance(row, dict):
        raise ReplayAnchorError("replay anchor receipt must be an object")
    required = {
        "schema", "status", "operation", "anchor_id", "rollback_domain",
        "key_id", "counter", "high_water", "claim_id", "state",
        "idempotent", "authority",
    }
    if set(row) != required:
        raise ReplayAnchorError("replay anchor receipt fields mismatch")
    if row["schema"] != RECEIPT_SCHEMA or row["status"] != "accepted":
        raise ReplayAnchorError("replay anchor request not accepted")
    if row["operation"] != operation:
        raise ReplayAnchorError("replay anchor operation mismatch")
    if row["authority"] is not False:
        raise ReplayAnchorError("replay anchor receipt must not confer runtime authority")
    if row["key_id"] != key_id or int(row["counter"]) != int(sequence):
        raise ReplayAnchorError("replay anchor receipt binding mismatch")
    if row["claim_id"] != claim_id:
        raise ReplayAnchorError("replay anchor claim-id mismatch")
    if row["state"] not in {"prepared", "committed"}:
        raise ReplayAnchorError("invalid replay anchor state")
    if operation == "commit" and row["state"] != "committed":
        raise ReplayAnchorError("replay anchor commit did not commit")
    if not isinstance(row["idempotent"], bool):
        raise ReplayAnchorError("replay anchor idempotent flag must be boolean")
    if int(row["high_water"]) < 0:
        raise ReplayAnchorError("invalid replay anchor high-water mark")
    if row["state"] == "committed" and int(row["high_water"]) < int(sequence):
        raise ReplayAnchorError("committed replay anchor high-water mark is behind counter")
    if not isinstance(row["anchor_id"], str) or not row["anchor_id"]:
        raise ReplayAnchorError("replay anchor id missing")
    if row["rollback_domain"] in {"", "local", "same-host", "unknown", None}:
        raise ReplayAnchorError("replay anchor is not an independent rollback domain")
    return row


@dataclass
class CallbackReplayAnchor:
    callback: Callable[[str, str, int, str], dict]
    anchor_id: str = "callback"
    rollback_domain: str = "external"
    independent_rollback_domain: bool = True
    supports_two_phase_replay_claims: bool = True

    def _call(self, operation: str, key_id: str, counter: int, claim_id: str) -> dict:
        try:
            row = self.callback(operation, str(key_id), int(counter), str(claim_id))
        except ReplayRollbackDetected:
            raise
        except Exception as exc:
            raise ReplayAnchorError("replay anchor callback failed") from exc
        return validate_replay_receipt(row, operation=operation, key_id=str(key_id), sequence=int(counter), claim_id=str(claim_id))

    def prepare(self, key_id: str, counter: int, claim_id: str) -> dict:
        return self._call("prepare", key_id, counter, claim_id)

    def commit(self, key_id: str, counter: int, claim_id: str) -> dict:
        return self._call("commit", key_id, counter, claim_id)


@dataclass
class HTTPSReplayAnchor:
    endpoint: str
    ssl_context: ssl.SSLContext | None = None
    timeout: float = 15.0
    independent_rollback_domain: bool = True
    supports_two_phase_replay_claims: bool = True

    def __post_init__(self):
        u = urllib.parse.urlparse(self.endpoint)
        if u.scheme != "https" or not u.hostname:
            raise ReplayAnchorError("replay anchor endpoint must use HTTPS")

    @classmethod
    def mtls(cls, endpoint: str, *, ca_file=None, cert_file=None, key_file=None, timeout=15.0):
        if not cert_file or not key_file:
            raise ReplayAnchorError("mTLS replay anchor requires client certificate and key")
        ctx = ssl.create_default_context(cafile=ca_file)
        ctx.load_cert_chain(cert_file, key_file)
        return cls(endpoint, ssl_context=ctx, timeout=timeout)

    def _request(self, operation: str, key_id: str, counter: int, claim_id: str) -> dict:
        body = json.dumps({
            "schema": REQUEST_SCHEMA,
            "operation": operation,
            "key_id": str(key_id),
            "counter": int(counter),
            "claim_id": str(claim_id),
            "authority": False,
        }, sort_keys=True, separators=(",", ":")).encode()
        req = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "xavi-duo-encryption/0.8.1",
            },
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=self.timeout) as r:
                if r.status == 409:
                    raise ReplayClaimConflict("replay anchor rejected conflicting/rolled-back claim")
                if r.status not in {200, 201}:
                    raise ReplayAnchorError(f"replay anchor HTTP status {r.status}")
                raw = r.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                raise ReplayClaimConflict("replay anchor rejected conflicting/rolled-back claim") from exc
            raise ReplayAnchorError("replay anchor HTTP request failed") from exc
        except urllib.error.URLError as exc:
            raise ReplayAnchorError("replay anchor HTTPS request failed") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ReplayAnchorError("replay anchor response exceeds bound")
        try:
            row = json.loads(raw.decode("utf-8", "strict"))
        except Exception as exc:
            raise ReplayAnchorError("invalid replay anchor JSON response") from exc
        return validate_replay_receipt(row, operation=operation, key_id=str(key_id), sequence=int(counter), claim_id=str(claim_id))

    def prepare(self, key_id: str, counter: int, claim_id: str) -> dict:
        return self._request("prepare", key_id, counter, claim_id)

    def commit(self, key_id: str, counter: int, claim_id: str) -> dict:
        return self._request("commit", key_id, counter, claim_id)


def require_independent_replay_anchor(anchor) -> None:
    if anchor is None or getattr(anchor, "independent_rollback_domain", False) is not True:
        raise ReplayAnchorError("high-assurance replay claims require an independent rollback-domain anchor")
    if getattr(anchor, "supports_two_phase_replay_claims", False) is not True:
        raise ReplayAnchorError("high-assurance replay claims require two-phase claim-bound replay anchor v2")
    if not callable(getattr(anchor, "prepare", None)) or not callable(getattr(anchor, "commit", None)):
        raise ReplayAnchorError("replay anchor v2 prepare/commit operations are unavailable")


def replay_claim_context(*, project_id: str, session_id: str, sequence: int, message_id: str, expires_at: int) -> tuple[str, str]:
    key_id = replay_anchor_key(project_id, session_id)
    claim_id = replay_claim_id(project_id, session_id, sequence, message_id, expires_at)
    return key_id, claim_id


def prepare_replay_anchor(anchor, *, key_id: str, sequence: int, claim_id: str) -> dict:
    require_independent_replay_anchor(anchor)
    return anchor.prepare(key_id, int(sequence), claim_id)


def commit_replay_anchor(anchor, *, key_id: str, sequence: int, claim_id: str) -> dict:
    require_independent_replay_anchor(anchor)
    return anchor.commit(key_id, int(sequence), claim_id)


__all__ = [
    "CallbackReplayAnchor", "HTTPSReplayAnchor", "ReplayAnchorError",
    "ReplayRollbackDetected", "ReplayClaimConflict", "replay_anchor_key",
    "replay_claim_id", "replay_claim_context", "validate_replay_receipt",
    "require_independent_replay_anchor", "prepare_replay_anchor",
    "commit_replay_anchor",
]
