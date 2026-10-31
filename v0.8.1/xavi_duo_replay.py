#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import json
import os
import time
from pathlib import Path

from xavi_duo_fs import DurableIOError, atomic_write, read_regular_file
from xavi_duo_replay_anchor import (
    ReplayAnchorError,
    ReplayRollbackDetected,
    commit_replay_anchor,
    prepare_replay_anchor,
    replay_claim_context,
    require_independent_replay_anchor,
)

MAX_REPLAY_STATE_BYTES = 8 * 1024 * 1024


class ReplayError(RuntimeError):
    pass


class ReplayGuard:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = self.path.with_suffix(self.path.suffix + ".lock")
        self.quarantine = self.path.with_suffix(self.path.suffix + ".quarantine")

    def init(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        return self

    def _load_state(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            raw = read_regular_file(self.path, max_bytes=MAX_REPLAY_STATE_BYTES, private=True)
            state = json.loads(raw.decode("utf-8", "strict"))
        except (DurableIOError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReplayError("replay state is corrupt") from exc
        if not isinstance(state, dict):
            raise ReplayError("replay state is corrupt")
        return state

    def _persist(self, state: dict) -> None:
        raw = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(raw) > MAX_REPLAY_STATE_BYTES:
            raise ReplayError("replay state exceeds bound")
        atomic_write(self.path, raw, 0o600)

    def _cleanup(self, state: dict, now: int) -> dict:
        return {
            key: value
            for key, value in state.items()
            if isinstance(value, dict)
            and (value.get("pending") is not None or int(value.get("expires_at", now + 1)) >= now - 60)
        }

    def _quarantine(self, *, project_id: str, session_id: str, sequence: int, claim_id: str | None, reason: str) -> None:
        marker = {
            "schema": "XAVI-DUO/REPLAY-QUARANTINE/v2",
            "project_id": project_id,
            "session_id": session_id,
            "sequence": int(sequence),
            "claim_id": claim_id,
            "reason": reason,
            "authority": False,
        }
        atomic_write(
            self.quarantine,
            (json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o600,
        )

    @staticmethod
    def _base_row(row) -> dict:
        if not isinstance(row, dict):
            raise ReplayError("replay state row is corrupt")
        try:
            last = int(row.get("last_sequence", 0))
            ids = list(row.get("message_ids", []))
        except Exception as exc:
            raise ReplayError("replay state row is corrupt") from exc
        if last < 0 or any(not isinstance(x, str) for x in ids):
            raise ReplayError("replay state row is corrupt")
        out = dict(row)
        out["last_sequence"] = last
        out["message_ids"] = ids[-4096:]
        return out

    def claim(self, session_id, sequence, message_id, expires_at, *, project_id=None, anchor=None, require_anchor=False):
        now = int(time.time())
        session_id = str(session_id)
        message_id = str(message_id)
        sequence = int(sequence)
        expires_at = int(expires_at)
        if not session_id or len(session_id) > 128:
            raise ReplayError("invalid session id")
        if not message_id or len(message_id) > 256:
            raise ReplayError("invalid message id")
        if sequence < 1:
            raise ReplayError("invalid sequence")
        if expires_at - now > 86400:
            raise ReplayError("session expiry exceeds 24h policy")
        if self.quarantine.exists():
            raise ReplayError("replay state is quarantined")
        if require_anchor:
            try:
                require_independent_replay_anchor(anchor)
            except ReplayAnchorError as exc:
                raise ReplayError(str(exc)) from exc
        elif anchor is not None:
            try:
                require_independent_replay_anchor(anchor)
            except ReplayAnchorError as exc:
                raise ReplayError(str(exc)) from exc

        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(self.lock, flags, 0o600)
        except OSError as exc:
            raise ReplayError("unable to open replay lock securely") from exc
        try:
            with os.fdopen(lock_fd, "a+", encoding="ascii", closefd=True) as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                state = self._load_state()
                row = self._base_row(state.get(session_id, {"last_sequence": 0, "message_ids": []}))
                pending = row.get("pending")

                # Recovery is allowed only for the exact pending claim. Any other
                # request must wait; otherwise a transient anchor failure could
                # be turned into a sequence skip or conflicting replay.
                if pending is not None:
                    if not isinstance(pending, dict):
                        raise ReplayError("replay pending state is corrupt")
                    exact = (
                        pending.get("project_id") == str(project_id)
                        and int(pending.get("sequence", -1)) == sequence
                        and pending.get("message_id") == message_id
                        and int(pending.get("expires_at", -1)) == expires_at
                    )
                    if not exact:
                        raise ReplayError("unresolved replay claim requires exact retry before another message")
                    if anchor is None or not project_id:
                        raise ReplayError("pending anchored replay claim requires its independent anchor")
                    key_id, claim_id = replay_claim_context(
                        project_id=str(project_id), session_id=session_id,
                        sequence=sequence, message_id=message_id, expires_at=expires_at,
                    )
                    if pending.get("key_id") != key_id or pending.get("claim_id") != claim_id:
                        raise ReplayError("replay pending claim binding is corrupt")
                    phase = pending.get("phase")
                    if phase not in {"intent", "local-committed"}:
                        raise ReplayError("replay pending claim phase is corrupt")
                    try:
                        prep = prepare_replay_anchor(anchor, key_id=key_id, sequence=sequence, claim_id=claim_id)
                    except ReplayRollbackDetected as exc:
                        self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="external-anchor-conflict")
                        raise ReplayError("external replay rollback/conflict detected; state quarantined") from exc
                    except ReplayAnchorError as exc:
                        raise ReplayError("external replay anchor unavailable; pending claim retained for exact retry") from exc

                    if phase == "intent":
                        # A committed or idempotently prepared claim without the
                        # expected local phase means local durable state moved
                        # backwards. Fail closed rather than replaying execution.
                        if prep.get("state") == "committed":
                            self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="anchor-ahead-of-local-intent")
                            raise ReplayError("external replay anchor is ahead of local state; state quarantined")
                        expected = int(row["last_sequence"]) + 1
                        if sequence != expected or message_id in row["message_ids"]:
                            raise ReplayError("replay pending/local chronology mismatch")
                        row["last_sequence"] = sequence
                        row["message_ids"] = (row["message_ids"] + [message_id])[-4096:]
                        row["updated_at"] = now
                        row["expires_at"] = expires_at
                        pending["phase"] = "local-committed"
                        row["pending"] = pending
                        state[session_id] = row
                        self._persist(state)
                    else:
                        if int(row["last_sequence"]) != sequence or message_id not in row["message_ids"]:
                            raise ReplayError("replay local-committed pending state is corrupt")

                    try:
                        anchor_receipt = commit_replay_anchor(anchor, key_id=key_id, sequence=sequence, claim_id=claim_id)
                    except ReplayRollbackDetected as exc:
                        self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="external-anchor-commit-conflict")
                        raise ReplayError("external replay rollback/conflict detected during commit; state quarantined") from exc
                    except ReplayAnchorError as exc:
                        raise ReplayError("external replay anchor commit unavailable; pending claim retained for exact retry") from exc
                    row.pop("pending", None)
                    row["anchor_claim_id"] = claim_id
                    state[session_id] = row
                    state = self._cleanup(state, now)
                    self._persist(state)
                    if now > expires_at:
                        raise ReplayError("pending replay claim recovered after expiry; sequence consumed")
                    return {
                        "schema": "XAVI-DUO/REPLAY-CLAIM/v4",
                        "session_id": session_id,
                        "sequence": sequence,
                        "message_id": message_id,
                        "expires_at": expires_at,
                        "external_anchor": anchor_receipt,
                        "recovered_pending": True,
                        "authority": False,
                    }

                if now > expires_at:
                    raise ReplayError("session expired")
                expected = int(row["last_sequence"]) + 1
                if sequence != expected:
                    raise ReplayError(f"expected sequence {expected}")
                if message_id in row["message_ids"]:
                    raise ReplayError("duplicate message id")

                anchor_receipt = None
                claim_id = None
                if anchor is not None:
                    if not project_id:
                        raise ReplayError("project id required for replay anchor")
                    key_id, claim_id = replay_claim_context(
                        project_id=str(project_id), session_id=session_id,
                        sequence=sequence, message_id=message_id, expires_at=expires_at,
                    )
                    row["pending"] = {
                        "schema": "XAVI-DUO/REPLAY-PENDING/v2",
                        "phase": "intent",
                        "project_id": str(project_id),
                        "sequence": sequence,
                        "message_id": message_id,
                        "expires_at": expires_at,
                        "key_id": key_id,
                        "claim_id": claim_id,
                        "authority": False,
                    }
                    state[session_id] = row
                    self._persist(state)
                    try:
                        prep = prepare_replay_anchor(anchor, key_id=key_id, sequence=sequence, claim_id=claim_id)
                    except ReplayRollbackDetected as exc:
                        self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="external-anchor-conflict")
                        raise ReplayError("external replay rollback/conflict detected; state quarantined") from exc
                    except ReplayAnchorError as exc:
                        raise ReplayError("external replay anchor unavailable; pending claim retained for exact retry") from exc
                    if prep.get("state") == "committed" or prep.get("idempotent") is True:
                        self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="external-anchor-ahead-of-local")
                        raise ReplayError("external replay anchor is ahead of local state; state quarantined")

                    row["last_sequence"] = sequence
                    row["message_ids"] = (row["message_ids"] + [message_id])[-4096:]
                    row["updated_at"] = now
                    row["expires_at"] = expires_at
                    row["pending"]["phase"] = "local-committed"
                    state[session_id] = row
                    self._persist(state)
                    try:
                        anchor_receipt = commit_replay_anchor(anchor, key_id=key_id, sequence=sequence, claim_id=claim_id)
                    except ReplayRollbackDetected as exc:
                        self._quarantine(project_id=str(project_id), session_id=session_id, sequence=sequence, claim_id=claim_id, reason="external-anchor-commit-conflict")
                        raise ReplayError("external replay rollback/conflict detected during commit; state quarantined") from exc
                    except ReplayAnchorError as exc:
                        raise ReplayError("external replay anchor commit unavailable; pending claim retained for exact retry") from exc
                    row.pop("pending", None)
                    row["anchor_claim_id"] = claim_id
                else:
                    row["last_sequence"] = sequence
                    row["message_ids"] = (row["message_ids"] + [message_id])[-4096:]
                    row["updated_at"] = now
                    row["expires_at"] = expires_at

                state[session_id] = row
                state = self._cleanup(state, now)
                self._persist(state)
                return {
                    "schema": "XAVI-DUO/REPLAY-CLAIM/v4",
                    "session_id": session_id,
                    "sequence": sequence,
                    "message_id": message_id,
                    "expires_at": expires_at,
                    "external_anchor": anchor_receipt,
                    "recovered_pending": False,
                    "authority": False,
                }
        finally:
            # fdopen owns and closes lock_fd on the normal path. Close only if
            # fdopen was not reached or failed before ownership transferred.
            try:
                os.close(lock_fd)
            except OSError:
                pass
