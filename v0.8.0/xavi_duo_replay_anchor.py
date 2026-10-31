#!/usr/bin/env python3
"""Independent rollback-domain anchoring for authenticated replay chronology.

Reuses the monotonic-anchor transport/receipt contract used by nonce chronology,
but domain-separates replay keys by project and session.
"""
from __future__ import annotations
import hashlib
from xavi_duo_nonce_anchor import (
    CallbackNonceAnchor, HTTPSNonceAnchor, NonceAnchorError,
    NonceRollbackDetected, require_independent_anchor,
)

class ReplayAnchorError(RuntimeError): pass
class ReplayRollbackDetected(ReplayAnchorError): pass

def replay_anchor_key(project_id:str, session_id:str)->str:
    if not isinstance(project_id,str) or not project_id or len(project_id)>128:
        raise ReplayAnchorError('invalid replay anchor project id')
    if not isinstance(session_id,str) or not session_id or len(session_id)>128:
        raise ReplayAnchorError('invalid replay anchor session id')
    # Hash variable deployment identifiers so the generic anchor sees a bounded,
    # non-ambiguous domain-separated key id.
    digest=hashlib.sha256((project_id+'\x00'+session_id).encode('utf-8')).hexdigest()
    return 'replay:sha256:'+digest

def claim_replay_anchor(anchor, *, project_id:str, session_id:str, sequence:int)->dict:
    try:
        require_independent_anchor(anchor)
        return anchor.claim(replay_anchor_key(project_id,session_id),int(sequence))
    except NonceRollbackDetected as exc:
        raise ReplayRollbackDetected('external replay anchor detected rollback/reuse') from exc
    except NonceAnchorError as exc:
        raise ReplayAnchorError('external replay anchor unavailable or invalid') from exc

__all__=['CallbackNonceAnchor','HTTPSNonceAnchor','ReplayAnchorError','ReplayRollbackDetected','replay_anchor_key','claim_replay_anchor']
