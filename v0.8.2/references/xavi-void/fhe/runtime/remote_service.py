"""Remote evaluator protocol state machine with replay and expiry hardening."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Callable

from .remote_protocol import MessageType, RemoteMessage, ReplayProtector

class RemoteSessionPhase(str,Enum):
    NEW="new"
    CREATED="created"
    PROGRAM_UPLOADED="program-uploaded"
    RUNNING="running"
    FINISHED="finished"
    CANCELLED="cancelled"
    EXPIRED="expired"

@dataclass(slots=True)
class RemoteSessionProtocolState:
    session_id:str
    phase:RemoteSessionPhase=RemoteSessionPhase.NEW
    checkpoint_ids:list[str]=field(default_factory=list)
    chunk_count:int=0
    expires_at:float|None=None

class RemoteProtocolError(ValueError): pass

class RemoteEvaluatorProtocol:
    """Strict one-origin remote session protocol.

    Replay state is committed only after the message passes phase validation, so
    a malformed/out-of-phase frame cannot consume the next sequence number and
    wedge an otherwise recoverable session.
    """
    def __init__(self, *, session_ttl_seconds:float=900.0, clock:Callable[[],float]=time.monotonic):
        if session_ttl_seconds<=0: raise ValueError("session TTL must be positive")
        self.replay=ReplayProtector();self.sessions:dict[str,RemoteSessionProtocolState]={}
        self.session_ttl_seconds=float(session_ttl_seconds);self._clock=clock

    def _check_live(self,state:RemoteSessionProtocolState)->None:
        if state.expires_at is not None and self._clock()>=state.expires_at:
            state.phase=RemoteSessionPhase.EXPIRED
            raise RemoteProtocolError("remote session expired")
        if state.phase==RemoteSessionPhase.CANCELLED: raise RemoteProtocolError("session is cancelled")
        if state.phase==RemoteSessionPhase.EXPIRED: raise RemoteProtocolError("remote session expired")

    def _refresh(self,state:RemoteSessionProtocolState)->None:
        state.expires_at=self._clock()+self.session_ttl_seconds

    def accept(self,message:RemoteMessage)->str:
        commitment=self.replay.validate(message)
        state=self.sessions.get(message.session_id)
        mt=message.message_type
        if mt==MessageType.CREATE_SESSION:
            if state is not None: raise RemoteProtocolError("session already exists")
            state=RemoteSessionProtocolState(message.session_id,RemoteSessionPhase.CREATED)
            self._refresh(state);self.sessions[message.session_id]=state
            self.replay.commit(message,commitment);return commitment
        if state is None: raise RemoteProtocolError("unknown remote session")
        self._check_live(state)
        if mt==MessageType.UPLOAD_PROGRAM:
            if state.phase!=RemoteSessionPhase.CREATED: raise RemoteProtocolError("program upload is out of phase")
            if not message.payload: raise RemoteProtocolError("encrypted program payload is required")
            state.phase=RemoteSessionPhase.PROGRAM_UPLOADED
        elif mt==MessageType.INSTRUCTION_CHUNK:
            if state.phase not in {RemoteSessionPhase.PROGRAM_UPLOADED,RemoteSessionPhase.RUNNING}: raise RemoteProtocolError("instruction chunk is out of phase")
            if not message.payload: raise RemoteProtocolError("instruction chunk payload is required")
            state.phase=RemoteSessionPhase.RUNNING;state.chunk_count+=1
        elif mt==MessageType.CHECKPOINT:
            if state.phase not in {RemoteSessionPhase.PROGRAM_UPLOADED,RemoteSessionPhase.RUNNING}: raise RemoteProtocolError("checkpoint is out of phase")
            checkpoint_id=message.payload.decode("ascii")
            if not checkpoint_id: raise RemoteProtocolError("checkpoint id is required")
            if checkpoint_id in state.checkpoint_ids: raise RemoteProtocolError("checkpoint replay")
            state.checkpoint_ids.append(checkpoint_id)
        elif mt==MessageType.RECOVER:
            checkpoint_id=message.payload.decode("ascii")
            if checkpoint_id not in state.checkpoint_ids: raise RemoteProtocolError("unknown checkpoint for recovery")
            state.phase=RemoteSessionPhase.RUNNING
        elif mt==MessageType.FINISH:
            if state.phase not in {RemoteSessionPhase.PROGRAM_UPLOADED,RemoteSessionPhase.RUNNING}: raise RemoteProtocolError("finish is out of phase")
            state.phase=RemoteSessionPhase.FINISHED
        elif mt==MessageType.RESULT:
            if state.phase!=RemoteSessionPhase.FINISHED: raise RemoteProtocolError("result is out of phase")
        elif mt==MessageType.CANCEL:
            if state.phase==RemoteSessionPhase.FINISHED: raise RemoteProtocolError("cannot cancel finished session")
            state.phase=RemoteSessionPhase.CANCELLED
        elif mt in {MessageType.ACK,MessageType.ERROR}:
            pass
        else: raise RemoteProtocolError("unsupported remote message type")
        if state.phase not in {RemoteSessionPhase.CANCELLED,RemoteSessionPhase.FINISHED}:
            self._refresh(state)
        self.replay.commit(message,commitment)
        return commitment
    def authorize_execution(self,session_id:str)->RemoteSessionProtocolState:
        """Return a live execution-capable session or fail closed."""
        state=self.sessions.get(session_id)
        if state is None: raise RemoteProtocolError("unknown remote session")
        self._check_live(state)
        if state.phase not in {RemoteSessionPhase.PROGRAM_UPLOADED,RemoteSessionPhase.RUNNING}:
            raise RemoteProtocolError("remote session is not ready for execution")
        return state

    def snapshot(self)->dict[str,object]:
        now=self._clock()
        sessions={}
        for sid,state in sorted(self.sessions.items()):
            remaining=None if state.expires_at is None else max(0.0,state.expires_at-now)
            sessions[sid]={
                "phase":state.phase.value,"checkpoint_ids":list(state.checkpoint_ids),
                "chunk_count":state.chunk_count,"ttl_remaining":remaining,
            }
        return {"schema":"xavi-void-remote-protocol-snapshot-v1","session_ttl_seconds":self.session_ttl_seconds,"replay":self.replay.snapshot(),"sessions":sessions}

    @classmethod
    def restore(cls,snapshot:dict[str,object], *, clock:Callable[[],float]=time.monotonic)->"RemoteEvaluatorProtocol":
        if snapshot.get("schema")!="xavi-void-remote-protocol-snapshot-v1": raise RemoteProtocolError("unsupported remote protocol snapshot")
        ttl=float(snapshot.get("session_ttl_seconds",0))
        obj=cls(session_ttl_seconds=ttl,clock=clock)
        replay=snapshot.get("replay")
        sessions=snapshot.get("sessions")
        if not isinstance(replay,dict) or not isinstance(sessions,dict): raise RemoteProtocolError("malformed remote protocol snapshot")
        obj.replay=ReplayProtector.from_snapshot(replay)
        now=clock()
        for sid,raw in sessions.items():
            if not isinstance(sid,str) or not isinstance(raw,dict): raise RemoteProtocolError("malformed session snapshot")
            try: phase=RemoteSessionPhase(str(raw["phase"])); checkpoints=list(raw["checkpoint_ids"]); chunks=int(raw["chunk_count"])
            except Exception as exc: raise RemoteProtocolError("malformed session snapshot") from exc
            if any(not isinstance(x,str) or not x for x in checkpoints) or chunks<0: raise RemoteProtocolError("malformed session snapshot")
            remaining=raw.get("ttl_remaining")
            expires=None if remaining is None else now+max(0.0,float(remaining))
            obj.sessions[sid]=RemoteSessionProtocolState(sid,phase,checkpoints,chunks,expires)
        return obj
