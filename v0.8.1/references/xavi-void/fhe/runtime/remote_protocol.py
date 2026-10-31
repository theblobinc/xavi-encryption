"""Canonical binary protocol for remote encrypted evaluator sessions."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from xavi_void.crypto.shake import content_id
from xavi_void.math.types import Ordinal

MAGIC=b"XVOIDREM"
VERSION=1

class MessageType(IntEnum):
    CREATE_SESSION=1
    UPLOAD_PROGRAM=2
    INSTRUCTION_CHUNK=3
    CHECKPOINT=4
    FINISH=5
    RESULT=6
    CANCEL=7
    RECOVER=8
    ACK=9
    ERROR=10


def _uvar(value:int)->bytes:
    if value<0: raise ValueError("uvar cannot encode negative")
    out=bytearray()
    while True:
        b=value & 0x7f; value >>= 7; out.append(b | (0x80 if value else 0))
        if not value: return bytes(out)

class _Reader:
    def __init__(self,data:bytes): self.data=data; self.pos=0
    def take(self,n:int)->bytes:
        if n<0 or self.pos+n>len(self.data): raise ValueError("truncated remote message")
        v=self.data[self.pos:self.pos+n]; self.pos+=n; return v
    def uvar(self)->int:
        start=self.pos; shift=0; value=0
        while True:
            if self.pos>=len(self.data) or shift>63: raise ValueError("invalid varint")
            b=self.data[self.pos]; self.pos+=1; value |= (b & 0x7f)<<shift
            if not b & 0x80: break
            shift += 7
        if self.data[start:self.pos] != _uvar(value): raise ValueError("noncanonical varint")
        return value
    def blob(self)->bytes: return self.take(self.uvar())
    def text(self)->str: return self.blob().decode("utf-8")
    def finish(self):
        if self.pos != len(self.data): raise ValueError("trailing bytes")

def _blob(data:bytes)->bytes: return _uvar(len(data))+data
def _text(value:str)->bytes: return _blob(value.encode("utf-8"))

@dataclass(frozen=True,slots=True)
class RemoteMessage:
    message_type: MessageType
    session_id: str
    sequence: Ordinal
    prior_message_commitment: str | None
    payload: bytes

    def __post_init__(self):
        if not self.session_id: raise ValueError("session_id required")
        if not isinstance(self.sequence,Ordinal): raise TypeError("sequence must be Ordinal")
        if not isinstance(self.payload,bytes): raise TypeError("payload must be bytes")

    def encode(self)->bytes:
        prior=b"" if self.prior_message_commitment is None else self.prior_message_commitment.encode("ascii")
        return MAGIC+bytes([VERSION])+_uvar(int(self.message_type))+_text(self.session_id)+_uvar(self.sequence.value)+_blob(prior)+_blob(self.payload)

    def commitment(self)->str:
        return content_id("XAVI-VOID/REMOTE-MESSAGE/v1",self.encode())

    @classmethod
    def decode(cls,data:bytes)->"RemoteMessage":
        r=_Reader(data)
        if r.take(len(MAGIC)) != MAGIC: raise ValueError("invalid remote protocol magic")
        if r.take(1)[0] != VERSION: raise ValueError("unsupported remote protocol version")
        try: mt=MessageType(r.uvar())
        except ValueError as e: raise ValueError("unknown remote message type") from e
        session=r.text(); seqv=r.uvar()
        if seqv<1: raise ValueError("remote sequence is one-origin")
        prior_raw=r.blob(); payload=r.blob(); r.finish()
        prior=prior_raw.decode("ascii") if prior_raw else None
        obj=cls(mt,session,Ordinal(seqv),prior,payload)
        if obj.encode()!=data: raise ValueError("noncanonical remote message")
        return obj

class ReplayError(ValueError): pass

class ReplayProtector:
    """Per-session strict sequence + transcript-chain verification."""
    def __init__(self): self._last:dict[str,tuple[int,str]]={}
    def validate(self,message:RemoteMessage)->str:
        previous=self._last.get(message.session_id)
        if previous is None:
            if message.sequence.value != 1 or message.prior_message_commitment is not None:
                raise ReplayError("first message must be sequence 1 with no predecessor")
        else:
            last_seq,last_commitment=previous
            if message.sequence.value != last_seq+1: raise ReplayError("out-of-order or replayed remote message")
            if message.prior_message_commitment != last_commitment: raise ReplayError("remote transcript chain mismatch")
        return message.commitment()
    def commit(self,message:RemoteMessage,commitment:str|None=None)->str:
        commitment=message.commitment() if commitment is None else commitment
        self._last[message.session_id]=(message.sequence.value,commitment)
        return commitment
    def accept(self,message:RemoteMessage)->str:
        commitment=self.validate(message);return self.commit(message,commitment)
    def snapshot(self)->dict[str,list[object]]:
        return {session:[seq,commitment] for session,(seq,commitment) in sorted(self._last.items())}
    @classmethod
    def from_snapshot(cls,snapshot:dict[str,list[object]])->"ReplayProtector":
        obj=cls()
        for session,value in snapshot.items():
            if not session or not isinstance(value,list) or len(value)!=2: raise ValueError("invalid replay snapshot")
            seq,commitment=value
            if not isinstance(seq,int) or seq<1 or not isinstance(commitment,str) or not commitment: raise ValueError("invalid replay snapshot entry")
            obj._last[session]=(seq,commitment)
        return obj

@dataclass(frozen=True,slots=True)
class RemoteTranscript:
    session_id:str
    message_commitments:tuple[str,...]
    def commitment(self)->str:
        if not self.message_commitments: raise ValueError("transcript cannot be empty")
        return content_id("XAVI-VOID/REMOTE-TRANSCRIPT/v1",self.session_id.encode(),*(c.encode() for c in self.message_commitments))
