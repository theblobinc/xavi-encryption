"""Production remote TFHE request/response envelopes for Rev 1.2-dev4.

The client emits provider-portable ciphertext bytes.  The evaluator imports them
under its server/evaluation key, executes without a decryption key, and exports
only ciphertext results plus measurements/commitments.  The protocol deliberately
keeps key-custody policy separate from the transport; ``pq_transport`` can seal
these envelopes without learning their encrypted contents.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Sequence

from .encrypted import CipherWord64, EncryptedWordProgram, FHEBackend, FHEEvaluatorView
from .encrypted_wire import encode_encrypted_word_program, decode_encrypted_word_program
from .shake_encrypted import (
    EncryptedShakeInput,
    EncryptedShakeResult,
    EncryptedShakeTiming,
    execute_encrypted_shake256_512,
)
from .tfhe_split import assert_remote_safe_evaluator

MAGIC=b"XVOIDTFH"
VERSION=1
MAX_FRAME=512*1024*1024


def _uvar(v:int)->bytes:
    if v<0: raise ValueError("negative varint")
    out=bytearray()
    while True:
        b=v&0x7f; v >>= 7; out.append(b | (0x80 if v else 0))
        if not v:return bytes(out)

def _blob(v:bytes)->bytes:
    if len(v)>MAX_FRAME: raise ValueError("remote TFHE blob exceeds size limit")
    return _uvar(len(v))+v

def _text(v:str)->bytes:return _blob(v.encode("utf-8"))

class _Reader:
    def __init__(self,data:bytes):
        if len(data)>MAX_FRAME: raise ValueError("remote TFHE frame exceeds size limit")
        self.data=data;self.pos=0
    def take(self,n:int)->bytes:
        if n<0 or self.pos+n>len(self.data):raise ValueError("truncated remote TFHE frame")
        out=self.data[self.pos:self.pos+n];self.pos+=n;return out
    def uvar(self)->int:
        start=self.pos; shift=0; value=0
        while True:
            if self.pos>=len(self.data) or shift>63:raise ValueError("invalid remote TFHE varint")
            b=self.data[self.pos];self.pos+=1;value|=(b&0x7f)<<shift
            if not b&0x80:break
            shift+=7
        if self.data[start:self.pos]!=_uvar(value):raise ValueError("noncanonical remote TFHE varint")
        return value
    def blob(self)->bytes:return self.take(self.uvar())
    def text(self)->str:return self.blob().decode("utf-8")
    def finish(self):
        if self.pos!=len(self.data):raise ValueError("trailing remote TFHE bytes")

@dataclass(frozen=True,slots=True)
class RemoteTFHEShakeRequest:
    key_id:str
    message:EncryptedShakeInput
    program:EncryptedWordProgram | None
    specialized_keccak:bool

@dataclass(frozen=True,slots=True)
class RemoteTFHEShakeResponse:
    key_id:str
    result:EncryptedShakeResult


def _encode_input(value:EncryptedShakeInput,backend:FHEBackend)->bytes:
    body=bytearray()
    body+=_uvar(value.message_length)
    body+=_text(value.message_commitment)
    body+=_uvar(len(value.encrypted_blocks))
    for block in value.encrypted_blocks:
        body+=_uvar(len(block))
        for word in block: body+=_blob(backend.export_word64(word))
    return bytes(body)

def _decode_input(data:bytes,backend:FHEBackend)->EncryptedShakeInput:
    r=_Reader(data);length=r.uvar();commitment=r.text();blocks=[]
    block_count=r.uvar()
    if block_count<1: raise ValueError("encrypted SHAKE input needs at least one block")
    for _ in range(block_count):
        lanes=r.uvar()
        if lanes!=17: raise ValueError("encrypted SHAKE block must contain 17 lanes")
        blocks.append(tuple(backend.import_word64(r.blob()) for _ in range(lanes)))
    r.finish();return EncryptedShakeInput(length,commitment,tuple(blocks))


def encode_shake_request(value:RemoteTFHEShakeRequest,backend:FHEBackend)->bytes:
    if not value.key_id: raise ValueError("TFHE evaluation key id is required")
    if value.specialized_keccak:
        if value.program is not None:
            raise ValueError("specialized Keccak request must not carry encrypted ExecutionIR")
        program_blob=b""
    else:
        if value.program is None:
            raise ValueError("oblivious ExecutionIR request requires encrypted program")
        program_blob=encode_encrypted_word_program(value.program,backend)
    body=bytearray(MAGIC+bytes([VERSION,1 if value.specialized_keccak else 0]))
    body+=_text(value.key_id)
    body+=_blob(_encode_input(value.message,backend))
    body+=_blob(program_blob)
    return bytes(body)

def decode_shake_request(data:bytes,backend:FHEBackend)->RemoteTFHEShakeRequest:
    r=_Reader(data)
    if r.take(len(MAGIC))!=MAGIC:raise ValueError("invalid remote TFHE request magic")
    if r.take(1)[0]!=VERSION:raise ValueError("unsupported remote TFHE request version")
    mode=r.take(1)[0]
    if mode not in {0,1}:raise ValueError("invalid remote TFHE execution mode")
    key_id=r.text();message=_decode_input(r.blob(),backend);program_blob=r.blob();r.finish()
    if mode==1:
        if program_blob: raise ValueError("specialized Keccak request must not carry encrypted ExecutionIR")
        program=None
    else:
        if not program_blob: raise ValueError("oblivious ExecutionIR request requires encrypted program")
        program=decode_encrypted_word_program(program_blob,backend)
    obj=RemoteTFHEShakeRequest(key_id,message,program,bool(mode))
    if encode_shake_request(obj,backend)!=data:raise ValueError("noncanonical remote TFHE request")
    return obj


def _timing_json(timing:EncryptedShakeTiming|None)->bytes:
    if timing is None:return b"null"
    return json.dumps(asdict(timing),sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")

def _parse_timing(data:bytes)->EncryptedShakeTiming|None:
    raw=json.loads(data)
    if raw is None:return None
    if not isinstance(raw,dict):raise ValueError("invalid remote timing evidence")
    return EncryptedShakeTiming(
        str(raw["execution_path"]),tuple(int(x) for x in raw["block_ns"]),int(raw["full_evaluation_ns"]),
        dict(raw.get("provider_metrics") or {}),dict(raw.get("resident_before") or {}),dict(raw.get("resident_after") or {}),
    )


def encode_shake_response(value:RemoteTFHEShakeResponse,backend:FHEBackend)->bytes:
    result=value.result
    body=bytearray(MAGIC+bytes([VERSION]))
    body+=_text(value.key_id)+_text(result.semantic_workload_id)+_text(result.encrypted_program_commitment)+_text(result.ciphertext_commitment)
    body+=_uvar(len(result.encrypted_output))
    for word in result.encrypted_output:body+=_blob(backend.export_word64(word))
    body+=_blob(_timing_json(result.timing))
    return bytes(body)

def decode_shake_response(data:bytes,backend:FHEBackend)->RemoteTFHEShakeResponse:
    r=_Reader(data)
    if r.take(len(MAGIC))!=MAGIC:raise ValueError("invalid remote TFHE response magic")
    if r.take(1)[0]!=VERSION:raise ValueError("unsupported remote TFHE response version")
    key_id=r.text();semantic=r.text();program_commitment=r.text();ct_commitment=r.text();count=r.uvar()
    if count!=8:raise ValueError("SHAKE256-512 response must contain eight encrypted lanes")
    output=tuple(backend.import_word64(r.blob()) for _ in range(count));timing=_parse_timing(r.blob());r.finish()
    result=EncryptedShakeResult(semantic,program_commitment,output,ct_commitment,timing)
    obj=RemoteTFHEShakeResponse(key_id,result)
    if encode_shake_response(obj,backend)!=data:raise ValueError("noncanonical remote TFHE response")
    return obj


class ProductionTFHEWorker:
    """Evaluator process facade that enforces server-key-only custody."""
    def __init__(self,evaluator_backend:FHEBackend):
        assert_remote_safe_evaluator(evaluator_backend)
        self.backend=evaluator_backend
        self.evaluator=FHEEvaluatorView(evaluator_backend)

    @property
    def key_id(self)->str:return self.backend.capabilities.key_id

    def execute_shake(self,request_bytes:bytes)->bytes:
        request=decode_shake_request(request_bytes,self.backend)
        if request.key_id!=self.key_id:raise ValueError("request evaluation-key id does not match worker")
        result=execute_encrypted_shake256_512(
            request.message,request.program,self.evaluator,specialized_keccak=request.specialized_keccak,
        )
        return encode_shake_response(RemoteTFHEShakeResponse(self.key_id,result),self.backend)
