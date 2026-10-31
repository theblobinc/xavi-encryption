"""Canonical transport format for encrypted xavi-void programs.

Ciphertexts are opaque provider blobs.  The format exposes only the selected
execution-class shape (padded register/instruction counts), never plaintext
opcodes, register addresses, semantic IDs, or representation IDs.
"""
from __future__ import annotations

from xavi_void.math.types import InstructionId,PositiveExtent
from .encrypted import (
    CipherWord64,EncryptedInstruction,EncryptedProgram,EncryptedWordInstruction,
    EncryptedWordProgram,FHEBackend,
)

MAGIC=b"XVOIDENC"
VERSION=1
TYPE_BOOLEAN=1
TYPE_WORD=2


def _uvar(v:int)->bytes:
    if v<0: raise ValueError("negative varint")
    out=bytearray()
    while True:
        b=v&0x7f;v>>=7;out.append(b|(0x80 if v else 0))
        if not v:return bytes(out)

def _positive(v:int)->bytes:
    if v<1: raise ValueError("semantic positive value required")
    return _uvar(v)

def _blob(v:bytes)->bytes:return _uvar(len(v))+v

class _Reader:
    def __init__(self,data:bytes):self.data=data;self.pos=0
    def take(self,n:int)->bytes:
        if n<0 or self.pos+n>len(self.data):raise ValueError("truncated encrypted wire")
        out=self.data[self.pos:self.pos+n];self.pos+=n;return out
    def uvar(self)->int:
        start=self.pos;shift=0;v=0
        while True:
            if self.pos>=len(self.data) or shift>63:raise ValueError("invalid varint")
            b=self.data[self.pos];self.pos+=1;v|=(b&0x7f)<<shift
            if not b&0x80:break
            shift+=7
        if self.data[start:self.pos]!=_uvar(v):raise ValueError("noncanonical varint")
        return v
    def positive(self)->int:
        v=self.uvar()
        if v<1:raise ValueError("nonpositive semantic value")
        return v
    def blob(self)->bytes:return self.take(self.uvar())
    def finish(self):
        if self.pos!=len(self.data):raise ValueError("trailing encrypted wire bytes")

def _word_blob(word:CipherWord64,b:FHEBackend)->bytes:return _blob(b.export_word64(word))
def _read_word(r:_Reader,b:FHEBackend)->CipherWord64:return b.import_word64(r.blob())

def _encode_id(words:tuple[CipherWord64,...],b:FHEBackend)->bytes:
    if len(words)!=8:raise ValueError("encrypted id requires eight words")
    return b"".join(_word_blob(w,b) for w in words)

def _decode_id(r:_Reader,b:FHEBackend)->tuple[CipherWord64,...]:return tuple(_read_word(r,b) for _ in range(8))

def encode_encrypted_program(program:EncryptedProgram,b:FHEBackend)->bytes:
    if program.backend_id!=b.backend_id:raise ValueError("backend mismatch")
    body=bytearray(MAGIC+bytes([VERSION])+_positive(TYPE_BOOLEAN))
    body+=_positive(program.register_count.value)+_positive(program.padded_instruction_count.value)
    body+=_encode_id(program.encrypted_semantic_id,b)+_encode_id(program.encrypted_representation_id,b)
    body+=_positive(len(program.instructions))
    for ins in program.instructions:
        body+=_positive(ins.instruction_id.value)
        for w in (ins.opcode_tag,ins.destination,ins.source_a,ins.source_b,ins.input_slot):body+=_word_blob(w,b)
    body+=_positive(len(program.outputs))
    for w in program.outputs:body+=_word_blob(w,b)
    return bytes(body)

def decode_encrypted_program(data:bytes,b:FHEBackend)->EncryptedProgram:
    r=_Reader(data)
    if r.take(len(MAGIC))!=MAGIC:raise ValueError("invalid encrypted wire magic")
    if r.take(1)[0]!=VERSION:raise ValueError("unsupported encrypted wire version")
    if r.positive()!=TYPE_BOOLEAN:raise ValueError("wire object is not encrypted Boolean program")
    register_count=PositiveExtent(r.positive());padded=PositiveExtent(r.positive())
    sid=_decode_id(r,b);rid=_decode_id(r,b)
    count=r.positive();instructions=[]
    for expected in range(1,count+1):
        iid=InstructionId(r.positive())
        if iid.value!=expected:raise ValueError("encrypted instruction ids must be contiguous")
        fields=tuple(_read_word(r,b) for _ in range(5))
        instructions.append(EncryptedInstruction(iid,*fields))
    out_count=r.positive();outputs=tuple(_read_word(r,b) for _ in range(out_count));r.finish()
    obj=EncryptedProgram(b.backend_id,sid,rid,register_count,tuple(instructions),outputs,padded)
    if encode_encrypted_program(obj,b)!=data:raise ValueError("encrypted Boolean wire is not canonical")
    return obj

def encode_encrypted_word_program(program:EncryptedWordProgram,b:FHEBackend)->bytes:
    if program.backend_id!=b.backend_id:raise ValueError("backend mismatch")
    body=bytearray(MAGIC+bytes([VERSION])+_positive(TYPE_WORD))
    body+=_positive(program.register_count.value)+_positive(program.padded_instruction_count.value)
    body+=_encode_id(program.encrypted_semantic_id,b)+_encode_id(program.encrypted_representation_id,b)
    body+=_positive(len(program.instructions))
    for ins in program.instructions:
        body+=_positive(ins.instruction_id.value)
        for w in (ins.opcode_tag,ins.destination,ins.source_a,ins.source_b,ins.source_c,ins.source_d,ins.source_e,ins.rotate,ins.immediate):body+=_word_blob(w,b)
    return bytes(body)

def decode_encrypted_word_program(data:bytes,b:FHEBackend)->EncryptedWordProgram:
    r=_Reader(data)
    if r.take(len(MAGIC))!=MAGIC:raise ValueError("invalid encrypted wire magic")
    if r.take(1)[0]!=VERSION:raise ValueError("unsupported encrypted wire version")
    if r.positive()!=TYPE_WORD:raise ValueError("wire object is not encrypted word program")
    register_count=PositiveExtent(r.positive());padded=PositiveExtent(r.positive())
    sid=_decode_id(r,b);rid=_decode_id(r,b)
    count=r.positive();instructions=[]
    for expected in range(1,count+1):
        iid=InstructionId(r.positive())
        if iid.value!=expected:raise ValueError("encrypted word instruction ids must be contiguous")
        fields=tuple(_read_word(r,b) for _ in range(9))
        instructions.append(EncryptedWordInstruction(iid,*fields))
    r.finish()
    obj=EncryptedWordProgram(b.backend_id,sid,rid,register_count,tuple(instructions),padded)
    if encode_encrypted_word_program(obj,b)!=data:raise ValueError("encrypted word wire is not canonical")
    return obj
