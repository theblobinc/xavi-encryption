#!/usr/bin/env python3
"""Canonical commitments and authenticated evidence receipts for XDE2.

Design adapted from xavi-void's SHAKE256-512 canonical-content and receipt
patterns. Receipts are evidence only; they never grant authority.
License: MIT OR Apache-2.0
"""
from __future__ import annotations
import base64, hashlib, hmac, json, re, struct, unicodedata
from typing import Any, Iterable

OUTPUT_BYTES=64
ID_PREFIX='xduo:shake256-512:'

def _validate(value:Any,path='$')->None:
    if isinstance(value,float): raise ValueError(f'binary floating point forbidden at {path}')
    if isinstance(value,str):
        if unicodedata.normalize('NFC',value)!=value: raise ValueError(f'text not NFC at {path}')
        return
    if isinstance(value,bool) or value is None or isinstance(value,int): return
    if isinstance(value,list):
        for i,x in enumerate(value,start=1): _validate(x,f'{path}[{i}]')
        return
    if isinstance(value,dict):
        for k,x in value.items():
            if not isinstance(k,str): raise ValueError(f'non-text key at {path}')
            if unicodedata.normalize('NFC',k)!=k: raise ValueError(f'key not NFC at {path}')
            _validate(x,f'{path}.{k}')
        return
    raise ValueError(f'unsupported canonical type at {path}: {type(value).__name__}')

def canonical_bytes(value:Any)->bytes:
    _validate(value)
    return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode('utf-8')

def framed_shake256_512(domain:str,fields:Iterable[bytes])->bytes:
    if not domain.isascii() or re.fullmatch(r'[\x21-\x7e]+/v[1-9][0-9]*',domain) is None:
        raise ValueError('domain must be printable ASCII ending in /v<positive-version>')
    fields=tuple(fields); d=domain.encode('ascii'); s=hashlib.shake_256()
    s.update(struct.pack('>Q',len(d))); s.update(d); s.update(struct.pack('>I',len(fields)))
    for field in fields:
        s.update(struct.pack('>Q',len(field))); s.update(field)
    return s.digest(OUTPUT_BYTES)

def content_id(domain:str,*fields:bytes)->str:
    raw=framed_shake256_512(domain,fields)
    return ID_PREFIX+base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

def frame_id(frame:str)->str:
    return content_id('XAVI-DUO/XDE2-FRAME/v1',frame.encode('utf-8'))

def aad_id(aad:bytes)->str:
    return content_id('XAVI-DUO/XDE2-AAD/v1',aad)

def receipt_body(*,frame:str,aad:bytes,key_id:str,counter:int|None,pad_to:int,duo_context_commitment:str)->dict:
    parts=frame.split('|',2)
    cells=len(parts[2].split('.')) if len(parts)==3 and parts[2] else 0
    return {
        'schema':'XAVI-DUO/ENCRYPTION-RECEIPT/v2',
        'wire':'XDE2','duo_revision':'009','aead':'ChaCha20-Poly1305','kdf':'HKDF-SHA256',
        'frame_id':frame_id(frame),'aad_id':aad_id(aad),'key_id':key_id,
        'nonce_sequence':counter,'payload_cells':cells,'pad_to':pad_to,
        'duo_context_commitment':duo_context_commitment,
        'evidence_only':True,'grants_authority':False,
    }

def authenticate_receipt(body:dict,receipt_key:bytes)->dict:
    cb=canonical_bytes(body)
    rid=content_id('XAVI-DUO/ENCRYPTION-RECEIPT/v2',cb)
    tag=hmac.new(receipt_key,b'XDE2-receipt-v2\x00'+cb,hashlib.sha256).hexdigest()
    return {'body':body,'receipt_id':rid,'auth':'hmac-sha256:'+tag}

def verify_receipt(receipt:dict,receipt_key:bytes,*,frame:str,aad:bytes,duo_context_commitment:str)->bool:
    body=receipt.get('body')
    if not isinstance(body,dict): return False
    if body.get('frame_id')!=frame_id(frame) or body.get('aad_id')!=aad_id(aad): return False
    if body.get('duo_context_commitment')!=duo_context_commitment: return False
    cb=canonical_bytes(body)
    rid=content_id('XAVI-DUO/ENCRYPTION-RECEIPT/v2',cb)
    if not hmac.compare_digest(str(receipt.get('receipt_id','')),rid): return False
    expect='hmac-sha256:'+hmac.new(receipt_key,b'XDE2-receipt-v2\x00'+cb,hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(receipt.get('auth','')),expect)
