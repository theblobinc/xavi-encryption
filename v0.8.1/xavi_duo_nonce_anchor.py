#!/usr/bin/env python3
"""Independent rollback-domain anchors for XDE nonce chronology."""
from __future__ import annotations
import json,ssl,urllib.error,urllib.parse,urllib.request
from dataclasses import dataclass
from typing import Callable

CLAIM_SCHEMA='XAVI-DUO/NONCE-ANCHOR-CLAIM/v1'
RECEIPT_SCHEMA='XAVI-DUO/NONCE-ANCHOR-RECEIPT/v1'
MAX_RESPONSE_BYTES=64*1024
class NonceAnchorError(RuntimeError): pass
class NonceRollbackDetected(NonceAnchorError): pass


def _validate_key_id(key_id:str)->str:
    if not isinstance(key_id,str) or not key_id or len(key_id)>256: raise NonceAnchorError('invalid nonce anchor key id')
    return key_id

def _validate_counter(counter:int)->int:
    if not isinstance(counter,int) or isinstance(counter,bool) or counter<1 or counter>(1<<63)-1: raise NonceAnchorError('invalid nonce anchor counter')
    return counter

def validate_receipt(row:dict,key_id:str,counter:int)->dict:
    if not isinstance(row,dict): raise NonceAnchorError('nonce anchor receipt must be an object')
    required={'schema','status','anchor_id','rollback_domain','key_id','counter','high_water','authority'}
    if set(row)!=required: raise NonceAnchorError('nonce anchor receipt fields mismatch')
    if row['schema']!=RECEIPT_SCHEMA or row['status']!='accepted': raise NonceAnchorError('nonce anchor claim not accepted')
    if row['authority'] is not False: raise NonceAnchorError('nonce anchor receipt must not confer runtime authority')
    if row['key_id']!=key_id or int(row['counter'])!=counter: raise NonceAnchorError('nonce anchor receipt binding mismatch')
    if int(row['high_water'])<counter: raise NonceAnchorError('nonce anchor high-water mark is behind accepted counter')
    if not isinstance(row['anchor_id'],str) or not row['anchor_id']: raise NonceAnchorError('nonce anchor id missing')
    if row['rollback_domain'] in {'','local','same-host','unknown',None}: raise NonceAnchorError('nonce anchor is not an independent rollback domain')
    return row

@dataclass
class CallbackNonceAnchor:
    callback: Callable[[str,int],dict]
    anchor_id: str='callback'
    rollback_domain: str='external'
    independent_rollback_domain: bool=True
    def claim(self,key_id:str,counter:int)->dict:
        key_id=_validate_key_id(key_id);counter=_validate_counter(counter)
        try: row=self.callback(key_id,counter)
        except NonceRollbackDetected: raise
        except Exception as exc: raise NonceAnchorError('nonce anchor callback failed') from exc
        return validate_receipt(row,key_id,counter)

@dataclass
class HTTPSNonceAnchor:
    endpoint: str
    ssl_context: ssl.SSLContext|None=None
    timeout: float=15.0
    independent_rollback_domain: bool=True
    def __post_init__(self):
        u=urllib.parse.urlparse(self.endpoint)
        if u.scheme!='https' or not u.hostname: raise NonceAnchorError('nonce anchor endpoint must use HTTPS')
    @classmethod
    def mtls(cls,endpoint:str,*,ca_file=None,cert_file=None,key_file=None,timeout=15.0):
        if not cert_file or not key_file: raise NonceAnchorError('mTLS nonce anchor requires client certificate and key')
        ctx=ssl.create_default_context(cafile=ca_file)
        ctx.load_cert_chain(cert_file,key_file)
        return cls(endpoint,ssl_context=ctx,timeout=timeout)
    def claim(self,key_id:str,counter:int)->dict:
        key_id=_validate_key_id(key_id);counter=_validate_counter(counter)
        body=json.dumps({'schema':CLAIM_SCHEMA,'key_id':key_id,'counter':counter,'authority':False},sort_keys=True,separators=(',',':')).encode()
        req=urllib.request.Request(self.endpoint,data=body,method='POST',headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':'xavi-duo-encryption/0.8.1'})
        try:
            with urllib.request.urlopen(req,context=self.ssl_context,timeout=self.timeout) as r:
                if r.status==409: raise NonceRollbackDetected('nonce anchor rejected reused/rolled-back counter')
                if r.status not in {200,201}: raise NonceAnchorError(f'nonce anchor HTTP status {r.status}')
                raw=r.read(MAX_RESPONSE_BYTES+1)
        except urllib.error.HTTPError as exc:
            if exc.code==409: raise NonceRollbackDetected('nonce anchor rejected reused/rolled-back counter') from exc
            raise NonceAnchorError('nonce anchor HTTP request failed') from exc
        except urllib.error.URLError as exc: raise NonceAnchorError('nonce anchor HTTPS request failed') from exc
        if len(raw)>MAX_RESPONSE_BYTES: raise NonceAnchorError('nonce anchor response exceeds bound')
        try: row=json.loads(raw)
        except Exception as exc: raise NonceAnchorError('invalid nonce anchor JSON response') from exc
        return validate_receipt(row,key_id,counter)

def require_independent_anchor(anchor)->None:
    if anchor is None or getattr(anchor,'independent_rollback_domain',False) is not True:
        raise NonceAnchorError('high-assurance nonce claims require an independent rollback-domain anchor')
