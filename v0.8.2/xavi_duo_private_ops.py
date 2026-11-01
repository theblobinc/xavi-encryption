#!/usr/bin/env python3
"""Private-key operation boundary for XAVI-DUO.

Private operations consume CustodyRef objects.  A custody URI alone never
implies that a secure operator exists.  High-assurance callers require an
operator that explicitly attests non-exporting private-key use.
"""
from __future__ import annotations
import base64,json,ssl,urllib.error,urllib.parse,urllib.request
from dataclasses import dataclass,field
from pathlib import Path
from typing import Callable
from xavi_duo_custody import CustodyRef,parse_custody_ref

MAX_RESPONSE_BYTES=256*1024
class PrivateOpsError(RuntimeError): pass

class PrivateOperator:
    schemes=frozenset()
    non_exporting_private_key=False
    hardware_bound=False
    external_authority=False
    def sign(self,ref:CustodyRef,data:bytes,*,algorithm:str): raise NotImplementedError
    def decapsulate(self,ref:CustodyRef,ciphertext:bytes,*,algorithm:str): raise NotImplementedError

class FilePrivateOperator(PrivateOperator):
    schemes=frozenset({'file'})
    non_exporting_private_key=False
    def _path(self,ref): return Path(ref.name)
    def sign(self,ref,data,*,algorithm):
        from xavi_duo_identity import sign
        sig,ev=sign(self._path(ref),bytes(data),algorithm=algorithm)
        return sig,{**ev,'custody_ref':ref.raw,'private_key_exported_to_process':True,'hardware_bound':False}
    def decapsulate(self,ref,ciphertext,*,algorithm):
        from mlkem_provider import decapsulate
        ss,ev=decapsulate(self._path(ref),bytes(ciphertext),algorithm=algorithm)
        return ss,{**ev,'custody_ref':ref.raw,'private_key_exported_to_process':True,'hardware_bound':False}

@dataclass
class CallbackPrivateOperator(PrivateOperator):
    callback:Callable[[str,CustodyRef,bytes,str],dict]
    schemes:frozenset=field(default_factory=lambda:frozenset({'authority','remote','tpm2','pkcs11'}))
    non_exporting_private_key:bool=True
    hardware_bound:bool=False
    external_authority:bool=True
    def _call(self,operation,ref,payload,algorithm):
        try: row=self.callback(operation,ref,bytes(payload),algorithm)
        except Exception as exc: raise PrivateOpsError('private-operation callback failed') from exc
        if not isinstance(row,dict) or row.get('status')!='PASS' or row.get('algorithm')!=algorithm or row.get('reference')!=ref.raw:
            raise PrivateOpsError('invalid private-operation callback response')
        return row
    def sign(self,ref,data,*,algorithm):
        row=self._call('sign',ref,data,algorithm)
        try: out=base64.b64decode(row['signature'],validate=True)
        except Exception as exc: raise PrivateOpsError('invalid callback signature') from exc
        return out,{'schema':'XAVI-DUO/PRIVATE-OP-EVIDENCE/v1','operation':'sign','algorithm':algorithm,'custody_ref':ref.raw,'operator':'callback','non_exporting_private_key':True,'hardware_bound':bool(self.hardware_bound),'external_authority':bool(self.external_authority),'authority':False}
    def decapsulate(self,ref,ciphertext,*,algorithm):
        row=self._call('decapsulate',ref,ciphertext,algorithm)
        try: out=base64.b64decode(row['shared_secret'],validate=True)
        except Exception as exc: raise PrivateOpsError('invalid callback shared secret') from exc
        if len(out)!=32: raise PrivateOpsError('invalid callback shared-secret length')
        return out,{'schema':'XAVI-DUO/PRIVATE-OP-EVIDENCE/v1','operation':'decapsulate','algorithm':algorithm,'custody_ref':ref.raw,'operator':'callback','non_exporting_private_key':True,'hardware_bound':bool(self.hardware_bound),'external_authority':bool(self.external_authority),'authority':False}

@dataclass
class HTTPSPrivateOperator(PrivateOperator):
    endpoint:str
    ssl_context:ssl.SSLContext
    timeout:float=20.0
    schemes:frozenset=field(default_factory=lambda:frozenset({'authority','remote','tpm2','pkcs11'}))
    non_exporting_private_key:bool=True
    hardware_bound:bool=False
    external_authority:bool=True
    def __post_init__(self):
        u=urllib.parse.urlparse(self.endpoint)
        if u.scheme!='https' or not u.hostname: raise PrivateOpsError('private-operation endpoint must use HTTPS')
    @classmethod
    def mtls(cls,endpoint,*,ca_file=None,cert_file=None,key_file=None,timeout=20.0,hardware_bound=False):
        if not cert_file or not key_file: raise PrivateOpsError('mTLS private-operation service requires client certificate and key')
        ctx=ssl.create_default_context(cafile=ca_file);ctx.load_cert_chain(cert_file,key_file)
        return cls(endpoint,ctx,timeout=timeout,hardware_bound=hardware_bound)
    def _request(self,operation,ref,payload,algorithm):
        body=json.dumps({'schema':'XAVI-DUO/PRIVATE-OP-REQUEST/v1','operation':operation,'reference':ref.raw,'algorithm':algorithm,'payload':base64.b64encode(bytes(payload)).decode('ascii'),'authority':False},sort_keys=True,separators=(',',':')).encode()
        req=urllib.request.Request(self.endpoint,data=body,method='POST',headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':'xavi-duo-encryption/0.8'})
        try:
            with urllib.request.urlopen(req,context=self.ssl_context,timeout=self.timeout) as r:
                if r.status not in {200,201}: raise PrivateOpsError(f'private-operation HTTP status {r.status}')
                raw=r.read(MAX_RESPONSE_BYTES+1)
        except Exception as exc:
            if isinstance(exc,PrivateOpsError): raise
            raise PrivateOpsError('private-operation HTTPS request failed') from exc
        if len(raw)>MAX_RESPONSE_BYTES: raise PrivateOpsError('private-operation response exceeds bound')
        try: row=json.loads(raw.decode('utf-8','strict'))
        except Exception as exc: raise PrivateOpsError('invalid private-operation response JSON') from exc
        return CallbackPrivateOperator(lambda *_:row,schemes=self.schemes,hardware_bound=self.hardware_bound,external_authority=True)._call(operation,ref,payload,algorithm)
    def sign(self,ref,data,*,algorithm):
        row=self._request('sign',ref,data,algorithm)
        try: sig=base64.b64decode(row['signature'],validate=True)
        except Exception as exc: raise PrivateOpsError('invalid remote signature') from exc
        return sig,{'schema':'XAVI-DUO/PRIVATE-OP-EVIDENCE/v1','operation':'sign','algorithm':algorithm,'custody_ref':ref.raw,'operator':'https-mtls','non_exporting_private_key':True,'hardware_bound':bool(self.hardware_bound),'external_authority':True,'authority':False}
    def decapsulate(self,ref,ciphertext,*,algorithm):
        row=self._request('decapsulate',ref,ciphertext,algorithm)
        try: ss=base64.b64decode(row['shared_secret'],validate=True)
        except Exception as exc: raise PrivateOpsError('invalid remote shared secret') from exc
        if len(ss)!=32: raise PrivateOpsError('invalid remote shared-secret length')
        return ss,{'schema':'XAVI-DUO/PRIVATE-OP-EVIDENCE/v1','operation':'decapsulate','algorithm':algorithm,'custody_ref':ref.raw,'operator':'https-mtls','non_exporting_private_key':True,'hardware_bound':bool(self.hardware_bound),'external_authority':True,'authority':False}

class PrivateOpsRegistry:
    def __init__(self): self._ops={}
    def register(self,operator:PrivateOperator):
        for scheme in operator.schemes:self._ops[scheme]=operator
        return self
    def operator(self,ref:CustodyRef,*,high_assurance=False):
        op=self._ops.get(ref.scheme)
        if op is None: raise PrivateOpsError(f'no private-operation provider configured for {ref.scheme}://')
        if high_assurance and not op.non_exporting_private_key:
            raise PrivateOpsError(f'high-assurance mode rejects exporting private-key operator for {ref.scheme}://')
        if high_assurance and ref.scheme in {'tpm2','pkcs11'} and not op.hardware_bound:
            raise PrivateOpsError(f'high-assurance mode requires hardware-bound operator for {ref.scheme}://')
        return op
    def sign(self,ref,data,*,algorithm,high_assurance=False): return self.operator(ref,high_assurance=high_assurance).sign(ref,data,algorithm=algorithm)
    def decapsulate(self,ref,ciphertext,*,algorithm,high_assurance=False): return self.operator(ref,high_assurance=high_assurance).decapsulate(ref,ciphertext,algorithm=algorithm)

def default_registry(): return PrivateOpsRegistry().register(FilePrivateOperator())

def custody_sign(reference,data,*,algorithm,registry=None,high_assurance=False):
    ref=parse_custody_ref(reference) if not isinstance(reference,CustodyRef) else reference
    return (registry or default_registry()).sign(ref,data,algorithm=algorithm,high_assurance=high_assurance)

def custody_decapsulate(reference,ciphertext,*,algorithm,registry=None,high_assurance=False):
    ref=parse_custody_ref(reference) if not isinstance(reference,CustodyRef) else reference
    return (registry or default_registry()).decapsulate(ref,ciphertext,algorithm=algorithm,high_assurance=high_assurance)
