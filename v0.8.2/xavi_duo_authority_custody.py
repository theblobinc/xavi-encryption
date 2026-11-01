#!/usr/bin/env python3
"""Authority-gated software custody.

This backend never treats possession of the external wrapping secret as
sufficient authorization. Every unseal requires an approval object and a
caller-supplied verifier. The verifier is the authority boundary; this module
only enforces fail-closed invocation and cryptographic object binding.
"""
from __future__ import annotations
import base64,hashlib,json,os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from xavi_duo_fs import atomic_create,fsync_dir,read_regular_file,DurableIOError
SCHEMA='XAVI-DUO/AUTHORITY-CUSTODY/v2'
class AuthorityCustodyError(RuntimeError): pass
def _e(b): return base64.urlsafe_b64encode(b).decode('ascii')
def _d(s): return base64.b64decode(s.encode('ascii'),altchars=b'-_',validate=True)
class AuthorityCustody:
    def __init__(self,root,node_id,secret_path,approval_verifier=None):
        self.root=Path(root); self.node_id=str(node_id); self.secret_path=Path(secret_path); self.objects=self.root/'objects'; self.approval_verifier=approval_verifier
    def init(self):
        self.root.mkdir(parents=True,exist_ok=True); self.objects.mkdir(parents=True,exist_ok=True); os.chmod(self.root,0o700); os.chmod(self.objects,0o700); fsync_dir(self.root)
        if not self.secret_path.is_file(): raise AuthorityCustodyError('authority wrapping secret is not provisioned')
        try: secret=read_regular_file(self.secret_path,max_bytes=32,private=True)
        except (OSError,DurableIOError) as exc: raise AuthorityCustodyError(str(exc)) from exc
        if len(secret)!=32: raise AuthorityCustodyError('authority wrapping secret must be 32 bytes')
        if self.approval_verifier is None: raise AuthorityCustodyError('authority approval verifier is required')
        return self
    def _key(self):
        try: key=read_regular_file(self.secret_path,max_bytes=32,private=True)
        except (OSError,DurableIOError) as exc: raise AuthorityCustodyError(str(exc)) from exc
        if len(key)!=32: raise AuthorityCustodyError('authority wrapping secret must be 32 bytes')
        return key
    def seal(self,name,plaintext,purpose='private-key'):
        if not name or '/' in name or '..' in name: raise ValueError('invalid custody name')
        dest=self.objects/(name+'.json')
        if dest.exists(): raise FileExistsError(dest)
        meta={'schema':SCHEMA,'node':self.node_id,'name':name,'purpose':purpose}; aad=json.dumps(meta,sort_keys=True,separators=(',',':')).encode(); nonce=os.urandom(12); ct=ChaCha20Poly1305(self._key()).encrypt(nonce,plaintext,aad); obj={**meta,'nonce':_e(nonce),'ciphertext':_e(ct),'plaintext_sha256':hashlib.sha256(plaintext).hexdigest()}
        atomic_create(dest,(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        return {'reference':f'authority://{self.node_id}/{name}','sha256':obj['plaintext_sha256'],'secret_external':True,'hardware_bound':False,'authority_gate_required':True,'authority':False}
    def unseal(self,name,purpose='private-key',*,approval=None):
        if approval is None: raise AuthorityCustodyError('authority approval is required')
        request={'schema':'XAVI-DUO/CUSTODY-UNSEAL-REQUEST/v1','node':self.node_id,'name':str(name),'purpose':str(purpose),'authority':False}
        try: allowed=bool(self.approval_verifier(approval,request))
        except Exception as exc: raise AuthorityCustodyError('authority approval verifier failed') from exc
        if not allowed: raise AuthorityCustodyError('authority approval denied')
        path=self.objects/(name+'.json')
        try: raw=read_regular_file(path,max_bytes=16*1024*1024,private=True)
        except (OSError,DurableIOError) as exc: raise AuthorityCustodyError(str(exc)) from exc
        try: obj=json.loads(raw)
        except Exception as exc: raise AuthorityCustodyError('invalid custody object') from exc
        expected={'schema','node','name','purpose','nonce','ciphertext','plaintext_sha256'}
        if not isinstance(obj,dict) or set(obj)!=expected: raise AuthorityCustodyError('custody object fields mismatch')
        meta={'schema':SCHEMA,'node':self.node_id,'name':name,'purpose':purpose}
        if any(obj.get(k)!=v for k,v in meta.items()): raise AuthorityCustodyError('metadata mismatch')
        aad=json.dumps(meta,sort_keys=True,separators=(',',':')).encode(); pt=ChaCha20Poly1305(self._key()).decrypt(_d(obj['nonce']),_d(obj['ciphertext']),aad)
        if hashlib.sha256(pt).hexdigest()!=obj['plaintext_sha256']: raise AuthorityCustodyError('digest mismatch')
        return pt
