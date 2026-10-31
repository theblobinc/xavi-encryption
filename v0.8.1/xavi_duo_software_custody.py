#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from xavi_duo_fs import atomic_create,fsync_dir,read_regular_file,DurableIOError
SCHEMA='XAVI-DUO/SOFTWARE-CUSTODY/v1'
class SoftwareCustodyError(RuntimeError): pass
def _b64e(b): return base64.urlsafe_b64encode(b).decode('ascii')
def _b64d(s): return base64.b64decode(s.encode('ascii'),altchars=b'-_',validate=True)
class SoftwareCustody:
    def __init__(self,root,node_id): self.root=Path(root); self.node_id=str(node_id); self.kek_path=self.root/'wrapping.key'; self.objects=self.root/'objects'
    def init(self):
        self.root.mkdir(parents=True,exist_ok=True); self.objects.mkdir(parents=True,exist_ok=True); os.chmod(self.root,0o700); os.chmod(self.objects,0o700)
        if not self.kek_path.exists():
            try: atomic_create(self.kek_path,os.urandom(32),0o600)
            except FileExistsError: pass
        try: key=read_regular_file(self.kek_path,max_bytes=32,private=True)
        except (OSError,DurableIOError) as exc: raise SoftwareCustodyError(str(exc)) from exc
        if len(key)!=32: raise SoftwareCustodyError('invalid wrapping key length')
        return self
    def _key(self):
        try: key=read_regular_file(self.kek_path,max_bytes=32,private=True)
        except (OSError,DurableIOError) as exc: raise SoftwareCustodyError(str(exc)) from exc
        if len(key)!=32: raise SoftwareCustodyError('invalid wrapping key length')
        return key
    def seal(self,name,plaintext,purpose='private-key'):
        if not name or '/' in name or '..' in name: raise ValueError('invalid custody object name')
        dest=self.objects/(name+'.json')
        if dest.exists(): raise FileExistsError(dest)
        nonce=os.urandom(12); meta={'schema':SCHEMA,'node':self.node_id,'name':name,'purpose':purpose}; aad=json.dumps(meta,sort_keys=True,separators=(',',':')).encode(); ct=ChaCha20Poly1305(self._key()).encrypt(nonce,plaintext,aad)
        obj={**meta,'nonce':_b64e(nonce),'ciphertext':_b64e(ct),'plaintext_sha256':hashlib.sha256(plaintext).hexdigest()}
        atomic_create(dest,(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        return {'reference':f'file://{self.objects/(name+".json")}','sha256':obj['plaintext_sha256'],'hardware_bound':False,'authority':False}
    def unseal(self,name,purpose='private-key'):
        path=self.objects/(name+'.json')
        try: raw=read_regular_file(path,max_bytes=16*1024*1024,private=True)
        except (OSError,DurableIOError) as exc: raise SoftwareCustodyError(str(exc)) from exc
        try: obj=json.loads(raw)
        except Exception as exc: raise SoftwareCustodyError('invalid custody object') from exc
        expected={'schema','node','name','purpose','nonce','ciphertext','plaintext_sha256'}
        if not isinstance(obj,dict) or set(obj)!=expected: raise SoftwareCustodyError('custody object fields mismatch')
        meta={'schema':SCHEMA,'node':self.node_id,'name':name,'purpose':purpose}
        if any(obj.get(k)!=v for k,v in meta.items()): raise SoftwareCustodyError('custody metadata mismatch')
        aad=json.dumps(meta,sort_keys=True,separators=(',',':')).encode(); pt=ChaCha20Poly1305(self._key()).decrypt(_b64d(obj['nonce']),_b64d(obj['ciphertext']),aad)
        if hashlib.sha256(pt).hexdigest()!=obj['plaintext_sha256']: raise SoftwareCustodyError('plaintext digest mismatch')
        return pt
