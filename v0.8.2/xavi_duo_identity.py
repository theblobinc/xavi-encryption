#!/usr/bin/env python3
"""Post-quantum node identity using ML-DSA in the isolated pinned OpenSSL provider."""
from __future__ import annotations
import base64,hashlib,shutil,re
from pathlib import Path
from mlkem_provider import _run, image_info
from xavi_duo_fs import secure_tempdir
DEFAULT_ALGORITHM='ML-DSA-65'
HIGH_ASSURANCE_ALGORITHM='ML-DSA-87'
ALGORITHMS={'ML-DSA-44','ML-DSA-65','ML-DSA-87'}
class IdentityError(RuntimeError): pass
_KEY_DESC_RE=re.compile(r'^(ML-DSA-(?:44|65|87))\s+(?:Private|Public)-Key:',re.M)

def public_key_id(public_path): return 'sha256:'+hashlib.sha256(Path(public_path).read_bytes()).hexdigest()

def actual_key_algorithm(key_path, *, public=False):
    """Return the ML-DSA parameter set encoded by the actual key."""
    key_path=Path(key_path).resolve()
    with secure_tempdir(prefix='xavi-mldsa-inspect-') as work:
        name='identity.pub.pem' if public else 'identity.pem'
        shutil.copy2(key_path,work/name)
        args=['pkey'] + (['-pubin'] if public else []) + ['-in','/work/'+name,'-text','-noout']
        r=_run(work,args)
        m=_KEY_DESC_RE.search(r.get('stdout',''))
        if not m: raise IdentityError('unable to determine ML-DSA parameter set from key')
        alg=m.group(1)
        if alg not in ALGORITHMS: raise IdentityError('unsupported ML-DSA key parameter set')
        return alg

def require_key_algorithm(key_path, algorithm, *, public=False):
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-DSA parameter set')
    actual=actual_key_algorithm(key_path,public=public)
    if actual != algorithm:
        raise IdentityError(f'ML-DSA key parameter mismatch: required {algorithm}, actual {actual}')
    return actual

def keygen(private_path,public_path,*,algorithm=DEFAULT_ALGORITHM):
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-DSA parameter set')
    private_path,public_path=Path(private_path).resolve(),Path(public_path).resolve()
    if private_path.exists() or public_path.exists(): raise FileExistsError('identity key path already exists')
    if private_path.parent!=public_path.parent: raise ValueError('private/public paths must share one directory')
    work=private_path.parent; work.mkdir(parents=True,exist_ok=True)
    _run(work,['genpkey','-algorithm',algorithm,'-out','/work/'+private_path.name])
    ev=_run(work,['pkey','-in','/work/'+private_path.name,'-pubout','-out','/work/'+public_path.name])
    private_path.chmod(0o600); public_path.chmod(0o644)
    require_key_algorithm(private_path,algorithm,public=False); require_key_algorithm(public_path,algorithm,public=True)
    return {'algorithm':algorithm,'public_key_id':public_key_id(public_path),'provider':ev['provider']}

def sign(private_path,data:bytes,*,algorithm=DEFAULT_ALGORITHM):
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-DSA parameter set')
    private_path=Path(private_path).resolve()
    require_key_algorithm(private_path,algorithm,public=False)
    with secure_tempdir(prefix='xavi-mldsa-sign-') as work:
        shutil.copy2(private_path,work/'identity.pem'); (work/'message.bin').write_bytes(data)
        r=_run(work,['pkeyutl','-sign','-inkey','/work/identity.pem','-rawin','-in','/work/message.bin','-out','/work/signature.bin'])
        sig=(work/'signature.bin').read_bytes()
        return sig,{'schema':'XAVI-DUO/MLDSA-SIGN-EVIDENCE/v2','algorithm':algorithm,'message_sha256':hashlib.sha256(data).hexdigest(),'signature_sha256':hashlib.sha256(sig).hexdigest(),'signature_bytes':len(sig),'provider':r['provider'],'authority':False}

def verify(public_path,data:bytes,signature:bytes,*,algorithm=DEFAULT_ALGORITHM):
    if algorithm not in ALGORITHMS: return False
    public_path=Path(public_path).resolve()
    try: require_key_algorithm(public_path,algorithm,public=True)
    except Exception: return False
    with secure_tempdir(prefix='xavi-mldsa-verify-') as work:
        shutil.copy2(public_path,work/'identity.pub.pem'); (work/'message.bin').write_bytes(data); (work/'signature.bin').write_bytes(signature)
        try:
            _run(work,['pkeyutl','-verify','-pubin','-inkey','/work/identity.pub.pem','-rawin','-in','/work/message.bin','-sigfile','/work/signature.bin'])
            return True
        except Exception: return False

def self_test(algorithm=DEFAULT_ALGORITHM):
    with secure_tempdir(prefix='xavi-mldsa-selftest-') as root:
        info=keygen(root/'private.pem',root/'public.pem',algorithm=algorithm); msg=b'xavi-duo ML-DSA identity self-test'; sig,_=sign(root/'private.pem',msg,algorithm=algorithm)
        if not verify(root/'public.pem',msg,sig,algorithm=algorithm): raise IdentityError('ML-DSA verification failed')
        if verify(root/'public.pem',msg+b'!',sig,algorithm=algorithm): raise IdentityError('tamper verified')
        return {'status':'PASS','algorithm':algorithm,'signature_bytes':len(sig),'public_key_id':info['public_key_id'],'provider':image_info()}
