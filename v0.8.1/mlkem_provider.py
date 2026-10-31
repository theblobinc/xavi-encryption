#!/usr/bin/env python3
"""Rootless, witnessed OpenSSL 3.5 ML-KEM provider for XAVI-DUO.

The cryptographic primitive is OpenSSL's FIPS 203 ML-KEM implementation.
Xavi-derived machinery supplies isolation, capability metadata and evidence only.
"""
from __future__ import annotations
import hashlib, json, os, re, shutil, subprocess, time
from pathlib import Path
from xavi_duo_fs import secure_tempdir
from xavi_duo_provider_runtime import provider_choice, run_provider

IMAGE=os.environ.get('XAVI_DUO_MLKEM_IMAGE','localhost/xavi-duo-mlkem:openssl-3.5')
PINNED_IMAGE_ID='994c36c66732b7ac2333e658b9ac3dc0b16acf90fa546c72fa6c0601f3066a68'
DEFAULT_ALLOWED_IMAGE_IDS=(PINNED_IMAGE_ID,)
DEFAULT_ALGORITHM='ML-KEM-1024'
ALGORITHMS={'ML-KEM-512','ML-KEM-768','ML-KEM-1024'}
KEM_CIPHERTEXT_BYTES={'ML-KEM-512':768,'ML-KEM-768':1088,'ML-KEM-1024':1568}
_KEY_DESC_RE=re.compile(r'^(ML-KEM-(?:512|768|1024))\s+(?:Private|Public)-Key:',re.M)
PROVIDER_TIMEOUT=int(os.environ.get('XAVI_DUO_PROVIDER_TIMEOUT','120'))

class MLKEMProviderError(RuntimeError): pass

def _sha256_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def _sha256_file(p:Path)->str:return _sha256_bytes(p.read_bytes())

def image_info()->dict:
    return provider_choice(
        image=IMAGE,
        default_image_ids=list(DEFAULT_ALLOWED_IMAGE_IDS),
        native_env='XAVI_DUO_MLKEM_NATIVE',
        backend_env='XAVI_DUO_MLKEM_BACKEND',
    )

def _run(work:Path,args:list[str],timeout:int|None=None)->dict:
    timeout=PROVIDER_TIMEOUT if timeout is None else int(timeout)
    info=image_info()
    if not info.get('available'): raise MLKEMProviderError('ML-KEM provider unavailable: '+str(info.get('error') or 'unknown error'))
    started=time.monotonic()
    manager=os.environ.get('XAVI_DUO_PODMAN_CGROUP_MANAGER') or None
    try:
        cp=run_provider(info,work,args,timeout=timeout,cgroup_manager=manager)
    except Exception as exc:
        raise MLKEMProviderError(f'provider execution failed: {exc}') from exc
    elapsed_ms=round((time.monotonic()-started)*1000,3)
    if cp.returncode!=0:
        raise MLKEMProviderError(f"provider operation failed rc={cp.returncode}: {cp.stderr.strip()}")
    provider={**info}
    if info.get('runtime')=='podman': provider['cgroup_manager']=manager or 'default/auto'
    return {'elapsed_ms':elapsed_ms,'stdout':cp.stdout,'stderr':cp.stderr,'provider':provider}


def actual_key_algorithm(key_path:Path|str,*,public:bool=False)->str:
    """Return the ML-KEM parameter set encoded by the actual key object."""
    key_path=Path(key_path).resolve()
    if not key_path.is_file(): raise FileNotFoundError(key_path)
    with secure_tempdir(prefix='xavi-mlkem-inspect-') as t:
        name='kem.pub.pem' if public else 'kem.pem'
        shutil.copy2(key_path,t/name)
        args=['pkey'] + (['-pubin'] if public else []) + ['-in','/work/'+name,'-text','-noout']
        r=_run(t,args)
        m=_KEY_DESC_RE.search(r.get('stdout',''))
        if not m: raise MLKEMProviderError('unable to determine ML-KEM parameter set from key')
        alg=m.group(1)
        if alg not in ALGORITHMS: raise MLKEMProviderError('unsupported ML-KEM key parameter set')
        return alg

def require_key_algorithm(key_path:Path|str,algorithm:str,*,public:bool=False)->str:
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-KEM parameter set')
    actual=actual_key_algorithm(key_path,public=public)
    if actual!=algorithm:
        raise MLKEMProviderError(f'ML-KEM key parameter mismatch: required {algorithm}, actual {actual}')
    return actual

def self_test()->dict:
    with secure_tempdir(prefix='xavi-mlkem-selftest-') as work:
        r=_run(work,['version'])
        algs=_run(work,['list','-kem-algorithms'])['stdout']
        for alg in ALGORITHMS:
            if alg not in algs:raise MLKEMProviderError(f'{alg} unavailable')
        keygen(work/'private.pem',work/'public.pem',algorithm=DEFAULT_ALGORITHM)
        ct,ss1,_=encapsulate(work/'public.pem',algorithm=DEFAULT_ALGORITHM)
        ss2,_=decapsulate(work/'private.pem',ct,algorithm=DEFAULT_ALGORITHM)
        if ss1!=ss2:raise MLKEMProviderError('ML-KEM shared secret mismatch')
        return {'status':'PASS','openssl':r['stdout'].strip(),'algorithm':DEFAULT_ALGORITHM,'shared_secret_bytes':len(ss1),**r['provider']}

def keygen(private_path:Path|str,public_path:Path|str,*,algorithm:str=DEFAULT_ALGORITHM)->dict:
    if algorithm not in ALGORITHMS:raise ValueError('unsupported ML-KEM parameter set')
    private_path=Path(private_path).resolve(); public_path=Path(public_path).resolve()
    if private_path.exists() or public_path.exists():raise FileExistsError('ML-KEM key path already exists')
    if private_path.parent!=public_path.parent:raise ValueError('private/public paths must share one directory')
    work=private_path.parent; work.mkdir(parents=True,exist_ok=True); os.chmod(work,0o700)
    priv='/work/'+private_path.name; pub='/work/'+public_path.name
    r1=_run(work,['genpkey','-algorithm',algorithm,'-out',priv])
    r2=_run(work,['pkey','-in',priv,'-pubout','-out',pub])
    os.chmod(private_path,0o600); os.chmod(public_path,0o644)
    require_key_algorithm(private_path,algorithm,public=False); require_key_algorithm(public_path,algorithm,public=True)
    return {'algorithm':algorithm,'private':str(private_path),'public':str(public_path),'public_key_id':'sha256:'+_sha256_file(public_path),
            'private_sha256':_sha256_file(private_path),'public_sha256':_sha256_file(public_path),'provider':r1['provider'],'elapsed_ms':r1['elapsed_ms']+r2['elapsed_ms']}

def encapsulate(public_path:Path|str,*,algorithm:str=DEFAULT_ALGORITHM)->tuple[bytes,bytes,dict]:
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-KEM parameter set')
    public_path=Path(public_path).resolve(); work=public_path.parent
    if not public_path.is_file():raise FileNotFoundError(public_path)
    require_key_algorithm(public_path,algorithm,public=True)
    with secure_tempdir(prefix='xavi-mlkem-encap-') as t:
        pub=t/'public.pem'; shutil.copyfile(public_path,pub)
        r=_run(t,['pkeyutl','-encap','-inkey','/work/public.pem','-pubin','-out','/work/ciphertext.bin','-secret','/work/shared.bin'])
        ct=(t/'ciphertext.bin').read_bytes(); ss=(t/'shared.bin').read_bytes()
        if len(ct)!=KEM_CIPHERTEXT_BYTES[algorithm]: raise MLKEMProviderError('unexpected ML-KEM ciphertext length')
        if len(ss)!=32: raise MLKEMProviderError('unexpected ML-KEM shared-secret length')
        evidence={'operation':'encapsulate','algorithm':algorithm,'public_key_id':'sha256:'+_sha256_file(public_path),'ciphertext_sha256':_sha256_bytes(ct),
                  'ciphertext_bytes':len(ct),'shared_secret_bytes':len(ss),'provider':r['provider'],'elapsed_ms':r['elapsed_ms'],'authority':False}
        return ct,ss,evidence

def decapsulate(private_path:Path|str,ciphertext:bytes,*,algorithm:str=DEFAULT_ALGORITHM)->tuple[bytes,dict]:
    if algorithm not in ALGORITHMS: raise ValueError('unsupported ML-KEM parameter set')
    private_path=Path(private_path).resolve(); work=private_path.parent
    if not private_path.is_file():raise FileNotFoundError(private_path)
    require_key_algorithm(private_path,algorithm,public=False)
    if len(ciphertext)!=KEM_CIPHERTEXT_BYTES[algorithm]: raise MLKEMProviderError('invalid ML-KEM ciphertext length')
    with secure_tempdir(prefix='xavi-mlkem-decap-') as t:
        priv=t/'private.pem'; shutil.copyfile(private_path,priv); (t/'ciphertext.bin').write_bytes(ciphertext)
        r=_run(t,['pkeyutl','-decap','-inkey','/work/private.pem','-in','/work/ciphertext.bin','-secret','/work/shared.bin'])
        ss=(t/'shared.bin').read_bytes()
        if len(ss)!=32: raise MLKEMProviderError('unexpected ML-KEM shared-secret length')
        evidence={'operation':'decapsulate','algorithm':algorithm,'ciphertext_sha256':_sha256_bytes(ciphertext),'ciphertext_bytes':len(ciphertext),
                  'shared_secret_bytes':len(ss),'provider':r['provider'],'elapsed_ms':r['elapsed_ms'],'authority':False}
        return ss,evidence


def public_key_id_from_private(private_path:Path|str)->str:
    private_path=Path(private_path).resolve()
    if not private_path.is_file(): raise FileNotFoundError(private_path)
    with secure_tempdir(prefix='xavi-mlkem-pubid-') as t:
        shutil.copyfile(private_path,t/'private.pem')
        _run(t,['pkey','-in','/work/private.pem','-pubout','-out','/work/public.pem'])
        return 'sha256:'+_sha256_file(t/'public.pem')
