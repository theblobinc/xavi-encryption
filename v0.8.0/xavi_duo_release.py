#!/usr/bin/env python3
"""Standalone detached release signing and verification.

The release signature is ML-DSA-87 over a domain-separated SHA-256 digest of
canonical JSON manifest bytes.  The verifier derives the signer key id from
the supplied public key; key ids in the signature object are never trusted.
"""
from __future__ import annotations
import argparse,base64,hashlib,json
from pathlib import Path
from xavi_duo_fs import atomic_write
from xavi_duo_identity import HIGH_ASSURANCE_ALGORITHM,keygen,public_key_id,sign,verify
from xavi_duo_private_ops import custody_sign

SCHEMA='XAVI-DUO/RELEASE-SIGNATURE/v1'
DOMAIN=b'XAVI-DUO/RELEASE-SIGNATURE/v1\x00'
class ReleaseSignatureError(RuntimeError): pass

def canonical_manifest_bytes(path:Path|str)->bytes:
    try: obj=json.loads(Path(path).read_text(encoding='utf-8'))
    except Exception as exc: raise ReleaseSignatureError(f'invalid release manifest: {exc}') from exc
    if not isinstance(obj,dict): raise ReleaseSignatureError('release manifest must be a JSON object')
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')

def manifest_sha256(path:Path|str)->str:
    return 'sha256:'+hashlib.sha256(canonical_manifest_bytes(path)).hexdigest()

def signing_message(path:Path|str)->bytes:
    digest=hashlib.sha256(canonical_manifest_bytes(path)).digest()
    return DOMAIN+digest

def sign_manifest(private_key:Path|str,public_key:Path|str,manifest:Path|str,out:Path|str)->dict:
    key_id=public_key_id(public_key)
    msg=signing_message(manifest)
    sig,evidence=sign(private_key,msg,algorithm=HIGH_ASSURANCE_ALGORITHM)
    row={
      'schema':SCHEMA,
      'algorithm':HIGH_ASSURANCE_ALGORITHM,
      'manifest_sha256':manifest_sha256(manifest),
      'signer_key_id':key_id,
      'signature':base64.b64encode(sig).decode('ascii'),
      'signature_bytes':len(sig),
      'signature_sha256':'sha256:'+hashlib.sha256(sig).hexdigest(),
      'authority':False,
    }
    atomic_write(Path(out),(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode(),0o644)
    return {**row,'evidence':evidence}

def sign_manifest_custody(private_ref,public_key:Path|str,manifest:Path|str,out:Path|str,*,registry,high_assurance=True)->dict:
    key_id=public_key_id(public_key)
    msg=signing_message(manifest)
    sig,evidence=custody_sign(private_ref,msg,algorithm=HIGH_ASSURANCE_ALGORITHM,registry=registry,high_assurance=high_assurance)
    row={'schema':SCHEMA,'algorithm':HIGH_ASSURANCE_ALGORITHM,'manifest_sha256':manifest_sha256(manifest),'signer_key_id':key_id,'signature':base64.b64encode(sig).decode('ascii'),'signature_bytes':len(sig),'signature_sha256':'sha256:'+hashlib.sha256(sig).hexdigest(),'authority':False}
    atomic_write(Path(out),(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode(),0o644)
    return {**row,'evidence':evidence}

def verify_manifest(public_key:Path|str,manifest:Path|str,signature_file:Path|str)->dict:
    try: row=json.loads(Path(signature_file).read_text(encoding='utf-8'))
    except Exception as exc: raise ReleaseSignatureError(f'invalid signature object: {exc}') from exc
    required={'schema','algorithm','manifest_sha256','signer_key_id','signature','signature_bytes','signature_sha256','authority'}
    if not isinstance(row,dict) or set(row)!=required: raise ReleaseSignatureError('release signature schema fields mismatch')
    if row['schema']!=SCHEMA: raise ReleaseSignatureError('release signature schema mismatch')
    if row['algorithm']!=HIGH_ASSURANCE_ALGORITHM: raise ReleaseSignatureError('release signature algorithm is not high-assurance ML-DSA-87')
    if row['authority'] is not False: raise ReleaseSignatureError('release signature must not confer runtime authority')
    actual_key_id=public_key_id(public_key)
    if row['signer_key_id']!=actual_key_id: raise ReleaseSignatureError('release signer key id mismatch')
    actual_manifest=manifest_sha256(manifest)
    if row['manifest_sha256']!=actual_manifest: raise ReleaseSignatureError('release manifest digest mismatch')
    try: sig=base64.b64decode(row['signature'],validate=True)
    except Exception as exc: raise ReleaseSignatureError('invalid release signature encoding') from exc
    if len(sig)!=int(row['signature_bytes']): raise ReleaseSignatureError('release signature length mismatch')
    if row['signature_sha256']!='sha256:'+hashlib.sha256(sig).hexdigest(): raise ReleaseSignatureError('release signature digest mismatch')
    if not verify(public_key,signing_message(manifest),sig,algorithm=HIGH_ASSURANCE_ALGORITHM): raise ReleaseSignatureError('release signature verification failed')
    return {'status':'PASS','schema':SCHEMA,'algorithm':HIGH_ASSURANCE_ALGORITHM,'manifest_sha256':actual_manifest,'signer_key_id':actual_key_id,'signature_bytes':len(sig),'authority':False}

def main():
    a=argparse.ArgumentParser(prog='xavi-duo-release',description='Standalone XAVI-DUO release attestation')
    sub=a.add_subparsers(dest='command',required=True)
    k=sub.add_parser('keygen');k.add_argument('--private',required=True);k.add_argument('--public',required=True)
    s=sub.add_parser('sign');s.add_argument('--private',required=True);s.add_argument('--public',required=True);s.add_argument('--manifest',required=True);s.add_argument('--out',required=True)
    v=sub.add_parser('verify');v.add_argument('--public',required=True);v.add_argument('--manifest',required=True);v.add_argument('--signature',required=True)
    x=a.parse_args()
    if x.command=='keygen': row=keygen(x.private,x.public,algorithm=HIGH_ASSURANCE_ALGORITHM)
    elif x.command=='sign': row=sign_manifest(x.private,x.public,x.manifest,x.out)
    else: row=verify_manifest(x.public,x.manifest,x.signature)
    print(json.dumps(row,sort_keys=True))
if __name__=='__main__': main()
