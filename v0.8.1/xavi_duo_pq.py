#!/usr/bin/env python3
"""XDE2-PQ2: ML-KEM-1024 recipient envelope + XDE2 authenticated DUO payload."""
from __future__ import annotations
import base64, hashlib, json, os
from pathlib import Path
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mlkem_provider import DEFAULT_ALGORITHM, KEM_CIPHERTEXT_BYTES, encapsulate, decapsulate, public_key_id_from_private
from xavi_duo_private_ops import custody_decapsulate
from xavi_duo_crypto import encrypt_bytes, decrypt_bytes, MAX_AAD, MAX_FRAME_BYTES, MAX_PLAINTEXT, MAX_PAD_TO
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'vendor'))
import duo_core as duo

SCHEMA='XAVI-DUO/XDE2-PQ2/v1'
KEM_CT_BYTES=KEM_CIPHERTEXT_BYTES[DEFAULT_ALGORITHM]
MAX_KEM_DUO_CHARS=8192
MAX_ENVELOPE_BYTES=MAX_FRAME_BYTES+MAX_KEM_DUO_CHARS+65536
INFO=b'XAVI-DUO/XDE2-PQ2/ML-KEM-1024/master/v1'

def _b64e(b:bytes)->str:return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')
def _b64d(s:str)->bytes:return base64.urlsafe_b64decode(s+'='*(-len(s)%4))
def _duo_byte(n:int)->str:
    if not 0<=n<=255: raise ValueError('byte out of range')
    return duo.duo_count(n+1)

def _parse_duo_byte(s:str)->int:
    if not isinstance(s,str) or not 1<=len(s)<=3: raise ValueError('invalid DUO byte glyph')
    try: n=duo.parse_duo_count(s)-1
    except Exception as exc: raise ValueError('invalid DUO byte glyph') from exc
    if not 0<=n<=255: raise ValueError('DUO byte outside range')
    if _duo_byte(n)!=s: raise ValueError('noncanonical DUO byte glyph')
    return n

def duo_bytes_encode(data:bytes)->str:return '.'.join(_duo_byte(b) for b in data)
def duo_bytes_decode(text:str,expected_len:int|None=None)->bytes:
    if not isinstance(text,str) or len(text)>MAX_KEM_DUO_CHARS: raise ValueError('DUO byte string exceeds limit')
    parts=text.split('.') if text else []
    if expected_len is not None and len(parts)!=expected_len: raise ValueError('unexpected DUO byte cell count')
    if any(len(x)>3 for x in parts): raise ValueError('DUO byte glyph exceeds length limit')
    out=bytes(_parse_duo_byte(x) for x in parts)
    if expected_len is not None and len(out)!=expected_len: raise ValueError('unexpected decoded byte length')
    return out

def public_key_id(public_path:Path|str)->str:return 'sha256:'+hashlib.sha256(Path(public_path).read_bytes()).hexdigest()
def _master(shared:bytes,ct:bytes,kid:str)->bytes:
    salt=hashlib.sha256(ct).digest()
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=INFO+b'|'+kid.encode('ascii')).derive(shared)
def _bound_aad(kid:str,ct:bytes,user_aad:bytes)->bytes:
    meta=json.dumps({'schema':SCHEMA,'algorithm':DEFAULT_ALGORITHM,'recipient_key_id':kid,'kem_ciphertext_sha256':hashlib.sha256(ct).hexdigest()},sort_keys=True,separators=(',',':')).encode()
    return meta+b'\x00'+user_aad

def encrypt_for(public_path:Path|str,plaintext:bytes,*,aad:bytes=b'',pad_to:int=0)->tuple[dict,dict]:
    if len(aad)>MAX_AAD: raise ValueError('AAD exceeds production limit')
    kid=public_key_id(public_path); ct,shared,evidence=encapsulate(public_path)
    if len(ct)!=KEM_CT_BYTES: raise ValueError('unexpected ML-KEM ciphertext length')
    master=_master(shared,ct,kid); frame=encrypt_bytes(master,plaintext,aad=_bound_aad(kid,ct,aad),nonce=os.urandom(12),pad_to=pad_to)
    env={'schema':SCHEMA,'algorithm':DEFAULT_ALGORITHM,'recipient_key_id':kid,'kem_ciphertext_duo':duo_bytes_encode(ct),'xde2_frame':frame}
    witness={'schema':'XAVI-DUO/XDE2-PQ2-WITNESS/v1','operation':'encrypt','provider':evidence,'envelope_sha256':hashlib.sha256(json.dumps(env,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'authority':False}
    return env,witness

def decrypt_for(private_path:Path|str,envelope:dict,*,aad:bytes=b'')->tuple[bytes,dict]:
    if len(aad)>MAX_AAD: raise ValueError('AAD exceeds production limit')
    if envelope.get('schema')!=SCHEMA or envelope.get('algorithm')!=DEFAULT_ALGORITHM:raise ValueError('unsupported PQ envelope')
    if set(envelope)!={'schema','algorithm','recipient_key_id','kem_ciphertext_duo','xde2_frame'}: raise ValueError('noncanonical PQ envelope fields')
    if not isinstance(envelope.get('xde2_frame'),str) or len(envelope['xde2_frame'].encode())>MAX_FRAME_BYTES: raise ValueError('PQ XDE frame exceeds production size limit')
    ct=duo_bytes_decode(envelope['kem_ciphertext_duo'],KEM_CT_BYTES)
    kid=public_key_id_from_private(private_path)
    if str(envelope.get('recipient_key_id'))!=kid: raise ValueError('recipient key id does not match local private key')
    shared,evidence=decapsulate(private_path,ct); master=_master(shared,ct,kid)
    plain=decrypt_bytes(master,envelope['xde2_frame'],aad=_bound_aad(kid,ct,aad))
    witness={'schema':'XAVI-DUO/XDE2-PQ2-WITNESS/v1','operation':'decrypt','provider':evidence,'envelope_sha256':hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'authority':False}
    return plain,witness


def decrypt_for_custody(private_ref,public_path,envelope:dict,*,aad:bytes=b'',registry=None,high_assurance=False)->tuple[bytes,dict]:
    if len(aad)>MAX_AAD: raise ValueError('AAD exceeds production limit')
    if envelope.get('schema')!=SCHEMA or envelope.get('algorithm')!=DEFAULT_ALGORITHM: raise ValueError('unsupported PQ envelope')
    if set(envelope)!={'schema','algorithm','recipient_key_id','kem_ciphertext_duo','xde2_frame'}: raise ValueError('noncanonical PQ envelope fields')
    if not isinstance(envelope.get('xde2_frame'),str) or len(envelope['xde2_frame'].encode())>MAX_FRAME_BYTES: raise ValueError('PQ XDE frame exceeds production size limit')
    ct=duo_bytes_decode(envelope['kem_ciphertext_duo'],KEM_CT_BYTES)
    kid=public_key_id(public_path)
    if str(envelope.get('recipient_key_id'))!=kid: raise ValueError('recipient key id does not match trusted transport public key')
    shared,evidence=custody_decapsulate(private_ref,ct,algorithm=DEFAULT_ALGORITHM,registry=registry,high_assurance=high_assurance)
    master=_master(shared,ct,kid)
    plain=decrypt_bytes(master,envelope['xde2_frame'],aad=_bound_aad(kid,ct,aad))
    witness={'schema':'XAVI-DUO/XDE2-PQ2-WITNESS/v1','operation':'decrypt','provider':evidence,'envelope_sha256':hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'custody_ref':getattr(private_ref,'raw',str(private_ref)),'authority':False}
    return plain,witness
