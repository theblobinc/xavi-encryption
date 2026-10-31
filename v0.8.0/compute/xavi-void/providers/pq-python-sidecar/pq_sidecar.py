#!/usr/bin/env python3
"""Production PQ transport sidecar for xavi-void Rev 1.2-dev2.

The process is intentionally isolated from the xavi-void semantic/runtime layers.
It uses liboqs through liboqs-python for ML-KEM-1024 and ML-DSA-87,
PyCryptodome KMAC256, and cryptography AES-256-GCM-SIV.
"""
from __future__ import annotations

import base64
import contextlib
import json
import sys

# The JSON-lines protocol owns stdout.  liboqs-python emits an import-time
# diagnostic on some builds, so keep all third-party startup chatter on stderr.
with contextlib.redirect_stdout(sys.stderr):
    import oqs
from Crypto.Hash import KMAC256
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

KEM="ML-KEM-1024"
SIG="ML-DSA-87"
MAX_BLOB=64*1024*1024


def b64e(value:bytes)->str:
    return base64.b64encode(value).decode("ascii")


def b64d(request:dict,key:str)->bytes:
    try: value=base64.b64decode(request[key],validate=True)
    except Exception as exc: raise ValueError(f"invalid base64 field {key}") from exc
    if len(value)>MAX_BLOB: raise ValueError(f"field {key} exceeds size limit")
    return value


def kem_keypair():
    with oqs.KeyEncapsulation(KEM) as kem:
        public=kem.generate_keypair(); private=kem.export_secret_key()
    return public,private


def kem_encapsulate(public:bytes):
    with oqs.KeyEncapsulation(KEM) as kem:
        ciphertext,secret=kem.encap_secret(public)
    return ciphertext,secret


def kem_decapsulate(private:bytes,ciphertext:bytes):
    with oqs.KeyEncapsulation(KEM,secret_key=private) as kem:
        return kem.decap_secret(ciphertext)


def sig_keypair():
    with oqs.Signature(SIG) as sig:
        public=sig.generate_keypair(); private=sig.export_secret_key()
    return public,private


def sign(private:bytes,message:bytes):
    with oqs.Signature(SIG,secret_key=private) as sig:
        return sig.sign(message)


def verify(public:bytes,message:bytes,signature:bytes):
    with oqs.Signature(SIG) as sig:
        return bool(sig.verify(message,signature,public))


def kmac(key:bytes,custom:bytes,data:bytes,size:int)->bytes:
    if not 8<=size<=4096: raise ValueError("KMAC output length outside supported range")
    h=KMAC256.new(key=key,custom=custom,mac_len=size); h.update(data); return h.digest()


def execute(r:dict):
    op=r.get("op")
    if op=="capabilities":
        return {"provider":"liboqs-python","production_cryptographic":True,"kem":KEM,"signature":SIG,"kdf":"KMAC256","aead":"AES-256-GCM-SIV"}
    if op=="kem_keypair":
        pk,sk=kem_keypair();return {"public_key":b64e(pk),"private_key":b64e(sk)}
    if op=="kem_encapsulate":
        ct,ss=kem_encapsulate(b64d(r,"public_key"));return {"ciphertext":b64e(ct),"shared_secret":b64e(ss)}
    if op=="kem_decapsulate":
        ss=kem_decapsulate(b64d(r,"private_key"),b64d(r,"ciphertext"));return {"shared_secret":b64e(ss)}
    if op=="signature_keypair":
        pk,sk=sig_keypair();return {"public_key":b64e(pk),"private_key":b64e(sk)}
    if op=="sign": return {"signature":b64e(sign(b64d(r,"private_key"),b64d(r,"message")))}
    if op=="verify": return {"valid":verify(b64d(r,"public_key"),b64d(r,"message"),b64d(r,"signature"))}
    if op=="kmac256":
        return {"output":b64e(kmac(b64d(r,"key"),b64d(r,"customization"),b64d(r,"data"),int(r.get("output_bytes",32))))}
    if op=="seal":
        key=b64d(r,"key");nonce=b64d(r,"nonce")
        if len(key)!=32: raise ValueError("AES-256-GCM-SIV key must be 32 bytes")
        if len(nonce)!=12: raise ValueError("AES-GCM-SIV nonce must be 12 bytes")
        ct=AESGCMSIV(key).encrypt(nonce,b64d(r,"plaintext"),b64d(r,"aad"));return {"ciphertext":b64e(ct)}
    if op=="open":
        key=b64d(r,"key");nonce=b64d(r,"nonce")
        if len(key)!=32 or len(nonce)!=12: raise ValueError("invalid AES-256-GCM-SIV key/nonce size")
        try: pt=AESGCMSIV(key).decrypt(nonce,b64d(r,"ciphertext"),b64d(r,"aad"))
        except InvalidTag as exc: raise ValueError("AEAD authentication failed") from exc
        return {"plaintext":b64e(pt)}
    if op=="selftest":
        kpk,ksk=kem_keypair();ct,a=kem_encapsulate(kpk);b=kem_decapsulate(ksk,ct)
        spk,ssk=sig_keypair();msg=b"xavi-void-pq-selftest";signature=sign(ssk,msg)
        mac=kmac(bytes(range(32)),b"XAVI-VOID/KMAC-INTEROP/v1",msg,64)
        key=bytes(range(32));nonce=bytes(range(12));aad=b"aad";sealed=AESGCMSIV(key).encrypt(nonce,msg,aad)
        import hashlib
        return {
            "kem_roundtrip":a==b,"signature_roundtrip":verify(spk,msg,signature),
            "kmac256":mac.hex(),"aes256gcmsiv":sealed.hex(),
            "kem_public_key_bytes":len(kpk),"kem_secret_key_bytes":len(ksk),
            "kem_ciphertext_bytes":len(ct),"kem_shared_secret_bytes":len(a),
            "signature_public_key_bytes":len(spk),"signature_secret_key_bytes":len(ssk),
            "signature_bytes":len(signature),
            "kem_transcript_sha3_512":hashlib.sha3_512(kpk+ct+a).hexdigest(),
            "signature_transcript_sha3_512":hashlib.sha3_512(spk+msg+signature).hexdigest(),
        }
    if op=="close": return {"closed":True}
    raise ValueError(f"unknown op {op}")


def main():
    for line in sys.stdin:
        try:
            r=json.loads(line); result=execute(r); response={"ok":True,"result":result}
        except Exception as exc:
            response={"ok":False,"error":str(exc)}
        print(json.dumps(response,separators=(",",":")),flush=True)
        if isinstance(locals().get("r"),dict) and r.get("op")=="close": break

if __name__=="__main__": main()
