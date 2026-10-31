"""Post-quantum authenticated transport boundary for xavi-void.

Production operation requires a provider that implements the exact suite:
ML-KEM-1024, ML-DSA-87, KMAC256, AES-256-GCM-SIV.  This module intentionally
contains no home-grown ML-KEM/ML-DSA implementation.  A strict sidecar adapter
allows validated providers to supply those primitives without contaminating the
execution runtime.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import subprocess
from typing import Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id, framed_shake256_512

SUITE_ID="xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv"

class PQProviderUnavailable(RuntimeError): pass

@dataclass(frozen=True,slots=True)
class PQCapabilities:
    provider:str
    production_cryptographic:bool
    kem:str
    signature:str
    kdf:str
    aead:str

class PostQuantumProvider(ABC):
    capabilities:PQCapabilities
    @abstractmethod
    def kem_keypair(self)->tuple[bytes,bytes]: ...
    @abstractmethod
    def kem_encapsulate(self,public_key:bytes)->tuple[bytes,bytes]: ...
    @abstractmethod
    def kem_decapsulate(self,private_key:bytes,ciphertext:bytes)->bytes: ...
    @abstractmethod
    def signature_keypair(self)->tuple[bytes,bytes]: ...
    @abstractmethod
    def sign(self,private_key:bytes,message:bytes)->bytes: ...
    @abstractmethod
    def verify(self,public_key:bytes,message:bytes,signature:bytes)->bool: ...
    @abstractmethod
    def kmac256(self,key:bytes,customization:bytes,data:bytes,output_bytes:int=32)->bytes: ...
    @abstractmethod
    def seal(self,key:bytes,nonce:bytes,plaintext:bytes,aad:bytes)->bytes: ...
    @abstractmethod
    def open(self,key:bytes,nonce:bytes,ciphertext:bytes,aad:bytes)->bytes: ...

class SidecarPQProvider(PostQuantumProvider):
    """Strict external adapter for a validated PQ crypto provider."""
    def __init__(self,command:Sequence[str])->None:
        if not command: raise ValueError("PQ sidecar command required")
        try:self._proc=subprocess.Popen(list(command),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        except OSError as e: raise PQProviderUnavailable(f"unable to launch PQ sidecar: {e}") from e
        result=self._call("capabilities")
        caps=PQCapabilities(
            str(result.get("provider","")),bool(result.get("production_cryptographic")),
            str(result.get("kem","")),str(result.get("signature","")),str(result.get("kdf","")),str(result.get("aead","")),
        )
        expected=("ML-KEM-1024","ML-DSA-87","KMAC256","AES-256-GCM-SIV")
        actual=(caps.kem,caps.signature,caps.kdf,caps.aead)
        if not caps.production_cryptographic or actual != expected:
            self.close(); raise PQProviderUnavailable(f"PQ sidecar does not implement required suite: {actual!r}")
        self.capabilities=caps
    def close(self):
        if getattr(self,"_proc",None) is not None and self._proc.poll() is None:
            try:self._call("close")
            except Exception:pass
            self._proc.terminate()
    def _call(self,op:str,**kwargs):
        if self._proc.poll() is not None: raise PQProviderUnavailable("PQ sidecar terminated")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        import base64
        def enc(v): return base64.b64encode(v).decode() if isinstance(v,(bytes,bytearray)) else v
        request={"op":op,**{k:enc(v) for k,v in kwargs.items()}}
        self._proc.stdin.write(json.dumps(request,separators=(",",":"))+"\n");self._proc.stdin.flush()
        line=self._proc.stdout.readline()
        if not line: raise PQProviderUnavailable("PQ sidecar returned no response")
        response=json.loads(line)
        if not response.get("ok",False): raise RuntimeError(str(response.get("error","PQ sidecar failure")))
        return response.get("result",{})
    @staticmethod
    def _b64(value:str)->bytes:
        import base64; return base64.b64decode(value)
    def kem_keypair(self):
        r=self._call("kem_keypair");return self._b64(r["public_key"]),self._b64(r["private_key"])
    def kem_encapsulate(self,public_key):
        r=self._call("kem_encapsulate",public_key=public_key);return self._b64(r["ciphertext"]),self._b64(r["shared_secret"])
    def kem_decapsulate(self,private_key,ciphertext): return self._b64(self._call("kem_decapsulate",private_key=private_key,ciphertext=ciphertext)["shared_secret"])
    def signature_keypair(self):
        r=self._call("signature_keypair");return self._b64(r["public_key"]),self._b64(r["private_key"])
    def sign(self,private_key,message): return self._b64(self._call("sign",private_key=private_key,message=message)["signature"])
    def verify(self,public_key,message,signature): return bool(self._call("verify",public_key=public_key,message=message,signature=signature)["valid"])
    def kmac256(self,key,customization,data,output_bytes=32): return self._b64(self._call("kmac256",key=key,customization=customization,data=data,output_bytes=output_bytes)["output"])
    def seal(self,key,nonce,plaintext,aad): return self._b64(self._call("seal",key=key,nonce=nonce,plaintext=plaintext,aad=aad)["ciphertext"])
    def open(self,key,nonce,ciphertext,aad): return self._b64(self._call("open",key=key,nonce=nonce,ciphertext=ciphertext,aad=aad)["plaintext"])
    def interoperability_selftest(self)->dict[str,object]:
        result=dict(self._call("selftest"))
        required=("kem_roundtrip","signature_roundtrip","kmac256","aes256gcmsiv")
        if any(k not in result for k in required): raise RuntimeError("PQ sidecar returned incomplete interoperability selftest")
        return result

class DevelopmentPQProviderNOTSECURE(PostQuantumProvider):
    """Protocol-only CI provider. NOT post-quantum and NOT for production."""
    capabilities=PQCapabilities("development-NOT-SECURE",False,"SIMULATED-KEM","HMAC-SHAKE","SHAKE-KDF","AES-256-GCM-SIV")
    def kem_keypair(self):
        private=os.urandom(32);public=hashlib.sha3_256(private).digest();return public,private
    def kem_encapsulate(self,public_key):
        nonce=os.urandom(32);secret=framed_shake256_512("XAVI-VOID/DEV-KEM/v1",(public_key,nonce))[:32];return nonce,secret
    def kem_decapsulate(self,private_key,ciphertext):
        public=hashlib.sha3_256(private_key).digest();return framed_shake256_512("XAVI-VOID/DEV-KEM/v1",(public,ciphertext))[:32]
    def signature_keypair(self):
        key=os.urandom(32);return key,key
    def sign(self,private_key,message): return hmac.new(private_key,message,hashlib.sha3_512).digest()
    def verify(self,public_key,message,signature): return hmac.compare_digest(signature,hmac.new(public_key,message,hashlib.sha3_512).digest())
    def kmac256(self,key,customization,data,output_bytes=32): return framed_shake256_512("XAVI-VOID/DEV-KDF/v1",(key,customization,data))[:output_bytes]
    def seal(self,key,nonce,plaintext,aad):
        try: from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
        except ImportError as e: raise PQProviderUnavailable("development transport AEAD requires optional cryptography package") from e
        return AESGCMSIV(key[:32]).encrypt(nonce,plaintext,aad)
    def open(self,key,nonce,ciphertext,aad):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
            from cryptography.exceptions import InvalidTag
        except ImportError as e:
            raise PQProviderUnavailable("development transport AEAD requires optional cryptography package") from e
        try:
            return AESGCMSIV(key[:32]).decrypt(nonce,ciphertext,aad)
        except InvalidTag as e:
            raise ValueError("transport AEAD authentication failed") from e

@dataclass(frozen=True,slots=True)
class TransportIdentity:
    identity_id:str
    signature_public_key:bytes
    signature_private_key:bytes

@dataclass(frozen=True,slots=True)
class KEMIdentity:
    public_key:bytes
    private_key:bytes

@dataclass(frozen=True,slots=True)
class TransportSessionKeys:
    session_id:str
    client_to_server:bytes
    server_to_client:bytes
    transcript_key:bytes

@dataclass(frozen=True,slots=True)
class HandshakeOffer:
    session_id:str
    kem_ciphertext:bytes
    client_signature_public_key:bytes
    signature:bytes

@dataclass(frozen=True,slots=True)
class SealedTransportMessage:
    session_id:str
    direction:str
    sequence:int
    nonce:bytes
    ciphertext:bytes
    authority_signature:bytes | None = None


def make_transport_identity(provider:PostQuantumProvider)->TransportIdentity:
    public,private=provider.signature_keypair()
    identity_id=content_id("XAVI-VOID/TRANSPORT-IDENTITY/v1",public)
    return TransportIdentity(identity_id,public,private)

def make_kem_identity(provider:PostQuantumProvider)->KEMIdentity:
    public,private=provider.kem_keypair();return KEMIdentity(public,private)

def client_handshake(provider:PostQuantumProvider,server_kem_public:bytes,client_identity:TransportIdentity,session_id:str)->tuple[HandshakeOffer,TransportSessionKeys]:
    kem_ct,shared=provider.kem_encapsulate(server_kem_public)
    transcript=canonical_bytes({"suite":SUITE_ID,"session_id":session_id,"kem_ciphertext":kem_ct.hex(),"client_identity":client_identity.identity_id})
    signature=provider.sign(client_identity.signature_private_key,transcript)
    master=provider.kmac256(shared,b"XAVI-VOID/TRANSPORT-MASTER/v1",transcript,96)
    keys=TransportSessionKeys(session_id,master[:32],master[32:64],master[64:96])
    return HandshakeOffer(session_id,kem_ct,client_identity.signature_public_key,signature),keys

def server_accept_handshake(provider:PostQuantumProvider,server_kem:KEMIdentity,offer:HandshakeOffer)->TransportSessionKeys:
    client_id=content_id("XAVI-VOID/TRANSPORT-IDENTITY/v1",offer.client_signature_public_key)
    transcript=canonical_bytes({"suite":SUITE_ID,"session_id":offer.session_id,"kem_ciphertext":offer.kem_ciphertext.hex(),"client_identity":client_id})
    if not provider.verify(offer.client_signature_public_key,transcript,offer.signature): raise ValueError("invalid transport handshake signature")
    shared=provider.kem_decapsulate(server_kem.private_key,offer.kem_ciphertext)
    master=provider.kmac256(shared,b"XAVI-VOID/TRANSPORT-MASTER/v1",transcript,96)
    return TransportSessionKeys(offer.session_id,master[:32],master[32:64],master[64:96])

def seal_transport_message(provider:PostQuantumProvider,keys:TransportSessionKeys,sender:TransportIdentity,direction:str,sequence:int,plaintext:bytes,*,authority_boundary:bool=False)->SealedTransportMessage:
    if direction not in {"client-to-server","server-to-client"}: raise ValueError("unknown transport direction")
    if sequence<1: raise ValueError("transport sequence is one-origin")
    key=keys.client_to_server if direction=="client-to-server" else keys.server_to_client
    nonce=provider.kmac256(keys.transcript_key,b"XAVI-VOID/TRANSPORT-NONCE/v1",direction.encode()+sequence.to_bytes(8,"big"),12)
    aad=canonical_bytes({"suite":SUITE_ID,"session_id":keys.session_id,"direction":direction,"sequence":sequence})
    ciphertext=provider.seal(key,nonce,plaintext,aad)
    sig=provider.sign(sender.signature_private_key,aad+ciphertext) if authority_boundary else None
    return SealedTransportMessage(keys.session_id,direction,sequence,nonce,ciphertext,sig)

def open_transport_message(provider:PostQuantumProvider,keys:TransportSessionKeys,sender_public_key:bytes,envelope:SealedTransportMessage,*,require_authority_signature:bool=False)->bytes:
    if envelope.session_id != keys.session_id: raise ValueError("transport session mismatch")
    key=keys.client_to_server if envelope.direction=="client-to-server" else keys.server_to_client
    aad=canonical_bytes({"suite":SUITE_ID,"session_id":keys.session_id,"direction":envelope.direction,"sequence":envelope.sequence})
    if require_authority_signature and envelope.authority_signature is None:
        raise ValueError("authority-boundary transport message requires signature")
    if envelope.authority_signature is not None and not provider.verify(sender_public_key,aad+envelope.ciphertext,envelope.authority_signature):
        raise ValueError("invalid authority-boundary transport signature")
    expected_nonce=provider.kmac256(keys.transcript_key,b"XAVI-VOID/TRANSPORT-NONCE/v1",envelope.direction.encode()+envelope.sequence.to_bytes(8,"big"),12)
    if expected_nonce != envelope.nonce: raise ValueError("transport nonce mismatch")
    return provider.open(key,envelope.nonce,envelope.ciphertext,aad)

def seal_remote_protocol_message(provider:PostQuantumProvider,keys:TransportSessionKeys,sender:TransportIdentity,direction:str,message)->SealedTransportMessage:
    """Seal a canonical ``RemoteMessage`` without coupling transport to computation identity."""
    from .remote_protocol import RemoteMessage
    if not isinstance(message,RemoteMessage): raise TypeError("message must be RemoteMessage")
    return seal_transport_message(provider,keys,sender,direction,message.sequence.value,message.encode())

def open_remote_protocol_message(provider:PostQuantumProvider,keys:TransportSessionKeys,sender_public_key:bytes,envelope:SealedTransportMessage):
    from .remote_protocol import RemoteMessage
    return RemoteMessage.decode(open_transport_message(provider,keys,sender_public_key,envelope))
