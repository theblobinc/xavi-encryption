"""Rev 1.2-dev4 production split-worker acceptance harness."""
from __future__ import annotations
from dataclasses import asdict,dataclass
import hashlib
from pathlib import Path
from typing import Sequence

from xavi_void.crypto.shake import content_id
from .encrypted import FHEClientView
from .native_validation import ShakeVector,shake_validation_vectors
from .pq_transport import (
    PostQuantumProvider,client_handshake,make_kem_identity,make_transport_identity,
    open_transport_message,seal_transport_message,server_accept_handshake,
)
from .remote_tfhe import ProductionTFHEWorker,RemoteTFHEShakeRequest,decode_shake_response,encode_shake_request
from .shake_encrypted import compile_encrypted_shake_program,decrypt_encrypted_shake_result,prepare_encrypted_shake_input
from .tfhe_split import TFHEClientCryptoSidecar,TFHEEvaluatorSidecarBackend,TFHEPortableClientBackend

@dataclass(frozen=True,slots=True)
class Dev4VectorEvidence:
    name:str
    input_bytes:int
    specialized_match:bool
    oblivious_match:bool|None
    specialized_request_bytes:int
    specialized_response_bytes:int
    oblivious_request_bytes:int|None
    oblivious_response_bytes:int|None
    specialized_ns:int
    oblivious_ns:int|None
    specialized_metrics:dict[str,object]
    oblivious_metrics:dict[str,object]|None

@dataclass(frozen=True,slots=True)
class Dev4AcceptanceReport:
    schema:str
    key_id:str
    device:str
    evaluator_has_client_secret:bool
    split_key_match:bool
    evaluator_source_secret_free:bool
    pq_provider:str|None
    pq_production:bool
    pq_interop:dict[str,object]|None
    full_oblivious_required:bool
    transport_used:bool
    vectors:tuple[Dev4VectorEvidence,...]
    transcript_commitment:str
    @property
    def passed(self)->bool:
        return bool(
            self.split_key_match and not self.evaluator_has_client_secret and self.evaluator_source_secret_free
            and self.pq_production and self.transport_used and self.vectors
            and all(v.specialized_match and ((v.oblivious_match is True) if self.full_oblivious_required else True) for v in self.vectors)
        )
    def canonical(self):
        value=asdict(self);value["passed"]=self.passed;return value


def _source_secret_free()->bool:
    source=(Path(__file__).resolve().parents[3]/"providers"/"tfhe-rs-split"/"src"/"bin"/"evaluator.rs").read_text()
    return "ClientKey" not in source and ".decrypt(" not in source


def validate_dev4_split_worker(
    client:TFHEClientCryptoSidecar,
    evaluator:TFHEEvaluatorSidecarBackend,
    *,
    pq_provider:PostQuantumProvider|None,
    vectors:Sequence[ShakeVector]|None=None,
    run_oblivious_execution_ir:bool=True,
)->Dev4AcceptanceReport:
    client_backend=TFHEPortableClientBackend(client);view=FHEClientView(client_backend);worker=ProductionTFHEWorker(evaluator)
    chosen=tuple(vectors or shake_validation_vectors(random_cases=2));rows=[];transcript=[]
    pq_interop=None;transport_used=False;pq_name=None;pq_production=False
    if pq_provider is not None:
        pq_name=pq_provider.capabilities.provider;pq_production=pq_provider.capabilities.production_cryptographic
        if hasattr(pq_provider,"interoperability_selftest"):pq_interop=getattr(pq_provider,"interoperability_selftest")()
        server_kem=make_kem_identity(pq_provider);client_identity=make_transport_identity(pq_provider);server_identity=make_transport_identity(pq_provider)
        offer,client_keys=client_handshake(pq_provider,server_kem.public_key,client_identity,"dev4-acceptance")
        server_keys=server_accept_handshake(pq_provider,server_kem,offer)
        if client_keys!=server_keys:raise ValueError("PQ transport handshake derived different client/server keys")
        transport_used=True
    sequence=0
    for vector in chosen:
        encrypted_input=prepare_encrypted_shake_input(vector.message,view)
        encrypted_program=compile_encrypted_shake_program(view) if run_oblivious_execution_ir else None
        mode_results={}
        for specialized in ((False,True) if run_oblivious_execution_ir else (True,)):
            request_program=None if specialized else encrypted_program
            request=encode_shake_request(RemoteTFHEShakeRequest(worker.key_id,encrypted_input,request_program,specialized),client_backend)
            sequence+=1
            if pq_provider is not None:
                sealed=seal_transport_message(pq_provider,client_keys,client_identity,"client-to-server",sequence,request,authority_boundary=True)
                request_on_worker=open_transport_message(pq_provider,server_keys,client_identity.signature_public_key,sealed,require_authority_signature=True)
            else:request_on_worker=request
            response_on_worker=worker.execute_shake(request_on_worker)
            if pq_provider is not None:
                sealed_response=seal_transport_message(pq_provider,server_keys,server_identity,"server-to-client",sequence,response_on_worker,authority_boundary=True)
                response=open_transport_message(pq_provider,client_keys,server_identity.signature_public_key,sealed_response,require_authority_signature=True)
            else:response=response_on_worker
            decoded=decode_shake_response(response,client_backend);digest=decrypt_encrypted_shake_result(decoded.result,view)
            timing=decoded.result.timing
            mode_results[specialized]=(digest==hashlib.shake_256(vector.message).digest(64),len(request),len(response),0 if timing is None else timing.full_evaluation_ns,{} if timing is None else timing.provider_metrics)
            transcript.extend((content_id("XAVI-VOID/DEV4-REQUEST/v1",request).encode(),content_id("XAVI-VOID/DEV4-RESPONSE/v1",response).encode()))
        spec=mode_results[True];obl=mode_results.get(False)
        rows.append(Dev4VectorEvidence(vector.name,len(vector.message),spec[0],None if obl is None else obl[0],spec[1],spec[2],None if obl is None else obl[1],None if obl is None else obl[2],spec[3],None if obl is None else obl[3],dict(spec[4]),None if obl is None else dict(obl[4])))
    transcript_commitment=content_id("XAVI-VOID/DEV4-ACCEPTANCE-TRANSCRIPT/v1",*transcript)
    return Dev4AcceptanceReport(
        "xavi-void-rev-1.2-dev4-acceptance-v1",worker.key_id,evaluator.capabilities.device,evaluator.capabilities.has_client_secret,
        client.capabilities.key_id==worker.key_id,_source_secret_free(),pq_name,pq_production,pq_interop,run_oblivious_execution_ir,transport_used,tuple(rows),transcript_commitment,
    )
