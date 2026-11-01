import hashlib
from pathlib import Path
import pytest

from xavi_void.runtime.encrypted import FHECapabilities, FHEClientView, ReferenceFHEBackend
from xavi_void.runtime.remote_tfhe import (
    ProductionTFHEWorker,
    RemoteTFHEShakeRequest,
    decode_shake_response,
    encode_shake_request,
)
from xavi_void.runtime.shake_encrypted import (
    compile_encrypted_shake_program,
    decrypt_encrypted_shake_result,
    prepare_encrypted_shake_input,
)
from xavi_void.runtime.tfhe_split import (
    EvaluatorPolicyError,
    TFHEClientCapabilities,
    TFHEPortableClientBackend,
    assert_remote_safe_evaluator,
)


KEY_ID="sha3-512:"+"42"*64


class FakeClientCrypto:
    """Protocol fixture only; intentionally not cryptographic."""
    capabilities=TFHEClientCapabilities("tfhe","client",True,True,KEY_ID,True)
    def encrypt_bit(self,value):return b"\x01" if value else b"\x00"
    def decrypt_bit(self,data):
        if data not in {b"\x00",b"\x01"}:raise ValueError
        return data==b"\x01"
    def encrypt_word64(self,value):return int(value).to_bytes(8,"little")
    def decrypt_word64(self,data):return int.from_bytes(data,"little")
    def export_server_key(self):return b"fixture-server-key"
    def close(self):pass


class PolicyFixtureEvaluator(ReferenceFHEBackend):
    """Non-secure arithmetic fixture carrying production evaluator policy metadata."""
    def __init__(self):
        super().__init__()
        self.capabilities=FHECapabilities(
            "tfhe",True,role="evaluator",has_client_secret=False,key_id=KEY_ID,
            supports_bulk_registers=False,supports_keccak24=True,
        )
        self.backend_id=f"xavi-void-policy-fixture:{KEY_ID}"
    def keccak24_words(self,state):
        from xavi_void.crypto.keccak import keccak_f1600
        values=[self._word(x) for x in state];keccak_f1600(values)
        return tuple(self.trivial_word64(v) for v in values)


def test_dev4_production_worker_rejects_combined_or_noncryptographic_backend():
    with pytest.raises(EvaluatorPolicyError):
        ProductionTFHEWorker(ReferenceFHEBackend())


def test_dev4_remote_safe_policy_requires_evaluator_role_and_no_client_secret():
    backend=PolicyFixtureEvaluator()
    assert_remote_safe_evaluator(backend)
    backend.capabilities=FHECapabilities("tfhe",True,role="combined",has_client_secret=True,key_id=KEY_ID)
    with pytest.raises(EvaluatorPolicyError):assert_remote_safe_evaluator(backend)


def test_dev4_portable_client_to_evaluator_roundtrip_empty_message():
    client_backend=TFHEPortableClientBackend(FakeClientCrypto())
    client=FHEClientView(client_backend)
    encrypted_input=prepare_encrypted_shake_input(b"",client)
    encrypted_program=compile_encrypted_shake_program(client)
    request=RemoteTFHEShakeRequest(KEY_ID,encrypted_input,encrypted_program,False)
    encoded=encode_shake_request(request,client_backend)

    worker=ProductionTFHEWorker(PolicyFixtureEvaluator())
    response=worker.execute_shake(encoded)
    decoded=decode_shake_response(response,client_backend)
    assert decoded.key_id==KEY_ID
    digest=decrypt_encrypted_shake_result(decoded.result,client)
    assert digest==hashlib.shake_256(b"").digest(64)


def test_dev4_split_rust_evaluator_source_has_no_client_key_or_decrypt_call():
    source=(Path(__file__).resolve().parents[1]/"providers"/"tfhe-rs-split"/"src"/"bin"/"evaluator.rs").read_text()
    assert "ClientKey" not in source
    assert ".decrypt(" not in source
    assert '"role":"evaluator"' in source
    assert '"has_client_secret":false' in source


def test_dev4_split_client_source_owns_client_key_and_exports_only_server_key():
    source=(Path(__file__).resolve().parents[1]/"providers"/"tfhe-rs-split"/"src"/"bin"/"client.rs").read_text()
    assert "ClientKey" in source
    assert "CompressedServerKey" in source
    assert '"export_server_key"' in source
    assert '"role":"client"' in source
    assert '"has_client_secret":true' in source


def test_dev4_pq_transport_composes_with_split_worker_but_dev_provider_cannot_pass_production_acceptance():
    from xavi_void.runtime.dev4_acceptance import validate_dev4_split_worker
    from xavi_void.runtime.native_validation import ShakeVector
    from xavi_void.runtime.pq_transport import DevelopmentPQProviderNOTSECURE
    fake_client=FakeClientCrypto();evaluator=PolicyFixtureEvaluator()
    report=validate_dev4_split_worker(
        fake_client,evaluator,pq_provider=DevelopmentPQProviderNOTSECURE(),
        vectors=(ShakeVector("empty",b""),),run_oblivious_execution_ir=True,
    )
    assert report.transport_used is True
    assert report.vectors[0].specialized_match is True
    assert report.vectors[0].oblivious_match is True
    assert report.pq_production is False
    assert report.passed is False


def test_dev4_remote_request_rejects_wrong_evaluation_key_id():
    client_backend=TFHEPortableClientBackend(FakeClientCrypto());view=FHEClientView(client_backend)
    request=RemoteTFHEShakeRequest("wrong-key",prepare_encrypted_shake_input(b"abc",view),compile_encrypted_shake_program(view),False)
    worker=ProductionTFHEWorker(PolicyFixtureEvaluator())
    with pytest.raises(ValueError,match="key id"):
        worker.execute_shake(encode_shake_request(request,client_backend))


def test_dev4_worker_image_does_not_copy_client_binary_or_client_key():
    root=Path(__file__).resolve().parents[1]
    for name in ("Containerfile","Containerfile.cuda"):
        text=(root/"providers"/"tfhe-worker"/name).read_text()
        assert "xvoid-tfhe-client" not in text
        assert "client-key.bin" not in text
        assert "xvoid-tfhe-evaluator" in text
