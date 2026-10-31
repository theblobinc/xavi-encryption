import sys
from pathlib import Path
import pytest

from xavi_void.runtime.encrypted import BackendUnavailable, SidecarFHEBackend, TFHESidecarBackend

SCRIPT=Path(__file__).resolve().parents[1]/"providers"/"reference_fhe_sidecar.py"

def test_reference_sidecar_exercises_provider_protocol_but_is_not_cryptographic():
    b=SidecarFHEBackend([sys.executable,str(SCRIPT)],expected_provider="reference",require_cryptographic=False)
    try:
        a=b.encrypt_bit(True); c=b.encrypt_bit(False)
        assert b.decrypt_bit(b.bit_xor(a,c)) is True
        x=b.encrypt_word64(0x8000000000000001)
        assert b.decrypt_word64(b.word_rotl_public(x,1))==3
        exported=b.export_word64(x); imported=b.import_word64(exported)
        assert b.decrypt_word64(imported)==0x8000000000000001
        assert b.capabilities.cryptographic is False
        assert b.capabilities.supports_resident_sessions is True
        before=b.resident_stats()["resident_objects"]
        temp=b.encrypt_word64(99)
        assert b.resident_stats()["resident_objects"]==before+1
        assert b.release_ciphertexts([temp])==1
        assert b.resident_stats()["resident_objects"]==before
    finally:b.close()

def test_production_tfhe_adapter_rejects_noncryptographic_sidecar():
    with pytest.raises(BackendUnavailable):
        TFHESidecarBackend([sys.executable,str(SCRIPT)])
