from __future__ import annotations

from dataclasses import replace

import pytest

from xavi_void.math.types import Ordinal
from xavi_void.runtime.pq_transport import DevelopmentPQProviderNOTSECURE, make_transport_identity
from xavi_void.runtime.receipt import ExecutionChronology
from xavi_void.runtime.remote_client import RemoteWorkerIdentity
from xavi_void.runtime.remote_evidence import RemoteExecutionEvidenceBuilder
from xavi_void.runtime.remote_receipt import (
    receipt_signing_key_id,
    sign_remote_execution_receipt,
    verify_remote_execution_receipt,
)
from xavi_void.witness.domain import AuthorityDomain


def _domain() -> AuthorityDomain:
    return AuthorityDomain(
        "xavi://authority/sandbox/remote-evidence",
        "sandbox-test-only",
        "pytest",
        False,
        "registry-remote-evidence",
    )


def _worker(carrier: str = "xvoid:shake256-512:ssh-carrier-a") -> RemoteWorkerIdentity:
    return RemoteWorkerIdentity(
        role="remote-worker",
        provider="tfhe",
        key_id="sha3-512:fhe-evaluation-key-a",
        device="cpu",
        protocol_snapshot="v1",
        transport_commitment=carrier,
    )


def _builder(worker: RemoteWorkerIdentity | None = None):
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    builder = RemoteExecutionEvidenceBuilder(
        worker=worker or _worker(),
        evaluator_identity_id=identity.identity_id,
        evaluator_key_id=receipt_signing_key_id(identity.signature_public_key),
        provider_build_commitment="xvoid:shake256-512:provider-build-a",
        execution_mode="ssh-tfhe-encrypted",
        authority_domain=_domain(),
    )
    return provider, identity, builder


def _build(builder: RemoteExecutionEvidenceBuilder, *, previous=None, chronology=1, state="state-a"):
    return builder.build(
        semantic_program_id="semantic-shake",
        encrypted_representation_commitment="xvoid:shake256-512:encrypted-program",
        session_id="session-a",
        input_commitment="xvoid:shake256-512:input",
        encrypted_result_commitment=f"xvoid:shake256-512:result-{chronology}",
        decrypted_output_commitment="xvoid:shake256-512:plaintext-result",
        session_state_commitment=f"xvoid:shake256-512:{state}",
        transport_transcript_commitment=f"xvoid:shake256-512:transcript-{chronology}",
        chronology=ExecutionChronology(Ordinal(chronology), f"2026-09-15T21:20:0{chronology}+00:00"),
        checkpoint_ids=(f"checkpoint-{chronology}",),
        previous_receipt=previous,
    )


def test_builder_binds_validated_worker_device_and_carrier_and_stays_non_authoritative():
    provider, identity, builder = _builder()
    unsigned = _build(builder)
    assert unsigned.session_sequence == Ordinal(1)
    assert unsigned.predecessor_receipt_id is None
    assert unsigned.device_id == "cpu"
    assert unsigned.carrier_commitment == builder.worker.transport_commitment
    assert unsigned.execution_soundness == "receipt-only-not-malicious-evaluator-proof"
    assert unsigned.authority_granted is False

    signed = sign_remote_execution_receipt(unsigned, provider, identity)
    report = verify_remote_execution_receipt(
        signed,
        provider,
        identity.signature_public_key,
        expected_session_sequence=Ordinal(1),
        expected_carrier_commitment=builder.worker.transport_commitment,
        require_production_pq=False,
    )
    assert report.valid is True


def test_builder_derives_one_origin_predecessor_chain_instead_of_accepting_caller_sequence():
    provider, identity, builder = _builder()
    first = sign_remote_execution_receipt(_build(builder), provider, identity)
    second_unsigned = _build(builder, previous=first, chronology=2, state="state-b")
    assert second_unsigned.session_sequence == Ordinal(2)
    assert second_unsigned.predecessor_receipt_id == first.receipt_id()
    second = sign_remote_execution_receipt(second_unsigned, provider, identity)
    report = verify_remote_execution_receipt(
        second,
        provider,
        identity.signature_public_key,
        previous_receipt=first,
        expected_session_sequence=Ordinal(2),
        expected_carrier_commitment=builder.worker.transport_commitment,
        require_production_pq=False,
    )
    assert report.valid is True


def test_builder_fails_closed_if_carrier_changes_mid_session():
    provider, identity, builder = _builder()
    first = sign_remote_execution_receipt(_build(builder), provider, identity)
    changed = RemoteExecutionEvidenceBuilder(
        worker=_worker("xvoid:shake256-512:ssh-carrier-b"),
        evaluator_identity_id=builder.evaluator_identity_id,
        evaluator_key_id=builder.evaluator_key_id,
        provider_build_commitment=builder.provider_build_commitment,
        execution_mode=builder.execution_mode,
        authority_domain=builder.authority_domain,
    )
    with pytest.raises(ValueError, match="carrier commitment changed"):
        _build(changed, previous=first, chronology=2, state="state-b")


def test_builder_fails_closed_on_cross_session_or_signer_chain_changes():
    provider, identity, builder = _builder()
    first = sign_remote_execution_receipt(_build(builder), provider, identity)
    with pytest.raises(ValueError, match="another session"):
        builder.build(
            semantic_program_id="semantic-shake",
            encrypted_representation_commitment="xvoid:shake256-512:encrypted-program",
            session_id="session-b",
            input_commitment="xvoid:shake256-512:input",
            encrypted_result_commitment="xvoid:shake256-512:result-2",
            session_state_commitment="xvoid:shake256-512:state-b",
            transport_transcript_commitment="xvoid:shake256-512:transcript-2",
            chronology=ExecutionChronology(Ordinal(2), "2026-09-15T21:20:02+00:00"),
            previous_receipt=first,
        )

    altered = replace(builder, evaluator_identity_id="xvoid:shake256-512:other-signer")
    with pytest.raises(ValueError, match="evaluator identity changed"):
        _build(altered, previous=first, chronology=2, state="state-b")
