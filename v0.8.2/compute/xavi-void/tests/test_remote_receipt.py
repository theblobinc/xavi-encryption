from dataclasses import replace

import pytest

from xavi_void.math.types import Ordinal
from xavi_void.runtime.pq_transport import DevelopmentPQProviderNOTSECURE, make_transport_identity
from xavi_void.runtime.receipt import ExecutionChronology
from xavi_void.runtime.remote_receipt import (
    RemoteExecutionReceipt,
    receipt_signing_key_id,
    sign_remote_execution_receipt,
    verify_remote_execution_receipt,
)
from xavi_void.witness.domain import AuthorityDomain


def _domain():
    return AuthorityDomain(
        "xavi://authority/sandbox/test",
        "sandbox-test-only",
        "pytest",
        False,
        "registry-1",
    )


def test_remote_receipt_is_non_authoritative_and_evidence_addressable():
    # Archived v1 construction remains backward compatible.
    r = RemoteExecutionReceipt(
        "semantic",
        "encrypted-representation",
        "evaluator-1",
        "session-1",
        "input",
        "cipher-output",
        "plain-output",
        ("rewrite-1",),
        ("equiv-1",),
        ("cp-1",),
        "transcript",
        _domain(),
        ExecutionChronology(Ordinal(1), "2026-09-14T15:00:00+00:00"),
    )
    assert r.execution_soundness == "receipt-only-not-malicious-evaluator-proof"
    assert r.authority_granted is False
    assert r.is_v2 is False
    node = r.evidence_node()
    node.validate()
    assert node.content_id == r.receipt_id()
    assert node.content_type == "xavi-void/remote-execution-receipt/v1"


def _v2_receipt(
    provider,
    identity,
    *,
    sequence=1,
    predecessor=None,
    chronology_sequence=None,
    build="shake256-512:provider-build-a",
    session_state="shake256-512:session-state-a",
    session_id="session-v2",
    carrier="xvoid:shake256-512:test-ssh-carrier",
):
    if chronology_sequence is None:
        chronology_sequence = sequence
    return RemoteExecutionReceipt(
        semantic_program_id="semantic-v2",
        encrypted_representation_commitment="shake256-512:encrypted-representation-v2",
        evaluator_identity_id=identity.identity_id,
        session_id=session_id,
        input_commitment="shake256-512:input-v2",
        encrypted_result_commitment=f"shake256-512:cipher-output-{sequence}",
        decrypted_output_commitment="shake256-512:plain-output-v2",
        rewrite_witness_ids=("rewrite-v2",),
        equivalence_witness_ids=("equiv-v2",),
        checkpoint_ids=(f"checkpoint-{sequence}",),
        transport_transcript_commitment="shake256-512:transcript-v2",
        authority_domain=_domain(),
        chronology=ExecutionChronology(
            Ordinal(chronology_sequence), f"2026-09-15T15:00:0{chronology_sequence}+00:00"
        ),
        evaluator_key_id=receipt_signing_key_id(identity.signature_public_key),
        provider_build_commitment=build,
        device_id="tbi-production-3/rtx2070",
        execution_mode="tfhe-cuda-encrypted",
        predecessor_receipt_id=predecessor,
        session_sequence=Ordinal(sequence),
        session_state_commitment=session_state,
        carrier_commitment=carrier,
    )


def test_v2_receipt_pq_authentication_and_independent_verifier_accept_valid_evidence():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    unsigned = _v2_receipt(provider, identity)
    receipt_id_before_sign = unsigned.receipt_id()
    signed = sign_remote_execution_receipt(unsigned, provider, identity)

    # Detached authentication must not create a signature/self-hash cycle.
    assert signed.receipt_id() == receipt_id_before_sign
    assert signed.canonical()["pq_authentication"] is not None
    assert signed.evidence_node().content_type == "xavi-void/remote-execution-receipt/v2"

    report = verify_remote_execution_receipt(
        signed,
        provider,
        identity.signature_public_key,
        expected_receipt_id=receipt_id_before_sign,
        expected_session_id="session-v2",
        expected_session_sequence=Ordinal(1),
        expected_session_state_commitment="shake256-512:session-state-a",
        expected_carrier_commitment="xvoid:shake256-512:test-ssh-carrier",
        expected_provider_build_commitment="shake256-512:provider-build-a",
        expected_evaluator_key_id=signed.evaluator_key_id,
        require_production_pq=False,
    )
    assert report.valid is True
    assert report.failures == ()
    assert "pq-signature-valid" in report.checks
    assert signed.execution_soundness == "receipt-only-not-malicious-evaluator-proof"
    assert signed.authority_granted is False


def test_production_verification_fails_closed_on_development_pq_provider():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    signed = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    report = verify_remote_execution_receipt(signed, provider, identity.signature_public_key)
    assert report.valid is False
    assert "pq-provider-not-production-suite" in report.failures


def test_tampered_receipt_invalidates_pq_signature():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    signed = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    tampered = replace(signed, encrypted_result_commitment="shake256-512:tampered-result")
    report = verify_remote_execution_receipt(
        tampered, provider, identity.signature_public_key, require_production_pq=False
    )
    assert report.valid is False
    assert "pq-signature-invalid" in report.failures


def test_carrier_commitment_is_signed_and_expected_value_is_fail_closed():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    signed = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    assert signed.unsigned_canonical()["carrier_commitment"] == "xvoid:shake256-512:test-ssh-carrier"

    wrong_expected = verify_remote_execution_receipt(
        signed,
        provider,
        identity.signature_public_key,
        expected_carrier_commitment="xvoid:shake256-512:wrong-carrier",
        require_production_pq=False,
    )
    assert wrong_expected.valid is False
    assert "carrier-commitment-mismatch" in wrong_expected.failures

    tampered = replace(signed, carrier_commitment="xvoid:shake256-512:tampered-carrier")
    tampered_report = verify_remote_execution_receipt(
        tampered, provider, identity.signature_public_key, require_production_pq=False
    )
    assert tampered_report.valid is False
    assert "pq-signature-invalid" in tampered_report.failures


def test_wrong_evaluator_signing_key_is_rejected():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    wrong_identity = make_transport_identity(provider)
    signed = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    report = verify_remote_execution_receipt(
        signed, provider, wrong_identity.signature_public_key, require_production_pq=False
    )
    assert report.valid is False
    assert "public-key-id-does-not-match-evaluator-key-id" in report.failures
    assert "pq-signature-invalid" in report.failures


def test_wrong_provider_build_expectation_and_replay_are_rejected():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    signed = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    report = verify_remote_execution_receipt(
        signed,
        provider,
        identity.signature_public_key,
        expected_provider_build_commitment="shake256-512:wrong-build",
        seen_receipt_ids={signed.receipt_id()},
        require_production_pq=False,
    )
    assert report.valid is False
    assert "provider-build-commitment-mismatch" in report.failures
    assert "receipt-replay-detected" in report.failures


def test_chained_receipt_verifies_predecessor_and_session_monotonicity():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    first = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    second_unsigned = _v2_receipt(
        provider,
        identity,
        sequence=2,
        predecessor=first.receipt_id(),
        chronology_sequence=2,
        session_state="shake256-512:session-state-b",
    )
    second = sign_remote_execution_receipt(second_unsigned, provider, identity)
    report = verify_remote_execution_receipt(
        second,
        provider,
        identity.signature_public_key,
        previous_receipt=first,
        expected_session_sequence=Ordinal(2),
        expected_session_state_commitment="shake256-512:session-state-b",
        require_production_pq=False,
    )
    assert report.valid is True
    assert "predecessor-chain-and-session-monotonicity-valid" in report.checks


def test_broken_predecessor_chain_is_rejected_even_with_valid_signature():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    first = sign_remote_execution_receipt(_v2_receipt(provider, identity), provider, identity)
    broken_unsigned = _v2_receipt(
        provider,
        identity,
        sequence=2,
        predecessor="shake256-512:not-the-predecessor",
        chronology_sequence=2,
        session_state="shake256-512:session-state-b",
    )
    broken = sign_remote_execution_receipt(broken_unsigned, provider, identity)
    report = verify_remote_execution_receipt(
        broken,
        provider,
        identity.signature_public_key,
        previous_receipt=first,
        require_production_pq=False,
    )
    assert report.valid is False
    assert "predecessor-receipt-id-mismatch" in report.failures
    assert "pq-signature-valid" in report.checks


def test_v2_receipt_rejects_partial_or_invalid_chain_fields():
    provider = DevelopmentPQProviderNOTSECURE()
    identity = make_transport_identity(provider)
    with pytest.raises(ValueError, match="complete set"):
        replace(
            RemoteExecutionReceipt(
                "semantic",
                "encrypted-representation",
                identity.identity_id,
                "session-1",
                "input",
                "cipher-output",
                None,
                (),
                (),
                (),
                "transcript",
                _domain(),
                ExecutionChronology(Ordinal(1), "2026-09-15T15:00:00+00:00"),
            ),
            evaluator_key_id=receipt_signing_key_id(identity.signature_public_key),
        )

    with pytest.raises(ValueError, match="must not name a predecessor"):
        _v2_receipt(provider, identity, sequence=1, predecessor="unexpected")
