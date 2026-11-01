"""Witnessed remote execution receipts.

A receipt binds the observed transcript and commitments.  It deliberately does
not claim universal proof that a malicious evaluator executed every operation.

Revision 2 adds independently checkable receipt chaining, evaluator signing-key
identity, provider/build and device/mode commitments, session-state/replay
binding, and a PQ authentication envelope.  Authentication strengthens the
evidence boundary; it does not turn a receipt into a malicious-evaluator proof.
"""
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, replace

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.types import Ordinal
from xavi_void.witness.domain import AuthorityDomain

from .pq_transport import PostQuantumProvider, SUITE_ID, TransportIdentity
from .receipt import ExecutionChronology


_EXECUTION_SOUNDNESS = "receipt-only-not-malicious-evaluator-proof"
_PRODUCTION_PQ = ("ML-KEM-1024", "ML-DSA-87", "KMAC256", "AES-256-GCM-SIV")


@dataclass(frozen=True, slots=True)
class ReceiptPQAuthentication:
    """Detached PQ authentication for a v2 remote-execution receipt.

    The signature is detached deliberately: ``receipt_id`` commits to the
    execution evidence before authentication, avoiding a signature/self-hash
    cycle while keeping the receipt identifier stable across serialization.
    """

    signer_identity_id: str
    signing_key_id: str
    suite_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if not self.signer_identity_id or not self.signing_key_id or not self.suite_id:
            raise ValueError("receipt authentication identity fields are required")
        if not isinstance(self.signature, bytes) or not self.signature:
            raise ValueError("receipt authentication signature is required")

    def canonical(self) -> dict:
        return {
            "signer_identity_id": self.signer_identity_id,
            "signing_key_id": self.signing_key_id,
            "suite_id": self.suite_id,
            "signature": self.signature.hex(),
        }


@dataclass(frozen=True, slots=True)
class RemoteReceiptVerification:
    receipt_id: str
    valid: bool
    checks: tuple[str, ...]
    failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RemoteExecutionReceipt:
    semantic_program_id: str
    encrypted_representation_commitment: str
    evaluator_identity_id: str
    session_id: str
    input_commitment: str
    encrypted_result_commitment: str
    decrypted_output_commitment: str | None
    rewrite_witness_ids: tuple[str, ...]
    equivalence_witness_ids: tuple[str, ...]
    checkpoint_ids: tuple[str, ...]
    transport_transcript_commitment: str
    authority_domain: AuthorityDomain
    chronology: ExecutionChronology

    # v2 execution-evidence fields.  They are optional as a group so archived
    # v1 receipts remain constructible and content-addressable.
    evaluator_key_id: str | None = None
    provider_build_commitment: str | None = None
    device_id: str | None = None
    execution_mode: str | None = None
    predecessor_receipt_id: str | None = None
    session_sequence: Ordinal | None = None
    session_state_commitment: str | None = None
    # Optional carrier evidence (for example SSHTransportPolicy.commitment()).
    # It is never authority. When present it is committed by receipt_id/PQ auth.
    carrier_commitment: str | None = None
    pq_authentication: ReceiptPQAuthentication | None = None

    execution_soundness: str = _EXECUTION_SOUNDNESS
    authority_granted: bool = False

    def __post_init__(self) -> None:
        self.authority_domain.validate()
        required = (
            self.semantic_program_id,
            self.encrypted_representation_commitment,
            self.evaluator_identity_id,
            self.session_id,
            self.input_commitment,
            self.encrypted_result_commitment,
            self.transport_transcript_commitment,
        )
        if any(not x for x in required):
            raise ValueError("remote receipt commitments are required")
        if self.authority_granted:
            raise ValueError("execution receipt cannot grant authority")
        if self.execution_soundness != _EXECUTION_SOUNDNESS:
            raise ValueError("unsupported execution-soundness claim")

        v2_values = (
            self.evaluator_key_id,
            self.provider_build_commitment,
            self.device_id,
            self.execution_mode,
            self.session_sequence,
            self.session_state_commitment,
            self.carrier_commitment,
            self.pq_authentication,
        )
        if any(value is not None for value in v2_values) or self.predecessor_receipt_id is not None:
            required_v2 = (
                self.evaluator_key_id,
                self.provider_build_commitment,
                self.device_id,
                self.execution_mode,
                self.session_sequence,
                self.session_state_commitment,
            )
            if any(value is None for value in required_v2):
                raise ValueError("v2 remote receipt fields must be supplied as one complete set")
            if not isinstance(self.session_sequence, Ordinal):
                raise TypeError("remote receipt session_sequence must be Ordinal")
            for value in (
                self.evaluator_key_id,
                self.provider_build_commitment,
                self.device_id,
                self.execution_mode,
                self.session_state_commitment,
            ):
                if not value:
                    raise ValueError("v2 remote receipt commitment fields must not be empty")
            if self.carrier_commitment is not None and not self.carrier_commitment:
                raise ValueError("carrier commitment must not be empty")
            if self.session_sequence.value == 1 and self.predecessor_receipt_id is not None:
                raise ValueError("initial remote receipt must not name a predecessor")
            if self.session_sequence.value > 1 and not self.predecessor_receipt_id:
                raise ValueError("non-initial remote receipt requires predecessor_receipt_id")
            if self.pq_authentication is not None:
                if self.pq_authentication.signer_identity_id != self.evaluator_identity_id:
                    raise ValueError("receipt signer identity does not match evaluator identity")
                if self.pq_authentication.signing_key_id != self.evaluator_key_id:
                    raise ValueError("receipt authentication key does not match evaluator_key_id")
                if self.pq_authentication.suite_id != SUITE_ID:
                    raise ValueError("receipt authentication suite mismatch")

    @property
    def is_v2(self) -> bool:
        return self.session_sequence is not None

    def _base_canonical(self) -> dict:
        d = self.authority_domain
        return {
            "semantic_program_id": self.semantic_program_id,
            "encrypted_representation_commitment": self.encrypted_representation_commitment,
            "evaluator_identity_id": self.evaluator_identity_id,
            "session_id": self.session_id,
            "input_commitment": self.input_commitment,
            "encrypted_result_commitment": self.encrypted_result_commitment,
            "decrypted_output_commitment": self.decrypted_output_commitment,
            "rewrite_witness_ids": list(self.rewrite_witness_ids),
            "equivalence_witness_ids": list(self.equivalence_witness_ids),
            "checkpoint_ids": list(self.checkpoint_ids),
            "transport_transcript_commitment": self.transport_transcript_commitment,
            "authority_domain": {
                "authority_namespace": d.authority_namespace,
                "authority_profile": d.authority_profile,
                "evidence_environment": d.evidence_environment,
                "production_eligible": d.production_eligible,
                "trust_registry_snapshot_id": d.trust_registry_snapshot_id,
                "cryptographic_suite_id": d.cryptographic_suite_id,
            },
            "chronology": self.chronology.canonical(),
            "execution_soundness": self.execution_soundness,
            "authority_granted": False,
        }

    def unsigned_canonical(self) -> dict:
        """Canonical evidence committed by a v2 receipt before authentication."""
        if not self.is_v2:
            return self._base_canonical()
        assert self.session_sequence is not None
        payload = self._base_canonical()
        payload.update(
            {
                "schema_version": "xavi-void/remote-execution-receipt/v2",
                "evaluator_key_id": self.evaluator_key_id,
                "provider_build_commitment": self.provider_build_commitment,
                "device_id": self.device_id,
                "execution_mode": self.execution_mode,
                "predecessor_receipt_id": self.predecessor_receipt_id,
                "session_sequence": self.session_sequence.value,
                "session_state_commitment": self.session_state_commitment,
            }
        )
        # Preserve historical v2 identifiers: absent carrier evidence is omitted.
        if self.carrier_commitment is not None:
            payload["carrier_commitment"] = self.carrier_commitment
        return payload

    def canonical(self) -> dict:
        if not self.is_v2:
            return self._base_canonical()
        payload = self.unsigned_canonical()
        payload["pq_authentication"] = (
            None if self.pq_authentication is None else self.pq_authentication.canonical()
        )
        return payload

    def receipt_id(self) -> str:
        if not self.is_v2:
            return content_id(
                "XAVI-VOID/REMOTE-EXECUTION-RECEIPT/v1",
                canonical_bytes(self._base_canonical()),
            )
        return content_id(
            "XAVI-VOID/REMOTE-EXECUTION-RECEIPT/v2",
            canonical_bytes(self.unsigned_canonical()),
        )

    def signing_payload(self) -> bytes:
        if not self.is_v2:
            raise ValueError("legacy v1 receipts do not have a PQ signing payload")
        return canonical_bytes(
            {
                "domain": "XAVI-VOID/REMOTE-EXECUTION-RECEIPT-AUTH/v1",
                "receipt_id": self.receipt_id(),
                "evaluator_identity_id": self.evaluator_identity_id,
                "evaluator_key_id": self.evaluator_key_id,
                "suite_id": SUITE_ID,
                "receipt": self.unsigned_canonical(),
            }
        )

    def evidence_node(self):
        from xavi_void.witness.evidence import EvidenceNode

        content_type = (
            "xavi-void/remote-execution-receipt/v2"
            if self.is_v2
            else "xavi-void/remote-execution-receipt/v1"
        )
        return EvidenceNode(self.receipt_id(), content_type, self.authority_domain)


def receipt_signing_key_id(public_key: bytes) -> str:
    if not public_key:
        raise ValueError("receipt signing public key is required")
    return content_id("XAVI-VOID/REMOTE-RECEIPT-SIGNING-KEY/v1", public_key)


def sign_remote_execution_receipt(
    receipt: RemoteExecutionReceipt,
    provider: PostQuantumProvider,
    evaluator_identity: TransportIdentity,
) -> RemoteExecutionReceipt:
    """Attach a detached PQ authentication envelope to a complete v2 receipt."""
    if not receipt.is_v2:
        raise ValueError("only v2 remote receipts can be PQ authenticated")
    if evaluator_identity.identity_id != receipt.evaluator_identity_id:
        raise ValueError("transport identity does not match receipt evaluator identity")
    key_id = receipt_signing_key_id(evaluator_identity.signature_public_key)
    if key_id != receipt.evaluator_key_id:
        raise ValueError("transport signing key does not match receipt evaluator_key_id")
    signature = provider.sign(evaluator_identity.signature_private_key, receipt.signing_payload())
    authentication = ReceiptPQAuthentication(
        signer_identity_id=evaluator_identity.identity_id,
        signing_key_id=key_id,
        suite_id=SUITE_ID,
        signature=signature,
    )
    return replace(receipt, pq_authentication=authentication)


def verify_remote_execution_receipt(
    receipt: RemoteExecutionReceipt,
    provider: PostQuantumProvider,
    signing_public_key: bytes,
    *,
    previous_receipt: RemoteExecutionReceipt | None = None,
    expected_receipt_id: str | None = None,
    expected_session_id: str | None = None,
    expected_session_sequence: Ordinal | None = None,
    expected_session_state_commitment: str | None = None,
    expected_carrier_commitment: str | None = None,
    expected_provider_build_commitment: str | None = None,
    expected_evaluator_key_id: str | None = None,
    seen_receipt_ids: Collection[str] = (),
    require_production_pq: bool = True,
) -> RemoteReceiptVerification:
    """Independently verify v2 receipt commitments, chain state, and PQ auth.

    The result is authenticated execution evidence only.  A valid report does
    not prove that a malicious evaluator faithfully executed every operation.
    """
    checks: list[str] = []
    failures: list[str] = []

    receipt_id = receipt.receipt_id()
    checks.append("canonical-receipt-id-recomputed")
    if expected_receipt_id is not None and receipt_id != expected_receipt_id:
        failures.append("receipt-id-mismatch")
    if receipt_id in seen_receipt_ids:
        failures.append("receipt-replay-detected")

    if not receipt.is_v2:
        failures.append("legacy-receipt-has-no-v2-authentication")
        return RemoteReceiptVerification(receipt_id, False, tuple(checks), tuple(failures))

    assert receipt.session_sequence is not None
    if expected_session_id is not None and receipt.session_id != expected_session_id:
        failures.append("session-id-mismatch")
    if expected_session_sequence is not None and receipt.session_sequence != expected_session_sequence:
        failures.append("session-sequence-mismatch")
    if (
        expected_session_state_commitment is not None
        and receipt.session_state_commitment != expected_session_state_commitment
    ):
        failures.append("session-state-commitment-mismatch")
    if (
        expected_carrier_commitment is not None
        and receipt.carrier_commitment != expected_carrier_commitment
    ):
        failures.append("carrier-commitment-mismatch")
    if (
        expected_provider_build_commitment is not None
        and receipt.provider_build_commitment != expected_provider_build_commitment
    ):
        failures.append("provider-build-commitment-mismatch")
    if expected_evaluator_key_id is not None and receipt.evaluator_key_id != expected_evaluator_key_id:
        failures.append("evaluator-key-id-mismatch")

    if receipt.session_sequence.value == 1:
        checks.append("initial-session-sequence-valid")
    else:
        if previous_receipt is None:
            failures.append("previous-receipt-required-for-chain-verification")
        else:
            if not previous_receipt.is_v2 or previous_receipt.session_sequence is None:
                failures.append("previous-receipt-is-not-v2")
            else:
                if receipt.session_id != previous_receipt.session_id:
                    failures.append("predecessor-session-mismatch")
                if receipt.predecessor_receipt_id != previous_receipt.receipt_id():
                    failures.append("predecessor-receipt-id-mismatch")
                if receipt.session_sequence.value != previous_receipt.session_sequence.value + 1:
                    failures.append("session-sequence-not-monotonic")
                if receipt.chronology.sequence.value <= previous_receipt.chronology.sequence.value:
                    failures.append("chronology-not-monotonic")
                if receipt.evaluator_identity_id != previous_receipt.evaluator_identity_id:
                    failures.append("evaluator-identity-changed-within-session")
                if receipt.provider_build_commitment != previous_receipt.provider_build_commitment:
                    failures.append("provider-build-changed-within-session")
                if not failures:
                    checks.append("predecessor-chain-and-session-monotonicity-valid")

    key_id = receipt_signing_key_id(signing_public_key)
    if key_id != receipt.evaluator_key_id:
        failures.append("public-key-id-does-not-match-evaluator-key-id")

    auth = receipt.pq_authentication
    if auth is None:
        failures.append("pq-authentication-missing")
    else:
        if auth.signer_identity_id != receipt.evaluator_identity_id:
            failures.append("pq-signer-identity-mismatch")
        if auth.signing_key_id != receipt.evaluator_key_id:
            failures.append("pq-signing-key-id-mismatch")
        if auth.suite_id != SUITE_ID:
            failures.append("pq-suite-id-mismatch")
        if not provider.verify(signing_public_key, receipt.signing_payload(), auth.signature):
            failures.append("pq-signature-invalid")
        else:
            checks.append("pq-signature-valid")

    caps = provider.capabilities
    if require_production_pq:
        actual = (caps.kem, caps.signature, caps.kdf, caps.aead)
        if not caps.production_cryptographic or actual != _PRODUCTION_PQ:
            failures.append("pq-provider-not-production-suite")
        else:
            checks.append("production-pq-suite-valid")
    else:
        checks.append("non-production-pq-accepted-by-explicit-test-policy")

    if not failures:
        checks.extend(
            (
                "session-state-commitment-present",
                "provider-build-commitment-present",
                "device-execution-mode-present",
                "execution-soundness-remains-receipt-only",
            )
        )
    return RemoteReceiptVerification(receipt_id, not failures, tuple(checks), tuple(failures))
