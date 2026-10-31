"""Structured construction of non-authoritative remote execution evidence.

This module turns a validated remote-worker identity plus locally observed
commitments into chained ``RemoteExecutionReceipt`` objects.  It deliberately
contains no signing authority and no execution authority.  Callers may pass the
result to ``sign_remote_execution_receipt`` using an independently controlled PQ
identity.
"""
from __future__ import annotations

from dataclasses import dataclass

from xavi_void.math.types import Ordinal
from xavi_void.witness.domain import AuthorityDomain

from .receipt import ExecutionChronology
from .remote_client import RemoteWorkerIdentity
from .remote_receipt import RemoteExecutionReceipt


@dataclass(frozen=True, slots=True)
class RemoteExecutionEvidenceBuilder:
    """Build fail-closed v2 receipt evidence from a validated remote worker.

    ``evaluator_identity_id`` and ``evaluator_key_id`` identify the independent
    PQ receipt signer.  ``worker.key_id`` remains the FHE provider's evaluation
    key identity and is intentionally not treated as signing authority.
    """

    worker: RemoteWorkerIdentity
    evaluator_identity_id: str
    evaluator_key_id: str
    provider_build_commitment: str
    execution_mode: str
    authority_domain: AuthorityDomain

    def __post_init__(self) -> None:
        self.authority_domain.validate()
        required = (
            self.worker.role,
            self.worker.provider,
            self.worker.key_id,
            self.worker.device,
            self.worker.transport_commitment,
            self.evaluator_identity_id,
            self.evaluator_key_id,
            self.provider_build_commitment,
            self.execution_mode,
        )
        if any(not value for value in required):
            raise ValueError("remote execution evidence context fields are required")
        if self.worker.role != "remote-worker":
            raise ValueError("receipt evidence requires role=remote-worker")

    def build(
        self,
        *,
        semantic_program_id: str,
        encrypted_representation_commitment: str,
        session_id: str,
        input_commitment: str,
        encrypted_result_commitment: str,
        session_state_commitment: str,
        transport_transcript_commitment: str,
        chronology: ExecutionChronology,
        decrypted_output_commitment: str | None = None,
        rewrite_witness_ids: tuple[str, ...] = (),
        equivalence_witness_ids: tuple[str, ...] = (),
        checkpoint_ids: tuple[str, ...] = (),
        previous_receipt: RemoteExecutionReceipt | None = None,
    ) -> RemoteExecutionReceipt:
        """Construct one chained receipt without granting authority.

        Sequence and predecessor are derived rather than caller supplied, which
        prevents accidental one-origin/chain divergence between distributed
        workers and the receipt ledger.
        """
        if previous_receipt is None:
            sequence = Ordinal(1)
            predecessor_receipt_id = None
        else:
            if not previous_receipt.is_v2 or previous_receipt.session_sequence is None:
                raise ValueError("previous remote receipt must be v2")
            if previous_receipt.session_id != session_id:
                raise ValueError("previous remote receipt belongs to another session")
            if previous_receipt.evaluator_identity_id != self.evaluator_identity_id:
                raise ValueError("evaluator identity changed within receipt chain")
            if previous_receipt.evaluator_key_id != self.evaluator_key_id:
                raise ValueError("evaluator signing key changed within receipt chain")
            if previous_receipt.provider_build_commitment != self.provider_build_commitment:
                raise ValueError("provider build changed within receipt chain")
            if previous_receipt.carrier_commitment != self.worker.transport_commitment:
                raise ValueError("carrier commitment changed within receipt chain")
            sequence = Ordinal(previous_receipt.session_sequence.value + 1)
            predecessor_receipt_id = previous_receipt.receipt_id()

        if chronology.sequence.value < sequence.value:
            raise ValueError("chronology sequence cannot precede receipt session sequence")

        return RemoteExecutionReceipt(
            semantic_program_id=semantic_program_id,
            encrypted_representation_commitment=encrypted_representation_commitment,
            evaluator_identity_id=self.evaluator_identity_id,
            session_id=session_id,
            input_commitment=input_commitment,
            encrypted_result_commitment=encrypted_result_commitment,
            decrypted_output_commitment=decrypted_output_commitment,
            rewrite_witness_ids=tuple(rewrite_witness_ids),
            equivalence_witness_ids=tuple(equivalence_witness_ids),
            checkpoint_ids=tuple(checkpoint_ids),
            transport_transcript_commitment=transport_transcript_commitment,
            authority_domain=self.authority_domain,
            chronology=chronology,
            evaluator_key_id=self.evaluator_key_id,
            provider_build_commitment=self.provider_build_commitment,
            device_id=self.worker.device,
            execution_mode=self.execution_mode,
            predecessor_receipt_id=predecessor_receipt_id,
            session_sequence=sequence,
            session_state_commitment=session_state_commitment,
            carrier_commitment=self.worker.transport_commitment,
            authority_granted=False,
        )
