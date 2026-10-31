"""Witness-bearing execution receipts.

A receipt binds a semantic object to the concrete representation that ran,
inputs/outputs, execution profile, proof witnesses, authority domain and
chronology. A receipt is evidence; it never grants authority by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import semantic_bit_label
from xavi_void.math.types import Ordinal
from xavi_void.witness.domain import AuthorityDomain

from .behavior import exact_behavior
from .ir import ExecutionIR, evaluate
from .semantic import semantic_from_execution


def _bit_token(value: bool) -> str:
    return semantic_bit_label(value)


@dataclass(frozen=True, slots=True)
class ExecutionChronology:
    sequence: Ordinal
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, Ordinal):
            raise TypeError("chronology sequence must be Ordinal")
        try:
            parsed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("observed_at must be ISO-8601") from error
        if parsed.tzinfo is None:
            raise ValueError("observed_at must include timezone")

    @classmethod
    def now(cls, sequence: Ordinal = Ordinal(1)) -> "ExecutionChronology":
        return cls(sequence, datetime.now(timezone.utc).isoformat())

    def canonical(self) -> dict:
        return {"sequence": self.sequence.value, "observed_at": self.observed_at}


@dataclass(frozen=True, slots=True)
class ExecutionProfile:
    backend: str
    mode: str
    implementation: str

    def __post_init__(self) -> None:
        if not self.backend or not self.mode or not self.implementation:
            raise ValueError("execution profile fields are required")

    def canonical(self) -> dict:
        return {"backend": self.backend, "mode": self.mode, "implementation": self.implementation}


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    semantic_program_id: str
    concrete_representation_id: str
    behavior_commitment_id: str
    input_commitment: str
    output_commitment: str
    trace_commitment: str
    execution_profile: ExecutionProfile
    rewrite_witness_ids: tuple[str, ...]
    equivalence_witness_ids: tuple[str, ...]
    authority_domain: AuthorityDomain
    chronology: ExecutionChronology

    def __post_init__(self) -> None:
        self.authority_domain.validate()
        for value in (
            self.semantic_program_id,
            self.concrete_representation_id,
            self.behavior_commitment_id,
            self.input_commitment,
            self.output_commitment,
            self.trace_commitment,
        ):
            if not value:
                raise ValueError("receipt commitment fields must not be empty")

    def canonical(self) -> dict:
        d = self.authority_domain
        return {
            "semantic_program_id": self.semantic_program_id,
            "concrete_representation_id": self.concrete_representation_id,
            "behavior_commitment_id": self.behavior_commitment_id,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "trace_commitment": self.trace_commitment,
            "execution_profile": self.execution_profile.canonical(),
            "rewrite_witness_ids": list(self.rewrite_witness_ids),
            "equivalence_witness_ids": list(self.equivalence_witness_ids),
            "authority_domain": {
                "authority_namespace": d.authority_namespace,
                "authority_profile": d.authority_profile,
                "evidence_environment": d.evidence_environment,
                "production_eligible": d.production_eligible,
                "trust_registry_snapshot_id": d.trust_registry_snapshot_id,
                "cryptographic_suite_id": d.cryptographic_suite_id,
            },
            "chronology": self.chronology.canonical(),
            "authority_granted": False,
        }

    def receipt_id(self) -> str:
        return content_id("XAVI-VOID/EXECUTION-RECEIPT/v2", canonical_bytes(self.canonical()))


def execute_with_receipt(
    program: ExecutionIR,
    inputs: Mapping[Ordinal, bool],
    *,
    authority_domain: AuthorityDomain,
    chronology: ExecutionChronology,
    execution_profile: ExecutionProfile = ExecutionProfile("cpu", "plaintext-reference", "python"),
    rewrite_witness_ids: Sequence[str] = (),
    equivalence_witness_ids: Sequence[str] = (),
    max_exact_inputs: int = 12,
) -> tuple[tuple[bool, ...], ExecutionReceipt]:
    program.validate()
    authority_domain.validate()
    semantic = semantic_from_execution(program)
    behavior = exact_behavior(program, max_inputs=max_exact_inputs)
    evaluation = evaluate(program, inputs)
    ordered_inputs = [
        {"slot": slot.value, "value": _bit_token(inputs[slot])}
        for slot in program.input_slots()
    ]
    ordered_outputs = [
        {"ordinal": ordinal, "value": _bit_token(value)}
        for ordinal, value in enumerate(evaluation.outputs, start=1)
    ]
    input_commitment = content_id("XAVI-VOID/EXECUTION-INPUT/v1", canonical_bytes(ordered_inputs))
    output_commitment = content_id("XAVI-VOID/EXECUTION-OUTPUT/v1", canonical_bytes(ordered_outputs))
    receipt = ExecutionReceipt(
        semantic_program_id=semantic.semantic_id(),
        concrete_representation_id=program.representation_id(),
        behavior_commitment_id=behavior.behavior_id,
        input_commitment=input_commitment,
        output_commitment=output_commitment,
        trace_commitment=evaluation.trace_commitment,
        execution_profile=execution_profile,
        rewrite_witness_ids=tuple(rewrite_witness_ids),
        equivalence_witness_ids=tuple(equivalence_witness_ids),
        authority_domain=authority_domain,
        chronology=chronology,
    )
    return evaluation.outputs, receipt


def receipt_evidence_node(receipt: ExecutionReceipt):
    """Project a receipt into the evidence graph without granting authority."""
    from xavi_void.witness.evidence import EvidenceNode
    return EvidenceNode(
        content_id=receipt.receipt_id(),
        content_type="xavi-void/execution-receipt/v2",
        domain=receipt.authority_domain,
    )
