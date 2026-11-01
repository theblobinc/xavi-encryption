"""First-class compiled SHAKE256-512 workload.

The semantic object specifies SHAKE256 with 512-bit output. A compiled workload
binds a message commitment to a one-origin absorb/squeeze schedule while
referencing one reusable Keccak-f[1600] permutation body.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from xavi_void.crypto.keccak import SHAKE256_512_OUTPUT_BYTES, SHAKE256_RATE_BYTES, shake256_512
from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.types import Ordinal, PositiveExtent

from .word_ir import KECCAK_WORD_PROGRAM, WordProgram, shake256_512_word_ir, shake_padding


@dataclass(frozen=True, slots=True)
class ShakeSemanticIR:
    rate_bytes: PositiveExtent = PositiveExtent(SHAKE256_RATE_BYTES)
    permutation_rounds: PositiveExtent = PositiveExtent(24)
    output_bytes: PositiveExtent = PositiveExtent(SHAKE256_512_OUTPUT_BYTES)
    domain_suffix: int = 0x1F

    def canonical(self) -> dict:
        return {
            "algorithm": "SHAKE256",
            "rate_bytes": self.rate_bytes.value,
            "permutation_rounds": self.permutation_rounds.value,
            "output_bytes": self.output_bytes.value,
            "domain_suffix": self.domain_suffix,
            "bit_order": "keccak-lsb-first",
        }

    def semantic_id(self) -> str:
        return content_id("XAVI-VOID/SHAKE256-512-SEMANTIC-IR/v1", canonical_bytes(self.canonical()))


SHAKE256_512_SEMANTIC_IR = ShakeSemanticIR()


@dataclass(frozen=True, slots=True)
class AbsorbStep:
    ordinal: Ordinal

    def canonical(self) -> dict:
        return {"ordinal": self.ordinal.value, "action": "xor-rate-block-then-permute"}


@dataclass(frozen=True, slots=True)
class SqueezeStep:
    ordinal: Ordinal

    def canonical(self) -> dict:
        return {"ordinal": self.ordinal.value, "action": "read-rate-prefix-then-permute-if-needed"}


@dataclass(frozen=True, slots=True)
class CompiledShakeWorkload:
    semantic_ir: ShakeSemanticIR
    message_commitment: str
    message_length: int
    permutation_body_representation_id: str
    absorb_schedule: tuple[AbsorbStep, ...]
    squeeze_schedule: tuple[SqueezeStep, ...]

    def __post_init__(self) -> None:
        if self.message_length < 0:
            raise ValueError("message length cannot be negative")
        if not self.absorb_schedule or not self.squeeze_schedule:
            raise ValueError("SHAKE workload requires absorb and squeeze schedules")
        if [step.ordinal.value for step in self.absorb_schedule] != list(range(1, len(self.absorb_schedule) + 1)):
            raise ValueError("absorb schedule must be contiguous and one-origin")
        if [step.ordinal.value for step in self.squeeze_schedule] != list(range(1, len(self.squeeze_schedule) + 1)):
            raise ValueError("squeeze schedule must be contiguous and one-origin")

    def semantic_workload_id(self) -> str:
        return content_id(
            "XAVI-VOID/SHAKE256-512-WORKLOAD-SEMANTICS/v1",
            self.semantic_ir.semantic_id().encode("ascii"),
            self.message_commitment.encode("ascii"),
            str(self.message_length).encode("ascii"),
        )

    def representation_id(self) -> str:
        return content_id(
            "XAVI-VOID/SHAKE256-512-EXECUTION-PLAN/v1",
            canonical_bytes({
                "semantic_workload_id": self.semantic_workload_id(),
                "permutation_body_representation_id": self.permutation_body_representation_id,
                "absorb_schedule": [step.canonical() for step in self.absorb_schedule],
                "squeeze_schedule": [step.canonical() for step in self.squeeze_schedule],
            }),
        )


def compile_shake256_512(message: bytes, *, program: WordProgram = KECCAK_WORD_PROGRAM) -> CompiledShakeWorkload:
    program.validate()
    padded_length = len(shake_padding(message))
    absorb_blocks = padded_length // SHAKE256_RATE_BYTES
    squeeze_blocks = (SHAKE256_512_OUTPUT_BYTES + SHAKE256_RATE_BYTES - 1) // SHAKE256_RATE_BYTES
    return CompiledShakeWorkload(
        semantic_ir=SHAKE256_512_SEMANTIC_IR,
        message_commitment=content_id("XAVI-VOID/SHAKE-MESSAGE/v1", message),
        message_length=len(message),
        permutation_body_representation_id=program.representation_id(),
        absorb_schedule=tuple(AbsorbStep(Ordinal(i)) for i in range(1, absorb_blocks + 1)),
        squeeze_schedule=tuple(SqueezeStep(Ordinal(i)) for i in range(1, squeeze_blocks + 1)),
    )


def execute_shake_semantic(message: bytes, semantic: ShakeSemanticIR = SHAKE256_512_SEMANTIC_IR) -> bytes:
    if semantic != SHAKE256_512_SEMANTIC_IR:
        raise ValueError("reference semantic evaluator currently supports the canonical SHAKE256-512 profile")
    return shake256_512(message)


def execute_shake_plan(message: bytes, plan: CompiledShakeWorkload, *, program: WordProgram = KECCAK_WORD_PROGRAM) -> bytes:
    expected = compile_shake256_512(message, program=program)
    if plan.semantic_workload_id() != expected.semantic_workload_id():
        raise ValueError("message does not match compiled semantic workload")
    if plan.permutation_body_representation_id != program.representation_id():
        raise ValueError("execution plan binds a different permutation body")
    if plan.absorb_schedule != expected.absorb_schedule or plan.squeeze_schedule != expected.squeeze_schedule:
        raise ValueError("execution schedule does not match message/output shape")
    return shake256_512_word_ir(message, program)


@dataclass(frozen=True, slots=True)
class ShakeVerification:
    semantic_workload_id: str
    execution_representation_id: str
    output_commitment: str
    absorb_blocks: int
    reusable_permutation_body: bool


def verify_compiled_shake256_512(message: bytes) -> ShakeVerification:
    plan = compile_shake256_512(message)
    standard = hashlib.shake_256(message).digest(SHAKE256_512_OUTPUT_BYTES)
    semantic = execute_shake_semantic(message)
    execution = execute_shake_plan(message, plan)
    if not (standard == semantic == execution):
        raise ValueError("SHAKE differential verification failed")
    return ShakeVerification(
        plan.semantic_workload_id(),
        plan.representation_id(),
        content_id("XAVI-VOID/SHAKE256-512-OUTPUT/v1", execution),
        len(plan.absorb_schedule),
        True,
    )
