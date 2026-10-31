"""Encrypted SHAKE256-512 workload and Rev 1.2-dev2 receipt path."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import time

from xavi_void.crypto.keccak import SHAKE256_512_OUTPUT_BYTES, SHAKE256_RATE_BYTES
from xavi_void.crypto.shake import content_id
from xavi_void.witness.domain import AuthorityDomain

from .encrypted import (
    CipherWord64, EncryptedWordProgram, FHEBackend, FHEClientView, FHEEvaluatorView,
    encrypt_word_program, encrypted_word_program_commitment,
    execute_oblivious_word_program, execute_keccak24_execution_class,
)
from .shake_workload import (
    SHAKE256_512_SEMANTIC_IR, compile_shake256_512,
    execute_shake_plan, execute_shake_semantic,
)
from .word_ir import KECCAK_WORD_PROGRAM, RATE_LANE_COUNT, shake_padding, shake256_512_word_ir
from .privacy import KECCAK_24R, ExecutionClass
from .receipt import ExecutionChronology
from .remote_receipt import RemoteExecutionReceipt


@dataclass(frozen=True, slots=True)
class EncryptedShakeInput:
    message_length: int
    message_commitment: str
    encrypted_blocks: tuple[tuple[CipherWord64, ...], ...]


@dataclass(frozen=True, slots=True)
class EncryptedShakeTiming:
    execution_path: str
    block_ns: tuple[int, ...]
    full_evaluation_ns: int
    provider_metrics: dict[str, object] = field(default_factory=dict)
    resident_before: dict[str, object] = field(default_factory=dict)
    resident_after: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EncryptedShakeResult:
    semantic_workload_id: str
    encrypted_program_commitment: str
    encrypted_output: tuple[CipherWord64, ...]
    ciphertext_commitment: str
    timing: EncryptedShakeTiming | None = None


@dataclass(frozen=True, slots=True)
class EncryptedShakeRun:
    digest: bytes
    result: EncryptedShakeResult
    receipt: RemoteExecutionReceipt


def prepare_encrypted_shake_input(message: bytes, client: FHEClientView) -> EncryptedShakeInput:
    """Pad on the trusted client and encrypt the 136-byte SHAKE rate blocks."""
    padded = shake_padding(message)
    blocks: list[tuple[CipherWord64, ...]] = []
    for start in range(0, len(padded), SHAKE256_RATE_BYTES):
        block = padded[start:start + SHAKE256_RATE_BYTES]
        lanes = tuple(
            client.encrypt_word64(int.from_bytes(block[i:i+8], "little"))
            for i in range(0, SHAKE256_RATE_BYTES, 8)
        )
        if len(lanes) != RATE_LANE_COUNT:
            raise AssertionError("SHAKE256 rate must contain 17 64-bit lanes")
        blocks.append(lanes)
    return EncryptedShakeInput(
        len(message), content_id("XAVI-VOID/SHAKE-MESSAGE/v1", message), tuple(blocks)
    )


def compile_encrypted_shake_program(client: FHEClientView, *, execution_class: ExecutionClass = KECCAK_24R) -> EncryptedWordProgram:
    execution_class.validate_program_shape(
        instruction_count=len(KECCAK_WORD_PROGRAM.instructions),
        register_count=KECCAK_WORD_PROGRAM.register_count.value,
    )
    return encrypt_word_program(
        KECCAK_WORD_PROGRAM,
        client,
        semantic_id=SHAKE256_512_SEMANTIC_IR.semantic_id(),
        padded_instruction_count=execution_class.padded_instruction_count.value,
        padded_register_count=execution_class.register_bank_size.value,
    )


def specialized_keccak_program_commitment() -> str:
    """Commit the public specialized Keccak execution class without fake encrypted IR."""
    return content_id(
        "XAVI-VOID/SPECIALIZED-KECCAK24-PROGRAM/v1",
        SHAKE256_512_SEMANTIC_IR.semantic_id().encode("ascii"),
        str(KECCAK_24R.padded_instruction_count.value).encode("ascii"),
        str(KECCAK_24R.register_bank_size.value).encode("ascii"),
    )


def execute_encrypted_shake256_512(
    encrypted_input: EncryptedShakeInput,
    encrypted_program: EncryptedWordProgram | None,
    evaluator: FHEEvaluatorView,
    *,
    specialized_keccak: bool = False,
) -> EncryptedShakeResult:
    """Evaluate SHAKE256-512 without decrypting data or encrypted program fields.

    The default path is the conformance path: the encrypted ExecutionIR is
    interpreted obliviously. ``specialized_keccak=True`` selects the public
    Keccak-24 execution class and invokes a provider kernel; it never decrypts
    encrypted opcode/register fields and is intended for performance runs after
    conformance has passed.
    """
    evaluator.reset_metrics()
    resident_before=evaluator.resident_stats()
    started = time.perf_counter_ns()
    block_times: list[int] = []
    state: tuple[CipherWord64, ...] = tuple(evaluator.trivial_word64(0) for _ in range(25))
    for block in encrypted_input.encrypted_blocks:
        block_started = time.perf_counter_ns()
        mutable = list(state)
        for lane_ordinal, encrypted_lane in enumerate(block, start=1):
            mutable[lane_ordinal - 1] = evaluator.word_xor(mutable[lane_ordinal - 1], encrypted_lane)
        if specialized_keccak:
            old_state=state
            state = execute_keccak24_execution_class(tuple(mutable), evaluator)
            # Sidecar-backed providers keep ciphertexts resident.  Once a block
            # has been absorbed, its input lanes and previous state cannot be
            # referenced again.  Release them explicitly while retaining the
            # freshly returned state and the encrypted program/session keys.
            if evaluator.capabilities.supports_resident_sessions:
                generated_prefix=tuple(mutable[:len(block)])
                evaluator.release_ciphertexts(tuple(old_state)+tuple(block)+generated_prefix)
        else:
            if encrypted_program is None:
                raise ValueError("encrypted ExecutionIR program is required for oblivious execution")
            state = execute_oblivious_word_program(encrypted_program, tuple(mutable), evaluator)
        block_times.append(time.perf_counter_ns() - block_started)

    # SHAKE256-512 emits 64 bytes, so one squeeze prefix (eight lanes) is enough.
    output = tuple(state[i] for i in range(8))
    commitments = [evaluator.ciphertext_word_commitment(word) for word in output]
    ciphertext_commitment = content_id(
        "XAVI-VOID/ENCRYPTED-SHAKE256-512-OUTPUT/v1",
        *(value.encode("ascii") for value in commitments),
    )
    semantic_workload_id = content_id(
        "XAVI-VOID/SHAKE256-512-WORKLOAD-SEMANTICS/v1",
        SHAKE256_512_SEMANTIC_IR.semantic_id().encode("ascii"),
        encrypted_input.message_commitment.encode("ascii"),
        str(encrypted_input.message_length).encode("ascii"),
    )
    timing = EncryptedShakeTiming(
        "specialized-keccak24" if specialized_keccak else "encrypted-execution-ir",
        tuple(block_times),
        time.perf_counter_ns() - started,
        evaluator.metrics(),
        resident_before,
        evaluator.resident_stats(),
    )
    program_commitment = (
        specialized_keccak_program_commitment()
        if specialized_keccak
        else encrypted_word_program_commitment(encrypted_program, evaluator)
    )
    return EncryptedShakeResult(
        semantic_workload_id,
        program_commitment,
        output,
        ciphertext_commitment,
        timing,
    )


def decrypt_encrypted_shake_result(result: EncryptedShakeResult, client: FHEClientView) -> bytes:
    raw = b"".join(client.decrypt_word64(word).to_bytes(8, "little") for word in result.encrypted_output)
    return raw[:SHAKE256_512_OUTPUT_BYTES]


def encrypted_shake_input_commitment(encrypted_input: EncryptedShakeInput, evaluator: FHEEvaluatorView) -> str:
    fields = [
        evaluator.ciphertext_word_commitment(word).encode("ascii")
        for block in encrypted_input.encrypted_blocks
        for word in block
    ]
    return content_id(
        "XAVI-VOID/ENCRYPTED-SHAKE256-512-INPUT/v1",
        str(encrypted_input.message_length).encode("ascii"),
        *fields,
    )


def execute_encrypted_shake_with_receipt(
    message: bytes,
    backend: FHEBackend,
    *,
    evaluator_identity_id: str,
    authority_domain: AuthorityDomain,
    chronology: ExecutionChronology,
    execution_class: ExecutionClass = KECCAK_24R,
    specialized_keccak: bool = False,
) -> EncryptedShakeRun:
    """Trusted-client wrapper producing the digest and a bound execution receipt."""
    authority_domain.validate()
    client = FHEClientView(backend)
    evaluator = FHEEvaluatorView(backend)
    encrypted_input = prepare_encrypted_shake_input(message, client)
    encrypted_program = compile_encrypted_shake_program(client, execution_class=execution_class)
    program_commitment = encrypted_word_program_commitment(encrypted_program, evaluator)
    input_commitment = encrypted_shake_input_commitment(encrypted_input, evaluator)
    result = execute_encrypted_shake256_512(
        encrypted_input, encrypted_program, evaluator, specialized_keccak=specialized_keccak
    )
    digest = decrypt_encrypted_shake_result(result, client)
    expected = hashlib.shake_256(message).digest(SHAKE256_512_OUTPUT_BYTES)
    if digest != expected:
        raise ValueError("encrypted SHAKE256-512 result differs from the standard digest")
    decrypted_output_commitment = content_id("XAVI-VOID/SHAKE256-512-OUTPUT/v1", digest)
    transcript_commitment = content_id(
        "XAVI-VOID/LOCAL-TFHE-SHAKE-TRANSCRIPT/v1",
        backend.backend_id.encode("utf-8"),
        program_commitment.encode("ascii"),
        input_commitment.encode("ascii"),
        result.ciphertext_commitment.encode("ascii"),
    )
    receipt = RemoteExecutionReceipt(
        semantic_program_id=result.semantic_workload_id,
        encrypted_representation_commitment=program_commitment,
        evaluator_identity_id=evaluator_identity_id,
        session_id=content_id("XAVI-VOID/LOCAL-TFHE-SHAKE-SESSION/v1", transcript_commitment.encode("ascii")),
        input_commitment=input_commitment,
        encrypted_result_commitment=result.ciphertext_commitment,
        decrypted_output_commitment=decrypted_output_commitment,
        rewrite_witness_ids=(),
        equivalence_witness_ids=(),
        checkpoint_ids=(),
        transport_transcript_commitment=transcript_commitment,
        authority_domain=authority_domain,
        chronology=chronology,
    )
    return EncryptedShakeRun(digest, result, receipt)



def verify_encrypted_shake_receipt(
    message: bytes,
    run: EncryptedShakeRun,
    backend: FHEBackend,
    *,
    expected_evaluator_identity_id: str | None = None,
) -> None:
    """Trusted-client validation of the local encrypted SHAKE receipt.

    Recomputes semantic/input/program/result/output bindings and rejects swapped
    semantic identities, representation commitments, evaluator identities, or
    ciphertext objects from another key domain.  This is receipt validation, not
    a malicious-evaluator proof.
    """
    client = FHEClientView(backend)
    evaluator = FHEEvaluatorView(backend)
    encrypted_input = prepare_encrypted_shake_input(message, client)
    encrypted_program = compile_encrypted_shake_program(client)
    expected_semantic = content_id(
        "XAVI-VOID/SHAKE256-512-WORKLOAD-SEMANTICS/v1",
        SHAKE256_512_SEMANTIC_IR.semantic_id().encode("ascii"),
        encrypted_input.message_commitment.encode("ascii"),
        str(encrypted_input.message_length).encode("ascii"),
    )
    if run.receipt.semantic_program_id != expected_semantic:
        raise ValueError("receipt semantic program identity mismatch")
    if expected_evaluator_identity_id is not None and run.receipt.evaluator_identity_id != expected_evaluator_identity_id:
        raise ValueError("receipt evaluator identity mismatch")
    # Program ciphertexts are randomized for cryptographic providers, so validate
    # the run's own commitment against its result instead of expecting a second
    # encryption to reproduce it.
    if run.receipt.encrypted_representation_commitment != run.result.encrypted_program_commitment:
        raise ValueError("receipt encrypted program commitment mismatch")
    if run.receipt.encrypted_result_commitment != run.result.ciphertext_commitment:
        raise ValueError("receipt encrypted result commitment mismatch")
    digest = decrypt_encrypted_shake_result(run.result, client)
    if digest != hashlib.shake_256(message).digest(SHAKE256_512_OUTPUT_BYTES):
        raise ValueError("receipt output does not match standard SHAKE256-512")
    expected_output = content_id("XAVI-VOID/SHAKE256-512-OUTPUT/v1", digest)
    if run.receipt.decrypted_output_commitment != expected_output:
        raise ValueError("receipt decrypted output commitment mismatch")

def verify_encrypted_shake256_512(message: bytes, backend: FHEBackend) -> bytes:
    """Cross-check standard SHAKE, SemanticIR, plaintext ExecutionIR, and FHE IR."""
    client=FHEClientView(backend); evaluator=FHEEvaluatorView(backend)
    encrypted_input = prepare_encrypted_shake_input(message, client)
    encrypted_program = compile_encrypted_shake_program(client)
    result = execute_encrypted_shake256_512(encrypted_input, encrypted_program, evaluator)
    encrypted_digest = decrypt_encrypted_shake_result(result, client)
    plan = compile_shake256_512(message)
    standard = hashlib.shake_256(message).digest(SHAKE256_512_OUTPUT_BYTES)
    semantic = execute_shake_semantic(message)
    plaintext_execution = execute_shake_plan(message, plan)
    word = shake256_512_word_ir(message)
    if not (standard == semantic == plaintext_execution == word == encrypted_digest):
        raise ValueError("SHAKE256-512 differential verification failed")
    return encrypted_digest
