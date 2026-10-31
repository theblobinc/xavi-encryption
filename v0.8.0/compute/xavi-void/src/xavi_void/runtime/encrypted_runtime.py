"""High-level encrypted execution orchestration and witnessed receipts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import semantic_bit_label
from xavi_void.math.types import Ordinal
from xavi_void.witness.domain import AuthorityDomain

from .encrypted import (
    CipherBit, FHEClientView, FHEEvaluatorView, decrypt_encrypted_id, encrypt_program_representation,
    encrypted_program_commitment,
)
from .ir import ExecutionIR
from .privacy import ExecutionClass
from .receipt import ExecutionChronology
from .remote_receipt import RemoteExecutionReceipt
from .session import BooleanEvaluatorSession, SessionManager


@dataclass(frozen=True,slots=True)
class EncryptedBooleanRun:
    outputs:tuple[bool,...]
    receipt:RemoteExecutionReceipt


def execute_encrypted_boolean_with_receipt(
    program:ExecutionIR,
    plaintext_inputs:Mapping[Ordinal,bool],
    *,
    client:FHEClientView,
    evaluator:FHEEvaluatorView,
    execution_class:ExecutionClass,
    evaluator_identity_id:str,
    authority_domain:AuthorityDomain,
    chronology:ExecutionChronology,
    rewrite_witness_ids:Sequence[str]=(),
    equivalence_witness_ids:Sequence[str]=(),
)->EncryptedBooleanRun:
    program.validate(); authority_domain.validate()
    execution_class.validate_program_shape(instruction_count=len(program.instructions),register_count=program.register_count.value)
    encrypted_program=encrypt_program_representation(
        program,client,
        padded_instruction_count=execution_class.padded_instruction_count.value,
        padded_register_count=execution_class.register_bank_size.value,
    )
    encrypted_inputs={slot:client.encrypt_bit(value) for slot,value in plaintext_inputs.items()}
    input_commitment=content_id(
        "XAVI-VOID/ENCRYPTED-INPUT-SET/v1",
        *(
            evaluator.ciphertext_bit_commitment(encrypted_inputs[slot]).encode("ascii")
            for slot in sorted(encrypted_inputs,key=lambda s:s.value)
        ),
    )
    session=BooleanEvaluatorSession.create(encrypted_program,encrypted_inputs,evaluator)
    manager=SessionManager();manager.add(session)
    checkpoints=[]
    batch=execution_class.batch_size.value
    batch_ordinal=0
    while not session.complete:
        session.run_chunk(batch);batch_ordinal+=1
        if batch_ordinal % execution_class.checkpoint_interval_batches.value == 0 or session.complete:
            checkpoints.append(manager.save_checkpoint(session.session_id).checkpoint_id)
    encrypted_outputs=session.finish()
    encrypted_result_commitment=content_id(
        "XAVI-VOID/ENCRYPTED-RESULT-SET/v1",
        *(evaluator.ciphertext_bit_commitment(value).encode("ascii") for value in encrypted_outputs),
    )
    outputs=tuple(client.decrypt_bit(value) for value in encrypted_outputs)
    decrypted_output_commitment=content_id(
        "XAVI-VOID/DECRYPTED-OUTPUT/v1",
        canonical_bytes([semantic_bit_label(x) for x in outputs]),
    )
    transcript_commitment=content_id(
        "XAVI-VOID/LOCAL-ENCRYPTED-SESSION-TRANSCRIPT/v1",
        session.session_id.encode(),
        *(checkpoint.encode() for checkpoint in checkpoints),
    )
    receipt=RemoteExecutionReceipt(
        semantic_program_id=decrypt_encrypted_id(encrypted_program.encrypted_semantic_id,client),
        encrypted_representation_commitment=encrypted_program_commitment(encrypted_program,evaluator),
        evaluator_identity_id=evaluator_identity_id,
        session_id=session.session_id,
        input_commitment=input_commitment,
        encrypted_result_commitment=encrypted_result_commitment,
        decrypted_output_commitment=decrypted_output_commitment,
        rewrite_witness_ids=tuple(rewrite_witness_ids),
        equivalence_witness_ids=tuple(equivalence_witness_ids),
        checkpoint_ids=tuple(checkpoints),
        transport_transcript_commitment=transcript_commitment,
        authority_domain=authority_domain,
        chronology=chronology,
    )
    return EncryptedBooleanRun(outputs,receipt)
