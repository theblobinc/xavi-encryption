"""Persistent encrypted evaluator sessions and checkpoint/resume support."""
from __future__ import annotations

from dataclasses import dataclass, field
import secrets
from typing import Mapping

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.types import Ordinal

from .encrypted import (
    CipherBit, CipherWord64, EncryptedProgram, EncryptedWordProgram, FHEEvaluatorView,
    oblivious_boolean_step, oblivious_word_step,
)


@dataclass(frozen=True, slots=True)
class SessionCheckpoint:
    session_id: str
    sequence: Ordinal
    next_instruction: Ordinal | None
    state_commitment: str
    checkpoint_id: str


@dataclass(frozen=True, slots=True)
class SessionResult:
    session_id: str
    sequence: Ordinal
    ciphertext_commitments: tuple[str, ...]
    checkpoint_ids: tuple[str, ...]


class SessionStateError(ValueError):
    pass


def new_session_id() -> str:
    nonce = secrets.token_bytes(32)
    return content_id("XAVI-VOID/EVALUATOR-SESSION/v1", nonce)


@dataclass(slots=True)
class BooleanEvaluatorSession:
    session_id: str
    backend: FHEEvaluatorView
    program: EncryptedProgram
    inputs: tuple[CipherBit, ...]
    bank: tuple[CipherBit, ...]
    next_index: int = 0
    sequence_value: int = 1
    cancelled: bool = False
    checkpoints: list[SessionCheckpoint] = field(default_factory=list)

    @classmethod
    def create(cls, program: EncryptedProgram, encrypted_inputs: Mapping[Ordinal, CipherBit], backend: FHEEvaluatorView) -> "BooleanEvaluatorSession":
        if program.backend_id != backend.backend_id:
            raise SessionStateError("program belongs to another backend")
        slots = sorted(encrypted_inputs, key=lambda x:x.value)
        if slots and [s.value for s in slots] != list(range(1,len(slots)+1)):
            raise SessionStateError("session input slots must be contiguous and one-origin")
        return cls(
            new_session_id(), backend, program, tuple(encrypted_inputs[s] for s in slots),
            tuple(backend.trivial_bit(False) for _ in range(program.register_count.value)),
        )

    @property
    def complete(self) -> bool:
        return self.next_index >= len(self.program.instructions)

    def run_chunk(self, max_instructions: int) -> Ordinal:
        self._live()
        if max_instructions < 1: raise SessionStateError("chunk size must be positive")
        end = min(len(self.program.instructions), self.next_index + max_instructions)
        for i in range(self.next_index, end):
            self.bank = oblivious_boolean_step(self.bank, self.program.instructions[i], self.inputs, self.backend)
        self.next_index = end
        result = Ordinal(self.sequence_value)
        self.sequence_value += 1
        return result

    def checkpoint(self) -> SessionCheckpoint:
        self._live()
        commitments = [self.backend.ciphertext_bit_commitment(x) for x in self.bank]
        state_commitment = content_id(
            "XAVI-VOID/ENCRYPTED-BOOLEAN-SESSION-STATE/v1",
            self.session_id.encode(), str(self.next_index).encode(),
            *(x.encode() for x in commitments),
        )
        seq = Ordinal(self.sequence_value); self.sequence_value += 1
        next_instruction = None if self.complete else Ordinal(self.next_index + 1)
        checkpoint_id = content_id(
            "XAVI-VOID/EVALUATOR-CHECKPOINT/v1",
            self.session_id.encode(), str(seq.value).encode(), state_commitment.encode(),
        )
        cp = SessionCheckpoint(self.session_id, seq, next_instruction, state_commitment, checkpoint_id)
        self.checkpoints.append(cp)
        return cp

    def finish(self) -> tuple[CipherBit, ...]:
        self._live()
        if not self.complete: raise SessionStateError("session has unexecuted instructions")
        return tuple(self.backend.select_bit(self.bank, out) for out in self.program.outputs)

    def cancel(self) -> None:
        self.cancelled = True

    def _live(self) -> None:
        if self.cancelled: raise SessionStateError("session is cancelled")


@dataclass(slots=True)
class WordEvaluatorSession:
    session_id: str
    backend: FHEEvaluatorView
    program: EncryptedWordProgram
    bank: tuple[CipherWord64, ...]
    next_index: int = 0
    sequence_value: int = 1
    cancelled: bool = False
    checkpoints: list[SessionCheckpoint] = field(default_factory=list)

    @classmethod
    def create(cls, program: EncryptedWordProgram, encrypted_state: tuple[CipherWord64, ...], backend: FHEEvaluatorView) -> "WordEvaluatorSession":
        if program.backend_id != backend.backend_id: raise SessionStateError("program belongs to another backend")
        if len(encrypted_state) != 25: raise SessionStateError("word session requires 25 state words")
        bank = encrypted_state + tuple(backend.trivial_word64(0) for _ in range(program.register_count.value-25))
        return cls(new_session_id(), backend, program, bank)

    @property
    def complete(self) -> bool: return self.next_index >= len(self.program.instructions)

    def run_chunk(self, max_instructions: int) -> Ordinal:
        self._live()
        if max_instructions < 1: raise SessionStateError("chunk size must be positive")
        end = min(len(self.program.instructions), self.next_index + max_instructions)
        for i in range(self.next_index,end): self.bank = oblivious_word_step(self.bank,self.program.instructions[i],self.backend)
        self.next_index=end; seq=Ordinal(self.sequence_value); self.sequence_value += 1; return seq

    def checkpoint(self) -> SessionCheckpoint:
        self._live()
        commitments=[self.backend.ciphertext_word_commitment(x) for x in self.bank]
        state_commitment=content_id("XAVI-VOID/ENCRYPTED-WORD-SESSION-STATE/v1",self.session_id.encode(),str(self.next_index).encode(),*(x.encode() for x in commitments))
        seq=Ordinal(self.sequence_value); self.sequence_value += 1
        next_instruction=None if self.complete else Ordinal(self.next_index+1)
        checkpoint_id=content_id("XAVI-VOID/EVALUATOR-CHECKPOINT/v1",self.session_id.encode(),str(seq.value).encode(),state_commitment.encode())
        cp=SessionCheckpoint(self.session_id,seq,next_instruction,state_commitment,checkpoint_id); self.checkpoints.append(cp); return cp

    def finish_state(self) -> tuple[CipherWord64, ...]:
        self._live()
        if not self.complete: raise SessionStateError("session has unexecuted instructions")
        return tuple(self.bank[:25])

    def cancel(self) -> None: self.cancelled=True
    def _live(self) -> None:
        if self.cancelled: raise SessionStateError("session is cancelled")


class SessionManager:
    """Bounded in-process session cache. Real remote workers can persist the same state."""
    def __init__(self, max_sessions: int = 16) -> None:
        if max_sessions < 1: raise ValueError("max_sessions must be positive")
        self.max_sessions=max_sessions; self._sessions: dict[str, object]={}; self._checkpoints: dict[str, tuple[str,int,tuple]]={}

    def add(self, session: BooleanEvaluatorSession | WordEvaluatorSession) -> None:
        if len(self._sessions) >= self.max_sessions and session.session_id not in self._sessions:
            raise SessionStateError("session cache is full")
        self._sessions[session.session_id]=session

    def get(self, session_id: str) -> BooleanEvaluatorSession | WordEvaluatorSession:
        try: return self._sessions[session_id]  # type: ignore[return-value]
        except KeyError as e: raise SessionStateError("unknown session") from e

    def save_checkpoint(self, session_id: str) -> SessionCheckpoint:
        session=self.get(session_id); cp=session.checkpoint()
        bank=tuple(session.bank)
        self._checkpoints[cp.checkpoint_id]=(session_id,session.next_index,bank)
        return cp

    def recover(self, checkpoint_id: str) -> None:
        try: session_id,next_index,bank=self._checkpoints[checkpoint_id]
        except KeyError as e: raise SessionStateError("unknown checkpoint") from e
        session=self.get(session_id); session.bank=bank; session.next_index=next_index; session.cancelled=False

    def cancel(self, session_id: str) -> None: self.get(session_id).cancel()
    def evict(self, session_id: str) -> None: self._sessions.pop(session_id,None)
