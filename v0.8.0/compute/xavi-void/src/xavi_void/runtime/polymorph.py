"""Deterministic, witness-bearing representation polymorphism."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Sequence

from xavi_void.crypto.shake import canonical_bytes, content_id, framed_shake256_512
from xavi_void.math.boundary import to_host_offset
from xavi_void.math.types import PositiveExtent, RegisterId

from .behavior import EquivalenceWitness, prove_equivalent
from .ir import ExecutionIR, Instruction


def permute_registers(program: ExecutionIR, permutation: Sequence[RegisterId]) -> ExecutionIR:
    program.validate()
    if len(permutation) != program.register_count.value:
        raise ValueError("permutation must cover every register")
    if not all(isinstance(item, RegisterId) for item in permutation):
        raise TypeError("permutation elements must be RegisterId")
    values = [item.value for item in permutation]
    if set(values) != set(range(1, program.register_count.value + 1)):
        raise ValueError("permutation must be a bijection over 1..register_count")

    def remap(index: RegisterId) -> RegisterId:
        return permutation[to_host_offset(index)]

    instructions = tuple(
        replace(
            instruction,
            destination=remap(instruction.destination),
            sources=tuple(remap(source) for source in instruction.sources),
        )
        for instruction in program.instructions
    )
    morphed = ExecutionIR(
        register_count=PositiveExtent(program.register_count.value),
        instructions=instructions,
        outputs=tuple(remap(output) for output in program.outputs),
    )
    morphed.validate()
    return morphed


class _ShakeStream:
    def __init__(self, program_id: str, seed: bytes) -> None:
        if not seed:
            raise ValueError("polymorphism seed must not be empty")
        self._program_id = program_id.encode("ascii")
        self._seed = seed
        self._buffer = bytearray()
        self._block = 1

    def read(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._buffer.extend(
                framed_shake256_512(
                    "XAVI-VOID/POLYMORPH-RNG-BLOCK/v1",
                    (self._program_id, self._seed, str(self._block).encode("ascii")),
                )
            )
            self._block += 1
        out = bytes(self._buffer[:count])
        del self._buffer[:count]
        return out

    def randbelow(self, upper: int) -> int:
        if upper < 1:
            raise ValueError("upper bound must be positive")
        if upper == 1:
            return 0
        width = max(1, (upper.bit_length() + 7) // 8)
        space = 1 << (8 * width)
        cutoff = space - (space % upper)
        while True:
            candidate = int.from_bytes(self.read(width), "big")
            if candidate < cutoff:
                return candidate % upper


def derive_register_permutation(program: ExecutionIR, seed: bytes) -> tuple[RegisterId, ...]:
    program.validate()
    original = list(range(1, program.register_count.value + 1))
    stream = _ShakeStream(program.representation_id(), seed)
    if len(original) == 1:
        return (RegisterId(1),)
    # Rejection sampling over complete Fisher-Yates permutations guarantees a
    # genuine morph while remaining uniform over the non-identity permutations.
    while True:
        values = list(original)
        for host_i in range(len(values) - 1, 0, -1):
            host_j = stream.randbelow(host_i + 1)
            values[host_i], values[host_j] = values[host_j], values[host_i]
        if values != original:
            return tuple(RegisterId(value) for value in values)


@dataclass(frozen=True, slots=True)
class MorphWitness:
    source_representation_id: str
    target_representation_id: str
    behavior_id: str
    equivalence_witness_id: str
    strategy: str
    seed_commitment: str
    permutation: tuple[int, ...]

    def witness_id(self) -> str:
        return content_id(
            "XAVI-VOID/POLYMORPH-WITNESS/v1",
            canonical_bytes(
                {
                    "source_representation_id": self.source_representation_id,
                    "target_representation_id": self.target_representation_id,
                    "behavior_id": self.behavior_id,
                    "equivalence_witness_id": self.equivalence_witness_id,
                    "strategy": self.strategy,
                    "seed_commitment": self.seed_commitment,
                    "permutation": list(self.permutation),
                }
            ),
        )


def deterministic_register_morph(
    program: ExecutionIR,
    seed: bytes,
    *,
    max_exact_inputs: int = 12,
) -> tuple[ExecutionIR, MorphWitness, EquivalenceWitness]:
    permutation = derive_register_permutation(program, seed)
    morphed = permute_registers(program, permutation)
    equivalence = prove_equivalent(program, morphed, max_inputs=max_exact_inputs)
    witness = MorphWitness(
        source_representation_id=program.representation_id(),
        target_representation_id=morphed.representation_id(),
        behavior_id=equivalence.behavior_id,
        equivalence_witness_id=equivalence.witness_id(),
        strategy="shake256-512-register-permutation",
        seed_commitment=content_id("XAVI-VOID/POLYMORPH-SEED/v1", seed),
        permutation=tuple(item.value for item in permutation),
    )
    return morphed, witness, equivalence
