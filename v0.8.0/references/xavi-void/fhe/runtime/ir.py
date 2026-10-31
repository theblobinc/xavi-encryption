"""Typed one-origin Boolean ExecutionIR.

ExecutionIR is deliberately representation-bearing: register allocation, temporary
layout and instruction order belong here. Meaning lives in ``runtime.semantic``.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import semantic_bit_label
from xavi_void.math.types import InstructionId, Ordinal, PositiveExtent, RegisterId, require_type


class Op(str, Enum):
    INPUT = "INPUT"
    CONST_FALSE = "CONST_FALSE"
    CONST_TRUE = "CONST_TRUE"
    XOR = "XOR"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    COPY = "COPY"


@dataclass(frozen=True, slots=True)
class Instruction:
    instruction_id: InstructionId
    destination: RegisterId
    op: Op
    sources: tuple[RegisterId, ...] = ()
    input_slot: Ordinal | None = None

    def __post_init__(self) -> None:
        require_type(self.instruction_id, InstructionId, "instruction_id")
        require_type(self.destination, RegisterId, "destination")
        for source in self.sources:
            require_type(source, RegisterId, "source")
        if self.input_slot is not None:
            require_type(self.input_slot, Ordinal, "input_slot")

    def canonical(self) -> dict:
        return {
            "instruction_id": self.instruction_id.value,
            "destination": self.destination.value,
            "op": self.op.value,
            "sources": [source.value for source in self.sources],
            "input_slot": None if self.input_slot is None else self.input_slot.value,
        }


@dataclass(frozen=True, slots=True)
class ExecutionIR:
    register_count: PositiveExtent
    instructions: tuple[Instruction, ...]
    outputs: tuple[RegisterId, ...]

    def __post_init__(self) -> None:
        require_type(self.register_count, PositiveExtent, "register_count")
        for output in self.outputs:
            require_type(output, RegisterId, "output")

    def validate(self) -> None:
        if not self.instructions:
            raise ValueError("execution IR requires at least one instruction")
        if not self.outputs:
            raise ValueError("execution IR requires at least one output")

        expected = list(range(1, len(self.instructions) + 1))
        actual = [instruction.instruction_id.value for instruction in self.instructions]
        if actual != expected:
            raise ValueError("instruction ids must be contiguous and one-origin")

        written: set[int] = set()
        input_slots: list[int] = []
        for instruction in self.instructions:
            destination = instruction.destination.value
            if destination > self.register_count.value:
                raise ValueError("destination register outside declared register domain")
            if destination in written:
                raise ValueError("ExecutionIR is single-assignment; register written more than once")
            if any(source.value > self.register_count.value for source in instruction.sources):
                raise ValueError("source register outside declared register domain")
            self._validate_arity(instruction)
            for source in instruction.sources:
                if source.value not in written:
                    raise ValueError(
                        f"register {source.value} read before write at instruction "
                        f"{instruction.instruction_id.value}"
                    )
            if instruction.op == Op.INPUT:
                assert instruction.input_slot is not None
                input_slots.append(instruction.input_slot.value)
            written.add(destination)

        if len(set(input_slots)) != len(input_slots):
            raise ValueError("input slots must be unique")
        if input_slots and sorted(input_slots) != list(range(1, len(input_slots) + 1)):
            raise ValueError("input slots must form contiguous one-origin domain 1..N")

        for output in self.outputs:
            if output.value > self.register_count.value:
                raise ValueError("output register outside declared register domain")
            if output.value not in written:
                raise ValueError("output register is never written")

    @staticmethod
    def _validate_arity(instruction: Instruction) -> None:
        if instruction.op == Op.INPUT:
            if instruction.input_slot is None or instruction.sources:
                raise ValueError("INPUT requires one input_slot and no sources")
        elif instruction.op in {Op.CONST_FALSE, Op.CONST_TRUE}:
            if instruction.sources or instruction.input_slot is not None:
                raise ValueError("constant instruction accepts no sources or input slot")
        elif instruction.op in {Op.NOT, Op.COPY}:
            if len(instruction.sources) != 1 or instruction.input_slot is not None:
                raise ValueError(f"{instruction.op.value} requires exactly one source")
        elif instruction.op in {Op.XOR, Op.AND, Op.OR}:
            if len(instruction.sources) != 2 or instruction.input_slot is not None:
                raise ValueError(f"{instruction.op.value} requires exactly two sources")
        else:  # pragma: no cover
            raise ValueError("unknown opcode")

    def input_slots(self) -> tuple[Ordinal, ...]:
        self.validate()
        values = sorted(
            instruction.input_slot.value
            for instruction in self.instructions
            if instruction.op == Op.INPUT and instruction.input_slot is not None
        )
        return tuple(Ordinal(value) for value in values)

    def canonical(self) -> dict:
        return {
            "register_count": self.register_count.value,
            "instructions": [instruction.canonical() for instruction in self.instructions],
            "outputs": [output.value for output in self.outputs],
        }

    def representation_id(self) -> str:
        self.validate()
        return content_id(
            "XAVI-VOID/BOOLEAN-EXECUTION-IR-REPRESENTATION/v1",
            canonical_bytes(self.canonical()),
        )

    def semantic_id(self) -> str:
        """Compatibility shim; callers should use ``semantic_from_execution``."""
        from .semantic import semantic_from_execution
        return semantic_from_execution(self).semantic_id()


# Rev 1.1-dev2 compatibility name. New code should say ExecutionIR.
Program = ExecutionIR


@dataclass(frozen=True, slots=True)
class Evaluation:
    outputs: tuple[bool, ...]
    trace_commitment: str


def evaluate(program: ExecutionIR, inputs: Mapping[Ordinal, bool]) -> Evaluation:
    program.validate()
    expected_inputs = set(program.input_slots())
    if any(not isinstance(slot, Ordinal) for slot in inputs):
        raise TypeError("ExecutionIR input keys must be Ordinal")
    supplied_inputs = set(inputs)
    missing = sorted(slot.value for slot in expected_inputs - supplied_inputs)
    extra = sorted(slot.value for slot in supplied_inputs - expected_inputs)
    if missing:
        raise ValueError(f"missing one-origin input slots: {missing}")
    if extra:
        raise ValueError(f"unexpected input slots: {extra}")
    if any(type(value) is not bool for value in inputs.values()):
        raise TypeError("Boolean ExecutionIR inputs must be bool values")

    registers: dict[int, bool] = {}
    trace_rows: list[dict] = []

    def read(register: RegisterId) -> bool:
        if register.value not in registers:
            raise ValueError(f"register {register.value} read before write")
        return registers[register.value]

    for instruction in program.instructions:
        if instruction.op == Op.INPUT:
            assert instruction.input_slot is not None
            result = inputs[instruction.input_slot]
        elif instruction.op == Op.CONST_FALSE:
            result = False
        elif instruction.op == Op.CONST_TRUE:
            result = True
        elif instruction.op == Op.NOT:
            result = not read(instruction.sources[0])
        elif instruction.op == Op.COPY:
            result = read(instruction.sources[0])
        elif instruction.op == Op.XOR:
            result = read(instruction.sources[0]) ^ read(instruction.sources[1])
        elif instruction.op == Op.AND:
            result = read(instruction.sources[0]) and read(instruction.sources[1])
        elif instruction.op == Op.OR:
            result = read(instruction.sources[0]) or read(instruction.sources[1])
        else:  # pragma: no cover
            raise AssertionError("unreachable opcode")

        registers[instruction.destination.value] = result
        trace_rows.append(
            {
                "instruction": instruction.instruction_id.value,
                "destination": instruction.destination.value,
                "result": semantic_bit_label(result),
            }
        )

    outputs = tuple(read(output) for output in program.outputs)
    trace_commitment = content_id(
        "XAVI-VOID/EXECUTION-TRACE/v1",
        program.representation_id().encode("ascii"),
        canonical_bytes(trace_rows),
    )
    return Evaluation(outputs=outputs, trace_commitment=trace_commitment)
