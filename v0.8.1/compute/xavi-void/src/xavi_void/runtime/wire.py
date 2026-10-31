"""Canonical binary wire format for Boolean ExecutionIR.

The format is versioned, typed, length-framed and strictly decoded. Semantic
ordinals/register identifiers are always positive; physical byte lengths may be
zero because they are framing coordinates rather than semantic labels.
"""
from __future__ import annotations

from xavi_void.crypto.shake import content_id
from xavi_void.math.types import InstructionId, Ordinal, PositiveExtent, RegisterId
from .ir import ExecutionIR, Instruction, Op

MAGIC = b"XVOIDIR"
VERSION = 1
TYPE_EXECUTION_IR = 1
FIELD_REGISTER_COUNT = 1
FIELD_INSTRUCTIONS = 2
FIELD_OUTPUTS = 3
TYPE_INSTRUCTION = 2

_OP_TO_CODE = {
    Op.INPUT: 1, Op.CONST_FALSE: 2, Op.CONST_TRUE: 3, Op.XOR: 4,
    Op.AND: 5, Op.OR: 6, Op.NOT: 7, Op.COPY: 8,
}
_CODE_TO_OP = {value: key for key, value in _OP_TO_CODE.items()}


def _uvar(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvar cannot encode negative values")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _positive(value: int) -> bytes:
    if value < 1:
        raise ValueError("semantic positive integer must be >= 1")
    return _uvar(value)


def _field(tag: int, payload: bytes) -> bytes:
    return _positive(tag) + _uvar(len(payload)) + payload


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated wire value")
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def uvar(self) -> int:
        start = self.pos
        shift = 0
        value = 0
        while True:
            if self.pos >= len(self.data) or shift > 63:
                raise ValueError("invalid/truncated varint")
            byte = self.data[self.pos]; self.pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        raw = self.data[start:self.pos]
        if raw != _uvar(value):
            raise ValueError("non-canonical varint encoding")
        return value

    def positive(self) -> int:
        value = self.uvar()
        if value < 1:
            raise ValueError("semantic identifier encoded as nonpositive value")
        return value

    def field(self, expected_tag: int) -> bytes:
        tag = self.positive()
        if tag != expected_tag:
            raise ValueError(f"unexpected field tag {tag}; expected {expected_tag}")
        length = self.uvar()
        return self.take(length)

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise ValueError("trailing bytes after canonical value")


def _encode_instruction(instruction: Instruction) -> bytes:
    body = bytearray()
    body += _positive(TYPE_INSTRUCTION)
    body += _positive(instruction.instruction_id.value)
    body += _positive(instruction.destination.value)
    body += _positive(_OP_TO_CODE[instruction.op])
    body += _uvar(len(instruction.sources))
    for source in instruction.sources:
        body += _positive(source.value)
    if instruction.input_slot is None:
        body += _uvar(0)
    else:
        body += _uvar(1) + _positive(instruction.input_slot.value)
    return bytes(body)


def encode_execution_ir(program: ExecutionIR) -> bytes:
    program.validate()
    instructions = bytearray()
    instructions += _positive(len(program.instructions))
    for instruction in program.instructions:
        record = _encode_instruction(instruction)
        instructions += _uvar(len(record)) + record
    outputs = _positive(len(program.outputs)) + b"".join(_positive(output.value) for output in program.outputs)
    return (
        MAGIC + bytes([VERSION]) + _positive(TYPE_EXECUTION_IR)
        + _field(FIELD_REGISTER_COUNT, _positive(program.register_count.value))
        + _field(FIELD_INSTRUCTIONS, bytes(instructions))
        + _field(FIELD_OUTPUTS, outputs)
    )


def _decode_instruction(data: bytes) -> Instruction:
    r = _Reader(data)
    if r.positive() != TYPE_INSTRUCTION:
        raise ValueError("record is not an instruction")
    instruction_id = InstructionId(r.positive())
    destination = RegisterId(r.positive())
    try:
        op = _CODE_TO_OP[r.positive()]
    except KeyError as error:
        raise ValueError("unknown opcode tag") from error
    source_count = r.uvar()
    sources = tuple(RegisterId(r.positive()) for _ in range(source_count))
    input_present = r.uvar()
    if input_present not in (0, 1):
        raise ValueError("invalid optional input-slot discriminator")
    input_slot = Ordinal(r.positive()) if input_present else None
    r.finish()
    return Instruction(instruction_id, destination, op, sources, input_slot)


def decode_execution_ir(data: bytes) -> ExecutionIR:
    r = _Reader(data)
    if r.take(len(MAGIC)) != MAGIC:
        raise ValueError("invalid xavi-void wire magic")
    if r.take(1)[0] != VERSION:
        raise ValueError("unsupported wire version")
    if r.positive() != TYPE_EXECUTION_IR:
        raise ValueError("wire object is not ExecutionIR")

    rr = _Reader(r.field(FIELD_REGISTER_COUNT))
    register_count = PositiveExtent(rr.positive()); rr.finish()

    ir = _Reader(r.field(FIELD_INSTRUCTIONS))
    instruction_count = ir.positive()
    instructions: list[Instruction] = []
    for _ in range(instruction_count):
        length = ir.uvar()
        instructions.append(_decode_instruction(ir.take(length)))
    ir.finish()

    ordr = _Reader(r.field(FIELD_OUTPUTS))
    output_count = ordr.positive()
    outputs = tuple(RegisterId(ordr.positive()) for _ in range(output_count))
    ordr.finish(); r.finish()

    program = ExecutionIR(register_count, tuple(instructions), outputs)
    program.validate()
    if encode_execution_ir(program) != data:
        raise ValueError("wire value is not canonical")
    return program


def wire_commitment(program: ExecutionIR) -> str:
    return content_id("XAVI-VOID/CANONICAL-BINARY-EXECUTION-IR/v1", encode_execution_ir(program))
