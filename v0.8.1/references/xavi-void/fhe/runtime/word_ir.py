"""Reusable typed 64-bit ExecutionIR for Keccak-f[1600].

The same fixed 24-round body is reused for every absorb/squeeze step. Message
length never duplicates the permutation body.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from xavi_void.crypto.keccak import MASK64, SHAKE256_512_OUTPUT_BYTES, SHAKE256_RATE_BYTES
from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import to_host_offset
from xavi_void.math.types import InstructionId, PositiveExtent, RegisterId, RoundId

_RHO = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_ROUND_CONSTANTS = (
    0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
    0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
    0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
    0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
    0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
    0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008,
)

WORD_REGISTER_COUNT = 60
STATE_REGISTER_COUNT = 25
RATE_LANE_COUNT = 17


class WordOp(str, Enum):
    XOR5 = "XOR5"
    XOR_ROT1 = "XOR_ROT1"
    XOR2 = "XOR2"
    ROT_COPY = "ROT_COPY"
    CHI = "CHI"
    XOR_CONST = "XOR_CONST"


@dataclass(frozen=True, slots=True)
class WordInstruction:
    instruction_id: InstructionId
    round_id: RoundId
    destination: RegisterId
    op: WordOp
    sources: tuple[RegisterId, ...]
    rotate: int | None = None
    immediate: int | None = None

    def canonical(self) -> dict:
        return {
            "instruction_id": self.instruction_id.value,
            "round_id": self.round_id.value,
            "destination": self.destination.value,
            "op": self.op.value,
            "sources": [source.value for source in self.sources],
            "rotate": self.rotate,
            "immediate": self.immediate,
        }


@dataclass(frozen=True, slots=True)
class WordProgram:
    register_count: PositiveExtent
    instructions: tuple[WordInstruction, ...]

    def validate(self) -> None:
        if not isinstance(self.register_count, PositiveExtent):
            raise TypeError("word register_count must be PositiveExtent")
        if self.register_count.value != WORD_REGISTER_COUNT:
            raise ValueError(f"Keccak word program requires {WORD_REGISTER_COUNT} registers")
        if [i.instruction_id.value for i in self.instructions] != list(range(1, len(self.instructions) + 1)):
            raise ValueError("word instruction ids must be contiguous and one-origin")
        for instruction in self.instructions:
            if not isinstance(instruction.instruction_id, InstructionId):
                raise TypeError("word instruction id must be InstructionId")
            if not isinstance(instruction.round_id, RoundId) or instruction.round_id.value > 24:
                raise ValueError("Keccak round ids must lie in 1..24")
            if not isinstance(instruction.destination, RegisterId):
                raise TypeError("word destination must be RegisterId")
            if not all(isinstance(source, RegisterId) for source in instruction.sources):
                raise TypeError("word sources must be RegisterId")
            if instruction.destination.value > self.register_count.value:
                raise ValueError("word destination outside register domain")
            if any(source.value > self.register_count.value for source in instruction.sources):
                raise ValueError("word source outside register domain")
            if instruction.op == WordOp.XOR5 and len(instruction.sources) != 5:
                raise ValueError("XOR5 requires five sources")
            if instruction.op in {WordOp.XOR_ROT1, WordOp.XOR2} and len(instruction.sources) != 2:
                raise ValueError(f"{instruction.op.value} requires two sources")
            if instruction.op == WordOp.ROT_COPY:
                if len(instruction.sources) != 1 or instruction.rotate is None:
                    raise ValueError("ROT_COPY requires one source and rotation")
                if not 0 <= instruction.rotate < 64:
                    raise ValueError("rotation is a physical displacement and must lie in 0..63")
            elif instruction.rotate is not None:
                raise ValueError("rotation field only valid for ROT_COPY")
            if instruction.op == WordOp.CHI and len(instruction.sources) != 3:
                raise ValueError("CHI requires three sources")
            if instruction.op == WordOp.XOR_CONST:
                if len(instruction.sources) != 1 or instruction.immediate is None:
                    raise ValueError("XOR_CONST requires one source and immediate")
                if not 0 <= instruction.immediate <= MASK64:
                    raise ValueError("immediate must be an unsigned 64-bit word")
            elif instruction.immediate is not None:
                raise ValueError("immediate field only valid for XOR_CONST")

    def representation_id(self) -> str:
        self.validate()
        return content_id(
            "XAVI-VOID/KECCAK-WORD-EXECUTION-IR/v1",
            canonical_bytes({
                "register_count": self.register_count.value,
                "instructions": [instruction.canonical() for instruction in self.instructions],
            }),
        )


def _rotl64(value: int, amount: int) -> int:
    amount %= 64
    return value & MASK64 if amount == 0 else ((value << amount) | (value >> (64 - amount))) & MASK64


def _state(x: int, y: int) -> RegisterId:
    if not (1 <= x <= 5 and 1 <= y <= 5):
        raise ValueError("Keccak coordinates must lie in semantic range 1..5")
    return RegisterId(x + 5 * (y - 1))


def _c(x: int) -> RegisterId: return RegisterId(25 + x)
def _d(x: int) -> RegisterId: return RegisterId(30 + x)
def _b(x: int, y: int) -> RegisterId: return RegisterId(35 + x + 5 * (y - 1))


def build_keccak_word_program() -> WordProgram:
    instructions: list[WordInstruction] = []

    def emit(round_id: RoundId, destination: RegisterId, op: WordOp, sources: tuple[RegisterId, ...], *, rotate: int | None = None, immediate: int | None = None) -> None:
        instructions.append(WordInstruction(
            InstructionId(len(instructions) + 1), round_id, destination, op, sources, rotate, immediate
        ))

    for round_value in range(1, 25):
        round_id = RoundId(round_value)
        for x in range(1, 6):
            emit(round_id, _c(x), WordOp.XOR5, tuple(_state(x, y) for y in range(1, 6)))
        for x in range(1, 6):
            left_x, right_x = (5 if x == 1 else x - 1), (1 if x == 5 else x + 1)
            emit(round_id, _d(x), WordOp.XOR_ROT1, (_c(left_x), _c(right_x)))
        for x in range(1, 6):
            for y in range(1, 6):
                emit(round_id, _state(x, y), WordOp.XOR2, (_state(x, y), _d(x)))
        for x in range(1, 6):
            for y in range(1, 6):
                new_x, new_y = y, ((2 * (x - 1) + 3 * (y - 1)) % 5) + 1
                emit(round_id, _b(new_x, new_y), WordOp.ROT_COPY, (_state(x, y),), rotate=_RHO[x - 1][y - 1])
        for x in range(1, 6):
            right1, right2 = (1 if x == 5 else x + 1), ((x + 1) % 5) + 1
            for y in range(1, 6):
                emit(round_id, _state(x, y), WordOp.CHI, (_b(x, y), _b(right1, y), _b(right2, y)))
        emit(round_id, _state(1, 1), WordOp.XOR_CONST, (_state(1, 1),), immediate=_ROUND_CONSTANTS[round_value - 1])

    program = WordProgram(PositiveExtent(WORD_REGISTER_COUNT), tuple(instructions))
    program.validate()
    return program


KECCAK_WORD_PROGRAM = build_keccak_word_program()


def execute_word_program(state: list[int], program: WordProgram = KECCAK_WORD_PROGRAM) -> list[int]:
    program.validate()
    if len(state) != STATE_REGISTER_COUNT:
        raise ValueError("Keccak state requires exactly 25 words")
    if any(value < 0 or value > MASK64 for value in state):
        raise ValueError("state words must be unsigned 64-bit integers")
    registers = list(state) + [0] * (program.register_count.value - STATE_REGISTER_COUNT)
    def read(index: RegisterId) -> int: return registers[to_host_offset(index)]
    for instruction in program.instructions:
        values = tuple(read(source) for source in instruction.sources)
        if instruction.op == WordOp.XOR5:
            result = values[0] ^ values[1] ^ values[2] ^ values[3] ^ values[4]
        elif instruction.op == WordOp.XOR_ROT1:
            result = values[0] ^ _rotl64(values[1], 1)
        elif instruction.op == WordOp.XOR2:
            result = values[0] ^ values[1]
        elif instruction.op == WordOp.ROT_COPY:
            assert instruction.rotate is not None; result = _rotl64(values[0], instruction.rotate)
        elif instruction.op == WordOp.CHI:
            result = values[0] ^ ((~values[1]) & values[2])
        elif instruction.op == WordOp.XOR_CONST:
            assert instruction.immediate is not None; result = values[0] ^ instruction.immediate
        else:  # pragma: no cover
            raise AssertionError("unreachable word opcode")
        registers[to_host_offset(instruction.destination)] = result & MASK64
    return registers[:STATE_REGISTER_COUNT]


def shake_padding(message: bytes) -> bytes:
    remainder = len(message) % SHAKE256_RATE_BYTES
    pad_bytes = SHAKE256_RATE_BYTES - remainder
    if pad_bytes == 1:
        return message + b"\x9f"
    return message + b"\x1f" + (b"\x00" * (pad_bytes - 2)) + b"\x80"


def shake256_512_word_ir(message: bytes, program: WordProgram = KECCAK_WORD_PROGRAM) -> bytes:
    padded = shake_padding(message)
    state = [0] * STATE_REGISTER_COUNT
    for block_start in range(0, len(padded), SHAKE256_RATE_BYTES):
        block = padded[block_start:block_start + SHAKE256_RATE_BYTES]
        for lane_value in range(1, RATE_LANE_COUNT + 1):
            lane = RegisterId(lane_value)
            host_start = to_host_offset(lane) * 8
            state[to_host_offset(lane)] ^= int.from_bytes(block[host_start:host_start + 8], "little")
        state = execute_word_program(state, program)
    output = bytearray()
    while len(output) < SHAKE256_512_OUTPUT_BYTES:
        for lane_value in range(1, RATE_LANE_COUNT + 1):
            lane = RegisterId(lane_value)
            output.extend(state[to_host_offset(lane)].to_bytes(8, "little"))
            if len(output) >= SHAKE256_512_OUTPUT_BYTES:
                return bytes(output[:SHAKE256_512_OUTPUT_BYTES])
        state = execute_word_program(state, program)
    return bytes(output[:SHAKE256_512_OUTPUT_BYTES])
