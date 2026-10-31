"""One-origin Keccak-f[1600] and SHAKE256-512 reference implementation.

The cryptographic state uses standard 64-bit words and therefore naturally
contains mathematical/bitwise zero values. Semantic lane and round identifiers
are one-origin; zero-origin host offsets are private implementation coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass

from xavi_void.math.boundary import to_host_offset
from xavi_void.math.types import Ordinal, RoundId

MASK64 = (1 << 64) - 1
SHAKE256_RATE_BYTES = 136
SHAKE256_512_OUTPUT_BYTES = 64

# Rho offsets indexed by semantic coordinates x,y in 1..5 through lane().
_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)


@dataclass(frozen=True, slots=True)
class LaneCoordinate:
    x: Ordinal
    y: Ordinal

    def __post_init__(self) -> None:
        if self.x.value > 5 or self.y.value > 5:
            raise ValueError("Keccak lane coordinates must lie in semantic range 1..5")

    @property
    def semantic_lane(self) -> Ordinal:
        return Ordinal(self.x.value + 5 * (self.y.value - 1))

    @property
    def host_offset(self) -> int:
        return to_host_offset(self.semantic_lane)


def _lane(x: int, y: int) -> LaneCoordinate:
    return LaneCoordinate(Ordinal(x), Ordinal(y))


def _rotl64(value: int, amount: int) -> int:
    amount %= 64
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def keccak_f1600(state: list[int]) -> None:
    """Apply 24 one-origin-labeled Keccak rounds in place."""
    if len(state) != 25:
        raise ValueError("Keccak-f[1600] requires exactly 25 lanes")
    if any(value < 0 or value > MASK64 for value in state):
        raise ValueError("Keccak lanes must be unsigned 64-bit words")

    for round_value in range(1, 25):
        round_id = RoundId(round_value)
        # Theta: C[x] is parity down each semantic x-column.
        c = [0] * 5
        for x in range(1, 6):
            parity = 0
            for y in range(1, 6):
                parity ^= state[_lane(x, y).host_offset]
            c[x - 1] = parity
        d = [0] * 5
        for x in range(1, 6):
            left = c[(x - 2) % 5]
            right = c[x % 5]
            d[x - 1] = left ^ _rotl64(right, 1)
        for x in range(1, 6):
            for y in range(1, 6):
                offset = _lane(x, y).host_offset
                state[offset] = (state[offset] ^ d[x - 1]) & MASK64

        # Rho + Pi. The formulas are conventional Keccak coordinates expressed
        # through one-origin semantic labels at this API boundary.
        b = [0] * 25
        for x in range(1, 6):
            for y in range(1, 6):
                value = _rotl64(state[_lane(x, y).host_offset], _RHO[x - 1][y - 1])
                new_x = ((y - 1) % 5) + 1
                new_y = (((2 * (x - 1) + 3 * (y - 1)) % 5) + 1)
                b[_lane(new_x, new_y).host_offset] = value

        # Chi.
        for x in range(1, 6):
            for y in range(1, 6):
                a = b[_lane(x, y).host_offset]
                nxt = b[_lane((x % 5) + 1, y).host_offset]
                nxt2 = b[_lane(((x + 1) % 5) + 1, y).host_offset]
                state[_lane(x, y).host_offset] = (a ^ ((~nxt) & nxt2)) & MASK64

        # Iota. Round ids are semantic 1..24; host lookup translates once.
        state[_lane(1, 1).host_offset] ^= _ROUND_CONSTANTS[to_host_offset(round_id)]
        state[_lane(1, 1).host_offset] &= MASK64


def shake256_512(message: bytes) -> bytes:
    """Return SHAKE256(message, 512 bits) using the native reference sponge."""
    remainder = len(message) % SHAKE256_RATE_BYTES
    pad_bytes = SHAKE256_RATE_BYTES - remainder
    if pad_bytes == 1:
        padding = b"\x9f"  # SHAKE suffix 0x1f plus final pad bit 0x80.
    else:
        padding = b"\x1f" + (b"\x00" * (pad_bytes - 2)) + b"\x80"
    padded = message + padding

    state = [0] * 25
    for block_start in range(0, len(padded), SHAKE256_RATE_BYTES):
        block = padded[block_start:block_start + SHAKE256_RATE_BYTES]
        for lane_label in range(1, 18):  # 136 bytes / 8 = 17 rate lanes.
            lane = Ordinal(lane_label)
            start = to_host_offset(lane) * 8
            word = int.from_bytes(block[start:start + 8], "little")
            state[to_host_offset(lane)] ^= word
        keccak_f1600(state)

    output = bytearray()
    while len(output) < SHAKE256_512_OUTPUT_BYTES:
        for lane_label in range(1, 18):
            output.extend(state[to_host_offset(Ordinal(lane_label))].to_bytes(8, "little"))
            if len(output) >= SHAKE256_512_OUTPUT_BYTES:
                return bytes(output[:SHAKE256_512_OUTPUT_BYTES])
        keccak_f1600(state)
    return bytes(output[:SHAKE256_512_OUTPUT_BYTES])
