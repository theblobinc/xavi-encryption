"""Unity-origin ordinal, residue, and product-state mathematics.

All semantic labels are positive and one-origin.  No semantic coordinate uses a
numeric zero.  Raw host offsets are handled only by ``math.boundary``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .state import PositiveBijective


@dataclass(frozen=True, slots=True, order=True)
class PositiveIndex:
    value: int

    def __post_init__(self) -> None:
        if self.value < 1:
            raise ValueError("semantic indices are unity-origin and must be >= 1")


@dataclass(frozen=True, slots=True)
class UnityResidue:
    """A one-origin cyclic state in the closed label set ``1..modulus``."""

    modulus: int
    label: PositiveIndex

    def __post_init__(self) -> None:
        if self.modulus < 1:
            raise ValueError("modulus must be >= 1")
        if self.label.value > self.modulus:
            raise ValueError("unity residue label must lie in 1..modulus")


def ulabel(label: int, modulus: int) -> UnityResidue:
    """Construct a semantic cyclic label directly; both arguments are positive."""
    if modulus < 1:
        raise ValueError("modulus must be >= 1")
    if label < 1:
        raise ValueError("unity residue labels begin at 1")
    wrapped = label
    while wrapped > modulus:
        wrapped -= modulus
    return UnityResidue(modulus, PositiveIndex(wrapped))


def uadd(left: UnityResidue, right: UnityResidue) -> UnityResidue:
    """Unity-origin cyclic addition with ``1`` as the additive origin."""
    _same_modulus(left, right)
    value = left.label.value + right.label.value - 1
    while value > left.modulus:
        value -= left.modulus
    return UnityResidue(left.modulus, PositiveIndex(value))


def usub(left: UnityResidue, right: UnityResidue) -> UnityResidue:
    _same_modulus(left, right)
    value = left.label.value - right.label.value + 1
    while value < 1:
        value += left.modulus
    return UnityResidue(left.modulus, PositiveIndex(value))


def umul(left: UnityResidue, right: UnityResidue) -> UnityResidue:
    """Unity-origin cyclic product without a zero-valued semantic residue."""
    _same_modulus(left, right)
    # ((a-1)(b-1))+1, expanded so the represented value remains >= 1.
    value = left.label.value * right.label.value - left.label.value - right.label.value + 2
    while value > left.modulus:
        value -= left.modulus
    return UnityResidue(left.modulus, PositiveIndex(value))


def _same_modulus(left: UnityResidue, right: UnityResidue) -> None:
    if left.modulus != right.modulus:
        raise ValueError("unity residues use different moduli")


def fixed_length_rank(word: PositiveBijective) -> PositiveIndex:
    """One-origin rank for a fixed-length bijective word."""
    rank = 1
    length = len(word.digits)
    for position, digit in enumerate(word.digits, start=1):
        exponent = length - position
        if digit > 1:
            rank += (digit - 1) * (word.base ** exponent)
    return PositiveIndex(rank)


def minimum_fixed_length_value(base: int, length: int) -> int:
    if base < 2 or length < 1:
        raise ValueError("base >= 2 and length >= 1 required")
    return sum(base ** (position - 1) for position in range(1, length + 1))


def fixed_length_unrank(rank: PositiveIndex, *, base: int, length: int) -> PositiveBijective:
    """Inverse of :func:`fixed_length_rank` using only positive sub-ranks."""
    if base < 2 or length < 1:
        raise ValueError("base >= 2 and length >= 1 required")
    maximum = base ** length
    if rank.value > maximum:
        raise ValueError("rank outside fixed-length bijective domain")

    remaining = rank.value
    digits: list[int] = []
    for position in range(1, length + 1):
        remaining_places = length - position
        block = base ** remaining_places
        digit = 1
        while remaining > block:
            remaining -= block
            digit += 1
        digits.append(digit)
    return PositiveBijective(base=base, digits=tuple(digits))


def unity_product_rank(residues: Sequence[UnityResidue]) -> PositiveIndex:
    """One-origin mixed-radix rank for a product of unity-residue states."""
    if not residues:
        raise ValueError("at least one unity residue is required")
    rank = 1
    stride = 1
    for residue in residues:
        if residue.label.value > 1:
            rank += (residue.label.value - 1) * stride
        stride *= residue.modulus
    return PositiveIndex(rank)
