"""Explicit host/crypto boundary codecs for the native DUO semantic model.

Raw host offsets and physical bits are allowed here because Python arrays,
SHAKE and TFHE use conventional machine encodings.  Those representations must
not be used as xavi-void semantic state outside this module and provider/crypto
boundary code.
"""
from __future__ import annotations

from .duo import UnityTruth
from .state import Branch, SignedBijective
from .unity import PositiveIndex


def to_host_offset(index: PositiveIndex) -> int:
    """Convert one-origin semantic index to a host array offset."""
    return index.value - 1


def from_host_offset(offset: int) -> PositiveIndex:
    """Convert host array offset into a one-origin semantic index."""
    if offset < 0:
        raise ValueError("host offset must be nonnegative")
    return PositiveIndex(offset + 1)


def from_physical_bit(bit: bool) -> UnityTruth:
    return UnityTruth.TRUE if bit else UnityTruth.FALSE


def to_physical_bit(value: UnityTruth) -> bool:
    return value is UnityTruth.TRUE


def semantic_bit_label(bit: bool) -> str:
    """Canonical semantic label for a physical two-state bit."""
    return "+2" if bit else "1"


def from_signed_host_integer(value: int, *, base: int = 10) -> SignedBijective:
    """Interop-only lift for external signed integer APIs.

    The external machine origin is mapped to semantic unity.  This conversion
    exists only at the boundary; native DUO arithmetic never depends on it.
    """
    if value == 0:
        return SignedBijective.origin(base=base)
    branch = Branch.POSITIVE if value > 0 else Branch.NEGATIVE
    return SignedBijective.from_magnitude(abs(value) + 1, branch=branch, base=base)


def to_signed_host_integer(value: SignedBijective) -> int:
    """Interop-only lowering for libraries that require conventional integers."""
    if value.is_origin:
        return 0
    assert value.branch is not None
    distance = value.magnitude_int - 1
    return distance if value.branch is Branch.POSITIVE else -distance
