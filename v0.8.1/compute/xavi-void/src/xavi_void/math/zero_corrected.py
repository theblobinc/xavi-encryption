"""Compatibility import surface for the pre-migration module name.

The active implementation is the native DUO algebra in :mod:`xavi_void.math.state`
and geometry in :mod:`xavi_void.math.duo`.  No ZeroValue or displacement-based
semantic arithmetic is defined here.
"""
from .state import (  # noqa: F401
    Branch as BijectiveDirection,
    Ordering,
    PositiveBijective,
    SignedBijective,
    add as signed_add,
    subtract as signed_subtract,
    multiply as signed_multiply,
    divide_exact as signed_divide_exact,
    compare_numeric as signed_compare,
    origin,
)
from .duo import (  # noqa: F401
    CrossPolytopeAddress,
    DirectionSign,
    SignedDirection,
    UnityPolygon,
    UnityTruth,
    direction_alphabet_size,
    ordered_relation_count,
)
from .unity import PositiveIndex  # noqa: F401
from .types import PositiveExtent  # noqa: F401


class UnityOrdinal(PositiveIndex):
    """Compatibility name for a one-origin semantic ordinal."""


def lift_host_offset(value: int) -> PositiveIndex:
    from .boundary import from_host_offset
    return from_host_offset(value)


def lower_host_offset(label: PositiveIndex) -> int:
    from .boundary import to_host_offset
    return to_host_offset(label)
