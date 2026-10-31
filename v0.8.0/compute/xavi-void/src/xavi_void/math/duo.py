"""DUO-MATH semantic truth and polygon/cross-polytope topology.

Unity is the single bidirectional origin.  Polygon and directional labels are
strictly one-origin; geometry does not introduce a numeric-zero semantic node.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math

from .types import PositiveExtent
from .unity import PositiveIndex


class UnityTruth(Enum):
    """Two-state semantic truth with unity-origin false and positive departure true."""

    FALSE = 1
    TRUE = 2


class DirectionSign(Enum):
    POSITIVE = 1
    NEGATIVE = 2


@dataclass(frozen=True, slots=True)
class SignedDirection:
    axis: PositiveIndex
    sign: DirectionSign

    def polygon_vertex(self, dimension: PositiveExtent) -> PositiveIndex:
        if self.axis.value > dimension.value:
            raise ValueError("direction axis exceeds dimension")
        if self.sign is DirectionSign.POSITIVE:
            return PositiveIndex(self.axis.value)
        return PositiveIndex(dimension.value + self.axis.value)


@dataclass(frozen=True, slots=True)
class UnityPolygon:
    """Regular semantic polygon whose vertices are labeled exactly ``1..n``."""

    size: PositiveExtent

    def vertex(self, label: int | PositiveIndex) -> PositiveIndex:
        value = label.value if isinstance(label, PositiveIndex) else label
        if value < 1 or value > self.size.value:
            raise ValueError("polygon vertex must lie in 1..size")
        return PositiveIndex(value)

    def step(self, vertex: PositiveIndex, distance: int = 1) -> PositiveIndex:
        self.vertex(vertex)
        value = vertex.value + distance
        while value > self.size.value:
            value -= self.size.value
        while value < 1:
            value += self.size.value
        return PositiveIndex(value)

    def antipode(self, vertex: PositiveIndex) -> PositiveIndex:
        if self.size.value % 2:
            raise ValueError("an exact antipode requires an even polygon")
        return self.step(vertex, self.size.value // 2)

    def angle(self, vertex: PositiveIndex) -> float:
        """Rendering-only angle.  The semantic vertex remains one-origin."""
        self.vertex(vertex)
        return 2.0 * math.pi * ((vertex.value - 1) / self.size.value)

    def unit_xy(self, vertex: PositiveIndex) -> tuple[float, float]:
        """Rendering-only Cartesian projection, never a semantic coordinate."""
        theta = self.angle(vertex)
        return math.cos(theta), math.sin(theta)


def direction_alphabet_size(dimension: PositiveExtent) -> PositiveExtent:
    """Unity plus two signed directions per axis: ``2d+1`` states."""
    return PositiveExtent(2 * dimension.value + 1)


def ordered_relation_count(dimension: PositiveExtent) -> PositiveExtent:
    """DUO relation invariant ``A_d = 2d(2d+1)``."""
    d = dimension.value
    return PositiveExtent(2 * d * (2 * d + 1))


@dataclass(frozen=True, slots=True)
class CrossPolytopeAddress:
    """One-origin axis/sign address for antipodal routing."""

    dimension: PositiveExtent
    direction: SignedDirection

    def __post_init__(self) -> None:
        if self.direction.axis.value > self.dimension.value:
            raise ValueError("axis exceeds cross-polytope dimension")

    @property
    def vertex(self) -> PositiveIndex:
        return self.direction.polygon_vertex(self.dimension)

    @property
    def antipode(self) -> "CrossPolytopeAddress":
        opposite = DirectionSign.NEGATIVE if self.direction.sign is DirectionSign.POSITIVE else DirectionSign.POSITIVE
        return CrossPolytopeAddress(self.dimension, SignedDirection(self.direction.axis, opposite))
