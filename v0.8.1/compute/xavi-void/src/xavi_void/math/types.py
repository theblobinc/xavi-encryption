"""Strong unity-origin semantic types used across xavi-void."""
from __future__ import annotations

from dataclasses import dataclass

from .unity import PositiveIndex


@dataclass(frozen=True, slots=True, order=True)
class Ordinal(PositiveIndex):
    """Generic one-origin ordinal."""


@dataclass(frozen=True, slots=True, order=True)
class RegisterId(PositiveIndex):
    """One-origin execution register identifier."""


@dataclass(frozen=True, slots=True, order=True)
class InstructionId(PositiveIndex):
    """One-origin instruction identifier."""


@dataclass(frozen=True, slots=True, order=True)
class RoundId(PositiveIndex):
    """One-origin cryptographic/execution round identifier."""


@dataclass(frozen=True, slots=True, order=True)
class PositiveExtent(PositiveIndex):
    """Positive size/extent. Empty domains use an explicit typed state."""


def require_type(value: PositiveIndex, cls: type[PositiveIndex], field: str) -> None:
    if not isinstance(value, cls):
        raise TypeError(f"{field} must be {cls.__name__}; got {type(value).__name__}")
