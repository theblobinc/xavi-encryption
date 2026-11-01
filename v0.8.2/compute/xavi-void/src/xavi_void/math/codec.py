"""Canonical tagged encoding for native DUO semantic states."""
from __future__ import annotations

from typing import Any, Mapping

from .state import Absent, Branch, InvalidState, SignedBijective, State, Unknown


def state_to_object(value: State) -> dict[str, Any]:
    if value is Absent:
        return {"kind": "Absent"}
    if value is Unknown:
        return {"kind": "Unknown"}
    if isinstance(value, SignedBijective):
        branch = "unity" if value.is_origin else (
            "positive" if value.branch is Branch.POSITIVE else "negative"
        )
        return {
            "kind": "SignedBijective",
            "base": value.magnitude.base,
            "digits": list(value.magnitude.digits),
            "branch": branch,
        }
    if isinstance(value, InvalidState):
        return {
            "kind": "Invalid",
            "reason": value.reason,
            "operands": [repr(operand) for operand in value.operands],
        }
    raise TypeError(f"unsupported semantic state: {type(value).__name__}")


def state_from_object(value: Mapping[str, Any]) -> State:
    if set(value) == {"kind"}:
        if value["kind"] == "Absent":
            return Absent
        if value["kind"] == "Unknown":
            return Unknown
    if value.get("kind") == "SignedBijective" and set(value) == {"kind", "base", "digits", "branch"}:
        base = value["base"]
        digits = value["digits"]
        branch_name = value["branch"]
        if not isinstance(base, int) or isinstance(base, bool):
            raise ValueError("bijective base must be an integer")
        if not isinstance(digits, list) or any(not isinstance(d, int) or isinstance(d, bool) for d in digits):
            raise ValueError("bijective digits must be an integer list")
        from .state import PositiveBijective
        magnitude = PositiveBijective(base=base, digits=tuple(digits))
        if branch_name == "unity":
            branch = None
        elif branch_name == "positive":
            branch = Branch.POSITIVE
        elif branch_name == "negative":
            branch = Branch.NEGATIVE
        else:
            raise ValueError("unknown DUO branch")
        return SignedBijective.from_magnitude(magnitude.to_int(), branch=branch, base=base)
    if value.get("kind") == "Invalid" and set(value) == {"kind", "reason", "operands"}:
        reason = value["reason"]
        operands = value["operands"]
        if not isinstance(reason, str) or not isinstance(operands, list):
            raise ValueError("invalid-state encoding is malformed")
        return InvalidState(reason=reason, operands=tuple(operands))
    raise ValueError("unknown or malformed semantic state encoding")
