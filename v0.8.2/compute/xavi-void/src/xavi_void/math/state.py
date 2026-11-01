"""Native DUO-MATH zeroless semantic algebra for xavi-void.

The active semantic number line has one bidirectional origin, ``1``::

    ... -5, -4, -3, -2  <-  1  ->  +2, +3, +4, +5 ...

There is no numeric-zero semantic state.  ``1`` is simultaneously the meeting
point of both signed branches.  Sign becomes distinct only after leaving
unity.  Absence, unknown and invalid states are typed and never borrowed from
the numeric domain.

Hardware/cryptographic encodings that require raw bits or host offsets live in
explicit boundary modules; they are not part of this algebra.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, TypeAlias


class Branch(Enum):
    POSITIVE = 1
    NEGATIVE = 2

    def opposite(self) -> "Branch":
        return Branch.NEGATIVE if self is Branch.POSITIVE else Branch.POSITIVE


class Ordering(Enum):
    LESS = 1
    EQUAL = 2
    GREATER = 3


@dataclass(frozen=True, slots=True)
class PositiveBijective:
    """Positive bijective numeral; every digit lies in ``1..base``."""

    base: int
    digits: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.base < 2:
            raise ValueError("bijective base must be >= 2")
        if not self.digits:
            raise ValueError("positive bijective numeral requires at least one digit")
        if any(digit < 1 or digit > self.base for digit in self.digits):
            raise ValueError("bijective digits must lie in 1..base")

    def to_int(self) -> int:
        # Start from the first positive digit; no zero-valued accumulator is
        # needed in the semantic implementation.
        value = self.digits[0]
        for digit in self.digits[1:]:
            value = value * self.base + digit
        return value


@dataclass(frozen=True, slots=True)
class SignedBijective:
    """A native signed zeroless value.

    Magnitude ``1`` is the unique origin.  ``branch`` is therefore absent at
    unity because positive and negative coincide there.  Magnitudes greater
    than one must select exactly one branch.
    """

    magnitude: PositiveBijective
    branch: Branch | None = None

    def __post_init__(self) -> None:
        value = self.magnitude.to_int()
        if value == 1:
            if self.branch is not None:
                raise ValueError("unity is one bidirectional state, not separate +1/-1 states")
        elif self.branch is None:
            raise ValueError("non-origin DUO value requires a branch")

    @property
    def magnitude_int(self) -> int:
        return self.magnitude.to_int()

    @property
    def is_origin(self) -> bool:
        return self.magnitude_int == 1

    @classmethod
    def origin(cls, *, base: int = 10) -> "SignedBijective":
        return cls(encode_positive(1, base=base), None)

    @classmethod
    def from_magnitude(
        cls,
        magnitude: int,
        *,
        branch: Branch | None = None,
        base: int = 10,
    ) -> "SignedBijective":
        encoded = encode_positive(magnitude, base=base)
        if magnitude == 1:
            # +1 and -1 aliases canonicalize to the same state.
            return cls(encoded, None)
        if branch is None:
            raise ValueError("branch required for magnitude greater than unity")
        return cls(encoded, branch)

    def opposite(self) -> "SignedBijective":
        if self.is_origin:
            return self
        assert self.branch is not None
        return SignedBijective(self.magnitude, self.branch.opposite())


@dataclass(frozen=True, slots=True)
class _Absent:
    def __repr__(self) -> str:
        return "Absent"


@dataclass(frozen=True, slots=True)
class _Unknown:
    def __repr__(self) -> str:
        return "Unknown"


@dataclass(frozen=True, slots=True)
class InvalidState:
    reason: str
    operands: tuple[object, ...] = ()

    def __repr__(self) -> str:
        return f"Invalid({self.reason!r})"


Absent: Final = _Absent()
Unknown: Final = _Unknown()
Invalid = InvalidState

NumericState: TypeAlias = SignedBijective
State: TypeAlias = SignedBijective | _Absent | _Unknown | InvalidState


def encode_positive(value: int, base: int = 10) -> PositiveBijective:
    """Encode a strictly positive magnitude without a zero-valued digit/state."""
    if base < 2:
        raise ValueError("bijective base must be >= 2")
    if value < 1:
        raise ValueError("native DUO magnitude must be >= 1")
    if value <= base:
        return PositiveBijective(base=base, digits=(value,))

    # Bijective place split.  Because this branch only executes for
    # value > base, quotient and digit are both strictly positive.
    quotient = (value - 1) // base
    digit = value - quotient * base
    prefix = encode_positive(quotient, base=base)
    return PositiveBijective(base=base, digits=prefix.digits + (digit,))


def duo_value(
    magnitude: int,
    *,
    branch: Branch | None = None,
    base: int = 10,
) -> SignedBijective:
    return SignedBijective.from_magnitude(magnitude, branch=branch, base=base)


def origin(*, base: int = 10) -> SignedBijective:
    return SignedBijective.origin(base=base)


def add(left: State, right: State, *, base: int | None = None) -> State:
    pair = _numeric_pair(left, right)
    if isinstance(pair, InvalidState):
        return pair
    a, b = pair
    result_base = _resolve_base(a, b, base)
    if a.is_origin:
        return _rebase(b, result_base)
    if b.is_origin:
        return _rebase(a, result_base)
    assert a.branch is not None and b.branch is not None
    am = a.magnitude_int
    bm = b.magnitude_int
    if a.branch is b.branch:
        return duo_value(am + bm - 1, branch=a.branch, base=result_base)
    if am == bm:
        return origin(base=result_base)
    if am > bm:
        return duo_value(am - bm + 1, branch=a.branch, base=result_base)
    return duo_value(bm - am + 1, branch=b.branch, base=result_base)


def negate(value: State, *, base: int | None = None) -> State:
    if not isinstance(value, SignedBijective):
        return InvalidState("nonnumeric negation operand", (value,))
    result_base = value.magnitude.base if base is None else base
    return _rebase(value.opposite(), result_base)


def subtract(left: State, right: State, *, base: int | None = None) -> State:
    negated = negate(right, base=base)
    if isinstance(negated, InvalidState):
        return negated
    return add(left, negated, base=base)


def multiply(left: State, right: State, *, base: int | None = None) -> State:
    """Native DUO product.

    Unity is the additive origin and product absorber.  ``+2`` is the
    multiplicative identity because it is one positive step from unity.
    """
    pair = _numeric_pair(left, right)
    if isinstance(pair, InvalidState):
        return pair
    a, b = pair
    result_base = _resolve_base(a, b, base)
    if a.is_origin or b.is_origin:
        return origin(base=result_base)
    assert a.branch is not None and b.branch is not None
    magnitude = (a.magnitude_int - 1) * (b.magnitude_int - 1) + 1
    branch = Branch.POSITIVE if a.branch is b.branch else Branch.NEGATIVE
    return duo_value(magnitude, branch=branch, base=result_base)


def quotient_remainder(
    dividend: State,
    divisor: State,
    *,
    base: int | None = None,
) -> tuple[State, State]:
    """Return DUO quotient and remainder without introducing a numeric zero state."""
    pair = _numeric_pair(dividend, divisor)
    if isinstance(pair, InvalidState):
        return pair, pair
    left, right = pair
    result_base = _resolve_base(left, right, base)
    if right.is_origin:
        invalid = InvalidState("division by unity-origin state", (dividend, divisor))
        return invalid, invalid
    if left.is_origin:
        unit = origin(base=result_base)
        return unit, unit

    assert left.branch is not None and right.branch is not None
    divisor_stride = right.magnitude_int - 1
    remainder_magnitude = left.magnitude_int
    quotient_magnitude = 1

    # Repeated positive-stride subtraction keeps every represented magnitude
    # within the native positive domain.  No arithmetic-zero state is created.
    while remainder_magnitude > divisor_stride:
        remainder_magnitude -= divisor_stride
        quotient_magnitude += 1

    quotient_branch = Branch.POSITIVE if left.branch is right.branch else Branch.NEGATIVE
    quotient = duo_value(quotient_magnitude, branch=quotient_branch, base=result_base)
    if remainder_magnitude == 1:
        remainder = origin(base=result_base)
    else:
        remainder = duo_value(remainder_magnitude, branch=left.branch, base=result_base)
    return quotient, remainder


def divide_exact(dividend: State, divisor: State, *, base: int | None = None) -> State:
    quotient, remainder = quotient_remainder(dividend, divisor, base=base)
    if isinstance(quotient, InvalidState):
        return quotient
    assert isinstance(remainder, SignedBijective)
    if not remainder.is_origin:
        return InvalidState("non-exact DUO division", (dividend, divisor))
    return quotient


def compare_numeric(left: State, right: State) -> Ordering | InvalidState:
    pair = _numeric_pair(left, right)
    if isinstance(pair, InvalidState):
        return pair
    a, b = pair
    if a == b:
        return Ordering.EQUAL
    if a.is_origin:
        assert b.branch is not None
        return Ordering.LESS if b.branch is Branch.POSITIVE else Ordering.GREATER
    if b.is_origin:
        assert a.branch is not None
        return Ordering.GREATER if a.branch is Branch.POSITIVE else Ordering.LESS
    assert a.branch is not None and b.branch is not None
    if a.branch is not b.branch:
        return Ordering.GREATER if a.branch is Branch.POSITIVE else Ordering.LESS
    if a.branch is Branch.POSITIVE:
        return Ordering.GREATER if a.magnitude_int > b.magnitude_int else Ordering.LESS
    return Ordering.LESS if a.magnitude_int > b.magnitude_int else Ordering.GREATER


_DIGIT_ALPHABET = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def to_text(value: State | PositiveBijective) -> str:
    if isinstance(value, PositiveBijective):
        return _magnitude_text(value)
    if value is Absent:
        return "Absent"
    if value is Unknown:
        return "Unknown"
    if isinstance(value, InvalidState):
        return repr(value)
    if not isinstance(value, SignedBijective):
        raise TypeError(f"unsupported DUO state: {type(value).__name__}")
    magnitude = _magnitude_text(value.magnitude)
    if value.is_origin:
        return magnitude
    assert value.branch is not None
    prefix = "+" if value.branch is Branch.POSITIVE else "-"
    return prefix + magnitude


def from_text(text: str, *, base: int = 10) -> State:
    if text == "Absent":
        return Absent
    if text == "Unknown":
        return Unknown
    if not text:
        raise ValueError("DUO numeral text must not be empty")
    branch: Branch | None = None
    body = text
    if text[0] == "+":
        branch = Branch.POSITIVE
        body = text[1:]
    elif text[0] == "-":
        branch = Branch.NEGATIVE
        body = text[1:]
    magnitude = _positive_from_text(body, base=base)
    return SignedBijective.from_magnitude(magnitude.to_int(), branch=branch, base=base)


def _magnitude_text(value: PositiveBijective) -> str:
    if value.base > len(_DIGIT_ALPHABET):
        return "[" + ",".join(str(d) for d in value.digits) + "]"
    return "".join(_DIGIT_ALPHABET[d - 1] for d in value.digits)


def _positive_from_text(text: str, *, base: int) -> PositiveBijective:
    if base < 2:
        raise ValueError("bijective base must be >= 2")
    if base > len(_DIGIT_ALPHABET):
        raise ValueError("text parser supports bases up to 61")
    if not text:
        raise ValueError("positive DUO magnitude must not be empty")
    allowed = _DIGIT_ALPHABET[:base]
    reverse = {character: index + 1 for index, character in enumerate(allowed)}
    try:
        digits = tuple(reverse[character] for character in text)
    except KeyError as error:
        raise ValueError(f"digit {error.args[0]!r} is not valid in bijective base {base}") from error
    return PositiveBijective(base=base, digits=digits)


def _numeric_pair(left: State, right: State) -> tuple[SignedBijective, SignedBijective] | InvalidState:
    if not isinstance(left, SignedBijective) or not isinstance(right, SignedBijective):
        return InvalidState("nonnumeric arithmetic operand", (left, right))
    return left, right


def _resolve_base(left: SignedBijective, right: SignedBijective, base: int | None) -> int:
    if base is not None:
        if base < 2:
            raise ValueError("bijective base must be >= 2")
        return base
    if left.magnitude.base != right.magnitude.base:
        raise ValueError("mixed-base arithmetic requires explicit result base")
    return left.magnitude.base


def _rebase(value: SignedBijective, base: int) -> SignedBijective:
    return SignedBijective.from_magnitude(value.magnitude_int, branch=value.branch, base=base)
