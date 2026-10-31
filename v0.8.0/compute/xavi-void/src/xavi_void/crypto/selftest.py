"""Deterministic cryptographic conformance checks for the reference core."""

from __future__ import annotations

import hashlib

from .keccak import shake256_512
from .shake import framed_shake256_512


_BOUNDARY_LENGTHS = (0, 1, 31, 32, 63, 64, 135, 136, 137, 271, 272, 273)


def run_crypto_selftest() -> dict[str, object]:
    vectors_checked = 0
    for length in _BOUNDARY_LENGTHS:
        message = bytes((index * 37 + 11) % 256 for index in range(length))
        expected = hashlib.shake_256(message).digest(64)
        actual = shake256_512(message)
        if actual != expected:
            raise RuntimeError(f"native SHAKE256-512 mismatch at message length {length}")
        vectors_checked += 1

    # Confirm framing is not a raw-concatenation construction.
    left = framed_shake256_512("XAVI-VOID/SELFTEST/v1", (b"ab", b"c"))
    right = framed_shake256_512("XAVI-VOID/SELFTEST/v1", (b"a", b"bc"))
    if left == right:
        raise RuntimeError("length framing self-test failed")

    return {
        "status": "pass",
        "native_shake_vectors": vectors_checked,
        "framing_ambiguity_check": "pass",
    }
