"""SHAKE256 with 512-bit output and explicit length-framed domain separation."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import unicodedata
import re
from typing import Any, Iterable

OUTPUT_BYTES = 64
ID_PREFIX = "xvoid:shake256-512:"


def _validate_canonical(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise ValueError(f"binary floating point is forbidden at {path}")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError(f"text is not NFC-normalized at {path}")
        return
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return
    if isinstance(value, list):
        for ordinal, child in enumerate(value, start=1):
            _validate_canonical(child, f"{path}[{ordinal}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"object key is not text at {path}")
            if unicodedata.normalize("NFC", key) != key:
                raise ValueError(f"object key is not NFC-normalized at {path}")
            _validate_canonical(child, f"{path}.{key}")
        return
    raise ValueError(f"unsupported canonical value type at {path}: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _validate_canonical(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def framed_shake256_512(domain: str, fields: Iterable[bytes]) -> bytes:
    """Hash a versioned ASCII domain plus independently length-framed fields."""
    if not domain.isascii() or re.fullmatch(r"[\x21-\x7e]+/v[1-9][0-9]*", domain) is None:
        raise ValueError("domain must be printable ASCII ending in /v<positive-version>")
    material = tuple(fields)
    sponge = hashlib.shake_256()
    encoded_domain = domain.encode("ascii")
    sponge.update(struct.pack(">Q", len(encoded_domain)))
    sponge.update(encoded_domain)
    sponge.update(struct.pack(">I", len(material)))
    for field in material:
        sponge.update(struct.pack(">Q", len(field)))
        sponge.update(field)
    return sponge.digest(OUTPUT_BYTES)


def content_id(domain: str, *fields: bytes) -> str:
    raw = framed_shake256_512(domain, fields)
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return ID_PREFIX + encoded


def semantic_id(content_type: str, body: dict[str, Any]) -> str:
    return content_id(
        "XAVI-VOID/SEMANTIC-CONTENT/v1",
        content_type.encode("utf-8"),
        canonical_bytes(body),
    )
