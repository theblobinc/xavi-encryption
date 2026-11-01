# Standards and Source Notes

## Cryptographic standards / references

- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols: https://www.rfc-editor.org/rfc/rfc8439
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final

XDE2 v2 calls the ChaCha20-Poly1305 implementation provided by Python's `cryptography` package and does not implement the AEAD primitive itself.

## DUO source

Frozen implementation copied from:

`/datastore3/math/numbers/DUO_Numbers_Rev_008_2026-10-29/`

The encryption project includes `vendor/duo_core.py` and `vendor/duo_theorems.py` so protocol behavior is pinned to DUO Numbers Rev009: uppercase A-J encode realized left-count continuation, lowercase a-j encode modular rollover identity, and contextual identity binds modulus, span, cycle, remainder, left, right, symbol, and external count.

## Xavi-Void source

Read-only source reviewed:

`/datastore3/wg-rnn/xavi-void`

Reference copies are under `references/xavi-void/`. The adapted SHAKE/content-receipt code is in `xavi_duo_evidence.py`. Xavi-Void's FHE and remote-evaluator code is not in the XDE2 trusted computing base.

## OpenSSL ML-KEM provider

- OpenSSL 3.5 ML-KEM documentation: https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/
- OpenSSL 3.5 ML-KEM key documentation: https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/
- OpenSSL 3.5 release: https://openssl-library.org/post/2025-04-08-openssl-35-final-release/

The final provider image contains OpenSSL (Apache-2.0) and musl runtime material (MIT); Alpine is used only as the build-stage package source and is not the final userspace image.
