# Provenance

Date: 2026-10-29

## DUO-Math

XDE2 is bound to canonical DUO Numbers Rev009. A DUO glyph is not a global numeric identity: for modulus M>1, S=M-1 and N=cS+r with 1<=r<=S; the canonical symbol is H(r)R(c). XDE2 derives a keyed rotating per-cell modulus/offset schedule, keeps that context private, and authenticates a keyed commitment to the full typed decomposition. DUO ambiguity is a polymorphic representation layer; AEAD, PQ authentication/key establishment, custody, replay protection, and FHE boundaries remain authoritative for cryptographic security.

## Xavi-Void

Xavi-Void was inspected read-only and contributed design patterns for:

- canonical SHAKE256-512 identities;
- evidence/non-authority separation;
- explicit provider capabilities;
- privacy padding;
- strict wire-format rejection.

The exact source documents/code consulted are retained under `references/xavi-void/` with their MIT/Apache license files.

## Security boundary

This project contains no custom implementation of ChaCha20 or Poly1305. The installed `cryptography` package supplies AEAD. DUO-Math supplies a keyed representation layer after AEAD encryption.
