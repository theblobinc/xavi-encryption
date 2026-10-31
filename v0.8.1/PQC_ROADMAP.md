# Post-Quantum Envelope Status

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


## Implemented

- XDE2-PQ2 recipient envelope using ML-KEM-1024.
- OpenSSL 3.5.9 FIPS-203-conforming ML-KEM implementation in a minimal rootless provider image.
- Exact keygen/encapsulate/decapsulate self-test.
- KEM shared secret is HKDF-bound to KEM ciphertext + recipient public-key ID and then used as the XDE2 master key.
- ML-KEM ciphertext is serialized as zero-free DUO byte cells.
- Same provider image validated on prod4, prod3 and vm1.
- No non-PQ fallback.

## Still needed before production

- independent cryptographic review/audit;
- persistent node key-custody service/HSM/TPM binding;
- key rotation/revocation/discovery protocol;
- signed node/provider identity (ML-DSA or equivalent) for unauthenticated public-key distribution;
- replay/session protocol for multi-message channels;
- remote witness transport integrated with the live Xavi authority system;
- formal interoperability vectors against an independent FIPS 203 implementation.

The container uses OpenSSL's default provider and is FIPS-203 conforming; it is **not claimed to be a FIPS-validated deployment**.
