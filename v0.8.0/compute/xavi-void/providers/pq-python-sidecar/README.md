# Production PQ transport sidecar — Rev 1.2-dev4

This container implements the exact xavi-void transport suite advertised by `SidecarPQProvider`:

- ML-KEM-1024 through liboqs;
- ML-DSA-87 through liboqs;
- KMAC256 through PyCryptodome;
- AES-256-GCM-SIV through `cryptography`.

Build with a reviewed/pinned liboqs ref in production rather than leaving a moving source revision.

The line-delimited JSON `selftest` performs KEM and signature round-trips, emits deterministic KMAC256/AES-256-GCM-SIV values, records public/secret/ciphertext/signature sizes, and emits SHA3-512 digests of the randomized KEM/signature test transcripts. `benchmarks/dev4_acceptance.py` requires this provider for a full production acceptance pass and wraps the encrypted TFHE request and result in signed PQ transport envelopes.
