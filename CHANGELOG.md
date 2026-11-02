# Changelog

All canonical repository versions are recorded here. Each release directory is standalone.

## v0.8.2 — 2026-11-02

TPM custody and provider-runtime hardening revision.

- Ships the standalone `tpm2://` PCR-bound KEK custody backend and `xavi-duo-tpm2-custody` CLI.
- Wraps ML-DSA/ML-KEM private PEM objects with ChaCha20-Poly1305 under a TPM-sealed 256-bit KEK; it does not claim native TPM PQ execution.
- Requires explicit `hardware_bound=true` for high-assurance `tpm2://` and `pkcs11://` operators.
- Gives OCI provider invocations unique container names and forcibly removes named containers on timeout/exception, preventing stale provider containers from poisoning later discovery.
- Preserves cgroupfs fallback under a distinct unique provider container.
- Passed 92/92 Python tests on prod3 and 37/37 Node/WASM/FHE tests on prod4; the independent provider-backed subset is 14/14 and new v0.8.2 security regressions are 10/10.
- Two independent deterministic builds produced byte-identical source archive, wheel, and release manifest; deterministic-wheel install/self-test and TPM CLI smoke pass.
- ML-DSA-87 organizational release signature remains pending until a current non-exporting release root is provisioned.

## v0.8.1 — 2026-10-31

Hardening and release-integrity revision.

- Fixed CLI receipt generation/verification and added an end-to-end tamper regression.
- Replaced remote replay anchoring with claim-bound two-phase prepare/commit recovery and rollback quarantine.
- Hardened sensitive key/nonce state reads against final-component symlink substitution.
- Added actual ML-KEM parameter-set binding, matching the existing ML-DSA binding discipline.
- Tightened XDE2 frame inspection and corrected protocol/version documentation.
- Pinned build backend versions and disabled mutable build isolation.
- Passed 82/82 Python, 37/37 Node/WASM/FHE, and 33/33 portable security-core tests.
- Rebuilt twice with byte-identical source archive, wheel, and release manifest; clean-wheel self-test passes.
- ML-DSA-87 organizational release signature remains pending a configured non-exporting release root.

## v0.8.0 — 2026-10-30

Initial canonical `xavi-encrypt` repository version.

- Imported the exact frozen XAVI-DUO Encryption v0.8.0 source release.
- Preserved reproducible source archive and Python wheel.
- Preserved release manifest, release proof, artifact hash list, signing request, and custody-discovery evidence.
- Internal release validation is complete; organizational ML-DSA-87 release signing remains pending.
- Repository layout established for future `vX.Y.Z/` standalone revisions.
