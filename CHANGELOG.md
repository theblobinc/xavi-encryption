# Changelog

All canonical repository versions are recorded here. Each release directory is standalone.

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
