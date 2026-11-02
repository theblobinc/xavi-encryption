# XAVI-DUO Encryption v0.8.2 — Security / Audit Status

**Status:** standalone high-assurance experimental implementation; internal gates green; independent external security audit and accreditation are still required before treating the suite as a certified high-assurance product.

## Closed in v0.7

- Remote encrypted work is no longer considered authorized merely because it decrypts. Admission requires a project-scoped sender ML-DSA-87 signature, a short-lived authority ML-DSA-87 approval, durable replay claim, capability/provider binding, and immutable provider identity before expensive decrypt/evaluator execution.
- Caller-supplied public-key paths are not trust anchors. The worker resolves sender, authority and worker identities from a local project trust policy.
- PQ providers resolve an allowlisted immutable OCI image ID or hash-pinned native executable and execute that exact implementation. Mutable tags are not the execution identity.
- Hostile input is bounded before expensive DUO/PQ parsing; the CLI uses bounded regular-file reads rather than whole-file allocation.
- ML-KEM recipient identity is derived from the actual recipient key rather than trusted envelope metadata.
- Replay/witness/custody persistence uses durable file+directory synchronization. Custody object creation is create-only and rejects duplicate names/symlink substitution.
- High-assurance nonce chronology supports an independent rollback-domain anchor. Full-machine snapshot rollback is detected by the external high-water mark and quarantines the key.
- Release artifacts support detached ML-DSA-87 signing over a canonical manifest; the signing key is not part of the distributable payload.
- The Python package and worker install and run from a clean wheel without the source tree or Xavi cluster services.

## Current gates

- Python: **54/54 PASS** (404.411 s).
- Node/WASM/FHE: **37/37 PASS** (160.774 s).
- Clean wheel install from `/tmp` with source `PYTHONPATH` removed: **PASS**.
- Standalone core cluster-literal prohibition: **PASS**.
- Nonce external-anchor rollback tests: **3/3 PASS**.
- Release-signature tamper tests: **2/2 PASS**.

## Security claim boundary

The suite uses strong standard primitives and a high-assurance profile based on ML-KEM-1024 and ML-DSA-87. This does **not** by itself make the product “military grade,” a FIPS-validated module, or approved for classified use. Those claims require independent review, validated cryptographic modules where required, operational key-management controls, supply-chain controls, platform evaluation, and deployment-specific accreditation.

The DUO transform is a reversible authenticated wire/semantic layer. No independent security bits are claimed from DUO representational ambiguity.

## Remaining external assurance work

- independent cryptographic/security code review and penetration testing;
- fuzzing/sanitizer campaigns on parsers, transport servers, Worker RPC and native providers;
- reproducible build verification on an independent builder/OS;
- FIPS-validated provider/module path where a deployment requires FIPS validation;
- physical HSM/PKCS#11 validation (interface exists; physical token validation remains open);
- formal deployment profiles and key ceremonies for each consuming project;
- side-channel evaluation appropriate to the target hardware and threat model.

Reference Xavi-cluster evidence lives under `validation/xavi-cluster/`; it is lab evidence only and is not a runtime dependency.

## Closed in v0.8.2

- Ships the standalone TPM2 PCR-bound KEK custody backend and `xavi-duo-tpm2-custody` CLI.
- Requires explicit hardware binding for high-assurance `tpm2://` and `pkcs11://` operators.
- Documents that TPM protects the wrapping key; ML-DSA/ML-KEM execute in the pinned OpenSSL provider with ephemeral signer-process plaintext.
- Adds unique OCI provider container names plus forced cleanup on timeout/exception, closing the stale-provider-container failure observed during validation.
- Full validation: Python 92/92, Node/WASM/FHE 37/37, new TPM/provider regressions 10/10, independent prod3 provider-backed subset 14/14.
- Release signature remains pending until a current non-exporting organizational ML-DSA-87 release root is actually provisioned.

## Closed in v0.8.1

- Fixed the advertised CLI receipt path and added subprocess round-trip/tamper regression coverage.
- Replaced one-phase remote replay anchoring with claim-bound two-phase prepare/commit semantics, including crash recovery and rollback quarantine.
- Hardened local symmetric key and nonce state against final-component symlink substitution.
- Bound ML-KEM operations to the parameter set encoded by the actual public/private key object.
- Tightened XDE2 frame inspection and corrected protocol/version documentation.
- Pinned the Python build backend and disabled isolated mutable build dependencies for release construction.

Internal validation is passing; this is not an independent audit, FIPS-validated deployment, classified-system accreditation, or military-grade certification. Organizational ML-DSA-87 release signing remains pending a configured non-exporting release-root operator.
