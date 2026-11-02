# XAVI-DUO Encryption (`xavi-encrypt`)

Standalone authenticated encryption, post-quantum transport, key custody, and encrypted-compute tooling built around **XDE2 / XDE2-PQ2** with **DUO Numbers Rev009** as a reversible authenticated wire representation.

> **Security status:** experimental high-assurance implementation. Internally validated and reproducibly built, but **not independently audited, FIPS-validated as a deployment, accredited for classified systems, or certified as military-grade**.

## What it provides

- **XDE2 symmetric encryption** — ChaCha20-Poly1305 with HKDF-SHA256 key separation, durable nonce chronology, authenticated receipts, privacy padding, and zero-free DUO wire encoding.
- **XDE2-PQ2 post-quantum transport** — ML-KEM-1024 recipient key establishment with explicit actual-key parameter binding and fail-closed provider identity.
- **High-assurance identity/signing** — ML-DSA-87 with actual-key algorithm binding.
- **Key custody** — software-file development mode plus generic non-exporting `remote://`, `tpm2://`, and `pkcs11://` private-operation boundaries.
- **Remote execution admission** — signed project-scoped approvals, bounded envelopes, capability/provider binding, and claim-bound two-phase replay anchoring.
- **Encrypted compute** — split trusted-client / secret-blind evaluator paths for TFHE, CKKS/OpenFHE, WASM/Worker execution, and optional accelerator providers.
- **Standalone operation** — production code does not require the Xavi cluster, MCP, prod3/prod4, NFS, private Xavi hostnames, or Xavi authority services. Xavi infrastructure is validation/reference-lab evidence only.

DUO-Math is **not** treated as a replacement for standard cryptography or as extra entropy. The cryptographic security boundary remains the standard AEAD, KEM, and signature primitives; DUO provides the authenticated reversible polymorphic representation.

## Current release — v0.8.2

`v0.8.2/` is the current canonical standalone revision. It carries forward v0.8.1 and adds:

- a shipped standalone TPM2 PCR-bound KEK custody backend and `xavi-duo-tpm2-custody` CLI;
- authenticated wrapping of PQ private objects while explicitly avoiding any claim that TPM hardware natively executes ML-DSA/ML-KEM;
- hardware-bound attestation requirements for high-assurance `tpm2://` and `pkcs11://` operators;
- unique OCI provider container names with forced cleanup on timeout/exception;
- regression coverage for TPM custody, provider cleanup, and cgroup-manager fallback;
- updated standalone release/audit metadata and a reproducible v0.8.2 artifact set.

Validation for this release: **92/92 Python** and **37/37 Node/WASM/FHE** tests, including **10/10 new v0.8.2 TPM/provider regressions** and an independently rerun **14/14 provider-backed Python subset on prod3**. Two independent deterministic release builds produced byte-identical source archives, wheels, and release manifests. Organizational ML-DSA-87 release signing remains pending until a current configured non-exporting release root is provisioned.

## Quick start

```bash
cd v0.8.2
python3 -m pip install .

xavi-duo keygen --out alice.xdek
printf 'hello DUO\n' > plain.txt
xavi-duo encrypt --key alice.xdek --in plain.txt --out secret.xde \
  --receipt secret.receipt.json --aad 'example:v1' --pad-to 1024
xavi-duo verify-receipt --key alice.xdek --frame secret.xde \
  --receipt secret.receipt.json --aad 'example:v1'
xavi-duo decrypt --key alice.xdek --in secret.xde --out recovered.txt \
  --receipt secret.receipt.json --aad 'example:v1'
cmp plain.txt recovered.txt
```

For the threat model, custody requirements, PQ provider boundary, remote execution, and encrypted-compute design, start with `v0.8.2/README.md`, `v0.8.2/SECURITY.md`, `v0.8.2/THREAT_MODEL.md`, `v0.8.2/HIGH_ASSURANCE_PROFILE.json`, and `v0.8.2/PROTOCOL.md`.

## Versioned repository model

Every published revision is a **self-contained root-level version directory**. A reader does not need an earlier revision to build, test, or audit a later one. Released/tagged version directories are immutable; corrections and new work go into a new version directory.

```text
xavi-encrypt/
├── v0.8.0/        # frozen first canonical release
├── v0.8.1/        # frozen hardening release
├── v0.8.2/        # current TPM/provider hardening release
├── VERSION_INDEX.json
├── CHANGELOG.md
└── tools/verify_repository.py
```

Repository integrity check:

```bash
python3 tools/verify_repository.py
```

Version test suite:

```bash
cd v0.8.2
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Some PQ-provider, FHE, hardware-custody, and accelerator tests require the corresponding container/runtime/hardware environment documented by the version.

## Release verification

Each canonical version preserves its source archive, wheel, release manifest, reproducibility proof, artifact hash list, signing request, and custody-discovery record under `vX.Y.Z/release/`. `VERSION_INDEX.json` binds their SHA-256 digests.

The v0.8.2 release intentionally has **no detached release signature yet**: high-assurance release signing requires ML-DSA-87 through a non-exporting custody operator. An exportable file key is not substituted merely to make the status look green.

## Licensing

Unless a component explicitly states otherwise, this repository is dual-licensed under **MIT OR Apache-2.0**. See `LICENSE-MIT` and `LICENSE-APACHE`.
