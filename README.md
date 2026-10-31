# XAVI-DUO Encryption

**Standalone authenticated encryption, post-quantum transport, key custody, and encrypted-compute framework built around XDE2/XDE2-PQ2 and DUO-Math.**

XAVI-DUO Encryption is a portable security framework for protecting data and authenticated compute workloads across local, remote, hardware-backed, and encrypted-compute environments. It combines standard cryptographic primitives with typed custody, signed admission, replay protection, immutable provider identity, and a DUO-Math representation layer.

> **Current status:** v0.8.0 is an experimental high-assurance implementation that has passed the project's internal validation and reproducible-build gates. It has **not** been independently audited, accredited, or FIPS-validated, and its organizational ML-DSA-87 release-root signature is still pending.

## What it provides

- **XDE2 authenticated encryption** using ChaCha20-Poly1305 with HKDF-SHA256 key separation.
- **XDE2-PQ2 post-quantum recipient transport** using ML-KEM-1024.
- **ML-DSA authenticated identity and admission**, with ML-DSA-87 used for high-assurance identity and release-attestation paths.
- **Typed private-key custody** for `file://`, `tpm2://`, `pkcs11://`, `authority://`, and `remote://` backends.
- **Non-exporting private operations** for high-assurance signing and decapsulation.
- **Replay and nonce rollback protection**, including support for independent monotonic rollback-domain anchors.
- **Encrypted-compute integration** for FHE, Worker/WASM, OCI and native providers, with immutable provider identities and bounded execution policy.
- **Vendor-neutral accelerator policy** for GPU and other compute backends.
- **Evidence and witness records** that bind cryptographic, execution, provider, and policy state without granting authority themselves.
- **DUO-Math Rev009 wire representation**, used as an authenticated polymorphic representation layer rather than as a replacement for standard cryptography.

## Security boundary

XAVI-DUO does **not** rely on DUO-Math representation ambiguity for confidentiality or integrity.

The cryptographic boundary is provided by established primitives and explicit policy controls:

```text
ChaCha20-Poly1305       authenticated symmetric encryption
HKDF-SHA256             key separation and derivation
ML-KEM-1024             post-quantum key establishment
ML-DSA-87               high-assurance signatures and identity
FHE providers           encrypted computation where configured
Custody + policy        private-key and execution authority boundaries
DUO-Math Rev009         authenticated polymorphic wire representation
```

See [`v0.8.0/SECURITY.md`](v0.8.0/SECURITY.md) and [`v0.8.0/THREAT_MODEL.md`](v0.8.0/THREAT_MODEL.md) for the version-specific security model.

## Standalone by design

The product does **not** require the Xavi cluster, MCP, private DNS, prod3/prod4, NFS, or any fixed internal infrastructure.

The Xavi environment is used as a validation lab. Cluster-specific evidence is isolated under versioned `validation/` directories and is not a runtime dependency.

Portable deployments can use local files, TPM2, PKCS#11/HSMs, HTTPS/mTLS custody services, native providers, OCI providers, sockets, or remote transports according to deployment policy.

## Current release — v0.8.0

`v0.8.0/` is the first canonical standalone release in this repository.

Release state:

```text
PASS_INTERNAL_VALIDATION_REPRODUCIBLE_SIGNATURE_PENDING
```

The release preserves:

- the complete standalone source tree;
- deterministic source archive and Python wheel;
- release manifest and artifact hashes;
- reproducibility evidence;
- internal security/test gate results;
- release-signing request and custody-discovery evidence.

The frozen release artifacts live under [`v0.8.0/release/`](v0.8.0/release/).

## Repository model

Every published revision is a **self-contained version directory**:

```text
xavi-encryption/
├── v0.8.0/
├── v0.9.0/        # future revision
├── v1.0.0/        # future revision
├── VERSION_INDEX.json
├── CHANGELOG.md
└── tools/
```

A later version must contain everything required to understand, build, test, and audit that revision without depending on an earlier version directory. Released/tagged version directories are immutable historical snapshots; corrections belong in a later revision.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the versioning rules.

## Quick start

From the current release source:

```bash
cd v0.8.0
python3 -m pip install .

xavi-duo self-test
xavi-duo provider-status
```

For symmetric XDE2 usage:

```bash
xavi-duo keygen --out alice.xdek
printf 'hello XAVI-DUO\n' > plain.txt

xavi-duo encrypt \
  --key alice.xdek \
  --in plain.txt \
  --out secret.xde \
  --aad 'example:v1'

xavi-duo decrypt \
  --key alice.xdek \
  --in secret.xde \
  --out recovered.txt \
  --aad 'example:v1'
```

Post-quantum transport, custody-backed operations, remote execution, FHE and accelerator-backed paths require the corresponding provider/runtime configuration documented inside the version directory.

## Validation

Verify the repository's frozen release artifacts:

```bash
python3 tools/verify_repository.py
```

Run the version test suite:

```bash
cd v0.8.0
make test
```

Some provider, hardware-custody, FHE, accelerator and remote-execution tests require the corresponding runtime or hardware environment.

## Release verification

High-assurance consumers should verify a detached ML-DSA-87 release attestation using a release public key obtained through an independent trusted channel, then verify the release manifest and artifact hashes.

The v0.8.0 internal release proof is reproducible, but the organizational non-exporting ML-DSA-87 release-root signature is currently pending. Do not represent v0.8.0 as independently audited, accredited, FIPS validated, classified-system approved, or "military grade."

## Documentation

Start with:

- [`v0.8.0/README.md`](v0.8.0/README.md) — release documentation and usage
- [`v0.8.0/SECURITY.md`](v0.8.0/SECURITY.md) — security boundary and assurance model
- [`v0.8.0/THREAT_MODEL.md`](v0.8.0/THREAT_MODEL.md) — threat model
- [`v0.8.0/PROTOCOL.md`](v0.8.0/PROTOCOL.md) — protocol definitions
- [`v0.8.0/CUSTODY.md`](v0.8.0/CUSTODY.md) — custody model
- [`v0.8.0/FHE_EXECUTION.md`](v0.8.0/FHE_EXECUTION.md) — encrypted-compute plane
- [`v0.8.0/STANDALONE_DEPLOYMENT.md`](v0.8.0/STANDALONE_DEPLOYMENT.md) — portable deployment model

## Licensing

XAVI-DUO Encryption is dual-licensed under:

- **MIT License**
- **Apache License 2.0**

Unless a component explicitly states otherwise, you may use either license. See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
