# XAVI-DUO Encryption Security Model

## Security boundary

XAVI-DUO is a standalone encryption and encrypted-compute suite. Confidentiality and integrity are provided by standard cryptographic primitives and their correctly implemented key/custody boundaries. DUO-Math encoding is an authenticated reversible representation and does not replace cryptographic primitives.

### High-assurance profile

The v0.8.1 high-assurance profile selects ML-KEM-1024 and ML-DSA-87, immutable provider identity, project-scoped signed remote admission, secret-blind remote FHE evaluators, hardware/external authority custody for long-lived private keys, and an independent nonce rollback anchor for stateful symmetric encryption.

Algorithm selection alone does not make a deployment FIPS validated, accredited, classified-system approved, or "military grade." Those statuses require validated modules, evaluated implementation/deployment, operational controls, key management, and external authorization.

## Remote admission

The remote worker verifies, in order, bounded input structure, sender ML-DSA-87 signature, project trust policy, short-lived authority countersignature/scope, durable replay claim, PQ transport authentication/decryption, capability/operation/provider binding, immutable provider identity, and accelerator sandbox policy before evaluation. Worker results are ML-DSA-87 signed and bind the project/policy/request/provider/evaluator result.

## v0.8.1 state and parameter binding

- ML-DSA and ML-KEM operations bind the requested parameter set to the parameter set encoded by the actual key object before signing, verification, encapsulation, or decapsulation. Metadata alone is not accepted as algorithm identity.
- High-assurance replay chronology uses a claim-bound two-phase external anchor (`prepare` then `commit`). Local expected-sequence validation occurs before external mutation, a durable pending intent bridges crash recovery, and a completed external claim observed after local rollback quarantines the replay state rather than re-executing the message.
- Symmetric key files and nonce state reject final-component symlinks and non-regular files. Sensitive mutable state is opened with `O_NOFOLLOW` where available and verified with `fstat`; bounded immutable reads use the hardened regular-file reader.
- CLI receipt generation and verification are covered by a subprocess round-trip regression gate, including authenticated receipt tamper rejection.

## Provider execution

OCI providers are inspected once and executed by exact allowlisted image ID. Native executables are permitted only when their SHA-256 is allowlisted. The runtime abstraction supports Podman or Docker and is designed to fail closed when a requested runtime/device/provider combination has not been validated.

## Input bounds

XDE2 v2 currently bounds plaintext to 16 MiB, AAD to 64 KiB, padding bucket to 1 MiB, frame/cell/token sizes, PQ envelope size, and ML-KEM ciphertext length. CLI file reads apply bounds before full allocation/parsing. Larger streaming/container formats must use a separately designed authenticated chunking protocol rather than increasing these limits casually.

## Nonce chronology and rollback

Local nonce journals are append-first, fsync durable, and recoverable; journal/head rollback inconsistency fails closed. A complete local snapshot can roll both local files back together, so high-assurance stateful encryption additionally requires an independent rollback-domain anchor (for example TPM NV, HSM/secure element, or an authenticated remote monotonic service). A detected rollback writes a quarantine marker and prevents further nonce claims until key recovery/rotation.

## Custody

- `tpm2://`, PKCS#11/HSM, or equivalent hardware/external custody may satisfy high-assurance deployment policy after device-specific validation.
- `authority://` is approval-gated software custody with an externally provisioned wrapping secret; it is not hardware bound.
- `file://` software custody encrypts keys at rest and protects them with permissions/AEAD, but cannot resist a fully compromised host/root account as strongly as a TPM/HSM.
- `remote://` keeps private operations on a designated custody provider.

Software custody is not sufficient for long-lived high-assurance production private keys under the default profile.

## FHE trust boundary

WG-RNN/WG-SFM/WG-SRNN may operate as the trusted FHE client: they can use client-side plaintext context, keys through custody APIs, decrypted outcomes, and witnessed performance data to compile/optimize encrypted work. Remote evaluators receive only ciphertext, public/evaluation/server keys, approved IR, and sanitized witness metadata. Learned routing can rank eligible providers but cannot override cryptographic, authority, provider-identity, or accelerator compatibility gates.

## Release trust

Release manifests can be signed with detached ML-DSA-87 attestations. Consumers must pin the release public key/fingerprint through an independent trust channel, verify the manifest signature, then verify artifact/tree hashes. Release signing keys are not shipped inside the release.

## Validation boundary

The Xavi cluster is a lab. Records under `validation/xavi-cluster/` demonstrate tested configurations but are not product dependencies or universal hardware claims. Every new hardware/provider/platform combination requires its own conformance and security validation.

## Rev009 rotating-modulus representation

The DUO wire layer is deliberately context-dependent. Raw glyph equality does not imply numeric equality across moduli. XDE2 keeps the keyed per-cell modulus/offset schedule out of the public frame and commits to the recomputable hidden context in evidence receipts.

This is defense in depth for representation diversity and traffic analysis. Security claims do **not** count DUO collision space as secret-key entropy and do not replace ChaCha20-Poly1305, ML-KEM, ML-DSA, FHE security, authenticated admission, or key custody.

Remote FHE control messages are also bounded independently of bulk artifacts: each inline ciphertext is capped at 1 MiB decoded and the total inline ciphertext budget is 2 MiB. Larger encrypted tensors, model state, evaluation keys, or datasets must use separately committed artifact transport. The TFHE server/evaluation key is already out-of-band.
