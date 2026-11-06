# v0.8.2 release-root trust and custody recovery — 2026-11-06

## Scope and verification

The original **v0.8.2 tag and release manifest are frozen**. The detached ML-DSA-87 release signature was published independently in `attestations/v0.8.2/` on 2026-11-04.

The newly registered trust anchor is an **independent root-owned policy** installed on the custodian host, **not** the candidate JSON tracked in this repository. Repository content cannot self-authorize an unknown signing key.

- Trust-policy schema: `XAVI-ENCRYPT/RELEASE-TRUST-POLICY/v1`
- Purpose: `release-manifest-verification-only`
- Approved release: exactly `0.8.2`, canonical manifest SHA-256 `afecddbe0941794be169e9a097ced7640e5432830d97ab2648f9a1d02bc92f26`
- Approved public-key SHA-256: `ca74ba83611d2358efa2748f5945892069a55e2d3e1372ed53b5a1da5a851612`
- Algorithm: ML-DSA-87
- Custody: `tpm2://prod3/release-root-mldsa87`, TPM 2.0 KEK sealed to `sha256:7`
- The TPM protects the **wrapping key**; ML-DSA runs inside the pinned OpenSSL provider, not inside TPM hardware.
- **No runtime authority** is conferred. The release signature's original `authority: false` field is preserved.

### Validation completed

The root-owned, isolated Python verifier returned **`TRUSTED_RELEASE_PASS`** for the unmodified frozen release. Before root policy installation it failed closed. Nine scope/tamper unit tests passed on a separate checkout, including rejected revocation, unknown key, digest mismatch, unauthorized release version, modified signature, and runtime-authority escalation.

The custody backup, created under a private root-only location on **the original TPM host**, contains exactly five files: sealed TPM private and public objects, the PCR policy digest, KEK metadata, and one authenticated-encrypted ML-DSA-87 signing-key object. All files are owned by root with mode `0600`; directory permissions are `0700`.

Independent checks established:

1. Live, backup, and restored custody byte identity for all **5/5** files.
2. Recovered custody **successfully signed** the exact frozen v0.8.2 manifest using the original TPM.
3. Independent verification of the recovered signature returned **PASS** with the pinned ML-DSA-87 public-key ID.
4. Requesting PCR bank/index `sha256:8` against metadata sealed for `sha256:7` was denied before a signature was produced.
5. A **real TPM policy session** for PCR 8 could not unseal the PCR-7-bound object. PCR measurements were **not changed**.
6. A test-only encrypted object was modified and its ordinary SHA-256 field recalculated; authenticated encryption still denied use (`TPM custody authentication failed`) without emitting a signature.
7. No plaintext KEK or signing-key PEM was included in the backup or published to the repository.

An internal root-only receipt records the local backup inventory and SHA-256 values. Do **not** commit the custody blobs, root-only receipt, or recovery test objects.

## Operational guardrails and remaining boundaries

- **Local backup only:** the current recovery copy resides on the same host as the TPM. It is *not* off-node, geographically redundant, or a recovery plan for host/TPM loss. A separately approved off-node encrypted-backup system is still required.
- **Same physical TPM:** a saved sealed object is not a portable signing key. Restoring the backup to a different TPM, or booting into a PCR state not accepted by the policy, will not make it usable.
- **No simulated live-PCR change:** the negative tests exercised an incorrect PCR selection and TPM authorization path without modifying hardware PCR registers. A genuinely changed PCR-7 value was **not** created or tested.
- **No unattended trust expansion:** the root policy authorizes only version 0.8.2. Revocation or adding a new release is an explicit independent administrative approval. The copy in `trust-policy/` is a proposal, not the deployed policy.
- **Cryptographic authority is narrow:** successful release signature verification is not an audit, FIPS certificate, claim of TPM-native PQ execution, or runtime execution permission.
- **Recovery process:** restore the five encrypted/sealed objects *only* to an isolated `0700` root-owned directory under the same TPM; compare inventory digests before use; verify with the pinned public key and frozen manifest; never overwrite the live custody or extract unwrapped private material for backup.
- **Protected runtime:** the verifier must run with Python `-I` and an installed, root-owned, pinned v0.8.2 verification package. Do not execute the trust CLI from an uncontrolled Git checkout or import path.

## Next work

Build and approve independent off-node encrypted custody storage, with root-only access, integrity receipts, and audited return-copy testing on the original TPM. Specify a separate TPM-loss contingency (for example, authorized signing-root rotation followed by explicit trust re-enrollment); do not imply that copying sealed TPM material provides cross-TPM recovery.
