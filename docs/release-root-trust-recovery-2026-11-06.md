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

- **Local and encrypted off-node copies:** a local root-only copy remains on prod3. A second, CMS AES-256-GCM encrypted, RSA-OAEP wrapped archive is now stored root-only on prod4. It is not geographically redundant or a remedy for TPM loss. The independently held prod4 recipient key is a separate recovery dependency and still requires an escrow/rotation plan.
- **Same physical TPM:** a saved sealed object is not a portable signing key. Restoring the backup to a different TPM, or booting into a PCR state not accepted by the policy, will not make it usable.
- **No simulated live-PCR change:** the negative tests exercised an incorrect PCR selection and TPM authorization path without modifying hardware PCR registers. A genuinely changed PCR-7 value was **not** created or tested.
- **No unattended trust expansion:** the root policy authorizes only version 0.8.2. Revocation or adding a new release is an explicit independent administrative approval. The copy in `trust-policy/` is a proposal, not the deployed policy.
- **Cryptographic authority is narrow:** successful release signature verification is not an audit, FIPS certificate, claim of TPM-native PQ execution, or runtime execution permission.
- **Recovery process:** restore the five encrypted/sealed objects *only* to an isolated `0700` root-owned directory under the same TPM; compare inventory digests before use; verify with the pinned public key and frozen manifest; never overwrite the live custody or extract unwrapped private material for backup.
- **Protected runtime:** the verifier must run with Python `-I` and an installed, root-owned, pinned v0.8.2 verification package. Do not execute the trust CLI from an uncontrolled Git checkout or import path.

## Off-node encrypted copy — prod4

The custodian encrypted the five verified sealed/encrypted files **in memory as a streamed tar input** to OpenSSL CMS; no unencrypted tarball was written to prod3 disk. The recipient private key was generated separately on prod4 and was not transferred to prod3.

- Off-node archive: prod4 `/var/backups/xavi-encrypt/v0.8.2/custody.cms.der`, root-only mode `0600`.
- SHA-256: `ccd1438917fba5f108fb3d6f7e8facc9f190b7acb3c2f56f086e6f751fa6b41d`, 21,077 bytes.
- Encryption: CMS **AES-256-GCM** authenticated encryption, RSA-OAEP recipient key transport; prod4 recipient private key path `/var/lib/xavi-encrypt-backup/v082-recipient/recipient.key.pem`, root-owned mode `0600`.
- Recipient certificate SHA-256: `cf8127e10957d554f0b648ea26666c0595992869c09b5d0b8533d29ba1fe7cfc`; certificate fingerprint (SHA-256) `3D:08:30:2A:24:41:59:01:10:E5:20:B3:91:11:CC:ED:B2:26:AD:F9:B4:C9:89:E5:1D:0C:F3:36:9A:9E:3D:FB`.
- Authenticated CMS decryption on prod4 **PASS**. All five in-memory restored archive members matched the exact prod3 SHA-256 inventory. No decrypted archive was saved to disk.
- This is an encrypted **off-node** backup, but **not off-site**: prod3's original physical TPM must still be available and satisfy its PCR policy to use the restored signing identity.

### Return-copy checkpoint (not yet a complete restore)

Prod3 generated a one-time RSA recipient private key in its root-only recovery-test directory. Prod4 authenticated and decrypted its off-node archive, checked all five member digests, then immediately re-encrypted the in-memory tar for prod3 using AES-256-GCM and RSA-OAEP. The return ciphertext SHA-256 is `54e5471871ce503bf5e8a6345c9a2536fdbcdab7a6bcd6a7018b2c67d2cd02b3`. That **encrypted** file was transferred to prod3; its received digest matches.

The versioned, allowlisted restore validator `tools/offnode_return_restore_v082.py` compiles and is staged on this review branch. **Its privileged installation/execution was blocked before execution.** Therefore, the return archive has **not** yet been restored into a new test custody directory or used to perform a fresh TPM-backed signing operation. Do not claim that gate passed. The previously completed same-TPM local-restore sign/verify PASS is a different gate.

Before closing the return-copy gate, use the normal approved root execution path to run the pinned validator, verify the return-restored directory contains exactly the five root-owned `0600` files, sign the frozen v0.8.2 manifest through that *new* directory with the original prod3 TPM, and independently verify the signature. Then retire the short-lived return-recipient private key and destroy transient unprotected recovery material where applicable, retaining only bounded audit evidence.

### Remaining dependencies

1. Independent escrow/recovery for the prod4 backup recipient private key. Losing prod4 or that key makes the CMS archive unreadable even if prod3's TPM survives.
2. Genuine off-site or independent-failure-domain storage and scheduled backup validation.
3. A permanent-TPM-loss response requiring independently approved new signing-root enrollment, **not** attempting to export the original TPM-bound key. See `docs/release-root-rotation-runbook.md`.
4. Final off-node **return-restored TPM signing** gate (pending as described above).
