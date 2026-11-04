# v0.8.2 detached ML-DSA-87 release attestation

Published: 2026-11-04. This is an **append-only public attestation** to the frozen `v0.8.2` release; it does not modify the release directory, original `RELEASE.json`, or annotated tag.

- Frozen commit/tag target: `aa65bd5acbbc9789ad6731fc26bbda3fe3b68b21` (`v0.8.2`).
- Release manifest file SHA-256: `63dfeb027479f0f8b69caff3a66acce0bf1f2c55f3a6d0ce007f5168b754feb7`.
- Canonical manifest SHA-256 covered by the signature: `afecddbe0941794be169e9a097ced7640e5432830d97ab2648f9a1d02bc92f26`.
- Detached signature file SHA-256: `b600df191b575254f37f4ce4e43ce830a15b6ef16fd52892733779ac96985c20`.
- Public key SHA-256: `ca74ba83611d2358efa2748f5945892069a55e2d3e1372ed53b5a1da5a851612`.
- Signature algorithm: ML-DSA-87; raw signature: 4,627 bytes.
- Verification: **PASS** on prod3 and prod4 using the v0.8.2 verifier as the unprivileged `tbi` user.

## Reproduce signature verification

From the repository root, with the v0.8.2 Python dependencies installed:

```sh
cd v0.8.2
python3 -m xavi_duo_release verify \
  --public ../attestations/v0.8.2/release-root-mldsa87.pub.pem \
  --manifest release/XAVI_DUO_Encryption_v0.8.2_2026-11-02.RELEASE.json \
  --signature ../attestations/v0.8.2/XAVI_DUO_Encryption_v0.8.2_2026-11-02.RELEASE-SIGNATURE.json
```

The signer is `tpm2://prod3/release-root-mldsa87`, wrapped with a 256-bit TPM2-sealed KEK under `sha256:7` PCR policy. The TPM does **not** run ML-DSA natively: the pinned OpenSSL provider performs the operation with ephemeral signer-process exposure of private key material. No private keys or TPM sealed blobs are included here.

**Trust boundary:** The signature JSON intentionally states `"authority": false`. Cryptographic verification does not by itself establish an independently trusted organizational root, FIPS certification, a security audit, or runtime authority. An owner/verifier must independently pin and authorize the public-key fingerprint through a trusted process.
