# Release-root signing-key rotation and permanent TPM loss

**Status:** Operational design / review only. This document is **not** a completed rotation, an approved successor key, or a replacement for independent organizational authorization. It concerns the XAVI-DUO Encryption v0.8.x release attestation scheme, **not** runtime authorization.

## Non-negotiable invariants

- Release signatures and signed manifests continue to carry `authority: false`.
- No source repository commit, public key publication, or signature alone can authorize a new organizational signer. Trust comes from a separately authenticated, root-owned owner policy and its independent approval evidence.
- The currently pinned v0.8.2 ML-DSA-87 signer is `tpm2://prod3/release-root-mldsa87` with public-key SHA-256 `ca74ba83611d2358efa2748f5945892069a55e2d3e1372ed53b5a1da5a851612`.
- The existing active policy `theblobinc-xavi-encrypt-release-root-2026-11` authorizes **only** the canonical v0.8.2 manifest `afecddbe0941794be169e9a097ced7640e5432830d97ab2648f9a1d02bc92f26`.
- The TPM protects the KEK, not a native ML-DSA operator. Plaintext private-key material exists transiently inside the approved cryptographic signer process; it must not be exported into a backup or repository.
- A copied TPM-sealed KEK cannot be unsealed by a replacement TPM merely because the bytes or filesystem have been restored.

## Planned successor rotation while the original TPM is available

1. **Freeze and inventory.** Verify immutable predecessor manifests, detached signatures, public-key fingerprints, pinned provider runtime, active trust-policy hash, policy owner, and current recovery status. Record a change request with explicit scope and rollback plan.
2. **New independent custody.** Provision a *new* versioned TPM2-sealed KEK and distinct ML-DSA-87 signing identity on the intended successor TPM, with its own root-only custody, PCR selection, backup policy, and pinned verification evidence. Never overwrite old custody. Prove signing and verification of a non-release test challenge with the new key.
3. **Propose a transition certificate.** Bind predecessor and successor public-key fingerprints, former/current policy digest and epoch, algorithm, host/TPM identity claims, PCR policy, activation effective point, release scope, old-key restrictions, and the hashes of the human approval evidence. This transition proposal is not authoritative by itself.
4. **Dual signatures if possible.** Have the old and new signer each sign the *same* canonical transition proposal, so reviewers can prove both predecessor continuity and successor possession. The old signature does not self-authorize the new signer; a separately authenticated owner decision is still mandatory.
5. **Explicit owner approval.** Require independently authorized administrative confirmation through the organizational approval path (prefer distinct approvers / dual control when available). Record receipt, actor identities, decision, date, and immutable policy digest. Do not treat a successful root command alone as the policy owner's key-trust decision unless the approval ceremony says so.
6. **Constrained policy activation.** Install a new root-owned verifier policy with a monotonically ordered epoch and predecessor-policy digest. Scope old key to already committed releases and successor to explicitly admitted manifests/versions. Do not use wildcards or blanket trust of all future artifacts. If the policy system cannot authenticate epochs against an independent protected anchor, *do not claim rollback detection*.
7. **Independent tests before release.** Verify correct signers/releases pass; unrecognized signer, revoked key, altered manifest, divergent parent, unauthorized version, and old-policy resurrection fail closed. Test with the exact installed protected verifier, not only developer fixtures.
8. **Finalize publication.** Publish only nonsecret transition attestation, new public key, independent owner-policy receipt, tests and verification commands; leave old signatures intact for audit. Securely archive old signer custody after verifying retention obligations; disable future signing with the old key when the owner policy requires that.

## Emergency case: prod3 TPM physically lost or cannot unseal

The sealed backup can recover **the original files**, not their usability on a new TPM. Without the old TPM or an independently authorized recovery mechanism, there is **no valid technical path** to reproduce the old ML-DSA signing key.

1. Suspend new release signing. Mark the old signer *unavailable for future releases* without falsifying the fact that its previously issued v0.8.2 signature verified.
2. Preserve published old signatures, public keys, and the historical trust snapshot for forensic/historical verification. Separately establish whether any suspected compromise requires revocation of historical trust.
3. Start a **break-glass, out-of-band organizational owner approval** for a completely new signing identity. Require independently authenticated decision evidence (prefer two-person control). A Git commit, an inaccessible old signer, or a newly generated key **cannot** substitute for that decision.
4. Generate a new TPM-backed ML-DSA-87 signing identity on the replacement platform and validate its public key, custody receipts, isolation, and separate encrypted backup.
5. Write a successor policy specifically marking the emergency event, owner approval, changed TPM identity/PCR state, successor fingerprint, explicit permitted release manifests, predecessor policy digest, and new epoch. Adopt through the protected administrative procedure; fail closed if required approvals are absent.
6. Independently verify new signatures and the policy's restriction against unknown versions, changed manifests, and attempts to reuse the unavailable key for new releases. Preserve immutable evidence of the activation.
7. Rebuild independent off-node/recipient-key escrow; conduct a return-copy drill on the *new* TPM before declaring operational recovery.

**Do not** silently trust a key named `release-root`, automatically admit the next version, or call key replacement a restoration of the original cryptographic identity. It is a **new identity** under a new independently approved trust decision.

## Additional backup and audit responsibilities

- Current validated off-node CMS backup is encrypted and stored root-only on prod4. It remains bound to prod3's original physical TPM and current PCR policy; the prod4 RSA decryption private key is an additional single point of failure until independently escrowed.
- Escrow and test the **backup recipient decryption key** using a separate owner-approved mechanism. Do not publish it or the encrypted custody objects in the Git repo.
- Keep backup inventory, ciphertext digest, recipient-certificate fingerprint, event ID, vault location, verification receipt and expiry/rotation reminders. A SHA-256 sum alone is not an organizationally authenticated backup receipt.
- Distinguish `BACKUP_CREATED`, `OFFNODE_DECRYPT_VERIFIED`, `RETURN_TRANSFER_VERIFIED`, `RETURN_RESTORED`, `RESTORED_SIGNED`, `RESTORED_SIGNATURE_VERIFIED`, and `SUCCESSOR_TRUST_ENROLLED` as separately evidenced states. Never infer later states from earlier ones.
- Periodically test fail-closed wrong recipient, tampered ciphertext, mismatched object inventory, wrong TPM, wrong PCR, revoked signer, future version and stale-policy replay without changing live production PCR measurements.
- Retire one-time return private keys after the test and after retention needs are addressed. Do not assume an expired X.509 certificate necessarily makes previously encrypted CMS data undecryptable; recipient private-key custody is the actual confidentiality dependency.

## Current checkpoint

The root-owned v0.8.2 release-only trust policy and the original local same-TPM recovery drills are **PASS**. The prod4 encrypted copy has independently authenticated-decrypted and matched all five custody digests. The encrypted return capsule was sent back to prod3 and its SHA-256 verified. The subsequent protected *return-restored* TPM signing test is **not yet complete**; approval-gated execution was blocked before the restore validator could run. No old signer rotation has been performed.
