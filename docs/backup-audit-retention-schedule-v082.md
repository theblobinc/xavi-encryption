# v0.8.2 on-premises backup audit schedule, retention and key rotation — 2026-11-06

**Status: deployed and tested (integrity timers only).** Frozen release data and independently installed organizational release-only trust remain unchanged. This document describes the live host-local audit schedule, not authority to delete backups or issue a replacement signing identity.

## Verified schedules

All eight timers below are enabled and active in local systemd. Each associated oneshot service was executed *via systemd* after deployment and returned `Result=success`, `ExecMainStatus=0`. The code copied to `/usr/local/libexec/xavi-encrypt-v082-audit.py` on all three hosts is root-owned mode `0555`, SHA-256 `bf0a8eaa62ed79491e680686ed6f6381aad9ec7ea5f189d3eaab2e1dc6ce37ba`.

| Host | Timer | Runs | Scope |
|---|---|---|---|
| prod3 | `xavi-encrypt-v082-root@prod3-root.timer` | daily | root-only five-file restored custody inventory, protected audit receipt and detached signature SHA-256 |
| prod3 | `xavi-encrypt-v082-user@prod3-seaweed.timer` | daily | rootless Podman SeaweedFS filer encrypted-object readback and exact ciphertext hash |
| prod3 | `xavi-encrypt-v082-deep-prod3.timer` | weekly | repeat independently installed, protected, release-only ML-DSA-87 verification using approved local OCI OpenSSL provider |
| prod4 | `xavi-encrypt-v082-root@prod4-root.timer` | daily | root-owned original and vm1-recipient CMS archives, root-only prod4 audit receipt, cert fingerprint/mode/60-day window |
| prod4 | `xavi-encrypt-v082-user@prod4-user.timer` | daily | local datastore2 and prod3 NFS ciphertext hashes, file modes and pinned NFS mount source |
| prod4 | `xavi-encrypt-v082-deep@prod4-root.timer` | weekly | authenticated AES-256-GCM/RSA-OAEP decryption with prod4's own recipient key, exact five-member inventory |
| vm1 | `xavi-encrypt-v082-root@vm1-root.timer` | daily | root-owned original and vm1-specific CMS archives, audit receipt, certificate fingerprint/mode/60-day window |
| vm1 | `xavi-encrypt-v082-deep@vm1-root.timer` | weekly | authenticated decryption with vm1's **independent** recipient private key, exact five-member inventory |

The daily root timers use host-local `03:10`; daily unprivileged timers `03:40`; weekly deep timers Sundays `04:30`. Systemd applies up to 20 minutes random delay and five-minute accuracy; `Persistent=true` triggers a missed calendar check after a reboot. The user service runs as unprivileged `tbi`, with no access to root-owned private recipient keys. Deep decryption checks use memory-only plaintext and never save a decrypted custody tarball.

The prod3 deep verifier requires an OCI provider to verify ML-DSA-87; its dedicated `xavi-encrypt-v082-deep-prod3.service` preserves the local Podman execution environment while other deep profiles retain stricter read-only systemd sandboxing. The generic `deep@prod3-root.service` was **tested and rejected** under too-strict capabilities; that template is **not scheduled** for prod3.

## What a PASS establishes

- Original encrypted CMS archive SHA-256: `ccd1438917fba5f108fb3d6f7e8facc9f190b7acb3c2f56f086e6f751fa6b41d`.
- Independently re-encrypted vm1 CMS archive SHA-256: `da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511`.
- Installed root-owned recipient keys are regular `0600` files in `0700` directories; the correct public certificate matches an exact pinned SHA-256.
- A recipient certificate has **more than 60 days** remaining before expiry; a failing check is an operational rotation warning. X.509 expiry by itself does *not* delete an RSA decryption key or necessarily render previously encrypted CMS objects undecryptable.
- Each configured storage endpoint returns the frozen expected ciphertext; a missing file, altered ciphertext, unexpected file permissions, unknown NFS source, missing recipient or invalid/decrypting certificate fails closed.
- Weekly prod4/vm1 checks authenticate and decrypt the archive **with their own root-only private keys**, and verify exactly five expected TPM-sealed/AEAD-encrypted member hashes in memory.
- Weekly prod3 checks reverify the saved return-drill signature under the independent root-owned release-only trust policy; this **does not** run a fresh TPM seal/unseal/sign operation each week.

Prior operator-approved full restore drills have already exercised prod4 and vm1's distinct decryption recipients, returned sealed custody objects to original prod3, and produced **`TRUSTED_RELEASE_PASS`** after same-TPM signing. These are separate historical tests, not inferred from periodic hash checks.

## Audit journal and safe operation

To inspect jobs (on the respective host):

```sh
systemctl list-timers --all 'xavi-encrypt-v082*'
systemctl show xavi-encrypt-v082-root@prod4-root.service -p Result -p ExecMainStatus
journalctl -u xavi-encrypt-v082-root@prod4-root.service --since '2 days ago' --no-pager
journalctl -u xavi-encrypt-v082-deep@vm1-root.service --since '14 days ago' --no-pager
journalctl -u xavi-encrypt-v082-deep-prod3.service --since '14 days ago' --no-pager
```

Every verification emits a compact JSON `XAVI-ENCRYPT/BACKUP-AUDIT/v1` result and exits nonzero on failure. The host journal records it; **external push notifications or pager integrations are not yet configured**. Do not interpret an expired or missing timer as a passing check. In an incident, investigate the failed location, preserve old bytes/receipts, compare against independently trusted pinned digests, and require an owner-approved repair. No script or systemd unit automatically copies over a corrupt backup.

Do not run a root-owned auditor from a writable Git checkout or `PYTHONPATH`; install the independently verified, root-owned `0555` source and execute Python with `-I`. The frozen verifier uses a protected pinned venv and a separately installed `/etc` trust policy.

## Retention: frozen, versioned, no pruning

The v0.8.2 ciphertext and protected receipts must be retained under the immutable **version name** `v0.8.2`; create a *new* directory/version and a distinct pinned audit profile for any future release, instead of replacing these bytes. The machine-readable proposal is `backup-policy/v0.8.2-local-governance.PROPOSED.json`. It does **not** itself impose filesystem WORM, append-only protection, or independent owner authorization.

At present:
- Five original-ciphertext copies span prod4 local root disk, prod4 separate datastore2 device, vm1 local disk, prod3 NFS export, and prod3 SeaweedFS filer.
- A separately verified vm1-recipient CMS archive is root-only on prod4 and vm1.
- Prod3 NFS and SeaweedFS share the **same prod3 storage failure domain**. No AWS and no off-site provider.
- Backups are logically frozen by exact digest checks, root/private permissions, and fail-closed tools; they are **not proven storage-hardware WORM**. A privileged administrator or storage-system owner can still delete or replace a copy.
- **No automated deletion, pruning, garbage collection, source overwrite, emergency restore-over-live, or key rotation is authorized or enabled.** Old verified backups and signing receipts should only be retired after an independent owner decision and evidence of an appropriately validated successor.

## Successor CMS recipient rotation procedure (not yet executed)

1. **Identify** the recipient certificate nearing 60 days to expiry or subject to a security incident. Record its pinned fingerprint, storage host, owner approval and current encrypted-archive digest.
2. **Generate a new recipient key** in a new root-owned, restricted **versioned directory** on its own host; never overwrite the existing prod4/vm1 keys or move their private halves across hosts. Do not reuse a one-time transport key as a long-term recipient.
3. **Pin and distribute only the new public recipient certificate.** Authenticate its fingerprint through a separate trusted channel before rewrapping the five already-sealed objects into a new authenticated AES-256-GCM CMS envelope.
4. **Retain both old and new envelopes** while independently authenticating/decrypting the new one. Verify exact allowlisted five-member hashes, wrong-recipient rejection and ciphertext tamper rejection. Record root-only receipts with new capsule and certificate hashes.
5. **Conduct a fresh return-to-original-prod3-TPM signing drill** from the new recipient, then independently check `TRUSTED_RELEASE_PASS` against the unchanged v0.8.2 release-only policy. Preserve the complete audit ancestry.
6. **Activate only after owner review.** Add a new explicitly versioned monitoring profile/recipient fingerprint and an independently authorized backup-retention decision. Never make an old snapshot unreadable before confirming that a separate, independently held recipient still works.
7. **Retire old keys only after independent approval and custody inventory reconciliation.** File unlinking does not prove forensic erasure. Compromise handling/revocation of backup access is distinct from historical ML-DSA release-signature trust.

An expired CMS recipient certificate does not automatically confer or revoke release trust. The release signer itself remains TPM-bound to the original prod3 physical TPM under `sha256:7`. No key rotation or backup scheme substitutes for a new independently approved signing root after permanent TPM loss.

## Open cleanup boundary

The test-only prod3 `/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return-recipient/return.key.pem` still exists with root-only mode `0600`. An ordinary root unlink request was stopped by platform safety controls **before execution**. Do not bypass that control, falsely report successful retirement, or remove the permanent prod4/vm1 recipient private keys. It remains a specific administrative cleanup request pending authorized handling.

**Security review:** [XAVI Encryption PR #1](https://github.com/theblobinc/xavi-encryption/pull/1); this operating schedule does not merge the PR or expand its independent release trust policy.
