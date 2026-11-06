# XAVI-DUO v0.8.2 encrypted custody backup replicas

**Status:** validated node-level and storage-service replicas, 2026-11-06. This file documents ciphertext-only locations, not live signing authority. No AWS infrastructure is used.

## Independently verified storage copies

All five copies contain the *same authenticated CMS AES-256-GCM and RSA-OAEP ciphertext* originally encrypted for the **prod4** root-owned backup recipient. The exact file is 21,077 bytes, SHA-256 `ccd1438917fba5f108fb3d6f7e8facc9f190b7acb3c2f56f086e6f751fa6b41d`.

| Location | File / API object | Protection | Underlying host/failure domain | Verification |
|---|---|---|---|---|
| prod4 local | `/var/backups/xavi-encrypt/v0.8.2/custody.cms.der` | root:root, directory 0700, file 0600 | prod4 local filesystem | original authenticated decrypt and 5/5 custody digest audit PASS |
| prod4 separate data disk | `/datastore2/xavi-encrypt-backups/v0.8.2/custody.cms.der` | restricted directory 0700, file 0600, tbi account | prod4 `/datastore2` separate ext4 filesystem/device from primary root | independent SHA-256 matches original |
| vm1 local | `/var/backups/xavi-encrypt/v0.8.2/custody.cms.der` | root:root, directory 0700, file 0600 | vm1 local root filesystem, NOT its prod3 NFS mount | independent SHA-256 matches original |
| existing NFS backup export | `/srv/xavi-backups/xavi-encrypt/v0.8.2/custody.cms.der` as mounted on prod4 | file 0600 in restricted directory 2700, tbi account | prod3 `10.77.0.2:/xavi-storage/.nfs-exports/backups` backed by prod3 `/mnt/store` | independent SHA-256 matches original |
| SeaweedFS filer | `/xavi-backups/encrypt/v0.8.2/custody.cms.der` on prod3 rootless `xavi-seaweedfs` filer | encrypted CMS payload; Filer API access must be evaluated before calling its namespace access-controlled | prod3 `/mnt/store/xavi-storage/seaweedfs/data` | filer returned HTTP 200, 21,077 bytes; streamed readback SHA-256 matches original |

These are **five storage paths across three server nodes**, not four independent storage failure domains. SeaweedFS and the NFS export share the same prod3 storage host, and vm1's `/mnt/prod3-store` is also prod3 NFS; the vm1 copy above is specifically on its local root filesystem. This is **not off-site backup** and must not be presented as site-disaster protection.

## Decryption and signing dependencies

The canonical archived contents are exactly five root-owned TPM-sealed / AEAD-encrypted objects. An original-TPM return-and-sign drill already passed: copied custody bytes can sign the frozen 0.8.2 manifest with the **original prod3 TPM** and `sha256:7` PCR policy, then independently return `TRUSTED_RELEASE_PASS`. No plaintext private signing key or plaintext KEK is stored in any replica.

The five matching CMS copies described above are encrypted to the root-owned **prod4** recipient private key. This is a decryption dependency even when the same ciphertext exists elsewhere; duplication of its ciphertext alone cannot survive loss of the prod4 key.

A second, independent root-owned RSA-3072 CMS recipient was provisioned on **vm1** to permit a *different* archive envelope. Its certificate SHA-256 is `5f98e6ea8c65fef92080783f317b0003e0a0cdddc17759edf40764090caf7b02` and X.509 SHA-256 fingerprint `77:D4:83:AE:2E:01:3E:29:01:CC:2B:6D:B1:6F:25:D5:28:35:79:8E:10:C2:59:21:02:4A:13:14:BA:01:87:76`. Only its **public** certificate was transferred to prod4. The independent vm1-recipient rewrap helper was staged and syntax-checked as `tools/rewrap_custody_to_vm1_v082.py`, but both privilege-approval requests for installing that helper on prod4 **expired without execution**. Consequently the new vm1-recipient CMS capsule has **not** been created or verified. Until it is present and independently decrypted and hash-checked on vm1, the vm1 recipient is **not** a proven independent recovery path.

## Guardrails

- No AWS.
- No private-key material or TPM sealed custody files in Git, ordinary NFS, or the SeaweedFS filer. These remote copies contain only authenticated **already-encrypted CMS ciphertext**.
- The three transient tbi-owned ciphertext transfer files on the servers, and the temporary ciphertext file copied into the SeaweedFS container, were unlinked after their verified permanent replicas were established. Unlinking does not constitute forensic block erasure. Replication, readback, and signature verification are distinct gates. SHA-256 readback checks ciphertext integrity but does not by itself demonstrate decryption or TPM restore.
- SeaweedFS's filer was writable through its rootless container's local API. The specific namespace's authentication/authorization has not been independently proven; do not claim SeaweedFS object-level access restriction merely from ciphertext encryption.
- True cross-TPM recovery is **not supported** by this backup. Physical loss of prod3's TPM requires a new independently authorized signing identity and an explicitly admitted new release-root trust policy.
- Keep future backups immutable/versioned and retain a verifiable recovery receipt for each independently encrypted recipient. Never replace the live v0.8.2 custody in place.

## Next gates

Obtain an approved privileged installation/execution of the already versioned rewrap helper (do not duplicate pending approval requests); verify the vm1-recipient CMS envelope is written root-only, transferred to vm1, independently authenticated-decrypted and 5/5 member-hash verified; establish its independent ciphertext digest and a root-owned audit receipt. Consider copy placement and retention policy separately from cryptographic key custody and from site-level disaster recovery.
