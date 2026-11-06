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

A second, independent root-owned RSA-3072 CMS recipient was provisioned on **vm1** to permit a *different* archive envelope. Its certificate SHA-256 is `5f98e6ea8c65fef92080783f317b0003e0a0cdddc17759edf40764090caf7b02` and X.509 SHA-256 fingerprint `77:D4:83:AE:2E:01:3E:29:01:CC:2B:6D:B1:6F:25:D5:28:35:79:8E:10:C2:59:21:02:4A:13:14:BA:01:87:76`. Only its **public** certificate was transferred to prod4. The versioned `tools/rewrap_custody_to_vm1_v082.py` was subsequently installed under root approval on prod4 and completed successfully. The resulting **independent vm1-recipient CMS archive** is stored root-only at `/var/backups/xavi-encrypt/v0.8.2/custody-vm1-recipient.cms.der` on **both prod4 and vm1**, with distinct ciphertext SHA-256 `da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511` (21,080 bytes). The original prod4-recipient ciphertext remains unchanged.

## Guardrails

- No AWS.
- No private-key material or TPM sealed custody files in Git, ordinary NFS, or the SeaweedFS filer. These remote copies contain only authenticated **already-encrypted CMS ciphertext**.
- The three transient tbi-owned ciphertext transfer files on the servers, and the temporary ciphertext file copied into the SeaweedFS container, were unlinked after their verified permanent replicas were established. Unlinking does not constitute forensic block erasure. Replication, readback, and signature verification are distinct gates. SHA-256 readback checks ciphertext integrity but does not by itself demonstrate decryption or TPM restore.
- SeaweedFS's filer was writable through its rootless container's local API. The specific namespace's authentication/authorization has not been independently proven; do not claim SeaweedFS object-level access restriction merely from ciphertext encryption.
- True cross-TPM recovery is **not supported** by this backup. Physical loss of prod3's TPM requires a new independently authorized signing identity and an explicitly admitted new release-root trust policy.
- Keep future backups immutable/versioned and retain a verifiable recovery receipt for each independently encrypted recipient. Never replace the live v0.8.2 custody in place.

## Next gates

The vm1 independent-recipient, round-trip restore, TPM-backed sign, and policy verifier gates are now **PASS**. Remaining work is security governance of the two long-lived recipient private keys, approved immutable/retained snapshots, an independent-site option if one is ever provisioned, and the strictly separate permanent-TPM-loss signing-root rotation ceremony. The one-time vm1-return key retirement request was blocked before execution and must be completed through the authorized root path.

## VM1 independent recipient and return drill — completed 2026-11-06

- **Two independent CMS encryption recipients exist.** Prod4 and vm1 each retain a distinct private key root-owned at `/var/lib/xavi-encrypt-backup/v082-recipient/recipient.key.pem` on their respective host. The backup data itself remains TPM-sealed for use only with the original prod3 physical TPM and `sha256:7` policy.
- The independently encrypted vm1 archive has SHA-256 `da336ca348b41e64d3c2afbe809b43102b0e85dff4ee2faed9c956cfa0d0c511`, 21,080 bytes, stored root-owned mode `0600` in a `0700` directory on vm1 and also root-only on prod4.
- vm1 authenticated/decrypted its own archive and independently verified **5/5 member hashes**. The original prod4-recipient ciphertext was **rejected** by vm1's private key, and an altered vm1 ciphertext was also **rejected**. The root-only vm1 audit receipt `/var/backups/xavi-encrypt/v0.8.2/VM1-INDEPENDENT-RECIPIENT-RECEIPT.json` has SHA-256 `b9de1090dcbea31ed38c3141b6f7cac193aae4f22cf0cefd5f51a3e947efb47b`.
- A one-time public return certificate from prod3, SHA-256 `a4976bca65b5372beeeb909ed1f1e537c69e678329adc9ba05440f415be56276`, was provided to vm1 **without exporting its private half**. vm1 re-encrypted the verified five-member archive in memory for this separate recipient. The resulting return CMS SHA-256 `e95d52dfcddc77e64d5562afaa3d851fcba7d91afe09abc9dc63c2cb02f12261` (21,075 bytes) was transferred to prod3 and independently hash-verified.
- The versioned, digest-pinned, root-owned `tools/vm1_return_restore_v082.py` authenticated the CMS envelope and installed precisely the five allowed files in the **separate** root-only `/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return` directory. `diff -qr` found no differences against the original five-file backup; directory modes `0700` and file modes `0600` were verified.
- An original-prod3-TPM signature from that returned custody passed independent root-owned `TRUSTED_RELEASE_PASS` verification against the frozen v0.8.2 manifest, original ML-DSA-87 public key, and installed release-only policy. Fresh signature SHA-256 `17c012770f604b3f0affde013b5f2608596cbce9944f75aa8c31ee8fc3a20df8`. No runtime authority was conferred.
- A separately approved, non-overwriting evidence recorder rechecked all five files and repeated protected trusted-release verification before writing root-only prod3 `/var/backups/xavi-duo/release-root-v082-20261106/VM1-RETURN-DRILL-RECEIPT.json`, SHA-256 `bb4ab9f6873d3ccc711f7f0ddd1296130c0fc87f1827ad99ea09c580b2ffd4cf`.
- Four temporary `tbi`-owned encrypted transfer files were unlinked after verification. **The one-time prod3 return private key remains root-only under `/var/lib/xavi-duo/release-signer/recovery-tests/v082-vm1-return-recipient/return.key.pem`: its deletion request was blocked before execution. Do not claim retirement or secure erasure.** Its removal remains an authorized cleanup gate, not a blocker to the completed independent recovery result.

**Interpretation:** There are now two genuinely distinct decryption-key recipients on separate local hosts, and the vm1 path has been independently returned and signed with prod3's original TPM. The system remains **same-site**, with no proven second-site disaster recovery or physical-TPM-loss recovery. No AWS dependencies are introduced.
