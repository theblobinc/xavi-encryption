# XAVI-DUO custody backends — v0.8.2

XDE2/XDE2-PQ2 uses typed custody references so encrypted workloads do not need to embed private-key bytes or depend on one physical keystore.

| Scheme | Class | v0.8.2 status |
|---|---|---|
| `tpm2://host/name` | TPM-sealed KEK wrapping software PQ keys | **implementation shipped; fake-TPM contract tests green; historical prod3 hardware validation exists; current release-root provisioning pending** |
| `authority://host/name` | encrypted software custody plus approval/audit gate | implemented/tested |
| `file://path` | local file private operator | implemented; rejected by high-assurance mode |
| `remote://host/name` | private operation pinned to another node | policy/interface implemented |
| `pkcs11://provider/name` | HSM/token/smart-card | interface reserved; high-assurance requires a hardware-bound operator |

## TPM2 implementation contract

The backend persists only:

- TPM sealed-object public/private blobs,
- PCR policy digest and non-secret metadata,
- authenticated ciphertext wrappers for PQ private keys,
- exportable public keys.

The 256-bit KEK and decrypted PQ private key are temporary. Private-operation evidence explicitly records:

- `hardware_binding = TPM2-sealed-KEK`,
- `native_pq_operation = false`,
- `private_key_exported_to_caller = false`,
- `private_key_ephemeral_process_exposure = true`.

This distinction prevents a TPM-backed-at-rest deployment from being mislabeled as native HSM ML-DSA.

## PCR behavior

The default reference profile is `sha256:7`. Provisioning creates the policy digest from the current PCR state. Unsealing starts a policy session, re-evaluates the configured PCR selection, and authorizes `tpm2_unseal` through `session:policy.session`. A PCR mismatch therefore causes the TPM operation to fail closed.

## Deployment requirement

A process using `tpm2://` must have narrowly scoped access to `/dev/tpmrm0` (or an explicitly configured TCTI). v0.8.2 does not recommend adding a general application account to the `tss` group solely to make release signing convenient. A dedicated custody service/account or equivalent least-privilege device policy is preferred.
