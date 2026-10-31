# XAVI-DUO custody backends

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


XDE2/XDE2-PQ2 separates the cryptographic protocol from private-key custody. Portable tasks carry only a typed custody reference; they never carry private-key bytes.

| Scheme | Class | Current status |
|---|---|---|
| `tpm2://host/name` | TPM-sealed KEK wrapping software PQ keys | **Implemented/tested on prod3** |
| `authority://host/name` | encrypted software custody plus Xavi authority/audit gate | **Implemented/tested** |
| `file://path` | encrypted/local software custody | **Implemented/tested** |
| `remote://host/name` | private operation pinned to a remote custody node | policy/interface **implemented** |
| `pkcs11://provider/name` | HSM/smart-card/YubiKey class | interface **reserved; physical provider not yet tested** |

Security levels are intentionally not presented as equivalent. TPM2/PKCS#11 hardware custody can resist offline key extraction better than software custody. Software custody still uses authenticated encryption, strict file permissions, replay/authority gates and may delegate private operations to a remote hardware-custody node, but it cannot protect against a fully compromised host root to the same degree.

## prod3 hardware custody

prod3 has an AMD TPM 2.0. `tpm2-tools 5.6` is installed. A 256-bit KEK is sealed under PCR `sha256:7` at:

`/var/lib/xavi-duo/custody/prod3/default-kek`

The KEK wraps the persisted ML-KEM-1024 and ML-DSA-65 private PEMs. Only public PEMs and authenticated ciphertext wrappers are stored. Current references are `tpm2://prod3/mlkem-1024` and `tpm2://prod3/mldsa-65`.
