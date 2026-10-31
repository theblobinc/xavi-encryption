# XAVI-DUO Custody Backends — v0.3.0

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


XDE2-PQ2 is independent of the physical key-custody mechanism. Portable envelopes carry typed custody references and minimum-policy requirements; private key bytes are never portable task fields.

## Security classes

| Scheme | Strength | Intended backend | Security boundary |
|---|---:|---|---|
| `file://` | 1 | encrypted software storage | protects at rest; compromised host root can recover KEK |
| `authority://` | 2 | software custody plus Xavi approval/audit | authority-gated use; no hardware anti-extraction |
| `remote://` | 3 | key remains on another custody node | requesting worker never receives private bytes |
| `tpm2://` | 4 | TPM2-sealed KEK | hardware-bound wrapping secret and PCR policy |
| `pkcs11://` | 4 | HSM/token/smart-card provider | interface defined; physical provider validation still required |

The protocol does not claim equal resistance across these classes. A TPM/HSM can improve resistance to key extraction; software custody cannot protect a secret from a fully compromised privileged host to the same degree.

## prod3 TPM profile

prod3 uses TPM 2.0 custody. A random 256-bit KEK is sealed under a `sha256:7` PCR policy. The TPM does not implement ML-KEM or ML-DSA. Instead:

```text
TPM2 PCR policy -> unseal 256-bit KEK -> unwrap PQ private PEM in ephemeral memory -> isolated OpenSSL provider operation -> erase
```

Persistent references:

- `tpm2://prod3/default-kek`
- `tpm2://prod3/mlkem-1024`
- `tpm2://prod3/mldsa-65`

The persisted PQ private objects are ChaCha20-Poly1305 ciphertext authenticated to the node, key name and algorithm. Public keys remain exportable.

## Selection rule

`xavi_duo_custody.select_custody()` filters by the requested minimum strength and then prefers TPM2, PKCS#11, remote custody, Xavi authority custody, and file custody in that order. Private operations on `tpm2://`, `remote://`, or `authority://` references are pinned to the named custody node.
