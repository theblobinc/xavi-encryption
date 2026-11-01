# XAVI-DUO Custody Backends — v0.8.2

XDE2/XDE2-PQ2 separates the wire protocol from private-key custody. Portable tasks carry typed custody references and never carry private-key bytes.

## Security classes

| Scheme | Strength | Intended backend | Security boundary |
|---|---:|---|---|
| `file://` | 1 | encrypted/local software storage | protects at rest; privileged host compromise can recover the key |
| `authority://` | 2 | software custody plus approval/audit | authority-gated use; no hardware anti-extraction |
| `remote://` | 3 | private operation remains on another custody node | requesting worker never receives private bytes |
| `tpm2://` | 4 | TPM2-sealed KEK wrapping PQ private objects | hardware-bound wrapping secret and PCR policy |
| `pkcs11://` | 4 | HSM/token/smart-card provider | hardware-provider interface; device-specific validation required |

Security classes are not equivalent. Hardware custody improves resistance to offline extraction but does not make a software PQ implementation execute inside the TPM.

## TPM2 model shipped in v0.8.2

`xavi_duo_tpm2_custody.py` implements the standalone `tpm2://` backend using `tpm2-tools` argv execution without shell interpolation.

The TPM seals a random 256-bit KEK under a PCR policy such as `sha256:7`. The KEK wraps ML-DSA or ML-KEM private PEM objects with ChaCha20-Poly1305 authenticated encryption.

```text
TPM2 PCR policy
    -> unseal 256-bit KEK
    -> authenticate/decrypt wrapped PQ private PEM
    -> place PEM in secure temporary signer storage
    -> pinned OpenSSL 3.5 ML-DSA / ML-KEM operation
    -> destroy temporary plaintext
```

The TPM **does not implement ML-DSA or ML-KEM**. `hardware_bound=true` means the wrapping key is TPM/PCR-bound. The private PEM is present ephemerally in the custody process while the external PQ provider performs the operation.

High-assurance policy now requires `hardware_bound=true` for `tpm2://` and `pkcs11://` private operators. A callback cannot satisfy a TPM/HSM URI merely by claiming that it is non-exporting.

## Release-root workflow

The bundled CLI supports a complete release-root workflow once the process has permission to use the TPM device:

```bash
xavi-duo-tpm2-custody \
  --root /var/lib/xavi-duo/custody/prod3 \
  --node prod3 \
  --pcr sha256:7 \
  provision-kek

xavi-duo-tpm2-custody \
  --root /var/lib/xavi-duo/custody/prod3 \
  --node prod3 \
  --pcr sha256:7 \
  provision-mldsa \
  --name release-root-mldsa87 \
  --algorithm ML-DSA-87 \
  --public-out /var/lib/xavi-duo/custody/prod3/release-root-mldsa87.pub.pem

xavi-duo-tpm2-custody \
  --root /var/lib/xavi-duo/custody/prod3 \
  --node prod3 \
  --pcr sha256:7 \
  release-sign \
  --name release-root-mldsa87 \
  --public-key /var/lib/xavi-duo/custody/prod3/release-root-mldsa87.pub.pem \
  --manifest RELEASE.json \
  --output RELEASE.sig.json
```

The release signature remains the ordinary `XAVI-DUO/RELEASE-SIGNATURE/v1` ML-DSA-87 object and is independently verifiable without TPM access.

## Historical reference-lab evidence

On 2026-10-29, prod3 recorded a tested TPM2 KEK profile at `tpm2://prod3/default-kek`, PCR policy `sha256:7`, wrapping ML-KEM-1024 and ML-DSA-65 objects. That is historical integration evidence, not proof that a current ML-DSA-87 release root is provisioned.

The v0.8.2 release remains unsigned until the current release-root object is actually provisioned and used.
