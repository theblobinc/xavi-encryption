# Cryptographic Profile — Rev 1.2-dev2

## Unkeyed identity

xavi-void uses SHAKE256 with exactly 64 output bytes (512 bits), written `SHAKE256-512`, for unkeyed identities and commitments.

All domains are printable versioned ASCII and all fields are independently length framed. Identifiers use:

```text
xvoid:shake256-512:<unpadded-base64url>
```

## Authority / transport suite

The production suite identifier is:

```text
xavi-pq1-shake256-512-mldsa87-mlkem1024-kmac256-aes256gcmsiv
```

with roles:

```text
unkeyed identity : SHAKE256-512
signature        : ML-DSA-87
key establishment: ML-KEM-1024
keyed derivation : KMAC256
AEAD              : AES-256-GCM-SIV
```

Plain SHAKE is not substituted for keyed KMAC semantics.

## Provider boundary

The current environment has AES-256-GCM-SIV support but does not contain ML-KEM/ML-DSA or a secure FHE library. Production operations therefore go through strict external provider sidecars. The included development provider uses non-PQ test constructions and is named `DevelopmentPQProviderNOTSECURE` to prevent accidental security claims.

## Transport separation

Transport identities and keys are distinct from computation semantic/representation identities. A transport identity authenticates a peer; it does not alter or authorize the computation graph.
