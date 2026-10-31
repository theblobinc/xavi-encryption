# Threat Model

## Protects against

With a secret uncompromised key and unique nonces, XDE2 is designed to protect plaintext confidentiality and integrity against an attacker who can read, copy, modify, truncate, replay, or inject XDE2 frames.

Application AAD can bind protocol/session/sender/recipient/purpose identifiers so cross-context replay is rejected when the recipient supplies the required AAD.

## Does not protect against

- endpoint compromise or key theft;
- malicious plaintext before encryption or after decryption;
- nonce-state rollback caused by cloned/restored key-state pairs;
- denial of service;
- traffic analysis beyond explicit padding;
- malicious or compromised crypto libraries/OS RNG;
- future cryptanalysis of the selected standard primitives;
- public-key key distribution by itself.

## DUO-specific attacker knowledge

Assume the attacker knows Rev009, the exact XDE2 algorithms, all source code, and the fact that cells are DUO tokens. Security must not depend on obscurity of the numeral system. Only secret key material and, when added, validated KEM secrets are secret.

## DUO-context observer model

An observer of an XDE2 frame sees DUO glyphs but not the formatting key-derived per-cell modulus/offset schedule. A glyph may have many legal numeric interpretations across candidate moduli according to `N(M)=c(M-1)+r`. This ambiguity is deterministic and measurable, not assumed random.

The threat model therefore treats hidden DUO context as a keyed encoding layer that can increase representation uncertainty for an observer. It is never credited as the sole confidentiality or authenticity mechanism. Compromise of the formatting context must still leave AEAD/PQ/FHE boundaries responsible for cryptographic protection.

