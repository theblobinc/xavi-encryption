# Threat Model

## Protects against

With a secret uncompromised key and unique nonces, XDE2 is designed to protect plaintext confidentiality and integrity against an attacker who can read, copy, modify, truncate, replay, or inject XDE2 frames.

Application AAD can bind protocol/session/sender/recipient/purpose identifiers so cross-context replay is rejected when the recipient supplies the required AAD.

## Does not protect against

- endpoint compromise or key theft;
- malicious plaintext before encryption or after decryption;
- full local snapshot rollback when the deployment does not use the independent rollback-domain anchors required by the high-assurance profile;
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
## Stateful rollback and replay

The standard/local profile cannot distinguish a complete rollback of all local state from an earlier valid machine snapshot. The high-assurance profile therefore requires independent rollback-domain anchors. Nonce chronology uses an external monotonic high-water mark. Remote replay chronology uses the v0.8.1 claim-bound two-phase `prepare`/`commit` protocol with durable local pending state. A completed external claim observed after local rollback is treated as rollback/conflict and quarantines state; it is not accepted as an executable retry.
