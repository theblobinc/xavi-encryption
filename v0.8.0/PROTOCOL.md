# XAVI-DUO Encryption Protocol — XDE2

## 1. Scope

XDE2 is an authenticated symmetric encryption protocol whose ciphertext is encoded as DUO-Math Rev009 modular tokens. It uses conventional integers only as implementation coordinates; the emitted DUO cells contain no ASCII `0` glyph.

## 2. Master key schedule

The master key `K` is 32 random bytes. Independent 32-byte subkeys are derived with HKDF-SHA256 using salt:

```text
XAVI-DUO-ENC/v1/HKDF-SHA256
```

and info labels:

```text
aead
duo-format
receipt-auth
```

This yields `K_enc`, `K_fmt`, and `K_receipt`.

## 3. Nonce chronology

Each key has an immutable random 8-byte nonce prefix `P` and append-only one-origin counter `j`.

```text
nonce = P || u32be(j)
```

`j` is claimed under an exclusive Linux file lock and successor `j+1` is appended and `fsync`ed before the nonce is returned.

## 4. Authenticated payload

Before AEAD, plaintext `m` is wrapped as:

```text
"XDP2" || u64be(len(m)) || m || random_padding
```

If `pad_to = 0`, no random padding is added. Otherwise the full payload is extended to the next multiple of `pad_to` bytes.

AEAD is RFC-8439 ChaCha20-Poly1305:

```text
blob = AEAD_Encrypt(K_enc, nonce,
                    aad = "XAVI-DUO-ENC/v1" || 0x00 || application_aad,
                    plaintext = payload)
```

The library output `blob` is ciphertext followed by the 16-byte Poly1305 tag.

## 5. Keyed DUO projection

For each byte index `i`, derive:

```text
d_i = HMAC-SHA256(K_fmt, "XDE2-cell" || nonce || u64be(i))
M_i = 2 + uint32be(d_i[0:4]) mod 65534
O_i = 2^40 + uint64be(d_i[4:12]) mod ((2^62-257) - 2^40 + 1)
N_i = O_i + blob[i] + 1
cell_i = Rev009.token_at(N_i, M_i)
```

`M_i` is a typed hidden modulus, `O_i` is a keyed hidden address window, and `cell_i` is the canonical Rev009 positive-hand modular glyph.

Decryption re-derives `(M_i,O_i)`, applies the exact Rev009 inverse recurrence to `cell_i`, checks the recovered byte is in `[0,255]`, reconstructs the AEAD blob, verifies Poly1305, and only then releases plaintext.

## 6. Text frame

```text
XDE2|nonce_cell_1....nonce_cell_12|payload_cell_1.payload_cell_2...
```

Each raw nonce byte `b` is exposed as the Rev009 global count glyph for `b+1`; this is a reversible public representation of the public AEAD nonce.

Payload cells match:

```text
[1-9][a-z]*
```

The frame contains no ASCII `0` glyph. `|` and `.` are framing delimiters, not DUO numerals.

## 7. Evidence receipt

An optional receipt binds:

- exact frame commitment;
- exact AAD commitment;
- random key ID (not the key itself or a hash of it);
- claimed nonce chronology ordinal;
- plaintext length and padding class;
- algorithm/revision identifiers.

Canonical JSON is SHAKE256-512 content-addressed with independently length-framed domains and authenticated with `HMAC-SHA256(K_receipt, ...)`.

A receipt is **evidence only and never grants authority**.

## 8. Canonical rejection

A decoder rejects:

- bad magic/version;
- ASCII zero in textual XDE2 frame;
- noncanonical nonce count glyphs;
- malformed DUO payload cells;
- cells absent from their derived modulus;
- recovered values outside a single byte;
- invalid payload envelope/length;
- AEAD tag failure;
- optional receipt mismatch.

## 9. Limits

Current implementation limit: 16 MiB plaintext per frame. The whole message is buffered. A chunked file/container profile is future work.


## 10. XDE2-PQ2 recipient envelope

XDE2-PQ2 adds FIPS 203 ML-KEM-1024 key establishment around the XDE2 payload.

1. Recipient publishes an ML-KEM-1024 public key and SHA-256 key ID.
2. Sender encapsulates to that public key using the witnessed OpenSSL 3.5 provider.
3. The 32-byte ML-KEM shared secret is passed through HKDF-SHA256. The HKDF salt is SHA-256 of the ML-KEM ciphertext and the info string binds `XAVI-DUO/XDE2-PQ2/ML-KEM-1024/master/v1` plus the recipient key ID.
4. The resulting 32 bytes become the one-message XDE2 master key.
5. The ML-KEM ciphertext is serialized as one-origin zero-free DUO byte cells (`byte + 1` rendered with the Rev009 human count adapter).
6. XDE2 AAD binds envelope schema, algorithm, recipient key ID, KEM ciphertext digest, and caller AAD.
7. Recipient decapsulates with a node-local private key, derives the same XDE2 key, and authenticates XDE2 before releasing plaintext.

A wrong private key, modified KEM ciphertext, modified recipient key ID, modified XDE2 payload, or wrong AAD fails authentication.

The KEM provider is portable; the private key is not. Decapsulation is pinned to its key-custody node/provider reference.

## DUO Rev009 contextual numeral identity

XDE2 uses DUO-Math Rev009. A DUO glyph is not a globally self-describing number. For modulus `M>1`, every cell is interpreted by the exact decomposition

`S=M-1`, `N=cS+r`, `1<=r<=S`, `symbol=H(r)R(c)`.

The trusted identity is therefore the typed context `(M,N,S,c,r,H(r),R(c),symbol)`, not the glyph string alone. Mod 1 is the explicit absolute-count transport used for witness ordinals.

XDE2 derives a per-cell modulus and offset from the formatting key and nonce. The public frame serializes only the DUO symbol. It does not serialize the derived modulus, offset, cycle, or remainder. Authorized software can recompute the full context and `duo_context_commitment()` binds that hidden interpretation into authenticated evidence without disclosing the schedule on wire.

For a fixed glyph `H(r)R(c)`, the finite-modulus value law is `N(M)=c(M-1)+r`; for fixed `N`, the glyph sequence across moduli is a deterministic staircase. These properties provide keyed polymorphic representation and same-glyph/different-value ambiguity. They are not treated as an independent confidentiality primitive; AEAD/PQ/FHE remain the cryptographic security boundary.

