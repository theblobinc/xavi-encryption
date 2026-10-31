# Canonical Wire Formats

xavi-void currently defines four versioned binary formats:

- `XVOIDIR/v1` — plaintext Boolean `ExecutionIR`;
- `XVOIDENC/v1` — encrypted Boolean/word programs using opaque provider ciphertext blobs;
- `XVOIDREM/v1` — remote evaluator control messages;
- `XVOIDTFH/v1` — provider-portable TFHE SHAKE request/result envelopes for the split client/evaluator path.

All formats use canonical minimal unsigned varints, explicit object/type tags, length framing, and reject trailing/noncanonical data.

Semantic identifiers/counts are positive and one-origin. Byte lengths and physical ciphertext sizes may be zero where the protocol permits an empty byte string because those are framing coordinates rather than semantic labels.

`XVOIDENC/v1` deliberately exposes only the selected padded execution-class shape. Program meaning, program/semantic IDs, opcodes, register identifiers, rotations, and immediates remain ciphertext fields.

`XVOIDTFH/v1` binds the evaluation-key ID and carries only opaque ciphertext blobs plus public execution-mode metadata. The evaluator imports the blobs under its server key and returns encrypted output lanes, commitments, and timing/residency evidence.
