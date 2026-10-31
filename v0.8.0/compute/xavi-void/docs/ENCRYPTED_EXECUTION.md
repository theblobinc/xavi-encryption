# Encrypted Execution — Rev 1.2-dev2

## Trust split

The encrypted runtime has an explicit capability split:

- `FHEClientView` — trusted side: encrypt, decrypt, ciphertext import/export;
- `FHEEvaluatorView` — untrusted evaluator side: trivial constants, Boolean/word gates, comparisons, mux/select, oblivious register read/write, ciphertext import/export and commitments;
- `FHEBackend` — provider implementation object used to construct those restricted views.

Evaluator code receives the evaluator-only view and has no public decrypt method.

## Encrypted program fields

Boolean `ExecutionIR` compiles to `EncryptedProgram`. The following are ciphertexts:

- semantic ID;
- representation ID;
- opcode;
- destination register;
- source registers;
- input-slot identifier;
- output register identifiers.

The word/Keccak program additionally encrypts:

- five source identifiers;
- rotate amount;
- 64-bit immediate.

The evaluator selects registers and operations through equality + mux operations. It does not inspect or branch on decrypted opcodes or register IDs.

## Provider model

`ReferenceFHEBackend` is intentionally non-secure and exists only for deterministic conformance. Production provider adapters are:

- `TFHESidecarBackend`;
- `OpenFHESidecarBackend`.

Rev 1.2-dev2 also bundles `providers/tfhe-rs-sidecar/`, which stores TFHE ciphertexts behind process-resident opaque handles. It exposes bulk encrypted register access, cached equality selector masks, a fixed Keccak-24 execution class, CPU/CUDA server-key modes, and operation timing counters.

A sidecar is rejected unless it advertises cryptographic FHE and all required Boolean/word/oblivious-selection capabilities.

## Portable ciphertexts

`XVOIDENC/v1` serializes encrypted programs using provider-supplied opaque ciphertext blobs. The outer format exposes the selected execution-class shape but not plaintext instruction semantics.

## Encrypted SHAKE

`shake_encrypted.py` encrypts padded SHAKE rate lanes on the trusted side, runs the same reusable 24-round Keccak program through encrypted word operations, and decrypts only the final eight output lanes on the trusted side.

Current deterministic conformance verifies empty, short, 135/136/137-byte boundary, multi-block, and 512-byte inputs.

## Execution classes and performance

The generic encrypted interpreter remains the conformance definition. After it agrees with the semantic/plaintext layers, a provider may execute the public `keccak-24r` class using a constrained encrypted kernel. This optimization does not decrypt or plaintext-branch on encrypted opcode/register fields; it replaces repeated generic dispatch with a public, fixed operation family.

`EncryptedShakeTiming` records per-block and full-evaluation nanoseconds while sidecars return per-operation counters. `benchmarks/benchmark_encrypted_shake.py` emits JSON suitable for CPU/GPU comparisons.

## Key separation

The local TFHE sidecar currently combines client and evaluator key custody to make the local Rev 1.2-dev2 milestone executable. Production remote deployment must split those roles so evaluator workers receive only server/evaluation material and cannot decrypt application ciphertexts.
