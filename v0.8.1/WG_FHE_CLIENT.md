# WG-RNN / WG-SFM / WG-SRNN as the FHE client trust domain

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


The WG witness stack is the **client**, not the evaluator. It owns semantic state, witness authority, FHE client/private keys, encryption/decryption and the decision about what may leave the trust domain. Evaluator workers are extensions of the WG client's compute graph and receive only the evaluation material required for a permitted operation.

```text
WG-RNN / WG-SFM / WG-SRNN CLIENT TRUST DOMAIN
  witness state + authority
  FHE client/private keys
  encrypt/decrypt
  recursive planner / semantic equivalence checks
  learned cost model
             |
             | evaluation/server keys + ciphertext + approved program
             v
FHE EVALUATOR DOMAIN
  TFHE / CKKS / OpenFHE / GPU sidecar
  no WG authority
  no FHE client secret
  result ciphertext + metrics + witness evidence
             |
             v
WG CLIENT decrypts, validates, witnesses, learns from cost/result
```

## Current lanes

- **WG-RNN**: split OpenFHE CKKS client/evaluator with packed vector and recurrent profiles. The trusted client owns the decryption secret; remote prod3 evaluation receives only context/public/evaluation material and ciphertext. The production recurrent proof passed 10/10 evaluator operations, decrypted to the expected WG-RNN cell, and the witnessed latency/error/provider result was settled back through WG-RNN/SFM/SRNN.
- **WG-SFM**: TFHE Boolean/word64/oblivious-select/Keccak capabilities. Remote execution uses the split evaluator and rejects any provider with `has_client_secret=true`.
- **WG-SRNN**: hybrid. Discrete arbitration/release/reconsideration/selection uses TFHE; numeric strategy/calibration vectors use CKKS where supported.

## Recursive/self-referential FHE optimization

The WG stack may recursively learn and compare semantically equivalent encrypted execution plans. Safe optimization inputs include provider/image ID, public/evaluation-key ID, device, wall time, circuit depth, bootstrap count, ciphertext/resident bytes, cache hits, queue latency and witness/equivalence outcomes. It may learn which rewrite/provider/partition is faster and use that evidence in later planning.

The model never receives raw client/private/wrapping/TPM-unsealed key bytes. Knowing the client's cryptographic secret is not used as a learned shortcut. When the **plaintext value itself is already known to the trusted client**, ordinary constant folding, cached encrypted constants and deterministic equivalent-plan selection are allowed before encryption.

## Efficiency directions

The main speed opportunities are not key-dependent shortcuts. They are packed-vector CKKS, smaller/depth-bounded circuits, Boolean/word IR rewriting, LUT/polynomial approximation, server/evaluation-key caching, resident ciphertext handles, bootstrap minimization, GPU TFHE, workload partitioning, common-subexpression reuse, batch packing, semantic-equivalence caching and learned provider scheduling. Every learned rewrite remains witness-gated and must preserve the declared semantic result within the FHE scheme's exact/approximate contract.

## v0.5 end-to-end validation

The trusted WG client has now been exercised through real split FHE providers rather than policy-only mocks.

- **WG-RNN / CKKS:** prod4 kept `private.bin`; prod3 received only context/public/evaluation keys and ciphertext. A complete depth-10 encrypted recurrent step decrypted within `0.0259441931` max absolute error of the plaintext `RecurrentCore` cell. Remote wall time was `6231 ms`; the recurrent evaluator operation itself measured about `5037 ms`.
- **WG-SFM / TFHE CUDA:** encrypted witness gate and typed-selection semantics ran on prod3 and decrypted exactly. Measured semantic operation estimate: about `507.063 ms`; learning reward `0.781303`.
- **WG-SRNN / TFHE CUDA:** encrypted release, reconsideration, arbitration and reflection-selection semantics ran on prod3 and decrypted exactly. Measured semantic operation estimate: about `375.498 ms`; learning reward `0.822556`.
- `settle()` feeds success, latency, CKKS approximation error/tolerance and measured per-operation TFHE costs into RecurrentCore teaching, WitnessSFM outcome ingestion and SRNN strategy/reflection state. Hard cryptographic eligibility is applied before learned ranking.
- Combined client/evaluator providers carrying a client secret remain ineligible for remote selection regardless of learned score.


## Production validation boundary

The v0.5.0 production evidence closes the client/evaluator loops explicitly:

- **Remote CKKS WG-RNN:** prod4 prepares ciphertext, prod3 evaluates without the decryption secret, prod4 decrypts and compares, then WG-RNN/SFM/SRNN settle the witnessed result.
- **Remote CUDA TFHE:** prod3 evaluates with server/evaluation material only and advertises `has_client_secret=false`; the mixed encrypted workload passed and its measured operation costs are retained.
- **WG-SFM/WG-SRNN semantic TFHE:** encrypted witness gating, typed equality/selection, release gating, arbitration/reconsideration and reflection selection match precommitted trusted-client semantics.
- **Portable control plane:** zero-import WASM has no raw host imports; Worker RPC exposes only frozen typed FHE capabilities. Raw GPU and authority-bearing calls fail closed.

Evaluator evidence remains non-authoritative. Decryption, semantic comparison and authority stay inside the WG client trust domain.
