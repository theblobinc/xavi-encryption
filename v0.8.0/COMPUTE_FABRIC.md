# XAVI-DUO unified encrypted compute fabric

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


**Version:** 0.5.0  
**Status:** experimental internal validation; not independently audited

## Layering

```text
XDE2 / XDE2-PQ2 transport + authentication + custody
                    |
WG-RNN / WG-SFM / WG-SRNN trusted client domain
  keys, plaintext-aware optimization, compile, encrypt/decrypt, witness learning
                    |
       typed capability / encrypted task
                    |
     JS Worker RPC / compute broker
                    |
   +----------------+----------------+
   |                |                |
TFHE CPU        TFHE CUDA        OpenFHE CKKS
Boolean/word    prod3 GPU        packed vectors/recurrent
   |                |                |
secret-blind evaluator/server-key domain
```

Native WASM is a pure control/computation lane with zero host imports. It does not receive raw GPU/device authority. FHE/GPU work is reached through a typed Worker RPC capability bridge.

## Validated provider families

- TFHE-rs split client/evaluator for encrypted Boolean, 64-bit word, mux/equality, secret/public rotation, Keccak and oblivious selection.
- CUDA TFHE evaluator on prod3 RTX 2070 with server key only.
- OpenFHE CKKS split client/evaluator for packed dot/cosine/linear vector work, cubic sigmoid/tanh and depth-10 WG-RNN recurrent update.
- JS/WASM Worker bridge capabilities: `fhe.boolean`, `fhe.word64`, `fhe.vector.approx`.

## Trusted-client rule

WG-RNN/WG-SFM/WG-SRNN is the FHE client. It may use plaintext locally, deterministic key metadata and decrypted prior outcomes to optimize future circuits. Raw private-key bytes are not neural features. Remote evaluators are secret-blind and cannot grant authority.

## Learned optimization

Only hard-eligible providers enter learned ranking. The client learns from observed success, latency, approximation error/tolerance, cache/session state and per-operation cost. Repeated failures can shift provider choice. Operation mix is priced using candidate metrics, learned history or conservative bounds.

## Exact 64-bit semantics

`XAVI-DUO/WORD64-WIRE/v1` encodes unsigned 64-bit values as decimal strings at JS/JSON boundaries. This prevents IEEE-754 rounding of witness IDs, semantic selections and encrypted word results.

## GPU sandbox note

NVIDIA CDI on prod3 requires writable container-root paths while it creates driver-library symlinks. The validated CUDA evaluator therefore uses an ephemeral `--rm` root rather than `--read-only`; network remains disabled, all capabilities are dropped, `no-new-privileges` is enabled, and server/evaluation keys are mounted read-only.

## Evidence

Canonical validation records are under `validation/`, including remote WG-RNN CKKS, remote CUDA TFHE, WG-SFM/SRNN semantic execution, recursive learning feedback, CPU/GPU benchmark evidence and the WASM/Worker FHE bridge.
