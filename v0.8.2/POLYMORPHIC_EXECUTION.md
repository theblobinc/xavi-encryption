# XDE2-PQ2 encrypted polymorphic execution

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


## Purpose

Use the JS/WASM/container/witness ideas from `xavi-memory-js` to move machine-learning and other approved compute across Xavi nodes while keeping transport confidentiality and authentication below the learned routing layer.

## Execution flow

1. Each execution node owns an ML-KEM-1024 key pair. The private key remains node-local; the public key and key ID may be distributed.
2. The requester creates a typed portable task containing capability, runtime kind, approved image/model digest, entrypoint, resource class, input digest and requester return-key ID.
3. Task inputs and task metadata are encrypted to the worker public key with XDE2-PQ2.
4. Hard policy filters eligible workers by algorithm, provider image ID/digest evidence, requested capability, allowed node set and key custody.
5. WG-RNN/WG-SFM/WG-SRNN or another model may rank only those already-eligible workers using load, latency, health, historical success and anomaly evidence.
6. The chosen node decapsulates ML-KEM using a node-local key reference. Private key bytes are not sent in a portable task.
7. XDE2 authentication is verified before task material is released.
8. The node executes only an approved Worker/WASM/container2wasm/small-model capability under bounded sandbox policy.
9. Start/result/failure evidence binds provider image, runtime/model image digest, policy, input/output commitments and node identity. Evidence never grants authority by itself.
10. The result is encrypted to the requester's return public key using XDE2-PQ2.

## ML boundary

Machine learning is allowed to optimize **where and when** an already-valid operation runs. It may not change:

- ML-KEM parameter set or arithmetic;
- provider/image digest requirements;
- key custody;
- private key or shared-secret material;
- XDE2 authentication outcomes;
- capability allowlists or authority decisions.

This gives polymorphic execution a learned scheduling layer without making the neural network part of the cryptographic trusted computing base.

## Current cluster validation

The same ML-KEM provider image has passed exact shared-secret round trips on prod4, prod3 and vm1. vm1 uses Podman's `cgroupfs` manager because its rootless user session does not expose the default systemd cgroup scope.

## WASM / Worker / FHE execution boundary

Native first-party WASM remains zero-import: no network, filesystem, clock, randomness, raw GPU device or arbitrary host callback is exposed. Rich encrypted-compute capabilities cross a registered Worker RPC boundary instead:

```text
zero-import WASM / portable JS
        |
        | typed request only
        v
Worker RPC capability host
        |
        +-- fhe.boolean      -> trusted WG TFHE client -> evaluator sidecar
        +-- fhe.word64       -> trusted WG TFHE client -> evaluator sidecar
        +-- fhe.vector.approx-> trusted WG CKKS client -> evaluator sidecar
```

The Worker is inside the trusted client domain and may hold client-side key references. Evaluator directories and remote workers receive only server/evaluation material. `gpu.raw` and authority-bearing Worker requests are rejected before provider execution.

A real v0.5 integration test executes pure WASM control logic, then real split TFHE Boolean/uint64 operations and split CKKS vector cosine through this Worker bridge. Full uint64 values use canonical decimal-string wire encoding to avoid JavaScript precision loss.


## Accelerator portability

The portable execution contract does not encode a GPU vendor. Tasks bind a semantic/program digest, typed capability and, where needed, an accelerator ABI. The Worker/compute broker selects an approved compute provider and a compatible profile from `ACCELERATOR_PROVIDERS.json`.

Examples of accelerator ABIs include CUDA, ROCm/HIP, Level Zero/SYCL, OpenCL, Vulkan compute, WebGPU, generic CDI and authenticated remote accelerator RPC. A physical device is eligible only when both the compute backend and accelerator profile advertise a compatible ABI and satisfy the sandbox/custody policy. Learned WG routing can rank those eligible plans but cannot make an incompatible backend/device pair executable.

Native zero-import WASM still receives no raw GPU/NPU device imports. It crosses Worker RPC using a typed capability; device files, CDI injection, driver overlays and native sidecars stay in the Worker/evaluator domain. See `ACCELERATORS.md`.
