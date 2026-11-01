# XAVI-DUO Encryption — XDE2

## v0.8.2 TPM2 release-custody hardening

v0.8.2 ships the previously missing standalone TPM2-sealed-KEK backend (`xavi_duo_tpm2_custody.py`). It binds a 256-bit wrapping key to a PCR policy, wraps PQ private PEM objects with authenticated encryption, and exposes high-assurance private operations without returning private bytes to the caller. It does **not** claim native TPM ML-DSA/ML-KEM: the TPM protects the KEK while the private PEM exists briefly inside the isolated signer process for the pinned OpenSSL provider operation.

High-assurance `tpm2://` and `pkcs11://` operators must now attest `hardware_bound=true`. See `CUSTODY.md` and `CUSTODY_BACKENDS.md`.


**Status:** experimental high-assurance cryptographic/secure-compute implementation; not independently audited or accredited
**DUO semantics:** DUO Numbers Rev009
**License:** MIT OR Apache-2.0


> **Standalone product boundary (v0.8.1):** this suite does not depend on the Xavi cluster, MCP, prod3/prod4, NFS, a private registry, or fixed host paths. The Xavi systems are reference integration/test hardware only. See `STANDALONE_DEPLOYMENT.md`. Cluster-specific proof artifacts are isolated under `validation/xavi-cluster/` and are never runtime configuration.
XDE2 is the symmetric DUO-Math encryption profile. XDE2-PQ2 adds an ML-KEM-1024 recipient envelope through an allowlisted provider backend. The provider may be an immutable OCI image (Podman or Docker) or a hash-pinned native executable; no cluster service is required. It deliberately separates two layers:

1. **cryptographic security** — standard ChaCha20-Poly1305 AEAD with HKDF-SHA256 key separation;
2. **DUO-native wire semantics** — every encrypted byte is projected through a keyed Rev009 modulus/offset coordinate into a zero-free DUO cell.

The same visible DUO token can have different values under different hidden typed moduli, but XDE2 does **not** count that representational ambiguity as independent cryptographic strength. The standard AEAD is the security foundation.

## Quick start

```bash
# From a source checkout:
python3 -m pip install .
# Or install the release wheel in your normal package workflow.

xavi-duo keygen --out alice.xdek
printf 'hello DUO\n' > plain.txt

xavi-duo encrypt \
  --key alice.xdek \
  --in plain.txt \
  --out secret.xde \
  --receipt secret.receipt.json \
  --aad 'example:v1' \
  --pad-to 1024

xavi-duo inspect --in secret.xde
xavi-duo verify-receipt \
  --key alice.xdek --frame secret.xde \
  --receipt secret.receipt.json --aad 'example:v1'

xavi-duo decrypt \
  --key alice.xdek \
  --in secret.xde \
  --out recovered.txt \
  --receipt secret.receipt.json \
  --aad 'example:v1'

cmp plain.txt recovered.txt
```

## Key and nonce state

`keygen` creates two mode-0600 files:

- `alice.xdek` — immutable 256-bit master key, random key ID and random 64-bit nonce prefix;
- `alice.xdek.nonce` — append-only, locked and fsynced nonce chronology.

Each encryption claims one 32-bit counter and constructs the RFC 8439 96-bit nonce as:

```text
random 64-bit key prefix || monotonic 32-bit counter
```

The next counter is durably appended **before** the nonce is returned. A torn/malformed journal fails closed. Standard mode detects local journal/head inconsistencies, but a full-machine snapshot can roll both files back together. In the v0.8.1 high-assurance profile, stateful-key encryption therefore requires an **independent rollback-domain nonce anchor** (for example TPM/HSM/secure-element backed service or HTTPS+mTLS monotonic witness). Reused/lower counters quarantine the key and fail closed. Do not clone a stateful key for concurrent encryption.

## v0.8.1 hardening

v0.8.1 is a compatibility-preserving security hardening revision over the frozen v0.8.0 snapshot. It adds actual-key ML-KEM parameter binding, crash-safe two-phase external replay anchoring, symlink-safe sensitive key/nonce state access, CLI receipt regression coverage, stricter frame inspection, pinned Python build-tool versions, and specification/metadata corrections. High-assurance remote replay anchors must implement the v2 claim-bound `prepare`/`commit` contract; the explicit local-replay development exception remains lower assurance.

## Privacy padding

`--pad-to N` pads the authenticated internal payload to a multiple of `N` bytes using CSPRNG bytes. It reduces exact plaintext-length leakage but cannot hide traffic timing, message count, endpoint metadata, or the selected padding bucket.

## Xavi-Void concepts reused

The project imports the parts that fit this problem:

- canonical SHAKE256-512, length-framed content commitments;
- evidence receipts that **do not grant authority**;
- strict transport/semantic identity separation;
- fail-closed provider boundaries;
- privacy padding as an explicit execution/transport class;
- canonical parsing and rejection of malformed/trailing/noncanonical data.

The Xavi-Void FHE/evaluator compute plane is now vendored as an **optional execution layer**. XDE2/XDE2-PQ2 remains the transport/custody envelope; TFHE/OpenFHE/CUDA/WASM execution is selected only after hard key-custody, capability, provider-image, session and authority gates pass.

## Post-quantum boundary

`xavi-duo provider-status` now reports the rootless OpenSSL 3.5 ML-KEM provider as available. XDE2-PQ2 uses ML-KEM-1024 for recipient key establishment and retains the original pre-shared-key XDE2 profile for symmetric deployments. No non-PQ fallback is permitted.

See `SECURITY.md`, `THREAT_MODEL.md`, `PQC_ROADMAP.md`, and `XAVI_VOID_IMPORT.md`.


## XDE2-PQ2

A standards-conforming ML-KEM-1024 provider is now available in `providers/mlkem-openssl/`. The final scratch image contains only musl + OpenSSL runtime material and executes with no network, read-only rootfs, dropped capabilities and bounded resources.

```bash
xavi-duo provider-self-test
xavi-duo pq-keygen --private worker.pem --public worker.pub.pem
xavi-duo pq-encrypt --public worker.pub.pem --in task.bin --out task.pq2 --aad 'worker:prod3' --pad-to 1024
xavi-duo pq-decrypt --private worker.pem --in task.pq2 --out task.bin.out --aad 'worker:prod3'
```

The ML-KEM ciphertext itself is represented as 1,568 zero-free DUO byte cells. The resulting 32-byte shared secret is context-derived into the XDE2 master key; it is never exposed to the ML routing layer.

See `ML_EXECUTION_BOUNDARY.md` and `POLYMORPHIC_EXECUTION.md`.

## v0.3.0 custody and polymorphic execution

The protocol now uses typed custody references (`tpm2://`, `authority://`, `file://`, `remote://`, `pkcs11://`) so the same encrypted workload can run on hardware-custody and non-TPM nodes without changing the wire protocol. Reference-lab validation includes TPM-backed custody, software custody, replay rejection, ML-DSA identity, witness chaining, and multi-node polymorphic execution. Those results are historical integration evidence, not deployment requirements. See `CUSTODY_BACKENDS.md`, `validation/xavi-cluster/CUSTODY_STATUS.json`, `REMOTE_EXECUTION.md`, and `validation/xavi-cluster/REMOTE_EXECUTION_VALIDATION.json`.


## v0.3.0 — custody + polymorphic execution

Historical v0.3.0 reference-lab work added typed custody backends (`file://`, `authority://`, `remote://`, `tpm2://`, `pkcs11://`), ML-DSA-65 node identity, durable anti-replay chronology, a WG-style witness bridge, and the first three-node polymorphic DUO execution validation. See `CUSTODY.md`, `REMOTE_EXECUTION.md`, `validation/xavi-cluster/CUSTODY_STATUS.json`, and `validation/xavi-cluster/REMOTE_EXECUTION_VALIDATION.json`.

prod3 is the first hardware-custody node: its TPM2 seals a 256-bit KEK under PCR 7, and that KEK wraps the ML-KEM-1024 and ML-DSA-65 private objects. Systems without a TPM remain supported through encrypted software/Xavi-authority custody or remote custody; those modes deliberately make weaker anti-extraction claims.

## v0.4.0 encrypted compute plane

XAVI-DUO now includes an optional encrypted-compute plane built around typed provider capabilities. It imports Xavi-Void Boolean/word IR, TFHE/OpenFHE/remote/GPU provider contracts and adds a JS brokered-WASM host. XDE2/PQ2 remains the transport/custody core; remote FHE must use split client/evaluator providers without client secrets. CPU TFHE, split CKKS, and the prod3 CUDA TFHE evaluator are validated paths. See `FHE_EXECUTION.md`, `COMPUTE_PROVIDERS.json`, and `ACCELERATORS.md`.

## v0.5.0 WG stack as FHE client

The WG-RNN/WG-SFM/WG-SRNN witness stack is now modeled as the FHE client trust domain. It owns client/private keys, encryption/decryption, semantic authority and recursive plan selection; remote sidecars are evaluation extensions only. A real TFHE split-client smoke test passes with ephemeral secret custody and server-key export. A new OpenFHE CKKS client lane passes encrypted 256-slot vector add/multiply/dot for WG-RNN. WG-SFM discrete gates map to TFHE; WG-SRNN uses a TFHE/CKKS hybrid. Learned optimization may consume provider/evaluation-key IDs and execution metrics but never raw secret-key material. See `WG_FHE_CLIENT.md` and `WG_FHE_CAPABILITIES.json`.

## v0.5 validated encrypted compute fabric

The WG-RNN/WG-SFM/WG-SRNN stack is the **trusted FHE client domain**. Client/private keys, plaintext-aware optimization, encrypt/decrypt and witness authority remain there. Remote evaluators receive only ciphertext plus public/server/evaluation material.

Validated paths include:

- split TFHE Boolean/word64 execution with client secret absent from the evaluator;
- split CKKS packed-vector execution, cubic activation, and a depth-10 encrypted WG-RNN recurrent cell;
- prod4 trusted WG-RNN client -> prod3 OpenFHE CKKS evaluator -> prod4 decrypt, max absolute recurrent error `0.0259441931` at tolerance `0.03`;
- prod3 RTX 2070 CUDA TFHE execution for WG-SFM witness/typed selection and WG-SRNN release/reconsideration/arbitration/reflection semantics, all decrypted results exact;
- recursive WG learning from measured provider latency, approximation quality and per-operation FHE costs;
- zero-import native WASM -> Worker RPC -> typed `fhe.boolean`, `fhe.word64` and `fhe.vector.approx` capabilities. WASM never receives raw GPU, filesystem, network or private-key authority;
- canonical FHE word64 JSON/wire values are unsigned decimal strings. Unsafe JavaScript `Number` inputs are rejected rather than rounded.

## v0.6.0 vendor-neutral accelerator fabric

The earlier NVIDIA writable-root exception is superseded. On prod3 the real CUDA TFHE evaluator now passes with a **read-only root filesystem**. Stock NVIDIA CDI writes only into disposable tmpfs copy-up overlays at `/usr/lib/x86_64-linux-gnu` and `/etc`; the non-root evaluator cannot persist changes there, and the server key remains read-only.

Accelerator selection is now separated from compute-provider selection. Tasks request a compute capability plus an accelerator ABI; the broker hard-gates backend/ABI compatibility before learned routing. `ACCELERATOR_PROVIDERS.json` defines host-neutral accelerator interfaces for NVIDIA CDI/CUDA, AMD ROCm/HIP, Intel Level Zero/SYCL, generic CDI, render-node/OpenCL/Vulkan/WebGPU, and remote accelerator adapters. Reference-lab validation of particular hardware is stored separately. These interfaces do not claim every backend already runs on every vendor: a backend image must advertise a matching ABI. See `ACCELERATORS.md` and `validation/xavi-cluster/ACCELERATOR_NVIDIA_READONLY_PROD3_v0.6.json`.

See `COMPUTE_FABRIC.md`, `FHE_EXECUTION.md`, `WG_FHE_CLIENT.md`, `WG_FHE_CAPABILITIES.json`, and the validation JSON files under `validation/`.
