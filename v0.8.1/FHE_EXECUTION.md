# XAVI-DUO encrypted compute plane

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


XDE2/XDE2-PQ2 remains the transport/authentication layer. FHE/GPU/WASM execution is an optional provider plane selected only after cryptographic, custody, image, capability, session and authority gates pass.

## Portable execution model

A portable program binds a semantic/program digest and typed capability rather than a machine-specific implementation. The broker may select among:

- zero-import native WASM for pure portable computation;
- brokered WASM/Worker RPC for typed sidecar capabilities;
- TFHE-rs Boolean/word64/Keccak evaluators on CPU;
- split TFHE evaluator workers for remote/untrusted execution;
- TFHE CUDA evaluators where rebuilt and device-gated;
- OpenFHE CPU providers;
- CUDA word sidecars;
- future PKCS#11/HSM/device-specific providers.

The current zero-import native WASM executor intentionally cannot open sockets, files, GPU devices, clocks or arbitrary host callbacks. FHE/GPU access is therefore provided by a second **brokered WASM** mode whose only imports are frozen typed capabilities. The broker, not the WASM module, owns native sidecar/container/remote execution.

## Security boundary

Remote production FHE uses the split client/evaluator pattern imported from Xavi-Void. The client trust domain owns `ClientKey` and encrypt/decrypt operations. The evaluator receives only the server/evaluation key and encrypted program/input material. A provider advertising `contains_client_secret=true` is not eligible for remote execution.

Machine learning may rank already-eligible providers by load, latency, GPU availability, historical success or anomaly evidence. It cannot widen capabilities, move private keys, choose an unapproved image, bypass replay/authentication, or turn evidence into authority.

## Current provider state

See `COMPUTE_PROVIDERS.json` for the machine-readable registry. Current validated lanes are:

- split TFHE CPU evaluator, secret-blind and remote-safe;
- prod3 CUDA TFHE evaluator (`localhost/xavi-duo-tfhe-cuda-evaluator:0.5.0`, image ID `2ea9e686f6c3a8df005791247ab64115087a606efbaf046af6f9e0f05fe6152e`), secret-blind and remote-tested;
- split OpenFHE CKKS depth-2 vector, depth-4 activation and depth-10 WG-RNN recurrent profiles;
- zero-import native WASM plus Worker RPC typed-capability bridge to the trusted-client TFHE/CKKS runtimes.

The v0.5 NVIDIA CDI writable-root exception is superseded in v0.6. The prod3 CUDA lane now runs with `--read-only` root. Stock NVIDIA CDI is confined to disposable tmpfs copy-up overlays at `/usr/lib/x86_64-linux-gnu` and `/etc`, where its pre-start hooks materialize driver symlinks, ld-cache and profile state. The evaluator runs as numeric UID/GID `10001:999`; ordinary rootfs writes are blocked, the evaluator process cannot persist driver-overlay changes, `network=none`, `cap-drop=all`, `no-new-privileges`, and the evaluation/server-key mount is read-only. See `ACCELERATORS.md` and `validation/xavi-cluster/ACCELERATOR_NVIDIA_READONLY_PROD3_v0.6.json`.

## Wire precision

Encrypted `word64` semantics are exact uint64 values. At JS/JSON boundaries they are encoded as canonical unsigned decimal strings (`XAVI-DUO/WORD64-WIRE/v1`). JavaScript `Number` is accepted only inside the safe-integer range; larger numeric inputs fail closed and must be supplied as a string or `BigInt`.

## Xavi-Void source import

The imported compute/runtime/provider sources are under `compute/xavi-void/` with reference provenance under `references/xavi-void/`. XDE2/XDE2-PQ2 remains the outer authenticated transport/custody layer; the Void-derived code supplies the optional encrypted-compute plane.


## Accelerator ABI boundary

Compute providers and physical accelerators are now separate registries. A provider may advertise an `accelerator_abi` such as `cuda`, `rocm`, `level-zero`, `opencl`, `vulkan-compute`, `webgpu`, or a future/custom ABI. `ACCELERATOR_PROVIDERS.json` describes how a compatible device/runtime is injected and sandboxed. The broker rejects a provider/accelerator pair unless their ABIs match before WG learning is allowed to rank it.

The current TFHE GPU binary is CUDA-specific. AMD/Intel/generic accelerator profiles make the execution fabric extensible, but they require a compatible backend build before encrypted computation can run there. Zero-import WASM never receives raw device authority; the Worker/broker owns all accelerator access.
