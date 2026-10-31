# TFHE-rs provider — Rev 1.2-dev4

This sidecar is the production cryptographic implementation of the xavi-void FHE provider contract. It uses **TFHE-rs 1.8**, stores ciphertexts and keys in the worker process behind opaque handles, implements encrypted Boolean and 64-bit word operations, encrypted register selection/write, encrypted secret rotation, and a fixed Keccak-f[1600]/24-round execution-class kernel.

The default image is CPU-only. `Containerfile.cuda` builds TFHE-rs with its GPU feature and installs the CUDA server key on startup. The host does not need Rust, Cargo, Python, or Node for this provider; only Podman/Docker and, for the CUDA image, a working NVIDIA container runtime.

```sh
podman build -t xavi-void-tfhe:1.2-dev2 -f providers/tfhe-rs-sidecar/Containerfile providers/tfhe-rs-sidecar
podman run --rm -i xavi-void-tfhe:1.2-dev2 --device cpu
```

For CUDA:

```sh
podman build -t xavi-void-tfhe:1.2-dev2-cuda -f providers/tfhe-rs-sidecar/Containerfile.cuda providers/tfhe-rs-sidecar
podman run --rm -i --device nvidia.com/gpu=all xavi-void-tfhe:1.2-dev2-cuda --device cuda
```

## Security boundary

The current local sidecar is a **combined client/evaluator process** so the Rev 1.2-dev4 local milestone can encrypt, evaluate, and decrypt in one process. Remote production deployment must split client-key custody from evaluator/server-key custody before treating the evaluator as untrusted. The Python evaluator view never exposes decrypt operations, but process separation is the stronger boundary and remains a remote-execution deployment requirement.

Imported ciphertext blobs are size-bounded and kind checked. The sidecar returns stable ciphertext commitments and operation timing counters. No operation decrypts an opcode, register index, message word, or secret rotation amount in order to choose an execution branch.

Rev 1.2-dev4 additionally exposes `resident_stats` / `release_handles` and records host-wall timing for each Keccak round and Theta/Rho+Pi/Chi/Iota phase. CUDA timing is explicitly host-dispatch timing unless a future provider advertises device-event timing.
