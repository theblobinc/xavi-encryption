# xavi-void Provider Sidecars

Production cryptography/GPU dependencies are isolated behind line-delimited JSON sidecars so provider runtimes do not leak into the semantic layer or host OS.

## TFHE provider roles

Rev 1.2-dev4 has two distinct TFHE deployment modes.

### Combined local-validation provider

`providers/tfhe-rs-sidecar/` owns a TFHE client key and supports encrypt/evaluate/decrypt in one process. It remains useful for conformance and local debugging but **must not** be deployed as an untrusted remote evaluator.

### Production split provider

`providers/tfhe-rs-split/` builds:

- `xvoid-tfhe-client`: `role=client`, `has_client_secret=true`; owns `ClientKey`, encrypts/decrypts, and exports only `server-key.bin`;
- `xvoid-tfhe-evaluator`: `role=evaluator`, `has_client_secret=false`; loads `CompressedServerKey`, performs TFHE operations, and exposes no encrypt/decrypt RPC.

The evaluator advertises `key_id`, `device`, `supports_bulk_registers`, `supports_keccak24`, `supports_metrics`, and `supports_resident_sessions`. Optional operations include `select_register`, `write_register`, `keccak24`, `metrics`, `reset_metrics`, `resident_stats`, `release_handles`, and `clear_session`.

Python `ProductionTFHEWorker` fails closed unless a provider is cryptographic, has `role=evaluator`, reports `has_client_secret=false`, and supplies a stable evaluation-key ID. The source tests also reject `ClientKey` or decrypt calls in the Rust evaluator binary.

Ciphertexts cross process/network boundaries as opaque serialized provider blobs in `XVOIDENC/v1` and `XVOIDTFH/v1`.

## PQ sidecar

A production PQ sidecar must advertise exactly ML-KEM-1024, ML-DSA-87, KMAC256 and AES-256-GCM-SIV with `production_cryptographic=true`. The sidecar self-test records KEM/signature round-trips, deterministic KMAC/AEAD values, object sizes and SHA3-512 transcript digests.

## GPU execution

`providers/tfhe-worker/Containerfile.cuda` packages Python worker logic with only the evaluation-only CUDA TFHE binary. The worker does not contain `xvoid-tfhe-client` or `client-key.bin`.

The provider reports host-wall timing and resident ciphertext evidence. GPU VRAM and kernel-launch counters are left null unless an external CUDA profiler supplies them; they are never guessed.

## Deployment rule

Client-secret material stays in the client trust domain. Copy only `server-key.bin` to a remote evaluator. Never mount the client key directory into the worker container.
