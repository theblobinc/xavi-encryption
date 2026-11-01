# Remote Encrypted Execution

## Control protocol

`XVOIDREM/v1` is the canonical control protocol for create/upload/chunk/checkpoint/finish/result/cancel/recover/ack/error messages. Every message carries a one-origin sequence and prior-message commitment. `ReplayProtector` rejects duplicate, skipped, reordered, or spliced messages.

Rev 1.2-dev3 snapshot/restore preserves replay state, checkpoints, cancellation, chunk count and remaining TTL across worker-process restarts. Rev 1.2-dev4 adds `authorize_execution()` so an encrypted workload cannot run unless its session is live and in an execution-capable phase.

## Production TFHE data path

`XVOIDTFH/v1` carries opaque provider ciphertext blobs from the client to an evaluator-only worker. The client owns `ClientKey`; the evaluator receives only `CompressedServerKey` and reports `has_client_secret=false`. `ProductionTFHEWorker` rejects any combined or client-secret provider.

The request binds the evaluation-key ID, encrypted SHAKE input, encrypted word program and public execution-class choice. The response returns only encrypted output lanes, semantic/program/result commitments and timing/residency evidence. The client imports and decrypts the result in its own trust domain.

## PQ transport

The TFHE envelope is independent of transport. `pq_transport.py` can authenticate and seal it with the exact production suite ML-KEM-1024 + ML-DSA-87 + KMAC256 + AES-256-GCM-SIV. `benchmarks/dev4_acceptance.py` exercises this composition and requires signed request/result envelopes for a full pass.

## Receipts and limits

`RemoteExecutionReceipt` remains explicitly `receipt-only-not-malicious-evaluator-proof`. Rev 1.2-dev4 proves stronger key separation and transcript binding, but not universal honest execution by a malicious evaluator. That is the Rev 1.3 verification problem.
