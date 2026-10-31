# Rev 1.2-dev4 production TFHE worker

Rev 1.2-dev4 makes the remote trust boundary enforceable in process/container layout rather than merely documenting it.

```text
CLIENT TRUST DOMAIN                          REMOTE EVALUATOR TRUST DOMAIN

xvoid-tfhe-client                           xavi-void worker
  ClientKey                                   XVOIDREM replay/session state
  encrypt/decrypt                             XVOIDTFH request decoder
  client-key.bin (0600)                           |
       |                                           v
       +-- server-key.bin only ----------> xvoid-tfhe-evaluator
                                             CompressedServerKey only
                                             CPU/CUDA TFHE operations
                                             no ClientKey type
                                             no decrypt RPC
```

The client can use `TFHEPortableClientBackend` to compile and encrypt the entire program before any evaluator exists. Ciphertexts are serialized into `XVOIDTFH/v1`; the worker imports them under the matching evaluation key, executes either generic encrypted ExecutionIR or the fixed Keccak execution class, and returns only encrypted result lanes and measurements.

`ProductionTFHEWorker` fails closed unless the backend reports all of:

- `cryptographic=true`;
- `role=evaluator`;
- `has_client_secret=false`;
- a nonempty evaluation-key ID.

The Rust evaluator source is also regression-tested to contain neither `ClientKey` nor a decrypt call.

## Containers

`providers/tfhe-worker/Containerfile` contains Python xavi-void plus only the evaluator Rust binary. The client binary is built separately and its key directory must never be mounted into the remote worker. Copy only `server-key.bin` to the evaluator node.

Use `deploy/podman/build-dev4.sh` to build the CPU worker, client/split provider, and PQ provider without host language runtimes. Set `BUILD_CUDA=1` to also build the CUDA worker image.

## Acceptance

`benchmarks/dev4_acceptance.py` requires client, evaluator, and production PQ sidecars. A full passing report requires:

- matching client/evaluator key IDs;
- evaluator source and capability evidence showing no client-secret custody;
- production PQ provider capability;
- signed PQ-wrapped request/result transport;
- exact SHAKE256-512 equality for every selected vector through both generic encrypted ExecutionIR and specialized Keccak execution;
- provider timing, operation counters, resident-object counts, and serialized resident bytes.

GPU VRAM and kernel-launch counters are reported as unavailable unless an external device profiler supplies them. Host-wall dispatch timing is never relabeled as CUDA kernel time.
