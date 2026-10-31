# Xavi-Void Design Import

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


Read-only source reviewed:

`/datastore3/wg-rnn/xavi-void`

Only concepts/code relevant to encrypted transport were merged. The source tree was not modified.

## Imported/adapted

- SHAKE256-512 content IDs with versioned domain separation and independent length framing;
- canonical JSON restrictions (NFC text, no binary floats, sorted compact form);
- evidence receipts as non-authorizing evidence;
- semantic/representation/transport identity separation;
- strict provider capability gates;
- explicit padding/privacy classes;
- canonical decoder rejection philosophy.

Exact reference copies used during integration are under `references/xavi-void/`.

## Optional encrypted-compute plane now imported

The following were originally excluded from the small XDE2 transport core, but are now brought forward as a **separate optional compute-provider plane** rather than folded into the transport TCB:

- FHE program execution contracts;
- encrypted Boolean ExecutionIR and 64-bit word IR;
- evaluator scheduling;
- TFHE-rs CPU/CUDA sidecars;
- split client/evaluator key-custody model;
- remote execution protocol/evidence;
- OpenFHE provider adapter;
- GPU word/FHE worker machinery.

Exact read-only source copies are under `references/xavi-void/fhe/`. XDE2/PQ2 remains usable without loading any FHE/GPU provider. See `FHE_EXECUTION.md` and `COMPUTE_PROVIDERS.json`.
