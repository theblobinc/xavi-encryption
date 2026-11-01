# Execution Shape and Privacy Hardening

`ExecutionClass` defines public shape buckets for encrypted jobs:

- padded instruction count;
- constant batch size;
- padded register-bank size;
- checkpoint cadence;
- optional padded absorb-block count;
- ciphertext reuse policy.

Boolean padding uses encrypted NOP instructions that write a register back to itself. Keccak uses a 2080-instruction execution class for the 2064-instruction canonical body so 32-instruction batches remain constant-sized.

Oblivious register selection/writes hide source and destination identifiers from evaluator control flow. The provider may internally batch these operations.

Current hardening provides architecture and deterministic conformance for:

- instruction-count padding;
- register-bank padding;
- constant batch sizing;
- checkpoint/recovery;
- session caching;
- least-loaded multi-worker assignment.

Timing/traffic side-channel resistance depends on the production provider, process isolation, scheduler, and network deployment and is not claimed by the Python reference environment.
