# Machine-learning and portable execution boundary

`ML-KEM` means **Module-Lattice-Based Key Encapsulation Mechanism**, not machine learning.

The WG-RNN/WG-SFM/WG-SRNN and `xavi-memory-js` work is useful here as an execution and policy substrate:

- select among already-approved provider nodes using witnessed load/latency/health evidence;
- anomaly detection on provider timing/failure telemetry;
- choose public encapsulation execution placement;
- schedule WASM/Worker/container workloads associated with an encrypted job;
- learn routing policy from validated outcomes;
- carry DUO semantic state and portable witness envelopes across nodes.

It must **not**:

- synthesize or approximate ML-KEM arithmetic;
- alter FIPS 203 parameter sets;
- predict/generate private keys, randomness, ciphertexts or shared secrets;
- override authentication failures;
- route decapsulation away from the node/provider that owns the private-key reference;
- turn a learned score into authority.

The routing order is therefore:

1. hard cryptographic + image-ID + key-custody + capability gates;
2. only then optional ML scoring among the surviving providers;
3. execution in the sandboxed provider;
4. witnessed result/failure envelope;
5. XDE2 authentication remains authoritative.

This mirrors the capability/portable/sandbox principles read from `xavi-memory-js` while keeping the cryptographic primitive independent of the model stack.
