# Xavi portable cryptographic execution contract

This layer adapts patterns read from `xavi-memory-js` without depending on that live tree at runtime.

Borrowed design properties:

- explicit capability allowlists;
- first-party image identity/digest binding;
- sandbox policy as evidence;
- Worker/WASM/container runners as interchangeable execution backends;
- no authority escalation from a capability descriptor;
- witnessed start/result/failure semantics;
- portable result envelopes suitable for another Xavi node.

Machine learning may rank or select eligible providers, but it cannot alter ML-KEM inputs/outputs, key material, algorithm parameters, or authentication decisions.
