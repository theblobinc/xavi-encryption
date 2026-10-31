# xavi-memory-js design import

Source tree was treated read-only. Selected files are copied under `references/xavi-memory-js/` for provenance/review.

Adapted concepts:

- `native-wasm.js`: zero-host-import WASM execution boundary;
- `container2wasm.js`: runner/provider adapter rather than bundled foreign runtime;
- `worker-rpc.js`: bounded Worker RPC execution;
- `policy.js`: explicit network/filesystem/runtime/output policy;
- `witness-stack-capability.js`: allowlisted capabilities, authority-escalation rejection, portable capability descriptors.

New encryption-side implementations live in `providers/xavi-portable/` and are intentionally narrower than the Memory runtime.
