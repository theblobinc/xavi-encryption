# Split TFHE-rs providers (Rev 1.2-dev4)

This is the production key-custody split. `xvoid-tfhe-client` owns the `ClientKey` and is the only process allowed to encrypt/decrypt. `xvoid-tfhe-evaluator` loads only a serialized `CompressedServerKey`; its source does not import or construct `ClientKey` and it exposes no encrypt/decrypt RPC.

The client creates `/keys/client-key.bin` mode `0600` and `/keys/server-key.bin` mode `0644` on first launch. Only `server-key.bin` is transferred/mounted to a remote evaluator. The evaluator is started with `--server-key /keys/server-key.bin --device cpu|cuda`.

The old combined sidecar remains for local conformance/debugging only. Production remote workers must use the split evaluator and are rejected by Python policy if a provider advertises `has_client_secret=true`.
