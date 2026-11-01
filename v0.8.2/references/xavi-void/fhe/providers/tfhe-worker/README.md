# Evaluation-only TFHE worker

This image contains Python xavi-void runtime code and **only** the `xvoid-tfhe-evaluator` Rust binary. It does not contain `xvoid-tfhe-client` or the client key. The evaluator receives `/keys/server-key.bin` read-only and rejects combined/client-secret providers at startup.

The worker uses line-delimited JSON on stdin/stdout so transport can be SSH, a local supervisor, or the PQ transport layer. `protocol_accept` drives replay/session state, `execute_shake` executes a canonical `XVOIDTFH` encrypted request, and snapshot/restore preserves replay/checkpoint state across worker restarts.
