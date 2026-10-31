# Rev 1.2-dev5 target-worker native evidence

This file records native-provider evidence collected during the Rev 1.2-dev5 release validation. It supplements the default 149-test package suite; it does not replace the fail-closed provider skips in an environment where the corresponding sidecars are absent.

## Environment boundary

All application/toolchain work was performed inside isolated Podman/Docker containers. No host Python, Rust, Cargo, liboqs or CUDA userland installation was required by xavi-void. Production-3 supplied the NVIDIA driver/container device boundary for its RTX 2070.

## Native lanes executed

Validated target-worker lanes in this release session:

- real TFHE CPU conformance;
- real TFHE CUDA SHAKE256-512 conformance;
- full canonical TFHE CUDA SHAKE matrix covering empty/`abc`, 135/136/137, 271/272/273 and 544-byte messages;
- split TFHE client/evaluator remote-worker acceptance with the evaluator on CUDA;
- OpenFHE provider integration;
- CUDA word-provider integration;
- production PQ-provider interoperability.

The retained full CUDA matrix container `xavi-void-dev5-cuda-matrix` exited with code 0 after pytest reported `. [100%]`.

The retained split-key CUDA container `xavi-void-dev5-split-cuda` ran from 2026-09-15T02:42:44Z to 2026-09-15T02:57:10Z and exited with code 0 after pytest reported `. [100%]`. Its integration test encrypts and verifies three messages: empty input, `abc`, and a 136-byte SHAKE rate-boundary message.

## Split-key custody

The split acceptance launcher created separate client and evaluator key directories. `xvoid-tfhe-client` generated the TFHE client/server material in the client directory. Only `server-key.bin` was copied into the evaluator directory. Before pytest was executed, the launcher asserted both that the client key existed client-side and that `client-key.bin` did **not** exist in the evaluator directory.

The evaluator binary was built separately with TFHE-rs CUDA support and launched with `--device cuda --server-key <evaluator>/server-key.bin`. The evaluator source/runtime contract contains no client-key/decrypt RPC path.

## GPU observation

The target GPU was an NVIDIA GeForce RTX 2070 with 8192 MiB total memory. Post-run `nvidia-smi` snapshots showed approximately 5447 MiB allocated by the worker environment. Those snapshots are coarse process/device observations only. They are **not** presented as CUDA-event timing, kernel-launch counts, or exact per-operation VRAM attribution.

## Superseded CPU split run

A CPU split-worker duplicate on production-4 remained compute-bound for several hours. After the equivalent split-key CUDA acceptance completed successfully, that duplicate was terminated to free resources. It is not counted as a passing release gate.

## Release preflight

The release preflight passed:

- Python compilation inside the self-contained integration image;
- shell syntax checks for deployment scripts;
- `git diff --check`;
- conservative private-key/token marker scanning;
- tracked `client-key.bin` / `server-key.bin` artifact checks;
- the complete non-integration regression suite.

Final package-suite and artifact hashes are recorded separately in `TEST_STATUS.md` and the generated Rev 1.2-dev5 hash manifest.
