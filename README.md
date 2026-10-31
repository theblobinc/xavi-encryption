# xavi-encrypt

Versioned source repository for XAVI-DUO encryption, post-quantum transport, custody, encrypted-compute, and related release evidence.

## Repository model

Every published revision is a **self-contained version directory** at the repository root:

```text
xavi-encrypt/
├── v0.8.0/
├── v0.9.0/        # future
├── v1.0.0/        # future
├── VERSION_INDEX.json
└── ...repository metadata
```

A reader must not need an earlier version directory to understand, build, test, or audit a later revision. Once a version is released and tagged, its source snapshot is treated as immutable. New work goes into a new version directory.

## Current version

`v0.8.0/` is the first canonical version in this repository. It was materialized from the frozen reproducible release archive `XAVI_DUO_Encryption_v0.8.0_2026-10-30.tar.gz`.

Its release status is:

`PASS_INTERNAL_VALIDATION_REPRODUCIBLE_SIGNATURE_PENDING`

The source tree, release manifest, reproducibility proof, artifact hashes, wheel, source archive, signing request, and custody-discovery record are preserved under `v0.8.0/` and `v0.8.0/release/`.

## Validation

Run the repository-level integrity check:

```bash
python3 tools/verify_repository.py
```

Run the version's own test suite from the version directory:

```bash
cd v0.8.0
make test
```

Some provider, FHE, hardware-custody, and remote execution tests require the corresponding runtime/container/hardware environment described in that version's documentation.

## Licensing

Unless a component explicitly states otherwise, this repository is offered under either of:

- MIT License
- Apache License 2.0

See `LICENSE-MIT` and `LICENSE-APACHE`.
