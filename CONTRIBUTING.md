# Contributing to xavi-encrypt

## Version-directory rule

All substantive development after `v0.8.0` must be made in a new self-contained version directory (`vX.Y.Z/`). Do not make a new revision depend on files that exist only in an older version directory.

For each new version:

1. Copy forward every source, test, document, protocol definition, provider definition, and citation/evidence item still required by the new revision.
2. Update the version's package metadata and `VERSION` file.
3. Add or update its release gate and release manifest.
4. Run the complete applicable Python, JavaScript/WASM/FHE, parity, and packaging gates.
5. Add release artifacts/evidence under `vX.Y.Z/release/`.
6. Add the version and frozen hashes to `VERSION_INDEX.json` and `CHANGELOG.md`.
7. Commit and tag the completed revision as `vX.Y.Z`.

Released/tagged version directories are immutable historical snapshots. Corrections belong in a later version unless the change is strictly repository metadata outside the frozen version snapshot.

Never commit runtime private keys, decrypted custody material, `.state` directories, process IDs, caches, virtual environments, or machine-local secrets.
