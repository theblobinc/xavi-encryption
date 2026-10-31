# Security policy

The version-specific threat model, custody design, high-assurance profile, protocol, and security notes live inside each version directory. For the current release, start with:

- `v0.8.0/SECURITY.md`
- `v0.8.0/THREAT_MODEL.md`
- `v0.8.0/CUSTODY.md`
- `v0.8.0/CUSTODY_BACKENDS.md`
- `v0.8.0/HIGH_ASSURANCE_PROFILE.json`
- `v0.8.0/PROTOCOL.md`

Do not commit private keys, unsealed custody material, production secrets, runtime state, or approval credentials. Security-sensitive release artifacts should be detached, hashed, and linked to the exact immutable version snapshot.
