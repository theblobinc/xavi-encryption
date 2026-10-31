# Security policy

The current security documentation is under `v0.8.1/`:

- `v0.8.1/SECURITY.md`
- `v0.8.1/THREAT_MODEL.md`
- `v0.8.1/CUSTODY.md`
- `v0.8.1/CUSTODY_BACKENDS.md`
- `v0.8.1/HIGH_ASSURANCE_PROFILE.json`
- `v0.8.1/PROTOCOL.md`

Do not commit private keys, unsealed custody material, production secrets, runtime state, approval credentials, or exploitable vulnerability details.

For a security vulnerability, prefer GitHub private vulnerability reporting / a private Security Advisory when available. If a private channel is unavailable, open only a minimal public issue requesting a private contact path; do **not** include exploit details, secrets, keys, or sensitive proof material in that issue.

Security-sensitive release artifacts must be detached, hashed, and bound to the exact immutable version snapshot. A release is not described as independently audited, FIPS-validated, accredited, or military-grade unless external evidence actually establishes that claim.
