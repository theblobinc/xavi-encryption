# XAVI-DUO ML-KEM OpenSSL provider

Minimal rootless provider image for FIPS 203 ML-KEM operations.

The build stage uses Alpine only as a package source. The final `scratch` image contains only:

- musl runtime loader (MIT);
- OpenSSL 3.5+ executable and libcrypto/libssl (Apache-2.0);
- OpenSSL configuration.

No shell, package manager, BusyBox or network client is present in the final image.

Runtime policy is applied by `mlkem_provider.py`: no network, read-only rootfs, all capabilities dropped, no-new-privileges, bounded PIDs/memory/CPU, and a single mounted work directory.
