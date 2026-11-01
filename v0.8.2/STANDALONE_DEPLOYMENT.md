# Standalone Deployment

XAVI-DUO Encryption is designed to operate independently of the Xavi cluster.

## Layers

1. **Core runtime** — XDE2/XDE2-PQ2, custody contracts, trust policy, replay/witness state, remote admission, provider identity, accelerator policy, FHE task formats, and release verification.
2. **Portable adapters** — software files, TPM2/PKCS#11 implementations, native executable providers, Podman/Docker OCI providers, Worker/WASM, file/socket/TLS/HTTPS/mTLS transports, callbacks, and remote services.
3. **Integration evidence** — Xavi-specific cluster harnesses and historical validation records. These are tests/examples only.

A machine does not need Xavi DNS, MCP, prod3/prod4, NFS, or Xavi authority services. It may have no container runtime at all if approved native/remote providers satisfy the deployment policy.

## Provider configuration

Default compute/accelerator registries are host-neutral. Deployments can supply `XAVI_DUO_COMPUTE_REGISTRY` and the corresponding accelerator registry override without editing the package. Provider identity is still immutable: OCI implementations must match an allowlisted image ID and native implementations an allowlisted executable SHA-256.

## Hardware

The accelerator fabric separates hardware discovery, OS/device permission, accelerator ABI, compatible backend implementation, and validated execution. NVIDIA/CUDA, AMD ROCm/HIP, Intel Level Zero/SYCL, OpenCL/Vulkan/WebGPU, generic CDI, Metal/PJRT/OpenXLA, remote accelerator RPC, and future device services can be represented without changing FHE/WG task semantics. An accelerator profile does not imply an FHE backend exists for it.

## High assurance

Use hardware/external custody for long-lived private keys, ML-KEM-1024 and ML-DSA-87, signed project-scoped remote admission, immutable provider identities, fail-closed sandbox policy, and an independent rollback-domain nonce anchor. A local file-only deployment can be secure for lower threat models but does not satisfy the default high-assurance custody/rollback requirements.

## Distribution verification

Install the signed wheel or source archive only after verifying the detached ML-DSA-87 release manifest using a release public key obtained through an independent trusted channel.

## Xavi lab evidence

Files under `validation/xavi-cluster/` record tests run on the development cluster. They are not configuration defaults and must not be interpreted as required infrastructure.
