# XAVI-DUO accelerator fabric

> **Lab evidence note:** Any prod3/prod4/vm1, Xavi DNS, NFS, or cluster-specific names in this document describe validation history only. The standalone suite does not require that infrastructure.


Version: 0.6.0

The accelerator layer separates **what a computation requires** from **which vendor device executes it**. FHE/WG/WASM tasks request a typed compute capability and, when needed, an accelerator ABI. The broker first selects a compatible compute backend, then a compatible accelerator profile, then applies the profile's sandbox/device-injection contract. Learned routing happens only after those hard gates.

```text
WG trusted client / zero-import WASM
        |
        v
Worker RPC / compute broker
        |
        +-- compute capability: fhe.word64 / fhe.vector.approx / ...
        +-- backend ABI: cuda / rocm / level-zero / opencl / ...
        |
        v
ACCELERATOR_PROVIDERS.json
        |
        +-- device/runtime injection
        +-- read-only-root sandbox contract
        +-- ephemeral driver-injection overlays, if required
        v
GPU / NPU / FPGA / accelerator worker
```

## Security invariants

Accelerator choice never changes the cryptographic trust model. Remote FHE evaluators still receive only ciphertext and public/server/evaluation material. Client/private keys remain in the WG client/custody domain.

Production accelerator profiles must keep the container root filesystem read-only. If a device runtime needs to materialize driver links or cache/configuration data before process start, the profile may declare narrowly scoped **ephemeral tmpfs copy-up overlays**. They are discarded with the container and are not treated as persistent writable root state. The evaluator process itself need not be able to write those overlays.

Zero-import WASM never receives raw device files. WASM calls a Worker RPC typed capability; the Worker/broker owns device selection and sidecar launch.

## Current accelerator profiles

`ACCELERATOR_PROVIDERS.json` is the machine-readable authority for accelerator profiles.

- `nvidia-cdi-compute-v1`: **validated on prod3 RTX 2070** for the CUDA TFHE evaluator. Uses stock NVIDIA CDI. Root filesystem is read-only. `/usr/lib/x86_64-linux-gnu` and `/etc` are disposable copy-up tmpfs overlays used by CDI hooks for driver symlinks, ld-cache and application-profile state. The evaluator runs as numeric UID/GID `10001:999`, with `network=none`, `cap-drop=all`, `no-new-privileges`, and a read-only TFHE server-key mount.
- `amd-rocm-device-v1`: interface-ready for ROCm/HIP/OpenCL/Vulkan using `/dev/kfd` and DRM render nodes. **Not yet hardware/backend validated by this project.** A compatible backend image must provide matching ROCm/HIP userspace.
- `intel-level-zero-device-v1`: interface-ready for Level Zero/SYCL/OpenCL/Vulkan using DRM render nodes. **Not yet hardware/backend validated by this project.**
- `generic-cdi-v1`: vendor-neutral CDI full-device-name adapter for future GPU/NPU/FPGA/TPU-class runtimes that publish CDI devices.
- `generic-render-node-v1`: render-node adapter for OpenCL/Vulkan/WebGPU/custom backends.
- `remote-accelerator-rpc-v1`: capability endpoint for accelerator appliances or remote workers where no local device node is exposed to the task container.

Current prod4 discovery demonstrates the distinction: the host exposes NVIDIA plus AMD DRM/KFD devices, but the `tbi` worker identity currently has no read/write access to the AMD render/KFD nodes and ROCm tooling is not installed. The AMD lane therefore fails closed at the device-permission/backend gates. See `validation/xavi-cluster/ACCELERATOR_DISCOVERY_PROD4_v0.6.json`.

A registered accelerator profile does **not** imply an arbitrary program can run on that device. A backend must advertise an ABI the profile supports. The current TFHE GPU evaluator is compiled for CUDA, so it cannot run on AMD/Intel hardware merely because those devices are discoverable. The intended migration path is to add a compatible TFHE/OpenFHE/ML backend for `rocm`, `level-zero`, `opencl`, `vulkan-compute`, `webgpu`, or a future ABI while leaving the WG task/wire format unchanged.

## NVIDIA read-only-root correction

The v0.5 release documented a conservative exception that used an ephemeral but writable CUDA evaluator root because NVIDIA CDI needed to create driver-library symlinks. v0.6 removes that exception.

The validated prod3 launch profile is equivalent to:

```bash
podman run --rm -i \
  --user 10001:999 \
  --read-only \
  --tmpfs /usr/lib/x86_64-linux-gnu:rw,exec,mode=755,tmpcopyup \
  --tmpfs /etc:rw,exec,mode=755,tmpcopyup \
  --network none \
  --cap-drop all \
  --security-opt no-new-privileges \
  --security-opt label=disable \
  --device nvidia.com/gpu=all \
  -v server-key.bin:/keys/server-key.bin:ro \
  localhost/xavi-duo-tfhe-cuda-evaluator:0.5.0
```

The CDI hook created and verified the expected runtime links, including:

```text
libcuda.so -> libcuda.so.1
libcuda.so.1 -> libcuda.so.535.309.01
libnvidia-ptxjitcompiler.so.1 -> libnvidia-ptxjitcompiler.so.535.309.01
```

Writes to the ordinary root filesystem were blocked. The non-root evaluator process was also unable to write the driver-library overlay itself; the privileged pre-start CDI hook populated it. See `validation/xavi-cluster/ACCELERATOR_NVIDIA_READONLY_PROD3_v0.6.json`.

## Discovery and planning

```bash
./bin/xavi-duo accelerator-status

./bin/xavi-duo accelerator-plan \
  --profile nvidia-cdi-compute-v1 \
  --selector all \
  --runtime-user 10001:999
```

`accelerator-status` reports observable device/runtime surfaces without claiming backend compatibility. The current Linux discovery path recognizes DRM PCI vendor IDs for NVIDIA, AMD and Intel, render nodes, `/dev/kfd`, NVIDIA device nodes, CDI devices, and available runtime tools.

## Adding a future accelerator

A new device family should normally require no WG-RNN/WG-SFM/WG-SRNN changes. Add:

1. an accelerator profile declaring ABI(s), device/runtime injection and sandbox requirements;
2. a backend/provider image that advertises the same ABI and required FHE/ML capabilities;
3. hardware/backend validation evidence; and
4. benchmark/quality telemetry so WG learning can rank it against other already-eligible plans.

Profiles may use CDI, explicit device-node maps, render nodes, or authenticated remote RPC. Persistent writable host mounts, broad privileged containers, raw device authority in WASM, or learned overrides of the compatibility/security gate are not permitted by the v0.6 model.
