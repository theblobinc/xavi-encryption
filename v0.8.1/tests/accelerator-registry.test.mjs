import test from 'node:test';
import assert from 'node:assert/strict';
import {selectAccelerator,acceleratorCompatible,assertAcceleratorSandbox} from '../providers/xavi-exec/accelerator-registry.mjs';
import {selectExecution} from '../providers/xavi-exec/capability-broker.mjs';

test('NVIDIA accelerator profile keeps root read-only and uses only ephemeral injection overlays',()=>{
 const p=selectAccelerator({abi:'cuda',vendor:'nvidia',remote:true});
 assert.equal(p.id,'nvidia-cdi-compute-v1');
 assert.equal(p.sandbox.read_only_rootfs,true);
 assert.deepEqual(p.sandbox.writable_injection_overlays.map(x=>x.path),['/usr/lib/x86_64-linux-gnu','/etc']);
 assert.ok(p.sandbox.writable_injection_overlays.every(x=>x.type==='tmpfs'&&x.persistent===false));
 assert.equal(assertAcceleratorSandbox(p),true);
});

test('compute broker binds CUDA TFHE only to a compatible accelerator profile',()=>{
 const plan=selectExecution({capability:'fhe.word64',acceleratorAbi:'cuda',acceleratorVendor:'nvidia',remote:true});
 assert.equal(plan.provider.id,'tfhe-cuda-evaluator');
 assert.equal(plan.accelerator.id,'nvidia-cdi-compute-v1');
 assert.equal(acceleratorCompatible(plan.provider,plan.accelerator),true);
});

test('future accelerator classes are registry-driven',()=>{
 assert.equal(selectAccelerator({abi:'rocm',vendor:'amd'}).id,'amd-rocm-device-v1');
 assert.equal(selectAccelerator({abi:'level-zero',vendor:'intel'}).id,'intel-level-zero-device-v1');
 assert.equal(selectAccelerator({abi:'webgpu'}).id,'generic-render-node-v1');
 assert.equal(selectAccelerator({abi:'generic-cdi'}).id,'nvidia-cdi-compute-v1');
});
