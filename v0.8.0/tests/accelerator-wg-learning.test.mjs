import test from 'node:test';
import assert from 'node:assert/strict';
import {WGTrustedFHEClient} from '../integrations/wg-fhe-client/index.mjs';

test('WG accelerator metadata is safe, witnessed, and retained for accelerator-aware learning',async()=>{
 const c=await new WGTrustedFHEClient({stateDim:16,inputDim:8}).init();
 const candidate={id:'gpu-a',provider:'tfhe',device:'cuda',acceleratorAbi:'cuda',acceleratorProfile:'nvidia-cdi-compute-v1',acceleratorVendor:'nvidia',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:'eval-key',wallMs:20,queue:0,cacheHitRate:0,supportsResidentSessions:true,supportsBulkRegisters:true};
 const planned=await c.plan({program:{id:'accel-test',irCommitment:'sha256:program',wordOps:1},key:{scheme:'tfhe',keyId:'eval-key',clientSecretPresent:true},candidates:[candidate]});
 assert.equal(planned.plan.acceleratorAbi,'cuda');
 assert.equal(planned.plan.acceleratorProfile,'nvidia-cdi-compute-v1');
 assert.equal(planned.evaluatorView.acceleratorProfile,'nvidia-cdi-compute-v1');
 const wire=JSON.stringify(planned.evaluatorView);assert.ok(!wire.includes('privateKey'));assert.ok(!wire.includes('clientSecret'));
 const settled=await c.settle({planned,outcome:{ok:true,wallMs:18,provider:'tfhe',device:'cuda',acceleratorAbi:'cuda',acceleratorProfile:'nvidia-cdi-compute-v1',acceleratorVendor:'nvidia'}});
 assert.equal(settled.row.acceleratorProfile,'nvidia-cdi-compute-v1');
 const planned2=await c.plan({program:{id:'accel-test',irCommitment:'sha256:program',wordOps:1},key:{scheme:'tfhe',keyId:'eval-key',clientSecretPresent:true},candidates:[candidate]});
 assert.equal(planned2.ranked[0].learning.attempts,1);
});
