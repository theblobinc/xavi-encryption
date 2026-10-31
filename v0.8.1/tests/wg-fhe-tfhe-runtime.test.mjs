import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { WGEncryptedGateRuntime } from '../integrations/wg-fhe-client/tfhe-runtime.mjs';

test('WG trusted client executes RNN/SFM/SRNN gates through split TFHE and learns witnesses',{timeout:240000},async()=>{
  const td=fs.mkdtempSync(path.join(os.tmpdir(),'wg-fhe-tfhe-')),clientDir=path.join(td,'client'),evalDir=path.join(td,'eval');
  const runtime=await new WGEncryptedGateRuntime({clientKeyDir:clientDir,evaluatorKeyDir:evalDir,custodyRef:'file://test/tfhe',remote:true}).init();
  try{
    assert.equal(runtime.caps.client_has_secret,true);assert.equal(runtime.caps.evaluator_role,'evaluator');assert.equal(runtime.caps.evaluator_has_client_secret,false);
    const r1=await runtime.rnnRouteGate({routeEnabled:true,capacityOk:true});
    const r2=await runtime.rnnRouteGate({routeEnabled:true,capacityOk:false});
    const s1=await runtime.sfmWitnessGate({evidenceValid:true,authorityAllowed:true});
    const s2=await runtime.sfmWitnessGate({evidenceValid:true,authorityAllowed:false});
    const s3=await runtime.sfmWitnessGate({evidenceValid:false,authorityAllowed:false,override:true});
    const q1=await runtime.srnnReleaseGate({candidateValid:true,noConflict:true,integrityOk:true});
    const q2=await runtime.srnnReleaseGate({candidateValid:true,noConflict:false,integrityOk:true});
    assert.deepEqual([r1.value,r2.value,s1.value,s2.value,s3.value,q1.value,q2.value],[true,false,true,false,true,true,false]);
    for(const row of [r1,r2,s1,s2,s3,q1,q2]){assert.equal(row.settled.recurrentTeaching.updated,true);const wire=JSON.stringify(row.evaluatorView);for(const bad of ['trustedPlaintextFeatures','clientLearning','clientSecretPresent','route_enabled','evidence_valid','candidate_valid'])assert.ok(!wire.includes(bad),bad);}
    assert.equal(runtime.wg.history.length,7);assert.equal(fs.existsSync(path.join(evalDir,'client-key.bin')),false);assert.equal(fs.existsSync(path.join(evalDir,'server-key.bin')),true);assert.equal(fs.existsSync(path.join(clientDir,'client-key.bin')),true);assert.equal(fs.statSync(path.join(clientDir,'client-key.bin')).mode&0o777,0o600);
  } finally {await runtime.close();fs.rmSync(td,{recursive:true,force:true});}
});
