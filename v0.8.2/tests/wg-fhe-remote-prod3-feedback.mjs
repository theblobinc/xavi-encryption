import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {WGTrustedFHEClient} from '../integrations/wg-fhe-client/index.mjs';

test('real prod3 CKKS outcome feeds latency+quality witness back into WG-RNN/SFM/SRNN',async()=>{
  const v=JSON.parse(fs.readFileSync(new URL('../validation/xavi-cluster/VALIDATION_REMOTE_WG_RNN_FHE_PROD3.json',import.meta.url),'utf8'));
  assert.equal(v.status,'PASS');assert.equal(v.evaluator_has_client_secret,false);
  const client=await new WGTrustedFHEClient({namespace:'remote-prod3-feedback',stateDim:64,inputDim:24}).init();
  const base={program:{id:'wg-rnn-recurrent-depth10',irCommitment:v.response_sha256,depth:10,ciphertextBytes:0,recursiveDepth:1},key:{scheme:'CKKS',keyId:v.key_id,parameterSet:'depth10-b16-s40',clientSecretPresent:true},trustedPlaintextFeatures:{validatedMaxAbsError:v.max_abs_error,tolerance:v.tolerance}};
  const candidates=[
    {id:'prod3-ckks-depth10',provider:'openfhe',device:'cpu',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:v.key_id,wallMs:v.remote_wall_ms,queue:0,cacheHitRate:.5,supportsResidentSessions:true,supportsBulkRegisters:true},
    {id:'prod4-ckks-depth10',provider:'openfhe',device:'cpu',remote:false,fhe:true,role:'evaluator',hasClientSecret:false,keyId:v.key_id,wallMs:v.remote_wall_ms+2500,queue:0,cacheHitRate:.2,supportsResidentSessions:true,supportsBulkRegisters:true},
  ];
  const planned=await client.plan({...base,candidates});
  assert.equal(planned.plan.evaluatorId,'prod3-ckks-depth10');
  const settled=await client.settle({planned,outcome:{ok:true,wallMs:v.remote_wall_ms,provider:'openfhe',device:'cpu',cacheHit:true,bootstrapCount:0,approximationError:v.max_abs_error,tolerance:v.tolerance}});
  assert.equal(settled.row.ok,true);assert.equal(settled.row.approximationError,v.max_abs_error);assert.equal(settled.row.tolerance,v.tolerance);assert.ok(settled.row.qualityReward>0&&settled.row.qualityReward<1);assert.ok(settled.row.reward>0);assert.equal(settled.recurrentTeaching.updated,true);
  const next=await client.plan({...base,candidates});
  const learned=next.ranked.find(x=>x.id==='prod3-ckks-depth10');
  assert.ok(learned.learning.attempts>=1);assert.ok(learned.learning.meanReward>0);
  const projection=client.srnn.publicProjection({capability:'fhe-evaluate',limit:8});
  assert.ok(projection.outcomes.length>=1);
  console.log(JSON.stringify({status:'PASS',selected:planned.plan.evaluatorId,reward:settled.row.reward,latencyReward:settled.row.latencyReward,qualityReward:settled.row.qualityReward,recurrentTeaching:settled.recurrentTeaching.updated,nextScore:learned.score,historyAttempts:learned.learning.attempts,srnnOutcomes:projection.outcomes.length},null,2));
});
