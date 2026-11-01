import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {WGTrustedFHEClient} from '../integrations/wg-fhe-client/index.mjs';

const FILE='validation/xavi-cluster/REMOTE_TFHE_WG_SEMANTICS_PROD3_v0.5.json';
const ms=(row)=>Number(row?.total_ns||0)/1e6;

test('real prod3 TFHE GPU SFM/SRNN semantic outcomes feed measured operation costs into WG learning',async()=>{
  const v=JSON.parse(fs.readFileSync(FILE,'utf8'));
  assert.equal(v.status,'PASS');
  assert.equal(v.evaluator_has_client_secret,false);
  assert.equal(v.device,'cuda');
  assert.deepEqual(v.results,v.expected);
  const ops=v.metrics.operations;
  const bitAnd=ms(ops.bit_and)/Number(ops.bit_and.calls||1);
  const wordMux=ms(ops.word_mux)/Number(ops.word_mux.calls||1);
  const costs={
    bit_and:bitAnd,
    bit_or:ms(ops.bit_or),
    bit_not:ms(ops.bit_not),
    bit_mux:ms(ops.bit_mux),
    word_eq:ms(ops.word_eq),
    word_mux:wordMux,
  };
  const client=await new WGTrustedFHEClient({namespace:'remote-prod3-sfm-srnn-feedback',stateDim:64,inputDim:24}).init();
  const candidate={id:'prod3-tfhe-gpu',provider:'tfhe',device:'cuda',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:v.key_id,wallMs:v.remote_wall_ms,queue:0,cacheHitRate:.75,supportsResidentSessions:true,supportsBulkRegisters:true,operationCostsMs:costs};
  const unsafe={...candidate,id:'unsafe-combined',wallMs:1,hasClientSecret:true};
  const cpu={...candidate,id:'tfhe-cpu-bound',device:'cpu',wallMs:268000,cacheHitRate:0,operationCostsMs:{},costBounds:{bit_and:1000,bit_or:1000,bit_not:100,bit_mux:1500,word_eq:5000,word_mux:5000}};
  const key={scheme:'TFHE',keyId:v.key_id,parameterSet:'tfhe-rs-1.8',clientSecretPresent:true,custodyRef:'trusted-client://prod4/tfhe'};

  const sfmProfile={bit_and:1,bit_or:1,word_eq:1,word_mux:1};
  const sfmPlanned=await client.plan({program:{id:'wg-sfm:remote-semantic-batch',irCommitment:'sha256:sfm-prod3-semantic',operationProfile:sfmProfile,booleanOps:2,wordOps:2,depth:3},key,candidates:[candidate,cpu,unsafe],trustedPlaintextFeatures:{component:'wg-sfm',validatedSemantics:v.results}});
  assert.equal(sfmPlanned.plan.evaluatorId,'prod3-tfhe-gpu');
  assert.equal(sfmPlanned.ranked.some(x=>x.id==='unsafe-combined'),false);
  const sfmWall=costs.bit_and+costs.bit_or+costs.word_eq+costs.word_mux;
  const sfmSettled=await client.settle({planned:sfmPlanned,outcome:{ok:true,wallMs:sfmWall,provider:'tfhe',device:'cuda',cacheHit:true,operationCostsMs:costs}});
  assert.equal(sfmSettled.row.ok,true); assert.equal(sfmSettled.recurrentTeaching.updated,true);

  const srnnProfile={bit_and:2,bit_not:1,bit_mux:1,word_mux:1};
  const srnnPlanned=await client.plan({program:{id:'wg-srnn:remote-semantic-batch',irCommitment:'sha256:srnn-prod3-semantic',operationProfile:srnnProfile,booleanOps:4,wordOps:1,depth:4},key,candidates:[candidate,cpu,unsafe],trustedPlaintextFeatures:{component:'wg-srnn',validatedSemantics:v.results}});
  assert.equal(srnnPlanned.plan.evaluatorId,'prod3-tfhe-gpu');
  assert.equal(srnnPlanned.ranked.some(x=>x.id==='unsafe-combined'),false);
  const srnnWall=2*costs.bit_and+costs.bit_not+costs.bit_mux+costs.word_mux;
  const srnnSettled=await client.settle({planned:srnnPlanned,outcome:{ok:true,wallMs:srnnWall,provider:'tfhe',device:'cuda',cacheHit:true,operationCostsMs:costs}});
  assert.equal(srnnSettled.row.ok,true); assert.equal(srnnSettled.recurrentTeaching.updated,true);

  const nextSfm=await client.plan({program:{id:'wg-sfm:next',irCommitment:'sha256:sfm-next',operationProfile:sfmProfile},key,candidates:[candidate,cpu]});
  const nextSrnn=await client.plan({program:{id:'wg-srnn:next',irCommitment:'sha256:srnn-next',operationProfile:srnnProfile},key,candidates:[candidate,cpu]});
  const out={
    schema:'XAVI-DUO/REMOTE-TFHE-WG-SEMANTIC-LEARNING/v1',status:'PASS',client_node:'prod4',evaluator_node:'prod3',key_id:v.key_id,image_id:v.image_id,authority:false,
    semantic_results:v.results,
    measured_operation_cost_ms:costs,
    sfm:{selected:sfmPlanned.plan.evaluatorId,wall_ms:sfmWall,reward:sfmSettled.row.reward,recurrent_updated:sfmSettled.recurrentTeaching.updated,next_selected:nextSfm.plan.evaluatorId,next_learning:nextSfm.ranked.find(x=>x.id==='prod3-tfhe-gpu')?.learning},
    srnn:{selected:srnnPlanned.plan.evaluatorId,wall_ms:srnnWall,reward:srnnSettled.row.reward,recurrent_updated:srnnSettled.recurrentTeaching.updated,next_selected:nextSrnn.plan.evaluatorId,next_learning:nextSrnn.ranked.find(x=>x.id==='prod3-tfhe-gpu')?.learning},
    sfm_outcome_ingested:true,srnn_reflection_observed:Boolean(srnnSettled.reflection),unsafe_combined_eligible:false,
  };
  fs.writeFileSync('validation/xavi-cluster/REMOTE_TFHE_WG_SEMANTIC_LEARNING_v0.5.json',JSON.stringify(out,null,2)+'\n');
});
