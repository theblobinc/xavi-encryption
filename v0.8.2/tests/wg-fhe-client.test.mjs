import test from 'node:test';import assert from 'node:assert/strict';
import {WGTrustedFHEClient,sanitizeEvaluatorView} from '../integrations/wg-fhe-client/index.mjs';

test('WG trusted FHE client uses real RNN/SFM/SRNN and emits secret-blind evaluator view',async()=>{
  const client=await new WGTrustedFHEClient().init();
  const input={program:{id:'p1',irCommitment:'sha256:abc',booleanOps:42,wordOps:8,depth:9,bootstraps:3,ciphertextBytes:4096,recursiveDepth:2},key:{scheme:'tfhe',keyId:'sha3-512:key1',parameterSet:'tfhe-rs-1.8',clientSecretPresent:true,custodyRef:'tpm2://prod3/tfhe-client',evaluationKeyBytes:60227968,ciphertextExpansion:12.2,deterministicClient:true},trustedPlaintextFeatures:{knownInputShape:'64-bit words',knownConstants:5},candidates:[{id:'prod4-cpu',provider:'tfhe',device:'cpu',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:'sha3-512:key1',wallMs:100,queue:1,cacheHitRate:.8,supportsResidentSessions:true,supportsBulkRegisters:true},{id:'bad-combined',provider:'tfhe',device:'cpu',remote:true,fhe:true,role:'combined',hasClientSecret:true,keyId:'sha3-512:key1',wallMs:1,queue:0,cacheHitRate:1}]};
  const planned=await client.plan(input);assert.equal(planned.plan.evaluatorId,'prod4-cpu');assert.equal(planned.evaluatorView.evaluationKeyId,'sha3-512:key1');assert.equal(planned.trustedContext.key.clientSecretPresent,true);const wire=JSON.stringify(planned.evaluatorView);assert.ok(!wire.includes('knownInputShape'));assert.ok(!wire.includes('trustedPlaintextFeatures'));assert.ok(!wire.includes('clientSecretPresent'));assert.equal(planned.plan.wg.srnn.strategyId,'prod4-cpu');
  const settled=await client.settle({planned,outcome:{ok:true,wallMs:80,provider:'tfhe',device:'cpu',cacheHit:true,bootstrapCount:3}});assert.equal(settled.row.ok,true);assert.equal(settled.authority,false);
});

test('evaluator sanitizer rejects secret-bearing property names',()=>{assert.throws(()=>sanitizeEvaluatorView({programId:'x',witnessContext:{clientSecret:'bad'}}));});

test('WG trusted FHE client recursively shifts away from a repeatedly failed evaluator',async()=>{
  const c=await new WGTrustedFHEClient({namespace:'adaptive-test',stateDim:32,inputDim:16}).init();
  const base={program:{id:'p-adapt',irCommitment:'sha256:adapt'},key:{scheme:'CKKS',keyId:'k-adapt',parameterSet:'ckks16',clientSecretPresent:true},trustedPlaintextFeatures:{knownRange:1.5}};
  const candidates=[
    {id:'eval-a',provider:'openfhe',device:'cpu',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:'k-adapt',wallMs:8,queue:0,cacheHitRate:.2,supportsResidentSessions:true,supportsBulkRegisters:true},
    {id:'eval-b',provider:'openfhe',device:'cpu',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId:'k-adapt',wallMs:10,queue:0,cacheHitRate:.2,supportsResidentSessions:true,supportsBulkRegisters:true},
  ];
  const first=await c.plan({...base,candidates});
  assert.equal(first.plan.evaluatorId,'eval-a');
  for(let i=0;i<4;i++){
    const p=await c.plan({...base,candidates});
    if(p.plan.evaluatorId==='eval-a') await c.settle({planned:p,outcome:{ok:false,wallMs:1000,provider:'openfhe',device:'cpu'}});
    else await c.settle({planned:p,outcome:{ok:true,wallMs:10,provider:'openfhe',device:'cpu'}});
  }
  const after=await c.plan({...base,candidates});
  assert.equal(after.plan.evaluatorId,'eval-b');
  const a=after.ranked.find(x=>x.id==='eval-a'),b=after.ranked.find(x=>x.id==='eval-b');
  assert.ok(a.learning.attempts>=1);
  assert.ok(b.score>a.score);
});

test('WG trusted FHE client uses witnessed operation mix to prefer CUDA for secret-rotation-heavy TFHE',async()=>{
  const c=await new WGTrustedFHEClient({namespace:'operation-aware-test',stateDim:32,inputDim:16}).init();
  const keyId='tfhe-key-op-aware';
  const base={program:{id:'tfhe-heavy',irCommitment:'sha256:op-aware',operationProfile:{word_xor:1,word_and:1,word_mux:1,word_rotl_public:1,word_rotl_secret:1}},key:{scheme:'TFHE',keyId,parameterSet:'word64',clientSecretPresent:true}};
  const candidates=[
    {id:'prod3-gpu',provider:'tfhe-cuda-evaluator',device:'cuda',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:28960,queue:0,cacheHitRate:0,supportsResidentSessions:true,supportsBulkRegisters:true,operationCostsMs:{word_xor:100.06,word_and:84.64,word_mux:219.22,word_rotl_public:74.34,word_rotl_secret:27321.93}},
    {id:'prod4-cpu',provider:'tfhe-cpu-evaluator',device:'cpu',remote:false,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:268000,queue:0,cacheHitRate:0,supportsResidentSessions:true,supportsBulkRegisters:true,costBounds:{word_rotl_secret:268000}},
  ];
  const p=await c.plan({...base,candidates});
  assert.equal(p.plan.evaluatorId,'prod3-gpu');
  const gpu=p.ranked.find(x=>x.id==='prod3-gpu'),cpu=p.ranked.find(x=>x.id==='prod4-cpu');
  assert.ok(gpu.learning.estimatedOperationMs<cpu.learning.estimatedOperationMs);
  assert.ok(gpu.learning.operationCoverage>cpu.learning.operationCoverage);
});

test('WG trusted FHE client reuses witnessed per-operation costs on later plans',async()=>{
  const c=await new WGTrustedFHEClient({namespace:'operation-history-test',stateDim:32,inputDim:16}).init();
  const keyId='tfhe-history-key';
  const base={program:{id:'tfhe-history',irCommitment:'sha256:history',operationProfile:{word_rotl_secret:1}},key:{scheme:'TFHE',keyId,parameterSet:'word64',clientSecretPresent:true}};
  const firstCandidates=[
    {id:'gpu',provider:'tfhe-cuda',device:'cuda',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:29000,operationCostsMs:{word_rotl_secret:27322}},
    {id:'cpu',provider:'tfhe-cpu',device:'cpu',remote:false,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:268000,costBounds:{word_rotl_secret:268000}},
  ];
  const p=await c.plan({...base,candidates:firstCandidates});assert.equal(p.plan.evaluatorId,'gpu');
  await c.settle({planned:p,outcome:{ok:true,wallMs:29000,operationCostsMs:{word_rotl_secret:27322}}});
  const nextCandidates=[
    {id:'gpu',provider:'tfhe-cuda',device:'cuda',remote:true,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:29000},
    {id:'cpu',provider:'tfhe-cpu',device:'cpu',remote:false,fhe:true,role:'evaluator',hasClientSecret:false,keyId,wallMs:268000,costBounds:{word_rotl_secret:268000}},
  ];
  const next=await c.plan({...base,candidates:nextCandidates});assert.equal(next.plan.evaluatorId,'gpu');
  const g=next.ranked.find(x=>x.id==='gpu');assert.equal(g.learning.operationPricing.word_rotl_secret.source,'history');assert.equal(g.learning.operationPricing.word_rotl_secret.value,27322);
});
