import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CKKSSplitSession } from '../integrations/wg-fhe-client/ckks-session.mjs';
import { WGEncryptedVectorRuntime } from '../integrations/wg-fhe-client/vector-runtime.mjs';

test('WG trusted client executes split CKKS cosine and recursively learns from witness', {timeout:300000}, async()=>{
  const td=fs.mkdtempSync(path.join(os.tmpdir(),'wg-fhe-ckks-'));const c=path.join(td,'client'),e=path.join(td,'eval');
  const session=new CKKSSplitSession({clientKeyDir:c,evaluatorKeyDir:e});const runtime=await new WGEncryptedVectorRuntime({ckksSession:session,custodyRef:'file://test/ckks'}).init();
  try{
    const a=Array.from({length:32},(_,i)=>i+1), b=Array.from({length:32},(_,i)=>i+2);
    const expected=a.reduce((s,x,i)=>s+x*b[i],0)/Math.sqrt(a.reduce((s,x)=>s+x*x,0)*b.reduce((s,x)=>s+x*x,0));
    const first=await runtime.cosine(a,b);const second=await runtime.cosine(a,b);
    assert.ok(Math.abs(first.value-expected)<1e-6);assert.ok(Math.abs(second.value-expected)<1e-6);
    assert.equal(first.plan.evaluatorId,'openfhe-ckks-evaluator');assert.equal(first.settled.recurrentTeaching.updated,true);assert.equal(second.settled.recurrentTeaching.updated,true);
    assert.equal(second.settled.row.cacheHit,true);assert.equal(runtime.wg.history.length,2);
    const wire=JSON.stringify(first.evaluatorView);for(const forbidden of ['trustedPlaintextFeatures','clientLearning','clientSecretPresent','leftNorm2','rightNorm2'])assert.ok(!wire.includes(forbidden));
    assert.equal(session.evaluatorCaps.has_client_secret,false);assert.equal(fs.existsSync(path.join(e,'private.bin')),false);assert.equal(fs.statSync(path.join(c,'private.bin')).mode & 0o777,0o600);
  } finally {await runtime.close();fs.rmSync(td,{recursive:true,force:true});}
});
