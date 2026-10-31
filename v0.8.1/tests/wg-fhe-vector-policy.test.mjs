import test from 'node:test';
import assert from 'node:assert/strict';
import {planWGClientOperation} from '../providers/wg-fhe-client/client-policy.mjs';
test('WG-RNN cosine selects split CKKS evaluator',()=>{const p=planWGClientOperation({component:'wg-rnn',operation:'cosine-similarity',remote:true});assert.equal(p.mode,'fhe');assert.equal(p.provider_id,'openfhe-ckks-evaluator');assert.equal(p.client_owns_fhe_secret,true);assert.equal(p.evaluator_has_client_secret,false);});
test('WG-RNN prediction vector selects split CKKS evaluator',()=>{const p=planWGClientOperation({component:'wg-rnn',operation:'prediction-vector',remote:true});assert.equal(p.provider_id,'openfhe-ckks-evaluator');assert.equal(p.capability,'fhe.vector.approx');});
test('WG-RNN nonlinear recurrent update selects split depth-10 CKKS evaluator',()=>{const p=planWGClientOperation({component:'wg-rnn',operation:'recurrent-vector-update',remote:true});assert.equal(p.mode,'fhe');assert.equal(p.provider_id,'openfhe-ckks-wg-rnn-evaluator');assert.equal(p.capability,'fhe.wg-rnn.recurrent');assert.equal(p.client_owns_fhe_secret,true);assert.equal(p.evaluator_has_client_secret,false);});
