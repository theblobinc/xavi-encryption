import test from 'node:test';
import assert from 'node:assert/strict';
import {WasmCapabilityHost,frozenCapabilityPolicy} from '../providers/xavi-exec/wasm-capability-host.mjs';
test('brokered WASM exposes typed capability but no raw GPU authority',async()=>{const seen=[];const h=new WasmCapabilityHost({allowedCapabilities:['fhe.boolean'],dispatch:async r=>{seen.push(r);return {ok:true};}});assert.deepEqual(await h.call('fhe.boolean',{op:'xor'}),{ok:true});assert.equal(seen[0].request.authority,false);await assert.rejects(()=>h.call('gpu.raw',{op:'launch'}),/denied/);});
test('policy is frozen and has no network/filesystem/raw GPU',()=>{const p=frozenCapabilityPolicy(['fhe.word64']);assert.equal(p.network,'none');assert.equal(p.filesystem,'none');assert.equal(p.raw_gpu,false);assert.equal(p.authority,false);assert.ok(Object.isFrozen(p));});
