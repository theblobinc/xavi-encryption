import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createNativeWasmExecutor} from '../providers/xavi-exec/native-wasm.mjs';
import {FheWorkerRpc} from '../providers/xavi-exec/worker-fhe-rpc.mjs';

// (module (func (export "run") (param i32 i32) (result i32) local.get 0 local.get 1 i32.xor))
const xorWasm=new Uint8Array([0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,0x01,0x07,0x01,0x60,0x02,0x7f,0x7f,0x01,0x7f,0x03,0x02,0x01,0x00,0x07,0x07,0x01,0x03,0x72,0x75,0x6e,0x00,0x00,0x0a,0x09,0x01,0x07,0x00,0x20,0x00,0x20,0x01,0x73,0x0b]);

test('pure WASM -> Worker RPC -> real TFHE/CKKS capabilities without raw host authority',{timeout:300000},async()=>{
  const td=fs.mkdtempSync(path.join(os.tmpdir(),'xde-wasm-fhe-'));
  const dirs={tfheClient:path.join(td,'tfhe-client'),tfheEval:path.join(td,'tfhe-eval'),ckksClient:path.join(td,'ckks-client'),ckksEval:path.join(td,'ckks-eval')};
  const wasm=createNativeWasmExecutor({bytes:xorWasm});
  const control=await wasm({args:[1,0]});
  assert.equal(control.value,1);assert.equal(control.hostImports,false);assert.equal(control.authority,false);
  const rpc=new FheWorkerRpc({allowedCapabilities:['fhe.boolean','fhe.word64','fhe.vector.approx'],dispatcher:{
    tfhe:{clientKeyDir:dirs.tfheClient,evaluatorKeyDir:dirs.tfheEval,custodyRef:'worker://trusted-client/tfhe',remote:false},
    ckks:{clientKeyDir:dirs.ckksClient,evaluatorKeyDir:dirs.ckksEval,custodyRef:'worker://trusted-client/ckks',remote:false,evaluatorId:'worker-ckks-evaluator'},
  }});
  try{
    const gate=await rpc.call('fhe.boolean',{op:'sfm-witness-gate',evidenceValid:true,authorityAllowed:false,override:Boolean(control.value)});
    assert.equal(gate.value,true);assert.equal(gate.authority,false);assert.equal(gate.evaluatorView.authority,false);

    const exact='1234605616436508552';
    const eq=await rpc.call('fhe.word64',{op:'eq',left:exact,right:'0x1122334455667788'});
    assert.equal(eq.value,true);
    const x=await rpc.call('fhe.word64',{op:'xor',left:exact,right:'18446744073709551615'});
    assert.equal(x.value,(0x1122334455667788n^0xffffffffffffffffn).toString(10));

    const a=Array.from({length:16},(_,i)=>(i-7)/8),b=Array.from({length:16},(_,i)=>(8-i)/9);
    const cosine=await rpc.call('fhe.vector.approx',{op:'cosine',left:a,right:b});
    const dot=a.reduce((s,v,i)=>s+v*b[i],0),na=Math.sqrt(a.reduce((s,v)=>s+v*v,0)),nb=Math.sqrt(b.reduce((s,v)=>s+v*v,0)),truth=dot/(na*nb);
    assert.ok(Math.abs(cosine.value-truth)<1e-4,{got:cosine.value,truth});
    assert.equal(cosine.authority,false);assert.equal(cosine.evaluatorView.authority,false);

    await assert.rejects(()=>rpc.call('gpu.raw',{op:'launch'}),/denied|unsupported/);
    await assert.rejects(()=>rpc.call('fhe.boolean',{op:'sfm-witness-gate',evidenceValid:true,authorityAllowed:true,authority:true}),/authority/);

    assert.equal(fs.existsSync(path.join(dirs.tfheClient,'client-key.bin')),true);
    assert.equal(fs.existsSync(path.join(dirs.tfheEval,'client-key.bin')),false);
    assert.equal(fs.existsSync(path.join(dirs.ckksClient,'private.bin')),true);
    assert.equal(fs.existsSync(path.join(dirs.ckksEval,'private.bin')),false);
    fs.mkdirSync('validation',{recursive:true});
    fs.writeFileSync('validation/WASM_WORKER_FHE_BRIDGE_v0.5.json',JSON.stringify({schema:'XAVI-DUO/WASM-WORKER-FHE-BRIDGE/v1',status:'PASS',native_wasm_host_imports:false,worker_capabilities:['fhe.boolean','fhe.word64','fhe.vector.approx'],tfhe_client_secret_only_in_client:true,ckks_client_secret_only_in_client:true,raw_gpu_exposed_to_wasm:false,network_exposed_to_wasm:false,filesystem_exposed_to_wasm:false,word64_wire:'unsigned-decimal-string',word64_exact:exact,cosine_abs_error:Math.abs(cosine.value-truth),authority:false},null,2)+'\n');
  }finally{await rpc.close();fs.rmSync(td,{recursive:true,force:true});}
});
