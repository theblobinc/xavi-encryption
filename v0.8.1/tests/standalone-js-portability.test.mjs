import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {loadProviders} from '../providers/xavi-exec/capability-broker.mjs';
import {loadAccelerators} from '../providers/xavi-exec/accelerator-registry.mjs';

test('JS compute registry is replaceable per deployment',()=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'xde-js-compute-'));
 const p=path.join(d,'compute.json');
 fs.writeFileSync(p,JSON.stringify({schema:'XAVI-DUO/COMPUTE-PROVIDERS/v2',providers:[{id:'portable-js',capabilities:['duo.native'],remote_safe:true,contains_client_secret:false,deployment_scope:'host-neutral'}]}));
 const old=process.env.XAVI_DUO_COMPUTE_REGISTRY;
 try{process.env.XAVI_DUO_COMPUTE_REGISTRY=p; assert.equal(loadProviders()[0].id,'portable-js');}
 finally{if(old===undefined)delete process.env.XAVI_DUO_COMPUTE_REGISTRY;else process.env.XAVI_DUO_COMPUTE_REGISTRY=old;fs.rmSync(d,{recursive:true,force:true});}
});

test('JS accelerator registry is replaceable per deployment',()=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'xde-js-accel-'));
 const p=path.join(d,'accelerators.json');
 fs.writeFileSync(p,JSON.stringify({schema:'XAVI-DUO/ACCELERATOR-PROVIDERS/v2',profiles:[{id:'portable-js-accel',abis:['future'],vendor:'any',remote_safe:true,status:'interface-ready',deployment_scope:'host-neutral'}]}));
 const old=process.env.XAVI_DUO_ACCELERATOR_REGISTRY;
 try{process.env.XAVI_DUO_ACCELERATOR_REGISTRY=p; assert.equal(loadAccelerators()[0].id,'portable-js-accel');}
 finally{if(old===undefined)delete process.env.XAVI_DUO_ACCELERATOR_REGISTRY;else process.env.XAVI_DUO_ACCELERATOR_REGISTRY=old;fs.rmSync(d,{recursive:true,force:true});}
});

test('portable JS runtime has no reference-lab host literals',()=>{
 const files=['capability-broker.mjs','accelerator-registry.mjs','fhe-capability-dispatcher.mjs','fhe-worker.mjs','native-wasm.mjs','wasm-capability-host.mjs','worker-fhe-rpc.mjs','word64.mjs'];
 const forbidden=['prod3','prod4','10.77.','/datastore3','/srv/xavi','/mnt/store','xavi-prod','tbi-production','registry.xavi.local'];
 for(const f of files){const text=fs.readFileSync(new URL('../providers/xavi-exec/'+f,import.meta.url),'utf8');for(const needle of forbidden)assert.equal(text.includes(needle),false,`${f} contains ${needle}`);}
});
