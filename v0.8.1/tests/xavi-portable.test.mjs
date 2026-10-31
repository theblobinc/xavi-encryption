import test from 'node:test'; import assert from 'node:assert/strict';
import {providerDescriptor} from '../providers/xavi-portable/provider-contract.js';
import {selectCryptoProvider} from '../providers/xavi-portable/ml-provider-router.js';
import {portableCryptoTask} from '../providers/xavi-portable/remote-task.js';
const imageId='994c36c66732b7ac2333e658b9ac3dc0b16acf90fa546c72fa6c0601f3066a68';
const mk=(id,node)=>({...providerDescriptor({id,image:{imageId}}),node});
test('ML ranks only hard-eligible providers',async()=>{
 const candidates=[mk('p4','prod4'),mk('p3','prod3'),{...mk('bad','evil'),algorithm:'not-mlkem'}];
 const r=await selectCryptoProvider({candidates,requirements:{algorithm:'ML-KEM-1024',capability:'mlkem-encapsulate',imageId,allowedNodes:['prod4','prod3']},features:{load:{prod4:.8,prod3:.2}},scorer:(p,f)=>1-f.load[p.node]});
 assert.equal(r.chosen.node,'prod3'); assert.equal(r.eligible.length,2); assert.equal(r.authority,false);
});
test('private decapsulation is pinned to key custody node',async()=>{
 const candidates=[mk('p4','prod4'),mk('p3','prod3')];
 const r=await selectCryptoProvider({candidates,requirements:{algorithm:'ML-KEM-1024',capability:'mlkem-decapsulate',imageId,privateKeyNode:'prod4'},scorer:()=>999});
 assert.equal(r.chosen.node,'prod4');
});
test('portable task carries key reference not private key bytes',()=>{
 const t=portableCryptoTask({operation:'decapsulate',providerImageId:imageId,keyRef:'nodekey://recipient/alice',inputDigest:'abc',requestId:'req:1'}); assert.equal(t.authority,false); assert.equal(t.keyRef,'nodekey://recipient/alice');
});
