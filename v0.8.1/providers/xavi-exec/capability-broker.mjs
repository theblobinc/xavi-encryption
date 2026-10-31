import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {selectAccelerator,acceleratorCompatible} from './accelerator-registry.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const defaultRegistryPath=path.resolve(here,'../../COMPUTE_PROVIDERS.json');
export function computeRegistryPath(){return process.env.XAVI_DUO_COMPUTE_REGISTRY?path.resolve(process.env.XAVI_DUO_COMPUTE_REGISTRY):defaultRegistryPath;}
export function loadProviders(){return JSON.parse(fs.readFileSync(computeRegistryPath(),'utf8')).providers;}
export function selectProvider({capability,device=null,remote=false,requireNoClientSecret=true,allowedIds=null,acceleratorAbi=null}){
  const rows=loadProviders().filter(p=>{
    if(!p.capabilities?.includes(capability))return false;
    if(acceleratorAbi && p.accelerator_abi!==acceleratorAbi)return false;
    if(device && ![device,'portable'].includes(p.device))return false;
    if(remote && !p.remote_safe)return false;
    if(requireNoClientSecret && p.contains_client_secret)return false;
    if(String(p.status||'').includes('rebuild-required'))return false;
    if(allowedIds && !allowedIds.includes(p.id))return false;
    return true;
  });
  if(!rows.length)throw new Error('no eligible compute provider');
  const order={wasm:0,tfhe:1,openfhe:2,'gpu-word':3};
  rows.sort((a,b)=>(order[a.kind]??99)-(order[b.kind]??99)||a.id.localeCompare(b.id));
  return Object.freeze({...rows[0]});
}

export function selectExecution({capability,device=null,remote=false,requireNoClientSecret=true,allowedProviderIds=null,acceleratorAbi=null,acceleratorVendor=null,allowedAcceleratorIds=null}){
  const provider=selectProvider({capability,device,remote,requireNoClientSecret,allowedIds:allowedProviderIds,acceleratorAbi});
  const abi=acceleratorAbi||provider.accelerator_abi||null;
  if(!abi)return Object.freeze({provider,accelerator:null});
  const accelerator=selectAccelerator({abi,vendor:acceleratorVendor,remote,allowedIds:allowedAcceleratorIds});
  if(!acceleratorCompatible(provider,accelerator))throw new Error('compute provider is incompatible with accelerator profile');
  return Object.freeze({provider,accelerator});
}
export function makeExecutionRequest({capability,programDigest,inputDigest,provider,sessionId,sequence,custodyRef=null}){
  if(!provider || provider.contains_client_secret)throw new Error('portable execution cannot bind client-secret provider');
  if(!capability || !programDigest || !inputDigest || !sessionId || !Number.isInteger(sequence)||sequence<1)throw new Error('invalid execution request');
  return Object.freeze({schema:'XAVI-DUO/COMPUTE-REQUEST/v1',capability,program_digest:programDigest,input_digest:inputDigest,provider_id:provider.id,provider_image_id:provider.image_id??null,session_id:sessionId,sequence,custody_ref:custodyRef,authority:false});
}
