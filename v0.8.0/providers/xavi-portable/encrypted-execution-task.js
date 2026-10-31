import { digest } from './provider-contract.js';
export const EXEC_SCHEMA='xavi-encrypted-polymorphic-task/v1';
export const EXEC_KINDS=Object.freeze(['worker','wasm','container2wasm','small-model']);

export function executionTask({requestId,kind,capability,imageDigest=null,modelDigest=null,entrypoint,inputDigest,resourceClass='bounded',returnKeyId}={}){
  if(!requestId||!capability||!inputDigest||!returnKeyId)throw new Error('requestId, capability, inputDigest and returnKeyId required');
  if(!EXEC_KINDS.includes(kind))throw new Error(`unsupported execution kind: ${kind}`);
  if((kind==='wasm'||kind==='container2wasm')&&!imageDigest)throw new Error(`${kind} requires approved imageDigest`);
  if(kind==='small-model'&&!modelDigest)throw new Error('small-model requires modelDigest');
  const body={schema:EXEC_SCHEMA,requestId,kind,capability,imageDigest,modelDigest,entrypoint:String(entrypoint||''),inputDigest,resourceClass,returnKeyId,authority:false};
  return Object.freeze({...body,digest:digest(body)});
}
