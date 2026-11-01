import { digest, ALLOWED_CRYPTO_CAPABILITIES } from './provider-contract.js';
export const TASK_SCHEMA='xavi-crypto-portable-task/v1';
export function portableCryptoTask({operation,algorithm='ML-KEM-1024',providerImageId,keyRef=null,inputRef=null,inputDigest=null,requestId,nodeHint=null}={}){
  const capability=`mlkem-${operation}`;
  if(!ALLOWED_CRYPTO_CAPABILITIES.includes(capability))throw new Error(`unsupported portable operation: ${operation}`);
  if(!providerImageId||!requestId)throw new Error('providerImageId and requestId required');
  if(operation==='decapsulate'&&!keyRef)throw new Error('decapsulation requires node-local keyRef; private key bytes must not be carried in task');
  const body={schema:TASK_SCHEMA,operation,capability,algorithm,providerImageId,keyRef,inputRef,inputDigest,requestId,nodeHint,authority:false};
  return Object.freeze({...body,digest:digest(body)});
}
