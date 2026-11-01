import { createHash } from 'node:crypto';

export const XAVI_CRYPTO_PROVIDER_SCHEMA='xavi-crypto-provider-capability/v1';
export const XAVI_CRYPTO_RESULT_SCHEMA='xavi-crypto-provider-result/v1';
export const ALLOWED_CRYPTO_CAPABILITIES=Object.freeze([
  'mlkem-keygen','mlkem-encapsulate','mlkem-decapsulate','provider-self-test'
]);

function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}
export function digest(value){return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');}
export function providerDescriptor({id,image,algorithm='ML-KEM-1024',capabilities=ALLOWED_CRYPTO_CAPABILITIES}={}){
  if(!id||!image)throw new TypeError('id and image required');
  for(const c of capabilities)if(!ALLOWED_CRYPTO_CAPABILITIES.includes(c))throw new Error(`unapproved crypto capability: ${c}`);
  return Object.freeze({schema:XAVI_CRYPTO_PROVIDER_SCHEMA,id:String(id),algorithm:String(algorithm),capabilities:[...capabilities],image:{...image},authority:false});
}
export function resultEnvelope({provider,operation,inputCommitment,outputCommitment,node='local',policy={},evidence={}}={}){
  if(!provider?.id)throw new TypeError('provider required');
  if(!provider.capabilities.includes(`mlkem-${operation}`)&&operation!=='self-test')throw new Error('operation not allowed by provider capability');
  const body={schema:XAVI_CRYPTO_RESULT_SCHEMA,providerId:provider.id,algorithm:provider.algorithm,operation,node,policy,inputCommitment,outputCommitment,evidence,authority:false};
  return Object.freeze({...body,digest:digest(body)});
}
