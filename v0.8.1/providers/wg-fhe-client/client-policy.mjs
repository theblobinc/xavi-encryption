import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'../..');
const wg=JSON.parse(fs.readFileSync(path.join(root,'WG_FHE_CAPABILITIES.json'),'utf8'));
const compute=JSON.parse(fs.readFileSync(path.join(root,'COMPUTE_PROVIDERS.json'),'utf8')).providers;
const canonical=v=>JSON.stringify(v,Object.keys(v).sort());
function opSpec(component,operation){const row=wg.components?.[component]?.operations?.[operation];if(!row)throw new Error(`unknown WG FHE operation ${component}/${operation}`);return row;}
export function planWGClientOperation({component,operation,remote=false,privacyRequired=true,allowedProviderIds=null}){
  const spec=opSpec(component,operation); const capability=spec.preferred;
  const eligible=compute.filter(p=>{
    if(!p.capabilities?.includes(capability))return false;
    if(remote && !p.remote_safe)return false;
    if(remote && p.contains_client_secret)return false;
    if(String(p.status||'').includes('rebuild-required'))return false;
    if(allowedProviderIds && !allowedProviderIds.includes(p.id))return false;
    return true;
  });
  let mode='fhe',provider=null,reason='eligible-provider';
  if(eligible.length){provider=[...eligible].sort((a,b)=>a.id.localeCompare(b.id))[0];}
  else if(spec.fallback==='trusted-client-local'){mode='trusted-client-local';reason='no-declared-fhe-provider';}
  else if(privacyRequired){throw new Error(`no eligible FHE provider for ${component}/${operation}`);}
  else {mode='trusted-client-local';reason='privacy-not-required';}
  const plan={schema:'XAVI-DUO/WG-FHE-PLAN/v1',trust_domain:wg.trust_domain,component,operation,capability,mode,provider_id:provider?.id??null,provider_image_id:provider?.image_id??null,remote:Boolean(remote&&provider),client_owns_fhe_secret:true,evaluator_has_client_secret:provider?Boolean(provider.contains_client_secret):false,authority:false,reason};
  plan.plan_id='sha256:'+crypto.createHash('sha256').update(JSON.stringify(plan,Object.keys(plan).sort())).digest('hex');
  return Object.freeze(plan);
}
export function sanitizeLearningTelemetry(row={}){
  const allowed=new Set(wg.learning_feedback_allowed); const forbidden=new Set(wg.learning_feedback_forbidden); const out={};
  for(const [k,v] of Object.entries(row)){if(forbidden.has(k))continue;if(allowed.has(k))out[k]=v;}
  return Object.freeze({...out,authority:false});
}
export function knownValueOptimization({knownPlaintext=false,secretKeyProvided=false}){
  if(secretKeyProvided)throw new Error('secret keys are not optimizer inputs');
  return Object.freeze({schema:'XAVI-DUO/WG-FHE-KNOWN-VALUE/v1',constant_fold:Boolean(knownPlaintext),deterministic_plan:true,authority:false});
}
