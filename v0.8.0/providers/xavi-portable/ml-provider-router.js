import { digest } from './provider-contract.js';

export const ROUTE_SCHEMA='xavi-crypto-ml-route-decision/v1';

function hardEligible(p,requirements){
  if(!p||p.authority!==false)return false;
  if(p.algorithm!==requirements.algorithm)return false;
  if(!p.capabilities?.includes(requirements.capability))return false;
  if(requirements.imageId && p.image?.imageId!==requirements.imageId)return false;
  if(requirements.allowedNodes?.length && !requirements.allowedNodes.includes(p.node))return false;
  if(requirements.privateKeyNode && p.node!==requirements.privateKeyNode)return false;
  return true;
}

/**
 * ML may rank ONLY candidates that already passed hard crypto/policy gates.
 * scorer(candidate,features) returns a finite preference score; it has no access
 * to private key bytes or shared secrets and cannot rewrite candidate metadata.
 */
export async function selectCryptoProvider({candidates,requirements,features={},scorer=null}={}){
  const eligible=(candidates||[]).filter(p=>hardEligible(p,requirements));
  if(!eligible.length)throw new Error('no cryptographically eligible provider');
  const scored=[];
  for(const p of eligible){
    const raw=scorer?await scorer(Object.freeze({...p}),Object.freeze({...features})):Number(p.prior||0);
    const score=Number(raw); if(!Number.isFinite(score))throw new Error('ML/provider score must be finite');
    scored.push({provider:p,score});
  }
  scored.sort((a,b)=>b.score-a.score||String(a.provider.id).localeCompare(String(b.provider.id)));
  const chosen=scored[0].provider;
  const body={schema:ROUTE_SCHEMA,requirements:{...requirements},eligible:scored.map(x=>({id:x.provider.id,node:x.provider.node,score:x.score})),chosen:{id:chosen.id,node:chosen.node},authority:false};
  return Object.freeze({...body,digest:digest(body)});
}
