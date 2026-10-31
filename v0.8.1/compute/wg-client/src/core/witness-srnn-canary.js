import { MemoryStore } from '../storage/memory-store.js';
import { WitnessLedger } from './witness.js';
import { WitnessGatedSelfReferentialStages } from './witness-srnn-stages.js';
import { collapseSrnnArbitrationObservations } from './witness-srnn-arbitration.js';
import { wgSrnnDependencyReflectionContext } from './witness-srnn-resume.js';

export const WG_SRNN_CANARY_PROFILE='WG-SRNN-CANARY-VALIDATION/1';
export const WG_SRNN_CANARY_AUTHORITY_PROFILE=Object.freeze({
  truth_authority:false,
  promotion_authority:false,
  learning_authority:false,
  mutation_authority:false,
  self_model_write_authority:false,
  network_access:false,
  live_memory_writes:false,
});

export class WGSRNNCanaryValidationError extends Error{
  constructor(message){super(message);this.name='WGSRNNCanaryValidationError';}
}

export class WGSRNNCanaryScope{
  constructor({agentId,threadId,userId='system'}={}){this.agentId=String(agentId??'').trim();this.threadId=String(threadId??'').trim();this.userId=String(userId??'').trim();}
  validate(){
    if(!this.agentId.startsWith('wg-srnn-canary-'))throw new WGSRNNCanaryValidationError("agentId must begin with 'wg-srnn-canary-'");
    if(!this.threadId.startsWith('validation-'))throw new WGSRNNCanaryValidationError("threadId must begin with 'validation-'");
    if(this.userId!=='system')throw new WGSRNNCanaryValidationError("WG-SRNN canary validation is restricted to userId='system'");
    return this;
  }
  get namespace(){this.validate();return`${this.userId}/${this.agentId}/${this.threadId}`;}
}

function consensusEvaluation(observations,{claimKey,minIndependentGroups=3,minSupportRatio=.75,minSupportWeight=1.8,maxContradictionRatio=.2}={}){
  const result=collapseSrnnArbitrationObservations(observations);
  const groups=result.independent_groups,supportRatio=result.support_ratio,contradictionRatio=result.contradiction_ratio,supportWeight=result.support_weight;
  let status,promotionRecommended=false;
  if(groups<minIndependentGroups)status='insufficient_observers';
  else if(contradictionRatio>maxContradictionRatio)status='disputed';
  else if(supportRatio>=minSupportRatio&&supportWeight>=minSupportWeight){status='promotion_recommended';promotionRecommended=true;}
  else status='candidate_consensus';
  return{...result,claim_key:claimKey??'',status,promotion_recommended:promotionRecommended,truth_authority:false,promotion_authority:false};
}

export function consensusCollapseProbe(){
  const correlated=Array.from({length:500},(_,i)=>({observer_id:`corr-${i}`,independence_group:'family-a',stance:'support',confidence:.9,created_at_ms:i}));
  const independent=Array.from({length:3},(_,i)=>({observer_id:`ind-${i}`,independence_group:`family-${i}`,stance:'support',confidence:.9,created_at_ms:1000+i}));
  const c1=consensusEvaluation(correlated,{claimKey:'claim-correlated'}),c2=consensusEvaluation(independent,{claimKey:'claim-independent'});
  return{schema:'wg-srnn-canary-consensus-probe/v1',profile_id:WG_SRNN_CANARY_PROFILE,correlated:{independent_observers:c1.independent_observers,independent_groups:c1.independent_groups,support_weight:c1.support_weight,support_ratio:c1.support_ratio,status:c1.status,group_observer_count:c1.observer_summary.groups[0]?.observer_count??0},independent:{independent_observers:c2.independent_observers,independent_groups:c2.independent_groups,support_weight:c2.support_weight,support_ratio:c2.support_ratio,status:c2.status},truth_authority:false,promotion_authority:false,authority_profile:{...WG_SRNN_CANARY_AUTHORITY_PROFILE}};
}

export function dependencyCausalReport(directive,{directives=[],stages=null,limit=12,minimumIndependentGroups=2}={}){
  if(!directive)throw new TypeError('directive is required');
  const reflection=wgSrnnDependencyReflectionContext(directive,{directives,stages,limit,minimumIndependentGroups});
  const edges=Array.isArray(stages?.edges)?stages.edges:[],relations={};const nodes=new Set();
  for(const edge of edges){const relation=String(edge?.relation??'').trim();if(relation)relations[relation]=(relations[relation]||0)+1;if(edge?.fromDigest)nodes.add(edge.fromDigest);if(edge?.toDigest)nodes.add(edge.toDigest);}
  const sorted=Object.fromEntries(Object.entries(relations).sort(([a],[b])=>a.localeCompare(b)));
  return{schema:'wg-srnn-canary-dependency-causal-report/v1',profile_id:WG_SRNN_CANARY_PROFILE,sealed_record_count:directives.length+(stages?.assessments?.length||0)+(stages?.outcomes?.length||0)+(stages?.credits?.length||0),dependency:{edge_candidate_count:reflection.edge_candidate_count,items:reflection.items,authority:reflection.authority,causal_claim_authority:reflection.causal_claim_authority,truth_authority:reflection.truth_authority,promotion_authority:reflection.promotion_authority,learning_authority:reflection.learning_authority},causal_graph:{node_count:nodes.size,edge_count:edges.length,relations:sorted,has_causes_relation:Object.hasOwn(sorted,'causes'),authority:'witness-derived-audit-graph-not-causal-inference',truth_authority:false},truth_authority:false,promotion_authority:false,interpretation:'dependency-association-and-witness-graph-not-causal-inference',authority_profile:{...WG_SRNN_CANARY_AUTHORITY_PROFILE}};
}

export async function adversarialProbe(){
  const namespace=`canary-adversarial:${Date.now()}:${Math.random().toString(16).slice(2)}`,store=new MemoryStore(),ledger=new WitnessLedger({store,namespace});
  await ledger.init();const stages=await new WitnessGatedSelfReferentialStages({store,ledger,namespace,autoIntegrity:false}).init();
  let selfWitnessRejected=false,selfWitnessException='';let tamperFailedClosed=false,tamperException='';
  try{
    const directive=await ledger.append('wg-srnn-directive-proposed',{directiveId:'canary-directive',author:'wg-rnn',capability:'verify:canary',strategyId:'canary-route',goal:'canary adversarial validation',proposedAction:'inspect synthetic validation boundary',authority:false});
    const evidence=await ledger.append('observer-evidence',{source:'synthetic-canary',epistemicStatus:'reported'});
    try{await stages.assessDirective({directiveDigest:directive.digest,directiveAuthor:'wg-rnn',directiveAuthorProvenanceGroup:'wg-rnn',assessorIdentity:'wg-rnn',assessorProvenanceGroup:'wg-rnn',verdict:'supported',confidence:.9,evidenceWitnessDigests:[evidence.digest],provenanceGroups:['wg-rnn']});}catch(error){selfWitnessRejected=true;selfWitnessException=error?.name||'Error';}
    const stored=await store.get('witness',directive.id);await store.set('witness',directive.id,{...stored,body:{...stored.body,goal:'TAMPERED AFTER SEAL'}});
    const probe=new WitnessGatedSelfReferentialStages({store,ledger,namespace,autoIntegrity:false});
    try{await probe.init();}catch(error){tamperFailedClosed=true;tamperException=error?.name||'Error';}finally{probe.dispose();}
  }finally{stages.dispose();}
  return{schema:'wg-srnn-canary-adversarial-probe/v1',profile_id:WG_SRNN_CANARY_PROFILE,tamper_failed_closed:tamperFailedClosed,tamper_exception:tamperException,self_witness_rejected:selfWitnessRejected,self_witness_exception:selfWitnessException,truth_authority:false,promotion_authority:false,authority_profile:{...WG_SRNN_CANARY_AUTHORITY_PROFILE}};
}

export class WGSRNNCanaryValidator{
  constructor({scope,releaseCandidate='unknown'}={}){this.scope=(scope instanceof WGSRNNCanaryScope?scope:new WGSRNNCanaryScope(scope)).validate();this.releaseCandidate=String(releaseCandidate??'unknown').slice(0,128);}
  async runPure(){const consensus=consensusCollapseProbe(),adversarial=await adversarialProbe();const passed=consensus.correlated.independent_groups===1&&consensus.independent.status==='promotion_recommended'&&adversarial.tamper_failed_closed&&adversarial.self_witness_rejected;return{schema:'wg-srnn-canary-validation-report/v1',profile_id:WG_SRNN_CANARY_PROFILE,release_candidate:this.releaseCandidate,namespace:this.scope.namespace,passed,consensus,adversarial,network_used:false,live_memory_writes:false,truth_authority:false,promotion_authority:false,authority_profile:{...WG_SRNN_CANARY_AUTHORITY_PROFILE}};}
}

export const consensus_collapse_probe=consensusCollapseProbe;
export const dependency_causal_report=dependencyCausalReport;
export const adversarial_probe=adversarialProbe;
