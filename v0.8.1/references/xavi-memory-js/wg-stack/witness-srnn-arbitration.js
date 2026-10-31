export const WG_SRNN_ARBITRATION_PROFILE='WG-SRNN-ARBITRATION/1';
export const WG_SRNN_ARBITRATION_COLLAPSE_SCHEMA='wg-srnn-arbitration-collapse/v1';
export const WG_SRNN_COMPACT_CONSENSUS_SCHEMA='wg-srnn-compact-consensus/v1';

export const WG_SRNN_ARBITRATION_AUTHORITY_PROFILE=Object.freeze({
  profile_id:WG_SRNN_ARBITRATION_PROFILE,
  truth_authority:false,
  proof_authority:false,
  promotion_authority:false,
  pruning_authority:false,
  mutation_authority:false,
  self_model_write_authority:false,
  self_kernel_write_authority:false,
  expert_output_is_observation_not_authority:true,
  independence_group_collapse_required:true,
});

const ALLOWED_STANCES=new Set(['support','contradict','uncertain']);

export class WGSRNNArbitrationError extends Error{
  constructor(message){super(message);this.name='WGSRNNArbitrationError';}
}

function text(value,max=4096){return String(value??'').trim().slice(0,max);}
function observerId(row){return text(row?.observer_id??row?.observerId,512);}
function independenceGroup(row,id){return text(row?.independence_group??row?.independenceGroup??id,512)||id;}
function stanceOf(row){return text(row?.stance||'uncertain',64).toLowerCase();}
function clamp01(value){
  const number=Number(value);
  if(!Number.isFinite(number))throw new WGSRNNArbitrationError('weight/confidence must be numeric and finite');
  return Math.max(0,Math.min(1,number));
}
function authorityProfile(){return{...WG_SRNN_ARBITRATION_AUTHORITY_PROFILE};}

export function collapseSrnnArbitrationObservations(observations=[]){
  const latest=new Map();
  for(const row of Array.from(observations??[])){
    if(!row||typeof row!=='object')throw new WGSRNNArbitrationError('observation must be an object');
    const id=observerId(row);
    if(!id)throw new WGSRNNArbitrationError('observer_id is required');
    const stance=stanceOf(row);
    if(!ALLOWED_STANCES.has(stance))throw new WGSRNNArbitrationError('stance must be support, contradict, or uncertain');
    latest.set(id,row);
  }

  const groups=new Map();
  for(const row of latest.values()){
    const id=observerId(row),group=independenceGroup(row,id);
    if(!groups.has(group))groups.set(group,[]);
    groups.get(group).push(row);
  }

  let supportWeight=0,contradictionWeight=0,uncertainWeight=0;
  const summaries=[];
  for(const groupId of [...groups.keys()].sort()){
    const members=groups.get(groupId);
    const stanceWeight={support:0,contradict:0,uncertain:0};
    for(const row of members){
      const stance=stanceOf(row);
      stanceWeight[stance]+=clamp01(row?.confidence??0.5);
    }
    const total=stanceWeight.support+stanceWeight.contradict+stanceWeight.uncertain||1;
    const supportFraction=stanceWeight.support/total;
    const contradictionFraction=stanceWeight.contradict/total;
    const groupConfidence=Math.min(1,total/Math.max(1,members.length));
    let effectiveStance;
    if(Math.abs(supportFraction-contradictionFraction)<0.10){effectiveStance='uncertain';uncertainWeight+=groupConfidence;}
    else if(supportFraction>contradictionFraction){effectiveStance='support';supportWeight+=groupConfidence;}
    else{effectiveStance='contradict';contradictionWeight+=groupConfidence;}
    summaries.push({
      independence_group:groupId,
      observer_count:members.length,
      effective_stance:effectiveStance,
      weight:Number(groupConfidence.toFixed(6)),
      observers:members.map(observerId).sort(),
    });
  }
  const decisive=supportWeight+contradictionWeight;
  return{
    schema:WG_SRNN_ARBITRATION_COLLAPSE_SCHEMA,
    independent_observers:latest.size,
    independent_groups:groups.size,
    support_weight:Number(supportWeight.toFixed(6)),
    contradiction_weight:Number(contradictionWeight.toFixed(6)),
    uncertain_weight:Number(uncertainWeight.toFixed(6)),
    support_ratio:Number((decisive?supportWeight/decisive:0).toFixed(6)),
    contradiction_ratio:Number((decisive?contradictionWeight/decisive:0).toFixed(6)),
    observer_summary:{groups:summaries},
    authority_profile:authorityProfile(),
  };
}

export function compactSrnnConsensusContext(consensus={}, {maxGroups=8}={}){
  const source=consensus?.observer_summary?.groups;
  const groups=Array.isArray(source)?source:[];
  const clean=[];
  for(const row of groups){
    if(!row||typeof row!=='object')continue;
    const stance=text(row?.effective_stance??'uncertain',64).toLowerCase();
    if(!ALLOWED_STANCES.has(stance))throw new WGSRNNArbitrationError('invalid consensus effective_stance');
    clean.push({
      independence_group:text(row?.independence_group,512),
      observer_count:Math.max(0,Math.trunc(Number(row?.observer_count)||0)),
      effective_stance:stance,
      weight:clamp01(row?.weight??0),
    });
  }
  clean.sort((a,b)=>b.weight-a.weight||a.independence_group.localeCompare(b.independence_group));
  const limit=Math.max(1,Math.trunc(Number(maxGroups)||8));
  const bounded=clean.slice(0,limit);
  return{
    schema:WG_SRNN_COMPACT_CONSENSUS_SCHEMA,
    claim_key:text(consensus?.claim_key,4096),
    subject:consensus?.subject??null,
    predicate:consensus?.predicate??null,
    object:consensus?.object??null,
    status:text(consensus?.status||'unresolved',128)||'unresolved',
    support_ratio:Number(consensus?.support_ratio)||0,
    contradiction_ratio:Number(consensus?.contradiction_ratio)||0,
    independent_observers:Math.max(0,Math.trunc(Number(consensus?.independent_observers)||0)),
    independent_groups:Math.max(0,Math.trunc(Number(consensus?.independent_groups)||0)),
    groups:bounded,
    groups_omitted:Math.max(0,clean.length-bounded.length),
    raw_observer_messages_included:false,
    authority_profile:authorityProfile(),
  };
}

export function srnnConsensusToAssessmentInputs(consensus={}, {maxGroups=8}={}){
  const compact=compactSrnnConsensusContext(consensus,{maxGroups});
  const status=compact.status;
  const support=Math.max(0,Math.min(1,compact.support_ratio));
  const contradiction=Math.max(0,Math.min(1,compact.contradiction_ratio));
  let verdict;
  if(status==='promotion_recommended')verdict='supported';
  else if(status==='disputed')verdict=contradiction>support?'contradicted':'partial';
  else if(status==='candidate_consensus')verdict='partial';
  else verdict='insufficient';

  const evidence_edges=[],contradiction_edges=[];
  for(const group of compact.groups){
    const edge=`consensus-group:${group.independence_group}`;
    if(group.effective_stance==='support')evidence_edges.push(edge);
    else if(group.effective_stance==='contradict')contradiction_edges.push(edge);
  }
  let confidence;
  if(verdict==='supported')confidence=support;
  else if(verdict==='contradicted')confidence=contradiction;
  else if(verdict==='partial')confidence=Math.max(support,contradiction);
  else confidence=Math.min(0.5,Math.max(support,contradiction));

  return{
    verdict,
    confidence:Number(confidence.toFixed(6)),
    evidence_edges,
    contradiction_edges,
    rationale:`Observer consensus status=${status}; independent_groups=${compact.independent_groups}; support_ratio=${support.toFixed(6)}; contradiction_ratio=${contradiction.toFixed(6)}; raw expert messages excluded from recurrent context.`,
    compact_context:compact,
    authority_profile:authorityProfile(),
  };
}

export const collapse_observations=collapseSrnnArbitrationObservations;
export const compact_consensus_context=compactSrnnConsensusContext;
export const consensus_to_assessment_inputs=srnnConsensusToAssessmentInputs;
