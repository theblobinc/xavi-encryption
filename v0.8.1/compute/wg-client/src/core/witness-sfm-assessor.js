import { digest } from './utils.js';
import { compactSrnnConsensusContext, srnnConsensusToAssessmentInputs } from './witness-srnn-arbitration.js';

export const WG_SRNN_SFM_REFLECTION_BRIDGE_PROFILE='WG-SRNN-SFM-REFLECTION-BRIDGE/1';
export const WG_SRNN_SFM_ASSESSMENT_REQUEST_SCHEMA='wg-srnn-sfm-assessment-request/v1';
export const WG_SRNN_SFM_ASSESSMENT_REQUEST_SET_SCHEMA='wg-srnn-sfm-assessment-requests/v1';
export const WG_SFM_SEMANTIC_ASSESSOR_PROFILE='WG-SFM-SEMANTIC-ASSESSOR/1';
export const WG_SFM_SEMANTIC_ASSESSMENT_RESPONSE_SCHEMA='wg-sfm-semantic-assessment-response/v1';
export const WG_SFM_SEALED_SEMANTIC_ASSESSMENT_SCHEMA='wg-sfm-sealed-semantic-assessment/v1';
export const WG_SFM_REFLECTION_CLAIM_PREDICATE='wg-srnn-reflection-assessment';

const AUTHORITY_PROFILE=Object.freeze({
  profile_id:WG_SFM_SEMANTIC_ASSESSOR_PROFILE,
  truth_authority:false,proof_authority:false,promotion_authority:false,selection_authority:false,
  execution_authority:false,learning_authority:false,mutation_authority:false,
  self_model_write_authority:false,self_kernel_write_authority:false,
  consensus_is_evidence_not_authority:true,independence_group_collapse_required:true,
});
function text(v,max=4096){const s=String(v??'').trim();return s?s.slice(0,max):'';}
function clamp01(v){const n=Number(v);return Number.isFinite(n)?Math.max(0,Math.min(1,n)):0;}
function bounded(values,max=8){return (Array.isArray(values)?values:[]).filter(Boolean).slice(0,max);}
function assertNonAuthoritative(value,where='value'){
  for(const key of ['automatic_execution','execution_authority','selection_authority','truth_authority','promotion_authority','learning_authority','mutation_authority','self_model_write_authority'])if(value?.[key]===true)throw new Error(`${where} unexpectedly grants ${key}`);
  for(const key of ['recommended_action','action_override','proposal_confidence_override'])if(value?.[key]!=null)throw new Error(`${where} unexpectedly sets ${key}`);
}
function directiveId(d){return text(d?.directiveId??d?.directive_id,256);}
function directiveDigest(d){return text(d?.directiveDigest??d?.directive_digest??d?.record_digest,256);}
function requestCore(request){return{
  schema:WG_SRNN_SFM_ASSESSMENT_REQUEST_SCHEMA,profile_id:WG_SRNN_SFM_REFLECTION_BRIDGE_PROFILE,
  directive_id:text(request?.directive_id,256),directive_digest:text(request?.directive_digest,256),agenda_state:text(request?.agenda_state,128),
  kind:text(request?.kind,256),question:text(request?.question,4096),target_action:text(request?.target_action,4096),
  reason_codes:bounded(request?.reason_codes,8).map(v=>text(v,256)),requested_assessor:text(request?.requested_assessor,128),
  requested_witness_role:text(request?.requested_witness_role,128),response_expected:text(request?.response_expected,128),
};}
async function validateRequest(request,{directive=null}={}){
  if(request?.schema!==WG_SRNN_SFM_ASSESSMENT_REQUEST_SCHEMA)throw new Error('unsupported WG-SFM assessment request schema');
  if(directive){if(text(request.directive_id,256)!==directiveId(directive))throw new Error('assessment request targets a different directive');if(text(request.directive_digest,256)!==directiveDigest(directive))throw new Error('assessment request directive digest mismatch');}
  const expected=await digest(requestCore(request));if(text(request.request_id,256)!==expected)throw new Error('assessment request digest mismatch');
  if(request.requested_assessor!=='wg-sfm')throw new Error("WG-SRNN reflection bridge requires requested_assessor='wg-sfm'");
  if(request.requested_witness_role!=='independent-semantic-assessor')throw new Error('WG-SRNN reflection bridge requires an independent semantic assessor');
  if(request.response_expected!=='witnessed-semantic-assessment')throw new Error('WG-SRNN reflection bridge requires a witnessed semantic assessment response');
  assertNonAuthoritative(request,'assessment request');return true;
}

export async function buildWgSfmAssessmentRequests(directive,agenda,{requestLimit=4}={}){
  if(!directive)throw new TypeError('directive is required');if(!agenda)throw new TypeError('agenda is required');
  if(text(agenda.target_directive_id,256)!==directiveId(directive))throw new Error('reflection agenda targets a different directive');assertNonAuthoritative(agenda,'reflection agenda');
  const limit=Math.max(1,Math.min(12,Math.floor(Number(requestLimit)||4))),rawItems=Array.isArray(agenda.items)?agenda.items:[],requests=[];
  for(const raw of rawItems.slice(0,limit)){
    if(!raw||typeof raw!=='object')throw new Error('reflection agenda items must be objects');assertNonAuthoritative(raw,'reflection agenda item');
    if(raw.requested_assessor!=='wg-sfm')throw new Error('WG-SRNN reflection bridge only dispatches WG-SFM agenda items');
    if(raw.requested_witness_role!=='independent-semantic-assessor')throw new Error('reflection agenda item does not require an independent semantic assessor');
    if(raw.response_expected!=='witnessed-semantic-assessment')throw new Error('reflection agenda item does not request a witnessed semantic assessment');
    const core=requestCore({directive_id:directiveId(directive),directive_digest:directiveDigest(directive),agenda_state:agenda.agenda_state,kind:raw.kind,question:raw.question,target_action:raw.target_action,reason_codes:raw.reason_codes,requested_assessor:raw.requested_assessor,requested_witness_role:raw.requested_witness_role,response_expected:raw.response_expected});
    if(!core.kind||!core.question)throw new Error('reflection agenda item requires kind and question');
    requests.push({...core,request_id:await digest(core),authority:'assessment-request-only',recommended_action:null,action_override:null,proposal_confidence_override:null,automatic_execution:false,execution_authority:false,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,self_model_write_authority:false});
  }
  return{schema:WG_SRNN_SFM_ASSESSMENT_REQUEST_SET_SCHEMA,profile_id:WG_SRNN_SFM_REFLECTION_BRIDGE_PROFILE,target_directive_id:directiveId(directive),target_directive_digest:directiveDigest(directive),agenda_state:text(agenda.agenda_state,128),request_count:requests.length,requests,omitted_request_count:Math.max(0,rawItems.length-requests.length),authority:'assessment-dispatch-plan-only',recommended_action:null,action_override:null,proposal_confidence_override:null,automatic_execution:false,execution_authority:false,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,self_model_write_authority:false};
}

export async function wgSfmAssessmentClaim(request){
  await validateRequest(request);const target=text(request.target_action,4096);if(!request.request_id)throw new Error('WG-SFM assessment request_id is required');if(!target)throw new Error('WG-SFM assessment target_action is required');
  return{subject:request.request_id,predicate:WG_SFM_REFLECTION_CLAIM_PREDICATE,object:target,authority:'claim-key-only-not-truth',truth_authority:false,promotion_authority:false,mutation_authority:false};
}

export function compactWgSfmConsensus(consensus,{maxGroups=8}={}){
  return compactSrnnConsensusContext(consensus,{maxGroups});
}
function consensusInputs(consensus){
  const mapped=srnnConsensusToAssessmentInputs(consensus);
  return{verdict:mapped.verdict,confidence:mapped.confidence,evidence_edges:mapped.evidence_edges,contradiction_edges:mapped.contradiction_edges,rationale:mapped.rationale,compact_context:mapped.compact_context};
}

export async function wgSfmSemanticAssessmentResponse(request,consensus,{observerId='wg-sfm:semantic-assessor',independenceGroup='wg-sfm'}={}){
  await validateRequest(request);const claim=await wgSfmAssessmentClaim(request);for(const key of ['subject','predicate','object'])if(String(consensus?.[key]??'')!==String(claim[key]))throw new Error(`WG-SFM consensus ${key} does not match reflection request`);
  const observer=text(observerId,256),group=text(independenceGroup,256);if(!observer)throw new Error('WG-SFM semantic assessor observer_id is required');if(observer==='wg-rnn')throw new Error('WG-SFM semantic assessor cannot use wg-rnn as its observer');if(!group)throw new Error('WG-SFM semantic assessor independence_group is required');
  const inputs=consensusInputs(consensus),witnessPayload={request_id:request.request_id,claim:{subject:claim.subject,predicate:claim.predicate,object:claim.object},status:text(consensus?.status,64),verdict:inputs.verdict,confidence:inputs.confidence,compact_consensus:inputs.compact_context},payloadDigest=await digest(witnessPayload);
  const witness={witness_id:await digest({kind:'wg-sfm-semantic-assessor',payload:payloadDigest}),payload_digest:payloadDigest,observer_id:observer,provenance_digest:await digest({claim_key:text(consensus?.claim_key,512),evaluated_at_ms:Math.floor(Number(consensus?.evaluated_at_ms)||0),status:text(consensus?.status,64),independent_groups:Math.max(0,Math.floor(Number(consensus?.independent_groups)||0))}),independence_group:group};
  return{schema:WG_SFM_SEMANTIC_ASSESSMENT_RESPONSE_SCHEMA,profile_id:WG_SFM_SEMANTIC_ASSESSOR_PROFILE,request_id:request.request_id,assessor:'wg-sfm',verdict:inputs.verdict,confidence:inputs.confidence,evidence_edges:inputs.evidence_edges,contradiction_edges:inputs.contradiction_edges,rationale:inputs.rationale,witness,consensus_status:text(consensus?.status,64),consensus_promotion_recommended:Boolean(consensus?.promotion_recommended),independent_groups:Math.max(0,Math.floor(Number(consensus?.independent_groups)||0)),compact_consensus:inputs.compact_context,recommended_action:null,action_override:null,proposal_confidence_override:null,automatic_execution:false,execution_authority:false,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,mutation_authority:false,self_model_write_authority:false,authority:'witnessed-semantic-response-candidate-only',authority_profile:{...AUTHORITY_PROFILE}};
}

export async function sealWgSfmAssessmentFromConsensus(srnn,{directiveDigest,directiveId=null,request,consensus,observerId='wg-sfm:semantic-assessor',independenceGroup='wg-sfm'}={}){
  if(!srnn?.assessDirective)throw new TypeError('srnn with assessDirective() is required');const directive=srnn._findDirective?.(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');await validateRequest(request,{directive});
  const response=await wgSfmSemanticAssessmentResponse(request,consensus,{observerId,independenceGroup});
  if(!srnn.ledger?.append)throw new TypeError('srnn ledger is required to witness WG-SFM assessment evidence');
  const evidenceWitness=await srnn.ledger.append('wg-sfm-semantic-assessment-response',{schema:response.schema,profileId:response.profile_id,requestId:response.request_id,assessor:response.assessor,verdict:response.verdict,confidence:response.confidence,evidenceEdges:response.evidence_edges,contradictionEdges:response.contradiction_edges,rationale:response.rationale,witness:response.witness,consensusStatus:response.consensus_status,independentGroups:response.independent_groups,compactConsensus:response.compact_consensus,authority:false});
  const result=await srnn.assessDirective({directiveDigest:directive.directiveDigest,assessorIdentity:observerId,assessorProvenanceGroup:independenceGroup,verdict:response.verdict,confidence:response.confidence,evidenceWitnessDigests:[evidenceWitness.digest],provenanceGroups:[independenceGroup],consensusSummary:{schema:response.schema,requestId:response.request_id,claimKey:response.compact_consensus.claim_key,status:response.consensus_status,independentGroups:response.independent_groups,supportRatio:response.compact_consensus.support_ratio,contradictionRatio:response.compact_consensus.contradiction_ratio,responseWitness:response.witness,evidenceWitnessDigest:evidenceWitness.digest,authority:false}});
  if(!result?.accepted)throw new Error(`WG-SFM assessment sealing failed: ${result?.reason||'unknown'}`);
  return{schema:WG_SFM_SEALED_SEMANTIC_ASSESSMENT_SCHEMA,response,evidenceWitness,assessment:result,authority:false};
}

export const build_assessment_requests=buildWgSfmAssessmentRequests;
export const assessment_claim=wgSfmAssessmentClaim;
export const semantic_assessment_response=wgSfmSemanticAssessmentResponse;
export const seal_assessment_from_consensus=sealWgSfmAssessmentFromConsensus;
