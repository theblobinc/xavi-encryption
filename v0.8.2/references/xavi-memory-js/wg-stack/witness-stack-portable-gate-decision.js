import { shake256Hex } from './crypto.js';
import { stringifyWgStackPortableJson } from './witness-stack-portable-envelope.js';
import { verifyWgStackPortableFamilyAdmission } from './witness-stack-portable-admission.js';
import { WitnessGate } from './gates.js';

export const WG_STACK_PORTABLE_GATE_DECISION_SCHEMA='xavi-wg-stack-portable-family-gate-decision/v1';
export const WG_STACK_PORTABLE_GATE_DECISION_PROFILE='WG-STACK-PORTABLE-GATE-DECISION/1';
export const WG_STACK_PORTABLE_GATE_DECISION_VERIFICATION_SCHEMA='xavi-wg-stack-portable-family-gate-decision-verification/v1';
export const WG_STACK_PORTABLE_GATE_DECISION_WITNESS_SCHEMA='xavi-wg-stack-portable-family-gate-decision-witness/v1';
export const WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY=Object.freeze({
  authority:false,truth_authority:false,proof_authority:false,promotion_authority:false,
  learning_authority:false,execution_authority:false,mutation_authority:false,application_authority:false,
  self_model_write_authority:false,self_kernel_write_authority:false,
});
export class WGStackPortableGateDecisionError extends Error{constructor(message){super(message);this.name='WGStackPortableGateDecisionError';}}
const clean=v=>String(v??'').trim();
const bool=v=>v===true;
function digest(value){return `shake256-512:${shake256Hex(stringifyWgStackPortableJson(value,{space:0}),64)}`;}
function guard(value,where='gate decision value',seen=new Set()){
  if(value===null||typeof value!=='object'||seen.has(value))return;seen.add(value);
  const forbidden=new Set(['authority','truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority','learning_authority','learningAuthority','learning_authorized','learningAuthorized','execution_authority','executionAuthority','execution_authorized','executionAuthorized','mutation_authority','mutationAuthority','mutation_authorized','mutationAuthorized','promotion_authorized','promotionAuthorized','application_authority','applicationAuthority','application_authorized','applicationAuthorized','apply_authorized','applyAuthorized','install_authorized','installAuthorized','self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority']);
  for(const [key,row] of Object.entries(value)){if(forbidden.has(key)&&row===true)throw new WGStackPortableGateDecisionError(`${where} attempts authority escalation via ${key}`);guard(row,`${where}.${key}`,seen);}
}
function witnessed(value){return clean(value).startsWith('shake256-512:')||clean(value).startsWith('witness:')||clean(value).length>=16;}
function decisionIdentity(row){return{
  schema:row.schema,profile_id:row.profile_id,admission_digest:row.admission_digest,stage_digest:row.stage_digest,
  family:row.family,index:row.index??null,candidate_digest:row.candidate_digest,gate:row.gate,native_gate_schema:row.native_gate_schema,
  evidence:row.evidence,requirements:row.requirements,blockers:row.blockers,gate_ready:row.gate_ready===true,
  mutation_authorized:false,application_authorized:false,learning_authorized:false,execution_authorized:false,
  ...WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY,
};}
export function digestWgStackPortableGateDecision(row){return digest(decisionIdentity(row));}

function evaluateRnn(evidence){
  const gate=new WitnessGate({expectedStateDim:Number(evidence?.expectedStateDim||256)});
  const learning=gate.assessLearning({
    outcomeWitnessed:witnessed(evidence?.outcomeWitnessDigest),
    temporalCreditAvailable:bool(evidence?.temporalCreditAvailable),
    dependencyCreditAvailable:bool(evidence?.dependencyCreditAvailable),
    validationPassed:bool(evidence?.validationPassed),
    lineageSafe:evidence?.lineageSafe!==false,
  });
  const requirements={
    admissionWitnessed:witnessed(evidence?.admissionWitnessDigest),candidateWitnessed:witnessed(evidence?.candidateWitnessDigest),
    ...learning.requirements,
  };
  return{requirements,blockers:Object.entries(requirements).filter(([,v])=>v!==true).map(([k])=>k),native_gate_schema:learning.schemaVersion};
}
function evaluateSfmSnapshot(evidence){
  const requirements={
    admissionWitnessed:witnessed(evidence?.admissionWitnessDigest),candidateWitnessed:witnessed(evidence?.candidateWitnessDigest),
    validationPassed:bool(evidence?.validationPassed),lineageSafe:evidence?.lineageSafe!==false,targetCompatible:bool(evidence?.targetCompatible),
    learnedEvidencePreserved:bool(evidence?.learnedEvidencePreserved),stateDimensionsCompatible:bool(evidence?.stateDimensionsCompatible),
  };
  return{requirements,blockers:Object.entries(requirements).filter(([,v])=>v!==true).map(([k])=>k),native_gate_schema:'xavi-wg-sfm-application-gate/v1'};
}
function evaluateSfmProposal(evidence){
  const requirements={
    admissionWitnessed:witnessed(evidence?.admissionWitnessDigest),candidateWitnessed:witnessed(evidence?.candidateWitnessDigest),
    evidenceWitnessed:witnessed(evidence?.evidenceWitnessDigest),validationPassed:bool(evidence?.validationPassed),lineageSafe:evidence?.lineageSafe!==false,
  };
  return{requirements,blockers:Object.entries(requirements).filter(([,v])=>v!==true).map(([k])=>k),native_gate_schema:'xavi-wg-sfm-evidence-gate/v1'};
}
function evaluateSrnn(evidence){
  const requirements={
    admissionWitnessed:witnessed(evidence?.admissionWitnessDigest),candidateWitnessed:witnessed(evidence?.candidateWitnessDigest),
    sourceIntegrityVerified:bool(evidence?.sourceIntegrityVerified),rewitnessed:bool(evidence?.rewitnessed),
    resealedOrReledgered:bool(evidence?.resealedOrReledgered),targetSignatureFresh:bool(evidence?.targetSignatureFresh),
    nativeHistoryAppendPrepared:bool(evidence?.nativeHistoryAppendPrepared),lineageSafe:evidence?.lineageSafe!==false,
  };
  return{requirements,blockers:Object.entries(requirements).filter(([,v])=>v!==true).map(([k])=>k),native_gate_schema:'xavi-wg-srnn-reverify-rewitness-reseal-gate/v1'};
}
function gateEvidenceProjection(evidence={}){
  const out={};
  for(const key of ['admissionWitnessDigest','candidateWitnessDigest','outcomeWitnessDigest','evidenceWitnessDigest','candidateDigest']){if(evidence[key]!=null)out[key]=clean(evidence[key]);}
  for(const key of ['temporalCreditAvailable','dependencyCreditAvailable','validationPassed','lineageSafe','targetCompatible','learnedEvidencePreserved','stateDimensionsCompatible','sourceIntegrityVerified','rewitnessed','resealedOrReledgered','targetSignatureFresh','nativeHistoryAppendPrepared']){if(evidence[key]!==undefined)out[key]=Boolean(evidence[key]);}
  return out;
}

export async function evaluateWgStackPortableFamilyGate({admission,evidence={},stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  guard(admission,'portable admission');guard(evidence,'portable gate evidence');
  const admissionVerification=await verifyWgStackPortableFamilyAdmission(admission,{stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:targetRuntime??stage?.target_runtime});
  if(admissionVerification?.verified!==true||admissionVerification?.admission_ready!==true)throw new WGStackPortableGateDecisionError('verified ready family admission is required');
  let evaluated;
  if(admission.family==='rnn')evaluated=evaluateRnn(evidence);
  else if(admission.family==='sfm_snapshot')evaluated=evaluateSfmSnapshot(evidence);
  else if(admission.family==='sfm_proposal')evaluated=evaluateSfmProposal(evidence);
  else if(admission.family==='srnn')evaluated=evaluateSrnn(evidence);
  else throw new WGStackPortableGateDecisionError(`unsupported admitted family ${JSON.stringify(admission.family)}`);
  if(clean(evidence?.candidateDigest)&&clean(evidence.candidateDigest)!==clean(admission.candidate_digest))evaluated.blockers.push('candidateDigest');
  const row={
    schema:WG_STACK_PORTABLE_GATE_DECISION_SCHEMA,profile_id:WG_STACK_PORTABLE_GATE_DECISION_PROFILE,
    admission_digest:admission.admission_digest,stage_digest:admission.stage_digest,family:admission.family,index:admission.index??null,
    candidate_digest:admission.candidate_digest,gate:admission.gate,native_gate_schema:evaluated.native_gate_schema,
    evidence:gateEvidenceProjection(evidence),requirements:evaluated.requirements,blockers:[...new Set(evaluated.blockers)],
    gate_ready:evaluated.blockers.length===0,mutation_authorized:false,application_authorized:false,learning_authorized:false,execution_authorized:false,
    ...WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY,
  };
  row.decision_digest=digestWgStackPortableGateDecision(row);return row;
}

export async function verifyWgStackPortableFamilyGateDecision(decision,options={}){
  try{guard(decision,'portable gate decision');}catch(error){return{schema:WG_STACK_PORTABLE_GATE_DECISION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_GATE_DECISION_PROFILE,decision_digest:clean(decision?.decision_digest)||null,observed_decision_digest:null,identity_matches:false,digest_matches:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY};}
  let observed;try{observed=await evaluateWgStackPortableFamilyGate({...options,admission:options.admission??decision?.admission,evidence:options.evidence??decision?.evidence});}catch(error){return{schema:WG_STACK_PORTABLE_GATE_DECISION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_GATE_DECISION_PROFILE,decision_digest:clean(decision?.decision_digest)||null,observed_decision_digest:null,identity_matches:false,digest_matches:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY};}
  const identityMatches=stringifyWgStackPortableJson(decisionIdentity(decision),{space:0})===stringifyWgStackPortableJson(decisionIdentity(observed),{space:0}),digestMatches=Boolean(decision?.decision_digest&&decision.decision_digest===observed.decision_digest);
  return{schema:WG_STACK_PORTABLE_GATE_DECISION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_GATE_DECISION_PROFILE,decision_digest:clean(decision?.decision_digest)||null,observed_decision_digest:observed.decision_digest,identity_matches:identityMatches,digest_matches:digestMatches,gate_ready:observed.gate_ready===true,verified:identityMatches&&digestMatches,...WG_STACK_PORTABLE_GATE_DECISION_NO_AUTHORITY};
}

export async function witnessWgStackPortableFamilyGateDecision({ledger,...options}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableGateDecisionError('WitnessLedger-compatible ledger is required');
  const decision=await evaluateWgStackPortableFamilyGate(options);const verification=await verifyWgStackPortableFamilyGateDecision(decision,{...options,admission:options.admission,evidence:options.evidence});
  if(verification.verified!==true)throw new WGStackPortableGateDecisionError('verified family gate decision is required before witnessing');
  const witness=await ledger.append('wg-stack-portable-family-gate-decision',{schema:WG_STACK_PORTABLE_GATE_DECISION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_GATE_DECISION_PROFILE,decisionDigest:decision.decision_digest,admissionDigest:decision.admission_digest,stageDigest:decision.stage_digest,family:decision.family,index:decision.index,candidateDigest:decision.candidate_digest,gate:decision.gate,nativeGateSchema:decision.native_gate_schema,gateReady:decision.gate_ready,blockers:decision.blockers,mutationAuthorized:false,applicationAuthorized:false,learningAuthorized:false,executionAuthorized:false,authority:false});
  return{decision,verification,witness,authority:false};
}

export const evaluate_portable_family_gate=evaluateWgStackPortableFamilyGate;
export const digest_portable_family_gate_decision=digestWgStackPortableGateDecision;
export const verify_portable_family_gate_decision=verifyWgStackPortableFamilyGateDecision;
export const witness_portable_family_gate_decision=witnessWgStackPortableFamilyGateDecision;
