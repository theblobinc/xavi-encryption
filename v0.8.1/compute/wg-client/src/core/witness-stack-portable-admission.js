import { shake256Hex } from './crypto.js';
import { stringifyWgStackPortableJson } from './witness-stack-portable-envelope.js';
import { verifyWgStackPortableStage } from './witness-stack-portable-stage.js';

export const WG_STACK_PORTABLE_ADMISSION_SCHEMA='xavi-wg-stack-portable-family-admission/v1';
export const WG_STACK_PORTABLE_ADMISSION_PROFILE='WG-STACK-PORTABLE-ADMISSION/1';
export const WG_STACK_PORTABLE_ADMISSION_VERIFICATION_SCHEMA='xavi-wg-stack-portable-family-admission-verification/v1';
export const WG_STACK_PORTABLE_ADMISSION_WITNESS_SCHEMA='xavi-wg-stack-portable-family-admission-witness/v1';
export const WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY=Object.freeze({
  authority:false,truth_authority:false,proof_authority:false,promotion_authority:false,
  learning_authority:false,execution_authority:false,mutation_authority:false,
  application_authority:false,self_model_write_authority:false,self_kernel_write_authority:false,
});

export class WGStackPortableAdmissionError extends Error{constructor(message){super(message);this.name='WGStackPortableAdmissionError';}}
const clean=v=>String(v??'').trim();
function authorityGuard(value,where='portable admission value',seen=new Set()){
  if(value===null||typeof value!=='object'||seen.has(value))return;seen.add(value);
  const forbidden=new Set(['authority','truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority','learning_authority','learningAuthority','execution_authority','executionAuthority','mutation_authority','mutationAuthority','application_authority','applicationAuthority','application_authorized','applicationAuthorized','apply_authorized','applyAuthorized','install_authorized','installAuthorized','self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority']);
  for(const [key,row] of Object.entries(value)){if(forbidden.has(key)&&row===true)throw new WGStackPortableAdmissionError(`${where} attempts authority escalation via ${key}`);authorityGuard(row,`${where}.${key}`,seen);}
}
function digest(value){return `shake256-512:${shake256Hex(stringifyWgStackPortableJson(value,{space:0}),64)}`;}
function selectFamily(stage,family,index=0){
  const name=clean(family).toLowerCase();
  if(name==='rnn')return{name,row:stage?.families?.rnn,index:null};
  if(name==='sfm_snapshot'||name==='sfm-snapshot')return{name:'sfm_snapshot',row:stage?.families?.sfm_snapshot,index:null};
  if(name==='sfm_proposal'||name==='sfm-proposal')return{name:'sfm_proposal',row:stage?.families?.sfm_proposal,index:null};
  if(name==='srnn'){const i=Number(index);if(!Number.isInteger(i)||i<0)throw new WGStackPortableAdmissionError('SRNN admission index must be a non-negative integer');return{name,row:stage?.families?.srnn?.[i]??null,index:i};}
  throw new WGStackPortableAdmissionError(`unsupported portable admission family ${JSON.stringify(family)}`);
}
function rules(selected,targetRuntime){
  const {name,row}=selected,blockers=[];let gate;
  if(!row)blockers.push('staged-family-candidate-missing');
  if(row?.staged!==true)blockers.push('candidate-not-staged');
  if(row?.application_authorized===true||row?.authority===true)blockers.push('candidate-authority-escalation');
  if(name==='rnn'){
    gate=row?.candidate==null?'rnn-reference-verification-gate':'rnn-witness-learning-gate';
    if(row?.candidate!=null&&row?.requirements?.requires_witness_gate_for_learning!==true)blockers.push('rnn-learning-gate-not-required');
    if(row?.requirements?.direct_state_overwrite_allowed!==false)blockers.push('rnn-direct-state-overwrite-not-forbidden');
  }else if(name==='sfm_snapshot'){
    gate='sfm-witness-application-gate';
    if(row?.candidate==null)blockers.push('sfm-target-candidate-missing');
    if(row?.requirements?.requires_witness_gate_for_application!==true)blockers.push('sfm-application-gate-not-required');
    if(row?.requirements?.direct_install_allowed!==false)blockers.push('sfm-direct-install-not-forbidden');
    if(row?.requirements?.would_drop_learned_evidence===true)blockers.push('sfm-would-drop-learned-evidence');
  }else if(name==='sfm_proposal'){
    gate='sfm-evidence-witness-gate';
    if(row?.candidate==null)blockers.push('sfm-proposal-candidate-missing');
    if(row?.requirements?.evidence_only!==true)blockers.push('sfm-proposal-not-evidence-only');
    if(row?.requirements?.witness_gate_required!==true)blockers.push('sfm-proposal-witness-gate-not-required');
  }else if(name==='srnn'){
    gate='srnn-reverify-rewitness-reseal-gate';
    if(row?.candidate==null)blockers.push('srnn-source-reference-missing');
    if(row?.requirements?.must_rewitness_before_native_history!==true)blockers.push('srnn-rewitness-not-required');
    if(row?.requirements?.must_reseal_or_reledger!==true)blockers.push('srnn-reseal-not-required');
    if(row?.requirements?.native_digest_may_be_reused_as_target_signature!==false)blockers.push('srnn-target-signature-reuse-not-forbidden');
    if(row?.requirements?.direct_history_import_allowed!==false)blockers.push('srnn-direct-history-import-not-forbidden');
  }
  return{gate,blockers,target_runtime:targetRuntime};
}
function identity(row){return{schema:row.schema,profile_id:row.profile_id,stage_digest:row.stage_digest,plan_digest:row.plan_digest,envelope_digest:row.envelope_digest,family:row.family,index:row.index??null,target_runtime:row.target_runtime,candidate_digest:row.candidate_digest,gate:row.gate,requirements:row.requirements,admission_ready:row.admission_ready===true,application_authorized:false,...WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY};}
export function digestWgStackPortableFamilyAdmission(row){return digest(identity(row));}

export async function assessWgStackPortableFamilyAdmission({stage,family,index=0,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  authorityGuard(stage,'portable stage');
  const stageVerification=await verifyWgStackPortableStage(stage,{envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:targetRuntime??stage?.target_runtime});
  if(stageVerification?.verified!==true||stageVerification?.ready_for_family_gates!==true)throw new WGStackPortableAdmissionError('verified portable stage ready for family gates is required');
  const selected=selectFamily(stage,family,index);const rule=rules(selected,stage.target_runtime);
  const body={schema:WG_STACK_PORTABLE_ADMISSION_SCHEMA,profile_id:WG_STACK_PORTABLE_ADMISSION_PROFILE,stage_digest:stage.stage_digest,plan_digest:stage.plan_digest,envelope_digest:stage.envelope_digest,family:selected.name,index:selected.index,target_runtime:stage.target_runtime,candidate_digest:selected.row?.candidate_digest??null,gate:rule.gate,requirements:selected.row?.requirements??null,blockers:rule.blockers,admission_ready:rule.blockers.length===0,application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY};
  body.admission_digest=digestWgStackPortableFamilyAdmission(body);return body;
}

export async function verifyWgStackPortableFamilyAdmission(admission,options={}){
  try{authorityGuard(admission,'portable admission');}catch(error){return{schema:WG_STACK_PORTABLE_ADMISSION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_ADMISSION_PROFILE,admission_digest:clean(admission?.admission_digest)||null,observed_admission_digest:null,identity_matches:false,digest_matches:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY};}
  let observed;try{observed=await assessWgStackPortableFamilyAdmission({...options,family:admission?.family,index:admission?.index??0});}catch(error){return{schema:WG_STACK_PORTABLE_ADMISSION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_ADMISSION_PROFILE,admission_digest:clean(admission?.admission_digest)||null,observed_admission_digest:null,identity_matches:false,digest_matches:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY};}
  const identityMatches=stringifyWgStackPortableJson(identity(admission),{space:0})===stringifyWgStackPortableJson(identity(observed),{space:0});const digestMatches=Boolean(admission?.admission_digest&&admission.admission_digest===observed.admission_digest);
  return{schema:WG_STACK_PORTABLE_ADMISSION_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_ADMISSION_PROFILE,admission_digest:clean(admission?.admission_digest)||null,observed_admission_digest:observed.admission_digest,identity_matches:identityMatches,digest_matches:digestMatches,admission_ready:observed.admission_ready===true,verified:identityMatches&&digestMatches&&observed.admission_ready===true,...WG_STACK_PORTABLE_ADMISSION_NO_AUTHORITY};
}

export async function witnessWgStackPortableFamilyAdmission({ledger,...options}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableAdmissionError('WitnessLedger-compatible ledger is required');
  const admission=await assessWgStackPortableFamilyAdmission(options);if(admission.admission_ready!==true)throw new WGStackPortableAdmissionError(`family admission is not ready: ${admission.blockers.join(', ')}`);
  const verification=await verifyWgStackPortableFamilyAdmission(admission,options);if(verification.verified!==true)throw new WGStackPortableAdmissionError('verified family admission is required before witnessing');
  const witness=await ledger.append('wg-stack-portable-family-admission',{schema:WG_STACK_PORTABLE_ADMISSION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_ADMISSION_PROFILE,stageDigest:admission.stage_digest,planDigest:admission.plan_digest,envelopeDigest:admission.envelope_digest,admissionDigest:admission.admission_digest,family:admission.family,index:admission.index,candidateDigest:admission.candidate_digest,gate:admission.gate,admissionReady:true,applicationAuthorized:false,learningAuthorized:false,executionAuthorized:false,promotionAuthorized:false,authority:false});
  return{admission,verification,witness,authority:false};
}

export const assess_portable_family_admission=assessWgStackPortableFamilyAdmission;
export const digest_portable_family_admission=digestWgStackPortableFamilyAdmission;
export const verify_portable_family_admission=verifyWgStackPortableFamilyAdmission;
export const witness_portable_family_admission=witnessWgStackPortableFamilyAdmission;
