import { shake256Hex } from './crypto.js';
import { stringifyWgStackPortableJson, verifyWgStackPortableEnvelope } from './witness-stack-portable-envelope.js';
import { verifyWgStackPortableImportPlan, WG_STACK_PORTABLE_IMPORT_PROFILE } from './witness-stack-portable-import.js';
import { verifyRnnHandoff, javascriptRnnTeacherProjection, WG_RNN_INTERCHANGE_PROFILE } from './witness-rnn-interchange.js';
import { normalizeSfmSnapshot, normalizeSfmProposal, sfmTargetCompatibility, toJsSfmSnapshot, toPythonSfmSnapshot, WG_SFM_INTERCHANGE_PROFILE } from './witness-sfm-interchange.js';
import { normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeImportRequirements, WG_SRNN_INTERCHANGE_PROFILE } from './witness-srnn-interchange.js';

export const WG_STACK_PORTABLE_STAGE_SCHEMA='xavi-wg-stack-portable-import-stage/v1';
export const WG_STACK_PORTABLE_STAGE_PROFILE='WG-STACK-PORTABLE-STAGE/1';
export const WG_STACK_PORTABLE_STAGE_VERIFICATION_SCHEMA='xavi-wg-stack-portable-import-stage-verification/v1';
export const WG_STACK_PORTABLE_STAGE_WITNESS_SCHEMA='xavi-wg-stack-portable-import-stage-witness/v1';
export const WG_STACK_PORTABLE_STAGE_NO_AUTHORITY=Object.freeze({
  authority:false,truth_authority:false,proof_authority:false,promotion_authority:false,
  learning_authority:false,execution_authority:false,mutation_authority:false,
  self_model_write_authority:false,self_kernel_write_authority:false,
});

export class WGStackPortableStageError extends Error{constructor(message){super(message);this.name='WGStackPortableStageError';}}

const clean=v=>String(v??'').trim();
function authorityGuard(value,where='portable stage value',seen=new Set()){
  if(value===null||typeof value!=='object'||seen.has(value))return;
  seen.add(value);
  const forbidden=new Set([
    'authority','truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority',
    'learning_authority','learningAuthority','execution_authority','executionAuthority','mutation_authority','mutationAuthority',
    'self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority',
    'application_authorized','applicationAuthorized','learning_authorized','learningAuthorized','execution_authorized','executionAuthorized',
    'promotion_authorized','promotionAuthorized','install_authorized','installAuthorized','apply_authorized','applyAuthorized',
  ]);
  for(const [key,row] of Object.entries(value)){
    if(forbidden.has(key)&&row===true)throw new WGStackPortableStageError(`${where} attempts authority escalation via ${key}`);
    authorityGuard(row,`${where}.${key}`,seen);
  }
}
function portableDigest(value){return `shake256-512:${shake256Hex(stringifyWgStackPortableJson(value,{space:0}),64)}`;}
function portableBytes(value){return new TextEncoder().encode(stringifyWgStackPortableJson(value,{space:0})).length;}
function candidateRecord(candidate,extra={}){
  if(candidate==null)return{candidate:null,candidate_digest:null,candidate_bytes:0,...extra,...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY};
  authorityGuard(candidate,'staged candidate');
  return{candidate,candidate_digest:portableDigest(candidate),candidate_bytes:portableBytes(candidate),...extra,...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY};
}
function familyIdentity(row){
  if(!row)return null;
  if(Array.isArray(row))return row.map(familyIdentity);
  return{
    profile_id:row.profile_id??null,mode:row.mode??null,source_digest:row.source_digest??null,
    candidate_digest:row.candidate_digest??null,candidate_bytes:Number(row.candidate_bytes??0),
    target_schema:row.target_schema??null,requirements:row.requirements??null,
    source_runtime:row.source_runtime??null,target_runtime:row.target_runtime??null,index:row.index??null,
    staged:row.staged===true,application_authorized:false,...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY,
  };
}
function stageIdentity(stage){
  return{
    schema:stage.schema,profile_id:stage.profile_id,
    envelope_digest:stage.envelope_digest,plan_digest:stage.plan_digest,stack_fixture_digest:stage.stack_fixture_digest,
    handshake:stage.handshake,target_runtime:stage.target_runtime,
    families:{
      rnn:familyIdentity(stage.families?.rnn),sfm_snapshot:familyIdentity(stage.families?.sfm_snapshot),
      sfm_proposal:familyIdentity(stage.families?.sfm_proposal),srnn:familyIdentity(stage.families?.srnn??[]),
    },
    staged:stage.staged===true,ready_for_family_gates:stage.ready_for_family_gates===true,
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,
    ...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY,
  };
}
export function digestWgStackPortableStage(stage){return portableDigest(stageIdentity(stage));}

function assertCandidateDigests(stage){
  const rows=[stage?.families?.rnn,stage?.families?.sfm_snapshot,stage?.families?.sfm_proposal,...(Array.isArray(stage?.families?.srnn)?stage.families.srnn:[])].filter(Boolean);
  for(const row of rows){
    if(row.candidate==null){if(row.candidate_digest!=null||Number(row.candidate_bytes??0)!==0)throw new WGStackPortableStageError('null staged candidate has non-null digest or bytes');continue;}
    const observed=portableDigest(row.candidate),bytes=portableBytes(row.candidate);
    if(clean(row.candidate_digest)!==observed)throw new WGStackPortableStageError(`staged candidate digest mismatch for ${row.profile_id??'family'}`);
    if(Number(row.candidate_bytes)!==bytes)throw new WGStackPortableStageError(`staged candidate byte length mismatch for ${row.profile_id??'family'}`);
  }
}

export async function stageWgStackPortableImport({envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  authorityGuard(envelope,'portable envelope');authorityGuard(plan,'portable import plan');
  const target=clean(targetRuntime??plan?.target_runtime).toLowerCase()==='js'?'javascript':clean(targetRuntime??plan?.target_runtime).toLowerCase();
  if(!['javascript','python'].includes(target))throw new WGStackPortableStageError(`unsupported portable stage target ${JSON.stringify(targetRuntime??plan?.target_runtime)}`);
  const envelopeVerification=await verifyWgStackPortableEnvelope(envelope,{localDescriptor,remoteDescriptor,stackManifest,targetRuntime:target});
  if(envelopeVerification?.verified!==true)throw new WGStackPortableStageError(`verified portable envelope is required${envelopeVerification?.verification_error?.message?`: ${envelopeVerification.verification_error.message}`:''}`);
  const planVerification=await verifyWgStackPortableImportPlan(plan,{envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:target});
  if(planVerification?.verified!==true||planVerification?.ready!==true||plan?.ready!==true)throw new WGStackPortableStageError('verified ready portable import plan is required before staging');
  if(clean(plan?.profile_id)!==WG_STACK_PORTABLE_IMPORT_PROFILE)throw new WGStackPortableStageError('portable import profile mismatch');

  const families={rnn:null,sfm_snapshot:null,sfm_proposal:null,srnn:[]};
  if(envelope?.payloads?.rnn!=null){
    const source=verifyRnnHandoff(envelope.payloads.rnn),candidate=target==='javascript'?javascriptRnnTeacherProjection(source):null;
    families.rnn=candidateRecord(candidate,{
      profile_id:WG_RNN_INTERCHANGE_PROFILE,mode:target==='javascript'?'teacher-projection-candidate':'verified-reference-only',
      source_digest:source.state_digest,target_schema:candidate?.schema??null,staged:true,
      requirements:{requires_witness_gate_for_learning:true,native_weights_portable:false,direct_state_overwrite_allowed:false},
      application_authorized:false,
    });
  }
  if(envelope?.payloads?.sfm_snapshot!=null){
    const canonical=normalizeSfmSnapshot(envelope.payloads.sfm_snapshot),compat=sfmTargetCompatibility(canonical,{target});
    if(compat.compatible!==true||compat.would_drop_learned_evidence===true)throw new WGStackPortableStageError('WG-SFM staged target would lose learned evidence');
    const candidate=target==='javascript'?toJsSfmSnapshot(canonical,{strict:true,target}):toPythonSfmSnapshot(canonical);
    families.sfm_snapshot=candidateRecord(candidate,{
      profile_id:WG_SFM_INTERCHANGE_PROFILE,mode:'normalized-gated-application-candidate',source_digest:canonical.state_digest,
      target_schema:compat.target_schema,staged:true,
      requirements:{requires_witness_gate_for_application:true,direct_install_allowed:false,would_drop_learned_evidence:false},
      application_authorized:false,
    });
  }
  if(envelope?.payloads?.sfm_proposal!=null){
    const candidate=normalizeSfmProposal(envelope.payloads.sfm_proposal);
    families.sfm_proposal=candidateRecord(candidate,{
      profile_id:WG_SFM_INTERCHANGE_PROFILE,mode:'normalized-proposal-evidence-only',source_digest:clean(plan?.families?.sfm_proposal?.proposal_digest),
      target_schema:candidate?.schema??null,staged:true,requirements:{witness_gate_required:true,evidence_only:true},application_authorized:false,
    });
  }
  if(Array.isArray(envelope?.payloads?.srnn)){
    for(let i=0;i<envelope.payloads.srnn.length;i++){
      const candidate=await normalizeSrnnRuntimeInterchangeRecord(envelope.payloads.srnn[i]),req=await srnnRuntimeImportRequirements(candidate,{targetRuntime:target});
      families.srnn.push(candidateRecord(candidate,{
        profile_id:WG_SRNN_INTERCHANGE_PROFILE,index:i,mode:'verified-source-reference-reverify-rewitness-reseal',source_digest:candidate.interchange_digest,
        source_runtime:candidate.source_runtime,target_runtime:req.target_runtime,target_schema:candidate.schema??null,staged:true,
        requirements:{
          must_reverify_source_integrity:req.must_reverify_source_integrity===true,
          must_rewitness_before_native_history:req.must_rewitness_before_native_history===true,
          must_reseal_or_reledger:req.must_reseal_or_reledger===true,
          native_digest_may_be_reused_as_reference:req.native_digest_may_be_reused_as_reference===true,
          native_digest_may_be_reused_as_target_signature:false,
          direct_history_import_allowed:false,
        },
        application_authorized:false,
      }));
    }
  }
  const body={
    schema:WG_STACK_PORTABLE_STAGE_SCHEMA,profile_id:WG_STACK_PORTABLE_STAGE_PROFILE,
    envelope_digest:clean(envelope.envelope_digest),plan_digest:clean(plan.plan_digest),stack_fixture_digest:clean(plan?.envelope?.stack_fixture_digest),
    handshake:{...plan.handshake},target_runtime:target,families,staged:true,ready_for_family_gates:true,
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,
    ...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY,
  };
  body.stage_digest=digestWgStackPortableStage(body);
  return body;
}

export async function verifyWgStackPortableStage(stage,{envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  try{authorityGuard(stage,'portable stage');assertCandidateDigests(stage);}catch(error){return{schema:WG_STACK_PORTABLE_STAGE_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_STAGE_PROFILE,stage_digest:clean(stage?.stage_digest)||null,observed_stage_digest:null,identity_matches:false,digest_matches:false,candidates_match:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY};}
  if(!stage||typeof stage!=='object'||Array.isArray(stage))throw new WGStackPortableStageError('portable stage must be an object');
  let observed;
  try{observed=await stageWgStackPortableImport({envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:targetRuntime??stage.target_runtime});}
  catch(error){return{schema:WG_STACK_PORTABLE_STAGE_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_STAGE_PROFILE,stage_digest:clean(stage.stage_digest)||null,observed_stage_digest:null,identity_matches:false,digest_matches:false,candidates_match:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY};}
  let candidatesMatch=true;
  for(const key of ['rnn','sfm_snapshot','sfm_proposal']){
    const a=stage.families?.[key],b=observed.families?.[key];if(Boolean(a)!==Boolean(b)||(a&&b&&a.candidate_digest!==b.candidate_digest))candidatesMatch=false;
  }
  const aa=Array.isArray(stage.families?.srnn)?stage.families.srnn:[],bb=Array.isArray(observed.families?.srnn)?observed.families.srnn:[];
  if(aa.length!==bb.length||aa.some((row,i)=>row.candidate_digest!==bb[i]?.candidate_digest))candidatesMatch=false;
  const identityMatches=stringifyWgStackPortableJson(stageIdentity(stage),{space:0})===stringifyWgStackPortableJson(stageIdentity(observed),{space:0});
  const digestMatches=Boolean(stage.stage_digest&&stage.stage_digest===observed.stage_digest);
  return{schema:WG_STACK_PORTABLE_STAGE_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_STAGE_PROFILE,stage_digest:clean(stage.stage_digest)||null,observed_stage_digest:observed.stage_digest,identity_matches:identityMatches,digest_matches:digestMatches,candidates_match:candidatesMatch,ready_for_family_gates:observed.ready_for_family_gates===true,verified:identityMatches&&digestMatches&&candidatesMatch,...WG_STACK_PORTABLE_STAGE_NO_AUTHORITY};
}

export async function witnessWgStackPortableStage({ledger,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableStageError('WitnessLedger-compatible ledger is required');
  const stage=await stageWgStackPortableImport({envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime});
  const verification=await verifyWgStackPortableStage(stage,{envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime});
  if(verification.verified!==true)throw new WGStackPortableStageError('verified portable stage is required before witnessing');
  const witness=await ledger.append('wg-stack-portable-import-stage',{
    schema:WG_STACK_PORTABLE_STAGE_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STAGE_PROFILE,
    stageDigest:stage.stage_digest,planDigest:stage.plan_digest,envelopeDigest:stage.envelope_digest,stackFixtureDigest:stage.stack_fixture_digest,
    sourceRuntimeId:stage.handshake?.source_runtime_id??null,targetRuntimeId:stage.handshake?.target_runtime_id??null,targetRuntime:stage.target_runtime,
    rnnCandidateDigest:stage.families.rnn?.candidate_digest??null,sfmSnapshotCandidateDigest:stage.families.sfm_snapshot?.candidate_digest??null,
    sfmProposalCandidateDigest:stage.families.sfm_proposal?.candidate_digest??null,srnnCandidateDigests:stage.families.srnn.map(row=>row.candidate_digest),
    readyForFamilyGates:stage.ready_for_family_gates===true,applicationAuthorized:false,learningAuthorized:false,executionAuthorized:false,promotionAuthorized:false,authority:false,
  });
  return{stage,verification,witness,authority:false};
}

export const stage_portable_import=stageWgStackPortableImport;
export const digest_portable_import_stage=digestWgStackPortableStage;
export const verify_portable_import_stage=verifyWgStackPortableStage;
export const witness_portable_import_stage=witnessWgStackPortableStage;
