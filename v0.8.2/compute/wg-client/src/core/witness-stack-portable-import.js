import { shake256Hex } from './crypto.js';
import { canonicalize } from './utils.js';
import { compareWgStackCapabilityDescriptors, witnessWgStackCapabilityHandshake } from './witness-stack-capability.js';
import { verifyWgStackPortableEnvelope, WG_STACK_PORTABLE_ENVELOPE_PROFILE } from './witness-stack-portable-envelope.js';
import { verifyRnnHandoff, javascriptRnnTeacherProjection, WG_RNN_INTERCHANGE_PROFILE } from './witness-rnn-interchange.js';
import { normalizeSfmSnapshot, sfmTargetCompatibility, WG_SFM_INTERCHANGE_PROFILE } from './witness-sfm-interchange.js';
import { normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeImportRequirements, WG_SRNN_INTERCHANGE_PROFILE } from './witness-srnn-interchange.js';

export const WG_STACK_PORTABLE_IMPORT_SCHEMA='xavi-wg-stack-portable-import-plan/v1';
export const WG_STACK_PORTABLE_IMPORT_PROFILE='WG-STACK-PORTABLE-IMPORT/1';
export const WG_STACK_PORTABLE_IMPORT_VERIFICATION_SCHEMA='xavi-wg-stack-portable-import-plan-verification/v1';
export const WG_STACK_PORTABLE_IMPORT_WITNESS_SCHEMA='xavi-wg-stack-portable-import-plan-witness/v1';
export const WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY=Object.freeze({
  authority:false,truth_authority:false,proof_authority:false,promotion_authority:false,
  learning_authority:false,execution_authority:false,mutation_authority:false,
  self_model_write_authority:false,self_kernel_write_authority:false,
});

export class WGStackPortableImportError extends Error{constructor(message){super(message);this.name='WGStackPortableImportError';}}

const clean=v=>String(v??'').trim();
const bool=v=>v===true;
function authorityGuard(value,where='portable import value',seen=new Set()){
  if(value===null||typeof value!=='object'||seen.has(value))return;
  seen.add(value);
  const forbidden=new Set(['authority','truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority','learning_authority','learningAuthority','execution_authority','executionAuthority','mutation_authority','mutationAuthority','self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority','application_authorized','applicationAuthorized','learning_authorized','learningAuthorized','execution_authorized','executionAuthorized','promotion_authorized','promotionAuthorized']);
  for(const [key,row] of Object.entries(value)){
    if(forbidden.has(key)&&row===true)throw new WGStackPortableImportError(`${where} attempts authority escalation via ${key}`);
    authorityGuard(row,`${where}.${key}`,seen);
  }
}

function has(common,family,cap){return Array.isArray(common?.[family])&&common[family].includes(cap);}
function digest(value){return `shake256-512:${shake256Hex(canonicalize(value),64)}`;}
function planIdentity(plan){
  return{
    schema:plan.schema,profile_id:plan.profile_id,
    envelope:{profile_id:plan.envelope?.profile_id,envelope_digest:plan.envelope?.envelope_digest,stack_fixture_digest:plan.envelope?.stack_fixture_digest},
    handshake:{source_runtime_id:plan.handshake?.source_runtime_id,target_runtime_id:plan.handshake?.target_runtime_id,source_capability_digest:plan.handshake?.source_capability_digest,target_capability_digest:plan.handshake?.target_capability_digest},
    target_runtime:plan.target_runtime,
    families:plan.families,
    ready:plan.ready===true,
    ...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
  };
}
export function digestWgStackPortableImportPlan(plan){return digest(planIdentity(plan));}

export async function planWgStackPortableImport({envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime='javascript'}={}){
  authorityGuard(envelope,'portable envelope');authorityGuard(localDescriptor,'local capability descriptor');authorityGuard(remoteDescriptor,'remote capability descriptor');
  const verification=await verifyWgStackPortableEnvelope(envelope,{localDescriptor,remoteDescriptor,stackManifest,targetRuntime});
  if(verification?.verified!==true)throw new WGStackPortableImportError(`verified portable envelope is required${verification?.verification_error?.message?`: ${verification.verification_error.message}`:''}`);
  const handshake=compareWgStackCapabilityDescriptors(localDescriptor,remoteDescriptor,{stackManifest});
  if(handshake.compatible!==true)throw new WGStackPortableImportError('compatible WG stack capability handshake is required');
  const target=clean(targetRuntime).toLowerCase()==='js'?'javascript':clean(targetRuntime).toLowerCase();
  if(!['javascript','python'].includes(target))throw new WGStackPortableImportError(`unsupported portable import target ${JSON.stringify(targetRuntime)}`);
  const families={rnn:null,sfm_snapshot:null,sfm_proposal:null,srnn:[]};

  if(envelope?.payloads?.rnn!=null){
    const row=verifyRnnHandoff(envelope.payloads.rnn),teacher=target==='javascript'?javascriptRnnTeacherProjection(row):null;
    const required=['portable-state-verify',...(target==='javascript'?['teacher-projection']:[])];
    const capabilities_ready=required.every(cap=>has(handshake.common_capabilities,'rnn',cap));
    families.rnn={
      profile_id:WG_RNN_INTERCHANGE_PROFILE,action:target==='javascript'?'verify-then-teacher-projection-candidate':'verify-reference-only',
      source_state_digest:row.state_digest,required_capabilities:required,capabilities_ready,
      teacher_projection_schema:teacher?.schema??null,teacher_source_state_digest:teacher?.sourceStateDigest??null,
      requires_witness_gate_for_learning:true,native_weights_portable:false,direct_state_overwrite_allowed:false,
      application_authorized:false,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
    };
  }

  if(envelope?.payloads?.sfm_snapshot!=null){
    const canonical=normalizeSfmSnapshot(envelope.payloads.sfm_snapshot),compat=sfmTargetCompatibility(canonical,{target});
    const required=['snapshot-normalize'],capabilities_ready=required.every(cap=>has(handshake.common_capabilities,'sfm',cap));
    families.sfm_snapshot={
      profile_id:WG_SFM_INTERCHANGE_PROFILE,action:'normalize-then-gated-application-candidate',source_state_digest:canonical.state_digest,
      target_schema:compat.target_schema,compatible:compat.compatible===true,unsupported_operations:[...(compat.unsupported_operations??[])],would_drop_learned_evidence:compat.would_drop_learned_evidence===true,
      required_capabilities:required,capabilities_ready,requires_witness_gate_for_application:true,direct_install_allowed:false,
      application_authorized:false,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
    };
  }

  if(envelope?.payloads?.sfm_proposal!=null){
    const required=['proposal-normalize'],capabilities_ready=required.every(cap=>has(handshake.common_capabilities,'sfm',cap));
    families.sfm_proposal={
      profile_id:WG_SFM_INTERCHANGE_PROFILE,action:'normalize-proposal-evidence-only',proposal_digest:clean(envelope?.families?.sfm_proposal?.proposal_digest),
      required_capabilities:required,capabilities_ready,witness_gate_required:true,application_authorized:false,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
    };
  }

  if(Array.isArray(envelope?.payloads?.srnn)){
    const required=['runtime-envelope'],capabilities_ready=required.every(cap=>has(handshake.common_capabilities,'srnn',cap));
    for(let i=0;i<envelope.payloads.srnn.length;i++){
      const row=await normalizeSrnnRuntimeInterchangeRecord(envelope.payloads.srnn[i]),req=await srnnRuntimeImportRequirements(row,{targetRuntime:target});
      families.srnn.push({
        profile_id:WG_SRNN_INTERCHANGE_PROFILE,index:i,action:'reverify-rewitness-reseal-candidate',interchange_digest:row.interchange_digest,
        source_runtime:row.source_runtime,target_runtime:req.target_runtime,same_runtime:req.same_runtime===true,
        native_digest_may_be_reused_as_reference:req.native_digest_may_be_reused_as_reference===true,
        native_digest_may_be_reused_as_target_signature:req.native_digest_may_be_reused_as_target_signature===true,
        must_reverify_source_integrity:req.must_reverify_source_integrity===true,
        must_rewitness_before_native_history:req.must_rewitness_before_native_history===true,
        must_reseal_or_reledger:req.must_reseal_or_reledger===true,
        required_capabilities:required,capabilities_ready,application_authorized:false,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
      });
    }
  }

  const rows=[families.rnn,families.sfm_snapshot,families.sfm_proposal,...families.srnn].filter(Boolean);
  const ready=rows.length>0&&rows.every(row=>row.capabilities_ready===true&&row.compatible!==false&&row.would_drop_learned_evidence!==true&&row.native_digest_may_be_reused_as_target_signature!==true);
  const body={
    schema:WG_STACK_PORTABLE_IMPORT_SCHEMA,profile_id:WG_STACK_PORTABLE_IMPORT_PROFILE,
    envelope:{profile_id:WG_STACK_PORTABLE_ENVELOPE_PROFILE,envelope_digest:clean(envelope.envelope_digest),stack_fixture_digest:clean(envelope?.stack?.fixture_digest)},
    handshake:{source_runtime_id:handshake.remote_runtime_id,target_runtime_id:handshake.local_runtime_id,source_capability_digest:handshake.remote_capability_digest,target_capability_digest:handshake.local_capability_digest},
    target_runtime:target,families,ready,
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY,
  };
  body.plan_digest=digestWgStackPortableImportPlan(body);
  return body;
}

export async function verifyWgStackPortableImportPlan(plan,{envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null}={}){
  authorityGuard(plan,'portable import plan');
  if(!plan||typeof plan!=='object'||Array.isArray(plan))throw new WGStackPortableImportError('portable import plan must be an object');
  const expectedDigest=clean(plan.plan_digest),target=targetRuntime??plan.target_runtime;
  let observed;
  try{observed=await planWgStackPortableImport({envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:target});}
  catch(error){return{schema:WG_STACK_PORTABLE_IMPORT_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_IMPORT_PROFILE,plan_digest:expectedDigest||null,observed_plan_digest:null,identity_matches:false,digest_matches:false,verified:false,verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY};}
  const identityMatches=canonicalize(planIdentity(plan))===canonicalize(planIdentity(observed)),digestMatches=Boolean(expectedDigest&&expectedDigest===observed.plan_digest);
  return{schema:WG_STACK_PORTABLE_IMPORT_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_IMPORT_PROFILE,plan_digest:expectedDigest||null,observed_plan_digest:observed.plan_digest,identity_matches:identityMatches,digest_matches:digestMatches,ready:observed.ready===true,verified:identityMatches&&digestMatches,...WG_STACK_PORTABLE_IMPORT_NO_AUTHORITY};
}

export async function witnessWgStackPortableImportPlan({ledger,envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime='javascript',peerLabel=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableImportError('WitnessLedger-compatible ledger is required');
  const handshakeResult=await witnessWgStackCapabilityHandshake({ledger,localDescriptor,remoteDescriptor,stackManifest,peerLabel});
  if(handshakeResult.handshake?.compatible!==true)throw new WGStackPortableImportError('compatible witnessed capability handshake is required');
  const plan=await planWgStackPortableImport({envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime});
  const verification=await verifyWgStackPortableImportPlan(plan,{envelope,localDescriptor,remoteDescriptor,stackManifest,targetRuntime});
  if(verification.verified!==true)throw new WGStackPortableImportError('verified portable import plan is required before witnessing');
  const witness=await ledger.append('wg-stack-portable-import-plan',{
    schema:WG_STACK_PORTABLE_IMPORT_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_IMPORT_PROFILE,
    handshakeWitnessDigest:handshakeResult.witness.digest,
    planDigest:plan.plan_digest,envelopeDigest:plan.envelope.envelope_digest,stackFixtureDigest:plan.envelope.stack_fixture_digest,
    sourceRuntimeId:plan.handshake.source_runtime_id,targetRuntimeId:plan.handshake.target_runtime_id,
    sourceCapabilityDigest:plan.handshake.source_capability_digest,targetCapabilityDigest:plan.handshake.target_capability_digest,targetRuntime:plan.target_runtime,
    ready:plan.ready===true,
    rnnAction:plan.families.rnn?.action??null,rnnSourceStateDigest:plan.families.rnn?.source_state_digest??null,
    sfmSnapshotAction:plan.families.sfm_snapshot?.action??null,sfmSnapshotSourceStateDigest:plan.families.sfm_snapshot?.source_state_digest??null,
    sfmProposalAction:plan.families.sfm_proposal?.action??null,
    srnnActionCount:plan.families.srnn.length,srnnInterchangeDigests:plan.families.srnn.map(row=>row.interchange_digest),
    applicationAuthorized:false,learningAuthorized:false,executionAuthorized:false,promotionAuthorized:false,authority:false,
  });
  return{handshake:handshakeResult.handshake,handshakeWitness:handshakeResult.witness,plan,verification,witness,authority:false};
}

export const plan_portable_import=planWgStackPortableImport;
export const digest_portable_import_plan=digestWgStackPortableImportPlan;
export const verify_portable_import_plan=verifyWgStackPortableImportPlan;
export const witness_portable_import_plan=witnessWgStackPortableImportPlan;
