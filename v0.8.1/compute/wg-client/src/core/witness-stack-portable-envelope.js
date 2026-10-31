import { shake256Hex } from './crypto.js';
import { canonicalize } from './utils.js';
import { verifyRnnHandoff, WG_RNN_INTERCHANGE_PROFILE } from './witness-rnn-interchange.js';
import { normalizeSfmSnapshot, normalizeSfmProposal, digestSfmInterchangeValue, WG_SFM_INTERCHANGE_PROFILE } from './witness-sfm-interchange.js';
import { normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeImportRequirements, WG_SRNN_INTERCHANGE_PROFILE } from './witness-srnn-interchange.js';
import { compareWgStackCapabilityDescriptors, WG_STACK_CAPABILITY_PROFILE } from './witness-stack-capability.js';
import { WG_STACK_INTERCHANGE_PROFILE, WG_STACK_NO_AUTHORITY } from './witness-stack-interchange.js';

export const WG_STACK_PORTABLE_ENVELOPE_SCHEMA='xavi-wg-stack-portable-envelope/v1';
export const WG_STACK_PORTABLE_ENVELOPE_PROFILE='WG-STACK-PORTABLE-ENVELOPE/1';
export const WG_STACK_PORTABLE_ENVELOPE_VERIFICATION_SCHEMA='xavi-wg-stack-portable-envelope-verification/v1';

export class WGStackPortableEnvelopeError extends Error{
  constructor(message){super(message);this.name='WGStackPortableEnvelopeError';}
}

function requiredString(value,name){const row=String(value??'').trim();if(!row)throw new WGStackPortableEnvelopeError(`${name} is required`);return row;}
function authorityGuard(value,path='portable envelope'){
  if(!value||typeof value!=='object')return;
  for(const [key,row] of Object.entries(value)){
    if((key==='authority'||key.endsWith('_authority')||key.endsWith('Authority'))&&row===true)throw new WGStackPortableEnvelopeError(`${path} attempts authority escalation via ${key}`);
    if(row&&typeof row==='object')authorityGuard(row,`${path}.${key}`);
  }
}
function requireCommon(handshake,family,capability){
  if(!(handshake.common_capabilities?.[family]||[]).includes(capability))throw new WGStackPortableEnvelopeError(`missing negotiated ${family} capability ${capability}`);
}
function compactImportRequirements(row){
  if(!row)return null;
  return{
    schema:String(row.schema??''),source_runtime:String(row.source_runtime??''),target_runtime:String(row.target_runtime??''),same_runtime:row.same_runtime===true,
    native_digest_may_be_reused_as_reference:row.native_digest_may_be_reused_as_reference===true,
    native_digest_may_be_reused_as_target_signature:row.native_digest_may_be_reused_as_target_signature===true,
    must_reverify_source_integrity:row.must_reverify_source_integrity===true,
    must_rewitness_before_native_history:row.must_rewitness_before_native_history===true,
    must_reseal_or_reledger:row.must_reseal_or_reledger===true,
    may_grant_authority:false,authority:false,
  };
}
function identityProjection(value){
  return{
    schema:requiredString(value.schema,'schema'),profile_id:requiredString(value.profile_id,'profile_id'),
    stack:{profile_id:requiredString(value.stack?.profile_id,'stack.profile_id'),fixture_digest:requiredString(value.stack?.fixture_digest,'stack.fixture_digest')},
    source:{runtime_id:requiredString(value.source?.runtime_id,'source.runtime_id'),capability_digest:requiredString(value.source?.capability_digest,'source.capability_digest')},
    target:{runtime_id:requiredString(value.target?.runtime_id,'target.runtime_id'),capability_digest:requiredString(value.target?.capability_digest,'target.capability_digest')},
    families:{
      rnn:value.families?.rnn?{profile_id:WG_RNN_INTERCHANGE_PROFILE,state_digest:requiredString(value.families.rnn.state_digest,'families.rnn.state_digest')}:null,
      sfm_snapshot:value.families?.sfm_snapshot?{profile_id:WG_SFM_INTERCHANGE_PROFILE,state_digest:requiredString(value.families.sfm_snapshot.state_digest,'families.sfm_snapshot.state_digest')}:null,
      sfm_proposal:value.families?.sfm_proposal?{profile_id:WG_SFM_INTERCHANGE_PROFILE,proposal_digest:requiredString(value.families.sfm_proposal.proposal_digest,'families.sfm_proposal.proposal_digest')}:null,
      srnn:Array.isArray(value.families?.srnn)?value.families.srnn.map(row=>({profile_id:WG_SRNN_INTERCHANGE_PROFILE,interchange_digest:requiredString(row.interchange_digest,'families.srnn.interchange_digest'),import_requirements:compactImportRequirements(row.import_requirements)})):[],
    },
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_NO_AUTHORITY,
  };
}


function renderPortableJson(value,space=2,depth=0){
  if(value===null)return'null';
  if(typeof value==='boolean'||typeof value==='string')return JSON.stringify(value);
  if(typeof value==='number'){
    if(!Number.isFinite(value))throw new WGStackPortableEnvelopeError('portable JSON requires finite numbers');
    return Object.is(value,-0)?'-0.0':JSON.stringify(value);
  }
  const width=Math.max(0,Math.min(10,Math.trunc(Number(space)||0))),gap=' '.repeat(width),pad=gap.repeat(depth),next=gap.repeat(depth+1);
  if(Array.isArray(value)){
    if(!value.length)return'[]';
    const rows=value.map(row=>renderPortableJson(row,width,depth+1));
    return width?`[
${next}${rows.join(`,
${next}`)}
${pad}]`:`[${rows.join(',')}]`;
  }
  if(!value||typeof value!=='object')throw new WGStackPortableEnvelopeError(`unsupported portable JSON value ${typeof value}`);
  const entries=Object.entries(value);
  if(!entries.length)return'{}';
  const rows=entries.map(([key,row])=>`${JSON.stringify(key)}:${width?' ':''}${renderPortableJson(row,width,depth+1)}`);
  return width?`{
${next}${rows.join(`,
${next}`)}
${pad}}`:`{${rows.join(',')}}`;
}

export function stringifyWgStackPortableJson(value,{space=2}={}){authorityGuard(value,'portable JSON');return renderPortableJson(value,space,0)+(Number(space)>0?'\n':'');}
export function parseWgStackPortableJson(text){if(typeof text!=='string')throw new WGStackPortableEnvelopeError('portable JSON text is required');const value=JSON.parse(text);authorityGuard(value,'portable JSON');return value;}

export function digestWgStackPortableEnvelope(value){return `shake256-512:${shake256Hex(canonicalize(identityProjection(value)),64)}`;}

export async function projectWgStackPortableEnvelope({localDescriptor,remoteDescriptor,stackManifest,payloads,targetRuntime='javascript'}={}){
  authorityGuard(payloads,'portable payloads');
  const handshake=compareWgStackCapabilityDescriptors(localDescriptor,remoteDescriptor,{stackManifest});
  if(!handshake.compatible)throw new WGStackPortableEnvelopeError('compatible WG stack capability handshake is required');
  const body={
    schema:WG_STACK_PORTABLE_ENVELOPE_SCHEMA,profile_id:WG_STACK_PORTABLE_ENVELOPE_PROFILE,
    stack:{profile_id:WG_STACK_INTERCHANGE_PROFILE,fixture_digest:requiredString(stackManifest?.stack_manifest_digest,'stackManifest.stack_manifest_digest')},
    source:{runtime_id:handshake.remote_runtime_id,capability_digest:handshake.remote_capability_digest},
    target:{runtime_id:handshake.local_runtime_id,capability_digest:handshake.local_capability_digest},
    families:{rnn:null,sfm_snapshot:null,sfm_proposal:null,srnn:[]},
    payloads:{rnn:null,sfm_snapshot:null,sfm_proposal:null,srnn:[]},
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_NO_AUTHORITY,
  };
  if(payloads?.rnn!=null){requireCommon(handshake,'rnn','portable-state-verify');const row=verifyRnnHandoff(payloads.rnn);body.payloads.rnn=structuredClone(payloads.rnn);body.families.rnn={profile_id:WG_RNN_INTERCHANGE_PROFILE,state_digest:row.state_digest};}
  if(payloads?.sfm_snapshot!=null){requireCommon(handshake,'sfm','snapshot-normalize');const row=normalizeSfmSnapshot(payloads.sfm_snapshot);body.payloads.sfm_snapshot=structuredClone(payloads.sfm_snapshot);body.families.sfm_snapshot={profile_id:WG_SFM_INTERCHANGE_PROFILE,state_digest:row.state_digest||digestSfmInterchangeValue(row)};}
  if(payloads?.sfm_proposal!=null){requireCommon(handshake,'sfm','proposal-normalize');const row=normalizeSfmProposal(payloads.sfm_proposal);body.payloads.sfm_proposal=structuredClone(payloads.sfm_proposal);body.families.sfm_proposal={profile_id:WG_SFM_INTERCHANGE_PROFILE,proposal_digest:digestSfmInterchangeValue(row)};}
  if(Array.isArray(payloads?.srnn)){
    requireCommon(handshake,'srnn','runtime-envelope');
    for(const raw of payloads.srnn){const row=await normalizeSrnnRuntimeInterchangeRecord(raw);const req=await srnnRuntimeImportRequirements(row,{targetRuntime});if(req.may_grant_authority===true)throw new WGStackPortableEnvelopeError('SRNN import requirements may not grant authority');body.payloads.srnn.push(structuredClone(raw));body.families.srnn.push({profile_id:WG_SRNN_INTERCHANGE_PROFILE,interchange_digest:row.interchange_digest,import_requirements:compactImportRequirements(req)});}
  }
  const count=(body.families.rnn?1:0)+(body.families.sfm_snapshot?1:0)+(body.families.sfm_proposal?1:0)+body.families.srnn.length;
  if(count===0)throw new WGStackPortableEnvelopeError('portable envelope requires at least one family payload');
  body.payload_count=count;
  body.envelope_digest=digestWgStackPortableEnvelope(body);
  return body;
}

export async function verifyWgStackPortableEnvelope(envelope,{localDescriptor,remoteDescriptor,stackManifest,targetRuntime='javascript'}={}){
  authorityGuard(envelope);
  if(!envelope||typeof envelope!=='object'||Array.isArray(envelope))throw new WGStackPortableEnvelopeError('portable envelope must be an object');
  const expectedDigest=requiredString(envelope.envelope_digest,'envelope_digest');
  const expectedIdentity=identityProjection(envelope);
  let observed;
  try{observed=await projectWgStackPortableEnvelope({localDescriptor,remoteDescriptor,stackManifest,payloads:envelope.payloads,targetRuntime});}
  catch(error){
    return{
      schema:WG_STACK_PORTABLE_ENVELOPE_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_ENVELOPE_PROFILE,
      envelope_digest:expectedDigest,observed_envelope_digest:null,
      stack_matches:expectedIdentity.stack.fixture_digest===stackManifest?.stack_manifest_digest,
      source_capability_matches:false,target_capability_matches:false,family_identities_match:false,
      payload_count:Number(envelope.payload_count??0),verified:false,
      verification_error:{name:String(error?.name??'Error'),message:String(error?.message??error)},
      application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_NO_AUTHORITY,
    };
  }
  const observedIdentity=identityProjection(observed);
  const identityMatches=canonicalize(expectedIdentity)===canonicalize(observedIdentity);
  const observedDigest=digestWgStackPortableEnvelope(observed);
  const digestMatches=expectedDigest===observedDigest;
  return{
    schema:WG_STACK_PORTABLE_ENVELOPE_VERIFICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_ENVELOPE_PROFILE,
    envelope_digest:expectedDigest,observed_envelope_digest:observedDigest,
    stack_matches:expectedIdentity.stack.fixture_digest===stackManifest.stack_manifest_digest,
    source_capability_matches:expectedIdentity.source.capability_digest===observedIdentity.source.capability_digest,
    target_capability_matches:expectedIdentity.target.capability_digest===observedIdentity.target.capability_digest,
    family_identities_match:identityMatches,
    payload_count:observed.payload_count,
    verified:identityMatches&&digestMatches,
    application_authorized:false,learning_authorized:false,execution_authorized:false,promotion_authorized:false,...WG_STACK_NO_AUTHORITY,
  };
}

export const project_portable_envelope=projectWgStackPortableEnvelope;
export const digest_portable_envelope=digestWgStackPortableEnvelope;
export const verify_portable_envelope=verifyWgStackPortableEnvelope;
