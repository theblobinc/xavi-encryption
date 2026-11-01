import { shake256Hex } from './crypto.js';
import { canonicalize } from './utils.js';
import { verifyRnnInterchangeFixtureManifest, WG_RNN_INTERCHANGE_PROFILE } from './witness-rnn-interchange.js';
import { verifySfmInterchangeFixtureManifest, WG_SFM_INTERCHANGE_PROFILE } from './witness-sfm-interchange.js';
import { verifySrnnInterchangeFixtureManifest, WG_SRNN_INTERCHANGE_PROFILE } from './witness-srnn-interchange.js';

export const WG_STACK_INTERCHANGE_SCHEMA='xavi-wg-stack-interchange-manifest/v1';
export const WG_STACK_INTERCHANGE_PROFILE='WG-STACK-INTERCHANGE/1';
export const WG_STACK_INTERCHANGE_VERIFICATION_SCHEMA='xavi-wg-stack-interchange-manifest-verification/v1';
export const WG_STACK_PARITY_CONTRACT_SCHEMA='xavi-wg-stack-parity-contract/v1';
export const WG_STACK_NO_AUTHORITY=Object.freeze({
  authority:false,
  truth_authority:false,
  proof_authority:false,
  promotion_authority:false,
  learning_authority:false,
  execution_authority:false,
  mutation_authority:false,
  self_model_write_authority:false,
  self_kernel_write_authority:false,
});

export class WGStackInterchangeError extends Error{
  constructor(message){super(message);this.name='WGStackInterchangeError';}
}

function authorityGuard(value,path='stack manifest'){
  if(!value||typeof value!=='object')return;
  for(const [key,row] of Object.entries(value)){
    if((key==='authority'||key.endsWith('_authority')||key.endsWith('Authority'))&&row===true)throw new WGStackInterchangeError(`${path} attempts authority escalation via ${key}`);
    if(row&&typeof row==='object')authorityGuard(row,`${path}.${key}`);
  }
}

function requiredString(value,name){
  const row=String(value??'').trim();
  if(!row)throw new WGStackInterchangeError(`${name} is required`);
  return row;
}

export function digestWgStackInterchangeValue(value){
  return `shake256-512:${shake256Hex(canonicalize(value),64)}`;
}

export function projectWgStackManifestValue(value){
  authorityGuard(value);
  if(!value||typeof value!=='object'||Array.isArray(value))throw new WGStackInterchangeError('WG stack manifest must be an object');
  const families=value.families;
  if(!families||typeof families!=='object'||Array.isArray(families))throw new WGStackInterchangeError('WG stack manifest families are required');
  const row={
    schema:requiredString(value.schema,'schema'),
    profile_id:requiredString(value.profile_id,'profile_id'),
    parity_contract:{
      schema:requiredString(value.parity_contract?.schema,'parity_contract.schema'),
      digest:requiredString(value.parity_contract?.digest,'parity_contract.digest'),
    },
    families:{
      rnn:{profile_id:requiredString(families.rnn?.profile_id,'families.rnn.profile_id'),fixture_manifest_digest:requiredString(families.rnn?.fixture_manifest_digest,'families.rnn.fixture_manifest_digest')},
      sfm:{profile_id:requiredString(families.sfm?.profile_id,'families.sfm.profile_id'),fixture_manifest_digest:requiredString(families.sfm?.fixture_manifest_digest,'families.sfm.fixture_manifest_digest')},
      srnn:{profile_id:requiredString(families.srnn?.profile_id,'families.srnn.profile_id'),fixture_manifest_digest:requiredString(families.srnn?.fixture_manifest_digest,'families.srnn.fixture_manifest_digest')},
    },
    ...WG_STACK_NO_AUTHORITY,
  };
  return row;
}

export function digestWgStackInterchangeManifest(value){
  return digestWgStackInterchangeValue(projectWgStackManifestValue(value));
}

export async function projectWgStackInterchangeManifest({parityContract,rnnFixture,sfmFixture,srnnFixture}={}){
  authorityGuard(parityContract,'parity contract');
  if(!parityContract||typeof parityContract!=='object'||Array.isArray(parityContract))throw new WGStackInterchangeError('parityContract is required');
  if(String(parityContract.schema??'')!==WG_STACK_PARITY_CONTRACT_SCHEMA)throw new WGStackInterchangeError(`unsupported parity contract schema ${JSON.stringify(parityContract.schema??null)}`);
  const rnn=verifyRnnInterchangeFixtureManifest(rnnFixture);
  const sfm=verifySfmInterchangeFixtureManifest(sfmFixture);
  const srnn=await verifySrnnInterchangeFixtureManifest(srnnFixture);
  for(const [name,row,profile] of [['rnn',rnn,WG_RNN_INTERCHANGE_PROFILE],['sfm',sfm,WG_SFM_INTERCHANGE_PROFILE],['srnn',srnn,WG_SRNN_INTERCHANGE_PROFILE]]){
    if(!row?.verified||row.profile_id!==profile||row.fixture_profile_id!==profile)throw new WGStackInterchangeError(`${name} interchange fixture failed verification`);
  }
  return projectWgStackManifestValue({
    schema:WG_STACK_INTERCHANGE_SCHEMA,
    profile_id:WG_STACK_INTERCHANGE_PROFILE,
    parity_contract:{schema:WG_STACK_PARITY_CONTRACT_SCHEMA,digest:digestWgStackInterchangeValue(parityContract)},
    families:{
      rnn:{profile_id:WG_RNN_INTERCHANGE_PROFILE,fixture_manifest_digest:rnn.observed_manifest_digest},
      sfm:{profile_id:WG_SFM_INTERCHANGE_PROFILE,fixture_manifest_digest:sfm.observed_manifest_digest},
      srnn:{profile_id:WG_SRNN_INTERCHANGE_PROFILE,fixture_manifest_digest:srnn.observed_manifest_digest},
    },
  });
}

export async function verifyWgStackInterchangeManifest(manifest,inputs={}){
  authorityGuard(manifest);
  const pinned=projectWgStackManifestValue(manifest);
  const observed=await projectWgStackInterchangeManifest(inputs);
  const expectedDigest=requiredString(manifest?.stack_manifest_digest,'stack_manifest_digest');
  const pinnedDigest=digestWgStackInterchangeManifest(pinned);
  const observedDigest=digestWgStackInterchangeManifest(observed);
  const profileMatches=pinned.profile_id===WG_STACK_INTERCHANGE_PROFILE;
  const contractMatches=canonicalize(pinned.parity_contract)===canonicalize(observed.parity_contract);
  const familiesMatch=canonicalize(pinned.families)===canonicalize(observed.families);
  const digestMatches=expectedDigest===pinnedDigest&&pinnedDigest===observedDigest;
  return{
    schema:WG_STACK_INTERCHANGE_VERIFICATION_SCHEMA,
    profile_id:WG_STACK_INTERCHANGE_PROFILE,
    fixture_profile_id:pinned.profile_id,
    stack_manifest_digest:expectedDigest,
    observed_manifest_digest:observedDigest,
    profile_matches:profileMatches,
    contract_matches:contractMatches,
    families_match:familiesMatch,
    digest_matches:digestMatches,
    verified:profileMatches&&contractMatches&&familiesMatch&&digestMatches,
    ...WG_STACK_NO_AUTHORITY,
  };
}


export function wgStackInterchangeReleaseRequirement(manifest){
  authorityGuard(manifest);
  const projected=projectWgStackManifestValue(manifest);
  const digest=requiredString(manifest?.stack_manifest_digest,'stack_manifest_digest');
  const observed=digestWgStackInterchangeManifest(projected);
  if(digest!==observed)throw new WGStackInterchangeError('stack manifest digest does not match projected content');
  if(projected.profile_id!==WG_STACK_INTERCHANGE_PROFILE)throw new WGStackInterchangeError('unsupported stack interchange profile');
  return{profile_id:WG_STACK_INTERCHANGE_PROFILE,fixture_digest:digest,authority:false};
}

export function wgStackInterchangeReleaseEvidence(verification){
  authorityGuard(verification,'stack verification');
  if(!verification||typeof verification!=='object'||verification.verified!==true)throw new WGStackInterchangeError('verified stack interchange evidence is required');
  if(String(verification.profile_id??'')!==WG_STACK_INTERCHANGE_PROFILE)throw new WGStackInterchangeError('stack interchange evidence profile mismatch');
  const digest=requiredString(verification.observed_manifest_digest??verification.stack_manifest_digest,'observed_manifest_digest');
  if(verification.stack_manifest_digest&&String(verification.stack_manifest_digest)!==digest)throw new WGStackInterchangeError('stack interchange evidence digest mismatch');
  return{profile_id:WG_STACK_INTERCHANGE_PROFILE,fixture_digest:digest,authority:false};
}

export const project_stack_manifest=projectWgStackInterchangeManifest;
export const digest_stack_manifest=digestWgStackInterchangeManifest;
export const verify_stack_manifest=verifyWgStackInterchangeManifest;
export const release_requirement=wgStackInterchangeReleaseRequirement;
export const release_evidence=wgStackInterchangeReleaseEvidence;
