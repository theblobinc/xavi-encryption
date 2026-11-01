import { shake256Hex } from './crypto.js';
import { canonicalize } from './utils.js';
import {
  WG_STACK_INTERCHANGE_PROFILE,
  WG_STACK_NO_AUTHORITY,
  WGStackInterchangeError,
  wgStackInterchangeReleaseEvidence,
} from './witness-stack-interchange.js';
import { WG_RNN_INTERCHANGE_PROFILE } from './witness-rnn-interchange.js';
import { WG_SFM_INTERCHANGE_PROFILE } from './witness-sfm-interchange.js';
import { WG_SRNN_INTERCHANGE_PROFILE } from './witness-srnn-interchange.js';

export const WG_STACK_CAPABILITY_SCHEMA='xavi-wg-stack-capability-descriptor/v1';
export const WG_STACK_CAPABILITY_PROFILE='WG-STACK-CAPABILITY/1';
export const WG_STACK_CAPABILITY_VERIFICATION_SCHEMA='xavi-wg-stack-capability-verification/v1';
export const WG_STACK_CAPABILITY_HANDSHAKE_SCHEMA='xavi-wg-stack-capability-handshake/v1';

export const WG_STACK_CAPABILITY_ALLOWLIST=Object.freeze({
  rnn:Object.freeze(['portable-state-export','portable-state-verify','teacher-projection']),
  sfm:Object.freeze(['snapshot-normalize','proposal-normalize','fixture-verify']),
  srnn:Object.freeze(['record-projection','runtime-envelope','stage-normalize','fixture-verify']),
});

export class WGStackCapabilityError extends Error{
  constructor(message){super(message);this.name='WGStackCapabilityError';}
}

function authorityGuard(value,path='capability descriptor'){
  if(!value||typeof value!=='object')return;
  for(const [key,row] of Object.entries(value)){
    if((key==='authority'||key.endsWith('_authority')||key.endsWith('Authority'))&&row===true)throw new WGStackCapabilityError(`${path} attempts authority escalation via ${key}`);
    if(row&&typeof row==='object')authorityGuard(row,`${path}.${key}`);
  }
}
function requiredString(value,name){const row=String(value??'').trim();if(!row)throw new WGStackCapabilityError(`${name} is required`);return row;}
function sortedCapabilities(value,family){
  if(!Array.isArray(value))throw new WGStackCapabilityError(`${family} capabilities must be an array`);
  const allowed=new Set(WG_STACK_CAPABILITY_ALLOWLIST[family]);
  const out=[...new Set(value.map(x=>requiredString(x,`${family} capability`)))].sort();
  for(const item of out)if(!allowed.has(item))throw new WGStackCapabilityError(`unsupported ${family} capability ${JSON.stringify(item)}`);
  return out;
}
function profileFor(family){return family==='rnn'?WG_RNN_INTERCHANGE_PROFILE:family==='sfm'?WG_SFM_INTERCHANGE_PROFILE:WG_SRNN_INTERCHANGE_PROFILE;}
function fullFamily(family){
  const row={profile_id:profileFor(family),capabilities:[...WG_STACK_CAPABILITY_ALLOWLIST[family]]};
  if(family==='rnn')Object.assign(row,{native_weights_portable:false,direct_state_overwrite_allowed:false,temporal_witness_required_for_learning:true});
  if(family==='sfm')Object.assign(row,{witness_gate_required:true,proposal_authority:false});
  if(family==='srnn')Object.assign(row,{cross_runtime_import_requires_rewitness:true,native_seal_authority:false});
  return row;
}

export function digestWgStackCapabilityDescriptor(value){return `shake256-512:${shake256Hex(canonicalize(value),64)}`;}

export function projectWgStackCapabilityValue(value){
  authorityGuard(value);
  if(!value||typeof value!=='object'||Array.isArray(value))throw new WGStackCapabilityError('capability descriptor must be an object');
  const families=value.families;
  if(!families||typeof families!=='object'||Array.isArray(families))throw new WGStackCapabilityError('capability descriptor families are required');
  const row={
    schema:requiredString(value.schema,'schema'),
    profile_id:requiredString(value.profile_id,'profile_id'),
    runtime:{
      runtime_id:requiredString(value.runtime?.runtime_id,'runtime.runtime_id'),
      language:requiredString(value.runtime?.language,'runtime.language'),
      implementation:requiredString(value.runtime?.implementation,'runtime.implementation'),
    },
    stack:{
      profile_id:requiredString(value.stack?.profile_id,'stack.profile_id'),
      fixture_digest:requiredString(value.stack?.fixture_digest,'stack.fixture_digest'),
    },
    families:{},
    ...WG_STACK_NO_AUTHORITY,
  };
  for(const family of ['rnn','sfm','srnn']){
    const src=families[family];
    if(!src||typeof src!=='object'||Array.isArray(src))throw new WGStackCapabilityError(`${family} capability descriptor is required`);
    const item={profile_id:requiredString(src.profile_id,`families.${family}.profile_id`),capabilities:sortedCapabilities(src.capabilities,family)};
    if(family==='rnn')Object.assign(item,{native_weights_portable:src.native_weights_portable===true,direct_state_overwrite_allowed:src.direct_state_overwrite_allowed===true,temporal_witness_required_for_learning:src.temporal_witness_required_for_learning!==false});
    if(family==='sfm')Object.assign(item,{witness_gate_required:src.witness_gate_required!==false,proposal_authority:src.proposal_authority===true});
    if(family==='srnn')Object.assign(item,{cross_runtime_import_requires_rewitness:src.cross_runtime_import_requires_rewitness!==false,native_seal_authority:src.native_seal_authority===true});
    row.families[family]=item;
  }
  return row;
}

export function projectWgStackCapabilityDescriptor({stackVerification,runtimeId='xavi-browser-js',language='javascript',implementation='standalone-js',families=null}={}){
  let stackEvidence;
  try{stackEvidence=wgStackInterchangeReleaseEvidence(stackVerification);}catch(error){throw new WGStackCapabilityError(error?.message||String(error));}
  const familyRows=families??Object.fromEntries(['rnn','sfm','srnn'].map(name=>[name,fullFamily(name)]));
  return projectWgStackCapabilityValue({
    schema:WG_STACK_CAPABILITY_SCHEMA,
    profile_id:WG_STACK_CAPABILITY_PROFILE,
    runtime:{runtime_id:runtimeId,language,implementation},
    stack:{profile_id:stackEvidence.profile_id,fixture_digest:stackEvidence.fixture_digest},
    families:familyRows,
  });
}

export function verifyWgStackCapabilityDescriptor(descriptor,{stackManifest}={}){
  const row=projectWgStackCapabilityValue(descriptor);
  authorityGuard(stackManifest,'stack manifest');
  const expectedProfile=requiredString(stackManifest?.profile_id,'stackManifest.profile_id');
  const expectedDigest=requiredString(stackManifest?.stack_manifest_digest,'stackManifest.stack_manifest_digest');
  const issues=[];
  if(row.schema!==WG_STACK_CAPABILITY_SCHEMA)issues.push('descriptor-schema-mismatch');
  if(row.profile_id!==WG_STACK_CAPABILITY_PROFILE)issues.push('descriptor-profile-mismatch');
  if(row.stack.profile_id!==expectedProfile||expectedProfile!==WG_STACK_INTERCHANGE_PROFILE)issues.push('stack-profile-mismatch');
  if(row.stack.fixture_digest!==expectedDigest)issues.push('stack-digest-mismatch');
  for(const family of ['rnn','sfm','srnn']){
    if(row.families[family].profile_id!==profileFor(family))issues.push(`${family}-profile-mismatch`);
  }
  if(row.families.rnn.native_weights_portable)issues.push('rnn-native-weights-portable-unsafe');
  if(row.families.rnn.direct_state_overwrite_allowed)issues.push('rnn-direct-state-overwrite-unsafe');
  if(!row.families.rnn.temporal_witness_required_for_learning)issues.push('rnn-temporal-witness-gate-missing');
  if(!row.families.sfm.witness_gate_required)issues.push('sfm-witness-gate-missing');
  if(row.families.sfm.proposal_authority)issues.push('sfm-proposal-authority-unsafe');
  if(!row.families.srnn.cross_runtime_import_requires_rewitness)issues.push('srnn-rewitness-requirement-missing');
  if(row.families.srnn.native_seal_authority)issues.push('srnn-native-seal-authority-unsafe');
  const observedDigest=digestWgStackCapabilityDescriptor(row);
  const pinnedDigest=descriptor?.capability_digest==null?null:requiredString(descriptor.capability_digest,'capability_digest');
  if(pinnedDigest!==null&&pinnedDigest!==observedDigest)issues.push('capability-digest-mismatch');
  return{
    schema:WG_STACK_CAPABILITY_VERIFICATION_SCHEMA,
    profile_id:WG_STACK_CAPABILITY_PROFILE,
    capability_digest:pinnedDigest??observedDigest,
    observed_capability_digest:observedDigest,
    capability_digest_matches:pinnedDigest===null?null:pinnedDigest===observedDigest,
    runtime_id:row.runtime.runtime_id,
    stack_profile_matches:row.stack.profile_id===expectedProfile,
    stack_digest_matches:row.stack.fixture_digest===expectedDigest,
    family_profiles_match:['rnn','sfm','srnn'].every(name=>row.families[name].profile_id===profileFor(name)),
    issues,
    verified:issues.length===0,
    ...WG_STACK_NO_AUTHORITY,
  };
}

export function compareWgStackCapabilityDescriptors(local,remote,{stackManifest}={}){
  const left=projectWgStackCapabilityValue(local),right=projectWgStackCapabilityValue(remote);
  const lv=verifyWgStackCapabilityDescriptor(left,{stackManifest}),rv=verifyWgStackCapabilityDescriptor(right,{stackManifest});
  const stackMatches=left.stack.profile_id===right.stack.profile_id&&left.stack.fixture_digest===right.stack.fixture_digest;
  const familyProfilesMatch=['rnn','sfm','srnn'].every(name=>left.families[name].profile_id===right.families[name].profile_id);
  const common={};
  for(const family of ['rnn','sfm','srnn']){
    const remoteSet=new Set(right.families[family].capabilities);
    common[family]=left.families[family].capabilities.filter(item=>remoteSet.has(item));
  }
  const compatible=lv.verified&&rv.verified&&stackMatches&&familyProfilesMatch;
  return{
    schema:WG_STACK_CAPABILITY_HANDSHAKE_SCHEMA,
    profile_id:WG_STACK_CAPABILITY_PROFILE,
    local_runtime_id:left.runtime.runtime_id,
    remote_runtime_id:right.runtime.runtime_id,
    local_capability_digest:lv.capability_digest,
    remote_capability_digest:rv.capability_digest,
    stack_matches:stackMatches,
    family_profiles_match:familyProfilesMatch,
    common_capabilities:common,
    compatible,
    state_transfer_authorized:false,
    execution_authorized:false,
    promotion_authorized:false,
    ...WG_STACK_NO_AUTHORITY,
  };
}



export const WG_STACK_CAPABILITY_HISTORY_SCHEMA='xavi-wg-stack-capability-history/v1';

export async function inspectWgStackCapabilityHandshakeHistory({store,limit=128,remoteRuntimeId=null}={}){
  if(!store||typeof store.values!=='function')throw new WGStackCapabilityError('store with values() is required');
  const max=Math.max(1,Math.min(1024,Number(limit)||128));
  const filterId=remoteRuntimeId==null?null:String(remoteRuntimeId);
  const rows=(await store.values('witness')||[])
    .filter(row=>row?.type==='wg-stack-capability-handshake')
    .filter(row=>filterId===null||String(row?.body?.remoteRuntimeId??'')===filterId)
    .sort((a,b)=>Number(a?.sequence||0)-Number(b?.sequence||0))
    .slice(-max);
  const peers=new Map();
  for(const row of rows){
    const body=row.body||{};
    const id=String(body.remoteRuntimeId??'unknown');
    let peer=peers.get(id);
    if(!peer){peer={remote_runtime_id:id,peer_labels:new Set(),capability_digests:new Set(),compatible_count:0,incompatible_count:0,compatibility_values:new Set(),handshakes:0,first_sequence:Number(row.sequence||0),last_sequence:Number(row.sequence||0),last_witness_digest:row.digest||null,latest:null};peers.set(id,peer);}
    peer.handshakes+=1;peer.last_sequence=Number(row.sequence||0);peer.last_witness_digest=row.digest||null;
    if(body.peerLabel!=null)peer.peer_labels.add(String(body.peerLabel));
    if(body.remoteCapabilityDigest)peer.capability_digests.add(String(body.remoteCapabilityDigest));
    const compatible=body.compatible===true;peer.compatibility_values.add(compatible);if(compatible)peer.compatible_count+=1;else peer.incompatible_count+=1;
    peer.latest={peer_label:body.peerLabel??null,remote_capability_digest:body.remoteCapabilityDigest??null,local_capability_digest:body.localCapabilityDigest??null,stack_matches:body.stackMatches===true,family_profiles_match:body.familyProfilesMatch===true,common_capabilities:body.commonCapabilities??{rnn:[],sfm:[],srnn:[]},compatible,sequence:Number(row.sequence||0),witness_digest:row.digest||null};
  }
  const list=[...peers.values()].map(peer=>({
    remote_runtime_id:peer.remote_runtime_id,
    peer_labels:[...peer.peer_labels].sort(),
    handshakes:peer.handshakes,
    compatible_count:peer.compatible_count,
    incompatible_count:peer.incompatible_count,
    distinct_capability_digests:peer.capability_digests.size,
    capability_changed:peer.capability_digests.size>1,
    compatibility_changed:peer.compatibility_values.size>1,
    first_sequence:peer.first_sequence,
    last_sequence:peer.last_sequence,
    last_witness_digest:peer.last_witness_digest,
    latest:peer.latest,
    authority:false,
  })).sort((a,b)=>b.last_sequence-a.last_sequence);
  return{
    schema:WG_STACK_CAPABILITY_HISTORY_SCHEMA,
    profile_id:WG_STACK_CAPABILITY_PROFILE,
    inspected_handshakes:rows.length,
    peer_count:list.length,
    capability_drift_peers:list.filter(row=>row.capability_changed).length,
    compatibility_drift_peers:list.filter(row=>row.compatibility_changed).length,
    peers:list,
    ...WG_STACK_NO_AUTHORITY,
  };
}

export async function witnessWgStackCapabilityHandshake({ledger,localDescriptor,remoteDescriptor,stackManifest,peerLabel=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackCapabilityError('WitnessLedger-compatible ledger is required');
  const handshake=compareWgStackCapabilityDescriptors(localDescriptor,remoteDescriptor,{stackManifest});
  const witness=await ledger.append('wg-stack-capability-handshake',{
    schema:WG_STACK_CAPABILITY_HANDSHAKE_SCHEMA,
    profile_id:WG_STACK_CAPABILITY_PROFILE,
    peerLabel:peerLabel==null?null:String(peerLabel).slice(0,160),
    localRuntimeId:handshake.local_runtime_id,
    remoteRuntimeId:handshake.remote_runtime_id,
    localCapabilityDigest:handshake.local_capability_digest,
    remoteCapabilityDigest:handshake.remote_capability_digest,
    stackMatches:handshake.stack_matches,
    familyProfilesMatch:handshake.family_profiles_match,
    commonCapabilities:handshake.common_capabilities,
    compatible:handshake.compatible,
    stateTransferAuthorized:false,
    executionAuthorized:false,
    promotionAuthorized:false,
    authority:false,
  });
  return{handshake,witness,authority:false};
}

export const project_capability_descriptor=projectWgStackCapabilityDescriptor;
export const verify_capability_descriptor=verifyWgStackCapabilityDescriptor;
export const compare_capability_descriptors=compareWgStackCapabilityDescriptors;
export const witness_capability_handshake=witnessWgStackCapabilityHandshake;
export const inspect_capability_handshake_history=inspectWgStackCapabilityHandshakeHistory;
