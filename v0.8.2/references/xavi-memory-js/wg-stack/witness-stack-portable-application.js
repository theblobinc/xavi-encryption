import { shake256Hex } from './crypto.js';
import { stringifyWgStackPortableJson } from './witness-stack-portable-envelope.js';
import { verifyWgStackPortableFamilyGateDecision } from './witness-stack-portable-gate-decision.js';

export const WG_STACK_PORTABLE_APPLICATION_SCHEMA='xavi-wg-stack-portable-family-application/v1';
export const WG_STACK_PORTABLE_APPLICATION_PROFILE='WG-STACK-PORTABLE-APPLICATION/1';
export const WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA='xavi-wg-stack-portable-application-permit/v1';
export const WG_STACK_PORTABLE_APPLICATION_PERMIT_WITNESS_TYPE='wg-stack-portable-application-permit';
export const WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA='xavi-wg-stack-portable-family-application-witness/v1';
export const WG_STACK_PORTABLE_APPLICATION_ROLLBACK_WITNESS_SCHEMA='xavi-wg-stack-portable-family-application-rollback/v1';
export const WG_STACK_PORTABLE_STACK_APPLICATION_SCHEMA='xavi-wg-stack-portable-stack-application/v1';
export const WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE='WG-STACK-PORTABLE-STACK-APPLICATION/1';
export const WG_STACK_PORTABLE_STACK_APPLICATION_WITNESS_SCHEMA='xavi-wg-stack-portable-stack-application-witness/v1';
export const WG_STACK_PORTABLE_STACK_APPLICATION_ROLLBACK_WITNESS_SCHEMA='xavi-wg-stack-portable-stack-application-rollback/v1';
export const WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA='xavi-wg-stack-portable-stack-application-started/v1';
export const WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA='xavi-wg-stack-portable-stack-recovery-inspection/v1';
export const WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA='xavi-wg-stack-portable-stack-recovery-chain/v1';
export const WG_STACK_PORTABLE_STACK_RECOVERY_JOURNAL_SCHEMA='xavi-wg-stack-portable-stack-recovery-journal/v1';
export const WG_STACK_PORTABLE_RECOVERY_READINESS_ASSESSMENT_SCHEMA='xavi-wg-stack-portable-recovery-readiness-assessment/v1';
export const WG_STACK_PORTABLE_STACK_RECONCILIATION_WITNESS_SCHEMA='xavi-wg-stack-portable-stack-reconciliation/v1';
export const WG_STACK_PORTABLE_STACK_MUTATION_LEASE_SCHEMA='xavi-wg-stack-portable-stack-mutation-lease/v1';
export const WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY=Object.freeze({
  authority:false,truth_authority:false,proof_authority:false,promotion_authority:false,
  learning_authority:false,execution_authority:false,self_model_write_authority:false,self_kernel_write_authority:false,
});
export class WGStackPortableApplicationError extends Error{constructor(message,{rollback=null,cause=null}={}){super(message);this.name='WGStackPortableApplicationError';this.rollback=rollback;this.cause=cause;}}
const clean=v=>String(v??'').trim();
const finiteArray=(v,n)=>Array.isArray(v)&&v.length===n&&v.every(Number.isFinite);
function digest(v){return `shake256-512:${shake256Hex(stringifyWgStackPortableJson(v,{space:0}),64)}`;}
function witnessed(v){return clean(v).startsWith('shake256-512:')||clean(v).startsWith('witness:')||clean(v).length>=16;}
function validatePermit(permit,decision){
  if(!permit||typeof permit!=='object'||Array.isArray(permit))throw new WGStackPortableApplicationError('external application permit is required');
  if(permit.schema!==WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA)throw new WGStackPortableApplicationError('portable application permit schema mismatch');
  if(permit.allowMutation!==true)throw new WGStackPortableApplicationError('portable application permit does not allow mutation');
  if(clean(permit.authorizationSource)!=='external-authority')throw new WGStackPortableApplicationError('portable application permit must come from external-authority');
  if(!witnessed(permit.permitWitnessDigest))throw new WGStackPortableApplicationError('portable application permit witness digest is required');
  if(clean(permit.decisionDigest)!==clean(decision?.decision_digest))throw new WGStackPortableApplicationError('portable application permit decision digest mismatch');
  if(clean(permit.candidateDigest)!==clean(decision?.candidate_digest))throw new WGStackPortableApplicationError('portable application permit candidate digest mismatch');
  if(clean(permit.family)!==clean(decision?.family))throw new WGStackPortableApplicationError('portable application permit family mismatch');
  return{schema:permit.schema,permitWitnessDigest:clean(permit.permitWitnessDigest),decisionDigest:clean(permit.decisionDigest),candidateDigest:clean(permit.candidateDigest),family:clean(permit.family),authorizationSource:'external-authority',allowMutation:true};
}

export async function witnessWgStackPortableApplicationPermit({ledger,decision,authorizedBy,evidenceWitnessDigest=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableApplicationError('WitnessLedger-compatible ledger is required for portable application permit');
  if(!decision?.decision_digest||decision?.gate_ready!==true)throw new WGStackPortableApplicationError('gate-ready decision is required for portable application permit');
  const actor=clean(authorizedBy);if(!actor)throw new WGStackPortableApplicationError('external application authorizer identity is required');
  if(evidenceWitnessDigest!=null&&!witnessed(evidenceWitnessDigest))throw new WGStackPortableApplicationError('external application authorization evidence digest is invalid');
  const witness=await ledger.append(WG_STACK_PORTABLE_APPLICATION_PERMIT_WITNESS_TYPE,{schema:WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA,decisionDigest:decision.decision_digest,candidateDigest:decision.candidate_digest,family:decision.family,index:decision.index??null,authorizationSource:'external-authority',authorizedBy:actor,evidenceWitnessDigest:evidenceWitnessDigest?clean(evidenceWitnessDigest):null,allowMutation:true,authority:false});
  return{schema:WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA,permitWitnessDigest:witness.digest,decisionDigest:decision.decision_digest,candidateDigest:decision.candidate_digest,family:decision.family,authorizationSource:'external-authority',authorizedBy:actor,allowMutation:true,authority:false};
}
async function verifyPermitWitness(ledger,permit){
  if(!ledger?.store?.values)throw new WGStackPortableApplicationError('portable application requires a ledger store that can resolve permit witnesses');
  const rows=await ledger.store.values('witness');const row=(rows||[]).find(item=>item?.digest===permit.permitWitnessDigest);
  if(!row)throw new WGStackPortableApplicationError('portable application permit witness does not exist in target ledger');
  if(row.type!==WG_STACK_PORTABLE_APPLICATION_PERMIT_WITNESS_TYPE)throw new WGStackPortableApplicationError('portable application permit witness type mismatch');
  const body=row.body||{};
  if(body.schema!==WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA||body.allowMutation!==true||body.authorizationSource!=='external-authority')throw new WGStackPortableApplicationError('portable application permit witness body is invalid');
  if(clean(body.decisionDigest)!==permit.decisionDigest||clean(body.candidateDigest)!==permit.candidateDigest||clean(body.family)!==permit.family)throw new WGStackPortableApplicationError('portable application permit witness binding mismatch');
  if(!clean(body.authorizedBy))throw new WGStackPortableApplicationError('portable application permit witness authorizer is missing');
  return row;
}


async function assertPermitUnconsumed(ledger,permit,{stackTransactionId=null}={}){
  if(!ledger?.store?.values)throw new WGStackPortableApplicationError('portable application requires a ledger store that can verify permit consumption');
  const tx=stackTransactionId?clean(stackTransactionId):null;
  const rows=await ledger.store.values('witness');
  const consumed=(rows||[]).find(row=>
    (['wg-stack-portable-family-applied','wg-stack-portable-family-application-rollback'].includes(row?.type)&&clean(row?.body?.permitWitnessDigest)===permit.permitWitnessDigest)||
    (['wg-stack-portable-stack-applied','wg-stack-portable-stack-application-rollback'].includes(row?.type)&&Array.isArray(row?.body?.permitWitnessDigests)&&row.body.permitWitnessDigests.map(clean).includes(permit.permitWitnessDigest))||
    (row?.type==='wg-stack-portable-stack-application-started'&&Array.isArray(row?.body?.permitWitnessDigests)&&row.body.permitWitnessDigests.map(clean).includes(permit.permitWitnessDigest)&&clean(row?.body?.stackTransactionId)!==tx)
  );
  if(consumed)throw new WGStackPortableApplicationError(`portable application permit is already consumed or reserved by ${consumed.type}`);
  return true;
}

function familyStageRow(stage,family,index){if(family==='rnn')return stage?.families?.rnn;if(family==='sfm_snapshot')return stage?.families?.sfm_snapshot;if(family==='sfm_proposal')return stage?.families?.sfm_proposal;if(family==='srnn')return stage?.families?.srnn?.[Number(index??0)]??null;return null;}
function resultIdentity(row){return{schema:row.schema,profile_id:row.profile_id,family:row.family,index:row.index??null,decision_digest:row.decision_digest,candidate_digest:row.candidate_digest,permit_witness_digest:row.permit_witness_digest,mode:row.mode,before_digest:row.before_digest,after_digest:row.after_digest,mutation_applied:row.mutation_applied===true,post_verified:row.post_verified===true,authorization_source:row.authorization_source,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};}
export function digestWgStackPortableApplication(row){return digest(resultIdentity(row));}
async function rollbackRnn(recurrent,before,revision){try{recurrent.restore(before);recurrent.revision=revision;return{restored:true,digest:digest(recurrent.snapshot())};}catch(error){return{restored:false,error:String(error?.message??error)};}}
async function rollbackSfm({sfm,store,before,beforeRevision,priorRecord,expectedRecord=undefined}){try{sfm.restore(before);sfm.revision=beforeRevision;sfm.inferCache=null;if(store){if(expectedRecord!==undefined&&store.compareAndSet){const result=await store.compareAndSet('records',sfm.stateKey,expectedRecord,priorRecord??null);if(!result?.updated)return{restored:false,localRestored:true,digest:digest(sfm.snapshot()),error:'SFM rollback compare-and-set fence conflict'};}else if(priorRecord==null)await store.delete?.('records',sfm.stateKey);else await store.set?.('records',sfm.stateKey,priorRecord);}return{restored:true,digest:digest(sfm.snapshot())};}catch(error){return{restored:false,error:String(error?.message??error)};}}
async function rollbackSrnn({srnn,store,before,priorRecord,expectedRecord=undefined}){try{srnn.restore(before);if(store){if(expectedRecord!==undefined&&store.compareAndSet){const result=await store.compareAndSet('records',srnn.stateKey,expectedRecord,priorRecord??null);if(!result?.updated)return{restored:false,localRestored:true,digest:digest(srnn.snapshot()),error:'SRNN rollback compare-and-set fence conflict'};}else if(priorRecord==null)await store.delete?.('records',srnn.stateKey);else await store.set?.('records',srnn.stateKey,priorRecord);}return{restored:true,digest:digest(srnn.snapshot())};}catch(error){return{restored:false,error:String(error?.message??error)};}}
async function appendRollback(ledger,{family,decision,candidate,permit,reason,rollback,stackTransactionId=null}){try{return await ledger?.append?.('wg-stack-portable-family-application-rollback',{schema:WG_STACK_PORTABLE_APPLICATION_ROLLBACK_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family,index:decision.index??null,stackTransactionId:stackTransactionId?clean(stackTransactionId):null,decisionDigest:decision.decision_digest,candidateDigest:candidate?.candidate_digest??decision.candidate_digest,permitWitnessDigest:permit?.permitWitnessDigest??null,reason:String(reason||'application-failed'),restored:rollback?.restored===true,restoredDigest:rollback?.digest??null,authority:false});}catch{return null;}}

export async function applyWgStackPortableFamilyTransaction({decision,admission,evidence,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null,permit,recurrent=null,sfm=null,srnn=null,store=null,ledger=null,applicationData={},stackTransactionId=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableApplicationError('WitnessLedger-compatible ledger is required for portable application');
  const verification=await verifyWgStackPortableFamilyGateDecision(decision,{admission,evidence,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:targetRuntime??stage?.target_runtime});
  if(verification?.verified!==true||verification?.gate_ready!==true)throw new WGStackPortableApplicationError('verified gate-ready portable family decision is required');
  const externalPermit=validatePermit(permit,decision);const permitWitness=await verifyPermitWitness(ledger,externalPermit);await assertPermitUnconsumed(ledger,externalPermit,{stackTransactionId});const family=decision.family,candidateRow=familyStageRow(stage,family,decision.index),candidate=candidateRow?.candidate;
  if(!candidateRow||clean(candidateRow.candidate_digest)!==clean(decision.candidate_digest))throw new WGStackPortableApplicationError('staged candidate does not match gate decision');
  if(family==='sfm_proposal')throw new WGStackPortableApplicationError('SFM proposal is evidence-only and cannot be applied as state');


  if(family==='srnn'){
    if(!srnn||typeof srnn.snapshot!=='function'||typeof srnn.restore!=='function'||typeof srnn.proposeDirective!=='function')throw new WGStackPortableApplicationError('WitnessGatedSelfReferentialNeuralNetwork target is required for SRNN portable application');
    if(!store||typeof store.get!=='function'||typeof store.set!=='function'||typeof store.delete!=='function')throw new WGStackPortableApplicationError('persistent store with get/set/delete is required for transactional SRNN application');
    if(candidate?.stage_type!=='internal_directive')throw new WGStackPortableApplicationError('only SRNN internal_directive candidates support local rewitness/reledger application');
    const payload=candidate?.native_payload;if(!payload||payload.schema!=='wg-srnn-internal-directive/v1')throw new WGStackPortableApplicationError('SRNN staged internal directive payload schema mismatch');
    const before=srnn.snapshot(),beforeDigest=digest(before),priorRecord=await store.get('records',srnn.stateKey);let localWitness=null;
    try{
      const provenanceEdges=[...(Array.isArray(payload.justification_edges)?payload.justification_edges:[]),`portable-candidate:${decision.candidate_digest}`,`portable-native:${candidate.native_digest}`,`portable-permit:${externalPermit.permitWitnessDigest}`].slice(0,12);
      const proposed=await srnn.proposeDirective({
        author:'portable-import',capability:candidate.capability||payload.capability||null,strategyId:candidate.strategy_id||payload.strategy_id||null,
        goal:payload.goal,proposedAction:payload.proposed_action,justificationEdges:provenanceEdges,sourceStateDigest:payload.source_state_digest||candidate.native_digest,
        routeWitnessDigest:applicationData?.routeWitnessDigest||null,confidence:candidate.confidence??payload.confidence??0.5,expectedOutcome:payload.expected_outcome??null,commit:false,
      });
      localWitness=proposed?.witness||null;if(!localWitness?.digest)throw new Error('SRNN local rewitness did not produce a witness digest');
      const after=srnn.snapshot(),afterDigest=digest(after);if(afterDigest===beforeDigest)throw new Error('SRNN local rewitness produced no state change');
      const localDirective=(after.directives||[]).find(row=>row?.directiveDigest===localWitness.digest);if(!localDirective)throw new Error('SRNN local rewitnessed directive is missing from native state');
      if(localDirective.directiveDigest===candidate.native_digest||localDirective.directiveId===payload.directive_id)throw new Error('SRNN foreign directive identity was reused locally');
      if(localDirective.author!=='portable-import'||localDirective.status!=='proposed'||localDirective.witnessStatus!=='unverified'||localDirective.authority!==false)throw new Error('SRNN local directive authority/status post-verification failed');
      if(clean(localDirective.goal)!==clean(payload.goal)||clean(localDirective.proposedAction)!==clean(payload.proposed_action)||clean(localDirective.sourceStateDigest)!==clean(payload.source_state_digest))throw new Error('SRNN local directive semantic projection mismatch');
      const persisted=await store.get('records',srnn.stateKey);if(!persisted||digest(persisted)!==afterDigest)throw new Error('SRNN locally rewitnessed state was not persisted exactly');
      const result={schema:WG_STACK_PORTABLE_APPLICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family,index:decision.index??null,decision_digest:decision.decision_digest,candidate_digest:decision.candidate_digest,permit_witness_digest:externalPermit.permitWitnessDigest,mode:'srnn-local-rewitness-reledger',before_digest:beforeDigest,after_digest:afterDigest,mutation_applied:true,post_verified:true,authorization_source:'external-authority',permit_authorized_by:permitWitness.body.authorizedBy,native_result:{rewitnessed:true,reledgered:true,resealedLocally:true,localDirectiveId:localDirective.directiveId,localDirectiveWitnessDigest:localWitness.digest,sourceNativeDigest:candidate.native_digest,sourceInterchangeDigest:candidate.interchange_digest??null,foreignDirectiveId:payload.directive_id??null},authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};result.application_digest=digestWgStackPortableApplication(result);
      const witness=await ledger.append('wg-stack-portable-family-applied',{schema:WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family:'srnn',index:result.index,stackTransactionId:stackTransactionId?clean(stackTransactionId):null,decisionDigest:result.decision_digest,candidateDigest:result.candidate_digest,permitWitnessDigest:result.permit_witness_digest,applicationDigest:result.application_digest,mode:result.mode,beforeDigest,afterDigest,localDirectiveWitnessDigest:localWitness.digest,sourceNativeDigest:candidate.native_digest,mutationApplied:true,postVerified:true,authorizationSource:'external-authority',authority:false});
      return{result,witness,rollback:null,authority:false};
    }catch(error){const rb=await rollbackSrnn({srnn,store,before,priorRecord});const rw=await appendRollback(ledger,{family,decision,candidate:candidateRow,permit:externalPermit,reason:error?.message,rollback:rb,stackTransactionId});throw new WGStackPortableApplicationError(`SRNN portable application rolled back: ${error?.message??error}`,{rollback:{...rb,witness:rw,attemptedLocalWitnessDigest:localWitness?.digest??null},cause:error});}
  }

  if(family==='rnn'){
    if(!recurrent||typeof recurrent.snapshot!=='function'||typeof recurrent.teachFromWitness!=='function')throw new WGStackPortableApplicationError('RecurrentCore target is required for RNN portable application');
    if(!finiteArray(candidate?.teacherState,recurrent.stateDim))throw new WGStackPortableApplicationError('RNN teacher candidate dimension mismatch');
    if(!finiteArray(applicationData?.input,recurrent.inputDim))throw new WGStackPortableApplicationError('local witnessed RNN teaching input vector is required');
    const before=recurrent.snapshot(),beforeRevision=recurrent.revision,beforeDigest=digest(before);let mutation;
    try{
      mutation=recurrent.teachFromWitness({input:applicationData.input,targetState:candidate.teacherState,confidence:candidate.teacherConfidence,reward:Number(applicationData.reward??1),learningRate:Math.min(.12,Math.max(.001,Number(candidate.teacherBlend)||.06))});
      if(mutation?.updated!==true)throw new Error(`RNN native teaching rejected: ${mutation?.reason||'unknown'}`);
      for(const h of Object.keys(mutation.predictionErrorBefore||{}))if(Number(mutation.predictionErrorAfter?.[h])>Number(mutation.predictionErrorBefore[h])+1e-12)throw new Error(`RNN post-verification prediction error increased at horizon ${h}`);
      const after=recurrent.snapshot(),afterDigest=digest(after);if(afterDigest===beforeDigest)throw new Error('RNN native teaching produced no state change');
      const result={schema:WG_STACK_PORTABLE_APPLICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family,index:null,decision_digest:decision.decision_digest,candidate_digest:decision.candidate_digest,permit_witness_digest:externalPermit.permitWitnessDigest,mode:'rnn-teacher-learning',before_digest:beforeDigest,after_digest:afterDigest,mutation_applied:true,post_verified:true,authorization_source:'external-authority',permit_authorized_by:permitWitness.body.authorizedBy,native_result:{updated:true,rate:mutation.rate,strength:mutation.strength},authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};result.application_digest=digestWgStackPortableApplication(result);
      const witness=await ledger.append('wg-stack-portable-family-applied',{schema:WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family:'rnn',stackTransactionId:stackTransactionId?clean(stackTransactionId):null,decisionDigest:result.decision_digest,candidateDigest:result.candidate_digest,permitWitnessDigest:result.permit_witness_digest,applicationDigest:result.application_digest,mode:result.mode,beforeDigest,afterDigest,mutationApplied:true,postVerified:true,authorizationSource:'external-authority',authority:false});
      return{result,witness,rollback:null,authority:false};
    }catch(error){const rb=await rollbackRnn(recurrent,before,beforeRevision);const rw=await appendRollback(ledger,{family,decision,candidate:candidateRow,permit:externalPermit,reason:error?.message,rollback:rb,stackTransactionId});throw new WGStackPortableApplicationError(`RNN portable application rolled back: ${error?.message??error}`,{rollback:{...rb,witness:rw},cause:error});}
  }

  if(family==='sfm_snapshot'){
    if(!sfm||typeof sfm.snapshot!=='function'||typeof sfm.restore!=='function'||typeof sfm.toJsInterchangeSnapshot!=='function')throw new WGStackPortableApplicationError('WitnessSFM target is required for SFM portable application');
    if(!store||typeof store.get!=='function'||typeof store.set!=='function'||typeof store.delete!=='function')throw new WGStackPortableApplicationError('persistent store with get/set/delete is required for transactional SFM application');
    if(Number(candidate?.stateDim)!==Number(sfm.recurrent?.stateDim)||Number(candidate?.inputDim)!==Number(sfm.recurrent?.inputDim))throw new WGStackPortableApplicationError('SFM target dimensions do not match staged candidate');
    const before=sfm.snapshot(),beforeRevision=sfm.revision,beforeDigest=digest(before),priorRecord=await store?.get?.('records',sfm.stateKey);try{
      sfm.restore(candidate);const projected=sfm.toJsInterchangeSnapshot(sfm.snapshot(),{strict:true,target:'javascript'});if(stringifyWgStackPortableJson(projected,{space:0})!==stringifyWgStackPortableJson(candidate,{space:0}))throw new Error('SFM post-verification projection mismatch');
      const after=sfm.snapshot(),afterDigest=digest(after);if(afterDigest===beforeDigest)throw new Error('SFM snapshot application produced no state change');
      await store?.set?.('records',sfm.stateKey,{schema:'xavi-wg-sfm-state-record/v1',state:after,updatedAt:Date.now(),authority:false});
      const result={schema:WG_STACK_PORTABLE_APPLICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family,index:null,decision_digest:decision.decision_digest,candidate_digest:decision.candidate_digest,permit_witness_digest:externalPermit.permitWitnessDigest,mode:'sfm-snapshot-restore',before_digest:beforeDigest,after_digest:afterDigest,mutation_applied:true,post_verified:true,authorization_source:'external-authority',permit_authorized_by:permitWitness.body.authorizedBy,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};result.application_digest=digestWgStackPortableApplication(result);
      const witness=await ledger.append('wg-stack-portable-family-applied',{schema:WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family:'sfm_snapshot',stackTransactionId:stackTransactionId?clean(stackTransactionId):null,decisionDigest:result.decision_digest,candidateDigest:result.candidate_digest,permitWitnessDigest:result.permit_witness_digest,applicationDigest:result.application_digest,mode:result.mode,beforeDigest,afterDigest,mutationApplied:true,postVerified:true,authorizationSource:'external-authority',authority:false});
      return{result,witness,rollback:null,authority:false};
    }catch(error){const rb=await rollbackSfm({sfm,store,before,beforeRevision,priorRecord});const rw=await appendRollback(ledger,{family,decision,candidate:candidateRow,permit:externalPermit,reason:error?.message,rollback:rb,stackTransactionId});throw new WGStackPortableApplicationError(`SFM portable application rolled back: ${error?.message??error}`,{rollback:{...rb,witness:rw},cause:error});}
  }
  throw new WGStackPortableApplicationError(`portable application family ${family} is not implemented`);
}

export const witness_portable_application_permit=witnessWgStackPortableApplicationPermit;
export const apply_portable_family_transaction=applyWgStackPortableFamilyTransaction;
export const digest_portable_family_application=digestWgStackPortableApplication;

function stackDecisionKey(row){return row?.family==='srnn'?`srnn:${Number(row?.index??0)}`:String(row?.family||'');}
function stackLookup(source,decision){
  if(Array.isArray(source))return source.find(row=>row?.family===decision?.family&&(decision?.family!=='srnn'||Number(row?.index??0)===Number(decision?.index??0)))??null;
  if(!source||typeof source!=='object')return null;
  const key=stackDecisionKey(decision);
  if(Object.prototype.hasOwnProperty.call(source,key))return source[key];
  const family=String(decision?.family||'');const value=source[family];
  if(family==='srnn'&&Array.isArray(value))return value[Number(decision?.index??0)]??null;
  return value??null;
}
function orderedMutableDecisions(decisions=[]){
  const order=new Map([['rnn',0],['sfm_snapshot',1],['srnn',2]]);
  return (Array.isArray(decisions)?decisions:[]).filter(row=>order.has(row?.family)).sort((a,b)=>(order.get(a.family)-order.get(b.family))||(Number(a.index??0)-Number(b.index??0)));
}
function stackResultIdentity(row){return{schema:row.schema,profile_id:row.profile_id,stack_transaction_id:row.stack_transaction_id??null,before_digest:row.before_digest,after_digest:row.after_digest,applications:(row.applications||[]).map(x=>({family:x.family,index:x.index??null,decision_digest:x.decision_digest,candidate_digest:x.candidate_digest,permit_witness_digest:x.permit_witness_digest,application_digest:x.application_digest,witness_digest:x.witness_digest,mode:x.mode})),skipped_families:[...(row.skipped_families||[])],permit_witness_digests:[...(row.permit_witness_digests||[])],mutation_applied:row.mutation_applied===true,post_verified:row.post_verified===true,authorization_source:row.authorization_source,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};}
export function digestWgStackPortableStackApplication(row){return digest(stackResultIdentity(row));}
async function capturePortableStackState({recurrent,sfm,srnn,store}){
  return{
    rnn:{snapshot:recurrent.snapshot(),revision:recurrent.revision},
    sfm:{snapshot:sfm.snapshot(),revision:sfm.revision,priorRecord:await store.get('records',sfm.stateKey)},
    srnn:{snapshot:srnn.snapshot(),priorRecord:await store.get('records',srnn.stateKey)},
  };
}
function stackStateDigest(state){return digest({rnn:state.rnn.snapshot,sfm:state.sfm.snapshot,srnn:state.srnn.snapshot});}

function stackMutationLeaseKey(ledger){return `wg-stack-portable-stack-mutation-lease:${clean(ledger?.namespace)||'default'}`;}
async function acquirePortableStackMutationLease({store,ledger,operation='stack-mutation',leaseMs=5000,timeoutMs=15000}={}){
  if(!store?.compareAndSet||typeof store.get!=='function')throw new WGStackPortableApplicationError('portable stack mutation requires compare-and-set persistent store');
  leaseMs=Math.max(250,Number(leaseMs)||5000);timeoutMs=Math.max(0,Number(timeoutMs)||15000);
  const key=stackMutationLeaseKey(ledger),deadline=Date.now()+timeoutMs,namespace=clean(ledger?.namespace)||'default',owner=digest({schema:WG_STACK_PORTABLE_STACK_MUTATION_LEASE_SCHEMA,namespace,operation,createdAt:Date.now(),nonce:Math.random()});
  for(;;){
    const now=Date.now(),current=await store.get('records',key).catch(()=>null);
    if(!current||current.released===true||Number(current.expiresAt||0)<=now){
      const next={schema:WG_STACK_PORTABLE_STACK_MUTATION_LEASE_SCHEMA,namespace,operation,owner,leaseId:digest({owner,now,nonce:Math.random()}),createdAt:now,expiresAt:now+leaseMs,leaseMs,released:false,authority:false};
      const result=await store.compareAndSet('records',key,current,next);if(result?.updated)return{...next,key};
    }
    if(now>=deadline)throw new WGStackPortableApplicationError('portable stack mutation lease timeout');
    await new Promise(resolve=>setTimeout(resolve,2));
  }
}
async function refreshPortableStackMutationLeaseOnce({store,lease}={}){
  if(!lease)return null;const now=Date.now(),current=await store.get('records',lease.key).catch(()=>null);
  if(!current||current.owner!==lease.owner||current.leaseId!==lease.leaseId||current.released===true)throw new WGStackPortableApplicationError('portable stack mutation lease lost');
  const next={...current,expiresAt:now+Number(lease.leaseMs||5000),refreshedAt:now},result=await store.compareAndSet('records',lease.key,current,next);
  if(!result?.updated){const latest=await store.get('records',lease.key).catch(()=>null);if(latest?.owner===lease.owner&&latest?.leaseId===lease.leaseId&&latest?.released!==true&&Number(latest?.expiresAt||0)>Date.now()){Object.assign(lease,latest);return lease;}throw new WGStackPortableApplicationError('portable stack mutation lease lost');}Object.assign(lease,next);return lease;
}
async function refreshPortableStackMutationLease({store,lease}={}){
  if(!lease)return null;
  const previous=lease._refreshTail||Promise.resolve();
  const run=previous.catch(()=>{}).then(()=>refreshPortableStackMutationLeaseOnce({store,lease}));
  lease._refreshTail=run.catch(()=>{});
  return run;
}
function startPortableStackMutationLeaseHeartbeat({store,lease}={}){
  let tail=Promise.resolve(),stopped=false,lastError=null;const intervalMs=Math.max(50,Math.floor(Number(lease?.leaseMs||5000)/3));
  const timer=setInterval(()=>{if(stopped)return;tail=tail.then(()=>refreshPortableStackMutationLease({store,lease})).catch(error=>{lastError=error;});},intervalMs);timer?.unref?.();
  return{get error(){return lastError;},async stop(){stopped=true;clearInterval(timer);await tail.catch(()=>{});}};
}
async function releasePortableStackMutationLease({store,lease}={}){
  if(!lease||!store?.compareAndSet)return;const current=await store.get('records',lease.key).catch(()=>null);if(current?.owner!==lease.owner||current?.leaseId!==lease.leaseId||current?.released===true)return;
  const now=Date.now();await store.compareAndSet('records',lease.key,current,{...current,released:true,releasedAt:now,expiresAt:now});
}

export async function withWgStackPortableStackMutationLease({store,ledger,operation='stack-readiness',mutationLeaseOptions={}}={},fn,{finalize=null}={}){
  if(typeof fn!=='function')throw new WGStackPortableApplicationError('portable stack mutation lease callback is required');
  const lease=await acquirePortableStackMutationLease({store,ledger,operation,...mutationLeaseOptions}),heartbeat=startPortableStackMutationLeaseHeartbeat({store,lease});
  let heartbeatStopped=false;
  try{
    const controls={lease,refresh:()=>refreshPortableStackMutationLease({store,lease})};
    const out=await fn(controls);
    await heartbeat.stop();heartbeatStopped=true;
    if(heartbeat.error)throw heartbeat.error;
    await refreshPortableStackMutationLease({store,lease});
    return typeof finalize==='function'?await finalize(out,controls):out;
  }finally{
    if(!heartbeatStopped)await heartbeat.stop();
    await releasePortableStackMutationLease({store,lease});
  }
}

function stackRecoveryRecordKey(stackTransactionId){return `wg-stack-portable-stack-recovery:${clean(stackTransactionId)}`;}
async function restorePortableStackState({state,recurrent,sfm,srnn,store}){
  const sr=await rollbackSrnn({srnn,store,before:state.srnn.snapshot,priorRecord:state.srnn.priorRecord});
  const sf=await rollbackSfm({sfm,store,before:state.sfm.snapshot,beforeRevision:state.sfm.revision,priorRecord:state.sfm.priorRecord});
  const rn=await rollbackRnn(recurrent,state.rnn.snapshot,state.rnn.revision);
  const restored=sr.restored===true&&sf.restored===true&&rn.restored===true;
  const current={rnn:{snapshot:recurrent.snapshot()},sfm:{snapshot:sfm.snapshot()},srnn:{snapshot:srnn.snapshot()}};
  return{restored,families:{rnn:rn,sfm_snapshot:sf,srnn:sr},digest:stackStateDigest(current)};
}

export function digestWgStackPortableLiveStackState({recurrent,sfm,srnn}={}){
  if(!recurrent||typeof recurrent.snapshot!=='function'||!sfm||typeof sfm.snapshot!=='function'||!srnn||typeof srnn.snapshot!=='function')throw new WGStackPortableApplicationError('RNN, SFM and SRNN live targets are required for portable stack state digest');
  return stackStateDigest({rnn:{snapshot:recurrent.snapshot()},sfm:{snapshot:sfm.snapshot()},srnn:{snapshot:srnn.snapshot()}});
}

function recoveryRowsForTransaction(rows,stackTransactionId){
  const tx=clean(stackTransactionId);
  return (rows||[]).filter(row=>clean(row?.body?.stackTransactionId)===tx);
}

export async function inspectWgStackPortableStackRecovery({ledger,recurrent,sfm,srnn,stackTransactionId=null}={}){
  if(!ledger?.store?.values)throw new WGStackPortableApplicationError('portable stack recovery inspection requires a readable witness ledger');
  const rows=(await ledger.store.values('witness')||[]).slice().sort((a,b)=>Number(a?.sequence??0)-Number(b?.sequence??0));
  const starts=rows.filter(row=>row?.type==='wg-stack-portable-stack-application-started'&&row?.body?.schema===WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA);
  const started=stackTransactionId?starts.find(row=>clean(row?.body?.stackTransactionId)===clean(stackTransactionId)):starts.at(-1);
  if(!started)throw new WGStackPortableApplicationError('no witnessed portable stack transaction is available for recovery inspection');
  const tx=clean(started.body.stackTransactionId),txRows=recoveryRowsForTransaction(rows,tx);
  const terminal=txRows.filter(row=>row.type==='wg-stack-portable-stack-applied'||row.type==='wg-stack-portable-stack-application-rollback').at(-1)||null;
  const familyApplications=txRows.filter(row=>row.type==='wg-stack-portable-family-applied');
  const familyRollbacks=txRows.filter(row=>row.type==='wg-stack-portable-family-application-rollback');
  const currentDigest=digestWgStackPortableLiveStackState({recurrent,sfm,srnn});
  const transactionStatus=terminal?.type==='wg-stack-portable-stack-applied'?'committed':terminal?.type==='wg-stack-portable-stack-application-rollback'?'compensated':'incomplete';
  const expectedDigest=terminal?.type==='wg-stack-portable-stack-applied'?clean(terminal.body?.afterDigest):terminal?.type==='wg-stack-portable-stack-application-rollback'?clean(terminal.body?.restoredDigest):clean(started.body?.beforeDigest);
  const stateMatchesTerminal=Boolean(expectedDigest)&&currentDigest===expectedDigest;
  const laterRows=terminal?rows.filter(row=>Number(row?.sequence??0)>Number(terminal.sequence??0)):[];
  let liveStateStatus='matches-terminal';
  if(!stateMatchesTerminal)liveStateStatus=laterRows.length?'mismatch-with-later-ledger-evidence':'mismatch-without-later-ledger-evidence';
  else if(transactionStatus==='incomplete')liveStateStatus='matches-pre-transaction-state';
  const expectedFamilies=Array.isArray(started.body?.decisionDigests)?started.body.decisionDigests.length:3;
  const ledgerComplete=transactionStatus==='committed'?Boolean(terminal)&&familyApplications.length===expectedFamilies:transactionStatus==='compensated'?Boolean(terminal)&&(terminal.body?.recoveryReconciled===true||familyApplications.length===familyRollbacks.length):true;
  const recoveryRequired=transactionStatus==='incomplete'||!stateMatchesTerminal||!ledgerComplete;
  return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,stack_transaction_id:tx,transaction_status:transactionStatus,started_witness_digest:started.digest,terminal_type:terminal?.type??null,terminal_witness_digest:terminal?.digest??null,before_digest:clean(started.body?.beforeDigest)||null,expected_digest:expectedDigest||null,current_digest:currentDigest,state_matches_terminal:stateMatchesTerminal,live_state_status:liveStateStatus,recovery_required:recoveryRequired,ledger_complete:ledgerComplete,permit_witness_digests:[...(started.body?.permitWitnessDigests||[])].map(clean),decision_digests:[...(started.body?.decisionDigests||[])].map(clean),candidate_digests:[...(started.body?.candidateDigests||[])].map(clean),family_application_count:familyApplications.length,family_rollback_count:familyRollbacks.length,later_witness_count:laterRows.length,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
}


export async function listWgStackPortableOpenTransactions({ledger,recurrent=null,sfm=null,srnn=null}={}){
  if(!ledger?.store?.values)throw new WGStackPortableApplicationError('portable stack recovery listing requires a readable witness ledger');
  const rows=(await ledger.store.values('witness')||[]).slice().sort((a,b)=>Number(a?.sequence??0)-Number(b?.sequence??0));
  const starts=rows.filter(row=>row?.type==='wg-stack-portable-stack-application-started'&&row?.body?.schema===WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA),out=[];
  for(const started of starts){
    const tx=clean(started.body?.stackTransactionId),txRows=recoveryRowsForTransaction(rows,tx),terminal=txRows.find(row=>row.type==='wg-stack-portable-stack-applied'||row.type==='wg-stack-portable-stack-application-rollback');
    if(terminal)continue;
    const currentDigest=recurrent&&sfm&&srnn?digestWgStackPortableLiveStackState({recurrent,sfm,srnn}):null,beforeDigest=clean(started.body?.beforeDigest)||null;
    out.push({schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,stack_transaction_id:tx,started_witness_digest:started.digest,started_sequence:Number(started.sequence??0),before_digest:beforeDigest,current_digest:currentDigest,state_matches_pretransaction:currentDigest==null?null:currentDigest===beforeDigest,permit_witness_digests:[...(started.body?.permitWitnessDigests||[])].map(clean),decision_digests:[...(started.body?.decisionDigests||[])].map(clean),candidate_digests:[...(started.body?.candidateDigests||[])].map(clean),family_application_count:txRows.filter(row=>row.type==='wg-stack-portable-family-applied').length,family_rollback_count:txRows.filter(row=>row.type==='wg-stack-portable-family-application-rollback').length,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY});
  }
  return out;
}

function newerPortableStackRecoveryBarrier(rows,started,{allowCompensatedNewer=false}={}){
  const newerStarts=(rows||[]).filter(row=>row?.type==='wg-stack-portable-stack-application-started'&&Number(row?.sequence??0)>Number(started?.sequence??0));
  if(!newerStarts.length)return null;
  if(!allowCompensatedNewer)return{reason:'newer-stack-transaction-exists',newerTransactionIds:newerStarts.map(row=>clean(row?.body?.stackTransactionId)).filter(Boolean)};
  for(const newer of newerStarts){
    const tx=clean(newer?.body?.stackTransactionId),txRows=recoveryRowsForTransaction(rows,tx),terminal=txRows.filter(row=>row?.type==='wg-stack-portable-stack-applied'||row?.type==='wg-stack-portable-stack-application-rollback').at(-1)||null;
    if(!terminal)return{reason:'newer-stack-transaction-open',newerTransactionId:tx};
    if(terminal.type!=='wg-stack-portable-stack-application-rollback')return{reason:'newer-stack-transaction-committed',newerTransactionId:tx,terminalWitnessDigest:terminal.digest??null};
    const beforeDigest=clean(newer?.body?.beforeDigest),restoredDigest=clean(terminal?.body?.restoredDigest);
    if(terminal?.body?.restored!==true||!beforeDigest||restoredDigest!==beforeDigest)return{reason:'newer-stack-transaction-not-exactly-compensated',newerTransactionId:tx,terminalWitnessDigest:terminal.digest??null,beforeDigest:beforeDigest||null,restoredDigest:restoredDigest||null};
  }
  return null;
}

async function reconcileWgStackPortableStackRecoveryUnlocked({ledger,recurrent,sfm,srnn,store,stackTransactionId=null,_mutationLease=null,_allowCompensatedNewer=false}={}){
  if(!store||typeof store.get!=='function'||typeof store.set!=='function')throw new WGStackPortableApplicationError('portable stack recovery reconciliation requires persistent store');
  const inspection=await inspectWgStackPortableStackRecovery({ledger,recurrent,sfm,srnn,stackTransactionId});
  if(inspection.recovery_required!==true)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'none',reason:'transaction-already-consistent',inspection,reconciled:false,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  if(inspection.transaction_status!=='incomplete')return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'manual-review-required',reason:'terminal-transaction-live-state-mismatch',inspection,reconciled:false,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  const rows=(await ledger.store.values('witness')||[]).slice().sort((a,b)=>Number(a?.sequence??0)-Number(b?.sequence??0));
  const started=rows.find(row=>row.type==='wg-stack-portable-stack-application-started'&&clean(row?.body?.stackTransactionId)===inspection.stack_transaction_id);
  if(!started)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'manual-review-required',reason:'started-witness-missing',inspection,reconciled:false,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  const newerBarrier=newerPortableStackRecoveryBarrier(rows,started,{allowCompensatedNewer:_allowCompensatedNewer===true});
  if(newerBarrier)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'manual-review-required',reason:newerBarrier.reason,inspection,reconciled:false,newer_barrier:newerBarrier,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  const journal=await store.get('records',stackRecoveryRecordKey(inspection.stack_transaction_id));
  if(!journal||journal.schema!==WG_STACK_PORTABLE_STACK_RECOVERY_JOURNAL_SCHEMA||clean(journal.stackTransactionId)!==inspection.stack_transaction_id||!journal.beforeState)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'manual-review-required',reason:'recovery-journal-missing-or-invalid',inspection,reconciled:false,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  const journalDigest=stackStateDigest(journal.beforeState);
  if(journalDigest!==inspection.before_digest)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action:'manual-review-required',reason:'recovery-journal-digest-mismatch',inspection,journal_digest:journalDigest,reconciled:false,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  await refreshPortableStackMutationLease({store,lease:_mutationLease});
  let restored={restored:true,digest:inspection.current_digest,families:{}};
  let action='sealed-pretransaction-state';
  if(inspection.current_digest!==inspection.before_digest){
    restored=await restorePortableStackState({state:journal.beforeState,recurrent,sfm,srnn,store});
    if(restored.restored!==true||restored.digest!==inspection.before_digest)throw new WGStackPortableApplicationError('portable stack recovery could not restore exact pre-transaction state',{rollback:restored});
    action='restored-pretransaction-state';
  }
  const txRows=recoveryRowsForTransaction(rows,inspection.stack_transaction_id),familyApplications=txRows.filter(row=>row.type==='wg-stack-portable-family-applied'),existingRollbacks=txRows.filter(row=>row.type==='wg-stack-portable-family-application-rollback');
  const rolledFamilies=new Set(existingRollbacks.map(row=>`${row.body?.family}:${Number(row.body?.index??0)}`)),compensationWitnesses=[];
  for(const row of [...familyApplications].reverse()){
    const family=clean(row.body?.family),index=Number(row.body?.index??0),k=`${family}:${index}`;if(rolledFamilies.has(k))continue;
    const rw=await ledger.append('wg-stack-portable-family-application-rollback',{schema:WG_STACK_PORTABLE_APPLICATION_ROLLBACK_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_APPLICATION_PROFILE,family,index:family==='srnn'?index:null,stackTransactionId:inspection.stack_transaction_id,decisionDigest:row.body?.decisionDigest??null,candidateDigest:row.body?.candidateDigest??null,permitWitnessDigest:row.body?.permitWitnessDigest??null,reason:'restart-reconciliation',restored:true,restoredDigest:row.body?.beforeDigest??inspection.before_digest,authority:false});compensationWitnesses.push(rw);rolledFamilies.add(k);
  }
  const allRollbacks=[...existingRollbacks,...compensationWitnesses];
  const terminal=await ledger.append('wg-stack-portable-stack-application-rollback',{schema:WG_STACK_PORTABLE_STACK_APPLICATION_ROLLBACK_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stackTransactionId:inspection.stack_transaction_id,startedWitnessDigest:started.digest,failedAt:'restart-reconciliation',reason:'restart-reconciliation',beforeDigest:inspection.before_digest,restoredDigest:inspection.before_digest,restored:true,applicationDigests:familyApplications.map(row=>row.body?.applicationDigest).filter(Boolean),applicationWitnessDigests:familyApplications.map(row=>row.digest).filter(Boolean),compensationWitnessDigests:allRollbacks.map(row=>row.digest).filter(Boolean),permitWitnessDigests:inspection.permit_witness_digests,recoveryReconciled:true,authority:false});
  const witness=await ledger.append('wg-stack-portable-stack-reconciled',{schema:WG_STACK_PORTABLE_STACK_RECONCILIATION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stackTransactionId:inspection.stack_transaction_id,startedWitnessDigest:started.digest,terminalWitnessDigest:terminal.digest,action,beforeDigest:inspection.before_digest,preReconcileDigest:inspection.current_digest,restoredDigest:inspection.before_digest,restored:restored.restored===true,authority:false});
  await store.set('records',stackRecoveryRecordKey(inspection.stack_transaction_id),{...journal,status:'reconciled',reconciledAt:Date.now(),action,terminalWitnessDigest:terminal.digest,reconciliationWitnessDigest:witness.digest,authority:false});
  const after=await inspectWgStackPortableStackRecovery({ledger,recurrent,sfm,srnn,stackTransactionId:inspection.stack_transaction_id});
  return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA,action,inspection:after,reconciled:true,terminal,witness,rollback:restored,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
}

async function preflightPortableStackFamily({decision,admission,evidence,permit,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime,recurrent,sfm,srnn,store,ledger,applicationData}){
  const verification=await verifyWgStackPortableFamilyGateDecision(decision,{admission,evidence,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime:targetRuntime??stage?.target_runtime});
  if(verification?.verified!==true||verification?.gate_ready!==true)throw new WGStackPortableApplicationError(`stack preflight requires verified gate-ready ${decision?.family} decision`);
  const externalPermit=validatePermit(permit,decision);await verifyPermitWitness(ledger,externalPermit);await assertPermitUnconsumed(ledger,externalPermit);
  const candidateRow=familyStageRow(stage,decision.family,decision.index),candidate=candidateRow?.candidate;
  if(!candidateRow||clean(candidateRow.candidate_digest)!==clean(decision.candidate_digest))throw new WGStackPortableApplicationError(`stack preflight staged ${decision.family} candidate mismatch`);
  if(decision.family==='rnn'){
    if(!recurrent||typeof recurrent.snapshot!=='function'||typeof recurrent.teachFromWitness!=='function')throw new WGStackPortableApplicationError('stack preflight requires RecurrentCore target');
    if(!finiteArray(candidate?.teacherState,recurrent.stateDim)||!finiteArray(applicationData?.input,recurrent.inputDim))throw new WGStackPortableApplicationError('stack preflight RNN candidate/input dimension mismatch');
  }else if(decision.family==='sfm_snapshot'){
    if(!sfm||typeof sfm.snapshot!=='function'||typeof sfm.restore!=='function'||typeof sfm.toJsInterchangeSnapshot!=='function')throw new WGStackPortableApplicationError('stack preflight requires WitnessSFM target');
    if(!store||typeof store.get!=='function'||typeof store.set!=='function'||typeof store.delete!=='function')throw new WGStackPortableApplicationError('stack preflight requires persistent store');
    if(Number(candidate?.stateDim)!==Number(sfm.recurrent?.stateDim)||Number(candidate?.inputDim)!==Number(sfm.recurrent?.inputDim))throw new WGStackPortableApplicationError('stack preflight SFM target dimensions mismatch');
  }else if(decision.family==='srnn'){
    if(!srnn||typeof srnn.snapshot!=='function'||typeof srnn.restore!=='function'||typeof srnn.proposeDirective!=='function')throw new WGStackPortableApplicationError('stack preflight requires WG-SRNN target');
    if(!store||typeof store.get!=='function'||typeof store.set!=='function'||typeof store.delete!=='function')throw new WGStackPortableApplicationError('stack preflight requires persistent store');
    if(candidate?.stage_type!=='internal_directive'||candidate?.native_payload?.schema!=='wg-srnn-internal-directive/v1')throw new WGStackPortableApplicationError('stack preflight only supports SRNN internal_directive candidates');
  }
  return{decision,admission,evidence,permit:externalPermit,candidateRow,applicationData:applicationData||{}};
}
async function applyWgStackPortableStackTransactionUnlocked({decisions=[],admissions=[],evidenceByFamily={},stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime=null,permits={},recurrent=null,sfm=null,srnn=null,store=null,ledger=null,applicationDataByFamily={},_mutationLease=null}={}){
  if(!ledger||typeof ledger.append!=='function')throw new WGStackPortableApplicationError('WitnessLedger-compatible ledger is required for portable stack application');
  if(!store||typeof store.get!=='function'||typeof store.set!=='function'||typeof store.delete!=='function')throw new WGStackPortableApplicationError('persistent store with get/set/delete is required for portable stack application');
  const ordered=orderedMutableDecisions(decisions);for(const family of ['rnn','sfm_snapshot','srnn'])if(!ordered.some(row=>row.family===family))throw new WGStackPortableApplicationError(`portable stack application is missing ${family} gate decision`);
  const preflight=[];
  for(const decision of ordered){
    await refreshPortableStackMutationLease({store,lease:_mutationLease});
    const admission=stackLookup(admissions,decision),evidence=stackLookup(evidenceByFamily,decision),permit=stackLookup(permits,decision),applicationData=stackLookup(applicationDataByFamily,decision)||{};
    if(!admission)throw new WGStackPortableApplicationError(`portable stack application is missing ${stackDecisionKey(decision)} admission`);
    if(!evidence)throw new WGStackPortableApplicationError(`portable stack application is missing ${stackDecisionKey(decision)} gate evidence`);
    if(!permit)throw new WGStackPortableApplicationError(`portable stack application is missing ${stackDecisionKey(decision)} external permit`);
    preflight.push(await preflightPortableStackFamily({decision,admission,evidence,permit,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime,recurrent,sfm,srnn,store,ledger,applicationData}));
    await refreshPortableStackMutationLease({store,lease:_mutationLease});
  }
  await refreshPortableStackMutationLease({store,lease:_mutationLease});
  const before=await capturePortableStackState({recurrent,sfm,srnn,store}),beforeDigest=stackStateDigest(before),applications=[];
  const permitWitnessDigests=preflight.map(x=>x.permit.permitWitnessDigest),decisionDigests=preflight.map(x=>x.decision.decision_digest),candidateDigests=preflight.map(x=>x.decision.candidate_digest);
  const stackTransactionId=digest({schema:WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,beforeDigest,decisionDigests,candidateDigests,permitWitnessDigests});
  const recoveryJournal={schema:WG_STACK_PORTABLE_STACK_RECOVERY_JOURNAL_SCHEMA,stackTransactionId,beforeDigest,beforeState:before,decisionDigests,candidateDigests,permitWitnessDigests,status:'prepared',createdAt:Date.now(),authority:false};
  await store.set('records',stackRecoveryRecordKey(stackTransactionId),recoveryJournal);
  let startedWitness;try{startedWitness=await ledger.append('wg-stack-portable-stack-application-started',{schema:WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stackTransactionId,beforeDigest,decisionDigests,candidateDigests,permitWitnessDigests,authorizationSource:'external-authority',authority:false});}catch(error){await store.delete('records',stackRecoveryRecordKey(stackTransactionId)).catch?.(()=>{});throw error;}
  await store.set('records',stackRecoveryRecordKey(stackTransactionId),{...recoveryJournal,status:'started',startedWitnessDigest:startedWitness.digest,startedAt:Date.now()});
  let activeKey='stack-start';
  try{
    for(const item of preflight){
      await refreshPortableStackMutationLease({store,lease:_mutationLease});
      activeKey=stackDecisionKey(item.decision);
      const applied=await applyWgStackPortableFamilyTransaction({decision:item.decision,admission:item.admission,evidence:item.evidence,stage,envelope,plan,localDescriptor,remoteDescriptor,stackManifest,targetRuntime,permit:item.permit,recurrent,sfm,srnn,store,ledger,applicationData:item.applicationData,stackTransactionId});
      applications.push({item,applied});
    }
    const afterState=await capturePortableStackState({recurrent,sfm,srnn,store}),afterDigest=stackStateDigest(afterState);if(afterDigest===beforeDigest)throw new Error('portable stack transaction produced no composite state change');
    const compactApps=applications.map(({item,applied})=>({family:item.decision.family,index:item.decision.index??null,decision_digest:item.decision.decision_digest,candidate_digest:item.decision.candidate_digest,permit_witness_digest:item.permit.permitWitnessDigest,application_digest:applied.result.application_digest,witness_digest:applied.witness?.digest??null,mode:applied.result.mode}));
    const result={schema:WG_STACK_PORTABLE_STACK_APPLICATION_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stack_transaction_id:stackTransactionId,before_digest:beforeDigest,after_digest:afterDigest,applications:compactApps,skipped_families:(stage?.families&&Object.prototype.hasOwnProperty.call(stage.families,'sfm_proposal'))?['sfm_proposal']:[],permit_witness_digests:preflight.map(x=>x.permit.permitWitnessDigest),mutation_applied:true,post_verified:true,authorization_source:'external-authority',authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};result.stack_application_digest=digestWgStackPortableStackApplication(result);
    activeKey='stack-finalize';
    await refreshPortableStackMutationLease({store,lease:_mutationLease});
    const witness=await ledger.append('wg-stack-portable-stack-applied',{schema:WG_STACK_PORTABLE_STACK_APPLICATION_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stackTransactionId,stackApplicationDigest:result.stack_application_digest,beforeDigest,afterDigest,applicationDigests:compactApps.map(x=>x.application_digest),applicationWitnessDigests:compactApps.map(x=>x.witness_digest).filter(Boolean),permitWitnessDigests:result.permit_witness_digests,skippedFamilies:result.skipped_families,mutationApplied:true,postVerified:true,authorizationSource:'external-authority',authority:false});
    await store.set('records',stackRecoveryRecordKey(stackTransactionId),{...recoveryJournal,status:'committed',startedWitnessDigest:startedWitness.digest,terminalWitnessDigest:witness.digest,afterDigest,completedAt:Date.now(),authority:false}).catch?.(()=>{});
    return{result,witness,startedWitness,applications:applications.map(x=>x.applied),rollback:null,authority:false};
  }catch(error){
    const restored=await restorePortableStackState({state:before,recurrent,sfm,srnn,store});
    const compensationWitnesses=[];
    for(const {item,applied} of [...applications].reverse()){
      const rb=restored.families[item.decision.family]||{restored:restored.restored,digest:restored.digest};
      const rw=await appendRollback(ledger,{family:item.decision.family,decision:item.decision,candidate:item.candidateRow,permit:item.permit,reason:`stack-compensation:${activeKey}:${error?.message??error}`,rollback:rb,stackTransactionId});if(rw)compensationWitnesses.push(rw);
    }
    let stackWitness=null;try{stackWitness=await ledger.append('wg-stack-portable-stack-application-rollback',{schema:WG_STACK_PORTABLE_STACK_APPLICATION_ROLLBACK_WITNESS_SCHEMA,profile_id:WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE,stackTransactionId,startedWitnessDigest:startedWitness.digest,failedAt:activeKey,reason:String(error?.message??error),beforeDigest,restoredDigest:restored.digest,restored:restored.restored===true,applicationDigests:applications.map(x=>x.applied.result.application_digest),applicationWitnessDigests:applications.map(x=>x.applied.witness?.digest).filter(Boolean),compensationWitnessDigests:compensationWitnesses.map(x=>x.digest),permitWitnessDigests:preflight.map(x=>x.permit.permitWitnessDigest),authority:false});}catch{}
    await store.set('records',stackRecoveryRecordKey(stackTransactionId),{...recoveryJournal,status:stackWitness?'compensated':'incomplete',startedWitnessDigest:startedWitness.digest,terminalWitnessDigest:stackWitness?.digest??null,restoredDigest:restored.digest,failedAt:activeKey,failedAtTime:Date.now(),authority:false}).catch?.(()=>{});
    throw new WGStackPortableApplicationError(`portable stack application rolled back at ${activeKey}: ${error?.message??error}`,{rollback:{...restored,witness:stackWitness,compensationWitnesses},cause:error});
  }
}

export async function reconcileWgStackPortableStackRecoveryChain(options={}){
  const {store,ledger,recurrent,sfm,srnn,mutationLeaseOptions={},maxTransactions=8}=options||{};
  if(!store||!ledger)throw new WGStackPortableApplicationError('portable stack recovery chain requires persistent store and witness ledger');
  const lease=await acquirePortableStackMutationLease({store,ledger,operation:'reconcile-chain',...mutationLeaseOptions}),heartbeat=startPortableStackMutationLeaseHeartbeat({store,lease});
  try{
    let open=await listWgStackPortableOpenTransactions({ledger,recurrent,sfm,srnn});
    if(open.length===0)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA,action:'none',reason:'no-open-transactions',reconciled:false,transaction_count:0,transactions:[],remaining_open_transactions:[],authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
    const limit=Math.max(1,Math.min(32,Number(maxTransactions)||8));
    if(open.length>limit)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA,action:'manual-review-required',reason:'recovery-chain-limit-exceeded',reconciled:false,transaction_count:open.length,max_transactions:limit,transactions:open.map(row=>row.stack_transaction_id),remaining_open_transactions:open,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
    const ordered=[...open].sort((a,b)=>Number(b.started_sequence??0)-Number(a.started_sequence??0)),results=[];
    for(const item of ordered){
      await refreshPortableStackMutationLease({store,lease});
      const result=await reconcileWgStackPortableStackRecoveryUnlocked({...options,stackTransactionId:item.stack_transaction_id,_mutationLease:lease,_allowCompensatedNewer:true});
      results.push(result);
      const safe=result?.reconciled===true||(result?.action==='none'&&result?.inspection?.recovery_required!==true);
      if(!safe){open=await listWgStackPortableOpenTransactions({ledger,recurrent,sfm,srnn});return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA,action:'manual-review-required',reason:result?.reason||'recovery-chain-step-failed',failed_transaction_id:item.stack_transaction_id,reconciled:false,transaction_count:ordered.length,results,remaining_open_transactions:open,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};}
    }
    open=await listWgStackPortableOpenTransactions({ledger,recurrent,sfm,srnn});
    if(open.length)return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA,action:'manual-review-required',reason:'recovery-chain-not-fully-closed',reconciled:false,transaction_count:ordered.length,results,remaining_open_transactions:open,authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
    return{schema:WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA,action:'reconciled-reverse-chain',reason:'all-open-transactions-exactly-compensated',reconciled:true,transaction_count:ordered.length,transactions:ordered.map(row=>row.stack_transaction_id),results,remaining_open_transactions:[],final_digest:digestWgStackPortableLiveStackState({recurrent,sfm,srnn}),authority:false,...WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY};
  }finally{await heartbeat.stop();await releasePortableStackMutationLease({store,lease});}
}

export async function reconcileWgStackPortableStackRecovery(options={}){
  const {store,ledger,mutationLeaseOptions={}}=options||{},lease=await acquirePortableStackMutationLease({store,ledger,operation:'reconcile',...mutationLeaseOptions}),heartbeat=startPortableStackMutationLeaseHeartbeat({store,lease});
  try{const out=await reconcileWgStackPortableStackRecoveryUnlocked({...options,_mutationLease:lease});if(heartbeat.error)throw heartbeat.error;return out;}finally{await heartbeat.stop();await releasePortableStackMutationLease({store,lease});}
}

export async function applyWgStackPortableStackTransaction(options={}){
  const {store,ledger,mutationLeaseOptions={}}=options||{},lease=await acquirePortableStackMutationLease({store,ledger,operation:'apply',...mutationLeaseOptions}),heartbeat=startPortableStackMutationLeaseHeartbeat({store,lease});
  try{const out=await applyWgStackPortableStackTransactionUnlocked({...options,_mutationLease:lease});if(heartbeat.error)throw heartbeat.error;return out;}finally{await heartbeat.stop();await releasePortableStackMutationLease({store,lease});}
}
