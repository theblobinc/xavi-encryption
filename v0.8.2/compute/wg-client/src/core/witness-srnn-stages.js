import { canonicalize, digest } from './utils.js';
import { WG_SRNN_LESSON_WITNESS_TYPES, WG_SRNN_LESSON_PROMOTED_SCHEMA, WG_SRNN_LESSON_EVALUATED_SCHEMA, WG_SRNN_LESSON_DEMOTED_SCHEMA, WG_SRNN_LESSON_SUPERSEDED_SCHEMA, wgSrnnLessonId, wgSrnnLessonReliability, projectWgSrnnLesson, applyWgSrnnLessonEvent, cloneWgSrnnLessonStates } from './witness-srnn-lessons.js';
export * from './witness-srnn-lessons.js';

export const WG_SRNN_STAGES_SCHEMA='xavi-wg-srnn-stages-js/v1';
export const WG_SRNN_SEMANTIC_ASSESSMENT_SCHEMA='xavi-wg-srnn-semantic-assessment/v1';
export const WG_SRNN_OUTCOME_WITNESS_SCHEMA='xavi-wg-srnn-outcome-witness/v1';
export const WG_SRNN_TEMPORAL_CREDIT_SCHEMA='xavi-wg-srnn-temporal-credit/v1';
export const WG_SRNN_LESSON_CANDIDATE_SCHEMA='xavi-wg-srnn-lesson-candidate/v1';
export const WG_SRNN_CAUSAL_GRAPH_SCHEMA='xavi-wg-srnn-causal-graph/v1';
export const WG_SRNN_CAUSAL_TRACE_SCHEMA='xavi-wg-srnn-causal-trace/v1';
export const WG_SRNN_LESSON_EXPLANATION_SCHEMA='xavi-wg-srnn-lesson-explanation/v1';
export const WG_SRNN_INTEGRITY_REPORT_SCHEMA='xavi-wg-srnn-integrity-report/v1';
export const WG_SRNN_INTEGRITY_MONITOR_SCHEMA='xavi-wg-srnn-integrity-monitor/v1';
export const WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA='xavi-wg-srnn-integrity-telemetry/v1';

export const WG_SRNN_STAGE_WITNESS_TYPES=new Set([
  'wg-srnn-semantic-assessment',
  'wg-srnn-outcome-witness',
  'wg-srnn-temporal-credit',
  'wg-srnn-lesson-candidate',
  ...WG_SRNN_LESSON_WITNESS_TYPES,
]);

const RELATIONS=new Set([
  'assesses','supported_by','contradicted_by','outcome_of',
  'credits_directive','credits_assessment','credits_outcome','records_terminal_outcome','authorized_by_learning','authorized_by_policy_mutation','learned_from_credit',
  'promotes_candidate','evaluates_lesson','demotes_lesson','supersedes_lesson',
]);

function text(value,max=512){const s=String(value??'').trim();return s?s.slice(0,max):null;}
function clone(value){return value==null?value:structuredClone(value);}
function clamp(value,min=0,max=1,fallback=.5){const n=Number(value);return Number.isFinite(n)?Math.max(min,Math.min(max,n)):fallback;}
function array(value,max=32){return (Array.isArray(value)?value:[]).filter(Boolean).slice(0,max);}
function identity(id,provenanceGroup=null){
  const identityId=text(typeof id==='object'?id.id:id,160);
  const group=text(typeof id==='object'?(id.provenanceGroup??id.group):provenanceGroup,160)||identityId;
  if(!identityId)throw new TypeError('identity id is required');
  return{id:identityId,provenanceGroup:group,authority:false};
}
function compactConsensusSummary(value){
  if(!value||typeof value!=='object')return null;
  return{
    score:clamp(value.score),threshold:clamp(value.threshold),agreement:clamp(value.agreement),sourceDiversity:clamp(value.sourceDiversity),
    independentEvidenceCount:Math.max(0,Number(value.independentEvidenceCount??value.sourceCount??0)),validatedEvidenceCount:Math.max(0,Number(value.validatedEvidenceCount||0)),conflictingEvidenceCount:Math.max(0,Number(value.conflictingEvidenceCount||0)),meanSourceReliability:clamp(value.meanSourceReliability??.5),
    representedEvidenceFamilies:array(value.representedEvidenceFamilies,8).map(v=>text(v,160)).filter(Boolean),
    claimSupport:array(value.claimSupport,8).map(row=>({claimKey:text(row?.claimKey,160),independentValidatedSources:Math.max(0,Number(row?.independentValidatedSources||0)),representedEvidenceFamilies:array(row?.representedEvidenceFamilies,6).map(v=>text(v,160)).filter(Boolean),supported:Boolean(row?.supported)})),
    authority:false,
  };
}
function assertIndependent(author,assessor){
  if(!author?.id||!assessor?.id)throw new TypeError('author and assessor identities are required');
  if(author.id===assessor.id)throw new Error(`independent witness identity required: ${assessor.id}`);
  if(author.provenanceGroup&&assessor.provenanceGroup&&author.provenanceGroup===assessor.provenanceGroup)throw new Error(`independent witness provenance required: ${assessor.provenanceGroup}`);
}
function edge(fromDigest,relation,toDigest,stageWitnessDigest=null){
  if(!RELATIONS.has(relation))throw new TypeError(`unsupported causal relation: ${relation}`);
  const from=text(fromDigest,192),to=text(toDigest,192);if(!from||!to)return null;
  return{fromDigest:from,relation,toDigest:to,stageWitnessDigest:text(stageWitnessDigest,192),authority:false};
}
function uniqueEdges(rows,max=512){
  const seen=new Set(),out=[];for(const row of rows){if(!row)continue;const key=`${row.fromDigest}|${row.relation}|${row.toDigest}`;if(seen.has(key))continue;seen.add(key);out.push(row);if(out.length>=max)break;}return out;
}
function stageRecord(witness){return{witnessDigest:witness.digest,sequence:witness.sequence,type:witness.type,...clone(witness.body),authority:false};}

export class WitnessGatedSelfReferentialStages {
  constructor({store,ledger,namespace='default',maxAssessments=128,maxOutcomes=128,maxCredits=256,maxLessons=128,maxLessonStates=128,maxLessonEvents=256,maxEdges=768,autoLessonPromotion=true,autoLessonDemotion=true,minLessonUsesForDemotion=3,lessonReliabilityFloor=.35,lessonMeanCreditFloor=-.15,integrityFullEvery=16,integrityFullAfterWitnesses=512,autoIntegrity=true,integrityAutoEveryWitnesses=32,maxIntegrityTelemetryEvents=32}={}){
    this.store=store;this.ledger=ledger;this.namespace=namespace;
    this.maxAssessments=Math.max(16,Math.floor(maxAssessments));this.maxOutcomes=Math.max(16,Math.floor(maxOutcomes));this.maxCredits=Math.max(32,Math.floor(maxCredits));this.maxLessons=Math.max(16,Math.floor(maxLessons));this.maxLessonStates=Math.max(16,Math.floor(maxLessonStates));this.maxLessonEvents=Math.max(32,Math.floor(maxLessonEvents));this.maxEdges=Math.max(64,Math.floor(maxEdges));
    this.autoLessonPromotion=autoLessonPromotion!==false;this.autoLessonDemotion=autoLessonDemotion!==false;this.minLessonUsesForDemotion=Math.max(2,Math.floor(Number(minLessonUsesForDemotion)||3));this.lessonReliabilityFloor=clamp(lessonReliabilityFloor,0,.5,.35);this.lessonMeanCreditFloor=Math.max(-1,Math.min(0,Number(lessonMeanCreditFloor)||-.15));
    this.stateKey=`wg-srnn-stages:${namespace}`;this.integrityTelemetryKey=`wg-srnn-integrity-telemetry:${namespace}`;this.maxIntegrityTelemetryEvents=Math.max(4,Math.min(128,Math.floor(Number(maxIntegrityTelemetryEvents)||32)));
    this.integrityFullEvery=Math.max(1,Math.floor(Number(integrityFullEvery)||16));this.integrityFullAfterWitnesses=Math.max(1,Math.floor(Number(integrityFullAfterWitnesses)||512));this.autoIntegrity=autoIntegrity!==false;this.integrityAutoEveryWitnesses=Math.max(1,Math.floor(Number(integrityAutoEveryWitnesses)||32));
    this._integrityAnchor=null;this._integrityAnchorVersion=0;this._integrityIncrementalChecks=0;this._integrityPendingWitnesses=0;this._integrityAutoRuns=0;this._integrityAutoFailures=0;this._integrityAutoSuperseded=0;this._integrityMonitorPaused=false;this._integrityAutoScheduled=false;this._integrityDisposed=false;this._integrityEpoch=0;this._integrityAutoQueue=Promise.resolve();this._integrityLastReport=null;this._integrityLastFailure=null;this._integrityLastError=null;this._integrityTelemetryQueue=Promise.resolve();this._integrityTelemetryError=null;this._integrityTelemetry=null;
    this._witnessIndex=new Map();this._unsubscribeLedger=null;
    this.state={schema:WG_SRNN_STAGES_SCHEMA,namespace,revision:0,assessments:[],outcomes:[],credits:[],lessons:[],lessonStates:[],lessonEvents:[],edges:[],ledgerVerified:false,reconstructedAt:0,updatedAt:0,authority:false};
  }
  async init(){
    const row=await this.store?.get?.('records',this.stateKey);
    if(row?.schema===WG_SRNN_STAGES_SCHEMA)this.restore(row);
    await this._loadIntegrityTelemetry();const integrityStarted=Date.now();const rebuilt=await this.rebuildFromLedger({force:true});
    await this._recordIntegrityTelemetry(rebuilt?.integrityReport||rebuilt,{source:'startup',latencyMs:Date.now()-integrityStarted});
    if(!rebuilt?.verified){
      this.state.ledgerVerified=false;
      throw new Error(`WG-SRNN stage ledger verification failed: ${rebuilt?.reason||'unknown'}`);
    }
    if(!this._unsubscribeLedger&&this.ledger?.subscribe)this._unsubscribeLedger=this.ledger.subscribe(row=>{if(row?.digest)this._witnessIndex.set(row.digest,row);this._noteIntegrityWitness(row);});
    return this;
  }
  dispose(){if(this._integrityDisposed)return;this._integrityDisposed=true;this._integrityEpoch+=1;this._unsubscribeLedger?.();this._unsubscribeLedger=null;}
  _witness(digestValue){const d=text(digestValue,192);return d?this._witnessIndex.get(d)||null:null;}
  _requireWitness(digestValue,{types=null,label='witness'}={}){const row=this._witness(digestValue);if(!row)throw new Error(`${label} must reference a witnessed ledger receipt`);if(Array.isArray(types)&&types.length&&!types.includes(row.type))throw new Error(`${label} must reference ${types.join(' or ')}`);return row;}
  snapshot(){return clone(this.state);}
  restore(row={}){
    this.state={schema:WG_SRNN_STAGES_SCHEMA,namespace:this.namespace,revision:Math.max(0,Number(row.revision||0)),assessments:array(row.assessments,this.maxAssessments).map(clone),outcomes:array(row.outcomes,this.maxOutcomes).map(clone),credits:array(row.credits,this.maxCredits).map(clone),lessons:array(row.lessons,this.maxLessons).map(clone),lessonStates:cloneWgSrnnLessonStates(row.lessonStates,this.maxLessonStates),lessonEvents:array(row.lessonEvents,this.maxLessonEvents).map(clone),edges:uniqueEdges(array(row.edges,this.maxEdges).map(clone),this.maxEdges),ledgerVerified:Boolean(row.ledgerVerified),reconstructedAt:Number(row.reconstructedAt||0),updatedAt:Number(row.updatedAt||0),authority:false};return this;
  }
  async _persist(){
    this.state.revision+=1;this.state.updatedAt=Date.now();
    this.state.assessments=this.state.assessments.slice(-this.maxAssessments);this.state.outcomes=this.state.outcomes.slice(-this.maxOutcomes);this.state.credits=this.state.credits.slice(-this.maxCredits);this.state.lessons=this.state.lessons.slice(-this.maxLessons);this.state.lessonStates=cloneWgSrnnLessonStates(this.state.lessonStates,this.maxLessonStates);this.state.lessonEvents=this.state.lessonEvents.slice(-this.maxLessonEvents);this.state.edges=uniqueEdges(this.state.edges.slice(-this.maxEdges),this.maxEdges);
    await this.store?.set?.('records',this.stateKey,this.snapshot());return this.state;
  }
  _edgesForWitness(witness){
    const b=witness.body||{},d=witness.digest,rows=[];
    if(witness.type==='wg-srnn-semantic-assessment'){
      rows.push(edge(d,'assesses',b.directiveDigest,d));for(const e of array(b.evidenceWitnessDigests,24))rows.push(edge(d,'supported_by',e,d));
    } else if(witness.type==='wg-srnn-outcome-witness'){
      rows.push(edge(d,'outcome_of',b.directiveDigest,d));if(b.assessmentDigest)rows.push(edge(b.assessmentDigest,b.status==='contradicted'?'contradicted_by':'supported_by',d,d));if(b.outcomeWitnessDigest)rows.push(edge(d,'records_terminal_outcome',b.outcomeWitnessDigest,d));
    } else if(witness.type==='wg-srnn-temporal-credit'){
      rows.push(edge(d,'credits_directive',b.directiveDigest,d));if(b.assessmentDigest)rows.push(edge(d,'credits_assessment',b.assessmentDigest,d));if(b.outcomeStageDigest)rows.push(edge(d,'credits_outcome',b.outcomeStageDigest,d));if(b.learningWitnessDigest)rows.push(edge(d,'authorized_by_learning',b.learningWitnessDigest,d));if(b.promotionWitnessDigest)rows.push(edge(d,'authorized_by_policy_mutation',b.promotionWitnessDigest,d));
    } else if(witness.type==='wg-srnn-lesson-candidate'){
      for(const c of array(b.creditWitnessDigests,32))rows.push(edge(d,'learned_from_credit',c,d));
    } else if(witness.type==='wg-srnn-lesson-promoted'){
      rows.push(edge(d,'promotes_candidate',b.candidateDigest,d));
    } else if(witness.type==='wg-srnn-lesson-evaluated'){
      rows.push(edge(d,'evaluates_lesson',b.candidateDigest,d));
    } else if(witness.type==='wg-srnn-lesson-demoted'){
      rows.push(edge(d,'demotes_lesson',b.candidateDigest,d));
    } else if(witness.type==='wg-srnn-lesson-superseded'){
      rows.push(edge(d,'supersedes_lesson',b.candidateDigest,d));
    }
    return rows.filter(Boolean);
  }
  async _verifyLedgerDetailed(rows,{parent=null,lastSequence=0,indexOffset=0}={}){
    let index=indexOffset;
    const fail=(row,detail,extra={})=>({verified:false,reason:'ledger-verification-failed',phase:'cryptographic',detail,witnessDigest:row?.digest||null,witnessType:row?.type||null,sequence:Number.isFinite(Number(row?.sequence))?Number(row.sequence):null,index,...extra});
    for(const row of rows){
      if(!row?.digest)return fail(row,'missing-digest');
      if(!Number.isFinite(Number(row.sequence)))return fail(row,'invalid-sequence');
      const {digest:claimed,...receipt}=row;const actual=await digest(canonicalize(receipt));if(actual!==claimed)return fail(row,'digest-mismatch',{claimedDigest:claimed,actualDigest:actual});
      if(lastSequence&&Number(row.sequence)!==lastSequence+1)return fail(row,'sequence-gap',{expectedSequence:lastSequence+1,actualSequence:Number(row.sequence)});
      if(row.parentDigest!==parent)return fail(row,'parent-mismatch',{expectedParentDigest:parent,actualParentDigest:row.parentDigest??null});
      parent=row.digest;lastSequence=Number(row.sequence);index+=1;
    }
    return{verified:true,reason:'verified',phase:'cryptographic',witnessCount:rows.length,lastSequence,headDigest:parent};
  }
  async _verifyLedger(rows){return (await this._verifyLedgerDetailed(rows)).verified;}
  _verifyStageReferences(rows,{minSequence=1}={}){
    const byDigest=new Map(rows.filter(row=>row?.digest).map(row=>[row.digest,row]));
    const fail=(row,field,reason)=>({verified:false,reason:'stage-reference-verification-failed',witnessDigest:row?.digest||null,witnessType:row?.type||null,field,detail:reason});
    const ref=(row,value,field,types=null,{required=true}={})=>{
      const d=text(value,192);if(!d)return required?fail(row,field,'missing-reference'):{verified:true,row:null};
      const target=byDigest.get(d);if(!target)return fail(row,field,'missing-witness');
      if(Array.isArray(types)&&types.length&&!types.includes(target.type))return fail(row,field,`unexpected-type:${target.type}`);
      if(Number(target.sequence)>=Number(row.sequence))return fail(row,field,'reference-not-prior');
      return{verified:true,row:target};
    };
    for(const row of rows){
      if(!WG_SRNN_STAGE_WITNESS_TYPES.has(row.type)||Number(row.sequence)<Number(minSequence||1))continue;const b=row.body||{};let check;
      if(row.type==='wg-srnn-semantic-assessment'){
        check=ref(row,b.directiveDigest,'directiveDigest',['wg-srnn-directive-proposed']);if(!check.verified)return check;
        const evidence=array(b.evidenceWitnessDigests,24);if(!evidence.length)return fail(row,'evidenceWitnessDigests','missing-evidence');for(const d of evidence){check=ref(row,d,'evidenceWitnessDigests');if(!check.verified)return check;}
      } else if(row.type==='wg-srnn-outcome-witness'){
        const directive=ref(row,b.directiveDigest,'directiveDigest',['wg-srnn-directive-proposed']);if(!directive.verified)return directive;
        const terminal=ref(row,b.outcomeWitnessDigest,'outcomeWitnessDigest',['terminal-outcome']);if(!terminal.verified)return terminal;
        if(b.assessmentDigest){const assessment=ref(row,b.assessmentDigest,'assessmentDigest',['wg-srnn-semantic-assessment']);if(!assessment.verified)return assessment;if(assessment.row.body?.directiveDigest!==b.directiveDigest)return fail(row,'assessmentDigest','assessment-directive-mismatch');}
      } else if(row.type==='wg-srnn-temporal-credit'){
        const directive=ref(row,b.directiveDigest,'directiveDigest',['wg-srnn-directive-proposed']);if(!directive.verified)return directive;
        const assessment=ref(row,b.assessmentDigest,'assessmentDigest',['wg-srnn-semantic-assessment']);if(!assessment.verified)return assessment;
        const outcome=ref(row,b.outcomeStageDigest,'outcomeStageDigest',['wg-srnn-outcome-witness']);if(!outcome.verified)return outcome;
        const learning=ref(row,b.learningWitnessDigest,'learningWitnessDigest',['learning-assessment']);if(!learning.verified)return learning;
        const mutation=ref(row,b.promotionWitnessDigest,'promotionWitnessDigest',['policy-promoted','policy-demoted']);if(!mutation.verified)return mutation;
        if(assessment.row.body?.directiveDigest!==b.directiveDigest)return fail(row,'assessmentDigest','assessment-directive-mismatch');
        if(outcome.row.body?.directiveDigest!==b.directiveDigest||outcome.row.body?.assessmentDigest!==b.assessmentDigest)return fail(row,'outcomeStageDigest','outcome-lineage-mismatch');
        const eligible=learning.row.body?.assessment?.candidateTrainingEligible===true||learning.row.body?.trainingEligible===true;if(!eligible)return fail(row,'learningWitnessDigest','learning-not-training-eligible');
        if(mutation.row.body?.parentLearningWitness!==b.learningWitnessDigest)return fail(row,'promotionWitnessDigest','mutation-learning-mismatch');
        const strategy=text(b.strategyId,256),learningStrategy=text(learning.row.body?.strategyId,256),mutationStrategy=text(mutation.row.body?.strategyId,256);if(strategy&&learningStrategy&&strategy!==learningStrategy)return fail(row,'learningWitnessDigest','learning-strategy-mismatch');if(strategy&&mutationStrategy&&strategy!==mutationStrategy)return fail(row,'promotionWitnessDigest','mutation-strategy-mismatch');
      } else if(row.type==='wg-srnn-lesson-candidate'){
        const credits=array(b.creditWitnessDigests,32);if(credits.length<2)return fail(row,'creditWitnessDigests','insufficient-credit-references');for(const d of credits){check=ref(row,d,'creditWitnessDigests',['wg-srnn-temporal-credit']);if(!check.verified)return check;}
      } else if(WG_SRNN_LESSON_WITNESS_TYPES.has(row.type)){
        const candidate=ref(row,b.candidateDigest,'candidateDigest',['wg-srnn-lesson-candidate']);if(!candidate.verified)return candidate;
        if(row.type==='wg-srnn-lesson-promoted'){
          for(const d of array(b.creditWitnessDigests,32)){check=ref(row,d,'creditWitnessDigests',['wg-srnn-temporal-credit']);if(!check.verified)return check;}
        } else if(row.type==='wg-srnn-lesson-evaluated'){
          check=ref(row,b.creditWitnessDigest,'creditWitnessDigest',['wg-srnn-temporal-credit']);if(!check.verified)return check;
          if(b.learningWitnessDigest){check=ref(row,b.learningWitnessDigest,'learningWitnessDigest',['learning-assessment']);if(!check.verified)return check;}
          if(b.promotionWitnessDigest){check=ref(row,b.promotionWitnessDigest,'promotionWitnessDigest',['policy-promoted','policy-demoted']);if(!check.verified)return check;}
        } else if(row.type==='wg-srnn-lesson-superseded'){
          check=ref(row,b.replacementCandidateDigest,'replacementCandidateDigest',['wg-srnn-lesson-candidate']);if(!check.verified)return check;
        }
      }
    }
    return{verified:true};
  }
  async _committedWitnessSnapshot(){
    if(this.ledger?.committedSnapshot)return this.ledger.committedSnapshot();
    const headBefore=await this.store?.get?.('meta','witnessHead')||null,sequenceBefore=Number(await this.store?.get?.('meta','witnessSequence')||0);
    const rows=(await this.store?.values?.('witness')||[]).filter(Boolean).sort((a,b)=>Number(a.sequence||0)-Number(b.sequence||0));
    const headAfter=await this.store?.get?.('meta','witnessHead')||null,sequenceAfter=Number(await this.store?.get?.('meta','witnessSequence')||0);
    return{schema:'xavi-witness-committed-snapshot/v1',namespace:this.namespace,rows,head:headAfter,sequence:sequenceAfter,metadataStable:headBefore===headAfter&&sequenceBefore===sequenceAfter,authority:false};
  }
  _verifyCommittedWitnessSnapshot(snapshot,crypto){
    const committedSequence=Math.max(0,Number(snapshot?.sequence||0)),committedHead=text(snapshot?.head,192),verifiedSequence=Math.max(0,Number(crypto?.lastSequence||0)),verifiedHead=text(crypto?.headDigest,192);
    if(snapshot?.metadataStable!==true)return{verified:false,detail:'commit-metadata-changed',committedSequence,committedHead,verifiedSequence,verifiedHead};
    if(verifiedSequence!==committedSequence)return{verified:false,detail:'commit-sequence-mismatch',committedSequence,committedHead,verifiedSequence,verifiedHead};
    if((verifiedHead||null)!==(committedHead||null))return{verified:false,detail:'commit-head-mismatch',committedSequence,committedHead,verifiedSequence,verifiedHead};
    return{verified:true,committedSequence,committedHead};
  }
  _fullIntegrityReport(rows,crypto){
    const stageRows=rows.filter(row=>WG_SRNN_STAGE_WITNESS_TYPES.has(row?.type));const typeCounts={};for(const row of stageRows)typeCounts[row.type]=(typeCounts[row.type]||0)+1;
    const head={lastSequence:crypto?.lastSequence||0,digest:crypto?.headDigest||null};
    return{schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'full',verified:true,cryptographicVerified:true,referencesVerified:true,reason:'verified',phase:'complete',failure:null,counts:{witnesses:rows.length,srnnStages:stageRows.length,stageTypes:typeCounts},head,rootAnchor:clone(head),continuationDepth:0,sinceFullWitnesses:0,authority:false};
  }
  async verifyHistoricalIntegrity(){
    const snapshot=await this._committedWitnessSnapshot(),rows=snapshot.rows;
    const stageRows=rows.filter(row=>WG_SRNN_STAGE_WITNESS_TYPES.has(row?.type));
    const typeCounts={};for(const row of stageRows)typeCounts[row.type]=(typeCounts[row.type]||0)+1;
    const crypto=await this._verifyLedgerDetailed(rows);
    if(!crypto.verified)return{schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'full',verified:false,cryptographicVerified:false,referencesVerified:null,reason:crypto.reason,phase:crypto.phase,failure:{detail:crypto.detail,witnessDigest:crypto.witnessDigest,witnessType:crypto.witnessType,sequence:crypto.sequence,index:crypto.index,claimedDigest:crypto.claimedDigest||null,actualDigest:crypto.actualDigest||null,expectedSequence:crypto.expectedSequence??null,actualSequence:crypto.actualSequence??null,expectedParentDigest:crypto.expectedParentDigest??null,actualParentDigest:crypto.actualParentDigest??null},counts:{witnesses:rows.length,srnnStages:stageRows.length,stageTypes:typeCounts},head:{lastSequence:rows.at(-1)?.sequence??0,digest:rows.at(-1)?.digest??null},authority:false};
    const committed=this._verifyCommittedWitnessSnapshot(snapshot,crypto);
    if(!committed.verified)return{schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'full',verified:false,cryptographicVerified:true,referencesVerified:null,reason:'witness-commit-verification-failed',phase:'snapshot',failure:committed,counts:{witnesses:rows.length,srnnStages:stageRows.length,stageTypes:typeCounts},head:{lastSequence:crypto.lastSequence||0,digest:crypto.headDigest||null},authority:false};
    const references=this._verifyStageReferences(rows);
    if(!references.verified)return{schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'full',verified:false,cryptographicVerified:true,referencesVerified:false,reason:references.reason,phase:'stage-reference',failure:{detail:references.detail||null,witnessDigest:references.witnessDigest||null,witnessType:references.witnessType||null,field:references.field||null},counts:{witnesses:rows.length,srnnStages:stageRows.length,stageTypes:typeCounts},head:{lastSequence:crypto.lastSequence||0,digest:crypto.headDigest||null},authority:false};
    return this._fullIntegrityReport(rows,crypto);
  }
  async verifyHistoricalIntegritySince(anchor){
    const validAnchor=anchor?.schema===WG_SRNN_INTEGRITY_REPORT_SCHEMA&&anchor?.verified===true&&anchor?.cryptographicVerified===true&&anchor?.referencesVerified===true&&anchor?.namespace===this.namespace&&Number.isFinite(Number(anchor?.head?.lastSequence))&&Number(anchor.head.lastSequence)>=0&&(Number(anchor.head.lastSequence)===0||Boolean(text(anchor?.head?.digest,192)));
    const anchorFailure=(detail,extra={})=>({schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'incremental',verified:false,cryptographicVerified:null,referencesVerified:null,reason:'anchor-verification-failed',phase:'anchor',failure:{detail,...extra},anchor:anchor?.head?{lastSequence:Number(anchor.head.lastSequence||0),digest:text(anchor.head.digest,192)}:null,counts:{checkedWitnesses:0,checkedSrnnStages:0,stageTypes:{}},authority:false});
    if(!validAnchor)return anchorFailure('invalid-anchor-report');
    const snapshot=await this._committedWitnessSnapshot(),rows=snapshot.rows;
    const anchorSequence=Number(anchor.head.lastSequence||0),anchorDigest=text(anchor.head.digest,192);
    if(anchorSequence>0){const anchorRow=rows.find(row=>Number(row.sequence)===anchorSequence);if(!anchorRow)return anchorFailure('anchor-sequence-missing',{expectedSequence:anchorSequence});if(anchorRow.digest!==anchorDigest)return anchorFailure('anchor-head-mismatch',{expectedDigest:anchorDigest,actualDigest:anchorRow.digest||null,sequence:anchorSequence});}
    const tail=rows.filter(row=>Number(row.sequence)>anchorSequence),stageRows=tail.filter(row=>WG_SRNN_STAGE_WITNESS_TYPES.has(row?.type));
    const typeCounts={};for(const row of stageRows)typeCounts[row.type]=(typeCounts[row.type]||0)+1;
    const crypto=await this._verifyLedgerDetailed(tail,{parent:anchorDigest,lastSequence:anchorSequence,indexOffset:anchorSequence});
    const rootAnchor=anchor?.rootAnchor?clone(anchor.rootAnchor):{lastSequence:anchorSequence,digest:anchorDigest},continuationDepth=Math.max(0,Number(anchor?.continuationDepth||0))+1,sinceFullWitnesses=Math.max(0,Number(anchor?.sinceFullWitnesses||0))+tail.length;
    const base={schema:WG_SRNN_INTEGRITY_REPORT_SCHEMA,namespace:this.namespace,mode:'incremental',anchor:{lastSequence:anchorSequence,digest:anchorDigest},rootAnchor,continuationDepth,sinceFullWitnesses,counts:{checkedWitnesses:tail.length,checkedSrnnStages:stageRows.length,stageTypes:typeCounts,totalWitnesses:rows.length},authority:false};
    if(!crypto.verified)return{...base,verified:false,cryptographicVerified:false,referencesVerified:null,reason:crypto.reason,phase:crypto.phase,failure:{detail:crypto.detail,witnessDigest:crypto.witnessDigest,witnessType:crypto.witnessType,sequence:crypto.sequence,index:crypto.index,claimedDigest:crypto.claimedDigest||null,actualDigest:crypto.actualDigest||null,expectedSequence:crypto.expectedSequence??null,actualSequence:crypto.actualSequence??null,expectedParentDigest:crypto.expectedParentDigest??null,actualParentDigest:crypto.actualParentDigest??null},head:{lastSequence:rows.at(-1)?.sequence??anchorSequence,digest:rows.at(-1)?.digest??anchorDigest}};
    const committed=this._verifyCommittedWitnessSnapshot(snapshot,crypto);
    if(!committed.verified)return{...base,verified:false,cryptographicVerified:true,referencesVerified:null,reason:'witness-commit-verification-failed',phase:'snapshot',failure:committed,head:{lastSequence:crypto.lastSequence||anchorSequence,digest:crypto.headDigest||anchorDigest}};
    const references=this._verifyStageReferences(rows,{minSequence:anchorSequence+1});
    if(!references.verified)return{...base,verified:false,cryptographicVerified:true,referencesVerified:false,reason:references.reason,phase:'stage-reference',failure:{detail:references.detail||null,witnessDigest:references.witnessDigest||null,witnessType:references.witnessType||null,field:references.field||null},head:{lastSequence:crypto.lastSequence||anchorSequence,digest:crypto.headDigest||anchorDigest}};
    return{...base,verified:true,cryptographicVerified:true,referencesVerified:true,reason:'verified',phase:'complete',failure:null,head:{lastSequence:crypto.lastSequence||anchorSequence,digest:crypto.headDigest||anchorDigest}};
  }
  _emptyIntegrityTelemetry(){return{schema:WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA,namespace:this.namespace,totalChecks:0,successfulChecks:0,failedChecks:0,fullChecks:0,incrementalChecks:0,automaticChecks:0,manualChecks:0,startupChecks:0,lastCheckAt:0,lastVerifiedHead:null,lastFailure:null,history:[],updatedAt:0,authority:false};}
  _sanitizeIntegrityTelemetry(row){
    const base=this._emptyIntegrityTelemetry();if(row?.schema!==WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA||row?.namespace!==this.namespace)return base;
    const n=v=>Math.max(0,Math.floor(Number(v)||0)),head=v=>v&&typeof v==='object'?{lastSequence:n(v.lastSequence),digest:text(v.digest,192)||null}:null;
    const history=(Array.isArray(row.history)?row.history:[]).slice(-this.maxIntegrityTelemetryEvents).map(event=>({at:n(event?.at),source:text(event?.source,32)||'unknown',verified:Boolean(event?.verified),mode:text(event?.mode,32)||null,phase:text(event?.phase,48)||null,reason:text(event?.reason,96)||null,latencyMs:Math.max(0,Number(event?.latencyMs)||0),anchorAdvanced:Boolean(event?.anchorAdvanced),lifecycleInvalidated:Boolean(event?.lifecycleInvalidated),forcedFull:Boolean(event?.forcedFull),checkedWitnesses:n(event?.checkedWitnesses),checkedSrnnStages:n(event?.checkedSrnnStages),head:head(event?.head),failure:event?.failure?{detail:text(event.failure.detail,160)||null,witnessDigest:text(event.failure.witnessDigest,192)||null,witnessType:text(event.failure.witnessType,96)||null,field:text(event.failure.field,96)||null}:null,authority:false}));
    return{...base,totalChecks:n(row.totalChecks),successfulChecks:n(row.successfulChecks),failedChecks:n(row.failedChecks),fullChecks:n(row.fullChecks),incrementalChecks:n(row.incrementalChecks),automaticChecks:n(row.automaticChecks),manualChecks:n(row.manualChecks),startupChecks:n(row.startupChecks),lastCheckAt:n(row.lastCheckAt),lastVerifiedHead:head(row.lastVerifiedHead),lastFailure:row.lastFailure?{at:n(row.lastFailure.at),phase:text(row.lastFailure.phase,48)||null,reason:text(row.lastFailure.reason,96)||null,detail:text(row.lastFailure.detail,160)||null}:null,history,updatedAt:n(row.updatedAt),authority:false};
  }
  async _loadIntegrityTelemetry(){try{this._integrityTelemetry=this._sanitizeIntegrityTelemetry(await this.store?.get?.('records',this.integrityTelemetryKey));this._integrityTelemetryError=null;}catch(error){this._integrityTelemetry=this._emptyIntegrityTelemetry();this._integrityTelemetryError=text(error?.message||error,512)||'integrity-telemetry-load-failed';}return clone(this._integrityTelemetry);}
  _integrityTelemetryEvent(report,{source='manual',latencyMs=0}={}){const counts=report?.counts||{};return{at:Date.now(),source:text(source,32)||'manual',verified:Boolean(report?.verified),mode:text(report?.mode,32)||null,phase:text(report?.phase,48)||null,reason:text(report?.reason,96)||null,latencyMs:Math.max(0,Number(latencyMs)||0),anchorAdvanced:Boolean(report?.anchorAdvanced),lifecycleInvalidated:Boolean(report?.lifecycleInvalidated),forcedFull:Boolean(report?.forcedFull),checkedWitnesses:Math.max(0,Math.floor(Number(counts.checkedWitnesses??counts.witnesses)||0)),checkedSrnnStages:Math.max(0,Math.floor(Number(counts.checkedSrnnStages??counts.srnnStages)||0)),head:report?.head?{lastSequence:Math.max(0,Math.floor(Number(report.head.lastSequence)||0)),digest:text(report.head.digest,192)||null}:null,failure:report?.failure?{detail:text(report.failure.detail,160)||null,witnessDigest:text(report.failure.witnessDigest,192)||null,witnessType:text(report.failure.witnessType,96)||null,field:text(report.failure.field,96)||null}:null,authority:false};}
  async _recordIntegrityTelemetry(report,options={}){
    if(this._integrityDisposed)return clone(this._integrityTelemetry||this._emptyIntegrityTelemetry());const event=this._integrityTelemetryEvent(report,options);
    this._integrityTelemetryQueue=this._integrityTelemetryQueue.then(async()=>{const t=this._integrityTelemetry||this._emptyIntegrityTelemetry(),source=event.source;const next={...t,totalChecks:t.totalChecks+1,successfulChecks:t.successfulChecks+(event.verified?1:0),failedChecks:t.failedChecks+(event.verified?0:1),fullChecks:t.fullChecks+(event.mode==='full'?1:0),incrementalChecks:t.incrementalChecks+(event.mode==='incremental'?1:0),automaticChecks:t.automaticChecks+(source==='automatic'?1:0),manualChecks:t.manualChecks+(source==='manual'?1:0),startupChecks:t.startupChecks+(source==='startup'?1:0),lastCheckAt:event.at,lastVerifiedHead:event.verified&&event.head?clone(event.head):t.lastVerifiedHead,lastFailure:event.verified?t.lastFailure:{at:event.at,phase:event.phase,reason:event.reason,detail:event.failure?.detail||null},history:[...(t.history||[]),event].slice(-this.maxIntegrityTelemetryEvents),updatedAt:Date.now(),authority:false};await this.store?.set?.('records',this.integrityTelemetryKey,next);this._integrityTelemetry=this._sanitizeIntegrityTelemetry(next);this._integrityTelemetryError=null;}).catch(error=>{this._integrityTelemetryError=text(error?.message||error,512)||'integrity-telemetry-persist-failed';});await this._integrityTelemetryQueue;return clone(this._integrityTelemetry||this._emptyIntegrityTelemetry());
  }
  integrityTelemetry(){return clone(this._integrityTelemetry||this._emptyIntegrityTelemetry());}
  async flushIntegrityTelemetry(){await this._integrityTelemetryQueue;return this.integrityTelemetry();}
  _noteIntegrityWitness(row){
    if(!this.autoIntegrity||this._integrityDisposed||this._integrityMonitorPaused||!row?.digest)return;
    this._integrityPendingWitnesses+=1;if(this._integrityPendingWitnesses>=this.integrityAutoEveryWitnesses)this._scheduleIntegrityMonitor();
  }
  _scheduleIntegrityMonitor(){
    if(!this.autoIntegrity||this._integrityDisposed||this._integrityMonitorPaused||this._integrityAutoScheduled)return;
    this._integrityAutoScheduled=true;
    this._integrityAutoQueue=this._integrityAutoQueue.then(()=>new Promise(resolve=>setTimeout(resolve,0))).then(async()=>{
      while(this.autoIntegrity&&!this._integrityDisposed&&!this._integrityMonitorPaused&&this._integrityPendingWitnesses>=this.integrityAutoEveryWitnesses){
        this._integrityPendingWitnesses=0;
        try{const lifecycleEpoch=this._integrityEpoch;const report=await this.checkIntegrity({source:'automatic'});if(this._integrityDisposed||lifecycleEpoch!==this._integrityEpoch)break;this._integrityAutoRuns+=1;this._integrityLastReport=clone(report);if(report?.anchorSuperseded){this._integrityAutoSuperseded+=1;const sequence=Number(await this.store?.get?.('meta','witnessSequence'));if(Number.isFinite(sequence)){const trustedSequence=Number(this._integrityAnchor?.head?.lastSequence||0);this._integrityPendingWitnesses=Math.max(0,sequence-trustedSequence);}continue;}if(!report?.verified){this._integrityAutoFailures+=1;this._integrityMonitorPaused=true;this._integrityLastFailure=clone(report);break;}const sequence=Number(await this.store?.get?.('meta','witnessSequence'));if(Number.isFinite(sequence)){const trustedSequence=Number(this._integrityAnchor?.head?.lastSequence||report?.head?.lastSequence||0);this._integrityPendingWitnesses=Math.max(0,sequence-trustedSequence);}}
        catch(error){this._integrityAutoFailures+=1;this._integrityMonitorPaused=true;this._integrityLastError=text(error?.message||error,512)||'automatic-integrity-check-failed';break;}
      }
    }).catch(error=>{this._integrityAutoFailures+=1;this._integrityMonitorPaused=true;this._integrityLastError=text(error?.message||error,512)||'automatic-integrity-queue-failed';}).finally(()=>{this._integrityAutoScheduled=false;if(this.autoIntegrity&&!this._integrityDisposed&&!this._integrityMonitorPaused&&this._integrityPendingWitnesses>=this.integrityAutoEveryWitnesses)this._scheduleIntegrityMonitor();});
  }
  async flushIntegrityMonitor(){for(;;){const queue=this._integrityAutoQueue;await queue;if(queue===this._integrityAutoQueue&&!this._integrityAutoScheduled)break;}return this.integrityMonitorStatus();}
  integrityMonitorStatus(){
    const anchor=this.currentIntegrityAnchor();return{schema:WG_SRNN_INTEGRITY_MONITOR_SCHEMA,namespace:this.namespace,enabled:this.autoIntegrity,disposed:this._integrityDisposed,paused:this._integrityMonitorPaused,pendingWitnesses:this._integrityPendingWitnesses,scheduled:this._integrityAutoScheduled,automaticRuns:this._integrityAutoRuns,automaticFailures:this._integrityAutoFailures,automaticSuperseded:this._integrityAutoSuperseded,checksSinceFull:this._integrityIncrementalChecks,autoEveryWitnesses:this.integrityAutoEveryWitnesses,fullEvery:this.integrityFullEvery,fullAfterWitnesses:this.integrityFullAfterWitnesses,anchor:anchor?{mode:anchor.mode||null,head:clone(anchor.head),rootAnchor:clone(anchor.rootAnchor),continuationDepth:Number(anchor.continuationDepth||0),sinceFullWitnesses:Number(anchor.sinceFullWitnesses||0)}:null,lastReport:this._integrityLastReport?{verified:Boolean(this._integrityLastReport.verified),mode:this._integrityLastReport.mode||null,phase:this._integrityLastReport.phase||null,reason:this._integrityLastReport.reason||null,anchorSuperseded:Boolean(this._integrityLastReport.anchorSuperseded),head:clone(this._integrityLastReport.head)}:null,lastFailure:this._integrityLastFailure?{phase:this._integrityLastFailure.phase||null,reason:this._integrityLastFailure.reason||null,failure:clone(this._integrityLastFailure.failure)}:null,lastError:this._integrityLastError,telemetry:{schema:WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA,totalChecks:this._integrityTelemetry?.totalChecks||0,successfulChecks:this._integrityTelemetry?.successfulChecks||0,failedChecks:this._integrityTelemetry?.failedChecks||0,historyCount:this._integrityTelemetry?.history?.length||0,lastCheckAt:this._integrityTelemetry?.lastCheckAt||0,lastVerifiedHead:clone(this._integrityTelemetry?.lastVerifiedHead),lastFailure:clone(this._integrityTelemetry?.lastFailure),error:this._integrityTelemetryError,authority:false},authority:false};
  }
  currentIntegrityAnchor(){return clone(this._integrityAnchor);}
  async checkIntegrity({forceFull=false,advance=true,source='manual'}={}){
    const integrityStarted=Date.now(),lifecycleEpoch=this._integrityEpoch,anchorVersion=this._integrityAnchorVersion;
    const current=this._integrityAnchor,currentSequence=Math.max(Number(current?.head?.lastSequence||0),Number(await this.store?.get?.('meta','witnessSequence')||0)),pendingWitnesses=Math.max(0,currentSequence-Number(current?.head?.lastSequence||0));
    const wouldReachFullWitnessBudget=Number(current?.sinceFullWitnesses||0)+pendingWitnesses>=this.integrityFullAfterWitnesses;
    const needsFull=Boolean(forceFull||!current||this._integrityIncrementalChecks>=this.integrityFullEvery||wouldReachFullWitnessBudget);
    const report=needsFull?await this.verifyHistoricalIntegrity():await this.verifyHistoricalIntegritySince(current);
    const lifecycleActive=!this._integrityDisposed&&lifecycleEpoch===this._integrityEpoch,anchorCurrent=anchorVersion===this._integrityAnchorVersion,anchorSuperseded=lifecycleActive&&!anchorCurrent;let advanced=false;if(report?.verified&&advance!==false&&lifecycleActive&&anchorCurrent){this._integrityAnchor=clone(report);this._integrityAnchorVersion+=1;this._integrityIncrementalChecks=report.mode==='full'?0:this._integrityIncrementalChecks+1;this._integrityMonitorPaused=false;this._integrityLastFailure=null;this._integrityLastError=null;advanced=true;}else if(!report?.verified&&lifecycleActive&&anchorCurrent){this._integrityMonitorPaused=true;this._integrityLastFailure=clone(report);}
    const result={...report,managed:true,forcedFull:needsFull,anchorAdvanced:advanced,anchorSuperseded,lifecycleInvalidated:!lifecycleActive,checksSinceFull:this._integrityIncrementalChecks,authority:false};await this._recordIntegrityTelemetry(result,{source,latencyMs:Date.now()-integrityStarted});return result;
  }
  async rebuildFromLedger({force=false}={}){
    if(!force&&this.state.ledgerVerified)return{rebuilt:false,reason:'already-verified',state:this.snapshot()};
    const snapshot=await this._committedWitnessSnapshot(),rows=snapshot.rows;
    const crypto=await this._verifyLedgerDetailed(rows);if(!crypto.verified){this.state.ledgerVerified=false;this._integrityAnchor=null;this._integrityAnchorVersion+=1;this._integrityIncrementalChecks=0;return{rebuilt:false,...crypto,state:this.snapshot()};}
    const committed=this._verifyCommittedWitnessSnapshot(snapshot,crypto);if(!committed.verified){this.state.ledgerVerified=false;this._integrityAnchor=null;this._integrityAnchorVersion+=1;this._integrityIncrementalChecks=0;return{rebuilt:false,verified:false,cryptographicVerified:true,referencesVerified:null,reason:'witness-commit-verification-failed',phase:'snapshot',failure:committed,state:this.snapshot()};}
    const references=this._verifyStageReferences(rows);if(!references.verified){this.state.ledgerVerified=false;this._integrityAnchor=null;this._integrityAnchorVersion+=1;this._integrityIncrementalChecks=0;return{rebuilt:false,...references,state:this.snapshot()};}
    this._witnessIndex=new Map(rows.filter(row=>row?.digest).map(row=>[row.digest,row]));
    const assessments=[],outcomes=[],credits=[],lessons=[],lessonStates=[],lessonEvents=[],edges=[];
    for(const row of rows){
      if(!WG_SRNN_STAGE_WITNESS_TYPES.has(row.type))continue;
      const record=stageRecord(row);if(row.type==='wg-srnn-semantic-assessment')assessments.push(record);else if(row.type==='wg-srnn-outcome-witness')outcomes.push(record);else if(row.type==='wg-srnn-temporal-credit')credits.push(record);else if(row.type==='wg-srnn-lesson-candidate')lessons.push(record);else if(WG_SRNN_LESSON_WITNESS_TYPES.has(row.type)){lessonEvents.push(record);applyWgSrnnLessonEvent(lessonStates,row);}edges.push(...this._edgesForWitness(row));
    }
    this.state={schema:WG_SRNN_STAGES_SCHEMA,namespace:this.namespace,revision:this.state.revision,assessments:assessments.slice(-this.maxAssessments),outcomes:outcomes.slice(-this.maxOutcomes),credits:credits.slice(-this.maxCredits),lessons:lessons.slice(-this.maxLessons),lessonStates:cloneWgSrnnLessonStates(lessonStates,this.maxLessonStates),lessonEvents:lessonEvents.slice(-this.maxLessonEvents),edges:uniqueEdges(edges,this.maxEdges),ledgerVerified:true,reconstructedAt:Date.now(),updatedAt:Date.now(),authority:false};const integrityReport=this._fullIntegrityReport(rows,crypto);this._integrityAnchor=clone(integrityReport);this._integrityAnchorVersion+=1;this._integrityIncrementalChecks=0;this._integrityPendingWitnesses=0;this._integrityMonitorPaused=false;this._integrityLastReport=clone(integrityReport);this._integrityLastFailure=null;this._integrityLastError=null;await this._persist();return{rebuilt:true,verified:true,integrityReport,state:this.snapshot()};
  }
  async assessDirective({directiveDigest,directiveAuthor='wg-rnn',directiveAuthorProvenanceGroup='wg-rnn',assessorIdentity,assessorProvenanceGroup=null,verdict='uncertain',confidence=.5,evidenceWitnessDigests=[],provenanceGroups=[],consensusSummary=null}={}){
    const directive=text(directiveDigest,192);if(!directive)throw new TypeError('directiveDigest is required');
    this._requireWitness(directive,{types:['wg-srnn-directive-proposed'],label:'directiveDigest'});
    const author=identity(directiveAuthor,directiveAuthorProvenanceGroup),assessor=identity(assessorIdentity,assessorProvenanceGroup);assertIndependent(author,assessor);
    const evidence=array(evidenceWitnessDigests,24).map(v=>text(v,192)).filter(Boolean);if(!evidence.length)throw new Error('independent semantic assessment requires at least one evidence witness');for(const e of evidence)this._requireWitness(e,{label:'evidenceWitnessDigest'});
    const groups=[...new Set([assessor.provenanceGroup,...array(provenanceGroups,16).map(v=>text(v,160)).filter(Boolean)])];
    const witness=await this.ledger.append('wg-srnn-semantic-assessment',{schema:WG_SRNN_SEMANTIC_ASSESSMENT_SCHEMA,directiveDigest:directive,directiveAuthor:author,assessor,verdict:text(verdict,64)||'uncertain',confidence:clamp(confidence),evidenceWitnessDigests:evidence,provenanceGroups:groups,consensusSummary:compactConsensusSummary(consensusSummary),authority:false});
    const record=stageRecord(witness);this.state.assessments.push(record);this.state.edges.push(...this._edgesForWitness(witness));this.state.ledgerVerified=true;await this._persist();return{assessment:record,witness,authority:false};
  }
  async recordOutcome({directiveDigest,assessmentDigest=null,outcomeWitnessDigest,observerIdentity='browser-runtime',observerProvenanceGroup='browser-runtime',directiveAuthor='wg-rnn',directiveAuthorProvenanceGroup='wg-rnn',status='unverified',actual=null}={}){
    const directive=text(directiveDigest,192),terminal=text(outcomeWitnessDigest,192);if(!directive||!terminal)throw new TypeError('directiveDigest and outcomeWitnessDigest are required');
    this._requireWitness(directive,{types:['wg-srnn-directive-proposed'],label:'directiveDigest'});this._requireWitness(terminal,{types:['terminal-outcome'],label:'outcomeWitnessDigest'});
    const sourceAssessment=assessmentDigest?this.state.assessments.find(row=>row.witnessDigest===text(assessmentDigest,192)):null;if(assessmentDigest&&!sourceAssessment)throw new Error('outcome stage requires a known semantic assessment');if(sourceAssessment&&sourceAssessment.directiveDigest!==directive)throw new Error('outcome assessment does not belong to directive');
    const author=identity(directiveAuthor,directiveAuthorProvenanceGroup),observer=identity(observerIdentity,observerProvenanceGroup);assertIndependent(author,observer);
    const witness=await this.ledger.append('wg-srnn-outcome-witness',{schema:WG_SRNN_OUTCOME_WITNESS_SCHEMA,directiveDigest:directive,assessmentDigest:text(assessmentDigest,192),outcomeWitnessDigest:terminal,observer,status:text(status,48)||'unverified',actual:actual&&typeof actual==='object'?clone(actual):null,authority:false});
    const record=stageRecord(witness);this.state.outcomes.push(record);this.state.edges.push(...this._edgesForWitness(witness));this.state.ledgerVerified=true;await this._persist();return{outcome:record,witness,authority:false};
  }
  async assignTemporalCredit({directiveDigest,assessmentDigest,outcomeStageDigest,learningWitnessDigest,promotionWitnessDigest,credit=0,creditorIdentity='learning-authority',creditorProvenanceGroup='learning-authority',directiveAuthor='wg-rnn',directiveAuthorProvenanceGroup='wg-rnn',capability=null,strategyId=null,provenanceGroups=[]}={}){
    const directive=text(directiveDigest,192),assessment=text(assessmentDigest,192),outcomeStage=text(outcomeStageDigest,192),learning=text(learningWitnessDigest,192),promotion=text(promotionWitnessDigest,192);
    if(!directive||!assessment||!outcomeStage||!learning||!promotion)throw new Error('temporal credit requires directive, independent assessment, outcome stage, learning witness, and promotion witness');
    const author=identity(directiveAuthor,directiveAuthorProvenanceGroup),creditor=identity(creditorIdentity,creditorProvenanceGroup);assertIndependent(author,creditor);
    const sourceAssessment=this.state.assessments.find(row=>row.witnessDigest===assessment);if(!sourceAssessment)throw new Error('temporal credit requires a known semantic assessment');if(sourceAssessment.directiveDigest!==directive)throw new Error('temporal credit assessment does not belong to directive');
    const sourceOutcome=this.state.outcomes.find(row=>row.witnessDigest===outcomeStage);if(!sourceOutcome)throw new Error('temporal credit requires a known outcome stage');if(sourceOutcome.directiveDigest!==directive||sourceOutcome.assessmentDigest!==assessment)throw new Error('temporal credit outcome lineage does not match directive and assessment');
    const learningRow=this._requireWitness(learning,{types:['learning-assessment'],label:'learningWitnessDigest'}),mutationRow=this._requireWitness(promotion,{types:['policy-promoted','policy-demoted'],label:'promotionWitnessDigest'});
    const eligible=learningRow.body?.assessment?.candidateTrainingEligible===true||learningRow.body?.trainingEligible===true;if(!eligible)throw new Error('temporal credit requires a training-eligible learning assessment');if(mutationRow.body?.parentLearningWitness!==learning)throw new Error('temporal credit policy mutation does not descend from learning assessment');
    const requestedStrategy=text(strategyId,256),learningStrategy=text(learningRow.body?.strategyId,256),mutationStrategy=text(mutationRow.body?.strategyId,256);if(requestedStrategy&&learningStrategy&&requestedStrategy!==learningStrategy)throw new Error('temporal credit learning strategy mismatch');if(requestedStrategy&&mutationStrategy&&requestedStrategy!==mutationStrategy)throw new Error('temporal credit policy mutation strategy mismatch');
    // Creditor identity proves the learning gate admitted the update; it is not an independent epistemic source.
    const groups=[...new Set([...array(sourceAssessment.provenanceGroups,16),...array(provenanceGroups,16)].map(v=>text(v,160)).filter(Boolean))];
    const witness=await this.ledger.append('wg-srnn-temporal-credit',{schema:WG_SRNN_TEMPORAL_CREDIT_SCHEMA,directiveDigest:directive,assessmentDigest:assessment,outcomeStageDigest:outcomeStage,learningWitnessDigest:learning,promotionWitnessDigest:promotion,creditor,capability:text(capability,192),strategyId:text(strategyId,256),credit:clamp(credit,-1,1,0),provenanceGroups:groups,authority:false});
    const record=stageRecord(witness);this.state.credits.push(record);this.state.edges.push(...this._edgesForWitness(witness));this.state.ledgerVerified=true;await this._persist();return{credit:record,witness,authority:false};
  }
  async formLessonCandidate({capability=null,strategyId=null,concept=null,creditWitnessDigests=[],minCredits=2,minIndependentGroups=2,minMeanCredit=0.25}={}){
    const cap=text(capability,192),strategy=text(strategyId,256),lessonConcept=text(concept,768);
    const wanted=new Set(array(creditWitnessDigests,32).map(String)),credits=this.state.credits.filter(row=>wanted.has(row.witnessDigest));
    if(credits.length<Math.max(2,Number(minCredits)||2))return{formed:false,reason:'insufficient-temporal-credit',authority:false};
    const groups=[...new Set(credits.flatMap(row=>array(row.provenanceGroups,16)))];if(groups.length<Math.max(2,Number(minIndependentGroups)||2))return{formed:false,reason:'insufficient-independent-provenance',groups,authority:false};
    const mean=credits.reduce((sum,row)=>sum+Number(row.credit||0),0)/credits.length;if(mean<Number(minMeanCredit||.25))return{formed:false,reason:'insufficient-positive-credit',meanCredit:mean,authority:false};
    const creditDigests=credits.map(row=>row.witnessDigest);
    const existing=this.state.lessons.find(row=>row.capability===cap&&row.strategyId===strategy&&row.concept===lessonConcept&&array(row.creditWitnessDigests,32).length===creditDigests.length&&creditDigests.every(d=>array(row.creditWitnessDigests,32).includes(d)));
    if(existing)return{formed:false,reason:'existing-lesson-candidate',lesson:clone(existing),authority:'candidate'};
    const witness=await this.ledger.append('wg-srnn-lesson-candidate',{schema:WG_SRNN_LESSON_CANDIDATE_SCHEMA,capability:cap,strategyId:strategy,concept:lessonConcept,creditWitnessDigests:credits.map(row=>row.witnessDigest),independentProvenanceGroups:groups,creditCount:credits.length,meanCredit:mean,authority:'candidate'});
    const record=stageRecord(witness);this.state.lessons.push(record);this.state.edges.push(...this._edgesForWitness(witness));this.state.ledgerVerified=true;await this._persist();return{formed:true,lesson:record,witness,authority:'candidate'};
  }
  async _recordLessonEvent(type,body={}){
    if(!WG_SRNN_LESSON_WITNESS_TYPES.has(type))throw new TypeError(`unsupported WG-SRNN lesson event: ${type}`);
    const witness=await this.ledger.append(type,{...body,authority:false});const record=stageRecord(witness);this.state.lessonEvents.push(record);applyWgSrnnLessonEvent(this.state.lessonStates,witness);this.state.edges.push(...this._edgesForWitness(witness));this.state.ledgerVerified=true;await this._persist();return{event:record,witness,lesson:this.state.lessonStates.find(row=>row.lessonId===(body.lessonId||wgSrnnLessonId(body.candidateDigest)))||null,authority:false};
  }
  activeLessons({capability=null,strategyId=null,limit=8}={}){
    const cap=text(capability,192),strategy=text(strategyId,256),n=Math.max(1,Math.min(16,Number(limit)||8));return this.state.lessonStates.filter(row=>row.status==='active'&&(!cap||row.capability===cap)&&(!strategy||row.strategyId===strategy)).map(row=>projectWgSrnnLesson(row)).filter(Boolean).sort((a,b)=>Math.abs(b.adjustment)-Math.abs(a.adjustment)||String(a.lessonId).localeCompare(String(b.lessonId))).slice(0,n);
  }
  async supersedeLesson({lessonId=null,candidateDigest=null,replacementCandidateDigest,reason='newer-independent-lesson'}={}){
    const id=text(lessonId,256)||wgSrnnLessonId(candidateDigest),row=this.state.lessonStates.find(item=>item.lessonId===id);if(!row||row.status!=='active')return{superseded:false,reason:'lesson-not-active',authority:false};
    const replacement=text(replacementCandidateDigest,192);if(!replacement)return{superseded:false,reason:'missing-replacement-candidate',authority:false};
    const result=await this._recordLessonEvent('wg-srnn-lesson-superseded',{schema:WG_SRNN_LESSON_SUPERSEDED_SCHEMA,lessonId:row.lessonId,candidateDigest:row.candidateDigest,replacementCandidateDigest:replacement,capability:row.capability,strategyId:row.strategyId,reason:text(reason,192)||'newer-independent-lesson',at:Date.now()});return{superseded:true,...result};
  }
  async promoteLessonCandidate({candidateDigest,promoterIdentity='learning-authority',promoterProvenanceGroup='learning-authority',supersedeExisting=true}={}){
    const candidateId=text(candidateDigest,192),candidate=this.state.lessons.find(row=>row.witnessDigest===candidateId);if(!candidate)return{promoted:false,reason:'unknown-lesson-candidate',authority:false};
    const lessonId=wgSrnnLessonId(candidateId),existing=this.state.lessonStates.find(row=>row.lessonId===lessonId&&row.status==='active');if(existing)return{promoted:false,reason:'lesson-already-active',lesson:projectWgSrnnLesson(existing),authority:false};
    if(supersedeExisting){for(const old of this.state.lessonStates.filter(row=>row.status==='active'&&row.capability===candidate.capability&&row.strategyId===candidate.strategyId&&row.candidateDigest!==candidateId))await this.supersedeLesson({lessonId:old.lessonId,replacementCandidateDigest:candidateId});}
    const promoter=identity(promoterIdentity,promoterProvenanceGroup);const result=await this._recordLessonEvent('wg-srnn-lesson-promoted',{schema:WG_SRNN_LESSON_PROMOTED_SCHEMA,lessonId,candidateDigest:candidateId,capability:candidate.capability||null,strategyId:candidate.strategyId||null,concept:candidate.concept||null,creditWitnessDigests:array(candidate.creditWitnessDigests,32),independentProvenanceGroups:array(candidate.independentProvenanceGroups,16),creditCount:Number(candidate.creditCount||0),meanCredit:Number(candidate.meanCredit||0),promoter,lessonAuthority:'advisory',at:Date.now()});return{promoted:true,...result,lesson:projectWgSrnnLesson(result.lesson)};
  }
  async demoteLesson({lessonId=null,candidateDigest=null,reason='bounded-performance-regression',triggerWitnessDigest=null}={}){
    const id=text(lessonId,256)||wgSrnnLessonId(candidateDigest),row=this.state.lessonStates.find(item=>item.lessonId===id);if(!row||row.status!=='active')return{demoted:false,reason:'lesson-not-active',authority:false};
    const result=await this._recordLessonEvent('wg-srnn-lesson-demoted',{schema:WG_SRNN_LESSON_DEMOTED_SCHEMA,lessonId:row.lessonId,candidateDigest:row.candidateDigest,capability:row.capability,strategyId:row.strategyId,reason:text(reason,192)||'bounded-performance-regression',triggerWitnessDigest:text(triggerWitnessDigest,192),at:Date.now()});return{demoted:true,...result,lesson:projectWgSrnnLesson(result.lesson)};
  }
  async evaluateLessonsForCredit({lessonIds=[],creditWitnessDigest,routeWitnessDigest=null,outcomeWitnessDigest=null}={}){
    const ids=[...new Set(array(lessonIds,16).map(v=>text(v,256)).filter(Boolean))];if(!ids.length)return{evaluated:[],demoted:[],authority:false};
    const creditDigest=text(creditWitnessDigest,192),source=this.state.credits.find(row=>row.witnessDigest===creditDigest);if(!source)throw new Error('lesson evaluation requires a known gate-admitted temporal credit witness');
    const evaluated=[],demoted=[];
    for(const id of ids){const row=this.state.lessonStates.find(item=>item.lessonId===id);if(!row||row.status!=='active')continue;if(row.capability!==source.capability||row.strategyId!==source.strategyId)continue;
      const result=await this._recordLessonEvent('wg-srnn-lesson-evaluated',{schema:WG_SRNN_LESSON_EVALUATED_SCHEMA,lessonId:row.lessonId,candidateDigest:row.candidateDigest,capability:row.capability,strategyId:row.strategyId,creditWitnessDigest:source.witnessDigest,learningWitnessDigest:source.learningWitnessDigest||null,promotionWitnessDigest:source.promotionWitnessDigest||null,routeWitnessDigest:text(routeWitnessDigest,192),outcomeWitnessDigest:text(outcomeWitnessDigest,192),credit:Number(source.credit||0),at:Date.now()});evaluated.push({witness:result.witness,lesson:projectWgSrnnLesson(result.lesson)});
      const after=this.state.lessonStates.find(item=>item.lessonId===id),projection=projectWgSrnnLesson(after);if(this.autoLessonDemotion&&projection.uses>=this.minLessonUsesForDemotion&&(projection.reliability<this.lessonReliabilityFloor||projection.meanCredit<this.lessonMeanCreditFloor)){const d=await this.demoteLesson({lessonId:id,reason:projection.reliability<this.lessonReliabilityFloor?'lesson-reliability-below-floor':'lesson-mean-credit-below-floor',triggerWitnessDigest:result.witness.digest});if(d.demoted)demoted.push(d);}
    }
    return{evaluated,demoted,authority:false};
  }
  async maybeFormLessonCandidate({capability=null,strategyId=null,concept=null,minCredits=2,minIndependentGroups=2,minMeanCredit=0.25,maxCredits=12}={}){
    const cap=text(capability,192),strategy=text(strategyId,256);if(!cap||!strategy)return{formed:false,reason:'missing-capability-or-strategy',authority:false};
    const positive=this.state.credits.filter(row=>row.capability===cap&&row.strategyId===strategy&&Number(row.credit||0)>0).slice(-Math.max(2,Math.min(32,Number(maxCredits)||12)));
    const lessonConcept=text(concept,768)||`Repeated independent temporal credit supports ${strategy} for ${cap}`;
    const formed=await this.formLessonCandidate({capability:cap,strategyId:strategy,concept:lessonConcept,creditWitnessDigests:positive.map(row=>row.witnessDigest),minCredits,minIndependentGroups,minMeanCredit});
    if(formed.formed&&this.autoLessonPromotion)formed.promotion=await this.promoteLessonCandidate({candidateDigest:formed.witness.digest});
    return formed;
  }
  graph({directiveDigest=null,limit=128}={}){
    const d=text(directiveDigest,192);let edges=this.state.edges;
    if(d){const related=new Set([d]);let changed=true;while(changed){changed=false;for(const e of edges)if(related.has(e.fromDigest)||related.has(e.toDigest)){const n=[e.fromDigest,e.toDigest];for(const v of n)if(!related.has(v)){related.add(v);changed=true;}}}edges=edges.filter(e=>related.has(e.fromDigest)||related.has(e.toDigest));}
    return{schema:WG_SRNN_CAUSAL_GRAPH_SCHEMA,namespace:this.namespace,edges:edges.slice(-Math.max(1,Math.min(512,Number(limit)||128))).map(clone),verified:Boolean(this.state.ledgerVerified),authority:false};
  }
  _causalNodeIndex(){
    const map=new Map(),put=(row,kind=null)=>{const body=row?.body&&typeof row.body==='object'?row.body:row,d=text(row?.witnessDigest??row?.digest??body?.witnessDigest,192);if(!d)return;map.set(d,{digest:d,kind:kind||row.type||'stage',type:row.type||null,sequence:Number(row.sequence||0)||null,capability:text(body?.capability,192),strategyId:text(body?.strategyId,256),directiveDigest:text(body?.directiveDigest,192),candidateDigest:text(body?.candidateDigest,192),status:text(body?.status??body?.verdict,96),credit:Number.isFinite(Number(body?.credit))?Number(body.credit):null,concept:text(body?.concept,384),authority:false});};
    for(const row of this._witnessIndex.values())put(row,'witness');for(const row of this.state.assessments)put(row,'semantic-assessment');for(const row of this.state.outcomes)put(row,'outcome');for(const row of this.state.credits)put(row,'temporal-credit');for(const row of this.state.lessons)put(row,'lesson-candidate');for(const row of this.state.lessonEvents)put(row,'lesson-lifecycle');
    return map;
  }
  traceCausality({focusDigest,maxDepth=4,limit=96,relations=null,direction='both'}={}){
    const focus=text(focusDigest,192);if(!focus)throw new TypeError('focusDigest is required');if(!this.state.ledgerVerified)throw new Error('WG-SRNN causal trace requires a verified witness ledger');
    const depthLimit=Math.max(0,Math.min(8,Math.floor(Number(maxDepth)||0))),edgeLimit=Math.max(1,Math.min(256,Math.floor(Number(limit)||96))),dir=['incoming','outgoing','both'].includes(direction)?direction:'both';
    const relationSet=Array.isArray(relations)&&relations.length?new Set(relations.map(v=>text(v,64)).filter(v=>RELATIONS.has(v))):null;
    const eligible=this.state.edges.filter(e=>!relationSet||relationSet.has(e.relation)),queue=[{digest:focus,depth:0}],seenDepth=new Map([[focus,0]]),walk=[],usedEdges=new Set();let truncated=false;
    while(queue.length){const current=queue.shift();if(current.depth>=depthLimit)continue;for(const e of eligible){let traversalDirection=null,next=null;if((dir==='both'||dir==='outgoing')&&e.fromDigest===current.digest){traversalDirection='outgoing';next=e.toDigest;}else if((dir==='both'||dir==='incoming')&&e.toDigest===current.digest){traversalDirection='incoming';next=e.fromDigest;}else continue;const key=`${e.fromDigest}|${e.relation}|${e.toDigest}`;if(!usedEdges.has(key)){if(walk.length>=edgeLimit){truncated=true;break;}usedEdges.add(key);walk.push({...clone(e),traversalFromDigest:current.digest,traversalToDigest:next,traversalDirection,depth:current.depth+1,authority:false});}const nextDepth=current.depth+1;if(!seenDepth.has(next)||nextDepth<seenDepth.get(next)){seenDepth.set(next,nextDepth);queue.push({digest:next,depth:nextDepth});}}if(truncated)break;}
    const index=this._causalNodeIndex(),nodes=[...seenDepth.entries()].sort((a,b)=>a[1]-b[1]||String(a[0]).localeCompare(String(b[0]))).map(([digest,depth])=>({...clone(index.get(digest)||{digest,kind:'witness-reference',type:null,authority:false}),depth,focus:digest===focus,authority:false}));
    return{schema:WG_SRNN_CAUSAL_TRACE_SCHEMA,namespace:this.namespace,focusDigest:focus,maxDepth:depthLimit,direction:dir,relations:relationSet?[...relationSet]:null,nodes,edges:walk,truncated,verified:true,authority:false};
  }
  explainLesson({lessonId=null,candidateDigest=null,maxDepth=5,limit=128,relations=null}={}){
    const id=text(lessonId,256),candidate=text(candidateDigest,192);const state=this.state.lessonStates.find(row=>(id&&row.lessonId===id)||(candidate&&row.candidateDigest===candidate))||null;const candidateId=candidate||state?.candidateDigest||null;if(!candidateId)return{schema:WG_SRNN_LESSON_EXPLANATION_SCHEMA,namespace:this.namespace,found:false,lesson:null,candidate:null,lifecycleEvents:[],trace:null,verified:Boolean(this.state.ledgerVerified),authority:false};
    const candidateRow=this.state.lessons.find(row=>row.witnessDigest===candidateId)||null,lifecycleEvents=this.state.lessonEvents.filter(row=>row.candidateDigest===candidateId||row.lessonId===state?.lessonId).slice(-32).map(clone);
    return{schema:WG_SRNN_LESSON_EXPLANATION_SCHEMA,namespace:this.namespace,found:Boolean(state||candidateRow),lesson:projectWgSrnnLesson(state),candidate:candidateRow?clone(candidateRow):null,lifecycleEvents,trace:this.traceCausality({focusDigest:candidateId,maxDepth,limit,relations,direction:'both'}),verified:Boolean(this.state.ledgerVerified),authority:false};
  }
  publicProjection({limit=6}={}){
    const n=Math.max(1,Math.min(16,Number(limit)||6));return{schema:'xavi-wg-srnn-stages-context/v1',assessments:this.state.assessments.slice(-n).map(clone),outcomes:this.state.outcomes.slice(-n).map(clone),credits:this.state.credits.slice(-n).map(clone),lessons:this.state.lessons.slice(-n).map(clone),lessonStates:this.state.lessonStates.slice(-n).map(row=>projectWgSrnnLesson(row)).filter(Boolean),lessonAdvice:this.activeLessons({limit:n}),lessonEvents:this.state.lessonEvents.slice(-n).map(clone),graph:this.graph({limit:n*8}),authority:false};
  }
}
