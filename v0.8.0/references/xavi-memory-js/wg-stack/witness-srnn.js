import { digest } from './utils.js';
import { WitnessGatedSelfReferentialStages } from './witness-srnn-stages.js';
import { wgSrnnConfidenceCalibrationContext, wgSrnnStrategyComparisonContext, wgSrnnReconsiderationContext, wgSrnnReflectionAgendaContext } from './witness-srnn-reflection.js';
import { buildWgSfmAssessmentRequests, sealWgSfmAssessmentFromConsensus } from './witness-sfm-assessor.js';
import { wgSrnnSelfCalibrationContext, wgSrnnDependencyReflectionContext, wgSrnnEpisodicSelfSummaryContext, wgSrnnCommitmentSelfReferenceContext, wgSrnnResumeContext } from './witness-srnn-resume.js';
import { verifySrnnInterchangeProjection, normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeInterchangeLineageKey, srnnRuntimeImportRequirements } from './witness-srnn-interchange.js';

export const WG_SRNN_SCHEMA='xavi-wg-srnn-js/v1';
export const WG_SRNN_DIRECTIVE_SCHEMA='xavi-wg-srnn-directive/v1';
export const WG_SRNN_COMMITMENT_SCHEMA='xavi-wg-srnn-commitment/v1';

function text(value,max=512){
  const s=String(value??'').trim();return s?s.slice(0,max):null;
}
function finite01(value,fallback=0.5){const n=Number(value);return Number.isFinite(n)?Math.max(0,Math.min(1,n)):fallback;}
function boundedArray(value,max=12){return (Array.isArray(value)?value:[]).filter(Boolean).slice(0,max);}
function compactExpected(value){
  if(value==null)return null;
  if(typeof value==='string'||typeof value==='number'||typeof value==='boolean')return value;
  if(typeof value!=='object')return text(value,256);
  const out={};
  for(const key of ['expectedNextType','nextWitnessType','operation','targetHint','ok','validated','conflict','compatibility','feasible']){
    if(value[key]!==undefined)out[key]=value[key];
  }
  return Object.keys(out).length?out:null;
}
function clone(value){return value==null?value:structuredClone(value);}
function compactSelfReference(value){
  if(!value||typeof value!=='object')return{used:false,evidenceCount:0,directiveCount:0,commitmentCount:0,outcomeCount:0,authority:false};
  const directiveCount=Array.isArray(value.directives)?value.directives.length:0,commitmentCount=Array.isArray(value.commitments)?value.commitments.length:0,outcomeCount=Array.isArray(value.outcomes)?value.outcomes.length:0,evidenceCount=directiveCount+commitmentCount+outcomeCount;
  return{used:evidenceCount>0,evidenceCount,directiveCount,commitmentCount,outcomeCount,authority:false};
}
function calibrationKey(capability,strategyId){return `${String(capability||'')}|${String(strategyId||'')}`;}
function calibrationProjection(row,maxAdjustment=.12){
  const attempts=Math.max(0,Number(row?.attempts||0)),successes=Math.max(0,Number(row?.successes||0)),rewardSum=Number(row?.rewardSum||0);
  const reliability=(successes+1)/(attempts+2),meanReward=attempts?Math.max(-1,Math.min(1,rewardSum/attempts)):0;
  const adjustment=Math.max(-maxAdjustment,Math.min(maxAdjustment,(reliability-.5)*.24+meanReward*.04));
  return{strategyId:row?.strategyId||null,capability:row?.capability||null,attempts,successes,reliability,meanReward,adjustment,updatedAt:Number(row?.updatedAt||0),lastCalibrationWitnessDigest:row?.lastCalibrationWitnessDigest||null,authority:false};
}
function resultStatus({validated=true,ok=false,partial=false}={}){
  if(validated===false)return'unverified';
  if(partial===true)return'partial';
  return ok?'confirmed':'contradicted';
}
function publicDirective(row){if(!row)return null;return{directiveId:row.directiveId,directiveDigest:row.directiveDigest||null,capability:row.capability||null,goal:row.goal||null,proposedAction:row.proposedAction||null,strategyId:row.strategyId||null,selfReference:clone(row.selfReference),justificationEdges:boundedArray(row.justificationEdges,12),sourceStateDigest:row.sourceStateDigest||null,routeWitnessDigest:row.routeWitnessDigest||null,baseConfidence:row.baseConfidence??row.confidence,confidence:row.confidence,lessonAdjustment:Number(row.lessonAdjustment||0),lessonAdvice:boundedArray(row.lessonAdvice,4).map(clone),status:row.status,expectedOutcome:clone(row.expectedOutcome),actualOutcome:clone(row.actualOutcome),semanticAssessmentDigest:row.semanticAssessmentDigest||null,outcomeStageDigest:row.outcomeStageDigest||null,temporalCreditDigest:row.temporalCreditDigest||null,lessonCandidateDigest:row.lessonCandidateDigest||null,lessonPromotionDigest:row.lessonPromotionDigest||null,lessonEvaluationWitnessDigests:boundedArray(row.lessonEvaluationWitnessDigests,8),commitmentId:row.commitmentId||null,createdAt:row.createdAt,settledAt:row.settledAt||null,authority:false};}
function publicCommitment(row){if(!row)return null;return{commitmentId:row.commitmentId,directiveDigest:row.directiveDigest||null,capability:row.capability||null,goal:row.goal||null,status:row.status,createdAt:row.createdAt,updatedAt:row.updatedAt,authority:false};}

export class WitnessGatedSelfReferentialNeuralNetwork {
  constructor({store,ledger,namespace='default',maxDirectives=64,maxCommitments=32,maxHistory=128,maxSelfReferenceAdjustment=0.12,stages=null}={}){
    this.store=store;this.ledger=ledger;this.namespace=namespace;
    this.maxDirectives=Math.max(8,Math.floor(maxDirectives));this.maxCommitments=Math.max(4,Math.floor(maxCommitments));this.maxHistory=Math.max(16,Math.floor(maxHistory));this.maxSelfReferenceAdjustment=Math.max(0,Math.min(.2,Number(maxSelfReferenceAdjustment)||.12));
    this.stages=stages||new WitnessGatedSelfReferentialStages({store,ledger,namespace});
    this.stateKey=`wg-srnn:${namespace}`;
    this.state={schema:WG_SRNN_SCHEMA,namespace,revision:0,directives:[],commitments:[],history:[],calibration:{},updatedAt:0,authority:false};
  }
  async init(){const row=await this.store?.get?.('records',this.stateKey);if(row?.schema===WG_SRNN_SCHEMA)this.restore(row);await this.stages?.init?.();return this;}
  snapshot(){return clone(this.state);}
  restore(row={}){
    this.state={schema:WG_SRNN_SCHEMA,namespace:this.namespace,revision:Math.max(0,Number(row.revision||0)),directives:boundedArray(row.directives,this.maxDirectives).map(clone),commitments:boundedArray(row.commitments,this.maxCommitments).map(clone),history:boundedArray(row.history,this.maxHistory).map(clone),calibration:row.calibration&&typeof row.calibration==='object'?clone(row.calibration):{},updatedAt:Number(row.updatedAt||0),authority:false};return this;
  }
  async _persist(options={}){this.state.revision+=1;this.state.updatedAt=Date.now();this.state.directives=this.state.directives.slice(-this.maxDirectives);this.state.commitments=this.state.commitments.slice(-this.maxCommitments);this.state.history=this.state.history.slice(-this.maxHistory);const next=this.snapshot(),guarded=Object.prototype.hasOwnProperty.call(options||{},'expectedRecord')&&this.store?.compareAndSet;if(guarded){const result=await this.store.compareAndSet('records',this.stateKey,options.expectedRecord,next);if(!result?.updated)throw new Error('WG-SRNN persistence compare-and-set fence conflict');}else await this.store?.set?.('records',this.stateKey,next);return this.state;}
  _findDirective(ref){return this.state.directives.find(row=>row.directiveId===ref||row.directiveDigest===ref)||null;}
  _findCommitment(ref){return this.state.commitments.find(row=>row.commitmentId===ref)||null;}
  _history(kind,data={}){this.state.history.push({kind,at:Date.now(),...data,authority:false});}
  publicProjection({capability=null,limit=6}={}){
    const cap=capability==null?null:String(capability);const directives=this.state.directives.filter(row=>!cap||row.capability===cap).slice(-limit).map(publicDirective);
    const commitments=this.state.commitments.filter(row=>row.status==='active'&&(!cap||row.capability===cap)).slice(-limit).map(publicCommitment);
    const outcomes=this.state.history.filter(row=>row.kind==='directive-settled'&&(!cap||row.capability===cap)).slice(-limit).map(clone);
    const strategyAdvice=Object.values(this.state.calibration||{}).filter(row=>!cap||row.capability===cap).map(row=>calibrationProjection(row,this.maxSelfReferenceAdjustment)).sort((a,b)=>Math.abs(b.adjustment)-Math.abs(a.adjustment)||String(a.strategyId).localeCompare(String(b.strategyId))).slice(0,8);
    const lessonAdvice=this.stages?.activeLessons?.({capability:cap,limit:8})||[];
    return{schema:'xavi-wg-srnn-context/v1',namespace:this.namespace,currentGoals:commitments.map(row=>row.goal).filter(Boolean),commitments,directives,outcomes,strategyAdvice,lessonAdvice,stages:this.stages?.publicProjection?.({limit})||null,metrics:this.metrics(),authority:false};
  }
  metrics(){
    const settled=this.state.directives.filter(row=>row.settledAt);const counts={confirmed:0,contradicted:0,partial:0,unverified:0};for(const row of settled)if(counts[row.status]!==undefined)counts[row.status]+=1;
    const stages=this.stages?.publicProjection?.({limit:16});const lessonStates=stages?.lessonStates||[];return{directiveCount:this.state.directives.length,activeCommitments:this.state.commitments.filter(row=>row.status==='active').length,settledCount:settled.length,...counts,stageCounts:stages?{assessments:stages.assessments.length,outcomes:stages.outcomes.length,credits:stages.credits.length,lessons:stages.lessons.length,activeLessons:lessonStates.filter(row=>row.status==='active').length,demotedLessons:lessonStates.filter(row=>row.status==='demoted').length,supersededLessons:lessonStates.filter(row=>row.status==='superseded').length}:null,authority:false};
  }
  async proposeDirective({author='wg-rnn',capability=null,strategyId=null,goal=null,proposedAction=null,justificationEdges=[],sourceStateDigest=null,routeWitnessDigest=null,confidence=0.5,expectedOutcome=null,semantic=null,wgSfm=null,selfContext=null,commit=false,persistenceGuard=null}={}){
    const now=Date.now(),baseConfidence=finite01(confidence),lessonAdvice=(this.stages?.activeLessons?.({capability,strategyId,limit:4})||[]).map(row=>({lessonId:row.lessonId,candidateDigest:row.candidateDigest,capability:row.capability,strategyId:row.strategyId,concept:row.concept,reliability:row.reliability,adjustment:row.adjustment,lastWitnessDigest:row.lastWitnessDigest,authority:false}));const lessonAdjustment=Math.max(-.08,Math.min(.08,lessonAdvice.reduce((sum,row)=>sum+Number(row.adjustment||0),0)));const lessonEdges=lessonAdvice.map(row=>row.lastWitnessDigest).filter(Boolean);const base={schema:WG_SRNN_DIRECTIVE_SCHEMA,author:text(author,96)||'wg-rnn',target:'self',capability:text(capability,192),strategyId:text(strategyId,256),goal:text(goal,768),proposedAction:text(proposedAction,256),selfReference:compactSelfReference(selfContext),justificationEdges:boundedArray([...boundedArray(justificationEdges,12),...lessonEdges],12).map(v=>text(v,192)).filter(Boolean),sourceStateDigest:text(sourceStateDigest,192),routeWitnessDigest:text(routeWitnessDigest,192),baseConfidence,confidence:finite01(baseConfidence+lessonAdjustment),lessonAdjustment,lessonAdvice,expectedOutcome:compactExpected(expectedOutcome),semantic:semantic?{intent:semantic.intent??null,nextOperation:semantic.nextOperation??null,targetHint:semantic.targetHint??null,expectedWitnessDelta:compactExpected(semantic.expectedWitnessDelta),authority:false}:null,wgSfm:wgSfm?{operation:wgSfm.operation??null,targetHint:wgSfm.targetHint??null,expectedWitnessType:wgSfm.expectedWitnessType??null,confidence:wgSfm.confidence??null,authority:false}:null,authority:'proposal',witnessStatus:'unverified',status:'proposed',createdAt:now};
    const directiveId=`directive:${await digest({namespace:this.namespace,routeWitnessDigest:base.routeWitnessDigest,goal:base.goal,proposedAction:base.proposedAction,createdAt:now})}`;
    const witness=await this.ledger.append('wg-srnn-directive-proposed',{directiveId,...base,authority:false});
    const row={...base,directiveId,directiveDigest:witness.digest,authority:false};this.state.directives.push(row);this._history('directive-proposed',{directiveId,directiveDigest:witness.digest,capability:row.capability,goal:row.goal,proposedAction:row.proposedAction});
    let commitment=null;if(commit&&row.goal)commitment=await this.createCommitment({directiveDigest:witness.digest,capability:row.capability,goal:row.goal,reason:'explicit-goal'});else await this._persist(persistenceGuard||{});
    return{directive:publicDirective(this._findDirective(directiveId)),witness,commitment};
  }
  async createCommitment({directiveDigest=null,capability=null,goal,reason='explicit'}={}){
    const g=text(goal,768);if(!g)return null;const now=Date.now();const commitmentId=`commitment:${await digest({namespace:this.namespace,directiveDigest,goal:g,createdAt:now})}`;
    const witness=await this.ledger.append('wg-srnn-commitment-created',{commitmentId,directiveDigest:text(directiveDigest,192),capability:text(capability,192),goal:g,reason:text(reason,128),status:'active',authority:false});
    const row={schema:WG_SRNN_COMMITMENT_SCHEMA,commitmentId,directiveDigest:text(directiveDigest,192),capability:text(capability,192),goal:g,reason:text(reason,128),status:'active',createdAt:now,updatedAt:now,witnessDigest:witness.digest,authority:false};this.state.commitments.push(row);
    const directive=this._findDirective(directiveDigest);if(directive)directive.commitmentId=commitmentId;
    this._history('commitment-created',{commitmentId,directiveDigest:row.directiveDigest,capability:row.capability,goal:g});await this._persist();return{commitment:publicCommitment(row),witness};
  }
  async recordAction({directiveDigest,routeWitnessDigest=null,executionWitnessDigest=null,strategyId=null}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return null;const witness=await this.ledger.append('wg-srnn-action-recorded',{directiveDigest:directive.directiveDigest,routeWitnessDigest:text(routeWitnessDigest,192),executionWitnessDigest:text(executionWitnessDigest,192),strategyId:text(strategyId,256),proposedAction:directive.proposedAction,authority:false});directive.status='acted';directive.actionWitnessDigest=witness.digest;directive.executionWitnessDigest=text(executionWitnessDigest,192);this._history('action-recorded',{directiveDigest:directive.directiveDigest,routeWitnessDigest:text(routeWitnessDigest,192),executionWitnessDigest:text(executionWitnessDigest,192),strategyId:text(strategyId,256),capability:directive.capability});await this._persist();return{directive:publicDirective(directive),witness};
  }
  async settleDirective({directiveDigest,routeWitnessDigest=null,outcomeWitnessDigest=null,predictionAssessmentDigest=null,learningWitnessDigest=null,promotionWitnessDigest=null,outcome={},reward=null,goalComplete=false}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return null;const status=resultStatus({validated:outcome.validated!==false,ok:Boolean(outcome.ok),partial:Boolean(outcome.partial)});const now=Date.now();
    const actual={ok:Boolean(outcome.ok),validated:outcome.validated!==false,nextWitnessType:text(outcome?.semanticActual?.nextWitnessType??outcome?.nextWitnessType,128),targetHint:text(outcome?.semanticTarget??outcome?.targetHint,256),conflict:typeof outcome?.semanticConflict==='boolean'?outcome.semanticConflict:(typeof outcome?.conflict==='boolean'?outcome.conflict:null)};
    const witness=await this.ledger.append('wg-srnn-directive-settled',{directiveDigest:directive.directiveDigest,routeWitnessDigest:text(routeWitnessDigest,192),outcomeWitnessDigest:text(outcomeWitnessDigest,192),predictionAssessmentDigest:text(predictionAssessmentDigest,192),learningWitnessDigest:text(learningWitnessDigest,192),promotionWitnessDigest:text(promotionWitnessDigest,192),predicted:clone(directive.expectedOutcome),actual,status,reward:Number.isFinite(Number(reward))?Number(reward):null,authority:false});
    directive.status=status;directive.witnessStatus=status==='unverified'?'unverified':'witnessed';directive.settledAt=now;directive.outcomeWitnessDigest=text(outcomeWitnessDigest,192);directive.predictionAssessmentDigest=text(predictionAssessmentDigest,192);directive.learningWitnessDigest=text(learningWitnessDigest,192);directive.promotionWitnessDigest=text(promotionWitnessDigest,192);directive.settlementWitnessDigest=witness.digest;directive.actualOutcome=actual;
    const commitment=directive.commitmentId?this._findCommitment(directive.commitmentId):null;if(commitment){if(goalComplete&&status==='confirmed')commitment.status='completed';else if(status==='contradicted')commitment.status='needs-revision';commitment.updatedAt=now;}
    this._history('directive-settled',{directiveDigest:directive.directiveDigest,routeWitnessDigest:text(routeWitnessDigest,192),outcomeWitnessDigest:text(outcomeWitnessDigest,192),predictionAssessmentDigest:text(predictionAssessmentDigest,192),learningWitnessDigest:text(learningWitnessDigest,192),promotionWitnessDigest:text(promotionWitnessDigest,192),capability:directive.capability,goal:directive.goal,proposedAction:directive.proposedAction,status,reward:Number.isFinite(Number(reward))?Number(reward):null});await this._persist();return{directive:publicDirective(directive),commitment:publicCommitment(commitment),witness,status,authority:false};
  }
  async learnSelfReference({directiveDigest,capability=null,strategyId=null,reward=0,outcome={},routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null,promotionWitnessDigest=null}={}){
    const directive=this._findDirective(directiveDigest);
    if(!directive?.selfReference?.used)return{updated:false,reason:'no-prior-self-reference',authority:false};
    if(!learningWitnessDigest||!promotionWitnessDigest)return{updated:false,reason:'learning-gate-not-admitted',authority:false};
    const cap=text(capability??directive.capability,192),strategy=text(strategyId??directive.strategyId,256);if(!cap||!strategy)return{updated:false,reason:'missing-capability-or-strategy',authority:false};
    const key=calibrationKey(cap,strategy),current=this.state.calibration[key]||{capability:cap,strategyId:strategy,attempts:0,successes:0,rewardSum:0,updatedAt:0};
    const boundedReward=Math.max(-1,Math.min(1,Number(reward)||0)),success=Boolean(outcome?.ok&&outcome?.validated!==false);
    const next={...current,capability:cap,strategyId:strategy,attempts:Number(current.attempts||0)+1,successes:Number(current.successes||0)+(success?1:0),rewardSum:Number(current.rewardSum||0)+boundedReward,updatedAt:Date.now(),lastDirectiveDigest:directive.directiveDigest,lastLearningWitnessDigest:text(learningWitnessDigest,192),lastPromotionWitnessDigest:text(promotionWitnessDigest,192)};
    const projected=calibrationProjection(next,this.maxSelfReferenceAdjustment);
    const witness=await this.ledger.append('wg-srnn-self-reference-calibrated',{directiveDigest:directive.directiveDigest,routeWitnessDigest:text(routeWitnessDigest,192),outcomeWitnessDigest:text(outcomeWitnessDigest,192),learningWitnessDigest:text(learningWitnessDigest,192),promotionWitnessDigest:text(promotionWitnessDigest,192),capability:cap,strategyId:strategy,priorSelfReference:clone(directive.selfReference),attempts:projected.attempts,successes:projected.successes,reliability:projected.reliability,meanReward:projected.meanReward,adjustment:projected.adjustment,authority:false});
    next.lastCalibrationWitnessDigest=witness.digest;this.state.calibration[key]=next;this._history('self-reference-calibrated',{directiveDigest:directive.directiveDigest,capability:cap,strategyId:strategy,reliability:projected.reliability,adjustment:projected.adjustment,witnessDigest:witness.digest});await this._persist();
    return{updated:true,row:calibrationProjection(next,this.maxSelfReferenceAdjustment),witness,authority:false};
  }
  async verifyIntegrity(){return this.stages?.verifyHistoricalIntegrity?.()||{verified:false,reason:'stages-unavailable',authority:false};}
  async verifyIntegritySince(anchor){return this.stages?.verifyHistoricalIntegritySince?.(anchor)||{verified:false,reason:'stages-unavailable',authority:false};}
  integrityAnchor(){return this.stages?.currentIntegrityAnchor?.()||null;}
  async checkIntegrity(options={}){return this.stages?.checkIntegrity?.(options)||{verified:false,reason:'stages-unavailable',authority:false};}
  integrityMonitorStatus(){return this.stages?.integrityMonitorStatus?.()||{enabled:false,paused:true,reason:'stages-unavailable',authority:false};}
  async flushIntegrityMonitor(){return this.stages?.flushIntegrityMonitor?.()||this.integrityMonitorStatus();}
  integrityTelemetry(){return this.stages?.integrityTelemetry?.()||null;}
  async flushIntegrityTelemetry(){return this.stages?.flushIntegrityTelemetry?.()||this.integrityTelemetry();}
  async assessDirective({directiveDigest,assessorIdentity,assessorProvenanceGroup=null,verdict='uncertain',confidence=.5,evidenceWitnessDigests=[],provenanceGroups=[],consensusSummary=null}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return{accepted:false,reason:'directive-not-found',authority:false};
    try{const result=await this.stages.assessDirective({directiveDigest:directive.directiveDigest,directiveAuthor:directive.author,directiveAuthorProvenanceGroup:directive.author,assessorIdentity,assessorProvenanceGroup,verdict,confidence,evidenceWitnessDigests,provenanceGroups,consensusSummary});directive.semanticAssessmentDigest=result?.witness?.digest||null;await this._persist();return{accepted:true,...result};}catch(error){return{accepted:false,reason:String(error?.message||error),authority:false};}
  }
  async recordOutcomeStage({directiveDigest,assessmentDigest=null,outcomeWitnessDigest,observerIdentity='browser-runtime',observerProvenanceGroup='browser-runtime',status='unverified',actual=null}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return{recorded:false,reason:'directive-not-found',authority:false};
    try{const result=await this.stages.recordOutcome({directiveDigest:directive.directiveDigest,assessmentDigest:assessmentDigest||directive.semanticAssessmentDigest||null,outcomeWitnessDigest,observerIdentity,observerProvenanceGroup,directiveAuthor:directive.author,directiveAuthorProvenanceGroup:directive.author,status,actual});directive.outcomeStageDigest=result?.witness?.digest||null;await this._persist();return{recorded:true,...result};}catch(error){return{recorded:false,reason:String(error?.message||error),authority:false};}
  }
  async assignTemporalCredit({directiveDigest,assessmentDigest=null,outcomeStageDigest=null,learningWitnessDigest,promotionWitnessDigest,credit=0,creditorIdentity='learning-authority',creditorProvenanceGroup='learning-authority',provenanceGroups=[]}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return{credited:false,reason:'directive-not-found',authority:false};
    try{const result=await this.stages.assignTemporalCredit({directiveDigest:directive.directiveDigest,assessmentDigest:assessmentDigest||directive.semanticAssessmentDigest||null,outcomeStageDigest:outcomeStageDigest||directive.outcomeStageDigest||null,learningWitnessDigest,promotionWitnessDigest,credit,creditorIdentity,creditorProvenanceGroup,directiveAuthor:directive.author,directiveAuthorProvenanceGroup:directive.author,capability:directive.capability,strategyId:directive.strategyId,provenanceGroups});directive.temporalCreditDigest=result?.witness?.digest||null;await this._persist();return{credited:true,...result};}catch(error){return{credited:false,reason:String(error?.message||error),authority:false};}
  }
  async formLessonCandidate({directiveDigest=null,concept=null,creditWitnessDigests=[],minCredits=2,minIndependentGroups=2,minMeanCredit=.25}={}){
    const directive=directiveDigest?this._findDirective(directiveDigest):null;const result=await this.stages.formLessonCandidate({capability:directive?.capability||null,strategyId:directive?.strategyId||null,concept,creditWitnessDigests,minCredits,minIndependentGroups,minMeanCredit});if(result?.witness&&directive){directive.lessonCandidateDigest=result.witness.digest;await this._persist();}return result;
  }
  async maybeFormLessonCandidate({directiveDigest,concept=null,minCredits=2,minIndependentGroups=2,minMeanCredit=.25}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return{formed:false,reason:'directive-not-found',authority:false};const result=await this.stages.maybeFormLessonCandidate({capability:directive.capability,strategyId:directive.strategyId,concept,minCredits,minIndependentGroups,minMeanCredit});if(result?.witness){directive.lessonCandidateDigest=result.witness.digest;directive.lessonPromotionDigest=result.promotion?.witness?.digest||null;await this._persist();}return result;
  }
  activeLessons({capability=null,strategyId=null,limit=8}={}){return this.stages?.activeLessons?.({capability,strategyId,limit})||[];}
  async promoteLessonCandidate(options={}){return this.stages?.promoteLessonCandidate?.(options)||{promoted:false,reason:'stages-unavailable',authority:false};}
  async evaluateDirectiveLessons({directiveDigest,creditWitnessDigest,routeWitnessDigest=null,outcomeWitnessDigest=null}={}){
    const directive=this._findDirective(directiveDigest);if(!directive)return{evaluated:[],demoted:[],reason:'directive-not-found',authority:false};const lessonIds=boundedArray(directive.lessonAdvice,4).map(row=>row?.lessonId).filter(Boolean);if(!lessonIds.length)return{evaluated:[],demoted:[],reason:'directive-used-no-active-lessons',authority:false};const result=await this.stages.evaluateLessonsForCredit({lessonIds,creditWitnessDigest,routeWitnessDigest,outcomeWitnessDigest});directive.lessonEvaluationWitnessDigests=(result.evaluated||[]).map(row=>row.witness?.digest).filter(Boolean);await this._persist();return result;
  }
  async updateCommitment(commitmentId,{status,goal=null,reason=null}={}){
    const row=this._findCommitment(commitmentId);if(!row)return null;const allowed=new Set(['active','completed','abandoned','needs-revision','paused']);const next=allowed.has(String(status))?String(status):row.status;if(goal!=null)row.goal=text(goal,768);row.status=next;row.updatedAt=Date.now();const witness=await this.ledger.append('wg-srnn-commitment-updated',{commitmentId:row.commitmentId,directiveDigest:row.directiveDigest,goal:row.goal,status:row.status,reason:text(reason,128),authority:false});this._history('commitment-updated',{commitmentId:row.commitmentId,directiveDigest:row.directiveDigest,capability:row.capability,goal:row.goal,status:row.status});await this._persist();return{commitment:publicCommitment(row),witness};
  }
  _resumeSources({lessonLimit=16}={}){
    return{directives:this.state.directives,commitments:this.state.commitments,stages:this.stages?.state||null,lessons:this.stages?.activeLessons?.({limit:Math.max(1,Math.min(16,Number(lessonLimit)||16))})||[]};
  }
  selfCalibration({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnSelfCalibrationContext(directive,{...this._resumeSources(),...options});
  }
  dependencyReflection({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnDependencyReflectionContext(directive,{...this._resumeSources(),...options});
  }
  async episodicSelfSummary({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnEpisodicSelfSummaryContext(directive,{...this._resumeSources({lessonLimit:16}),...options});
  }
  async commitmentSelfReference(options={}){
    return wgSrnnCommitmentSelfReferenceContext({...this._resumeSources({lessonLimit:16}),...options});
  }
  async resumeContext(options={}){
    const sources=this._resumeSources({lessonLimit:16}),reflection=this.reflect({limit:Math.max(1,Math.min(16,Number(options.reflectionLimit)||16))});
    return wgSrnnResumeContext({...sources,reflection,...options});
  }
  async sfmAssessmentRequests({directiveDigest,directiveId=null,agenda=null,requestLimit=4,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    const resolvedAgenda=agenda||this.reflectionAgenda({directiveDigest:directive.directiveDigest,...options});
    return buildWgSfmAssessmentRequests(directive,resolvedAgenda,{requestLimit});
  }
  async sealSfmConsensusAssessment({directiveDigest,directiveId=null,request,consensus,observerId='wg-sfm:semantic-assessor',independenceGroup='wg-sfm'}={}){
    return sealWgSfmAssessmentFromConsensus(this,{directiveDigest:directiveDigest??directiveId,request,consensus,observerId,independenceGroup});
  }
  confidenceCalibration({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnConfidenceCalibrationContext(directive,{directives:this.state.directives,stages:this.stages?.state,...options});
  }
  strategyComparison({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnStrategyComparisonContext(directive,{directives:this.state.directives,stages:this.stages?.state,...options});
  }
  reconsideration({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnReconsiderationContext(directive,{directives:this.state.directives,stages:this.stages?.state,...options});
  }
  reflectionAgenda({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    return wgSrnnReflectionAgendaContext(directive,{directives:this.state.directives,stages:this.stages?.state,...options});
  }
  governanceReflection({directiveDigest,directiveId=null,...options}={}){
    const directive=this._findDirective(directiveDigest??directiveId);if(!directive)throw new Error('directive-not-found');
    const shared={directives:this.state.directives,stages:this.stages?.state,...options};
    const confidenceCalibration=wgSrnnConfidenceCalibrationContext(directive,shared),selfCalibration=wgSrnnSelfCalibrationContext(directive,shared),strategyComparison=wgSrnnStrategyComparisonContext(directive,shared),reconsideration=wgSrnnReconsiderationContext(directive,shared),reflectionAgenda=wgSrnnReflectionAgendaContext(directive,shared);
    return{schema:'xavi-wg-srnn-governance-reflection/v1',namespace:this.namespace,targetDirectiveId:directive.directiveId,targetDirectiveDigest:directive.directiveDigest,confidenceCalibration,selfCalibration,strategyComparison,reconsideration,reflectionAgenda,authority:false};
  }


  async normalizeInterchangeRecord(record,options={}){return normalizeSrnnRuntimeInterchangeRecord(record,options);}
  async normalize_interchange_record(record,options={}){return this.normalizeInterchangeRecord(record,options);}
  async interchangeLineageKey(record,options={}){return srnnRuntimeInterchangeLineageKey(record,options);}
  async interchange_lineage_key(record,options={}){return this.interchangeLineageKey(record,options);}
  async interchangeImportRequirements(record,options={}){return srnnRuntimeImportRequirements(record,options);}
  async interchange_import_requirements(record,options={}){return this.interchangeImportRequirements(record,options);}
  async verifyInterchangeProjection(options={}){return verifySrnnInterchangeProjection(options);}
  async verify_interchange_projection(options={}){return this.verifyInterchangeProjection(options);}
  reflect({capability=null,limit=8}={}){
    const cap=capability==null?null:String(capability);const directives=this.state.directives.filter(row=>!cap||row.capability===cap);const history=this.state.history.filter(row=>!cap||row.capability===cap);const commitments=this.state.commitments.filter(row=>!cap||row.capability===cap);
    return{schema:'xavi-wg-srnn-reflection/v1',namespace:this.namespace,currentGoals:commitments.filter(row=>row.status==='active').slice(-limit).map(row=>row.goal),currentCommitments:commitments.filter(row=>row.status==='active').slice(-limit).map(publicCommitment),whatDidIThink:directives.slice(-limit).map(publicDirective),whyDidIThink:directives.slice(-limit).map(row=>({directiveDigest:row.directiveDigest||null,justificationEdges:boundedArray(row.justificationEdges,12),sourceStateDigest:row.sourceStateDigest||null,routeWitnessDigest:row.routeWitnessDigest||null,authority:false})),whatDidIDo:history.filter(row=>row.kind==='action-recorded').slice(-limit).map(clone),whatActuallyHappened:history.filter(row=>row.kind==='directive-settled').slice(-limit).map(clone),whereWasIWrong:history.filter(row=>row.kind==='directive-settled'&&row.status==='contradicted').slice(-limit).map(clone),whatWorked:history.filter(row=>row.kind==='directive-settled'&&row.status==='confirmed').slice(-limit).map(clone),metrics:this.metrics(),authority:false};
  }
  explain({focusDigest=null,directiveDigest=null,lessonId=null,candidateDigest=null,maxDepth=5,limit=128,relations=null}={}){
    const directiveRef=text(directiveDigest,192),directive=directiveRef?this._findDirective(directiveRef):null;
    if(lessonId||candidateDigest){const lesson=this.stages?.explainLesson?.({lessonId,candidateDigest,maxDepth,limit,relations})||null;return{schema:'xavi-wg-srnn-explanation/v1',namespace:this.namespace,kind:'lesson',focusDigest:lesson?.trace?.focusDigest||candidateDigest||null,directive:null,lesson,trace:lesson?.trace||null,verified:Boolean(lesson?.verified),authority:false};}
    const focus=text(focusDigest??directiveRef,192);if(!focus)return{schema:'xavi-wg-srnn-explanation/v1',namespace:this.namespace,kind:'none',focusDigest:null,directive:null,lesson:null,trace:null,verified:Boolean(this.stages?.state?.ledgerVerified),authority:false};
    const trace=this.stages?.traceCausality?.({focusDigest:focus,maxDepth,limit,relations,direction:'both'})||null;return{schema:'xavi-wg-srnn-explanation/v1',namespace:this.namespace,kind:directive?'directive':'witness',focusDigest:focus,directive:directive?publicDirective(directive):null,lesson:null,trace,verified:Boolean(trace?.verified),authority:false};
  }
}
