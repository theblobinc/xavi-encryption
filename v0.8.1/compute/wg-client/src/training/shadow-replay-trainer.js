import { MemoryStore } from '../storage/memory-store.js';
import { WitnessSemanticLayer } from '../core/witness-semantic.js';
import { SEMANTIC_OPERATIONS } from '../core/witness-semantic-heads.js';
import { digest, dot } from '../core/utils.js';

const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const sigmoid=x=>1/(1+Math.exp(-Math.max(-30,Math.min(30,Number(x)||0))));
const scoreBinary=(probability,target)=>clamp(1-2*Math.pow(clamp(probability)-(target?1:0),2));
const finiteVector=value=>Array.isArray(value)&&value.length>0&&value.every(v=>Number.isFinite(Number(v)));
const hashUnit=value=>{let h=2166136261;for(const c of String(value||'')){h^=c.charCodeAt(0);h=Math.imul(h,16777619);}return(h>>>0)/4294967296;};
const mean=values=>values.length?values.reduce((a,b)=>a+b,0)/values.length:null;

function policyProbability(policy,vector){return sigmoid(dot(policy?.weights||[],vector));}
function operationProbability(headState,vector,target){
  if(!target)return null;const policies=headState?.operationPolicy||{};const rows=SEMANTIC_OPERATIONS.map(label=>({label,score:dot(policies[label]?.weights||[],vector)}));const max=Math.max(...rows.map(x=>x.score));const ex=rows.map(x=>({...x,e:Math.exp(x.score-max)}));const total=ex.reduce((sum,x)=>sum+x.e,0)||1;const row=ex.find(x=>x.label===target);return row?row.e/total:0;
}
function targetProbability(headState,vector,target){
  if(!target)return null;const policies=headState?.targetPolicy||{};const labels=Object.keys(policies);if(!labels.length)return 0.5;const rows=labels.map(label=>({label,score:dot(policies[label]?.weights||[],vector)}));const max=Math.max(...rows.map(x=>x.score));const ex=rows.map(x=>({...x,e:Math.exp(x.score-max)}));const total=ex.reduce((sum,x)=>sum+x.e,0)||1;const row=ex.find(x=>x.label===target);return row?row.e/total:0;
}
function binaryProbability(policy,vector){return policy?.attempts?sigmoid(dot(policy.weights||[],vector)+Number(policy.bias||0)):0.5;}
function nextWitnessProbability(headState,vector,target){
  if(!target)return null;
  const policies=headState?.nextWitnessPolicy||{};
  const labels=Object.keys(policies);
  if(!labels.length)return 0.5;
  const rows=labels.map(label=>({label,score:dot(policies[label]?.weights||[],vector)}));
  const max=Math.max(...rows.map(x=>x.score));
  const ex=rows.map(x=>({...x,e:Math.exp(x.score-max)}));
  const total=ex.reduce((s,x)=>s+x.e,0)||1;
  const row=ex.find(x=>x.label===target);
  return row?row.e/total:0;
}

function evaluateState(state,examples){
  const components={routeUtility:[],operationUtility:[],targetUtility:[],nextWitness:[],feasibility:[],compatibility:[],conflict:[]};
  for(const example of examples){
    const vector=example?.training?.semanticFeatures?.vector;
    if(!finiteVector(vector))continue;
    const reward=Number(example.training.reward||0);
    const utilityTarget=reward>0&&example?.observed?.validated!==false;
    components.routeUtility.push(scoreBinary(policyProbability(state?.policy?.[example.strategyId],vector),utilityTarget));
    const operationTarget=example?.training?.semanticFeatures?.operation||example?.action?.operation||null;
    const operationProb=operationProbability(state?.heads,vector,operationTarget);
    if(operationProb!=null)components.operationUtility.push(utilityTarget?clamp(operationProb):clamp(1-operationProb));
    const targetLabel=example?.labels?.routeTarget||example?.observed?.targetHint||null,targetProb=targetProbability(state?.heads,vector,targetLabel);
    if(targetProb!=null)components.targetUtility.push(utilityTarget?clamp(targetProb):clamp(1-targetProb));
    const nextProbability=nextWitnessProbability(state?.heads,vector,example?.observed?.nextWitnessType||null);
    if(nextProbability!=null)components.nextWitness.push(clamp(nextProbability));
    components.feasibility.push(scoreBinary(binaryProbability(state?.heads?.binaryPolicy?.feasibility,vector),Boolean(example?.observed?.ok)));
    components.compatibility.push(scoreBinary(binaryProbability(state?.heads?.binaryPolicy?.compatibility,vector),Boolean(example?.labels?.chainCompatible)));
    if(typeof example?.labels?.conflict==='boolean')components.conflict.push(scoreBinary(binaryProbability(state?.heads?.binaryPolicy?.conflict,vector),example.labels.conflict));
  }
  const scores=Object.fromEntries(Object.entries(components).map(([key,values])=>[key,mean(values)]));
  const present=Object.values(scores).filter(Number.isFinite);
  const semanticKeys=['operationUtility','targetUtility','nextWitness','feasibility','compatibility','conflict'];
  const semanticPresent=semanticKeys.map(key=>scores[key]).filter(Number.isFinite);
  return{schema:'xavi-semantic-shadow-evaluation-metrics/v2',count:examples.length,score:mean(present),routeScore:Number.isFinite(scores.routeUtility)?scores.routeUtility:null,semanticWitnessDelta:mean(semanticPresent),semanticComponents:semanticKeys.filter(key=>Number.isFinite(scores[key])),components:scores,authority:false};
}

export function compareSemanticShadowMetrics(live,shadow,{minImprovement=0.005,maxComponentRegression=0.02,maxSemanticRegression=0}={}){
  const liveScore=Number(live?.score),shadowScore=Number(shadow?.score);
  const improvement=Number.isFinite(liveScore)&&Number.isFinite(shadowScore)?shadowScore-liveScore:null;
  const liveSemantic=Number(live?.semanticWitnessDelta),shadowSemantic=Number(shadow?.semanticWitnessDelta);
  const semanticDelta=Number.isFinite(liveSemantic)&&Number.isFinite(shadowSemantic)?shadowSemantic-liveSemantic:null;
  const regressions={};let componentSafe=true;
  for(const key of new Set([...Object.keys(live?.components||{}),...Object.keys(shadow?.components||{})])){
    const a=live?.components?.[key],b=shadow?.components?.[key];
    if(Number.isFinite(a)&&Number.isFinite(b)){regressions[key]=b-a;if(b+maxComponentRegression<a)componentSafe=false;}
  }
  const improved=Number.isFinite(improvement)&&improvement>=minImprovement;
  const semanticSafe=semanticDelta==null?true:semanticDelta>=-Math.max(0,Number(maxSemanticRegression)||0);
  return{improvement,semanticDelta,componentDelta:regressions,improved,semanticSafe,componentSafe,eligible:Boolean(improved&&semanticSafe&&componentSafe)};
}

function splitExamples(examples,{holdoutFraction=0.25,minTrain=2,minHoldout=1}={}){
  const sorted=examples.slice().sort((a,b)=>hashUnit(a.id)-hashUnit(b.id)||String(a.id).localeCompare(String(b.id)));
  if(sorted.length<minTrain+minHoldout)return{train:[],holdout:[],reason:'insufficient-backfill-examples'};
  const requested=Math.max(minHoldout,Math.round(sorted.length*clamp(holdoutFraction,0.05,0.5)));
  const holdoutCount=Math.min(sorted.length-minTrain,requested);
  return{holdout:sorted.slice(0,holdoutCount),train:sorted.slice(holdoutCount),reason:null};
}

function outcomeFromExample(example){
  const predictedNext=example?.prediction?.chainContinuation?.type||example?.training?.semanticFeatures?.predictedNextWitnessType||null;
  const predictedTarget=example?.prediction?.targetHint||example?.training?.semanticFeatures?.targetHint||example?.training?.semanticFeatures?.predictedTarget||null;
  const actualTarget=example?.labels?.routeTarget||example?.observed?.targetHint||null;
  const predictedFeasibility=example?.prediction?.feasibility;const actualConflict=typeof example?.labels?.conflict==='boolean'?example.labels.conflict:null;const predictedConflict=example?.prediction?.conflict==null?null:Number(example.prediction.conflict)>=0.5;
  return{
    ok:Boolean(example?.observed?.ok),validated:example?.observed?.validated!==false,latencyMs:0,
    semanticActual:{nextWitnessType:example?.observed?.nextWitnessType||null,targetHint:actualTarget,feasible:Boolean(example?.observed?.ok),compatible:Boolean(example?.labels?.chainCompatible),conflict:actualConflict},
    semanticPrediction:{
      operation:example?.training?.semanticFeatures?.operation||example?.action?.operation||null,
      nextWitnessMatch:predictedNext==null?null:predictedNext===(example?.observed?.nextWitnessType||null),
      targetMatch:predictedTarget==null||actualTarget==null?null:String(predictedTarget)===String(actualTarget),
      feasibilityMatch:predictedFeasibility==null?null:(Number(predictedFeasibility)>=0.5)===Boolean(example?.observed?.ok),
      conflictMatch:actualConflict==null||predictedConflict==null?null:predictedConflict===actualConflict,
    },
  };
}

export class WitnessReplayBackfillTrainer {
  constructor(xavi){
    if(!xavi?.semantic||!xavi?.replay||!xavi?.ledger||!xavi?.authority)throw new TypeError('WitnessReplayBackfillTrainer requires semantic-enabled XaviBrowser');
    this.xavi=xavi;this.store=xavi.store;this.namespace=xavi.namespace;this.schema='xavi-witness-replay-backfill/v1';
  }

  async _stateDigest(state){return digest(state);}
  _shadowFromState=async state=>{
    const live=this.xavi.semantic,store=new MemoryStore();
    const shadow=new WitnessSemanticLayer({store,featureDim:live.featureDim,window:live.window,motifOrder:live.motifOrder,learningRate:live.learningRate,blend:live.blend,decay:live.decay,workingObjects:live.working.maxObjects,workingEdges:live.working.maxEdges,headLearningRate:live.heads.learningRate});
    await shadow.init();await shadow.importState(state,{persist:true,replace:true});return shadow;
  };

  async _resolveProposal(reference){
    const proposalDigest=typeof reference==='string'?reference:reference?.proposalDigest;
    if(!proposalDigest)throw new TypeError('shadow proposal digest required');
    const row=await this.store.get('records',`semantic-shadow-proposal:${proposalDigest}`);
    if(!row)throw new Error('semantic shadow proposal not found');
    return row;
  }
  async _resolveValidation(reference){
    const validationDigest=typeof reference==='string'?reference:reference?.validationDigest;
    if(!validationDigest)throw new TypeError('shadow validation digest required');
    const row=await this.store.get('records',`semantic-shadow-validation:${validationDigest}`);
    if(!row)throw new Error('semantic shadow validation not found');
    return row;
  }

  async prepare({window=8,limit=5000,holdoutFraction=0.25,minTrain=2,minHoldout=1,minImprovement=0.005,maxComponentRegression=0.02,maxSemanticRegression=0,persistExamples=false}={}){
    const dataset=await this.xavi.replay.build({window,limit,persist:persistExamples});
    const candidates=dataset.examples.filter(example=>example?.training?.backfillEligible&&finiteVector(example?.training?.semanticFeatures?.vector));
    const split=splitExamples(candidates,{holdoutFraction,minTrain,minHoldout});
    const baselineState=this.xavi.semantic.exportState(),baselineDigest=await this._stateDigest(baselineState);
    let shadowState=baselineState,shadowDigest=baselineDigest,liveMetrics=evaluateState(baselineState,split.holdout),shadowMetrics=liveMetrics;
    let comparison={improvement:null,componentDelta:{},improved:false,componentSafe:false,eligible:false};
    if(split.train.length&&split.holdout.length){
      const shadow=await this._shadowFromState(baselineState);
      for(const example of split.train){const candidate=shadow.buildCandidate(example.strategyId,example.training.semanticFeatures,example.training.reward,outcomeFromExample(example));await shadow.install(candidate);}
      shadowState=shadow.exportState();shadowDigest=await this._stateDigest(shadowState);shadowMetrics=evaluateState(shadowState,split.holdout);
      comparison=compareSemanticShadowMetrics(liveMetrics,shadowMetrics,{minImprovement,maxComponentRegression,maxSemanticRegression});
    }
    const thresholds={holdoutFraction,minTrain,minHoldout,minImprovement,maxComponentRegression,maxSemanticRegression};
    const trainingWitness=await this.xavi.ledger.append('semantic-shadow-training',{
      baselineDigest,shadowDigest,dataset:{count:dataset.count,backfillEligible:dataset.backfillEligible},
      trainRouteWitnessDigests:split.train.map(x=>x.routeWitnessDigest),holdoutRouteWitnessDigests:split.holdout.map(x=>x.routeWitnessDigest),
      reason:split.reason,authority:false,
    });
    const evaluationWitness=await this.xavi.ledger.append('semantic-shadow-evaluation',{
      parentTrainingWitness:trainingWitness.digest,baselineDigest,shadowDigest,live:liveMetrics,shadow:shadowMetrics,comparison,thresholds,
      eligibleForPromotion:Boolean(!split.reason&&comparison.eligible),authority:false,
    });
    const publicBase={schema:'xavi-semantic-shadow-proposal/v1',namespace:this.namespace,baselineDigest,shadowDigest,trainingWitnessDigest:trainingWitness.digest,evaluationWitnessDigest:evaluationWitness.digest,trainCount:split.train.length,holdoutCount:split.holdout.length,trainRouteWitnessDigests:split.train.map(x=>x.routeWitnessDigest),holdoutRouteWitnessDigests:split.holdout.map(x=>x.routeWitnessDigest),metrics:{live:liveMetrics,shadow:shadowMetrics,comparison},thresholds,eligibleForPromotion:Boolean(!split.reason&&comparison.eligible),reason:split.reason,authority:false};
    const proposalDigest=await digest(publicBase);const proposal={...publicBase,proposalDigest,baselineState,shadowState,trainExamples:split.train,holdoutExamples:split.holdout};
    await this.store.set('records',`semantic-shadow-proposal:${proposalDigest}`,proposal);
    return{...publicBase,proposalDigest,trainingWitness,evaluationWitness};
  }

  async validate(reference){
    const proposal=await this._resolveProposal(reference);
    const currentState=this.xavi.semantic.exportState(),currentDigest=await this._stateDigest(currentState),shadowDigest=await this._stateDigest(proposal.shadowState);
    const dataset=await this.xavi.replay.build({persist:false});
    const stillEligible=new Set(dataset.examples.filter(x=>x?.training?.backfillEligible).map(x=>x.routeWitnessDigest));
    const routesFresh=proposal.trainRouteWitnessDigests.every(route=>stillEligible.has(route));
    const liveMetrics=evaluateState(currentState,proposal.holdoutExamples),shadowMetrics=evaluateState(proposal.shadowState,proposal.holdoutExamples);
    const comparison=compareSemanticShadowMetrics(liveMetrics,shadowMetrics,proposal.thresholds);
    const checks={baselineFresh:currentDigest===proposal.baselineDigest,shadowDigestValid:shadowDigest===proposal.shadowDigest,routesStillBackfillEligible:routesFresh,heldOutImprovement:comparison.improved,componentSafe:comparison.componentSafe};
    const validated=Object.values(checks).every(Boolean)&&Boolean(proposal.eligibleForPromotion);
    const witness=await this.xavi.ledger.append('semantic-shadow-validation',{proposalDigest:proposal.proposalDigest,baselineDigest:proposal.baselineDigest,shadowDigest:proposal.shadowDigest,checks,live:liveMetrics,shadow:shadowMetrics,comparison,validated,authority:false});
    const publicBase={schema:'xavi-semantic-shadow-validation/v1',proposalDigest:proposal.proposalDigest,validationWitnessDigest:witness.digest,checks,metrics:{live:liveMetrics,shadow:shadowMetrics,comparison},validated,authority:false};
    const validationDigest=await digest(publicBase);const record={...publicBase,validationDigest,witnessId:witness.id};
    await this.store.set('records',`semantic-shadow-validation:${validationDigest}`,record);
    return{...record,witness};
  }

  async promote(proposalReference,validationReference){
    const proposal=await this._resolveProposal(proposalReference),validation=await this._resolveValidation(validationReference);
    if(!validation.validated)throw new Error('semantic shadow validation did not pass');
    if(validation.proposalDigest!==proposal.proposalDigest)throw new Error('semantic shadow validation/proposal mismatch');
    const witness=await this.store.get('witness',validation.witnessId);
    if(!witness||witness.type!=='semantic-shadow-validation'||witness.digest!==validation.validationWitnessDigest||witness.body?.proposalDigest!==proposal.proposalDigest)throw new Error('semantic shadow validation witness unavailable or mismatched');
    return this.xavi.authority.withLease(async authorityProof=>{
      const currentState=this.xavi.semantic.exportState(),currentDigest=await this._stateDigest(currentState);
      if(currentDigest!==proposal.baselineDigest)throw new Error('semantic shadow proposal is stale');
      const dataset=await this.xavi.replay.build({persist:false});const eligible=new Set(dataset.examples.filter(x=>x?.training?.backfillEligible).map(x=>x.routeWitnessDigest));
      if(!proposal.trainRouteWitnessDigests.every(route=>eligible.has(route)))throw new Error('semantic backfill routes are no longer eligible');
      const previousLatest=await this.store.get('records','semantic-backfill-latest');let promotionWitness=null;
      try{
        await this.xavi.semantic.importState(proposal.shadowState,{persist:true,replace:true,authorityProof});
        const draftLatest={schema:'xavi-semantic-backfill-state/v1',proposalDigest:proposal.proposalDigest,validationWitnessDigest:validation.validationWitnessDigest,state:proposal.shadowState,baselineDigest:proposal.baselineDigest,shadowDigest:proposal.shadowDigest,updatedAt:Date.now(),authority:false};
        await this.store.set('records','semantic-backfill-latest',draftLatest);
        promotionWitness=await this.xavi.ledger.append('semantic-backfill-promoted',{proposalDigest:proposal.proposalDigest,validationWitnessDigest:validation.validationWitnessDigest,baselineDigest:proposal.baselineDigest,shadowDigest:proposal.shadowDigest,appliedRouteWitnessDigests:proposal.trainRouteWitnessDigests,semanticAuthority:false,policyMutation:true});
        const checkpoint={schema:'xavi-semantic-backfill-checkpoint/v1',promotionWitnessId:promotionWitness.id,promotionWitnessDigest:promotionWitness.digest,promotionSequence:Number(promotionWitness.sequence||0),proposalDigest:proposal.proposalDigest,validationWitnessDigest:validation.validationWitnessDigest,beforeDigest:proposal.baselineDigest,afterDigest:proposal.shadowDigest,beforeState:currentState,afterState:proposal.shadowState,previousLatest:previousLatest||null,appliedRouteWitnessDigests:proposal.trainRouteWitnessDigests,createdAt:Date.now(),authority:false};
        await this.store.set('records',`semantic-backfill-checkpoint:${promotionWitness.digest}`,checkpoint);
        await this.store.set('records','semantic-backfill-latest',{...draftLatest,promotionWitnessDigest:promotionWitness.digest});
        this.xavi.bus?.publish({type:'semantic-backfill-promoted',proposalDigest:proposal.proposalDigest,promotionWitnessDigest:promotionWitness.digest,updatedAt:Date.now()});
        return{schema:'xavi-semantic-backfill-promotion/v1',promoted:true,proposalDigest:proposal.proposalDigest,validationDigest:validation.validationDigest,promotionWitness,appliedRouteWitnessDigests:proposal.trainRouteWitnessDigests,authority:false};
      }catch(error){
        await this.xavi.semantic.importState(currentState,{persist:true,replace:true,authorityProof}).catch(()=>{});
        if(previousLatest)await this.store.set('records','semantic-backfill-latest',previousLatest).catch(()=>{});
        else if(this.store.delete)await this.store.delete('records','semantic-backfill-latest').catch(()=>{});
        if(promotionWitness?.digest&&this.store.delete)await this.store.delete('records',`semantic-backfill-checkpoint:${promotionWitness.digest}`).catch(()=>{});
        await this.xavi.ledger.append('semantic-backfill-rollback',{proposalDigest:proposal.proposalDigest,revertedPromotionWitnessDigest:promotionWitness?.digest||null,appliedRouteWitnessDigests:proposal.trainRouteWitnessDigests,restoredPreviousLatest:Boolean(previousLatest),error:String(error?.message||error).slice(0,1000),authority:false}).catch(()=>{});
        throw error;
      }
    });
  }

  async revert(promotionReference,{reason='manual-revert'}={}){
    const promotionWitnessDigest=typeof promotionReference==='string'?promotionReference:(promotionReference?.promotionWitness?.digest||promotionReference?.promotionWitnessDigest);
    if(!promotionWitnessDigest)throw new TypeError('semantic backfill promotion witness digest required');
    const checkpoint=await this.store.get('records',`semantic-backfill-checkpoint:${promotionWitnessDigest}`);
    if(!checkpoint)throw new Error('semantic backfill checkpoint not found');
    return this.xavi.authority.withLease(async authorityProof=>{
      const currentState=this.xavi.semantic.exportState(),currentDigest=await this._stateDigest(currentState);
      if(currentDigest!==checkpoint.afterDigest)throw new Error('semantic backfill checkpoint is not the current semantic state');
      const latestBeforeRevert=await this.store.get('records','semantic-backfill-latest');let revertWitness=null;
      try{
        await this.xavi.semantic.importState(checkpoint.beforeState,{persist:true,replace:true,authorityProof});
        const restoredLatest=checkpoint.previousLatest||{schema:'xavi-semantic-backfill-baseline/v1',state:checkpoint.beforeState,baselineDigest:checkpoint.beforeDigest,revertedFromPromotionWitnessDigest:promotionWitnessDigest,updatedAt:Date.now(),authority:false};
        await this.store.set('records','semantic-backfill-latest',restoredLatest);
        revertWitness=await this.xavi.ledger.append('semantic-backfill-reverted',{revertedPromotionWitnessDigest:promotionWitnessDigest,proposalDigest:checkpoint.proposalDigest,fromDigest:checkpoint.afterDigest,toDigest:checkpoint.beforeDigest,appliedRouteWitnessDigests:checkpoint.appliedRouteWitnessDigests||[],reason:String(reason).slice(0,500),semanticAuthority:false,policyMutation:true});
        await this.store.set('records',`semantic-backfill-checkpoint:${promotionWitnessDigest}`,{...checkpoint,revertedAt:Date.now(),reversionWitnessDigest:revertWitness.digest});
        this.xavi.bus?.publish({type:'semantic-backfill-reverted',promotionWitnessDigest,reversionWitnessDigest:revertWitness.digest,updatedAt:Date.now()});
        return{schema:'xavi-semantic-backfill-reversion/v1',reverted:true,promotionWitnessDigest,reversionWitness:revertWitness,restoredDigest:checkpoint.beforeDigest,authority:false};
      }catch(error){
        await this.xavi.semantic.importState(currentState,{persist:true,replace:true,authorityProof}).catch(()=>{});
        if(latestBeforeRevert)await this.store.set('records','semantic-backfill-latest',latestBeforeRevert).catch(()=>{});
        await this.xavi.ledger.append('semantic-backfill-revert-rollback',{promotionWitnessDigest,reversionWitnessDigest:revertWitness?.digest||null,error:String(error?.message||error).slice(0,1000),authority:false}).catch(()=>{});
        throw error;
      }
    });
  }

  async status({window=8,limit=5000}={}){
    const dataset=await this.xavi.replay.build({window,limit,persist:false});
    const latest=await this.store.get('records','semantic-backfill-latest');
    const rows=(await this.store.values('witness')).filter(Boolean).sort((a,b)=>(a.sequence||0)-(b.sequence||0));
    const eventTypes=new Set(['semantic-shadow-training','semantic-shadow-evaluation','semantic-shadow-validation','semantic-backfill-promoted','semantic-backfill-reverted','semantic-backfill-rollback','semantic-backfill-canary']);
    const recentEvents=rows.filter(row=>eventTypes.has(row.type)).slice(-12).map(row=>({sequence:row.sequence,type:row.type,digest:row.digest,observedAt:row.observedAt}));
    const activePromotionWitnessDigest=latest?.promotionWitnessDigest||null;
    const checkpoint=activePromotionWitnessDigest?await this.store.get('records',`semantic-backfill-checkpoint:${activePromotionWitnessDigest}`):null;
    const currentDigest=await this._stateDigest(this.xavi.semantic.exportState());
    return{schema:'xavi-semantic-backfill-status/v1',namespace:this.namespace,dataset:{count:dataset.count,trainingEligible:dataset.trainingEligible,appliedOnline:dataset.appliedOnline,backfillEligible:dataset.backfillEligible,positive:dataset.positive,negative:dataset.negative},activePromotionWitnessDigest,latest:latest?{schema:latest.schema||null,proposalDigest:latest.proposalDigest||null,promotionWitnessDigest:latest.promotionWitnessDigest||null,revertedFromPromotionWitnessDigest:latest.revertedFromPromotionWitnessDigest||null,updatedAt:latest.updatedAt||null}:null,currentDigest,checkpoint:checkpoint?{promotionSequence:checkpoint.promotionSequence,beforeDigest:checkpoint.beforeDigest,afterDigest:checkpoint.afterDigest,revertable:currentDigest===checkpoint.afterDigest,revertedAt:checkpoint.revertedAt||null,reversionWitnessDigest:checkpoint.reversionWitnessDigest||null}:null,recentEvents,authority:false};
  }

  async canary(promotionReference=null,{window=8,limit=5000,minExamples=5,maxOverallRegression=0.02,maxComponentRegression=0.03,witness=true}={}){
    let promotionWitnessDigest=typeof promotionReference==='string'?promotionReference:(promotionReference?.promotionWitness?.digest||promotionReference?.promotionWitnessDigest||null);
    if(!promotionWitnessDigest){const latest=await this.store.get('records','semantic-backfill-latest');promotionWitnessDigest=latest?.promotionWitnessDigest||null;}
    if(!promotionWitnessDigest)throw new Error('no active semantic backfill promotion checkpoint');
    const checkpoint=await this.store.get('records',`semantic-backfill-checkpoint:${promotionWitnessDigest}`);
    if(!checkpoint)throw new Error('semantic backfill checkpoint not found');
    const dataset=await this.xavi.replay.build({window,limit,persist:false});
    const examples=dataset.examples.filter(example=>Number(example?.source?.routeSequence||0)>Number(checkpoint.promotionSequence||0)&&finiteVector(example?.training?.semanticFeatures?.vector));
    const before=evaluateState(checkpoint.beforeState,examples),after=evaluateState(checkpoint.afterState,examples);
    const improvement=Number.isFinite(before.score)&&Number.isFinite(after.score)?after.score-before.score:null;
    const componentDelta={};let componentSafe=true;
    for(const key of new Set([...Object.keys(before.components||{}),...Object.keys(after.components||{})])){const a=before.components?.[key],b=after.components?.[key];if(Number.isFinite(a)&&Number.isFinite(b)){componentDelta[key]=b-a;if(b+maxComponentRegression<a)componentSafe=false;}}
    const enoughExamples=examples.length>=Math.max(1,Number(minExamples)||1),overallSafe=Number.isFinite(improvement)?improvement>=-Math.abs(Number(maxOverallRegression)||0):false;
    const currentDigest=await this._stateDigest(this.xavi.semantic.exportState()),revertable=currentDigest===checkpoint.afterDigest;
    const healthy=Boolean(enoughExamples&&overallSafe&&componentSafe);const recommendation=!enoughExamples?'observe':healthy?'keep':revertable?'consider-revert':'regression-but-checkpoint-stale';
    const body={promotionWitnessDigest,promotionSequence:checkpoint.promotionSequence||0,exampleCount:examples.length,minExamples,before,after,improvement,componentDelta,checks:{enoughExamples,overallSafe,componentSafe,revertable},healthy,recommendation,authority:false};
    const canaryWitness=witness?await this.xavi.ledger.append('semantic-backfill-canary',body):null;
    return{schema:'xavi-semantic-backfill-canary/v1',...body,canaryWitnessDigest:canaryWitness?.digest||null};
  }

  async cycle(options={}){
    const proposal=await this.prepare(options);if(!proposal.eligibleForPromotion)return{proposal,validation:null,promotion:null};
    const validation=await this.validate(proposal);if(!validation.validated||options.promote===false)return{proposal,validation,promotion:null};
    const promotion=await this.promote(proposal,validation);return{proposal,validation,promotion};
  }
}
