import { assertBrowserAuthorityProof, refreshBrowserAuthorityProof } from '../sync/authority.js';
import { dot } from './utils.js';

export const SEMANTIC_OPERATIONS = Object.freeze(['observe','compare','route','retrieve','reconcile','execute','defer']);
const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const sigmoid=x=>1/(1+Math.exp(-Math.max(-30,Math.min(30,Number(x)||0))));
const softmax=rows=>{if(!rows.length)return[];const m=Math.max(...rows.map(x=>x.score));const ex=rows.map(x=>({...x,e:Math.exp(x.score-m)}));const z=ex.reduce((s,x)=>s+x.e,0)||1;return ex.map(x=>({...x,probability:x.e/z})).sort((a,b)=>b.probability-a.probability||a.label.localeCompare(b.label));};
const blank=dim=>({weights:Array(dim).fill(0),attempts:0,successes:0,rewardSum:0,updatedAt:0});
const blankBinary=dim=>({weights:Array(dim).fill(0),bias:0,attempts:0,positives:0,correct:0,updatedAt:0});
const blankCalibration=()=>({attempts:0,nextWitnessObserved:0,nextWitnessCorrect:0,targetObserved:0,targetCorrect:0,feasibilityObserved:0,feasibilityCorrect:0,compatibilityObserved:0,compatibilityCorrect:0,conflictObserved:0,conflictCorrect:0,updatedAt:0});
const calibrationCount=value=>{const n=Number(value);return Number.isFinite(n)&&n>=0?n:0;};
function normalizeCalibration(row={}){const out=blankCalibration();for(const key of Object.keys(out))out[key]=key==='updatedAt'?calibrationCount(row?.[key]):calibrationCount(row?.[key]);return out;}
function updateCalibrationRow(row,prediction={},updatedAt=Date.now()){
  const out=normalizeCalibration(row);out.attempts+=1;
  const fields=[['nextWitness','nextWitnessMatch'],['target','targetMatch'],['feasibility','feasibilityMatch'],['compatibility','compatibilityMatch'],['conflict','conflictMatch']];
  for(const [key,source] of fields)if(typeof prediction?.[source]==='boolean'){out[`${key}Observed`]+=1;if(prediction[source])out[`${key}Correct`]+=1;}
  out.updatedAt=calibrationCount(updatedAt)||Date.now();return out;
}
const INTENT_OPERATION=Object.freeze({extract:'observe',inspect:'observe',verify:'compare',reason:'compare',recall:'retrieve',transform:'execute',act:'execute'});

function heuristic(label,{intent='',gatePressure=0,uncertainty=0,conflict=0,capability=''}){
  let s=0;const expected=INTENT_OPERATION[intent]||'observe';if(label===expected)s+=0.75;
  if(label==='defer')s+=0.8*uncertainty+0.7*gatePressure;
  if(label==='reconcile')s+=0.9*conflict;
  if(label==='compare'&&/verify|check|compare|validate/.test(capability))s+=0.45;
  if(label==='retrieve'&&/memory|search|recall|lookup/.test(capability))s+=0.45;
  if(label==='route'&&/route|dispatch|select/.test(capability))s+=0.45;
  return s;
}
function targetHint(working,capability=''){
  const entities=working?.activeEntities||[];
  for(let i=entities.length-1;i>=0;i--){const row=entities[i];if(/^(strategyId|observerId|modelId|recordId)=/.test(row))return row.split('=').slice(1).join('=');}
  return String(capability||'').split(':')[0]||null;
}
function clonePolicy(map,id,dim,binary=false){return structuredClone(map.get(id)||(binary?blankBinary(dim):blank(dim)));}
function binaryCandidate(map,id,vector,target,learningRate){
  if(typeof target!=='boolean')return null;const current=clonePolicy(map,id,vector.length,true);const probability=sigmoid(dot(current.weights,vector)+Number(current.bias||0));const error=(target?1:0)-probability;const weights=current.weights.slice();for(let i=0;i<weights.length;i++)weights[i]+=learningRate*error*Number(vector[i]||0);const bias=Number(current.bias||0)+learningRate*error;
  return{id,policy:{...current,weights,bias,attempts:current.attempts+1,positives:current.positives+(target?1:0),correct:current.correct+((probability>=0.5)===target?1:0),updatedAt:Date.now()}};
}
function calibrationAccuracy(row,key){const observed=calibrationCount(row?.[`${key}Observed`]),correct=calibrationCount(row?.[`${key}Correct`]);return observed?correct/observed:null;}
function calibrationDeltaAccuracy(row){const keys=['nextWitness','target','feasibility','compatibility','conflict'];let observed=0,correct=0;for(const key of keys){observed+=calibrationCount(row?.[`${key}Observed`]);correct+=calibrationCount(row?.[`${key}Correct`]);}return observed?correct/observed:null;}

/**
 * Tiny specialized semantic output heads. No head is authoritative.
 * Policies are separated by task so an operation decision cannot silently become
 * a feasibility or continuation rule.
 */
export class WitnessSemanticHeads {
  constructor({store,featureDim=32,learningRate=0.06,requireAuthorityProof=false}={}){
    this.store=store;this.requireAuthorityProof=requireAuthorityProof===true;this.featureDim=featureDim;this.learningRate=learningRate;
    this.operationPolicy=new Map();this.targetPolicy=new Map();this.nextWitnessPolicy=new Map();this.binaryPolicy=new Map();this.calibration=new Map();this.revision=0;
    this.schema='xavi-witness-semantic-heads/v3';
  }
  async init(){
    for(const row of await this.store.values('semantic-head-policy'))if(row?.id&&row?.policy)this.operationPolicy.set(row.id,row.policy);
    for(const row of await this.store.values('semantic-target-policy'))if(row?.id&&row?.policy)this.targetPolicy.set(row.id,row.policy);
    for(const row of await this.store.values('semantic-next-witness-policy'))if(row?.id&&row?.policy)this.nextWitnessPolicy.set(row.id,row.policy);
    for(const row of await this.store.values('semantic-binary-head-policy'))if(row?.id&&row?.policy)this.binaryPolicy.set(row.id,row.policy);
    for(const row of await this.store.values('semantic-head-calibration'))if(row?.id&&row?.calibration)this.calibration.set(row.id,row.calibration);
    this.revision+=1;return this;
  }
  _calibration(operation){
    const global=this.calibration.get('global')||blankCalibration(),local=this.calibration.get(`operation:${operation}`)||null;
    const row=local&&local.attempts>=3?local:global;
    return{samples:Number(row.attempts||0),witnessDeltaAccuracy:calibrationDeltaAccuracy(row),nextWitnessAccuracy:calibrationAccuracy(row,'nextWitness'),targetAccuracy:calibrationAccuracy(row,'target'),feasibilityAccuracy:calibrationAccuracy(row,'feasibility'),compatibilityAccuracy:calibrationAccuracy(row,'compatibility'),conflictAccuracy:calibrationAccuracy(row,'conflict')};
  }
  _nextWitness(vector,working){
    const historical=new Map((working.nextWitnessTypes||[]).map(x=>[x.type,Number(x.count||0)]));const labels=new Set([...historical.keys(),...this.nextWitnessPolicy.keys()]);if(!labels.size)return null;
    // Witness-chain frequency is a cold-start prior, not an authority. As supervised
    // continuation evidence accumulates, decay the motif prior so learned witness
    // transitions can override a merely common pre-route pattern.
    const learnedAttempts=[...this.nextWitnessPolicy.values()].reduce((sum,p)=>sum+Number(p?.attempts||0),0);
    const historyPriorScale=0.35/Math.pow(1+learnedAttempts/4,2);
    const ranked=softmax([...labels].map(label=>{const p=this.nextWitnessPolicy.get(label)||blank(this.featureDim);const count=historical.get(label)||0;return{label,score:dot(p.weights,vector)+Math.log1p(count)*historyPriorScale,frequency:count,attempts:p.attempts};}));
    const best=ranked[0];return{type:best.label,confidence:best.probability,frequency:best.frequency,historyPriorScale,learnedAttempts,ranked:ranked.slice(0,4).map(x=>({type:x.label,probability:x.probability,frequency:x.frequency,attempts:x.attempts}))};
  }
  _target(vector,working,capability=''){
    const heuristicTarget=targetHint(working,capability);const labels=new Set(this.targetPolicy.keys());if(heuristicTarget)labels.add(heuristicTarget);if(!labels.size)return null;
    const ranked=softmax([...labels].map(label=>{const policy=this.targetPolicy.get(label)||blank(this.featureDim);const heuristicBoost=label===heuristicTarget?0.45/Math.pow(1+Number(policy.attempts||0)/4,2):0;return{label,score:dot(policy.weights,vector)+heuristicBoost,attempts:policy.attempts,heuristic:label===heuristicTarget};}));
    const best=ranked[0];return{target:best.label,confidence:best.probability,heuristicTarget,ranked:ranked.slice(0,4).map(x=>({target:x.label,probability:x.probability,attempts:x.attempts,heuristic:x.heuristic}))};
  }
  predict({vector,intent,capability='',gatePressure=0,uncertainty=0,working={}}={}){
    const conflictBase=clamp(working.conflict||0),compatibilityBase=clamp(working.compatibility??0.5);
    const conflictPolicy=this.binaryPolicy.get('conflict')||blankBinary(this.featureDim),conflictLearned=conflictPolicy.attempts?sigmoid(dot(conflictPolicy.weights,vector)+Number(conflictPolicy.bias||0)):null;
    const conflictAlpha=Math.min(0.65,Number(conflictPolicy.attempts||0)/20*0.65),conflict=conflictLearned==null?conflictBase:clamp((1-conflictAlpha)*conflictBase+conflictAlpha*conflictLearned);
    const ranked=softmax(SEMANTIC_OPERATIONS.map(label=>{const policy=this.operationPolicy.get(label)||blank(this.featureDim);return{label,score:dot(policy.weights,vector)+heuristic(label,{intent,gatePressure,uncertainty,conflict,capability}),attempts:policy.attempts};}));
    const best=ranked[0],next=this._nextWitness(vector,working),target=this._target(vector,working,capability);
    const feasibilityBase=clamp(0.38*(1-uncertainty)+0.22*(1-gatePressure)+0.20*(1-conflict)+0.20*compatibilityBase);
    const fp=this.binaryPolicy.get('feasibility')||blankBinary(this.featureDim),cp=this.binaryPolicy.get('compatibility')||blankBinary(this.featureDim);
    const feasibilityLearned=fp.attempts?sigmoid(dot(fp.weights,vector)+Number(fp.bias||0)):null;
    const compatibilityLearned=cp.attempts?sigmoid(dot(cp.weights,vector)+Number(cp.bias||0)):null;
    const fa=Math.min(0.65,Number(fp.attempts||0)/20*0.65),ca=Math.min(0.65,Number(cp.attempts||0)/20*0.65);
    const feasibility=feasibilityLearned==null?feasibilityBase:clamp((1-fa)*feasibilityBase+fa*feasibilityLearned);
    const compatibility=compatibilityLearned==null?compatibilityBase:clamp((1-ca)*compatibilityBase+ca*compatibilityLearned);
    const calibration=this._calibration(best.label);const reliability=calibration.samples>=3?Math.min(calibration.nextWitnessAccuracy??1,calibration.feasibilityAccuracy??1):1;
    const operationConfidence=clamp(best.probability*(0.55+0.45*reliability));
    return {schema:this.schema,semanticClass:intent,nextOperation:best.label,operationConfidence,targetHint:target?.target||targetHint(working,capability),targetConfidence:target?.confidence??null,rankedTargets:target?.ranked||[],
      chainContinuation:next?{type:next.type,frequency:next.frequency,confidence:next.confidence,historyPriorScale:next.historyPriorScale,learnedAttempts:next.learnedAttempts,ranked:next.ranked}:null,compatibility,conflict,feasibility,
      calibration,rankedOperations:ranked.slice(0,4).map(({label,probability})=>({operation:label,probability})),
      expectedWitnessDelta:{action:best.label,targetHint:target?.target||targetHint(working,capability),expectedNextType:next?.type||null,feasibility,compatibility,conflictProbability:conflict,expectedFeasible:feasibility>=0.5,expectedCompatible:compatibility>=0.5,expectedConflict:conflict>=0.5,gatePressure:gatePressure>0.35?'decrease_or_revalidate':'stable',conflict:conflict>0.35?'resolve':'stable',authority:false},authority:false};
  }
  buildCandidate(features,reward,outcome={}){
    const vector=Array.isArray(features)?features:(features?.vector||[]);const operation=features?.operation||features?.nextOperation||null;if(!operation||!SEMANTIC_OPERATIONS.includes(operation))return null;
    const current=clonePolicy(this.operationPolicy,operation,this.featureDim,false),weights=current.weights.slice(),scale=this.learningRate*Math.max(-1,Math.min(1,Number(reward)||0));for(let i=0;i<weights.length;i++)weights[i]+=scale*Number(vector[i]||0);
    const operationCandidate={id:operation,policy:{...current,weights,attempts:current.attempts+1,successes:current.successes+(outcome.ok?1:0),rewardSum:current.rewardSum+Number(reward||0),updatedAt:Date.now()}};
    const actual=outcome.semanticActual||{},predicted=features?.predictedNextWitnessType||null,nextCandidates=[],targetCandidates=[];
    const actualTarget=actual.targetHint||actual.target||null,predictedTarget=features?.targetHint||features?.predictedTarget||null;
    if(actualTarget){
      const target=clonePolicy(this.targetPolicy,actualTarget,this.featureDim,false),tw=target.weights.slice();for(let i=0;i<tw.length;i++)tw[i]+=this.learningRate*Number(vector[i]||0);targetCandidates.push({id:actualTarget,policy:{...target,weights:tw,attempts:target.attempts+1,successes:target.successes+1,rewardSum:target.rewardSum+1,updatedAt:Date.now()}});
      if(predictedTarget&&predictedTarget!==actualTarget){const wrong=clonePolicy(this.targetPolicy,predictedTarget,this.featureDim,false),ww=wrong.weights.slice();for(let i=0;i<ww.length;i++)ww[i]-=this.learningRate*0.5*Number(vector[i]||0);targetCandidates.push({id:predictedTarget,policy:{...wrong,weights:ww,attempts:wrong.attempts+1,rewardSum:wrong.rewardSum-0.5,updatedAt:Date.now()}});}
    }
    if(actual.nextWitnessType){
      const target=clonePolicy(this.nextWitnessPolicy,actual.nextWitnessType,this.featureDim,false),tw=target.weights.slice();for(let i=0;i<tw.length;i++)tw[i]+=this.learningRate*Number(vector[i]||0);nextCandidates.push({id:actual.nextWitnessType,policy:{...target,weights:tw,attempts:target.attempts+1,successes:target.successes+1,rewardSum:target.rewardSum+1,updatedAt:Date.now()}});
      if(predicted&&predicted!==actual.nextWitnessType){const wrong=clonePolicy(this.nextWitnessPolicy,predicted,this.featureDim,false),ww=wrong.weights.slice();for(let i=0;i<ww.length;i++)ww[i]-=this.learningRate*0.5*Number(vector[i]||0);nextCandidates.push({id:predicted,policy:{...wrong,weights:ww,attempts:wrong.attempts+1,rewardSum:wrong.rewardSum-0.5,updatedAt:Date.now()}});}
    }
    const feasibilityCandidate=binaryCandidate(this.binaryPolicy,'feasibility',vector,typeof actual.feasible==='boolean'?actual.feasible:Boolean(outcome.ok),this.learningRate);
    const compatibilityCandidate=binaryCandidate(this.binaryPolicy,'compatibility',vector,typeof actual.compatible==='boolean'?actual.compatible:Boolean(outcome.ok&&outcome.validated!==false),this.learningRate);
    const conflictCandidate=binaryCandidate(this.binaryPolicy,'conflict',vector,typeof actual.conflict==='boolean'?actual.conflict:null,this.learningRate);
    const calibrationCandidate=this._buildCalibration(operation,outcome.semanticPrediction||{});
    return{operationCandidate,targetCandidates,nextCandidates,feasibilityCandidate,compatibilityCandidate,conflictCandidate,calibrationCandidate};
  }
  _buildCalibration(operation,prediction={}){
    const update=id=>({id,calibration:updateCalibrationRow(this.calibration.get(id),prediction,Date.now())});
    return[update('global'),update(`operation:${operation}`)];
  }
  async rebuildCalibrationFromWitnesses({persist=true,authorityProof=null}={}){if(persist&&this.requireAuthorityProof){assertBrowserAuthorityProof(authorityProof);await refreshBrowserAuthorityProof(authorityProof);}
    const assessments=(await this.store.values('witness')).filter(row=>row?.type==='semantic-prediction-assessment').sort((a,b)=>Number(a.sequence||0)-Number(b.sequence||0));
    const rebuilt=new Map();
    const apply=(id,prediction,observedAt)=>rebuilt.set(id,updateCalibrationRow(rebuilt.get(id),prediction,observedAt));
    for(const row of assessments){
      const match=row.body?.match||{};const prediction={nextWitnessMatch:match.nextWitness,targetMatch:match.target,feasibilityMatch:match.feasibility,compatibilityMatch:match.compatibility,conflictMatch:match.conflict};
      apply('global',prediction,row.observedAt);const operation=row.body?.predicted?.nextOperation;if(operation)apply(`operation:${operation}`,prediction,row.observedAt);
    }
    if(persist&&this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);
    this.calibration.clear();for(const [id,value] of rebuilt)this.calibration.set(id,value);
    if(persist){
      for(const row of await this.store.values('semantic-head-calibration'))if(row?.id&&!rebuilt.has(row.id)&&this.store.delete){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);await this.store.delete('semantic-head-calibration',row.id);}
      for(const [id,value] of rebuilt){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);await this.store.set('semantic-head-calibration',id,{id,calibration:value});}
    }
    const first=assessments[0]||null,last=assessments.at(-1)||null;this.revision+=1;
    return{schema:'xavi-semantic-calibration-rebuild/v1',assessmentCount:assessments.length,sourceFirstSequence:first?.sequence||null,sourceLastSequence:last?.sequence||null,sourceLastDigest:last?.digest||null,calibration:Object.fromEntries([...rebuilt].map(([id,value])=>[id,structuredClone(value)])),authority:false};
  }
  async install(candidate,{authorityProof=null}={}){if(this.requireAuthorityProof){assertBrowserAuthorityProof(authorityProof);await refreshBrowserAuthorityProof(authorityProof);}
    if(!candidate)return null;
    if(candidate.operationCandidate){const c=candidate.operationCandidate;if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);this.operationPolicy.set(c.id,c.policy);await this.store.set('semantic-head-policy',c.id,c);}
    for(const c of candidate.targetCandidates||[]){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);this.targetPolicy.set(c.id,c.policy);await this.store.set('semantic-target-policy',c.id,c);}
    for(const c of candidate.nextCandidates||[]){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);this.nextWitnessPolicy.set(c.id,c.policy);await this.store.set('semantic-next-witness-policy',c.id,c);}
    for(const c of [candidate.feasibilityCandidate,candidate.compatibilityCandidate,candidate.conflictCandidate].filter(Boolean)){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);this.binaryPolicy.set(c.id,c.policy);await this.store.set('semantic-binary-head-policy',c.id,c);}
    for(const c of candidate.calibrationCandidate||[]){if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);this.calibration.set(c.id,c.calibration);await this.store.set('semantic-head-calibration',c.id,c);}
    this.revision+=1;return candidate.operationCandidate?.policy||null;
  }
  stats(){return{schema:this.schema,operations:Object.fromEntries(SEMANTIC_OPERATIONS.map(id=>[id,this.operationPolicy.get(id)||blank(this.featureDim)])),targets:Object.fromEntries(this.targetPolicy),nextWitness:Object.fromEntries(this.nextWitnessPolicy),binary:Object.fromEntries(this.binaryPolicy),calibration:Object.fromEntries(this.calibration),authority:false};}
  exportState(){return{schema:'xavi-witness-semantic-head-state/v1',featureDim:this.featureDim,learningRate:this.learningRate,operationPolicy:Object.fromEntries([...this.operationPolicy].map(([k,v])=>[k,structuredClone(v)])),targetPolicy:Object.fromEntries([...this.targetPolicy].map(([k,v])=>[k,structuredClone(v)])),nextWitnessPolicy:Object.fromEntries([...this.nextWitnessPolicy].map(([k,v])=>[k,structuredClone(v)])),binaryPolicy:Object.fromEntries([...this.binaryPolicy].map(([k,v])=>[k,structuredClone(v)])),calibration:Object.fromEntries([...this.calibration].map(([k,v])=>[k,structuredClone(v)])),authority:false};}
  async importState(state,{persist=true,replace=true,authorityProof=null}={}){if(persist&&this.requireAuthorityProof){assertBrowserAuthorityProof(authorityProof);await refreshBrowserAuthorityProof(authorityProof);}
    if(!state||Number(state.featureDim)!==Number(this.featureDim))throw new Error('semantic head state feature dimension mismatch');
    const specs=[[ 'operationPolicy', 'semantic-head-policy', 'policy' ],[ 'targetPolicy', 'semantic-target-policy', 'policy' ],[ 'nextWitnessPolicy', 'semantic-next-witness-policy', 'policy' ],[ 'binaryPolicy', 'semantic-binary-head-policy', 'policy' ],[ 'calibration', 'semantic-head-calibration', 'calibration' ]];
    for(const [field,table,valueField] of specs){const map=this[field],incoming=state[field]||{};if(replace){for(const key of [...map.keys()])if(!(key in incoming)){if(persist&&this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);map.delete(key);if(persist&&this.store.delete)await this.store.delete(table,key);}}for(const [key,value] of Object.entries(incoming)){if(persist&&this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof);const copy=structuredClone(value);map.set(key,copy);if(persist)await this.store.set(table,key,{id:key,[valueField]:copy});}}
    this.revision+=1;return this.exportState();
  }

}
