const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const DEFAULT_BRANCH_CALIBRATION_HALF_LIFE_MS=7*24*3600*1000;
export function effectiveBranchCalibration(reliability,{attempts=null,updatedAt=null,now=Date.now(),halfLifeMs=DEFAULT_BRANCH_CALIBRATION_HALF_LIFE_MS}={}){
  if(reliability==null||!Number.isFinite(Number(reliability)))return{reliability:null,effectiveReliability:null,evidenceStrength:null,freshness:null,strength:null};
  const raw=clamp(Number(reliability)),hasAttempts=attempts!=null&&Number.isFinite(Number(attempts)),n=hasAttempts?Math.max(0,Number(attempts)):null,evidenceStrength=hasAttempts?(n/(n+2)):1;
  const hasTime=updatedAt!=null&&Number.isFinite(Number(updatedAt))&&Number(updatedAt)>0,halfLife=Math.max(1,Number(halfLifeMs)||DEFAULT_BRANCH_CALIBRATION_HALF_LIFE_MS),age=hasTime?Math.max(0,Number(now)-Number(updatedAt)):0,freshness=hasTime?Math.exp(-Math.LN2*age/halfLife):1,strength=clamp(evidenceStrength*freshness);
  return{reliability:raw,effectiveReliability:clamp(.5+(raw-.5)*strength),evidenceStrength,freshness,strength};
}

function episodePayload(row){
  const stored=row?.row?.record ?? row?.record ?? null;
  if(stored?.schema==='xavi-witness-episode-memory/v1')return stored;
  if(stored?.schema==='xavi-auto-retained-memory/v1'&&stored?.kind==='witness-episode'&&stored?.payload?.schema==='xavi-witness-episode-memory/v1')return stored.payload;
  return null;
}
function boundedStrings(values,limit=8){return (Array.isArray(values)?values:[]).map(String).filter(Boolean).slice(-limit);}
function relationNames(value){
  if(Array.isArray(value))return value.map(row=>Array.isArray(row)?String(row[0]||''):String(row||'')).filter(Boolean).slice(0,16);
  return Object.keys(value||{}).slice(0,16);
}

export function projectWitnessEpisodeHint(row){
  const episode=episodePayload(row);if(!episode)return null;
  const semantic=episode.semantic||{},outcome=episode.outcome||{},promotion=episode.promotion||{};
  return{
    schema:'xavi-witness-episode-hint/v1',recordId:row?.recordId??row?.id??null,witnessDigest:row?.witnessDigest??episode.outcomeWitnessDigest??null,
    score:Number(row?.score??0),trustScore:Number(row?.trustScore??0),memoryUtility:Number(row?.memoryUtility??0),planReliability:row?.planReliability==null?(row?.utility?.planReliability==null?null:Number(row.utility.planReliability)):Number(row.planReliability),branchCalibrationReliability:row?.branchCalibrationReliability==null?(row?.utility?.branchCalibrationReliability==null?null:Number(row.utility.branchCalibrationReliability)):Number(row.branchCalibrationReliability),branchCalibrationAttempts:row?.branchCalibrationAttempts==null?(row?.utility?.branchCalibrationAttempts==null?null:Number(row.utility.branchCalibrationAttempts)):Number(row.branchCalibrationAttempts),branchCalibrationUpdatedAt:row?.branchCalibrationUpdatedAt==null?(row?.utility?.branchCalibrationUpdatedAt==null?null:Number(row.utility.branchCalibrationUpdatedAt)):Number(row.branchCalibrationUpdatedAt),branchCalibrationRecentReliability:row?.branchCalibrationRecentReliability==null?(row?.utility?.branchCalibrationRecentReliability==null?null:Number(row.utility.branchCalibrationRecentReliability)):Number(row.branchCalibrationRecentReliability),branchCalibrationRecentWeight:row?.branchCalibrationRecentWeight==null?(row?.utility?.branchCalibrationRecentWeight==null?null:Number(row.utility.branchCalibrationRecentWeight)):Number(row.branchCalibrationRecentWeight),branchCalibrationRecentUpdatedAt:row?.branchCalibrationRecentUpdatedAt==null?(row?.utility?.branchCalibrationRecentUpdatedAt==null?null:Number(row.utility.branchCalibrationRecentUpdatedAt)):Number(row.branchCalibrationRecentUpdatedAt),branchCalibrationDrift:row?.branchCalibrationDrift==null?(row?.utility?.branchCalibrationDrift==null?null:Number(row.utility.branchCalibrationDrift)):Number(row.branchCalibrationDrift),
    capability:episode.capability??null,strategyId:episode.strategyId??null,intent:semantic.intent??null,semanticClass:semantic.semanticClass??null,
    nextOperation:semantic.nextOperation??null,targetHint:semantic.targetHint??null,nextWitnessType:semantic.expectedWitnessDelta?.expectedNextType??semantic.chainContinuation??null,
    shortTermSignature:semantic.shortTermSignature??null,recentTypes:boundedStrings(semantic.recentTypes,6),entryWitnessType:semantic.entryWitnessType??boundedStrings(semantic.recentTypes,6).at(-1)??null,chainMotifs:boundedStrings(semantic.chainMotifs,6),workingRelations:relationNames(semantic.workingRelations),patternScore:row?.patternScore==null?null:Number(row.patternScore),
    compatibility:semantic.compatibility??null,conflict:semantic.conflict??null,feasibility:semantic.feasibility??null,
    outcomeOk:Boolean(outcome.ok),validated:outcome.validated!==false,promoted:Boolean(promotion.promoted),demoted:Boolean(promotion.demoted),
    witnessDeltaAccuracy:episode.witnessDelta?.accuracy??null,authority:false,
  };
}

function capabilityRelevance(hintCapability,currentCapability){
  const a=String(hintCapability||'').toLowerCase(),b=String(currentCapability||'').toLowerCase();
  if(!a||!b)return .55;if(a===b)return 1;const ar=a.split(':')[0],br=b.split(':')[0];if(ar&&ar===br)return .82;if(a.includes(b)||b.includes(a))return .72;return .36;
}
function jaccard(a,b){
  const A=new Set((Array.isArray(a)?a:[]).map(String).filter(Boolean)),B=new Set((Array.isArray(b)?b:[]).map(String).filter(Boolean));
  if(!A.size||!B.size)return .55;let intersection=0;for(const item of A)if(B.has(item))intersection++;return intersection/(A.size+B.size-intersection);
}
function patternSimilarity(hint,currentMotifs,currentRelations){
  const motif=jaccard(hint.chainMotifs,currentMotifs),relations=jaccard(hint.workingRelations,currentRelations);
  const signature=hint.shortTermSignature&&currentMotifs?.shortTermSignature&&hint.shortTermSignature===currentMotifs.shortTermSignature?1:null;
  return clamp(signature==null?.68*motif+.32*relations:.45*signature+.38*motif+.17*relations);
}
function vote(map,key,weight){if(!key||!Number.isFinite(weight)||weight===0)return;map.set(String(key),(map.get(String(key))||0)+weight);}
function bestPositive(map){let key=null,value=0;for(const [k,v] of map)if(v>value){key=k;value=v;}return{key,value};}
function mostNegative(map){let key=null,value=0;for(const [k,v] of map)if(v<value){key=k;value=v;}return{key,value};}

export function buildWitnessEpisodeGuidance(hints,{capability='',intent='',chainMotifs=[],workingRelations={},shortTermSignature=null}={}){
  const rows=(Array.isArray(hints)?hints:[]).filter(x=>x?.schema==='xavi-witness-episode-hint/v1').slice(0,12);
  if(!rows.length)return{schema:'xavi-witness-episode-guidance/v1',episodeCount:0,confidence:0,patternSupport:0,recommendedOperation:null,operationConfidence:0,avoidedOperation:null,avoidOperationConfidence:0,recommendedStrategyId:null,strategyConfidence:0,avoidedStrategyId:null,avoidStrategyConfidence:0,targetHint:null,targetConfidence:0,nextWitnessType:null,nextWitnessConfidence:0,successSupport:0,failureSupport:0,compatibility:null,conflict:null,feasibility:null,authority:false};
  const operations=new Map(),strategies=new Map(),targets=new Map(),nextTypes=new Map();
  const currentRelations=relationNames(workingRelations);const motifContext=boundedStrings(chainMotifs,8);motifContext.shortTermSignature=shortTermSignature;
  let positive=0,negative=0,totalWeight=0,weightedCompatibility=0,weightedConflict=0,weightedFeasibility=0,metricWeight=0,patternWeight=0;
  for(const hint of rows){
    const similarity=clamp((Number(hint.score||0)+1)/2),trust=clamp(hint.trustScore||0),relevance=capabilityRelevance(hint.capability,capability),pattern=patternSimilarity(hint,motifContext,currentRelations);
    const intentFit=!intent||!hint.intent?1:(String(intent)===String(hint.intent)?1:.72);
    let magnitude=Math.max(.02,(.31+.29*similarity+.25*trust+.15*pattern)*relevance*intentFit*(.60+.40*pattern));
    if(hint.promoted)magnitude*=1.08;if(hint.demoted)magnitude*=1.12;
    const success=Boolean(hint.validated&&hint.outcomeOk&&!hint.demoted),sign=success?1:-1,weight=sign*magnitude;
    vote(operations,hint.nextOperation,weight);vote(strategies,hint.strategyId,weight);vote(targets,hint.targetHint,weight);vote(nextTypes,hint.nextWitnessType,weight);
    totalWeight+=magnitude;patternWeight+=magnitude*pattern;if(success)positive+=magnitude;else negative+=magnitude;
    if(hint.compatibility!=null){weightedCompatibility+=magnitude*clamp(hint.compatibility);metricWeight+=magnitude;}
    if(hint.conflict!=null)weightedConflict+=magnitude*clamp(hint.conflict);if(hint.feasibility!=null)weightedFeasibility+=magnitude*clamp(hint.feasibility);
  }
  const op=bestPositive(operations),avoidOp=mostNegative(operations),strategy=bestPositive(strategies),avoidStrategy=mostNegative(strategies),target=bestPositive(targets),next=bestPositive(nextTypes);
  const denom=Math.max(.0001,totalWeight),patternSupport=rows.length?clamp(patternWeight/denom):0,confidence=clamp((positive-negative*.35)/denom)*clamp(rows.length/3,.35,1)*(.72+.28*patternSupport);
  return{
    schema:'xavi-witness-episode-guidance/v1',episodeCount:rows.length,confidence,patternSupport,
    recommendedOperation:op.key,operationConfidence:clamp(op.value/denom),avoidedOperation:avoidOp.key,avoidOperationConfidence:clamp(Math.abs(avoidOp.value)/denom),
    recommendedStrategyId:strategy.key,strategyConfidence:clamp(strategy.value/denom),avoidedStrategyId:avoidStrategy.key,avoidStrategyConfidence:clamp(Math.abs(avoidStrategy.value)/denom),
    targetHint:target.key,targetConfidence:clamp(target.value/denom),nextWitnessType:next.key,nextWitnessConfidence:clamp(next.value/denom),
    successSupport:clamp(positive/denom),failureSupport:clamp(negative/denom),compatibility:metricWeight?clamp(weightedCompatibility/metricWeight):null,
    conflict:metricWeight?clamp(weightedConflict/metricWeight):null,feasibility:metricWeight?clamp(weightedFeasibility/metricWeight):null,authority:false,
  };
}

export function episodeStrategyAdjustment(strategy,guidance){
  if(!guidance?.episodeCount)return 0;
  const id=String(strategy?.id||''),text=[id,strategy?.metadata?.observerId,strategy?.metadata?.modelId,...(strategy?.capabilities||[])].filter(Boolean).join(' ').toLowerCase();
  const patternScale=.70+.30*clamp(guidance.patternSupport??.55);let value=0;
  if(guidance.recommendedStrategyId===id)value+=.22*guidance.strategyConfidence;if(guidance.avoidedStrategyId===id)value-=.26*guidance.avoidStrategyConfidence;
  if(guidance.recommendedOperation&&text.includes(String(guidance.recommendedOperation).toLowerCase()))value+=.10*guidance.operationConfidence;
  if(guidance.avoidedOperation&&text.includes(String(guidance.avoidedOperation).toLowerCase()))value-=.12*guidance.avoidOperationConfidence;
  if(guidance.targetHint&&text.includes(String(guidance.targetHint).toLowerCase()))value+=.06*guidance.targetConfidence;
  return Math.max(-.32,Math.min(.32,value*patternScale));
}

export function compareEpisodeGuidanceToHeads(heads,guidance){
  const checks=[];
  const add=(name,expected,actual)=>{if(expected==null||actual==null||expected==='')return;checks.push({name,expected:String(expected),actual:String(actual),match:String(expected)===String(actual)});};
  add('operation',guidance?.recommendedOperation,heads?.nextOperation);
  add('target',guidance?.targetHint,heads?.targetHint);
  add('next-witness',guidance?.nextWitnessType,heads?.chainContinuation?.type);
  if(guidance?.feasibility!=null&&heads?.feasibility!=null)checks.push({name:'feasibility',expected:Number(guidance.feasibility)>=.5,actual:Number(heads.feasibility)>=.5,match:(Number(guidance.feasibility)>=.5)===(Number(heads.feasibility)>=.5)});
  const observed=checks.length,correct=checks.filter(row=>row.match).length,agreement=observed?correct/observed:.5;
  return{schema:'xavi-witness-episode-consistency/v1',observed,correct,agreement,disagreement:observed?1-agreement:.5,checks,confidence:Number(guidance?.confidence||0),patternSupport:Number(guidance?.patternSupport||0),authority:false};
}

function episodeTransitionWeight(hint){
  const similarity=clamp((Number(hint?.score??0)+1)/2),trust=clamp(hint?.trustScore??0),pattern=clamp(hint?.patternScore??.55),utility=clamp((Number(hint?.memoryUtility??0)+1)/2),delta=hint?.witnessDeltaAccuracy==null?.65:clamp(hint.witnessDeltaAccuracy),plan=hint?.planReliability==null?.65:clamp(hint.planReliability);
  return clamp(.14+.20*similarity+.20*trust+.14*pattern+.10*utility+.08*delta+.14*plan);
}

export function buildWitnessEpisodeTransitionPlan(hints,{currentWitnessType=null,maxDepth=3,beamWidth=4,minStepConfidence=.42,branchCalibrationHalfLifeMs=DEFAULT_BRANCH_CALIBRATION_HALF_LIFE_MS,now=Date.now()}={}){
  const depthLimit=Math.max(1,Math.min(4,Number(maxDepth)||3)),width=Math.max(1,Math.min(8,Number(beamWidth)||4)),start=String(currentWitnessType||'').trim()||null;
  const rows=(Array.isArray(hints)?hints:[]).filter(row=>row?.schema==='xavi-witness-episode-hint/v1').slice(0,16);
  const transitions=rows.map(row=>({recordId:row.recordId||null,witnessDigest:row.witnessDigest||null,from:String(row.entryWitnessType||'').trim()||null,to:String(row.nextWitnessType||'').trim()||null,operation:row.nextOperation||null,targetHint:row.targetHint||null,strategyId:row.strategyId||null,confidence:episodeTransitionWeight(row),branchCalibrationReliability:row.branchCalibrationReliability==null?null:clamp(row.branchCalibrationReliability),branchCalibrationAttempts:row.branchCalibrationAttempts==null?null:Math.max(0,Number(row.branchCalibrationAttempts)||0),branchCalibrationUpdatedAt:row.branchCalibrationUpdatedAt==null?null:Number(row.branchCalibrationUpdatedAt),branchCalibrationRecentReliability:row.branchCalibrationRecentReliability==null?null:clamp(row.branchCalibrationRecentReliability),branchCalibrationRecentWeight:row.branchCalibrationRecentWeight==null?null:Math.max(0,Number(row.branchCalibrationRecentWeight)||0),branchCalibrationRecentUpdatedAt:row.branchCalibrationRecentUpdatedAt==null?null:Number(row.branchCalibrationRecentUpdatedAt),branchCalibrationDrift:row.branchCalibrationDrift==null?null:Math.max(0,Number(row.branchCalibrationDrift)||0),validated:Boolean(row.validated),successful:Boolean(row.validated&&row.outcomeOk&&!row.demoted),demoted:Boolean(row.demoted),authority:false}));
  const forward=transitions.filter(row=>row.from&&row.to&&row.successful&&row.confidence>=minStepConfidence),avoided=transitions.filter(row=>row.from&&(!row.successful||row.demoted)).filter(row=>!start||row.from===start).sort((a,b)=>b.confidence-a.confidence).slice(0,4);
  if(!start||!forward.length)return{schema:'xavi-witness-episode-transition-plan/v1',currentWitnessType:start,depth:0,confidence:0,steps:[],alternatives:[],avoidedTransitions:avoided,connected:false,authority:false};
  let beam=[{state:start,steps:[],product:1,used:new Set()}],paths=[];
  for(let depth=0;depth<depthLimit;depth++){
    const expanded=[];
    for(const path of beam){
      for(const edge of forward){if(edge.from!==path.state||path.used.has(edge.recordId||edge.witnessDigest))continue;const used=new Set(path.used);used.add(edge.recordId||edge.witnessDigest);const next={state:edge.to,steps:[...path.steps,edge],product:path.product*edge.confidence,used};expanded.push(next);paths.push(next);}
    }
    if(!expanded.length)break;
    expanded.sort((a,b)=>{const ac=Math.pow(a.product,1/a.steps.length),bc=Math.pow(b.product,1/b.steps.length);return bc-ac||b.steps.length-a.steps.length;});beam=expanded.slice(0,width);
  }
  const scored=paths.map(path=>({steps:path.steps,depth:path.steps.length,confidence:Math.pow(path.product,1/path.steps.length),branchCalibrationReliability:path.steps[0]?.branchCalibrationReliability??null,branchCalibrationAttempts:path.steps[0]?.branchCalibrationAttempts??null,branchCalibrationUpdatedAt:path.steps[0]?.branchCalibrationUpdatedAt??null,branchCalibrationRecentReliability:path.steps[0]?.branchCalibrationRecentReliability??null,branchCalibrationRecentWeight:path.steps[0]?.branchCalibrationRecentWeight??null,branchCalibrationRecentUpdatedAt:path.steps[0]?.branchCalibrationRecentUpdatedAt??null,branchCalibrationDrift:path.steps[0]?.branchCalibrationDrift??null,terminalWitnessType:path.state})).sort((a,b)=>((b.confidence+.08*(b.depth-1))-(a.confidence+.08*(a.depth-1)))||b.depth-a.depth);
  const best=scored[0]||null;
  const alternatives=scored.slice(1,4);
  const posteriorRows=[best,...alternatives].filter(Boolean).map((row,index)=>{const adaptiveReliability=row.branchCalibrationRecentReliability==null?row.branchCalibrationReliability:row.branchCalibrationRecentReliability,adaptiveWeight=row.branchCalibrationRecentWeight==null?row.branchCalibrationAttempts:row.branchCalibrationRecentWeight,adaptiveUpdatedAt=row.branchCalibrationRecentUpdatedAt==null?row.branchCalibrationUpdatedAt:row.branchCalibrationRecentUpdatedAt;const calibration=effectiveBranchCalibration(adaptiveReliability,{attempts:adaptiveWeight,updatedAt:adaptiveUpdatedAt,now,halfLifeMs:branchCalibrationHalfLifeMs});return{index,weight:Math.max(1e-6,clamp(row.confidence)),calibrationReliability:row.branchCalibrationReliability==null?null:clamp(row.branchCalibrationReliability),adaptiveCalibrationReliability:adaptiveReliability==null?null:clamp(adaptiveReliability),calibrationDrift:row.branchCalibrationDrift??null,effectiveCalibrationReliability:calibration.effectiveReliability,calibrationEvidenceStrength:calibration.evidenceStrength,calibrationFreshness:calibration.freshness,calibrationStrength:calibration.strength,calibrationAttempts:row.branchCalibrationAttempts??null,calibrationUpdatedAt:row.branchCalibrationUpdatedAt??null,adaptiveCalibrationWeight:adaptiveWeight??null,adaptiveCalibrationUpdatedAt:adaptiveUpdatedAt??null};});
  const posteriorTotal=posteriorRows.reduce((sum,row)=>sum+row.weight,0)||1,baseProbabilities=posteriorRows.map(row=>row.weight/posteriorTotal),uniform=posteriorRows.length?1/posteriorRows.length:1;
  const branchCalibrationEvidence=posteriorRows.filter(row=>row.calibrationReliability!=null).length;
  const calibratedRaw=baseProbabilities.map((probability,index)=>{const reliability=posteriorRows[index].effectiveCalibrationReliability;if(reliability==null)return probability;const factor=.75+.5*reliability;return Math.max(1e-6,uniform+factor*(probability-uniform));});
  const calibratedTotal=calibratedRaw.reduce((sum,p)=>sum+p,0)||1,probabilities=calibratedRaw.map(p=>p/calibratedTotal);
  const entropyRaw=-probabilities.reduce((sum,p)=>sum+(p>0?p*Math.log(p):0),0),maxEntropy=probabilities.length>1?Math.log(probabilities.length):1,branchEntropy=probabilities.length>1?clamp(entropyRaw/maxEntropy):0;
  const dominantIndex=probabilities.length?probabilities.reduce((bestIndex,p,index)=>p>probabilities[bestIndex]?index:bestIndex,0):0;
  return{schema:'xavi-witness-episode-transition-plan/v1',currentWitnessType:start,depth:best?.depth||0,confidence:best?.confidence||0,branchEntropy,branchDisagreement:branchEntropy,branchCalibrationApplied:branchCalibrationEvidence>0,branchCalibrationEvidence,branchCalibrationHalfLifeMs:Math.max(1,Number(branchCalibrationHalfLifeMs)||DEFAULT_BRANCH_CALIBRATION_HALF_LIFE_MS),basePrimaryProbability:baseProbabilities[0]??1,primaryCalibrationReliability:posteriorRows[0]?.calibrationReliability??null,primaryAdaptiveCalibrationReliability:posteriorRows[0]?.adaptiveCalibrationReliability??null,primaryCalibrationDrift:posteriorRows[0]?.calibrationDrift??null,primaryAdaptiveCalibrationWeight:posteriorRows[0]?.adaptiveCalibrationWeight??null,primaryAdaptiveCalibrationUpdatedAt:posteriorRows[0]?.adaptiveCalibrationUpdatedAt??null,primaryEffectiveCalibrationReliability:posteriorRows[0]?.effectiveCalibrationReliability??null,primaryCalibrationAttempts:posteriorRows[0]?.calibrationAttempts??null,primaryCalibrationUpdatedAt:posteriorRows[0]?.calibrationUpdatedAt??null,primaryCalibrationFreshness:posteriorRows[0]?.calibrationFreshness??null,primaryCalibrationEvidenceStrength:posteriorRows[0]?.calibrationEvidenceStrength??null,primaryCalibrationStrength:posteriorRows[0]?.calibrationStrength??null,primaryProbability:probabilities[0]??1,dominantBranchId:dominantIndex===0?'primary':`alternative:${dominantIndex}`,dominantBranchProbability:probabilities[dominantIndex]??1,terminalWitnessType:best?.terminalWitnessType||start,steps:(best?.steps||[]).map(({used,...step})=>step),alternatives:alternatives.map((row,index)=>({id:`alternative:${index+1}`,depth:row.depth,confidence:row.confidence,baseProbability:baseProbabilities[index+1]??0,calibrationReliability:posteriorRows[index+1]?.calibrationReliability??null,adaptiveCalibrationReliability:posteriorRows[index+1]?.adaptiveCalibrationReliability??null,calibrationDrift:posteriorRows[index+1]?.calibrationDrift??null,adaptiveCalibrationWeight:posteriorRows[index+1]?.adaptiveCalibrationWeight??null,adaptiveCalibrationUpdatedAt:posteriorRows[index+1]?.adaptiveCalibrationUpdatedAt??null,effectiveCalibrationReliability:posteriorRows[index+1]?.effectiveCalibrationReliability??null,calibrationAttempts:posteriorRows[index+1]?.calibrationAttempts??null,calibrationUpdatedAt:posteriorRows[index+1]?.calibrationUpdatedAt??null,calibrationFreshness:posteriorRows[index+1]?.calibrationFreshness??null,calibrationEvidenceStrength:posteriorRows[index+1]?.calibrationEvidenceStrength??null,calibrationStrength:posteriorRows[index+1]?.calibrationStrength??null,probability:probabilities[index+1]??0,terminalWitnessType:row.terminalWitnessType,steps:row.steps.map(step=>({recordId:step.recordId,witnessDigest:step.witnessDigest,from:step.from,to:step.to,operation:step.operation,targetHint:step.targetHint,strategyId:step.strategyId,confidence:step.confidence,branchCalibrationReliability:step.branchCalibrationReliability??null,authority:false}))})),avoidedTransitions:avoided,connected:Boolean(best),authority:false};
}

export function summarizeEpisodePlanBranches(plan){
  if(!plan?.connected||!plan.steps?.length)return{schema:'xavi-witness-plan-branch-summary/v2',branchCount:0,firstStrategyCount:0,disagreement:0,entropy:0,dominantStrategyId:null,dominantShare:1,primaryProbability:1,calibrationDriftEvidence:0,calibrationDrift:0,maximumCalibrationDrift:0,calibrationDriftPressure:0,authority:false};
  const alternatives=(Array.isArray(plan.alternatives)?plan.alternatives:[]).slice(0,3);
  const hasPosterior=plan.primaryProbability!=null&&Number.isFinite(Number(plan.primaryProbability))&&alternatives.every(row=>row?.probability!=null&&Number.isFinite(Number(row.probability)));
  const primaryDrift=plan.primaryCalibrationDrift==null?null:clamp(plan.primaryCalibrationDrift),primaryStrength=plan.primaryCalibrationStrength==null?0:clamp(plan.primaryCalibrationStrength);
  let primaryProbability,rows;
  if(hasPosterior){
    const raw=[{strategyId:plan.steps[0]?.strategyId||null,probability:clamp(Number(plan.primaryProbability)),primary:true,calibrationDrift:primaryDrift,calibrationStrength:primaryStrength},...alternatives.map(row=>({strategyId:row?.steps?.[0]?.strategyId||row?.firstStrategyId||null,probability:clamp(Number(row?.probability)),primary:false,calibrationDrift:row?.calibrationDrift==null?null:clamp(row.calibrationDrift),calibrationStrength:row?.calibrationStrength==null?0:clamp(row.calibrationStrength)}))].filter(row=>row.strategyId);const total=raw.reduce((sum,row)=>sum+row.probability,0)||1;rows=raw.map(row=>({...row,probability:row.probability/total}));primaryProbability=rows.find(row=>row.primary)?.probability??1;
  } else {
    const weighted=[{strategyId:plan.steps[0]?.strategyId||null,weight:clamp(plan.confidence||0),primary:true,calibrationDrift:primaryDrift,calibrationStrength:primaryStrength},...alternatives.map(row=>({strategyId:row?.steps?.[0]?.strategyId||row?.firstStrategyId||null,weight:.72*clamp(row?.confidence||0),primary:false,calibrationDrift:row?.calibrationDrift==null?null:clamp(row.calibrationDrift),calibrationStrength:row?.calibrationStrength==null?0:clamp(row.calibrationStrength)}))].filter(row=>row.strategyId);const total=weighted.reduce((sum,row)=>sum+row.weight,0)||1;rows=weighted.map(row=>({...row,probability:row.weight/total}));primaryProbability=rows.find(row=>row.primary)?.probability??1;
  }
  const support=new Map();for(const row of rows)support.set(row.strategyId,(support.get(row.strategyId)||0)+row.probability);const ranked=[...support.entries()].sort((a,b)=>b[1]-a[1]),dominant=ranked[0]||[null,1],entropyRaw=-rows.reduce((sum,row)=>sum+(row.probability>0?row.probability*Math.log(row.probability):0),0),maxEntropy=rows.length>1?Math.log(rows.length):1,entropy=rows.length>1?clamp(entropyRaw/maxEntropy):0;
  const driftRows=rows.filter(row=>row.calibrationDrift!=null&&Number.isFinite(Number(row.calibrationDrift))),calibrationDriftEvidence=driftRows.filter(row=>row.calibrationStrength>0).length,calibrationDrift=clamp(driftRows.reduce((sum,row)=>sum+row.probability*clamp(row.calibrationDrift),0)),maximumCalibrationDrift=driftRows.length?Math.max(...driftRows.map(row=>clamp(row.calibrationDrift))):0,calibrationDriftPressure=clamp(driftRows.reduce((sum,row)=>sum+row.probability*clamp(row.calibrationDrift)*clamp(row.calibrationStrength),0));
  return{schema:'xavi-witness-plan-branch-summary/v2',branchCount:alternatives.length,firstStrategyCount:support.size,disagreement:entropy,entropy,dominantStrategyId:dominant[0],dominantShare:clamp(dominant[1]),primaryProbability,calibrationDriftEvidence,calibrationDrift,maximumCalibrationDrift,calibrationDriftPressure,authority:false};
}

export function episodePlanStrategyAdjustment(strategy,plan){
  if(!plan?.connected||!plan.steps?.length)return 0;const id=String(strategy?.id||''),first=plan.steps[0],alternatives=(Array.isArray(plan.alternatives)?plan.alternatives:[]).slice(0,3),summary=summarizeEpisodePlanBranches(plan);let value=0;const primaryWeight=clamp(summary.primaryProbability),primaryStrength=clamp(plan.confidence||0);if(first.strategyId===id)value+=.14*primaryWeight*primaryStrength;if(first.operation&&[id,...(strategy?.capabilities||[])].join(' ').toLowerCase().includes(String(first.operation).toLowerCase()))value+=.05*primaryWeight*primaryStrength;
  const fallbackTotal=alternatives.reduce((sum,row)=>sum+clamp(row?.confidence||0),0)||1;for(const alt of alternatives){const altFirst=alt?.steps?.[0]||((alt?.firstStrategyId)?{strategyId:alt.firstStrategyId,operation:alt.firstOperation||null}:null);const probability=alt?.probability!=null&&Number.isFinite(Number(alt.probability))?clamp(Number(alt.probability)):clamp(1-primaryWeight)*(clamp(alt?.confidence||0)/fallbackTotal);const branchStrength=clamp(alt?.confidence??plan.confidence??0);if(altFirst?.strategyId===id)value+=.14*probability*branchStrength;if(altFirst?.operation&&[id,...(strategy?.capabilities||[])].join(' ').toLowerCase().includes(String(altFirst.operation).toLowerCase()))value+=.05*probability*branchStrength;}
  for(const avoid of plan.avoidedTransitions||[])if(avoid.strategyId===id)value-=.12*clamp(avoid.confidence);return Math.max(-.18,Math.min(.18,value));
}


export function selectWitnessEpisodeTransitionPlanForStrategy(plan,strategyId){
  if(!plan?.connected||!Array.isArray(plan.steps)||!plan.steps.length)return plan||null;
  const chosen=String(strategyId||'').trim();if(!chosen||String(plan.steps[0]?.strategyId||'')===chosen)return plan;
  const alt=(plan.alternatives||[]).find(row=>String(row?.steps?.[0]?.strategyId||row?.firstStrategyId||'')===chosen);const altSteps=Array.isArray(alt?.steps)&&alt.steps.length?alt.steps:(alt?.firstStrategyId?[{recordId:alt.firstRecordId||null,witnessDigest:alt.firstWitnessDigest||null,from:alt.firstFrom||null,to:alt.firstTo||null,operation:alt.firstOperation||null,targetHint:alt.firstTargetHint||null,strategyId:alt.firstStrategyId,confidence:Number(alt.firstConfidence||0),authority:false}]:[]);if(!altSteps.length)return plan;
  return{schema:plan.schema||'xavi-witness-episode-transition-plan/v1',continuationId:plan.continuationId||null,currentWitnessType:plan.currentWitnessType||altSteps[0]?.from||null,depth:Number(alt.depth||altSteps.length||0),confidence:Number(alt.confidence||0),baseConfidence:alt.baseConfidence==null?null:Number(alt.baseConfidence),ageFactor:plan.ageFactor==null?null:Number(plan.ageFactor),structuralFactor:plan.structuralFactor==null?null:Number(plan.structuralFactor),advanceCount:Number(plan.advanceCount||0),repairCount:Number(plan.repairCount||0),branchSelectionCount:Number(plan.branchSelectionCount||0),terminalWitnessType:alt.terminalWitnessType||altSteps.at(-1)?.to||null,connected:true,steps:altSteps.slice(0,4),alternatives:[],avoidedTransitions:plan.avoidedTransitions||[],selectedAlternativeId:alt.id||null,selectedAlternativeSource:alt.source||null,authority:false};
}



export function assessWitnessEpisodeBranchPosterior(plan,{actualNextWitnessType=null,chosenStrategyId=null,validated=false}={}){
  const alternatives=(Array.isArray(plan?.alternatives)?plan.alternatives:[]).slice(0,3);
  const primaryFirst=plan?.steps?.[0]||null;
  if(!plan?.connected||!primaryFirst||!alternatives.length)return{schema:'xavi-witness-episode-branch-posterior-assessment/v1',applicable:false,observed:false,validationPassed:validated===true,reason:'branch-posterior-unavailable',branchCount:alternatives.length,authority:false};
  const rows=[{id:'primary',strategyId:primaryFirst.strategyId||null,to:primaryFirst.to||null,confidence:clamp(plan.confidence||0),probability:plan.primaryProbability,primary:true},...alternatives.map((row,index)=>{const first=row?.steps?.[0]||null;return{id:row?.id||`alternative:${index+1}`,strategyId:first?.strategyId||row?.firstStrategyId||null,to:first?.to||row?.firstTo||null,confidence:clamp(row?.confidence||0),probability:row?.probability,primary:false};})];
  const hasPosterior=plan.primaryProbability!=null&&Number.isFinite(Number(plan.primaryProbability))&&rows.slice(1).every(row=>row.probability!=null&&Number.isFinite(Number(row.probability)));
  let probs;
  if(hasPosterior){const raw=rows.map(row=>clamp(Number(row.probability)));const total=raw.reduce((sum,p)=>sum+p,0)||1;probs=raw.map(p=>p/total);}
  else {const weights=rows.map(row=>Math.max(1e-6,row.confidence*(row.primary?1:.72)));const total=weights.reduce((sum,w)=>sum+w,0)||1;probs=weights.map(w=>w/total);}
  rows.forEach((row,index)=>row.probability=probs[index]);
  const entropyRaw=-probs.reduce((sum,p)=>sum+(p>0?p*Math.log(p):0),0),maxEntropy=rows.length>1?Math.log(rows.length):1,branchEntropy=rows.length>1?clamp(entropyRaw/maxEntropy):0;
  const dominantIndex=probs.reduce((best,p,index)=>p>probs[best]?index:best,0);
  const actual=String(actualNextWitnessType||'').trim()||null,chosen=String(chosenStrategyId||'').trim()||null,validationPassed=validated===true,observed=Boolean(validationPassed&&actual&&chosen);
  const selectedIndex=observed?rows.findIndex(row=>String(row.strategyId||'')===chosen):-1,selectedSupported=selectedIndex>=0,transitionMatched=Boolean(selectedSupported&&(!rows[selectedIndex].to||String(rows[selectedIndex].to)===actual));
  const matchedIndex=transitionMatched?selectedIndex:-1,supportMiss=Boolean(observed&&matchedIndex<0),selectedProbability=selectedSupported?probs[selectedIndex]:null,predictedProbability=observed?(supportMiss?0:probs[matchedIndex]):null;
  const calibrationError=observed?(supportMiss?1:clamp(1-predictedProbability)):null;
  const brierScore=observed?(supportMiss?1:clamp(rows.reduce((sum,row,index)=>{const target=index===matchedIndex?1:0;return sum+(row.probability-target)**2;},0)/2)):null;
  const surprise=observed?-Math.log(Math.max(1e-6,predictedProbability)):null;
  const normalizedSurprise=observed?(rows.length>1?clamp(surprise/Math.log(rows.length)):supportMiss?1:0):null;
  let reason='branch-outcome-unobserved';if(!validationPassed)reason='terminal-outcome-not-validated';else if(validationPassed&&(!actual||!chosen))reason='branch-outcome-unobserved';else if(supportMiss)reason='observed-branch-outside-posterior-support';else if(observed)reason='observed-branch-scored';
  return{schema:'xavi-witness-episode-branch-posterior-assessment/v1',applicable:true,observed,validationPassed,reason,branchCount:alternatives.length,branchEntropy,dominantBranchId:rows[dominantIndex]?.id||null,dominantBranchProbability:probs[dominantIndex]??1,selectedSupported,selectedBranchId:selectedIndex>=0?rows[selectedIndex].id:null,selectedProbability,selectedExpectedNextWitnessType:selectedIndex>=0?rows[selectedIndex].to:null,transitionMatched,matchedBranchId:matchedIndex>=0?rows[matchedIndex].id:null,predictedProbability,calibrationError,brierScore,surprise,normalizedSurprise,supportMiss,actualNextWitnessType:actual,chosenStrategyId:chosen,authority:false};
}
export function assessWitnessEpisodeTransitionPlan(plan,{actualNextWitnessType=null,chosenStrategyId=null,validated=false}={}){
  const first=plan?.connected&&Array.isArray(plan?.steps)&&plan.steps.length?plan.steps[0]:null;
  const actual=String(actualNextWitnessType||'').trim()||null,chosen=String(chosenStrategyId||'').trim()||null,expected=String(first?.to||'').trim()||null,plannedStrategy=String(first?.strategyId||'').trim()||null;
  const followed=Boolean(first&&chosen&&plannedStrategy&&chosen===plannedStrategy);
  const validationPassed=validated===true;
  const observed=Boolean(first&&followed&&validationPassed&&actual&&expected);
  const match=observed?actual===expected:null;
  let reason='plan-disconnected';
  if(first&&!followed)reason='planned-strategy-not-followed';
  else if(first&&followed&&!validationPassed)reason='terminal-outcome-not-validated';
  else if(first&&followed&&validationPassed&&(!actual||!expected))reason='witness-endpoint-unobserved';
  else if(observed)reason=match?'witness-transition-match':'witness-transition-mismatch';
  return{schema:'xavi-witness-episode-transition-assessment/v1',routePlanConnected:Boolean(plan?.connected),planDepth:Number(plan?.depth||0),followed,validationPassed,observed,match,reason,actualNextWitnessType:actual,firstStep:first?{recordId:first.recordId||null,witnessDigest:first.witnessDigest||null,from:first.from||null,to:first.to||null,operation:first.operation||null,targetHint:first.targetHint||null,strategyId:first.strategyId||null,confidence:Number(first.confidence||0),authority:false}:null,authority:false};
}
