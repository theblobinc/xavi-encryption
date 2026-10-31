import { digest } from '../core/utils.js';
import { normalizeSmallModelRuntimeDescriptor } from '../runtime/small-model-runtime.js';

function clamp(v,lo=0,hi=1){return Math.max(lo,Math.min(hi,Number(v)||0));}
function retentionScore(retention={}){if(retention?.promotionEligible)return 1;const c=retention?.contracts||{};const values=Object.values(c);return values.length?values.filter(Boolean).length/values.length:0.35;}
function epistemicScore(status='reported'){return({observed:1,supported:.95,derived:.82,inferred:.72,reported:.62,contested:.48,uncertain:.4,speculative:.2,refuted:.05})[String(status).toLowerCase()]??.45;}
function recencyScore(ts,halfLifeMs){if(!ts||!halfLifeMs)return .7;const age=Math.max(0,Date.now()-Number(ts));return Math.exp(-Math.LN2*age/halfLifeMs);}
function autoRetentionPrior(metadata={}){if(!metadata?.autoRetained)return 0;if(metadata?.episode)return .02;const type=String(metadata.sourceWitnessType||'');if(type==='state-committed')return -0.08;if(type==='terminal-outcome')return -0.05;if(type==='observer-evidence')return -0.03;if(type.startsWith('policy-')||type.startsWith('semantic-backfill-')||type==='semantic-calibration-rebuilt')return -0.04;return -0.04;}
function utilityKey(witnessDigest){return String(witnessDigest||'');}
function blankUtility({witnessDigest,recordId=null}={}){return{schema:'xavi-memory-utility/v1',witnessDigest:String(witnessDigest||''),recordId,attempts:0,positive:0,negative:0,rewardSum:0,value:0,planAttempts:0,planCorrect:0,planAccuracy:null,planReliability:null,branchCalibrationAttempts:0,branchCalibrationCorrect:0,branchCalibrationProbabilitySum:0,branchCalibrationScoreSum:0,branchCalibrationErrorSum:0,branchCalibrationBrierSum:0,branchCalibrationLogLossSum:0,branchCalibrationAccuracy:null,branchCalibrationMeanProbability:null,branchCalibrationError:null,branchCalibrationBrier:null,branchCalibrationLogLoss:null,branchCalibrationReliability:null,branchCalibrationUpdatedAt:null,branchCalibrationRecentReliability:null,branchCalibrationRecentWeight:0,branchCalibrationRecentUpdatedAt:null,branchCalibrationDrift:null,updatedAt:0,authority:false};}

export class WitnessMemory {
  constructor({store,ledger,vectorStore,embedder,namespace='default',halfLifeMs=30*24*3600*1000}={}){
    if(!store||!ledger||!vectorStore||!embedder)throw new TypeError('WitnessMemory requires store, ledger, vectorStore and embedder');
    this.store=store;this.ledger=ledger;this.vectorStore=vectorStore;this.embedder=embedder;this.namespace=String(namespace);this.halfLifeMs=halfLifeMs;
  }
  async init(){await this.vectorStore.init?.();return this;}
  async indexRecord({id,text,recordId=id,witnessDigest,witnessId=null,sourceId=null,kind='memory',metadata={}}={}){
    if(!witnessDigest)throw new TypeError('witnessDigest required');
    const vector=await this.embedder.embed(String(text??''),metadata);
    return this.vectorStore.upsert({id,vector,witnessDigest,witnessId,recordId,sourceId,kind,metadata});
  }
  async indexRetainedRecord(recordRow,{text=null,kind='memory',metadata={}}={}){
    if(!recordRow?.id||!recordRow?.witnessDigest)throw new TypeError('retained record with witness required');
    const content=text??(typeof recordRow.record==='string'?recordRow.record:JSON.stringify(recordRow.record));
    return this.indexRecord({id:recordRow.id,text:content,recordId:recordRow.id,witnessDigest:recordRow.witnessDigest,kind,metadata:{epistemicStatus:recordRow.retention?.epistemicStatus||'observed',retentionAdmissible:Boolean(recordRow.retention?.promotionEligible),retainedAt:recordRow.retainedAt,...metadata}});
  }
  async utility(witnessDigest){
    if(!witnessDigest)return null;
    return await this.store.get('memoryUtility',utilityKey(witnessDigest)).catch(()=>null) || null;
  }
  async recall(query,{limit=8,candidateLimit=Math.max(32,limit*6),filter=null,minScore=-1,requireWitness=true}={}){
    const q=await this.embedder.embed(String(query??''),{kind:'memory-query'});
    const found=await this.vectorStore.search(q,{limit:candidateLimit,filter,minScore});
    const diagnostics={schema:'xavi-memory-recall-diagnostics/v1',rawHits:Number(found.hits?.length||0),missingRecord:0,retired:0,missingWitness:0,accepted:0,returned:0,authority:false};
    const hits=found.hits||[],batchGet=async(table,keys)=>{const list=[...keys];if(!list.length)return[];if(this.store.getMany){try{return await this.store.getMany(table,list);}catch{}}return Promise.all(list.map(key=>this.store.get(table,key).catch(()=>null)));};
    const recordKeys=[...new Set(hits.map(hit=>hit.recordId).filter(Boolean).map(String))],utilityKeys=[...new Set(hits.map(hit=>hit.witnessDigest).filter(Boolean).map(String))];
    const [recordRows,utilityRows]=await Promise.all([batchGet('records',recordKeys),batchGet('memoryUtility',utilityKeys)]),recordMap=new Map(recordKeys.map((key,i)=>[key,recordRows?.[i]||null])),utilityMap=new Map(utilityKeys.map((key,i)=>[key,utilityRows?.[i]||null]));
    const knowledgeKeys=[...new Set(hits.filter(hit=>hit.id&&!recordMap.get(String(hit.recordId||''))).map(hit=>String(hit.id)))],knowledgeRows=await batchGet('knowledge',knowledgeKeys),knowledgeMap=new Map(knowledgeKeys.map((key,i)=>[key,knowledgeRows?.[i]||null]));
    const candidates=[];
    for(const hit of hits){
      let row=hit.recordId?recordMap.get(String(hit.recordId))||null:null;
      if(!row&&hit.id)row=knowledgeMap.get(String(hit.id))||null;
      if(requireWitness&&!hit.witnessDigest){diagnostics.missingWitness++;continue;}
      if(hit.recordId&&!row){diagnostics.missingRecord++;continue;}
      if(row&&(row.retiredAt||row.active===false)){diagnostics.retired++;continue;}
      const retention=row?.retention||{};
      const epistemic=hit.metadata?.epistemicStatus||retention?.epistemicStatus||row?.epistemicStatus||'reported';
      const retainedAt=row?.retainedAt||row?.createdAt||hit.metadata?.retainedAt||0;
      const sourcePrior=autoRetentionPrior(hit.metadata||{});
      const baseTrust=clamp(.46*clamp((hit.score+1)/2)+.24*retentionScore(retention)+.2*epistemicScore(epistemic)+.1*recencyScore(retainedAt,this.halfLifeMs)+sourcePrior);
      const utility=hit.witnessDigest?utilityMap.get(String(hit.witnessDigest))||null:null;
      const utilityScore=clamp(utility?.value??0,-1,1);
      const trust=clamp(baseTrust+0.12*utilityScore);
      candidates.push({...hit,trustScore:trust,baseTrustScore:baseTrust,sourcePrior,memoryUtility:utilityScore,planReliability:utility?.planReliability==null?null:Number(utility.planReliability),branchCalibrationReliability:utility?.branchCalibrationReliability==null?null:Number(utility.branchCalibrationReliability),branchCalibrationAttempts:utility?.branchCalibrationAttempts==null?null:Number(utility.branchCalibrationAttempts),branchCalibrationUpdatedAt:utility?.branchCalibrationUpdatedAt==null?null:Number(utility.branchCalibrationUpdatedAt),branchCalibrationRecentReliability:utility?.branchCalibrationRecentReliability==null?null:Number(utility.branchCalibrationRecentReliability),branchCalibrationRecentWeight:utility?.branchCalibrationRecentWeight==null?null:Number(utility.branchCalibrationRecentWeight),branchCalibrationRecentUpdatedAt:utility?.branchCalibrationRecentUpdatedAt==null?null:Number(utility.branchCalibrationRecentUpdatedAt),branchCalibrationDrift:utility?.branchCalibrationDrift==null?null:Number(utility.branchCalibrationDrift),utility,row,epistemicStatus:epistemic,retention});
    }
    diagnostics.accepted=candidates.length;
    candidates.sort((a,b)=>b.trustScore-a.trustScore||b.score-a.score);
    const selected=candidates.slice(0,Math.max(1,Number(limit)||8));diagnostics.returned=selected.length;
    const embedderDescriptor=typeof this.embedder.describe==='function'?this.embedder.describe():this.embedder;
    const embeddingRuntime=embedderDescriptor?.smallModelRuntime||normalizeSmallModelRuntimeDescriptor(embedderDescriptor||{id:this.embedder?.id||'embedding',runtime:this.embedder?.runtime||'javascript',dimensions:this.embedder?.dimensions||q.length,license:this.embedder?.license||'unknown',semantic:true,offline:true},{kind:'embedding',modalities:['text'],capabilities:['embedding:text'],authority:false});
    const receipt=await this.ledger.append('memory-vector-recall',{
      queryDigest:await digest(String(query??'')),embeddingRuntime,indexMode:found.indexMode,candidateCount:found.candidateCount,totalCount:found.totalCount,diagnostics,
      returned:selected.map(x=>({id:x.id,recordId:x.recordId,witnessDigest:x.witnessDigest,score:x.score,trustScore:x.trustScore,memoryUtility:x.memoryUtility,planReliability:x.planReliability,branchCalibrationReliability:x.branchCalibrationReliability,branchCalibrationAttempts:x.branchCalibrationAttempts,branchCalibrationUpdatedAt:x.branchCalibrationUpdatedAt,branchCalibrationRecentReliability:x.branchCalibrationRecentReliability,branchCalibrationRecentWeight:x.branchCalibrationRecentWeight,branchCalibrationRecentUpdatedAt:x.branchCalibrationRecentUpdatedAt,branchCalibrationDrift:x.branchCalibrationDrift,epistemicStatus:x.epistemicStatus})),
      authority:false,
    });
    return{schema:'xavi-witness-memory-recall/v1',query:String(query??''),receipt,index:found,results:selected,diagnostics};
  }
  async credit(evidence,reward,{routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null}={}){
    const rows=Array.isArray(evidence)?evidence.filter(x=>x?.witnessDigest):[];
    if(!rows.length)return{schema:'xavi-memory-credit/v1',updated:0,rows:[],witness:null,authority:false};
    const r=clamp(reward,-1,1),updates=[];
    for(const item of rows){
      const key=utilityKey(item.witnessDigest),current=structuredClone(await this.utility(key) || blankUtility({witnessDigest:key,recordId:item.recordId||item.id||null}));
      const creditWeight=Number.isFinite(Number(item.creditWeight))?Math.max(-1,Math.min(1,Number(item.creditWeight))):1;const appliedReward=clamp(r*creditWeight,-1,1);
      const alpha=current.attempts?Math.max(0.06,Math.min(0.18,1/(current.attempts+2))):0.35;
      const next={...current,recordId:current.recordId||item.recordId||item.id||null,attempts:current.attempts+1,positive:current.positive+(appliedReward>0?1:0),negative:current.negative+(appliedReward<0?1:0),rewardSum:current.rewardSum+appliedReward,value:clamp((1-alpha)*Number(current.value||0)+alpha*appliedReward,-1,1),lastCreditWeight:creditWeight,lastAppliedReward:appliedReward,lastCreditReason:item.creditReason||'recalled-evidence',updatedAt:Date.now(),authority:false};
      await this.store.set('memoryUtility',key,next);updates.push(next);
    }
    const witness=await this.ledger.append('memory-utility-credit',{routeWitnessDigest,outcomeWitnessDigest,learningWitnessDigest,reward:r,updated:updates.map(x=>({witnessDigest:x.witnessDigest,recordId:x.recordId,attempts:x.attempts,value:x.value,creditWeight:x.lastCreditWeight,appliedReward:x.lastAppliedReward,creditReason:x.lastCreditReason})),authority:false});
    return{schema:'xavi-memory-credit/v1',updated:updates.length,rows:updates,witness,authority:false};
  }
  async calibratePlan(item,assessment,{routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null}={}){
    if(!item?.witnessDigest||assessment?.observed!==true||typeof assessment?.match!=='boolean')return{schema:'xavi-memory-plan-calibration/v1',updated:false,row:null,witness:null,authority:false};
    const key=utilityKey(item.witnessDigest),current=structuredClone(await this.utility(key)||blankUtility({witnessDigest:key,recordId:item.recordId||item.id||null}));
    const attempts=Number(current.planAttempts||0)+1,correct=Number(current.planCorrect||0)+(assessment.match?1:0),accuracy=correct/attempts,reliability=(correct+1)/(attempts+2);
    const next={...current,recordId:current.recordId||item.recordId||item.id||null,planAttempts:attempts,planCorrect:correct,planAccuracy:accuracy,planReliability:reliability,lastPlanMatch:assessment.match,lastPlanAssessmentReason:assessment.reason||null,updatedAt:Date.now(),authority:false};
    await this.store.set('memoryUtility',key,next);
    const witness=await this.ledger.append('memory-plan-calibration',{routeWitnessDigest,outcomeWitnessDigest,learningWitnessDigest,witnessDigest:key,recordId:next.recordId,planAttempts:attempts,planCorrect:correct,planAccuracy:accuracy,planReliability:reliability,match:assessment.match,assessmentReason:assessment.reason||null,authority:false});
    next.lastPlanAssessmentDigest=witness.digest;await this.store.set('memoryUtility',key,next);
    return{schema:'xavi-memory-plan-calibration/v1',updated:true,row:next,witness,authority:false};
  }
  async calibrateBranchPosterior(item,assessment,{routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null,calibrationHalfLifeMs=7*24*3600*1000,now=Date.now()}={}){
    const selectedProbability=Number(assessment?.selectedProbability),transitionMatched=assessment?.transitionMatched;
    if(!item?.witnessDigest||assessment?.observed!==true||!learningWitnessDigest||!Number.isFinite(selectedProbability)||typeof transitionMatched!=='boolean')return{schema:'xavi-memory-branch-posterior-calibration/v1',updated:false,row:null,witness:null,authority:false};
    const key=utilityKey(item.witnessDigest),current=structuredClone(await this.utility(key)||blankUtility({witnessDigest:key,recordId:item.recordId||item.id||null}));
    const probability=clamp(selectedProbability),target=transitionMatched?1:0,error=Math.abs(target-probability),brier=(probability-target)**2,logLoss=-(target?Math.log(Math.max(1e-6,probability)):Math.log(Math.max(1e-6,1-probability))),score=1-error;
    const attempts=Number(current.branchCalibrationAttempts||0)+1,correct=Number(current.branchCalibrationCorrect||0)+(transitionMatched?1:0),probabilitySum=Number(current.branchCalibrationProbabilitySum||0)+probability,scoreSum=Number(current.branchCalibrationScoreSum||0)+score,errorSum=Number(current.branchCalibrationErrorSum||0)+error,brierSum=Number(current.branchCalibrationBrierSum||0)+brier,logLossSum=Number(current.branchCalibrationLogLossSum||0)+logLoss;
    const reliability=clamp((scoreSum+1)/(attempts+2)),ts=Number.isFinite(Number(now))?Number(now):Date.now(),halfLife=Math.max(1,Number(calibrationHalfLifeMs)||7*24*3600*1000);
    const previousRecentWeight=Math.max(0,Number(current.branchCalibrationRecentWeight||0)),previousRecentReliability=current.branchCalibrationRecentReliability==null?.5:clamp(current.branchCalibrationRecentReliability),previousRecentUpdatedAt=Number(current.branchCalibrationRecentUpdatedAt||0)||null;
    const recentAge=previousRecentUpdatedAt==null?0:Math.max(0,ts-previousRecentUpdatedAt),recentPriorFreshness=previousRecentUpdatedAt==null?0:Math.exp(-Math.LN2*recentAge/halfLife),decayedRecentWeight=previousRecentWeight*recentPriorFreshness,recentWeight=Math.min(64,decayedRecentWeight+1),recentReliability=clamp((previousRecentReliability*decayedRecentWeight+score)/recentWeight),drift=Math.abs(recentReliability-reliability);
    const next={...current,recordId:current.recordId||item.recordId||item.id||null,branchCalibrationAttempts:attempts,branchCalibrationCorrect:correct,branchCalibrationProbabilitySum:probabilitySum,branchCalibrationScoreSum:scoreSum,branchCalibrationErrorSum:errorSum,branchCalibrationBrierSum:brierSum,branchCalibrationLogLossSum:logLossSum,branchCalibrationAccuracy:correct/attempts,branchCalibrationMeanProbability:probabilitySum/attempts,branchCalibrationError:errorSum/attempts,branchCalibrationBrier:brierSum/attempts,branchCalibrationLogLoss:logLossSum/attempts,branchCalibrationReliability:reliability,branchCalibrationUpdatedAt:ts,branchCalibrationRecentReliability:recentReliability,branchCalibrationRecentWeight:recentWeight,branchCalibrationRecentUpdatedAt:ts,branchCalibrationDrift:drift,lastBranchCalibrationProbability:probability,lastBranchCalibrationTarget:target,lastBranchCalibrationMatched:transitionMatched,lastBranchCalibrationAssessmentReason:assessment.reason||null,updatedAt:ts,authority:false};
    await this.store.set('memoryUtility',key,next);
    const witness=await this.ledger.append('memory-branch-posterior-calibration',{routeWitnessDigest,outcomeWitnessDigest,learningWitnessDigest,witnessDigest:key,recordId:next.recordId,branchCalibrationAttempts:attempts,branchCalibrationCorrect:correct,branchCalibrationAccuracy:next.branchCalibrationAccuracy,branchCalibrationMeanProbability:next.branchCalibrationMeanProbability,branchCalibrationError:next.branchCalibrationError,branchCalibrationBrier:next.branchCalibrationBrier,branchCalibrationLogLoss:next.branchCalibrationLogLoss,branchCalibrationReliability:reliability,branchCalibrationUpdatedAt:next.branchCalibrationUpdatedAt,branchCalibrationRecentReliability:recentReliability,branchCalibrationRecentWeight:recentWeight,branchCalibrationRecentUpdatedAt:ts,branchCalibrationDrift:drift,branchCalibrationRecentPriorFreshness:recentPriorFreshness,branchCalibrationRecentPreviousWeight:previousRecentWeight,branchCalibrationRecentDecayedWeight:decayedRecentWeight,selectedProbability:probability,transitionMatched,assessmentReason:assessment.reason||null,authority:false});
    next.lastBranchCalibrationDigest=witness.digest;await this.store.set('memoryUtility',key,next);
    return{schema:'xavi-memory-branch-posterior-calibration/v1',updated:true,row:next,witness,authority:false};
  }
  async remember(record,{text=null,epistemicStatus='observed',evidence={observedDirectly:true},provenance={sourceKind:'standalone-runtime'},freshness={observedAt:Date.now()},dependencies=[],kind='memory',metadata={}}={}){
    const retention=this.ledger?.gate?.assessRetention?this.ledger.gate.assessRetention({epistemicStatus,evidence,provenance,freshness,dependencies,addressable:true}):null;
    const id=await digest({namespace:this.namespace,record});
    const assessment=retention||{epistemicStatus,promotionEligible:true,contracts:{}};
    const witness=await this.ledger.append('memory-retention-assessment',{id,retention:assessment});
    const row={id,record,retention:assessment,witnessDigest:witness.digest,witnessId:witness.id,retainedAt:Date.now()};
    await this.store.set('records',id,row);
    await this.indexRetainedRecord(row,{text,kind,metadata:{...metadata,epistemicStatus}});
    return{id,retention:assessment,witness};
  }
}
