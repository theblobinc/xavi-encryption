import { digest } from './utils.js';

const COST={ 'very-low':0.08, low:0.16, medium:0.34, high:0.62, 'very-high':1 };
const bounded=(v,min,max,fallback)=>Math.max(min,Math.min(max,Number.isFinite(Number(v))?Number(v):fallback));
const costOf=value=>COST[String(value||'').toLowerCase()]??0.45;
const hasClaimScope=context=>Boolean((Array.isArray(context?.evidenceClaims)&&context.evidenceClaims.length)||context?.evidenceClaimKey||context?.evidenceClaim||context?.evidenceClaimDependencies);
const normalizeClaim=value=>String(value??'').trim().replace(/\s+/g,' ').slice(0,128).toLowerCase();
function claimDeficitFromSemantic(semantic,claimKey,fallback=0){
  const key=normalizeClaim(claimKey);if(!key)return bounded(fallback,0,1,0);
  const target=semantic?.evidenceClaimTarget;if(normalizeClaim(target?.claimKey)===key&&Number.isFinite(Number(target?.claimDeficit)))return bounded(target.claimDeficit,0,1,fallback);
  const support=(semantic?.evidenceSufficiency?.claimSupport||[]).find(row=>normalizeClaim(row?.claimKey)===key);if(support)return bounded(Math.max(0,2-Number(support.independentValidatedSources||0))/2,0,1,fallback);
  const schedule=semantic?.evidenceResolutionSchedule;if(normalizeClaim(schedule?.claimKey)===key&&Number.isFinite(Number(schedule?.claimDeficit)))return bounded(schedule.claimDeficit,0,1,fallback);
  return bounded(fallback,0,1,0);
}

function explicitValidation(execution,strategy){
  const direct=execution?.value?.validated;
  if(typeof direct==='boolean')return{validated:direct,source:'strategy-result'};
  const nested=execution?.value?.result?.validated;
  if(typeof nested==='boolean')return{validated:nested,source:'observer-result'};
  if(strategy?.metadata?.autoValidate===true){
    const resultOk=execution?.value?.result?.ok;
    return{validated:Boolean(execution?.ok&&resultOk!==false),source:'strategy-auto-validate'};
  }
  return null;
}

export class EvidenceResolutionController{
  constructor({xavi,enabled=true,maxSteps=6,maxCost=3,resumeClaimTtlMs=300000}={}){
    if(!xavi)throw new Error('EvidenceResolutionController requires xavi');
    this.xavi=xavi;this.enabled=enabled!==false;this.maxSteps=bounded(maxSteps,1,12,6);this.maxCost=bounded(maxCost,.05,12,3);this.resumeClaimTtlMs=bounded(resumeClaimTtlMs,5000,900000,300000);
  }

  status(){return{schema:'xavi-evidence-resolution-controller/v1',enabled:this.enabled,maxSteps:this.maxSteps,maxCost:this.maxCost,resumeClaimTtlMs:this.resumeClaimTtlMs,authority:false};}

  async _receipt(type,body,witness=true){if(!witness)return null;return this.xavi.ledger.append(type,{...body,authority:false});}

  async _claimPendingResume(receiptId,pending,requestDigest=null){
    const key=`pending:${receiptId}`,now=Date.now(),existing=pending?.evidenceResolutionResumeClaim||null;
    if(existing&&Number(existing.expiresAt||0)>now)throw new Error(`evidence resolution resume already in progress: ${receiptId}`);
    const token=await digest({schema:'xavi-evidence-resolution-resume-claim/v1',receiptId,routeWitnessDigest:pending?.receiptDigest||null,claimedAt:now,nonce:`${now}:${Math.random()}`});
    const claim={schema:'xavi-evidence-resolution-resume-claim/v1',token,requestDigest:requestDigest||null,claimedAt:now,expiresAt:now+this.resumeClaimTtlMs,authority:false},claimed={...pending,evidenceResolutionResumeClaim:claim};
    let result=null;
    if(typeof this.xavi.store.compareAndSet==='function')result=await this.xavi.store.compareAndSet('records',key,pending,claimed);
    else{const current=await this.xavi.store.get('records',key);if(JSON.stringify(current)!==JSON.stringify(pending))result={updated:false,current};else{await this.xavi.store.set('records',key,claimed);result={updated:true,current:claimed};}}
    if(!result?.updated){const current=result?.current??await this.xavi.store.get('records',key);if(current?.closed)throw new Error(`route receipt already closed: ${receiptId}`);const held=current?.evidenceResolutionResumeClaim;if(held&&Number(held.expiresAt||0)>Date.now())throw new Error(`evidence resolution resume already in progress: ${receiptId}`);throw new Error(`evidence resolution pending receipt changed before resume claim: ${receiptId}`);}
    this.xavi.pending?.set?.(receiptId,claimed);return{pending:claimed,claim};
  }

  async _releasePendingResumeClaim(receiptId,token){
    const key=`pending:${receiptId}`,current=this.xavi.pending?.get?.(receiptId)||await this.xavi.store.get('records',key);
    if(!current||current.closed||current.evidenceResolutionResumeClaim?.token!==token)return false;
    const next={...current};delete next.evidenceResolutionResumeClaim;let result=null;
    if(typeof this.xavi.store.compareAndSet==='function')result=await this.xavi.store.compareAndSet('records',key,current,next);else{await this.xavi.store.set('records',key,next);result={updated:true,current:next};}
    if(result?.updated)this.xavi.pending?.set?.(receiptId,next);return Boolean(result?.updated);
  }

  async _resumeRequestDigest(capability,contextDigest,receiptId,options={}){
    const normalized={...options,receiptId:undefined,outcome:options.outcome?{...options.outcome,sensitivePayload:undefined}:null};
    return digest({schema:'xavi-evidence-resolution-resume-request/v1',capability:String(capability||''),contextDigest,receiptId:String(receiptId||''),options:normalized});
  }

  _learningFromOutcomeSummary(summary){
    if(!summary)return null;
    return{outcomeWitness:summary.outcomeWitness||null,promotion:summary.promotion||{promoted:false,authority:false},evidenceSessionSettlement:summary.evidenceSessionSettlement||null,reward:Number(summary.reward||0),replayed:true,authority:false};
  }

  _compactResumeResult(result,requestDigest){
    const compactWitness=w=>w?{id:w.id||null,digest:w.digest||null,sequence:w.sequence??null,type:w.type||null}:null;
    const compactResolution=r=>r?{schema:r.schema||'xavi-evidence-resolution-cycle/v1',enabled:r.enabled!==false,capability:r.capability||null,stopReason:r.stopReason||null,complete:Boolean(r.complete),budgetLineageId:r.budgetLineageId||null,budgetLimit:r.budgetLimit??r.maxCost??null,budgetSpentCost:r.budgetSpentCost??r.spentCost??null,remainingBudget:r.remainingBudget??null,stepLimit:r.stepLimit??r.maxSteps??null,stepsUsed:r.stepsUsed??r.stepCount??null,remainingSteps:r.remainingSteps??null,pendingValidation:r.pendingValidation?{receiptId:r.pendingValidation.receiptId||null,routeWitnessDigest:r.pendingValidation.routeWitnessDigest||null,strategyId:r.pendingValidation.strategyId||null}:null,steps:(r.steps||[]).slice(0,12).map(step=>({index:step.index??null,status:step.status||null,strategyId:step.strategyId||step.actualStrategyId||step.route?.routeWitness?.body?.strategyId||null,cost:step.cost??null,receiptId:step.receiptId||step.route?.receiptId||null,routeWitnessDigest:step.routeWitnessDigest||step.route?.routeWitness?.digest||null,authority:false})),authority:false}:null;
    const learning=result.learning?{outcomeWitness:compactWitness(result.learning.outcomeWitness),promotion:{promoted:Boolean(result.learning.promotion?.promoted),demoted:Boolean(result.learning.promotion?.demoted),mutationType:result.learning.promotion?.mutationType||null,receipt:compactWitness(result.learning.promotion?.receipt),mutationWitness:compactWitness(result.learning.promotion?.mutationWitness),authority:false},evidenceSessionSettlement:result.learning.evidenceSessionSettlement?{entry:result.learning.evidenceSessionSettlement.entry||null,witness:compactWitness(result.learning.evidenceSessionSettlement.witness),authority:false}:null,reward:Number(result.learning.reward||0),authority:false}:null;
    return{schema:'xavi-evidence-resolution-resume/v1',requestDigest,capability:result.capability||null,receiptId:result.receiptId||null,stopReason:result.stopReason||null,complete:Boolean(result.complete),budgetLineageId:result.budgetLineageId||null,budgetLimit:result.budgetLimit??null,budgetSpentCost:result.budgetSpentCost??null,remainingBudget:result.remainingBudget??null,stepLimit:result.stepLimit??null,stepsUsed:result.stepsUsed??null,remainingSteps:result.remainingSteps??null,learning,resolution:compactResolution(result.resolution),resumeWitness:result.resumeWitness||null,audit:{resolutionEfficiencyCalibrationDigest:result.resolutionEfficiencyCalibration?.witness?.digest||null,observedCostCalibrationDigest:result.observedCostCalibration?.witness?.digest||null,closureForecastAssessmentDigest:result.closureForecastAssessment?.digest||null,closureForecastCalibrationDigest:result.closureForecastCalibration?.witness?.digest||null},recovered:Boolean(result.recovered),replayed:false,authority:false};
  }

  async _persistResumeResult(receiptId,requestDigest,result){
    const key=`pending:${receiptId}`,compact=this._compactResumeResult(result,requestDigest);
    for(let attempt=0;attempt<2;attempt++){
      const current=await this.xavi.store.get('records',key);if(!current?.closed)throw new Error(`cannot persist evidence resume result before route closes: ${receiptId}`);
      if(current.evidenceResolutionResumeResult?.requestDigest===requestDigest)return current.evidenceResolutionResumeResult;
      const next={...current,evidenceResolutionResumeRequestDigest:requestDigest,evidenceResolutionResumeResult:compact,evidenceResolutionResumeCompletedAt:Date.now()};delete next.evidenceResolutionResumeRecoveryClaim;
      if(typeof this.xavi.store.compareAndSet!=='function'){await this.xavi.store.set('records',key,next);return compact;}
      const saved=await this.xavi.store.compareAndSet('records',key,current,next);if(saved?.updated)return compact;
    }
    throw new Error(`evidence resolution resume result changed before persistence: ${receiptId}`);
  }

  async _claimClosedResumeRecovery(receiptId,pending,requestDigest){
    const key=`pending:${receiptId}`,now=Date.now(),recorded=pending.evidenceResolutionResumeRequestDigest||pending.evidenceResolutionResumeClaim?.requestDigest||null;
    if(recorded&&recorded!==requestDigest)throw new Error(`closed evidence resolution resume request mismatch: ${receiptId}`);
    const postTypes=new Set(['evidence-claim-closure-forecast-assessed','evidence-resolution-efficiency-calibrated','evidence-source-cost-calibrated','evidence-claim-closure-forecast-calibrated','evidence-resolution-cycle-resumed']),routeDigest=pending?.receiptDigest||null,witnesses=await this.xavi.store.values('witness'),partial=(witnesses||[]).find(row=>postTypes.has(row?.type)&&((row.type==='evidence-resolution-cycle-resumed'&&row.body?.receiptId===receiptId)||(routeDigest&&row.body?.routeWitnessDigest===routeDigest)));
    if(partial)throw new Error(`evidence resolution resume partial finalization detected: ${receiptId} (${partial.type})`);
    const active=pending.evidenceResolutionResumeRecoveryClaim;if(active&&Number(active.expiresAt||0)>now)throw new Error(`evidence resolution resume recovery already in progress: ${receiptId}`);
    const original=pending.evidenceResolutionResumeClaim;if(original&&Number(original.expiresAt||0)>now)throw new Error(`evidence resolution resume finalization still in progress: ${receiptId}`);
    const token=await digest({schema:'xavi-evidence-resolution-resume-recovery-claim/v1',receiptId,requestDigest,claimedAt:now,nonce:`${now}:${Math.random()}`}),claim={schema:'xavi-evidence-resolution-resume-recovery-claim/v1',token,requestDigest,claimedAt:now,expiresAt:now+this.resumeClaimTtlMs,authority:false},next={...pending,evidenceResolutionResumeRecoveryClaim:claim};
    const saved=typeof this.xavi.store.compareAndSet==='function'?await this.xavi.store.compareAndSet('records',key,pending,next):null;
    if(saved&&!saved.updated)throw new Error(`evidence resolution resume recovery claim lost: ${receiptId}`);if(!saved)await this.xavi.store.set('records',key,next);return{pending:next,claim};
  }

  async _budgetLineageForPending(pending,options={}){
    const direct=pending?.evidenceResolutionBudget||null;
    if(direct?.schema==='xavi-evidence-resolution-budget-lineage/v1'){
      const originalLimit=bounded(direct.maxCost,.05,12,this.maxCost),requested=options.maxCost==null?originalLimit:bounded(options.maxCost,.05,12,originalLimit);
      const originalSteps=bounded(direct.maxSteps,1,12,this.maxSteps),requestedSteps=options.maxSteps==null?originalSteps:bounded(options.maxSteps,1,12,originalSteps);return{schema:direct.schema,lineageId:direct.lineageId||pending.receiptDigest||pending.receiptId||null,maxCost:Math.min(originalLimit,requested),spentCost:Math.max(0,Number(direct.spentCost||0)),maxSteps:Math.min(originalSteps,requestedSteps),usedSteps:Math.max(0,Number(direct.usedSteps||0)),source:'pending-record',authority:false};
    }
    const witnesses=await this.xavi.store.values('witness'),prior=(witnesses||[]).filter(row=>row?.type==='evidence-resolution-cycle-closed'&&row?.body?.pendingRouteWitnessDigest===pending?.receiptDigest).sort((a,b)=>Number(b?.sequence||0)-Number(a?.sequence||0))[0]||null;
    if(prior){
      const originalLimit=bounded(prior.body?.budgetLimit??prior.body?.maxCost,.05,12,this.maxCost),requested=options.maxCost==null?originalLimit:bounded(options.maxCost,.05,12,originalLimit);
      const originalSteps=bounded(prior.body?.stepLimit??prior.body?.maxSteps,1,12,this.maxSteps),requestedSteps=options.maxSteps==null?originalSteps:bounded(options.maxSteps,1,12,originalSteps);return{schema:'xavi-evidence-resolution-budget-lineage/v1',lineageId:prior.body?.budgetLineageId||prior.digest||pending.receiptDigest||null,maxCost:Math.min(originalLimit,requested),spentCost:Math.max(0,Number(prior.body?.budgetSpentCost??prior.body?.spentCost??0)),maxSteps:Math.min(originalSteps,requestedSteps),usedSteps:Math.max(0,Number(prior.body?.stepsUsed??prior.body?.stepCount??0)),source:'legacy-cycle-witness',authority:false};
    }
    return{schema:'xavi-evidence-resolution-budget-lineage/v1',lineageId:null,maxCost:bounded(options.maxCost,.05,12,this.maxCost),spentCost:0,maxSteps:bounded(options.maxSteps,1,12,this.maxSteps),usedSteps:0,source:'new-lineage',authority:false};
  }

  async _bindPendingBudget(receiptId,budget){
    if(!receiptId||!budget)return null;const key=`pending:${receiptId}`,pending=this.xavi.pending?.get?.(receiptId)||await this.xavi.store.get('records',key);if(!pending)return null;
    const evidenceResolutionBudget={schema:'xavi-evidence-resolution-budget-lineage/v1',lineageId:budget.lineageId||null,maxCost:Number(budget.maxCost||0),spentCost:Math.max(0,Number(budget.spentCost||0)),remainingBudget:Math.max(0,Number(budget.maxCost||0)-Math.max(0,Number(budget.spentCost||0))),maxSteps:Math.max(1,Number(budget.maxSteps||this.maxSteps)),usedSteps:Math.max(0,Number(budget.usedSteps||0)),remainingSteps:Math.max(0,Math.max(1,Number(budget.maxSteps||this.maxSteps))-Math.max(0,Number(budget.usedSteps||0))),updatedAt:Date.now(),authority:false},updated={...pending,evidenceResolutionBudget};
    this.xavi.pending?.set?.(receiptId,updated);await this.xavi.store.set('records',key,updated);return evidenceResolutionBudget;
  }

  async resume(capability,context={},options={}){
    const receiptId=String(options.receiptId||'').trim();
    if(!receiptId)throw new Error('evidence resolution resume requires receiptId');
    if(!options.outcome||typeof options.outcome.validated!=='boolean')throw new Error('evidence resolution resume requires explicit outcome.validated boolean');
    let pending=this.xavi.pending?.get?.(receiptId)||await this.xavi.store.get('records',`pending:${receiptId}`);
    if(!pending)throw new Error(`unknown route receipt: ${receiptId}`);
    if(String(pending.capability||'')!==String(capability||''))throw new Error('evidence resolution resume capability mismatch');
    const contextDigest=await digest(context);
    if(pending.contextDigest&&pending.contextDigest!==contextDigest)throw new Error('evidence resolution resume context mismatch');
    const requestDigest=await this._resumeRequestDigest(capability,contextDigest,receiptId,options);
    if(pending.closed&&pending.evidenceResolutionResumeResult){
      if(pending.evidenceResolutionResumeResult.requestDigest!==requestDigest)throw new Error(`closed evidence resolution resume request mismatch: ${receiptId}`);
      return{...pending.evidenceResolutionResumeResult,replayed:true,replaySource:'persisted-result',authority:false};
    }
    const budget=await this._budgetLineageForPending(pending,options);
    let learning=null,recovered=false;
    if(pending.closed){
      if(!pending.outcomeResultSummary)throw new Error(`route receipt already closed without resumable outcome summary: ${receiptId}`);
      const recovery=await this._claimClosedResumeRecovery(receiptId,pending,requestDigest);pending=recovery.pending;learning=this._learningFromOutcomeSummary(pending.outcomeResultSummary);recovered=true;
    }else{
      const resumeClaim=await this._claimPendingResume(receiptId,pending,requestDigest);pending=resumeClaim.pending;
      try{learning=await this.xavi.outcome(receiptId,options.outcome);}catch(error){await this._releasePendingResumeClaim(receiptId,resumeClaim.claim.token).catch(()=>{});throw error;}
    }
    let resolutionEfficiencyCalibration=null,observedCostCalibration=null,closureForecastAssessment=null,closureForecastCalibration=null,preClaimDeficit=null,postClaimDeficit=null;const preSchedule=pending.semanticDecision?.evidenceResolutionSchedule||null,claimKey=preSchedule?.claimKey||null;
    if(options.outcome.validated===true&&claimKey){const memoryRecall=options.memoryRecall===undefined?false:options.memoryRecall,postProposal=await this.xavi.propose(capability,context,{witness:false,memoryRecall,excludeStrategyIds:[]}),selectedRow=(preSchedule.ranked||[]).find(row=>row?.strategyId===pending.strategyId)||null;preClaimDeficit=claimDeficitFromSemantic(pending.semanticDecision,claimKey,preSchedule.claimDeficit);postClaimDeficit=claimDeficitFromSemantic(postProposal.semantic,claimKey,preClaimDeficit);const predicted=selectedRow?.closureProbability,forecastObserved=selectedRow?.oneStepClosable===true&&predicted!=null&&Number.isFinite(Number(predicted));if(forecastObserved)closureForecastAssessment=await this._receipt('evidence-claim-closure-forecast-assessed',{claimKey,strategyId:pending.strategyId,sourceId:selectedRow?.sourceId||null,evidenceFamily:selectedRow?.evidenceFamily||null,routeWitnessDigest:pending.receiptDigest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,baseProbability:selectedRow?.baseClosureProbability??predicted,predictedProbability:Number(predicted),preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,observedClosed:preClaimDeficit>1e-12&&postClaimDeficit<=1e-12,authority:false},options.witness!==false);const learnedEntry=learning.evidenceSessionSettlement?.entry||null;if(learning.promotion?.promoted&&learnedEntry?.witnessDigest){const declaredCost=costOf(selectedRow?.costClass||pending.semanticDecision?.costClass);resolutionEfficiencyCalibration=await this.xavi.evidenceSessions?.calibrateResolutionEfficiency?.(learnedEntry,{claimKey,preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,cost:declaredCost,validated:true},{routeWitnessDigest:pending.receiptDigest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null});if(Number.isFinite(Number(options.outcome.latencyMs)))observedCostCalibration=await this.xavi.evidenceSessions?.calibrateObservedCost?.(learnedEntry,{claimKey,latencyMs:Number(options.outcome.latencyMs),declaredCost,validated:true},{routeWitnessDigest:pending.receiptDigest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null});if(forecastObserved)closureForecastCalibration=await this.xavi.evidenceSessions?.calibrateClaimClosureForecast?.(learnedEntry,{claimKey,predictedProbability:Number(predicted),preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,validated:true},{routeWitnessDigest:pending.receiptDigest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null});}}
    const resumedWitness=await this._receipt('evidence-resolution-cycle-resumed',{capability,contextDigest,receiptId,routeWitnessDigest:pending.receiptDigest||null,outcomeWitnessDigest:learning?.outcomeWitness?.digest||null,validated:options.outcome.validated===true,ok:Boolean(options.outcome.ok),claimKey,preClaimDeficit,postClaimDeficit,claimDeficitGain:preClaimDeficit==null||postClaimDeficit==null?null:Math.max(0,preClaimDeficit-postClaimDeficit),budgetLineageId:budget.lineageId||null,budgetLimit:budget.maxCost,budgetSpentCost:budget.spentCost,remainingBudget:Math.max(0,budget.maxCost-budget.spentCost),stepLimit:budget.maxSteps,stepsUsed:budget.usedSteps,remainingSteps:Math.max(0,budget.maxSteps-budget.usedSteps),budgetSource:budget.source,recovered,resolutionEfficiencyCalibrationDigest:resolutionEfficiencyCalibration?.witness?.digest||null,observedCostCalibrationDigest:observedCostCalibration?.witness?.digest||null,closureForecastAssessmentDigest:closureForecastAssessment?.digest||null,closureForecastCalibrationDigest:closureForecastCalibration?.witness?.digest||null},options.witness!==false);
    let result;
    if(options.outcome.validated!==true){
      result={schema:'xavi-evidence-resolution-resume/v1',capability,receiptId,stopReason:'validation-failed',complete:false,learning,resolution:null,budgetLineageId:budget.lineageId||null,budgetLimit:budget.maxCost,budgetSpentCost:budget.spentCost,remainingBudget:Math.max(0,budget.maxCost-budget.spentCost),stepLimit:budget.maxSteps,stepsUsed:budget.usedSteps,remainingSteps:Math.max(0,budget.maxSteps-budget.usedSteps),resolutionEfficiencyCalibration,observedCostCalibration,closureForecastAssessment,closureForecastCalibration,resumeWitness:resumedWitness?{id:resumedWitness.id,digest:resumedWitness.digest,sequence:resumedWitness.sequence}:null,recovered,authority:false};
    }else{
      const resolutionOptions={...options};delete resolutionOptions.receiptId;delete resolutionOptions.outcome;resolutionOptions.maxCost=budget.maxCost;resolutionOptions.maxSteps=budget.maxSteps;resolutionOptions._budgetLineageId=budget.lineageId||null;resolutionOptions._budgetInitialSpent=budget.spentCost;resolutionOptions._budgetLimit=budget.maxCost;resolutionOptions._stepInitialUsed=budget.usedSteps;resolutionOptions._stepLimit=budget.maxSteps;resolutionOptions._prevalidatedSufficient=postClaimDeficit!=null&&postClaimDeficit<=1e-12;
      const resolution=await this.resolve(capability,context,resolutionOptions);
      result={schema:'xavi-evidence-resolution-resume/v1',capability,receiptId,stopReason:resolution.stopReason,complete:resolution.complete,learning,resolution,budgetLineageId:resolution.budgetLineageId||budget.lineageId||null,budgetLimit:resolution.budgetLimit??budget.maxCost,budgetSpentCost:resolution.budgetSpentCost??budget.spentCost,remainingBudget:resolution.remainingBudget??Math.max(0,budget.maxCost-budget.spentCost),stepLimit:resolution.stepLimit??budget.maxSteps,stepsUsed:resolution.stepsUsed??budget.usedSteps,remainingSteps:resolution.remainingSteps??Math.max(0,budget.maxSteps-budget.usedSteps),resolutionEfficiencyCalibration,observedCostCalibration,closureForecastAssessment,closureForecastCalibration,resumeWitness:resumedWitness?{id:resumedWitness.id,digest:resumedWitness.digest,sequence:resumedWitness.sequence}:null,recovered,authority:false};
    }
    await this._persistResumeResult(receiptId,requestDigest,result);
    return result;
  }

  async resolve(capability,context={},options={}){
    const enabled=options.enabled===undefined?this.enabled:options.enabled!==false,maxSteps=bounded(options._stepLimit??options.maxSteps,1,12,this.maxSteps),maxCost=bounded(options._budgetLimit??options.maxCost,.05,12,this.maxCost),witness=options.witness!==false,memoryRecall=options.memoryRecall===undefined?false:options.memoryRecall,validator=typeof options.validator==='function'?options.validator:null;
    const contextDigest=await digest(context),startedAt=Date.now(),steps=[],usedFamiliesByClaim=new Map(),initialSpent=Math.max(0,Number(options._budgetInitialSpent||0)),initialSteps=Math.max(0,Number(options._stepInitialUsed||0)),budgetLineageId=String(options._budgetLineageId||'').trim()||await digest({schema:'xavi-evidence-resolution-budget-lineage/v1',capability,contextDigest,startedAt,maxCost,maxSteps});let spent=initialSpent,pendingValidation=null,stopReason=null;
    const start=await this._receipt('evidence-resolution-cycle-started',{capability,contextDigest,maxSteps,maxCost,claimScoped:hasClaimScope(context),budgetLineageId,budgetLimit:maxCost,initialSpent,budgetSpentCost:spent,remainingBudget:Math.max(0,maxCost-spent),stepLimit:maxSteps,initialSteps,stepsUsed:initialSteps,remainingSteps:Math.max(0,maxSteps-initialSteps)},witness);
    if(!enabled)stopReason='disabled';else if(!hasClaimScope(context))stopReason='no-claim-scope';else if(options._prevalidatedSufficient===true)stopReason='evidence-sufficient';else if(spent>=maxCost-1e-12)stopReason='budget-exhausted';else if(initialSteps>=maxSteps)stopReason='step-limit';
    for(let localIndex=0;!stopReason&&initialSteps+localIndex<maxSteps;localIndex++){const index=initialSteps+localIndex;
      let probe;
      try{probe=await this.xavi.propose(capability,context,{witness:false,memoryRecall,excludeStrategyIds:[]});}catch(error){if(String(error?.message||error).includes('no strategy for capability')){stopReason='no-eligible-evidence-producer';break;}throw error;}
      const probeSchedule=probe.semantic?.evidenceResolutionSchedule||null;
      if(!probeSchedule?.actionable){stopReason=probeSchedule?.reason||'no-actionable-schedule';break;}
      if(!probeSchedule.claimKey){stopReason='no-claim-scope';break;}
      const sessionSnapshot=await this.xavi.evidenceSessions?.prepare?.(capability,context);
      const persistedFamilies=new Set((sessionSnapshot?.entries||[]).filter(row=>String(row?.claimKey||'').trim().toLowerCase()===String(probeSchedule.claimKey||'').trim().toLowerCase()&&row?.validated===true&&row?.ok!==false&&row?.conflict!==true).map(row=>String(row?.evidenceFamily||row?.modelId||row?.source||'').trim()).filter(Boolean));
      const usedFamilies=new Set([...(usedFamiliesByClaim.get(probeSchedule.claimKey)||[]),...persistedFamilies]);
      const excludeStrategyIds=[...this.xavi.router.strategies.values()].filter(strategy=>{const family=String(strategy?.metadata?.evidenceFamily||strategy?.metadata?.sourceFamily||'').trim();return family&&usedFamilies.has(family);}).map(strategy=>strategy.id);
      let proposal=probe;
      if(excludeStrategyIds.length){
        try{proposal=await this.xavi.propose(capability,context,{witness:false,memoryRecall,excludeStrategyIds});}catch(error){if(String(error?.message||error).includes('no strategy for capability')){stopReason='no-eligible-evidence-producer';break;}throw error;}
      }
      const schedule=proposal.semantic?.evidenceResolutionSchedule||null;
      if(!schedule?.actionable){stopReason=schedule?.reason||'no-actionable-schedule';break;}
      if(!schedule.claimKey){stopReason='no-claim-scope';break;}
      const selectedScheduleRow=(schedule.ranked||[]).find(row=>row?.strategyId===proposal.strategyId)||null;
      if(!selectedScheduleRow){stopReason='selected-route-not-evidence-producer';break;}
      const strategy=this.xavi.router.strategies.get(proposal.strategyId),stepCost=costOf(selectedScheduleRow.costClass||strategy?.metadata?.costClass);
      if(spent+stepCost>maxCost){stopReason='budget-exhausted';break;}
      const pinnedExcludeStrategyIds=[...this.xavi.router.strategies.keys()].filter(id=>id!==proposal.strategyId);let execution;try{execution=await this.xavi.execute(capability,context,{...options.executionOptions,memoryRecall,explore:false,excludeStrategyIds:pinnedExcludeStrategyIds});}catch(error){if(String(error?.message||error).includes('no strategy for capability')){const row={index,claimKey:schedule.claimKey,recommendedStrategyId:schedule.recommendedStrategyId,proposedStrategyId:proposal.strategyId,actualStrategyId:null,cost:0,cumulativeCost:spent,status:'selected-strategy-became-ineligible',routeWitnessDigest:null,authority:false};steps.push(row);await this._receipt('evidence-resolution-step',row,witness);stopReason='selected-strategy-became-ineligible';break;}throw error;}
      const actualStrategyId=execution.routeWitness?.body?.strategyId||execution.strategyId||null;
      spent+=stepCost;
      if(actualStrategyId!==proposal.strategyId){
        const row={index,claimKey:schedule.claimKey,recommendedStrategyId:schedule.recommendedStrategyId,proposedStrategyId:proposal.strategyId,actualStrategyId,cost:stepCost,cumulativeCost:spent,status:'route-changed-after-proposal',routeWitnessDigest:execution.routeWitness?.digest||null,authority:false};steps.push(row);await this._receipt('evidence-resolution-step',row,witness);pendingValidation={receiptId:execution.receiptId,routeWitnessDigest:execution.routeWitness?.digest||null};stopReason='route-changed-after-proposal';break;
      }
      let validation=null;
      if(validator){
        const value=await validator(execution,{capability,context,index,schedule,proposal,strategy});
        if(typeof value==='boolean')validation={validated:value,source:'caller-validator'};
        else if(value&&typeof value.validated==='boolean')validation={...value,source:value.source||'caller-validator'};
      }else validation=explicitValidation(execution,strategy);
      if(!validation){
        const row={index,claimKey:schedule.claimKey,recommendedStrategyId:schedule.recommendedStrategyId,proposedStrategyId:proposal.strategyId,actualStrategyId,cost:stepCost,cumulativeCost:spent,status:'validation-required',routeWitnessDigest:execution.routeWitness?.digest||null,authority:false};steps.push(row);await this._receipt('evidence-resolution-step',row,witness);pendingValidation={receiptId:execution.receiptId,routeWitnessDigest:execution.routeWitness?.digest||null};stopReason='validation-required';break;
      }
      const validated=validation.validated!==false,outcome={ok:validation.ok===undefined?Boolean(execution.ok&&validated):Boolean(validation.ok),validated,latencyMs:execution.latencyMs,reason:validation.reason||null,...(Number.isFinite(Number(validation.reward))?{reward:Number(validation.reward)}:{})};
      const learning=await this.xavi.outcome(execution.receiptId,outcome);
      if(validated){const family=String(selectedScheduleRow.evidenceFamily||strategy?.metadata?.evidenceFamily||strategy?.metadata?.sourceFamily||'').trim();if(family){const claimFamilies=usedFamiliesByClaim.get(schedule.claimKey)||new Set();claimFamilies.add(family);usedFamiliesByClaim.set(schedule.claimKey,claimFamilies);}}
      if(!validated){const row={index,claimKey:schedule.claimKey,recommendedStrategyId:schedule.recommendedStrategyId,proposedStrategyId:proposal.strategyId,actualStrategyId,cost:stepCost,cumulativeCost:spent,status:'validation-failed',validationSource:validation.source||null,routeWitnessDigest:execution.routeWitness?.digest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null,authority:false};steps.push(row);await this._receipt('evidence-resolution-step',row,witness);stopReason='validation-failed';break;}
      const postProposal=await this.xavi.propose(capability,context,{witness:false,memoryRecall,excludeStrategyIds:[]}),postSchedule=postProposal.semantic?.evidenceResolutionSchedule||null,preClaimDeficit=claimDeficitFromSemantic(proposal.semantic,schedule.claimKey,schedule.claimDeficit),postClaimDeficit=claimDeficitFromSemantic(postProposal.semantic,schedule.claimKey,preClaimDeficit);
      let resolutionEfficiencyCalibration=null,closureForecastAssessment=null,closureForecastCalibration=null;const learnedEntry=learning.evidenceSessionSettlement?.entry||null,predictedClosureProbability=selectedScheduleRow?.closureProbability,forecastObserved=selectedScheduleRow?.oneStepClosable===true&&predictedClosureProbability!=null&&Number.isFinite(Number(predictedClosureProbability));
      if(forecastObserved)closureForecastAssessment=await this._receipt('evidence-claim-closure-forecast-assessed',{claimKey:schedule.claimKey,strategyId:actualStrategyId,sourceId:selectedScheduleRow?.sourceId||null,evidenceFamily:selectedScheduleRow?.evidenceFamily||null,routeWitnessDigest:execution.routeWitness?.digest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,baseProbability:selectedScheduleRow?.baseClosureProbability??predictedClosureProbability,predictedProbability:Number(predictedClosureProbability),preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,observedClosed:preClaimDeficit>1e-12&&postClaimDeficit<=1e-12,authority:false},witness);
      if(learning.promotion?.promoted&&learnedEntry?.witnessDigest){resolutionEfficiencyCalibration=await this.xavi.evidenceSessions?.calibrateResolutionEfficiency?.(learnedEntry,{claimKey:schedule.claimKey,preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,cost:stepCost,validated:true},{routeWitnessDigest:execution.routeWitness?.digest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null});if(forecastObserved)closureForecastCalibration=await this.xavi.evidenceSessions?.calibrateClaimClosureForecast?.(learnedEntry,{claimKey:schedule.claimKey,predictedProbability:Number(predictedClosureProbability),preDeficit:preClaimDeficit,postDeficit:postClaimDeficit,validated:true},{routeWitnessDigest:execution.routeWitness?.digest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null});}
      const row={index,claimKey:schedule.claimKey,recommendedStrategyId:schedule.recommendedStrategyId,proposedStrategyId:proposal.strategyId,actualStrategyId,cost:stepCost,cumulativeCost:spent,status:'validated',validationSource:validation.source||null,routeWitnessDigest:execution.routeWitness?.digest||null,outcomeWitnessDigest:learning.outcomeWitness?.digest||null,learningWitnessDigest:learning.promotion?.receipt?.digest||null,preClaimDeficit,postClaimDeficit,claimDeficitGain:Math.max(0,preClaimDeficit-postClaimDeficit),resolutionEfficiencyCalibrationDigest:resolutionEfficiencyCalibration?.witness?.digest||null,resolutionEfficiency:resolutionEfficiencyCalibration?.claimCalibration?.row?.resolutionEfficiency??null,closureForecastAssessmentDigest:closureForecastAssessment?.digest||null,closureForecastCalibrationDigest:closureForecastCalibration?.witness?.digest||null,closureForecastPredictedProbability:forecastObserved?Number(predictedClosureProbability):null,closureForecastObservedClosed:forecastObserved?(preClaimDeficit>1e-12&&postClaimDeficit<=1e-12):null,closureForecastCalibrationReliability:closureForecastCalibration?.row?.closureForecastReliability??null,authority:false};steps.push(row);await this._receipt('evidence-resolution-step',row,witness);
      if(postSchedule&&!postSchedule.actionable){stopReason=postSchedule.reason||'no-actionable-schedule';break;}
    }
    if(!stopReason)stopReason=steps.length>=maxSteps?'step-budget-exhausted':'complete';
    const stepsUsed=initialSteps+steps.length,remainingSteps=Math.max(0,maxSteps-stepsUsed);let pendingBudget=null;if(pendingValidation?.receiptId)pendingBudget=await this._bindPendingBudget(pendingValidation.receiptId,{lineageId:budgetLineageId,maxCost,spentCost:spent,maxSteps,usedSteps:stepsUsed});if(pendingBudget)pendingValidation={...pendingValidation,budget:pendingBudget};
    const cycleSpentCost=Math.max(0,spent-initialSpent),remainingBudget=Math.max(0,maxCost-spent),closedAt=Date.now(),closed=await this._receipt('evidence-resolution-cycle-closed',{startWitnessDigest:start?.digest||null,capability,contextDigest,stopReason,stepCount:steps.length,spentCost:cycleSpentCost,maxCost,maxSteps,budgetLineageId,budgetLimit:maxCost,initialSpent,budgetSpentCost:spent,remainingBudget,stepLimit:maxSteps,initialSteps,stepsUsed,remainingSteps,pendingRouteWitnessDigest:pendingValidation?.routeWitnessDigest||null,durationMs:Math.max(0,closedAt-startedAt)},witness);
    return{schema:'xavi-evidence-resolution-cycle/v1',enabled,capability,contextDigest,stopReason,complete:stopReason==='evidence-sufficient'||stopReason==='complete',steps,spentCost:cycleSpentCost,maxCost,maxSteps,budgetLineageId,budgetLimit:maxCost,initialSpent,budgetSpentCost:spent,remainingBudget,stepLimit:maxSteps,initialSteps,stepsUsed,remainingSteps,pendingValidation,startWitness:start?{id:start.id,digest:start.digest,sequence:start.sequence}:null,closeWitness:closed?{id:closed.id,digest:closed.digest,sequence:closed.sequence}:null,authority:false};
  }
}
