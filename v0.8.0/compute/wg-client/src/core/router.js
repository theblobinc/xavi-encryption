import { dot, featurize } from './utils.js';
import { assertBrowserAuthorityProof, refreshBrowserAuthorityProof } from '../sync/authority.js';

function blankPolicy(dim) { return {weights:Array(dim).fill(0), attempts:0, successes:0, rewardSum:0, updatedAt:0}; }

export class StrategyRouter {
  constructor({ store, featureDim = 32, exploration = 0.2, learningRate = 0.12, routeHealth = null, semanticScorer = null, graphScorer = null, runtimePolicy = null, requireAuthorityProof = false } = {}) {
    this.store = store;
    this.featureDim = featureDim;
    this.exploration = exploration;
    this.learningRate = learningRate;
    this.routeHealth = routeHealth;
    this.requireAuthorityProof = requireAuthorityProof === true;
    this.semanticScorer = semanticScorer || graphScorer || null;
    this.graphScorer = this.semanticScorer; // compatibility alias
    this.runtimePolicy=runtimePolicy;
    this.strategies = new Map();
    this.capabilityIndex = new Map();
    this.nextDuoIndex = 1;
    this.policy = new Map();
    this.totalPolicyAttempts = 0;
  }

  registerFaculty(strategy) { return this.register(strategy); }

  _rebuildCapabilityIndex() {
    this.capabilityIndex.clear();
    for (const strategy of this.strategies.values()) for (const capability of strategy.capabilities || []) {
      let bucket=this.capabilityIndex.get(capability);if(!bucket){bucket=[];this.capabilityIndex.set(capability,bucket);}bucket.push(strategy);
    }
  }

  register(strategy) {
    if (!strategy?.id || typeof strategy.run !== 'function') throw new TypeError('strategy requires id and run()');
    const existing=this.strategies.get(strategy.id),duoIndex=existing?.duoIndex||this.nextDuoIndex++;
    this.strategies.set(strategy.id, {...strategy, duoIndex, capabilities:[...(strategy.capabilities || [])]});
    this._rebuildCapabilityIndex();
    return this;
  }

  async init() {
    const saved = await this.store.values('policy');
    this.totalPolicyAttempts=0;
    for (const row of saved) if (row?.id && row?.policy) { this.policy.set(row.id, row.policy); this.totalPolicyAttempts += Number(row.policy.attempts||0); }
    await this.semanticScorer?.init?.();
    await this.runtimePolicy?.init?.();
    return this;
  }

  eligible(capability, context) {
    const bucket=this.capabilityIndex.get(capability)||[];
    return bucket.filter(s => (!s.when || s.when(context) !== false) && (!this.routeHealth || this.routeHealth.decision(s.id).allowed));
  }

  select(capability, context, {explore = true, excludeStrategyIds = []} = {}) {
    const excluded=new Set(Array.isArray(excludeStrategyIds)?excludeStrategyIds:[]);
    const candidates = this.eligible(capability, context).filter(strategy=>!excluded.has(strategy.id));
    if (!candidates.length) throw new Error(`no strategy for capability: ${capability}`);
    const x = featurize({capability, ...context}, this.featureDim);
    const total = this.totalPolicyAttempts;
    const selfReferenceAdvice=new Map((Array.isArray(context?.wgSrnn?.strategyAdvice)?context.wgSrnn.strategyAdvice:[]).filter(row=>row?.strategyId).map(row=>[String(row.strategyId),row]));
    const semanticInterpretation=this.semanticScorer?.prepare?.({capability,context,candidates}) || null;
    const ranked = candidates.map(strategy => {
      const policy = this.policy.get(strategy.id) || blankPolicy(this.featureDim);
      const learned = dot(policy.weights, x);
      const reliability = policy.attempts ? (policy.successes / policy.attempts - 0.5) * 0.4 : 0;
      const bonus = explore ? this.exploration * Math.sqrt(Math.log(total + 2) / (policy.attempts + 1)) : 0;
      const prior = Number(strategy.prior || 0);
      const linearBaseScore = learned + reliability + bonus + prior;
      const runtimeDecision=this.runtimePolicy?.score?.({capability,context,strategy,baseScore:linearBaseScore})||null;
      const selfReferenceDecision=selfReferenceAdvice.get(String(strategy.id))||null;
      const selfReferenceAdjustment=Math.max(-0.2,Math.min(0.2,Number(selfReferenceDecision?.adjustment||0)));
      const baseScore=linearBaseScore+Number(runtimeDecision?.adjustment||0)+selfReferenceAdjustment;
      const semantic = this.semanticScorer?.scoreCandidate?.({capability,context,strategy,baseScore,linearPolicy:policy,interpretation:semanticInterpretation}) || null;
      return {strategy, score: semantic?.score ?? baseScore, baseScore, linearBaseScore, runtimeDecision, selfReferenceDecision, selfReferenceAdjustment, features:Array.from(x), semanticFeatures:semantic?.features || null, semantic, policy};
    }).sort((a,b)=>b.score-a.score || a.strategy.id.localeCompare(b.strategy.id));
    return {...ranked[0], ranked: ranked.map(r=>({id:r.strategy.id,score:r.score,baseScore:r.baseScore,linearBaseScore:r.linearBaseScore,runtimeAdjustment:r.runtimeDecision?.adjustment??0,runtimeDecision:r.runtimeDecision||null,selfReferenceAdjustment:r.selfReferenceAdjustment??0,selfReferenceDecision:r.selfReferenceDecision||null,intent:r.semantic?.intent ?? null,nextOperation:r.semantic?.nextOperation ?? null,targetHint:r.semantic?.targetHint ?? null,feasibility:r.semantic?.feasibility ?? null,conflict:r.semantic?.conflict ?? null,semanticMatch:r.semantic?.semanticMatch ?? null,witnessContinuity:r.semantic?.witnessContinuity ?? null,gatePressure:r.semantic?.gatePressure ?? null,evidenceNeed:r.semantic?.evidenceNeed ?? null,evidenceSufficiency:r.semantic?.evidenceSufficiency?.score ?? null,evidenceStopRecommended:r.semantic?.evidenceSufficiency?.stopRecommended ?? false,evidenceProducer:r.semantic?.evidenceProducer ?? false,evidenceClass:r.semantic?.evidenceClass ?? null,evidenceFit:r.semantic?.evidenceFit ?? null,evidenceAdjustment:r.semantic?.evidenceAdjustment ?? null,evidenceRecommended:r.semantic?.evidenceScheduleMatch ?? false,evidenceScheduleAdjustment:r.semantic?.evidenceScheduleAdjustment ?? 0,evidenceSourceReliability:r.semantic?.evidenceSourceReliability ?? null,evidenceSourceCalibrationScope:r.semantic?.evidenceSourceCalibrationScope ?? null,costClass:r.semantic?.costClass ?? null}))};
  }

  buildCandidate(strategyId, features, reward, outcome = {}, semanticFeatures = null) {
    const current = structuredClone(this.policy.get(strategyId) || blankPolicy(this.featureDim));
    const weights = current.weights.slice();
    const scale = this.learningRate * reward;
    for (let i=0;i<weights.length;i+=1) weights[i] += scale * Number(features[i] || 0);
    const semanticCandidate = semanticFeatures && this.semanticScorer?.buildCandidate ? this.semanticScorer.buildCandidate(strategyId, semanticFeatures, reward, outcome) : null;
    return {
      id: strategyId,
      semanticCandidate,
      policy: {
        ...current, weights,
        attempts: current.attempts + 1,
        successes: current.successes + (outcome.ok ? 1 : 0),
        rewardSum: current.rewardSum + reward,
        updatedAt: Date.now(),
      }
    };
  }

  async install(candidate,{authorityProof=null}={}) {
    if (this.requireAuthorityProof) { assertBrowserAuthorityProof(authorityProof); await refreshBrowserAuthorityProof(authorityProof); }
    const previous=this.policy.get(candidate.id);this.totalPolicyAttempts+=Number(candidate.policy?.attempts||0)-Number(previous?.attempts||0);
    this.policy.set(candidate.id, candidate.policy);
    await this.store.set('policy', candidate.id, candidate);
    if (candidate.semanticCandidate) { if(this.requireAuthorityProof)await refreshBrowserAuthorityProof(authorityProof); await this.semanticScorer?.install?.(candidate.semanticCandidate,{authorityProof}); }
    return candidate.policy;
  }
}
