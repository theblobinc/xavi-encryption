import { digest } from '../core/utils.js';
import { smallModelRuntimeFromObserver } from '../runtime/small-model-runtime.js';

export const APPROVED_OBSERVER_LICENSES = Object.freeze(['MIT', 'Apache-2.0', 'MIT OR Apache-2.0']);
const licenseAllowed = value => APPROVED_OBSERVER_LICENSES.includes(String(value || ''));
const uniq = values => [...new Set((values || []).map(String).filter(Boolean))];
const evidenceClaimKeyFromContext=context=>{const one=Array.isArray(context?.evidenceClaims)&&context.evidenceClaims.length===1?context.evidenceClaims[0]:null,raw=context?.evidenceClaimKey??context?.evidenceClaim??(one&&typeof one==='object'?(one.key??one.id??one.claimKey):one)??(context?.evidenceSession?.requiredClaims?.length===1?context.evidenceSession.requiredClaims[0]:null);return raw==null?null:String(raw).trim().replace(/\s+/g,' ').slice(0,128).toLowerCase();};

function publicDescriptor(observer) {
  return {
    schema: 'xavi-evidence-observer/v1',
    id: observer.id,
    strategyId: observer.strategyId,
    modelId: observer.modelId,
    revision: observer.revision,
    license: observer.license,
    runtime: observer.runtime,
    capabilities: [...observer.capabilities],
    modalities: [...observer.modalities],
    retainOutput: observer.retainOutput,
    timeoutMs: observer.timeoutMs,
    metadata: {...observer.metadata},
    smallModelRuntime: observer.smallModelRuntime,
  };
}

export class EvidenceObserverRegistry {
  constructor(xavi) {
    if (!xavi?.router || !xavi?.ledger || !xavi?.store) throw new TypeError('EvidenceObserverRegistry requires XaviBrowser');
    this.xavi = xavi;
    this.observers = new Map();
  }

  register({
    id,
    modelId = id,
    revision = '',
    license,
    runtime = 'external',
    capabilities = [],
    modalities = ['text'],
    run,
    prior = 0,
    when = null,
    retainOutput = false,
    timeoutMs = null,
    metadata = {},
  } = {}) {
    if (!id) throw new TypeError('observer id required');
    if (!modelId) throw new TypeError('observer modelId required');
    if (!licenseAllowed(license)) throw new Error(`observer rejected: unsupported license ${license || '<missing>'}`);
    if (typeof run !== 'function') throw new TypeError('observer run(context, options) required');
    const caps = uniq(capabilities);
    if (!caps.length) throw new TypeError('observer requires at least one capability');
    const baseObserver = {
      id: String(id),
      strategyId: `observer:${String(id)}`,
      modelId: String(modelId),
      revision: String(revision || ''),
      license: String(license),
      runtime: String(runtime || 'external'),
      capabilities: Object.freeze(caps),
      modalities: Object.freeze(uniq(modalities)),
      run,
      prior: Number(prior) || 0,
      when,
      retainOutput: Boolean(retainOutput),
      timeoutMs: Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? Number(timeoutMs) : null,
      metadata: Object.freeze({...metadata}),
    };
    const observer = Object.freeze({...baseObserver,smallModelRuntime:smallModelRuntimeFromObserver(baseObserver)});
    this.observers.set(observer.id, observer);
    this.xavi.router.register({
      id: observer.strategyId,
      capabilities: observer.capabilities,
      modalities: observer.modalities,
      runtime: observer.runtime,
      metadata: {...observer.metadata, observerId:observer.id, modelId:observer.modelId, license:observer.license, smallModelRuntime:observer.smallModelRuntime},
      prior: observer.prior,
      when: observer.when,
      timeoutMs: observer.timeoutMs,
      run: (context, runtimeOptions) => this._invoke(observer, context, runtimeOptions),
    });
    return publicDescriptor(observer);
  }

  async _invoke(observer, context, runtimeOptions = {}) {
    const {signal} = runtimeOptions;
    const descriptor = publicDescriptor(observer);
    const inputDigest = await digest(context);
    const start = await this.xavi.ledger.append('observer-invocation-start', {
      observer: descriptor,
      inputDigest,
    });
    const started = performance.now();
    try {
      const result = await observer.run(context, {...runtimeOptions, signal, observer: descriptor});
      const elapsedMs = Math.max(0, performance.now() - started);
      const outputDigest = await digest(result);
      const evidence = {
        schema: 'xavi-observer-evidence/v1',
        observerId: observer.id,
        strategyId: observer.strategyId,
        modelId: observer.modelId,
        revision: observer.revision,
        license: observer.license,
        runtime: observer.runtime,
        evidenceClass: observer.metadata?.evidenceClass || 'observer-evidence',
        evidenceFamily: observer.metadata?.evidenceFamily || observer.metadata?.sourceFamily || observer.modelId || observer.id,
        evidenceSessionId: context?.evidenceSession?.id || context?.evidenceSessionId || null,
        evidenceClaimKey: evidenceClaimKeyFromContext(context),
        routeWitnessDigest: context?.evidenceSession?.routeWitnessDigest || context?.routeWitnessDigest || null,
        epistemicStatus: 'reported',
        inputDigest,
        outputDigest,
        elapsedMs,
      };
      const witness = await this.xavi.ledger.append('observer-evidence', {
        parent: start.digest,
        ...evidence,
      });
      await this.xavi.evidenceSessions?.ingest?.(witness);
      await this.xavi.store.set('observer-evidence', witness.id, {
        ...evidence,
        witnessDigest: witness.digest,
        retainedAt: Date.now(),
        ...(observer.retainOutput ? {result} : {}),
      });
      this.xavi.autoRetention?.enqueueObserverEvidence({observer:descriptor,evidence,witness,result,includeResult:observer.retainOutput});
      return {...evidence, witness, result};
    } catch (error) {
      const elapsedMs = Math.max(0, performance.now() - started);
      const witness = await this.xavi.ledger.append('observer-evidence', {
        parent: start.digest,
        observerId: observer.id,
        strategyId: observer.strategyId,
        modelId: observer.modelId,
        revision: observer.revision,
        license: observer.license,
        runtime: observer.runtime,
        evidenceClass: observer.metadata?.evidenceClass || 'observer-evidence',
        evidenceFamily: observer.metadata?.evidenceFamily || observer.metadata?.sourceFamily || observer.modelId || observer.id,
        evidenceSessionId: context?.evidenceSession?.id || context?.evidenceSessionId || null,
        evidenceClaimKey: evidenceClaimKeyFromContext(context),
        routeWitnessDigest: context?.evidenceSession?.routeWitnessDigest || context?.routeWitnessDigest || null,
        epistemicStatus: 'reported',
        inputDigest,
        ok: false,
        elapsedMs,
        error: String(error?.message || error).slice(0, 1000),
      });
      await this.xavi.evidenceSessions?.ingest?.(witness);
      this.xavi.autoRetention?.enqueueObserverEvidence({observer:descriptor,evidence:{...witness.body,ok:false},witness,result:null,includeResult:false});
      throw error;
    }
  }

  get(id) {
    const row = this.observers.get(String(id));
    return row ? publicDescriptor(row) : null;
  }

  list({capability = null} = {}) {
    return [...this.observers.values()]
      .filter(row => !capability || row.capabilities.includes(capability))
      .map(publicDescriptor);
  }

  async execute(capability, context = {}, options = {}) {
    return this.xavi.execute(capability, context, options);
  }
}
