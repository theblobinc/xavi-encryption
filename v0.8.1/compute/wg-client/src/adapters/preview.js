function resolveElement(target) {
  if (typeof target === 'function') return target();
  if (typeof target === 'string') return document.querySelector(target);
  return target;
}

export class PreviewLearner {
  constructor(xavi, { capability='preview' } = {}) { this.xavi=xavi; this.capability=capability; }
  register(strategy) { this.xavi.router.register({...strategy, capabilities:[...new Set([...(strategy.capabilities||[]),this.capability])]}); return this; }
  async open(context, options = {}) {
    const execution = await this.xavi.execute(this.capability, context, options);
    let outcome;
    if (typeof options.validate === 'function') outcome = await options.validate(execution, context);
    else outcome = {ok:execution.ok, latencyMs:execution.latencyMs, validated:true};
    const learning = await this.xavi.outcome(execution.receiptId, outcome);
    return {...execution, learning};
  }
}

export function createIframeStrategy({ id, target, makeUrl = ctx => ctx.url, sandbox = null, allow = null, referrerPolicy = null, className = '', prior = 0, when = null } = {}) {
  if (!id) throw new TypeError('iframe strategy id required');
  return {
    id, prior, when, capabilities:['preview'],
    async run(context, {signal} = {}) {
      const host = resolveElement(target);
      if (!host) throw new Error(`iframe target unavailable for strategy ${id}`);
      const iframe = document.createElement('iframe');
      iframe.className = className;
      iframe.src = String(await makeUrl(context));
      if (sandbox !== null) iframe.setAttribute('sandbox', sandbox);
      if (allow !== null) iframe.setAttribute('allow', allow);
      if (referrerPolicy !== null) iframe.referrerPolicy = referrerPolicy;
      iframe.dataset.xaviStrategy = id;
      const result = await new Promise((resolve,reject) => {
        const cleanup=()=>{ iframe.removeEventListener('load',onload); iframe.removeEventListener('error',onerror); signal?.removeEventListener('abort',onabort); };
        const onload=()=>{ cleanup(); resolve({iframe, loaded:true, url:iframe.src}); };
        const onerror=()=>{ cleanup(); reject(new Error(`iframe load error: ${id}`)); };
        const onabort=()=>{ cleanup(); iframe.remove(); reject(new DOMException('Aborted','AbortError')); };
        iframe.addEventListener('load',onload,{once:true});
        iframe.addEventListener('error',onerror,{once:true});
        signal?.addEventListener('abort',onabort,{once:true});
        host.replaceChildren(iframe);
      });
      return result;
    },
  };
}
