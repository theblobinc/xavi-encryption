export class BrowserRuntime {
  constructor({ defaultTimeoutMs = 8000 } = {}) { this.defaultTimeoutMs = defaultTimeoutMs; }

  async run(strategy, context, options = {}) {
    const { timeoutMs = this.defaultTimeoutMs, ...strategyOptions } = options || {};
    const controller = new AbortController();
    const started = performance.now();
    let timer;
    try {
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort('timeout'); reject(new Error(`strategy timeout: ${strategy.id}`)); }, timeoutMs);
      });
      const value = await Promise.race([Promise.resolve(strategy.run(context, {...strategyOptions, signal:controller.signal})), timeout]);
      return {ok:true, value, latencyMs:performance.now()-started, strategyId:strategy.id};
    } catch (error) {
      return {ok:false, error:String(error?.message || error), latencyMs:performance.now()-started, strategyId:strategy.id};
    } finally { clearTimeout(timer); }
  }

  idle(fn, {timeout = 1000} = {}) {
    if (typeof requestIdleCallback === 'function') return requestIdleCallback(() => fn(), {timeout});
    return setTimeout(fn, Math.min(timeout, 50));
  }
}
