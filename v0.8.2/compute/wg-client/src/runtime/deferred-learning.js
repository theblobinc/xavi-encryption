import { randomId } from '../core/utils.js';

export class DeferredLearningQueue {
  constructor({store,runtime,maxAttempts=4}={}) { this.store=store; this.runtime=runtime; this.maxAttempts=maxAttempts; this.running=false; }
  async enqueue(payload,{key=null}={}) {
    const id=key || randomId('deferred');
    const existing=await this.store.get('deferred',id).catch(()=>null);
    if (existing) return {...existing,duplicate:true};
    const row={id,status:'pending',attempts:0,nextAttemptAt:0,createdAt:Date.now(),updatedAt:Date.now(),payload};
    await this.store.set('deferred',id,row); return row;
  }
  async pending() { return (await this.store.values('deferred').catch(()=>[])).filter(r=>r?.status==='pending' && Number(r.nextAttemptAt||0)<=Date.now()); }
  async drain(handler,{limit=8}={}) {
    if (this.running) return {running:true,processed:0};
    this.running=true; let processed=0;
    try {
      for (const row of (await this.pending()).slice(0,limit)) {
        const active={...row,status:'inflight',attempts:row.attempts+1,updatedAt:Date.now()}; await this.store.set('deferred',row.id,active);
        try {
          const result=await handler(active.payload,active);
          await this.store.set('deferred',row.id,{...active,status:'done',result,completedAt:Date.now(),updatedAt:Date.now()});
        } catch (error) {
          const dead=active.attempts>=this.maxAttempts;
          await this.store.set('deferred',row.id,{...active,status:dead?'quarantined':'pending',lastError:String(error?.message||error),nextAttemptAt:Date.now()+Math.min(60000,500*(2**active.attempts)),updatedAt:Date.now()});
        }
        processed+=1;
      }
    } finally { this.running=false; }
    return {processed};
  }
  schedule(handler,{limit=8,timeout=1000}={}) { return this.runtime.idle(()=>{ void this.drain(handler,{limit}); },{timeout}); }
}
