export class RouteHealth {
  constructor({store, failureThreshold=2, baseCooldownMs=30000, maxCooldownMs=900000}={}) {
    this.store=store; this.failureThreshold=failureThreshold; this.baseCooldownMs=baseCooldownMs; this.maxCooldownMs=maxCooldownMs; this.rows=new Map();
  }
  async init() { for (const row of await this.store.values('routeHealth').catch(()=>[])) if (row?.id) this.rows.set(row.id,row); return this; }
  row(id) { return this.rows.get(id) || {id,state:'healthy',consecutiveFailures:0,successCount:0,failureCount:0,quarantineUntil:0,lastError:'',lastSuccessAt:0,lastFailureAt:0}; }
  decision(id, now=Date.now()) {
    const row=this.row(id);
    if (row.state==='quarantined' && now < row.quarantineUntil) return {allowed:false,state:'quarantined',retryAt:row.quarantineUntil,row};
    if (row.state==='quarantined' && now >= row.quarantineUntil) return {allowed:true,state:'half-open',retryAt:row.quarantineUntil,row};
    return {allowed:true,state:row.state,row};
  }
  async success(id) {
    const row={...this.row(id),state:'healthy',consecutiveFailures:0,successCount:this.row(id).successCount+1,lastSuccessAt:Date.now(),quarantineUntil:0,lastError:''};
    this.rows.set(id,row); await this.store.set('routeHealth',id,row); return row;
  }
  async failure(id,error='') {
    const prior=this.row(id); const failures=prior.consecutiveFailures+1; let state=prior.state; let quarantineUntil=prior.quarantineUntil||0;
    if (failures>=this.failureThreshold) { state='quarantined'; const exponent=Math.max(0,failures-this.failureThreshold); quarantineUntil=Date.now()+Math.min(this.maxCooldownMs,this.baseCooldownMs*(2**exponent)); }
    const row={...prior,state,consecutiveFailures:failures,failureCount:prior.failureCount+1,lastFailureAt:Date.now(),lastError:String(error).slice(0,500),quarantineUntil};
    this.rows.set(id,row); await this.store.set('routeHealth',id,row); return row;
  }
}
