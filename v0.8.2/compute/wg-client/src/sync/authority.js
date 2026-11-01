const ACTIVE_AUTHORITY_PROOFS = new WeakSet();
const AUTHORITY_PROOF_STATE = new WeakMap();
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const randomId=()=>globalThis.crypto?.randomUUID?.()||`${Date.now()}:${Math.random()}`;

function authorityProofError(message='live policy mutation requires an active BrowserAuthority lease proof',code=null,current=null){
  const error=new Error(message);if(code)error.code=code;if(current!==null)error.current=current;return error;
}

function invalidateAuthorityProof(proof,state=AUTHORITY_PROOF_STATE.get(proof)){
  if(state)state.active=false;
  if(proof&&typeof proof==='object')ACTIVE_AUTHORITY_PROOFS.delete(proof);
}

export function assertBrowserAuthorityProof(proof) {
  const state=proof&&typeof proof==='object'?AUTHORITY_PROOF_STATE.get(proof):null;
  if (!proof || typeof proof !== 'object' || !ACTIVE_AUTHORITY_PROOFS.has(proof) || state?.active===false) {
    throw authorityProofError();
  }
  return true;
}

export async function refreshBrowserAuthorityProof(proof) {
  assertBrowserAuthorityProof(proof);
  const state=AUTHORITY_PROOF_STATE.get(proof);
  if(!state?.refresh)return true;
  try{await state.refresh();return true;}
  catch(error){invalidateAuthorityProof(proof,state);throw error;}
}

export class BrowserAuthority {
  constructor({ namespace = 'default', store=null, leaseMs=60000, acquireRetryMs=25, acquireTimeoutMs=120000, owner=null } = {}) {
    this.namespace=String(namespace||'default');
    this.name = `xavi-browser-js:${this.namespace}:authority`;
    this.store=store||null;
    this.leaseSchema='xavi-browser-authority-lease/v2';
    this.leaseMs=Math.max(100,Number(leaseMs)||60000);
    this.acquireRetryMs=Math.max(5,Number(acquireRetryMs)||25);
    this.acquireTimeoutMs=Math.max(this.acquireRetryMs,Number(acquireTimeoutMs)||120000);
    this.owner=String(owner||randomId());
    this.localTail = Promise.resolve();
  }
  _durableSupported(){return typeof this.store?.get==='function'&&typeof this.store?.compareAndSet==='function';}
  _leaseKey(){return `browser-authority-lease:${this.name}`;}
  _newLeaseId(){return randomId();}
  _nextGeneration(current){return Math.max(0,Number(current?.generation||0))+1;}

  async _acquireDurableLease(){
    const key=this._leaseKey(),deadline=Date.now()+this.acquireTimeoutMs;
    for(;;){
      const now=Date.now(),current=await this.store.get('records',key);
      if(!current||current.released===true||Number(current.expiresAt||0)<=now){
        const next={schema:this.leaseSchema,namespace:this.namespace,authority:this.name,owner:this.owner,leaseId:this._newLeaseId(),generation:this._nextGeneration(current),acquiredAt:now,refreshedAt:now,expiresAt:now+this.leaseMs,released:false,authorityGrant:false};
        const result=await this.store.compareAndSet('records',key,current,next);
        if(result?.updated)return next;
        continue;
      }
      if(now>=deadline)throw authorityProofError('BrowserAuthority durable lease acquisition timed out','BROWSER_AUTHORITY_LEASE_TIMEOUT',current);
      const remaining=Math.max(1,Number(current.expiresAt||0)-now+1);
      await sleep(Math.max(1,Math.min(this.acquireRetryMs,remaining,deadline-now)));
    }
  }

  async _refreshDurableLease(state){
    if(!state?.active)throw authorityProofError('BrowserAuthority durable lease proof is inactive','BROWSER_AUTHORITY_LEASE_LOST');
    const key=this._leaseKey(),current=await this.store.get('records',key),now=Date.now(),lease=state.lease;
    if(!current||current.owner!==this.owner||current.leaseId!==lease?.leaseId||Number(current.generation||0)!==Number(lease?.generation||0)||current.released===true||Number(current.expiresAt||0)<=now){
      throw authorityProofError('BrowserAuthority durable lease lost','BROWSER_AUTHORITY_LEASE_LOST',current);
    }
    const next={...current,refreshedAt:now,expiresAt:now+this.leaseMs};
    const result=await this.store.compareAndSet('records',key,current,next);
    if(!result?.updated)throw authorityProofError('BrowserAuthority durable lease lost','BROWSER_AUTHORITY_LEASE_LOST',result?.current??null);
    Object.assign(lease,next);return lease;
  }

  async _releaseDurableLease(state){
    const lease=state?.lease;if(!lease||!this._durableSupported())return;
    const key=this._leaseKey(),current=await this.store.get('records',key).catch(()=>null);
    if(!current||current.owner!==this.owner||current.leaseId!==lease.leaseId||Number(current.generation||0)!==Number(lease.generation||0)||current.released===true)return;
    const now=Date.now();await this.store.compareAndSet('records',key,current,{...current,released:true,releasedAt:now,expiresAt:now}).catch(()=>{});
  }

  _startDurableHeartbeat(proof,state){
    const intervalMs=Math.max(25,Math.floor(this.leaseMs/3));
    state.heartbeatTail=Promise.resolve();
    state.heartbeat=setInterval(()=>{
      state.heartbeatTail=state.heartbeatTail.catch(()=>{}).then(()=>this._refreshDurableLease(state)).catch(error=>{state.error=error;invalidateAuthorityProof(proof,state);if(state.heartbeat){clearInterval(state.heartbeat);state.heartbeat=null;}});
    },intervalMs);
    state.heartbeat?.unref?.();
  }

  async _stopDurableHeartbeat(state){
    if(state?.heartbeat){clearInterval(state.heartbeat);state.heartbeat=null;}
    await state?.heartbeatTail?.catch?.(()=>{});
  }

  async _runWithProof(fn,{lease=null,durable=false}={}) {
    const leaseId=lease?.leaseId||this._newLeaseId();
    const proof=Object.freeze({schema:'xavi-browser-authority-proof/v1',authority:this.name,leaseId,generation:lease?.generation??null,durable:Boolean(durable)});
    const state={active:true,durable:Boolean(durable),lease,heartbeat:null,heartbeatTail:Promise.resolve(),error:null,refresh:null};
    if(durable)state.refresh=()=>this._refreshDurableLease(state);
    ACTIVE_AUTHORITY_PROOFS.add(proof);AUTHORITY_PROOF_STATE.set(proof,state);
    if(durable)this._startDurableHeartbeat(proof,state);
    try { return await fn(proof); }
    finally {
      if(durable)await this._stopDurableHeartbeat(state);
      invalidateAuthorityProof(proof,state);
      if(durable)await this._releaseDurableLease(state);
    }
  }

  async _serialize(fn){
    const previous=this.localTail;let release;
    this.localTail=new Promise(resolve=>{release=resolve;});
    await previous;
    try{return await fn();}finally{release();}
  }

  async withLease(fn) {
    if(this._durableSupported())return this._serialize(async()=>this._runWithProof(fn,{lease:await this._acquireDurableLease(),durable:true}));
    if (globalThis.navigator?.locks?.request) return navigator.locks.request(this.name, {mode:'exclusive'}, () => this._runWithProof(fn));
    return this._serialize(()=>this._runWithProof(fn));
  }
}

export class PolicyBus {
  constructor(namespace='default') {
    this.channel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(`xavi-browser-js:${namespace}`) : null;
  }
  publish(message) { this.channel?.postMessage(message); }
  subscribe(fn) { if (!this.channel) return () => {}; const handler=e=>fn(e.data); this.channel.addEventListener('message',handler); return ()=>this.channel.removeEventListener('message',handler); }
  close() { this.channel?.close(); }
}
