import { canonicalize, digest, nowMs, randomId } from './utils.js';
import { deriveWitnessSemanticSignature } from './witness-semantic.js';

export class WitnessLedger {
  constructor({ store, namespace = 'default' }) {
    this.store = store;
    this.namespace = namespace;
    this.head = null;
    this.sequence = 0;
    this.listeners = new Set();
    this._appendTail = Promise.resolve();
    this._appendOwner = randomId('witness-ledger');
    this._appendLockKey = 'witnessAppendLock';
  }

  async init() {
    this.head = await this.store.get('meta', 'witnessHead') || null;
    this.sequence = Number(await this.store.get('meta', 'witnessSequence') || 0);
    return this;
  }

  subscribe(listener) { if (typeof listener !== 'function') throw new TypeError('listener must be a function'); this.listeners.add(listener); return () => this.listeners.delete(listener); }


  async committedSnapshot({leaseMs=60000,timeoutMs=15000}={}) {
    const lease=await this._acquireAppendLease({leaseMs,timeoutMs});
    try{
      const headBefore=await this.store.get('meta','witnessHead')||null;
      const sequenceBefore=Number(await this.store.get('meta','witnessSequence')||0);
      const rows=(await this.store.values('witness')||[]).filter(Boolean).sort((a,b)=>Number(a?.sequence||0)-Number(b?.sequence||0));
      const headAfter=await this.store.get('meta','witnessHead')||null;
      const sequenceAfter=Number(await this.store.get('meta','witnessSequence')||0);
      return{schema:'xavi-witness-committed-snapshot/v1',namespace:this.namespace,rows,head:headAfter,sequence:sequenceAfter,metadataStable:headBefore===headAfter&&sequenceBefore===sequenceAfter,authority:false};
    }finally{await this._releaseAppendLease(lease);}
  }

  append(type, body = {}) {
    const run = () => this._appendCommitted(type, body);
    const task = this._appendTail.then(run, run);
    this._appendTail = task.then(() => undefined, () => undefined);
    return task;
  }

  async _acquireAppendLease({leaseMs=60000,timeoutMs=15000}={}) {
    if (!this.store?.compareAndSet) return null;
    const deadline = nowMs() + timeoutMs;
    for (;;) {
      const now = nowMs();
      const current = await this.store.get('meta', this._appendLockKey);
      if (!current || current.released === true || Number(current.expiresAt || 0) <= now) {
        const next = {schema:'xavi-witness-append-lock/v1',owner:this._appendOwner,leaseId:randomId('witness-append-lease'),createdAt:now,expiresAt:now+leaseMs,released:false};
        const result = await this.store.compareAndSet('meta', this._appendLockKey, current, next);
        if (result?.updated) return next;
      }
      if (now >= deadline) throw new Error('witness append lease timeout');
      await new Promise(resolve => setTimeout(resolve, 1));
    }
  }

  _appendLeaseLost() { const error=new Error('witness append lease lost'); error.code='WITNESS_APPEND_LEASE_LOST'; return error; }

  async _refreshAppendLease(lease,{leaseMs=60000}={}) {
    if (!lease || !this.store?.compareAndSet) return lease;
    const current=await this.store.get('meta',this._appendLockKey);
    if(current?.owner!==lease.owner||current?.leaseId!==lease.leaseId||current?.released===true)throw this._appendLeaseLost();
    const now=nowMs(),next={...current,expiresAt:now+leaseMs,refreshedAt:now};
    const result=await this.store.compareAndSet('meta',this._appendLockKey,current,next);
    if(!result?.updated)throw this._appendLeaseLost();
    Object.assign(lease,next);return lease;
  }

  async _releaseAppendLease(lease) {
    if (!lease || !this.store?.compareAndSet) return;
    const current = await this.store.get('meta', this._appendLockKey);
    if (current?.owner !== lease.owner || current?.leaseId !== lease.leaseId || current?.released === true) return;
    await this.store.compareAndSet('meta', this._appendLockKey, current, {...current,released:true,releasedAt:nowMs(),expiresAt:nowMs()});
  }

  async _appendCommitted(type, body = {}) {
    // A single runtime can have several asynchronous witness producers (routing,
    // retention, learning and SRNN stages), and several browser contexts may share
    // the same persistence backend. The local queue serializes one instance; this
    // store-level CAS lease serializes sequence/head allocation across instances.
    const lease = await this._acquireAppendLease();
    let committed;
    try {
      this.head = await this.store.get('meta', 'witnessHead') || null;
      this.sequence = Number(await this.store.get('meta', 'witnessSequence') || 0);
      const sequence = this.sequence + 1;
      const semantic = deriveWitnessSemanticSignature(type, body);
      const rawReceipt = {
        schemaVersion: 'xavi-browser-witness/v1',
        id: randomId('witness'), namespace: this.namespace, sequence,
        type, observedAt: nowMs(), parentDigest: this.head,
        semanticSignature: semantic.signature, metaObjectSignature: semantic.metaObjectSignature,
        body,
      };
      // Persist exactly the canonical JSON-safe object that is hashed. This prevents
      // values such as `undefined`, functions or typed arrays from hashing one way
      // and being serialized another way by a storage backend.
      const receipt = JSON.parse(canonicalize(rawReceipt));
      const receiptDigest = await digest(canonicalize(receipt));
      committed = {...receipt, digest: receiptDigest};
      await this.store.append('witness', committed);
      try{await this._refreshAppendLease(lease);}catch(error){await this.store.delete?.('witness',committed.id).catch?.(()=>{});throw error;}
      await this.store.set('meta', 'witnessHead', receiptDigest);
      await this.store.set('meta', 'witnessSequence', sequence);
      this.head = receiptDigest;
      this.sequence = sequence;
    } finally {
      await this._releaseAppendLease(lease);
    }
    for (const listener of [...this.listeners]) await listener(committed);
    return committed;
  }
}
