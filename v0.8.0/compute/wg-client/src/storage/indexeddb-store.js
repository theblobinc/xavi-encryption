const sameValue=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

export const INDEXEDDB_STORES = Object.freeze(['meta','state','policy','witness','records','routeHealth','deferred','investigations','knowledge','lexicon','translations','vectors','vectorBuckets','vectorMeta','memoryUtility','observer-evidence','semantic-policy','semantic-head-policy','semantic-target-policy','semantic-next-witness-policy','semantic-binary-head-policy','semantic-head-calibration','semantic-training-example']);

export class IndexedDBStore {
  constructor({ name = 'xavi-browser-js', version = 7 } = {}) { this.name = name; this.version = version; this.db = null; }
  async init() {
    if (typeof indexedDB === 'undefined') throw new Error('IndexedDB unavailable');
    this.db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(this.name, this.version);
      req.onupgradeneeded = () => {
        const db = req.result;
        for (const name of INDEXEDDB_STORES) if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this;
  }
  tx(table, mode = 'readonly') { return this.db.transaction(table, mode).objectStore(table); }
  async get(table, key) { return await new Promise((resolve,reject)=>{ const r=this.tx(table).get(key); r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(r.error); }); }
  async getMany(table, keys=[]) { const list=[...keys]; if(!list.length)return []; return await new Promise((resolve,reject)=>{ const tx=this.db.transaction(table,'readonly'),store=tx.objectStore(table),out=new Array(list.length); list.forEach((key,i)=>{const r=store.get(key);r.onsuccess=()=>{out[i]=r.result;};r.onerror=()=>reject(r.error);}); tx.oncomplete=()=>resolve(out); tx.onerror=()=>reject(tx.error); tx.onabort=()=>reject(tx.error||new Error('IndexedDB getMany aborted')); }); }
  async set(table, key, value) { return await new Promise((resolve,reject)=>{ const r=this.tx(table,'readwrite').put(value,key); r.onsuccess=()=>resolve(value); r.onerror=()=>reject(r.error); }); }
  async append(table, value) { const key=value.id || `${Date.now()}:${Math.random()}`; await this.set(table,key,value); return key; }
  async values(table) { return await new Promise((resolve,reject)=>{ const r=this.tx(table).getAll(); r.onsuccess=()=>resolve(r.result||[]); r.onerror=()=>reject(r.error); }); }
  async delete(table, key) { return await new Promise((resolve,reject)=>{ const r=this.tx(table,'readwrite').delete(key); r.onsuccess=()=>resolve(true); r.onerror=()=>reject(r.error); }); }
  async compareAndSet(table,key,expected,next){ return await new Promise((resolve,reject)=>{ const tx=this.db.transaction(table,'readwrite'),store=tx.objectStore(table);let result=null;const get=store.get(key);get.onerror=()=>reject(get.error);get.onsuccess=()=>{const current=get.result;if(!sameValue(current,expected)){result={updated:false,current};return;}const put=store.put(next,key);put.onerror=()=>reject(put.error);put.onsuccess=()=>{result={updated:true,current:next};};};tx.oncomplete=()=>resolve(result||{updated:false,current:undefined});tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error||new Error('IndexedDB compareAndSet aborted')); }); }
}
