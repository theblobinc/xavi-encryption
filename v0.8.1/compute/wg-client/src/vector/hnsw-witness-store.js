import { WitnessVectorStore, normalizeVector, cosineNormalized } from './witness-vector-store.js';
import { HnswIndex } from './hnsw-index.js';

function matchMetadata(meta,filter){
  if(!filter)return true;
  if(typeof filter==='function')return filter(meta);
  for(const [k,v] of Object.entries(filter)){const actual=meta?.[k];if(Array.isArray(v)?!v.includes(actual):actual!==v)return false;}
  return true;
}

export class HnswWitnessVectorStore {
  constructor({store,namespace='default',dimensions=384,m=12,efConstruction=80,efSearch=64,autoFlush=128}={}){
    this.store=store;this.namespace=String(namespace);this.dimensions=Number(dimensions);
    this.base=new WitnessVectorStore({store,namespace:this.namespace,dimensions:this.dimensions});
    this.index=new HnswIndex({dimensions:this.dimensions,m,efConstruction,efSearch});
    this.autoFlush=Math.max(1,Number(autoFlush)||128);this.dirty=0;this.indexRevisionToken=null;
    this.syncTelemetry={snapshotRestores:0,snapshotRejects:0,rebuilds:0,crossInstanceRefreshes:0,searchRetries:0,lastSyncAt:null,lastSyncReason:null};
  }
  _newIndex(){return new HnswIndex({dimensions:this.dimensions,m:this.index.m,efConstruction:this.index.efConstruction,efSearch:this.index.efSearch});}
  _token(meta){return this.base._metaToken(meta);}
  _adoptMeta(meta){this.base.count=Math.max(0,Number(meta?.count)||0);this.base.binaryCount=Math.max(0,Number(meta?.binaryCount)||0);this.base.metaRevisionToken=this._token(meta);}
  async init(){
    await this.base.init();const meta=await this.base._stableMeta(),token=this._token(meta),snap=await this.store.get('vectorMeta',`${this.namespace}:hnsw`).catch(()=>null);
    if(snap?.snapshot&&snap.baseRevisionToken===token&&Number(snap.count)===Number(meta?.count||0)){
      try{this.index.restore(snap.snapshot);this.indexRevisionToken=token;this._adoptMeta(meta);this.syncTelemetry.snapshotRestores++;return this;}catch{}
    }
    if(snap)this.syncTelemetry.snapshotRejects++;
    await this._rebuildFromStable({persist:true,reason:'init'});return this;
  }
  async _persistSnapshot(meta=null){
    meta=meta||await this.base._stableMeta();
    await this.store.set('vectorMeta',`${this.namespace}:hnsw`,{schema:'xavi-hnsw-persisted/v2',count:this.index.size,baseRevision:Number(meta?.revision||0),baseRevisionToken:this.indexRevisionToken,updatedAt:Date.now(),snapshot:this.index.snapshot(),authority:false});
  }
  async _rebuildFromStable({persist=false,reason='rebuild'}={}){
    for(let attempt=0;attempt<32;attempt++){
      const start=await this.base._stableMeta(),startToken=this._token(start),rows=(await this.store.values('vectors').catch(()=>[])).filter(r=>r?.namespace===this.namespace&&!r.deleted),next=this._newIndex();
      for(const row of rows)next.add(row.id,row.vector);
      const end=await this.base._stableMeta(),endToken=this._token(end);
      if(startToken!==endToken||rows.length!==Number(end?.count||0))continue;
      this.index=next;this.indexRevisionToken=endToken;this._adoptMeta(end);this.dirty=0;this.syncTelemetry.rebuilds++;this.syncTelemetry.lastSyncAt=Date.now();this.syncTelemetry.lastSyncReason=reason;
      if(persist)await this._persistSnapshot(end);return end;
    }
    throw new Error(`HNSW stable rebuild retry limit exceeded: ${this.namespace}`);
  }
  async _ensureCurrent({persist=true}={}){
    const meta=await this.base._stableMeta(),token=this._token(meta);
    if(token===this.indexRevisionToken&&this.index.size===Number(meta?.count||0)){this._adoptMeta(meta);return meta;}
    this.syncTelemetry.crossInstanceRefreshes++;
    return this._rebuildFromStable({persist,reason:'base-revision-changed'});
  }
  async upsert(row){
    const before=this.indexRevisionToken,{value:saved,commit}=await this.base._upsertWithCommit(row);
    if(commit&&commit.baseRevisionToken===before){this.index.add(saved.id,saved.vector);this.indexRevisionToken=commit.revisionToken;this.base.metaRevisionToken=commit.revisionToken;this.base.count=commit.count;this.base.binaryCount=commit.binaryCount;}
    else await this._rebuildFromStable({persist:false,reason:'write-base-diverged'});
    this.dirty++;if(this.dirty>=this.autoFlush)await this.flush();return saved;
  }
  async get(id){return this.base.get(id);}
  async remove(id){
    const before=this.indexRevisionToken,{value:removed,commit}=await this.base._removeWithCommit(id);
    if(commit&&commit.baseRevisionToken===before){if(removed)this.index.remove(id);this.indexRevisionToken=commit.revisionToken;this.base.metaRevisionToken=commit.revisionToken;this.base.count=commit.count;this.base.binaryCount=commit.binaryCount;}
    else await this._rebuildFromStable({persist:false,reason:'remove-base-diverged'});
    this.dirty++;if(this.dirty>=this.autoFlush)await this.flush();return removed;
  }
  async search(vector,{limit=8,filter=null,minScore=-1,ef=null,_snapshotAttempt=0}={}){
    const meta=await this._ensureCurrent(),startToken=this.indexRevisionToken,snapshotCount=Number(meta?.count||0),q=normalizeVector(vector,this.dimensions),want=Math.max(1,Number(limit)||8),raw=this.index.search(q,{k:Math.max(want*6,64),ef:ef||Math.max(want*8,64)}),rows=await this.base._candidateRows(new Set(raw.map(row=>String(row.id)))),hits=[];
    for(const row of rows){if(!matchMetadata(row.metadata,filter))continue;const score=cosineNormalized(q,row.vector);if(score<minScore)continue;hits.push({id:row.id,score,witnessDigest:row.witnessDigest,witnessId:row.witnessId,recordId:row.recordId,sourceId:row.sourceId,kind:row.kind,metadata:{...row.metadata}});}
    hits.sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));
    const end=await this.base._stableMeta(),endToken=this._token(end);
    if(endToken!==startToken){this.syncTelemetry.searchRetries++;if(Number(_snapshotAttempt)>=31)throw new Error(`HNSW search snapshot retry limit exceeded: ${this.namespace}`);await this._ensureCurrent();return this.search(vector,{limit,filter,minScore,ef,_snapshotAttempt:Number(_snapshotAttempt)+1});}
    return{schema:'xavi-vector-query/v1',namespace:this.namespace,dimensions:this.dimensions,indexMode:'hnsw+exact-rerank',candidateCount:raw.length,totalCount:snapshotCount,hits:hits.slice(0,want)};
  }
  async rebuild(){const meta=await this._rebuildFromStable({persist:true,reason:'manual-rebuild'});return this.stats(meta);}
  async flush(){const meta=await this._ensureCurrent({persist:false});await this._persistSnapshot(meta);this.dirty=0;return this;}
  stats(){const base=this.base.stats(),sync={...this.syncTelemetry,indexRevisionToken:this.indexRevisionToken,baseRevisionToken:this.base.metaRevisionToken,indexSynchronized:this.indexRevisionToken===this.base.metaRevisionToken,authority:false};return{...base,index:'hnsw',hnswNodes:this.index.size,m:this.index.m,efSearch:this.index.efSearch,sync};}
}
