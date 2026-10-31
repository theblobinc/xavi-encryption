import { HnswWitnessVectorStore } from './hnsw-witness-store.js';

function hash32(text){let h=2166136261;for(const ch of String(text)){h^=ch.codePointAt(0);h=Math.imul(h,16777619);}return h>>>0;}
export class ShardedWitnessVectorStore {
  constructor({store,namespace='default',dimensions=384,shards=8,hnsw={}}={}){if(!store)throw new TypeError('ShardedWitnessVectorStore requires store');this.store=store;this.namespace=String(namespace);this.dimensions=Number(dimensions);this.shardCount=Math.max(1,Number(shards)||8);this.shards=Array.from({length:this.shardCount},(_,i)=>new HnswWitnessVectorStore({store,namespace:`${this.namespace}:s${i}`,dimensions:this.dimensions,...hnsw}));}
  async init(){await Promise.all(this.shards.map(s=>s.init()));return this;}
  shardFor(row={}){const domain=row.metadata?.domain||'',kind=row.kind||'',source=row.sourceId||row.recordId||row.id||'';return hash32(`${domain}\u0000${kind}\u0000${source}`)%this.shardCount;}
  async upsert(row){const shard=this.shardFor(row);const saved=await this.shards[shard].upsert(row);return{...saved,shard};}
  async get(id){for(const s of this.shards){const row=await s.get(id);if(row&&!row.deleted)return row;}return undefined;}
  async remove(id){let removed=false;for(const s of this.shards)removed=(await s.remove(id))||removed;return removed;}
  async search(vector,{limit=8,...options}={}){const want=Math.max(1,Number(limit)||8),results=await Promise.all(this.shards.map((s,i)=>s.search(vector,{limit:Math.max(want*2,16),...options}).then(r=>({i,r}))));const hits=[];let candidates=0,total=0;for(const {i,r} of results){candidates+=r.candidateCount||0;total+=r.totalCount||0;for(const hit of r.hits)hits.push({...hit,shard:i});}hits.sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));return{schema:'xavi-vector-query/v1',namespace:this.namespace,dimensions:this.dimensions,indexMode:'sharded-hnsw+exact-rerank',shards:this.shardCount,candidateCount:candidates,totalCount:total,hits:hits.slice(0,want)};}
  async flush(){await Promise.all(this.shards.map(s=>s.flush()));return this;}
  async rebuild(){await Promise.all(this.shards.map(s=>s.rebuild()));return this.stats();}
  stats(){const parts=this.shards.map(s=>s.stats());return{schema:'xavi-sharded-witness-vector-store/v1',namespace:this.namespace,dimensions:this.dimensions,shards:this.shardCount,count:parts.reduce((n,p)=>n+p.count,0),parts,authority:false};}
}
