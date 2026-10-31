import { featurize } from './utils.js';

const RELATION_KEYS = Object.freeze({
  strategyId:'routes_to', observerId:'observed_by', modelId:'modeled_by', recordId:'refers_to', witnessId:'witness_ref',
  sourceId:'derived_from', parent:'derived_from', parentDigest:'derived_from', capability:'capability', domain:'belongs_to',
  sourceKind:'source_kind', epistemicStatus:'epistemic_state', reason:'reason', operation:'operation', intent:'intent',
});
const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const clean=v=>String(v??'').trim().slice(0,120).toLowerCase();

function family(type='unknown') {
  const v=clean(type);
  if(v.includes('memory')) return 'memory';
  if(v.includes('observer')||v.includes('evidence')) return 'evidence';
  if(v.includes('route')||v.includes('strategy')) return 'route';
  if(v.includes('outcome')||v.includes('validation')) return 'outcome';
  if(v.includes('learning')||v.includes('policy')) return 'learning';
  if(v.includes('state')) return 'state';
  if(v.includes('media')) return 'media';
  return v.split(/[-:]/)[0]||'witness';
}
function tokenParts(token=''){
  const m=String(token).match(/(?:^|\.)([A-Za-z][A-Za-z0-9_]*)=([^=]+)$/);
  return m?{key:m[1],value:clean(m[2])}:null;
}
function nodeId(receipt){return String(receipt?.digest||receipt?.id||`seq:${receipt?.sequence||0}`);}

/**
 * Bounded, ephemeral meta-object working memory.
 * This is not long-term memory and is never authoritative. It is reconstructed
 * from witnessed receipts and exists only to cheaply expose local topology.
 */
export class WitnessWorkingMemory {
  constructor({featureDim=32,maxObjects=96,maxEdges=384}={}){
    this.featureDim=Math.max(16,Number(featureDim)||32);
    this.maxObjects=Math.max(16,Math.min(256,Number(maxObjects)||96));
    this.maxEdges=Math.max(this.maxObjects,Number(maxEdges)||384);
    this.nodes=[];this.edges=[];this.byId=new Map();this.entityIndex=new Map();this.transitions=new Map();this.relationVectors=new Map();this.messageCache=new Map();this.summaryCache=null;this.revision=0;this.nextDuoIndex=1;
    this.schema='xavi-witness-working-memory/v1';
  }
  clear(){this.nodes=[];this.edges=[];this.byId.clear();this.entityIndex.clear();this.transitions.clear();this.messageCache.clear();this.summaryCache=null;this.nextDuoIndex=1;this.revision++;}
  _invalidate(){this.revision++;this.messageCache.clear();this.summaryCache=null;}
  _relationVector(relation){const key=String(relation||'related');let row=this.relationVectors.get(key);if(!row){row=Float64Array.from(featurize({relation:key},this.featureDim));this.relationVectors.set(key,row);}return row;}
  _edge(from,to,relation,weight=1){
    if(!from||!to||from===to)return;
    const source=this.byId.get(from),target=this.byId.get(to);if(!source||!target)return;
    this.edges.push({from,to,fromDuoIndex:source.duoIndex,toDuoIndex:target.duoIndex,relation:String(relation||'related'),weight:clamp(weight,0,1)});
    if(this.edges.length>this.maxEdges)this.edges.splice(0,this.edges.length-this.maxEdges);
    this._invalidate();
  }
  _evictOldest(){
    const gone=this.nodes.shift();if(!gone)return null;this.byId.delete(gone.id);this.edges=this.edges.filter(e=>e.from!==gone.id&&e.to!==gone.id);for(const [k,v] of this.entityIndex)if(v===gone.id)this.entityIndex.delete(k);return gone;
  }
  _pushNode(node){
    if(this.nodes.length>=this.maxObjects)this._evictOldest();
    node.duoIndex=this.nextDuoIndex;this.nextDuoIndex=this.nextDuoIndex>=this.maxObjects?1:this.nextDuoIndex+1;
    this.nodes.push(node);this.byId.set(node.id,node);this._invalidate();return node;
  }
  _trim(){while(this.nodes.length>this.maxObjects)this._evictOldest();}
  _addRecalledMemories(receipt,parentId){
    if(receipt?.type!=='memory-vector-recall'||!Array.isArray(receipt?.body?.returned))return;
    const hits=receipt.body.returned.slice(0,16);
    hits.forEach((hit,index)=>{
      if(!hit?.witnessDigest)return;
      const recordId=clean(hit.recordId||hit.id||`memory-${index}`),witnessDigest=String(hit.witnessDigest),id=`${parentId}:recalled:${recordId}:${index}`;
      const entities=[
        {key:'recordId',value:recordId,relation:'refers_to'},
        {key:'witnessId',value:clean(witnessDigest),relation:'witness_ref'},
        {key:'epistemicStatus',value:clean(hit.epistemicStatus||'reported'),relation:'epistemic_state'},
      ];
      const score=Number(hit.score),trustScore=Number(hit.trustScore);
      const node={id,sequence:Number(receipt.sequence||0),type:'recalled-memory',family:'memory',observedAt:Number(receipt.observedAt||0),virtual:true,sourceWitnessDigest:String(receipt.digest||''),semanticSignature:null,metaObjectSignature:null,entities,
        vector:Array.from(featurize({type:'recalled-memory',recordId,epistemicStatus:hit.epistemicStatus||'reported',similarity:Number.isFinite(score)?Math.round(score*10)/10:null,trust:Number.isFinite(trustScore)?Math.round(trustScore*10)/10:null},this.featureDim))};
      this._pushNode(node);this._edge(parentId,id,'retrieved',clamp(Number.isFinite(trustScore)?trustScore:0.75,0.2,1));
      if(this.byId.has(witnessDigest))this._edge(witnessDigest,id,'witness_ref',1);
      const entityKey=`recordId:${recordId}`,previous=this.entityIndex.get(entityKey);if(previous&&this.byId.has(previous))this._edge(previous,id,'same_semantic_object',0.9);this.entityIndex.set(entityKey,id);
    });
  }
  ingest(receipt,{metaTokens=[]}={}){
    if(!receipt)return null;
    const id=nodeId(receipt),type=String(receipt.type||'unknown'),prev=this.nodes.at(-1)||null;
    const entities=[];
    for(const token of metaTokens){const p=tokenParts(token);if(p&&RELATION_KEYS[p.key]&&p.value)entities.push({...p,relation:RELATION_KEYS[p.key]});}
    const node={
      id,sequence:Number(receipt.sequence||0),type,family:family(type),observedAt:Number(receipt.observedAt||0),
      semanticSignature:receipt.semanticSignature||null,metaObjectSignature:receipt.metaObjectSignature||null,
      entities:entities.slice(0,24),vector:Array.from(featurize({type,family:family(type),entities},this.featureDim)),
    };
    this._pushNode(node);
    if(prev){this._edge(prev.id,id,'precedes',1);const key=`${prev.type}>${type}`;this.transitions.set(key,(this.transitions.get(key)||0)+1);}
    if(receipt.parentDigest&&this.byId.has(String(receipt.parentDigest)))this._edge(String(receipt.parentDigest),id,'derived_from',1);
    for(const entity of entities){
      const entityKey=`${entity.key}:${entity.value}`;const previous=this.entityIndex.get(entityKey);
      if(previous&&this.byId.has(previous))this._edge(previous,id,entity.relation,0.85);
      this.entityIndex.set(entityKey,id);
    }
    this._addRecalledMemories(receipt,id);
    this._trim();
    return node;
  }
  recent(n=12){return this.nodes.slice(-Math.max(1,Number(n)||12));}
  messageVector({passes=3,recency=0.88}={}){
    if(!this.nodes.length)return Array(this.featureDim).fill(0);
    passes=Math.max(1,Math.min(5,Number(passes)||3));recency=Number(recency)||0.88;const cacheKey=`${this.revision}:${passes}:${recency}`;const cached=this.messageCache.get(cacheKey);if(cached)return cached.slice();
    // DUO one-origin direct addressing: slot 0 is an inert implementation sentinel.
    // Cognitive/meta-object addresses remain INDEX(1..maxObjects); no zero identity is exposed.
    const stride=this.featureDim,size=(this.maxObjects+1)*stride;let states=new Float64Array(size);
    for(const node of this.nodes)states.set(node.vector,node.duoIndex*stride);
    for(let pass=0;pass<passes;pass++){
      const acc=new Float64Array(size),counts=new Uint16Array(this.maxObjects+1);
      for(const edge of this.edges){const si=edge.fromDuoIndex,ti=edge.toDuoIndex;if(!(si>=1&&ti>=1))continue;const sourceBase=si*stride,targetBase=ti*stride,rel=this._relationVector(edge.relation),w=Number(edge.weight||1);for(let d=0;d<stride;d++)acc[targetBase+d]+=w*(0.72*states[sourceBase+d]+0.28*rel[d]);counts[ti]++;}
      const next=new Float64Array(size);
      for(const node of this.nodes){const slot=node.duoIndex,base=slot*stride,c=Math.max(1,counts[slot]);let ss=0;for(let d=0;d<stride;d++){const x=Math.tanh(0.68*states[base+d]+0.32*(acc[base+d]/c));next[base+d]=x;ss+=x*x;}const z=Math.sqrt(ss)||1;for(let d=0;d<stride;d++)next[base+d]/=z;}
      states=next;
    }
    const pooled=new Float64Array(stride);let total=0,w=1;
    for(let i=this.nodes.length-1;i>=0;i--){const base=this.nodes[i].duoIndex*stride;total+=w;for(let d=0;d<stride;d++)pooled[d]+=w*states[base+d];w*=recency;}
    if(total)for(let d=0;d<stride;d++)pooled[d]/=total;let ss=0;for(let d=0;d<stride;d++)ss+=pooled[d]*pooled[d];const z=Math.sqrt(ss)||1;for(let d=0;d<stride;d++)pooled[d]/=z;const result=Array.from(pooled);this.messageCache.set(cacheKey,result);return result.slice();
  }
  relationCounts(){const out={};for(const e of this.edges)out[e.relation]=(out[e.relation]||0)+1;return out;}
  familyCounts(){const out={};for(const n of this.nodes)out[n.family]=(out[n.family]||0)+1;return out;}
  nextTypes(type=this.nodes.at(-1)?.type){
    if(!type)return[];const rows=[];for(const [key,count] of this.transitions){const [from,to]=key.split('>');if(from===type)rows.push({type:to,count});}
    return rows.sort((a,b)=>b.count-a.count||a.type.localeCompare(b.type));
  }
  compatibility(a=this.nodes.at(-1),b=this.nodes.at(-2)){
    if(!a||!b)return 0.5;const ea=new Set(a.entities.map(x=>`${x.key}:${x.value}`)),eb=new Set(b.entities.map(x=>`${x.key}:${x.value}`));
    let shared=0;for(const x of ea)if(eb.has(x))shared++;const denom=Math.max(1,Math.min(ea.size,eb.size));
    const familyFit=a.family===b.family?0.2:0;return clamp(0.42+familyFit+0.38*(shared/denom));
  }
  conflictScore(){
    const recent=this.recent(10);let flags=0,total=0;
    for(const n of recent)for(const e of n.entities){if(/validated|admissible|eligible|ok|committed/.test(e.key)){total++;if(/false|reject|failed|invalid/.test(e.value))flags++;}if(/reason|status/.test(e.key)&&/conflict|contradict|reject|fail|invalid|quarantine/.test(e.value)){total++;flags++;}}
    return total?clamp(flags/total):0;
  }
  summary(){
    const cacheKey=`${this.revision}:${this.nodes.length}:${this.edges.length}`;if(this.summaryCache?.key===cacheKey)return this.summaryCache.value;
    const recent=this.recent(12);let lastWitness=null;for(let i=this.nodes.length-1;i>=0;i--)if(!this.nodes[i].virtual){lastWitness=this.nodes[i];break;}const next=this.nextTypes(lastWitness?.type).slice(0,4).map(Object.freeze);
    const messageVector=this.messageVector();const messageEnergy=Math.sqrt(messageVector.reduce((n,x)=>n+x*x,0));
    const value=Object.freeze({schema:this.schema,authority:false,maxObjects:this.maxObjects,objectCount:this.nodes.length,edgeCount:this.edges.length,messageEnergy,
      families:Object.freeze(this.familyCounts()),relations:Object.freeze(this.relationCounts()),recentTypes:Object.freeze(recent.map(x=>x.type)),
      compatibility:this.compatibility(),conflict:this.conflictScore(),nextWitnessTypes:Object.freeze(next),
      activeEntities:Object.freeze(recent.flatMap(n=>n.entities.map(e=>`${e.key}=${e.value}`)).slice(-24))});
    this.summaryCache={key:cacheKey,value};return value;
  }
}
