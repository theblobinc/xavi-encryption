import { digest, dot } from '../core/utils.js';
import { WitnessLedger } from '../core/witness.js';
import { WitnessGate } from '../core/gates.js';
import { WitnessVectorStore, HashFeatureEmbedder } from '../vector/index.js';

function cleanText(text){return String(text??'').replace(/\r\n?/g,'\n').replace(/[ \t]+/g,' ').replace(/\n{3,}/g,'\n\n').trim();}
function tokenSet(text){return [...new Set(String(text).toLowerCase().match(/[\p{L}\p{N}_'-]{2,}/gu)||[])].slice(0,512);}
function chunkText(text,{chunkChars=1400,overlapChars=180}={}){const src=cleanText(text);if(!src)return[];const out=[];let start=0;while(start<src.length){let end=Math.min(src.length,start+chunkChars);if(end<src.length){const p=src.lastIndexOf('\n\n',end),s=src.lastIndexOf('. ',end),cut=Math.max(p,s);if(cut>start+Math.floor(chunkChars*.55))end=cut+(cut===s?1:0);}const part=src.slice(start,end).trim();if(part)out.push(part);if(end>=src.length)break;start=Math.max(start+1,end-overlapChars);}return out;}

export class KnowledgeCorpus{
  constructor(xaviOrOptions={}){
    const attached=Boolean(xaviOrOptions?.store && xaviOrOptions?.ledger && xaviOrOptions?.gate);
    this.xavi=attached?xaviOrOptions:null;
    this.store=xaviOrOptions.store;
    if(!this.store)throw new TypeError('KnowledgeCorpus requires a store or XaviBrowser');
    this.namespace=attached?xaviOrOptions.namespace:(xaviOrOptions.namespace||'knowledge');
    this.ledger=attached?xaviOrOptions.ledger:new WitnessLedger({store:this.store,namespace:this.namespace});
    this.gate=attached?xaviOrOptions.gate:new WitnessGate({expectedStateDim:256});
    this.embedder=attached?xaviOrOptions.embedder:(xaviOrOptions.embedder||new HashFeatureEmbedder({dimensions:Number(xaviOrOptions.vectorDim||64)}));
    this.vectorMemory=attached?xaviOrOptions.vectorMemory:(xaviOrOptions.vectorMemory||new WitnessVectorStore({store:this.store,namespace:this.namespace,dimensions:this.embedder.dimensions}));
    this.featureDim=this.embedder.dimensions;
    this._ready=attached?Promise.resolve():Promise.all([this.ledger.init(),this.vectorMemory.init()]);
  }

  async ingestText(textOrOptions,options={}){
    await this._ready;
    const cfg=typeof textOrOptions==='string'?{...options,text:textOrOptions}:{...(textOrOptions||{})};
    const {text,title='Untitled',source='',domain='general',tags=[],license='',epistemicStatus='reported',chunkChars=1400,overlapChars=180}=cfg;
    const chunks=chunkText(text,{chunkChars,overlapChars});
    const normalized=cleanText(text);
    const sourceId=await digest({title,source,domain,license,textDigest:await digest(normalized)});
    const sourceWitness=await this.ledger.append('knowledge-source-observed',{sourceId,title,source,domain,tags,license,chunkCount:chunks.length,embedder:this.embedder.describe?.()||null});
    const ids=[];
    for(let i=0;i<chunks.length;i+=1){
      const chunk=chunks[i],id=await digest({sourceId,index:i,text:chunk});
      const retention=this.gate.assessRetention({epistemicStatus,evidence:{sourceWitnesses:[sourceWitness.digest]},provenance:{source,sourceKind:'corpus',witnessId:sourceWitness.id},freshness:{policy:'source-static'},dependencies:[],addressable:true});
      const vector=await this.embedder.embed(chunk,{domain,tags,title,source,kind:'knowledge'});
      const baseRow={id,sourceId,index:i,title,source,domain,tags:[...tags],license,text:chunk,tokens:tokenSet(chunk),features:Array.from(vector),createdAt:Date.now(),sourceWitnessDigest:sourceWitness.digest,epistemicStatus,retention};
      await this.store.set('knowledge',id,baseRow);
      const chunkWitness=await this.ledger.append('knowledge-chunk-retained',{id,sourceId,index:i,retention,textDigest:await digest(chunk),embeddingDigest:await digest(Array.from(vector)),embedder:this.embedder.describe?.()||null});
      const row={...baseRow,witnessId:chunkWitness.id,witnessDigest:chunkWitness.digest};
      await this.store.set('knowledge',id,row);
      try{
        await this.vectorMemory.upsert({id,vector,witnessDigest:chunkWitness.digest,witnessId:chunkWitness.id,recordId:id,sourceId,kind:'knowledge',metadata:{domain,tags:[...tags],title,source,license,epistemicStatus,retentionAdmissible:retention?.admissible!==false}});
      }catch(error){
        await this.ledger.append('knowledge-vector-index-failed',{id,witnessDigest:chunkWitness.digest,error:String(error?.message||error).slice(0,500)});
      }
      ids.push(id);
    }
    return {sourceId,sourceWitness,chunkCount:chunks.length,chunkIds:ids};
  }

  async search(query,{domain=null,tags=[],limit=8,exact=false}={}){
    await this._ready;
    const qText=cleanText(query),qTokens=tokenSet(qText),requiredTags=new Set(tags.map(String));
    const qVector=await this.embedder.embed(qText,{domain,tags,kind:'knowledge-query'});
    const filter=meta=>(!domain||meta?.domain===domain)&&[...requiredTags].every(tag=>(meta?.tags||[]).includes(tag));
    const vectorQuery=await this.vectorMemory.search(qVector,{limit:Math.max(24,Math.max(1,limit)*6),filter,exact});
    let pairs=[];
    for(const hit of vectorQuery.hits){const row=await this.store.get('knowledge',hit.id);if(row)pairs.push({row,semantic:hit.score,witnessDigest:hit.witnessDigest});}
    if(!pairs.length){
      const rows=(await this.store.values('knowledge').catch(()=>[])).filter(row=>row&&(!domain||row.domain===domain)&&[...requiredTags].every(tag=>(row.tags||[]).includes(tag)));
      pairs=rows.map(row=>({row,semantic:Math.max(-1,Math.min(1,dot(qVector,row.features||[]))),witnessDigest:row.witnessDigest||row.sourceWitnessDigest}));
    }
    const semanticReal=this.embedder.describe?.().semantic===true;
    const semanticWeight=semanticReal?.75:.32,lexicalWeight=1-semanticWeight;
    const scored=pairs.map(({row,semantic,witnessDigest})=>{const rt=new Set(row.tokens||[]),lexical=qTokens.length?qTokens.filter(t=>rt.has(t)).length/qTokens.length:0;return{...row,witnessDigest:witnessDigest||row.witnessDigest,vectorScore:semantic,lexicalScore:lexical,score:lexicalWeight*lexical+semanticWeight*((semantic+1)/2)};}).filter(r=>r.score>0).sort((a,b)=>b.score-a.score||a.index-b.index).slice(0,Math.max(1,limit));
    const witness=await this.ledger.append('knowledge-query',{queryDigest:await digest(qText),domain,tags,embedder:this.embedder.describe?.()||null,vectorIndex:{mode:vectorQuery.indexMode,candidates:vectorQuery.candidateCount,total:vectorQuery.totalCount},returned:scored.map(r=>({id:r.id,score:r.score,witnessDigest:r.witnessDigest}))});
    Object.defineProperty(scored,'witness',{value:witness,enumerable:false});Object.defineProperty(scored,'query',{value:qText,enumerable:false});Object.defineProperty(scored,'vectorQuery',{value:vectorQuery,enumerable:false});return scored;
  }
}
