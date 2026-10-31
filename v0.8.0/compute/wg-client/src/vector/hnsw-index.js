import { normalizeVector, cosineNormalized } from './witness-vector-store.js';

function seeded(seed=0x48534e57){let x=seed|0;return()=>{x^=x<<13;x^=x>>>17;x^=x<<5;return(x>>>0)/4294967296;};}
const distance=(a,b)=>1-cosineNormalized(a,b);

export class HnswIndex {
  constructor({dimensions,m=12,efConstruction=80,efSearch=64,seed=0x48534e57}={}){
    this.dimensions=Number(dimensions); if(!Number.isInteger(this.dimensions)||this.dimensions<1) throw new TypeError('HNSW dimensions required');
    this.m=Math.max(2,Number(m)||12); this.efConstruction=Math.max(this.m,Number(efConstruction)||80); this.efSearch=Math.max(this.m,Number(efSearch)||64);
    this.rand=seeded(seed); this.nodes=new Map(); this.entryId=null; this.maxLevel=-1; this.levelScale=1/Math.log(this.m);
  }
  _level(){return Math.min(24,Math.floor(-Math.log(Math.max(1e-12,this.rand()))*this.levelScale));}
  _node(id){return this.nodes.get(String(id));}
  _neighbors(node,level){while(node.links.length<=level)node.links.push(new Set());return node.links[level];}
  _greedy(q,entryId,level){let current=this._node(entryId),best=distance(q,current.vector),changed=true;while(changed){changed=false;for(const id of this._neighbors(current,level)){const n=this._node(id);if(!n)continue;const d=distance(q,n.vector);if(d<best){current=n;best=d;changed=true;}}}return current.id;}
  _searchLayer(q,entryIds,ef,level){const visited=new Set(),candidates=[],best=[];const pushSorted=(a,item)=>{let i=0;while(i<a.length&&a[i].distance<=item.distance)i++;a.splice(i,0,item);};for(const id of entryIds){const n=this._node(id);if(!n)continue;const item={id:n.id,distance:distance(q,n.vector)};visited.add(n.id);pushSorted(candidates,item);pushSorted(best,item);}while(candidates.length){const current=candidates.shift();const worst=best.length?best[best.length-1].distance:Infinity;if(best.length>=ef&&current.distance>worst)break;const node=this._node(current.id);for(const nid of this._neighbors(node,level)){if(visited.has(nid))continue;visited.add(nid);const n=this._node(nid);if(!n)continue;const item={id:n.id,distance:distance(q,n.vector)};const bw=best.length?best[best.length-1].distance:Infinity;if(best.length<ef||item.distance<bw){pushSorted(candidates,item);pushSorted(best,item);if(best.length>ef)best.pop();}}}return best;}
  _select(q,candidates,m=this.m){return candidates.slice().sort((a,b)=>a.distance-b.distance||a.id.localeCompare(b.id)).slice(0,m);}
  _prune(node,level){const ids=[...this._neighbors(node,level)];if(ids.length<=this.m)return;const ranked=ids.map(id=>({id,distance:distance(node.vector,this._node(id).vector)})).sort((a,b)=>a.distance-b.distance).slice(0,this.m);node.links[level]=new Set(ranked.map(x=>x.id));}
  add(id,values,{level=null}={}){id=String(id);const vector=normalizeVector(values,this.dimensions);if(this.nodes.has(id))this.remove(id);const nodeLevel=level==null?this._level():Number(level);const node={id,vector,level:nodeLevel,links:Array.from({length:nodeLevel+1},()=>new Set())};if(!this.entryId){this.nodes.set(id,node);this.entryId=id;this.maxLevel=nodeLevel;return node;}
    let ep=this.entryId;for(let l=this.maxLevel;l>nodeLevel;l--)ep=this._greedy(vector,ep,l);this.nodes.set(id,node);for(let l=Math.min(nodeLevel,this.maxLevel);l>=0;l--){const found=this._searchLayer(vector,[ep],this.efConstruction,l),selected=this._select(vector,found,this.m);for(const s of selected){node.links[l].add(s.id);const other=this._node(s.id);this._neighbors(other,l).add(id);this._prune(other,l);}if(selected.length)ep=selected[0].id;}if(nodeLevel>this.maxLevel){this.entryId=id;this.maxLevel=nodeLevel;}return node;
  }
  remove(id){id=String(id);const node=this._node(id);if(!node)return false;for(let l=0;l<node.links.length;l++)for(const nid of node.links[l]){const n=this._node(nid);if(n?.links[l])n.links[l].delete(id);}this.nodes.delete(id);if(this.entryId===id){let best=null;for(const n of this.nodes.values())if(!best||n.level>best.level)best=n;this.entryId=best?.id||null;this.maxLevel=best?.level??-1;}return true;}
  search(values,{k=8,ef=this.efSearch}={}){if(!this.entryId)return[];const q=normalizeVector(values,this.dimensions);let ep=this.entryId;for(let l=this.maxLevel;l>0;l--)ep=this._greedy(q,ep,l);return this._searchLayer(q,[ep],Math.max(Number(ef)||this.efSearch,Number(k)||8),0).slice(0,Math.max(1,Number(k)||8)).map(x=>({id:x.id,score:1-x.distance}));}
  snapshot(){return{schema:'xavi-hnsw/v1',dimensions:this.dimensions,m:this.m,efConstruction:this.efConstruction,efSearch:this.efSearch,entryId:this.entryId,maxLevel:this.maxLevel,nodes:[...this.nodes.values()].map(n=>({id:n.id,vector:Array.from(n.vector),level:n.level,links:n.links.map(s=>[...s])}))};}
  restore(snapshot){if(!snapshot||snapshot.dimensions!==this.dimensions)throw new Error('HNSW snapshot dimension mismatch');this.nodes.clear();for(const n of snapshot.nodes||[])this.nodes.set(String(n.id),{id:String(n.id),vector:normalizeVector(n.vector,this.dimensions),level:Number(n.level),links:(n.links||[]).map(a=>new Set(a.map(String)))});this.entryId=snapshot.entryId||null;this.maxLevel=Number(snapshot.maxLevel??-1);return this;}
  get size(){return this.nodes.size;}
}
