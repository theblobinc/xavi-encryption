function norm(w){return String(w||'').trim().toLocaleLowerCase();}
function distance(a,b,max=4){a=norm(a);b=norm(b);if(Math.abs(a.length-b.length)>max)return max+1;const prev=Array.from({length:b.length+1},(_,i)=>i),cur=new Array(b.length+1);for(let i=1;i<=a.length;i+=1){cur[0]=i;let rowMin=cur[0];for(let j=1;j<=b.length;j+=1){cur[j]=Math.min(cur[j-1]+1,prev[j]+1,prev[j-1]+(a[i-1]===b[j-1]?0:1));rowMin=Math.min(rowMin,cur[j]);}if(rowMin>max)return max+1;for(let j=0;j<=b.length;j+=1)prev[j]=cur[j];}return prev[b.length];}
export class LexicalFaculty {
  constructor({entries=[]}={}){this.entries=new Map();for(const e of entries)this.add(e.word,e);}
  add(word,{definition='',definitions=null,synonyms=[],antonyms=[],partOfSpeech='',language='en',metadata={}}={}){const key=norm(word);if(!key)return this;this.entries.set(key,{word:String(word),definition,definitions:definitions|| (definition?[definition]:[]),synonyms:[...new Set(synonyms.map(String))],antonyms:[...new Set(antonyms.map(String))],partOfSpeech,language,metadata});return this;}
  load(entries){if(Array.isArray(entries))for(const e of entries)this.add(e.word,e);else for(const [word,e] of Object.entries(entries||{}))this.add(word,typeof e==='string'?{definition:e}:e);return this;}
  lookup(word){return this.entries.get(norm(word))||null;}
  define(word){return this.lookup(word)?.definitions||[];}
  synonyms(word){return [...(this.lookup(word)?.synonyms||[])];}
  antonyms(word){return [...(this.lookup(word)?.antonyms||[])];}
  suggest(word,{limit=6,maxDistance=2}={}){const w=norm(word);if(!w||this.entries.has(w))return this.entries.has(w)?[this.entries.get(w).word]:[];const out=[];for(const [key,row] of this.entries){if(Math.abs(key.length-w.length)>maxDistance)continue;if(key[0]!==w[0]&&maxDistance<3)continue;const d=distance(w,key,maxDistance);if(d<=maxDistance)out.push({word:row.word,d});}return out.sort((a,b)=>a.d-b.d||a.word.localeCompare(b.word)).slice(0,limit).map(x=>x.word);}
  spellcheck(text,{maxDistance=2}={}){const re=/\b[\p{L}][\p{L}'-]*\b/gu,out=[];for(const m of String(text||'').matchAll(re)){const w=m[0],key=norm(w);if(this.entries.has(key))continue;const suggestions=this.suggest(w,{maxDistance});if(suggestions.length)out.push({word:w,index:m.index,suggestions});}return out;}
}
