function norm(s){return String(s??'').normalize('NFKC').trim().replace(/\s+/g,' ').toLocaleLowerCase();}
export class TranslationFaculty{
  constructor(){this.packs=new Map();}
  key(from,to){return `${String(from||'auto').toLowerCase()}->${String(to||'').toLowerCase()}`;}
  addPack({from='auto',to,entries={}}={}){if(!to)throw new TypeError('translation pack target language required');const key=this.key(from,to),pack=this.packs.get(key)||new Map();for(const [src,dst] of Object.entries(entries||{}))pack.set(norm(src),String(dst));this.packs.set(key,pack);return this;}
  translate(text,{from='auto',to}={}){if(!to)throw new TypeError('target language required');const pack=this.packs.get(this.key(from,to))||this.packs.get(this.key('*',to));if(!pack)return {ok:false,text:null,unknown:true,reason:'translation-pack-unavailable'};const source=String(text??''),exact=pack.get(norm(source));if(exact!==undefined)return {ok:true,text:exact,mode:'exact'};const parts=source.match(/[\p{L}\p{N}'-]+|[^\p{L}\p{N}'-]+/gu)||[];let hits=0;const translated=parts.map(part=>{if(!/[\p{L}\p{N}]/u.test(part))return part;const v=pack.get(norm(part));if(v!==undefined){hits+=1;return v;}return part;}).join('');return {ok:hits>0,text:translated,mode:'token',coverage:parts.length?hits/parts.filter(p=>/[\p{L}\p{N}]/u.test(p)).length:0};}
}
