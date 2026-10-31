function norm(word){return String(word??'').normalize('NFKC').toLocaleLowerCase().trim();}
function distance(a,b){
  a=norm(a);b=norm(b); const d=Array.from({length:a.length+1},()=>new Uint16Array(b.length+1));
  for(let i=0;i<=a.length;i++)d[i][0]=i; for(let j=0;j<=b.length;j++)d[0][j]=j;
  for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++){const cost=a[i-1]===b[j-1]?0:1;d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+cost);if(i>1&&j>1&&a[i-1]===b[j-2]&&a[i-2]===b[j-1])d[i][j]=Math.min(d[i][j],d[i-2][j-2]+1);} return d[a.length][b.length];
}

export class LexiconFaculty {
  constructor(xavi){this.xavi=xavi;this.store=xavi.store;}
  async addEntry(word,{language='en',definitions=[],synonyms=[],antonyms=[],partOfSpeech='',source='user',confidence=.8}={}){
    const key=`${language}:${norm(word)}`; const row={id:key,word:String(word),normalized:norm(word),language,definitions:[...definitions],synonyms:[...new Set(synonyms.map(String))],antonyms:[...new Set(antonyms.map(String))],partOfSpeech,source,confidence:Number(confidence),updatedAt:Date.now()};
    await this.store.set('lexicon',key,row); await this.xavi.ledger.append('lexicon-entry-retained',{id:key,language,source,confidence:row.confidence}); return row;
  }
  async loadWords(words,{language='en',source='word-list'}={}){let count=0;for(const item of words||[]){if(typeof item==='string')await this.addEntry(item,{language,source});else if(item?.word)await this.addEntry(item.word,{language,source,...item});count+=1;}return {count};}
  async lookup(word,{language='en'}={}){return await this.store.get('lexicon',`${language}:${norm(word)}`)||null;}
  async synonyms(word,{language='en'}={}){return (await this.lookup(word,{language}))?.synonyms||[];}
  async spellcheck(word,{language='en',limit=6,maxDistance=2}={}){
    const exact=await this.lookup(word,{language}); if(exact)return {correct:true,word:exact.word,suggestions:[]}; const n=norm(word);
    const rows=(await this.store.values('lexicon').catch(()=>[])).filter(r=>r?.language===language && Math.abs((r.normalized||'').length-n.length)<=maxDistance);
    const suggestions=rows.map(r=>({word:r.word,distance:distance(n,r.normalized)})).filter(r=>r.distance<=maxDistance).sort((a,b)=>a.distance-b.distance||a.word.localeCompare(b.word)).slice(0,limit);
    return {correct:false,word:String(word),suggestions};
  }
}
