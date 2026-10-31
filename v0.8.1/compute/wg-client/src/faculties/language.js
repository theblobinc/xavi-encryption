import { digest } from '../core/utils.js';
function norm(text){return String(text??'').normalize('NFKC').trim().replace(/\s+/g,' ');}

export class LanguageFaculty {
  constructor(xavi){this.xavi=xavi;this.store=xavi.store;}
  registerTranslator({id,sourceLang='*',targetLang='*',translate,prior=0,when=null}={}){
    if(!id||typeof translate!=='function')throw new TypeError('translator requires id and translate()');
    const capability=`translate:${sourceLang}:${targetLang}`;
    this.xavi.router.register({id:`translate:${id}:${sourceLang}:${targetLang}`,capabilities:[capability],prior,when,run:(context,runtime)=>translate(context.text,{sourceLang:context.sourceLang,targetLang:context.targetLang,...runtime})});
    return capability;
  }
  async teachPair(sourceText,targetText,{sourceLang='auto',targetLang,source='user',confidence=1}={}){
    if(!targetLang)throw new TypeError('targetLang required'); const src=norm(sourceText),dst=norm(targetText); const id=await digest({src,dst,sourceLang,targetLang});
    const row={id,sourceText:src,targetText:dst,sourceLang,targetLang,source,confidence:Number(confidence),createdAt:Date.now()}; await this.store.set('translations',id,row); await this.xavi.ledger.append('translation-pair-retained',{id,sourceLang,targetLang,source,confidence:row.confidence}); return row;
  }
  async memoryMatch(text,{sourceLang='auto',targetLang}={}){
    const src=norm(text); const rows=(await this.store.values('translations').catch(()=>[])).filter(r=>r?.targetLang===targetLang && (sourceLang==='auto'||r.sourceLang===sourceLang) && r.sourceText===src).sort((a,b)=>b.confidence-a.confidence); return rows[0]||null;
  }
  async translate(text,{sourceLang='auto',targetLang,explore=false,timeoutMs=8000}={}){
    if(!targetLang)throw new TypeError('targetLang required'); const exact=await this.memoryMatch(text,{sourceLang,targetLang}); if(exact){const witness=await this.xavi.ledger.append('translation-memory-hit',{pairId:exact.id,sourceLang,targetLang});return {ok:true,text:exact.targetText,source:'translation-memory',witness};}
    const direct=`translate:${sourceLang}:${targetLang}`; const wildcard=`translate:*:${targetLang}`; let capability=this.xavi.router.eligible(direct,{text,sourceLang,targetLang}).length?direct:wildcard;
    if(!this.xavi.router.eligible(capability,{text,sourceLang,targetLang}).length)return {ok:false,unknown:true,text:null,reason:'no-translation-memory-or-provider'};
    const result=await this.xavi.execute(capability,{text:norm(text),sourceLang,targetLang},{explore,timeoutMs}); return {...result,text:result.value};
  }
}
