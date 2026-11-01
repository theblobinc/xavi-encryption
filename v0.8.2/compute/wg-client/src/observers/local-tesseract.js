import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { DETERMINISTIC_OBSERVER_CATALOG } from './catalog.js';

const execFileAsync=promisify(execFile);
const PROJECT_ROOT=fileURLToPath(new URL('../../',import.meta.url));
const DEFAULT_BINARY=resolve(PROJECT_ROOT,'runtime/local/tesseract/bin/tesseract');
const DEFAULT_LIB=resolve(PROJECT_ROOT,'runtime/local/tesseract/lib');
const DEFAULT_TESSDATA=resolve(PROJECT_ROOT,'runtime/local/tesseract/tessdata');

function parseTsv(text,{maxWords=512,minConfidence=0}={}){
  const lines=String(text||'').split(/\r?\n/).filter(Boolean);if(lines.length<2)return{text:'',words:[],meanConfidence:0};
  const head=lines[0].split('\t');const idx=Object.fromEntries(head.map((x,i)=>[x,i]));const words=[];let confSum=0;
  for(const line of lines.slice(1)){
    const cols=line.split('\t');const word=String(cols[idx.text]??'').trim();const conf=Number(cols[idx.conf]??-1);if(!word||!Number.isFinite(conf)||conf<minConfidence)continue;
    words.push({text:word,confidence:conf,left:Number(cols[idx.left]||0),top:Number(cols[idx.top]||0),width:Number(cols[idx.width]||0),height:Number(cols[idx.height]||0)});confSum+=conf;if(words.length>=maxWords)break;
  }
  return{text:words.map(x=>x.text).join(' ').replace(/\s+/g,' ').trim(),words,meanConfidence:words.length?confSum/words.length:0};
}

export class TesseractEvidenceExtractor{
  constructor({binary=DEFAULT_BINARY,libPath=DEFAULT_LIB,tessdata=DEFAULT_TESSDATA,maxBuffer=16*1024*1024}={}){this.binary=binary;this.libPath=libPath;this.tessdata=tessdata;this.maxBuffer=maxBuffer;}
  async extract(context={}, {signal}={}){
    const path=context.path||context.imagePath||context.filePath||context.image;
    if(typeof path!=='string'||!path)throw new TypeError('Tesseract observer requires path/imagePath/filePath');
    const language=String(context.language||context.lang||'eng').replace(/[^A-Za-z0-9_+.-]/g,'')||'eng';
    const psm=Math.max(0,Math.min(13,Number(context.psm??6)||6));const minConfidence=Math.max(-1,Math.min(100,Number(context.minConfidence??0)||0));
    const env={...process.env,LD_LIBRARY_PATH:[this.libPath,process.env.LD_LIBRARY_PATH].filter(Boolean).join(':'),TESSDATA_PREFIX:this.tessdata};
    let stdout='',stderr='',parsed=null,format='tsv';
    try {
      const row=await execFileAsync(this.binary,[path,'stdout','-l',language,'--oem','1','--psm',String(psm),'tsv'],{env,maxBuffer:this.maxBuffer,signal});stdout=row.stdout;stderr=row.stderr;parsed=parseTsv(stdout,{maxWords:Number(context.maxWords)||512,minConfidence});
    } catch (error) { stderr=String(error?.stderr||error?.message||error); }
    if(!parsed?.text){
      format='text';const row=await execFileAsync(this.binary,[path,'stdout','-l',language,'--oem','1','--psm',String(psm)],{env,maxBuffer:this.maxBuffer,signal});stdout=row.stdout;stderr=[stderr,row.stderr].filter(Boolean).join('\n');const text=String(stdout||'').replace(/\s+/g,' ').trim();const words=text?text.split(/\s+/).slice(0,Number(context.maxWords)||512).map(text=>({text,confidence:null})):[];parsed={text:words.map(x=>x.text).join(' '),words,meanConfidence:null};
    }
    return{schema:'xavi-tesseract-evidence/v1',text:parsed.text,wordCount:parsed.words.length,meanConfidence:Number.isFinite(parsed.meanConfidence)?Number(parsed.meanConfidence.toFixed(3)):null,words:context.includeWords===false?undefined:parsed.words,language,psm,format,diagnostic:String(stderr||'').trim().slice(0,2000)||null};
  }
}

export function registerTesseractObserver(xavi,{prior=1.5,retainOutput=false,timeoutMs=8000,metadata={},extractorOptions={}}={}){
  if(!xavi?.observers)throw new TypeError('XaviBrowser observer registry required');
  const spec=DETERMINISTIC_OBSERVER_CATALOG.tesseract;const extractor=new TesseractEvidenceExtractor(extractorOptions);
  const descriptor=xavi.observers.register({
    id:'local-tesseract',modelId:'tesseract-ocr/tesseract',revision:'5.5.3-local',license:spec.license,runtime:'tesseract-5.5.3-local',
    capabilities:spec.capabilities,modalities:['image','document','text'],prior,retainOutput,timeoutMs,
    metadata:{deterministic:true,costClass:spec.costClass,networkRequired:false,evidenceClass:'ocr-extraction',localBinary:true,...metadata},
    run:(context,options)=>extractor.extract(context,options),
  });
  return{descriptor,extractor};
}

export { parseTsv as parseTesseractTsv };
