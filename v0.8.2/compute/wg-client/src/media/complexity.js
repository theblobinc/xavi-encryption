import { open, stat, realpath, readFile } from 'node:fs/promises';
import { basename, extname, resolve, sep } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { digest } from '../core/utils.js';
import { CheerioEvidenceExtractor } from '../observers/local-cheerio.js';

const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const logNorm=(value,scale)=>clamp(Math.log2(Math.max(1,Number(value)||0)+1)/scale);
const TEXT_EXT=new Set(['.txt','.md','.csv','.tsv','.json','.jsonl','.xml','.html','.htm','.svg','.css','.js','.mjs','.cjs','.ts','.tsx','.jsx','.py','.c','.cc','.cpp','.h','.hpp','.java','.go','.rs','.php','.rb','.sh','.yaml','.yml','.toml','.ini','.conf','.log']);

function shannonEntropy(buffer){
  if(!buffer?.length)return 0;
  const counts=new Uint32Array(256); for(const b of buffer)counts[b]++;
  let h=0; for(const n of counts){if(!n)continue;const p=n/buffer.length;h-=p*Math.log2(p);} return h/8;
}
function printableRatio(buffer){if(!buffer?.length)return 0;let n=0;for(const b of buffer){if(b===9||b===10||b===13||(b>=32&&b<=126)||b>=160)n++;}return n/buffer.length;}
function compressionRatio(buffer){if(!buffer?.length)return 1;try{return clamp(deflateRawSync(buffer,{level:1}).length/buffer.length,0,2);}catch{return 1;}}
function ascii(buffer){return Buffer.from(buffer).toString('latin1');}
function u24le(b,o){return b[o]|(b[o+1]<<8)|(b[o+2]<<16);}

function pngInfo(b){if(b.length>=24&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))return{format:'png',mime:'image/png',width:b.readUInt32BE(16),height:b.readUInt32BE(20)};return null;}
function gifInfo(b){const s=b.subarray(0,6).toString('ascii');if((s==='GIF87a'||s==='GIF89a')&&b.length>=10)return{format:'gif',mime:'image/gif',width:b.readUInt16LE(6),height:b.readUInt16LE(8)};return null;}
function jpegInfo(b){if(b.length<4||b[0]!==0xff||b[1]!==0xd8)return null;let i=2;while(i+9<b.length){if(b[i]!==0xff){i++;continue;}const marker=b[i+1];if(marker===0xd8||marker===0xd9){i+=2;continue;}if(i+4>b.length)break;const len=b.readUInt16BE(i+2);if(len<2||i+2+len>b.length)break;if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)){return{format:'jpeg',mime:'image/jpeg',height:b.readUInt16BE(i+5),width:b.readUInt16BE(i+7)};}i+=2+len;}return{format:'jpeg',mime:'image/jpeg'};}
function webpInfo(b){if(b.length<30||b.toString('ascii',0,4)!=='RIFF'||b.toString('ascii',8,12)!=='WEBP')return null;const type=b.toString('ascii',12,16);if(type==='VP8X')return{format:'webp',mime:'image/webp',width:1+u24le(b,24),height:1+u24le(b,27)};return{format:'webp',mime:'image/webp'};}
function bmpInfo(b){if(b.length>=26&&b.toString('ascii',0,2)==='BM')return{format:'bmp',mime:'image/bmp',width:Math.abs(b.readInt32LE(18)),height:Math.abs(b.readInt32LE(22))};return null;}
function wavInfo(b){if(b.length>=28&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WAVE')return{format:'wav',mime:'audio/wav',channels:b.readUInt16LE(22),sampleRate:b.readUInt32LE(24)};return null;}
function formatInfo(buffer,extension){
  for(const fn of [pngInfo,gifInfo,jpegInfo,webpInfo,bmpInfo,wavInfo]){const x=fn(buffer);if(x)return x;}
  const head=ascii(buffer.subarray(0,64));
  if(head.startsWith('%PDF-'))return{format:'pdf',mime:'application/pdf'};
  if(buffer.length>=12&&buffer.toString('ascii',4,8)==='ftyp')return{format:'mp4',mime:'video/mp4'};
  if(head.startsWith('ID3')||(buffer[0]===0xff&&(buffer[1]&0xe0)===0xe0))return{format:'mp3',mime:'audio/mpeg'};
  const lower=head.trimStart().toLowerCase();
  if(lower.startsWith('<!doctype html')||lower.startsWith('<html')||['.html','.htm'].includes(extension))return{format:'html',mime:'text/html'};
  if(lower.startsWith('<?xml')||extension==='.xml')return{format:'xml',mime:'application/xml'};
  if(extension==='.json'||extension==='.jsonl')return{format:'json',mime:'application/json'};
  if(TEXT_EXT.has(extension))return{format:extension.slice(1)||'text',mime:'text/plain'};
  return{format:'binary',mime:'application/octet-stream'};
}
function mediaKind(info){if(info.mime.startsWith('image/'))return'image';if(info.mime.startsWith('video/'))return'video';if(info.mime.startsWith('audio/'))return'audio';if(info.mime.startsWith('text/')||['application/json','application/xml'].includes(info.mime))return'text';if(info.mime==='application/pdf')return'document';return'binary';}
function complexityClass(score){if(score<0.2)return'trivial';if(score<0.4)return'simple';if(score<0.65)return'moderate';if(score<0.82)return'complex';return'heavy';}
function taskFlags(taskHint=''){const s=String(taskHint).toLowerCase();return{text:/ocr|text|read|document|caption text|transcri/.test(s),visual:/visual|scene|object|image|photo|ui|layout|screenshot/.test(s),code:/code|program|source/.test(s),math:/math|equation|formula|calculate/.test(s)};}

export class MediaComplexityAnalyzer {
  constructor({allowedRoots=[process.cwd()],sampleBytes=65536,maxMarkupBytes=1048576}={}){this.allowedRoots=allowedRoots.map(x=>resolve(x));this.sampleBytes=Math.max(4096,Number(sampleBytes)||65536);this.maxMarkupBytes=Math.max(65536,Number(maxMarkupBytes)||1048576);this.cheerio=new CheerioEvidenceExtractor({maxTextChars:12000,maxItems:96});}
  async resolveAllowed(inputPath){const rp=await realpath(resolve(String(inputPath)));const ok=this.allowedRoots.some(root=>rp===root||rp.startsWith(root.endsWith(sep)?root:root+sep));if(!ok)throw new Error('media path is outside allowed roots');return rp;}
  async _sample(path,size){const fh=await open(path,'r');try{const chunk=Math.min(this.sampleBytes,Math.max(1,size));const offsets=[0,Math.max(0,Math.floor(size/2-chunk/2)),Math.max(0,size-chunk)];const unique=[...new Set(offsets)];const parts=[];for(const off of unique){const b=Buffer.alloc(Math.min(chunk,size-off));const {bytesRead}=await fh.read(b,0,b.length,off);parts.push(b.subarray(0,bytesRead));}return Buffer.concat(parts);}finally{await fh.close();}}
  _plan({kind,info,flags,printable,structureScore,semanticNeed}){
    const stages=[{tier:0,observer:'media-header-scan',cost:'tiny',action:'accept-current-assessment'}];
    if(kind==='text')stages.push({tier:1,observer:'cheerio',capability:info.format==='html'?'html:extract':'html:query',cost:'very-low',when:info.format==='html'||info.format==='xml'});
    if(kind==='image'){
      stages.push({tier:1,observer:'tesseract',capability:'image:ocr',cost:'low',when:flags.text||!flags.visual,stopWhen:'usable OCR text is recovered'});
      stages.push({tier:2,observer:'moondream2',capability:'vision:query',cost:'medium',when:flags.visual||semanticNeed>0.45,stopWhen:'visual question is answered with adequate evidence'});
    }
    if(kind==='document'){
      stages.push({tier:1,observer:'document-text-extractor',capability:'document:text',cost:'low',when:printable>0.22});
      stages.push({tier:1,observer:'tesseract',capability:'document:ocr',cost:'low',when:printable<=0.22,note:'requires page rendering for PDF inputs'});
    }
    if(kind==='video')stages.push({tier:1,observer:'frame-sampler',capability:'media:sample-frames',cost:'low',note:'sample key frames before OCR/vision escalation'},{tier:2,observer:'tesseract/moondream2',capability:'vision:query',cost:'medium',when:true});
    if(kind==='audio')stages.push({tier:1,observer:'audio-metadata',capability:'audio:metadata',cost:'very-low'},{tier:2,observer:'speech-specialist',capability:'audio:transcribe',cost:'medium',when:true});
    if(flags.math)stages.push({tier:3,observer:'qwen2.5-math-1.5b-instruct',capability:'math:reason',cost:'high',when:'extracted evidence contains nontrivial math'});
    if(flags.code)stages.push({tier:3,observer:'qwen2.5-coder-0.5b-instruct',capability:'code:explain',cost:'medium',when:'extracted evidence contains code requiring semantic analysis'});
    return stages.filter(s=>s.when!==false);
  }
  async analyzePath(inputPath,{taskHint='',retainStructure=true}={}){
    const path=await this.resolveAllowed(inputPath);const st=await stat(path);if(!st.isFile())throw new Error('media path is not a regular file');
    const extension=extname(path).toLowerCase();const sample=await this._sample(path,st.size);const info=formatInfo(sample,extension);const kind=mediaKind(info);
    const entropy=shannonEntropy(sample);const printable=printableRatio(sample);const compressed=compressionRatio(sample);
    let structure=null;let structureScore=0;
    if((info.format==='html'||info.format==='xml')&&st.size<=this.maxMarkupBytes*8){const raw=(await readFile(path)).subarray(0,this.maxMarkupBytes).toString('utf8');try{structure=this.cheerio.extract({[info.format==='xml'?'xml':'html']:raw,maxItems:96,maxTextChars:12000,includeHtml:false});structureScore=clamp((structure.counts?.links||0)/100*0.2+(structure.counts?.images||0)/50*0.2+(structure.counts?.headings||0)/30*0.15+(structure.jsonLd?.length||0)/10*0.1+Math.min(0.35,(structure.text?.length||0)/30000));}catch{structure=null;}}
    if(info.format==='pdf'){const s=ascii(sample);const pages=(s.match(/\/Type\s*\/Page\b/g)||[]).length;const streams=(s.match(/\bstream\b/g)||[]).length;structure={sampledPageMarkers:pages,sampledStreams:streams};structureScore=clamp(pages/20*0.5+streams/30*0.5);}
    const pixels=(info.width&&info.height)?info.width*info.height:0;const sizeScore=logNorm(st.size,31);const pixelScore=pixels?logNorm(pixels,30):0;const entropyScore=clamp(entropy);const redundancy=1-clamp(compressed);const flags=taskFlags(taskHint);
    const processingScore=clamp(0.30*sizeScore+0.20*entropyScore+0.20*pixelScore+0.20*structureScore+0.10*(1-redundancy));
    let semanticNeed=0.15;if(kind==='image')semanticNeed=flags.visual?0.65:(flags.text?0.25:0.45);else if(kind==='video')semanticNeed=0.75;else if(kind==='audio')semanticNeed=0.6;else if(kind==='document')semanticNeed=0.45;else if(kind==='text')semanticNeed=flags.math||flags.code?0.55:0.2;semanticNeed=clamp(semanticNeed+structureScore*0.15);
    const score=clamp(processingScore*0.65+semanticNeed*0.35);const plan=this._plan({kind,info,flags,printable,structureScore,semanticNeed});
    const result={schema:'xavi-media-complexity/v1',file:{name:basename(path),extension,sizeBytes:st.size,modifiedAtMs:st.mtimeMs,pathDigest:await digest(path)},media:{kind,...info,pixels:pixels||null},sample:{bytes:sample.length,entropyNormalized:Number(entropy.toFixed(4)),printableRatio:Number(printable.toFixed(4)),compressionRatio:Number(compressed.toFixed(4))},complexity:{score:Number(score.toFixed(4)),class:complexityClass(score),processingScore:Number(processingScore.toFixed(4)),semanticNeed:Number(semanticNeed.toFixed(4)),structureScore:Number(structureScore.toFixed(4))},task:{hint:String(taskHint||''),flags},routePlan:plan,recommendation:{firstUsefulObserver:plan.find(x=>x.tier>0)?.observer||null,escalateToModel:plan.some(x=>x.tier>=2),reason:kind==='image'?'prefer OCR for text evidence; use vision model only for unresolved visual semantics':kind==='text'?'prefer deterministic parsing before semantic models':'use the lowest tier that can close the evidence gap'}};
    if(retainStructure&&structure)result.structure=structure;return result;
  }
}

export class MediaTriageService {
  constructor(xavi,{allowedRoots=[process.cwd()],sampleBytes=65536,maxCheapMarkupBytes=1048576}={}){
    if(!xavi?.ledger)throw new TypeError('MediaTriageService requires XaviBrowser');
    this.xavi=xavi;this.analyzer=new MediaComplexityAnalyzer({allowedRoots,sampleBytes,maxMarkupBytes:maxCheapMarkupBytes});this.maxCheapMarkupBytes=Math.max(65536,Number(maxCheapMarkupBytes)||1048576);
  }
  async analyze(input,{retain=false,taskHint='',retainStructure=true}={}){
    const result=await this.analyzer.analyzePath(input,{taskHint,retainStructure});
    const state=await this.xavi.observe({type:'media-triage',mediaKind:result.media.kind,format:result.media.format,complexity:result.complexity,task:result.task.flags},{epistemicStatus:'observed',evidence:{observedDirectly:true,deterministicAssessment:true},provenance:{sourceKind:'standalone-media-triage'},freshness:{observedAt:Date.now()}});
    const witness=await this.xavi.ledger.append('media-complexity-assessment',{file:{name:result.file.name,sizeBytes:result.file.sizeBytes,pathDigest:result.file.pathDigest},media:result.media,sample:result.sample,complexity:result.complexity,task:result.task,routePlan:result.routePlan,stateWitnessDigest:state.receipt?.digest||state.stateWitness?.digest||null});
    const semantic=this.xavi.semantic?.interpret({capability:'media:triage',context:{taskHint,media:result.media,complexity:result.complexity,routePlan:result.routePlan,recommendation:result.recommendation}})||null;
    const semanticWitness=semantic?await this.xavi.ledger.append('media-semantic-assessment',{parentComplexityWitness:witness.digest,intent:semantic.intent,semanticClass:semantic.semanticClass,nextOperation:semantic.nextOperation,targetHint:semantic.targetHint,feasibility:semantic.feasibility,expectedWitnessDelta:semantic.expectedWitnessDelta,confidence:semantic.confidence,uncertainty:semantic.uncertainty,witnessContinuity:semantic.witnessContinuity,gatePressure:semantic.gatePressure,shortTermSignature:semantic.shortTermSignature,chainMotifs:semantic.chainMotifs,recommendedObserver:result.recommendation.firstUsefulObserver,escalateToModel:result.recommendation.escalateToModel,authority:false}):null;
    let retention=null;if(retain)retention=await this.xavi.remember({type:'media-complexity-assessment',assessment:result,witnessDigest:witness.digest},{epistemicStatus:'observed',evidence:{observedDirectly:true,deterministicAssessment:true},provenance:{sourceKind:'standalone-media-triage'},kind:'media-triage',text:`${result.file.name} ${result.media.kind} ${result.media.format} complexity ${result.complexity.class} ${result.task.hint}`.trim(),metadata:{domain:'media-triage',mediaKind:result.media.kind,format:result.media.format,complexityClass:result.complexity.class,semanticIntent:semantic?.intent||null}});
    return {...result,semantic,witness:{id:witness.id,digest:witness.digest,sequence:witness.sequence},semanticWitness:semanticWitness?{id:semanticWitness.id,digest:semanticWitness.digest,sequence:semanticWitness.sequence}:null,retention:retention?{id:retention.id,witnessDigest:retention.witness.digest}:null};
  }
  _cheapStage(analysis){return (analysis.routePlan||[]).find(stage=>Number(stage.tier)===1&&['tiny','very-low','low'].includes(String(stage.cost||''))&&stage.capability)||null;}
  _nextEscalationStage(analysis,afterTier=1){return (analysis.routePlan||[]).find(stage=>Number(stage.tier)>afterTier&&stage.capability)||null;}
  async _contextForStage(input,analysis,stage,taskHint){
    const path=await this.analyzer.resolveAllowed(input);
    const base={path,filePath:path,taskHint,media:analysis.media,complexity:analysis.complexity,triageWitnessDigest:analysis.witness?.digest||null};
    if(stage.observer==='cheerio'||String(stage.capability).startsWith('html:')){
      const st=await stat(path);if(st.size>this.maxCheapMarkupBytes)throw new Error('markup exceeds cheap observer byte limit');
      const raw=await readFile(path,'utf8');return analysis.media.format==='xml'?{...base,xml:raw,xmlMode:true}:{...base,html:raw};
    }
    return base;
  }
  _usable(stage,execution,{minOcrConfidence=45,minTextChars=2}={}){
    if(!execution?.ok)return{usable:false,reason:'execution-failed'};
    const result=execution.value?.result??execution.value;
    if(stage.observer==='tesseract'||/ocr/.test(String(stage.capability))){const text=String(result?.text||'').trim(),confidence=Number(result?.meanConfidence);const confidenceOk=!Number.isFinite(confidence)||confidence>=Number(minOcrConfidence);return{usable:text.length>=minTextChars&&confidenceOk,reason:text.length<minTextChars?'ocr-empty':!confidenceOk?'ocr-low-confidence':'ocr-usable',metrics:{textChars:text.length,wordCount:Number(result?.wordCount||0),meanConfidence:Number.isFinite(confidence)?confidence:null}};}
    if(stage.observer==='cheerio'||String(stage.capability).startsWith('html:')){const text=String(result?.text||'').trim(),matches=Number(result?.count||0),counts=result?.counts||{};const structural=(matches>0)||(Number(counts.links||0)+Number(counts.headings||0)+Number(counts.images||0)>0);return{usable:text.length>=minTextChars||structural,reason:text.length>=minTextChars||structural?'structured-evidence-usable':'structured-evidence-empty',metrics:{textChars:text.length,matches,links:Number(counts.links||0),headings:Number(counts.headings||0)}};}
    return{usable:false,reason:'no-cheap-sufficiency-rule'};
  }
  async _proposalForStage(stage,context){
    if(!stage)return null;
    try{return await this.xavi.propose(stage.capability,context,{witness:true});}
    catch(error){const receipt=await this.xavi.ledger.append('semantic-route-proposal',{schema:'xavi-semantic-route-proposal/v1',capability:stage.capability,strategyId:null,ranked:[],semantic:{nextOperation:'route',targetHint:stage.observer,feasibility:0,authority:false},authority:false,unavailable:true,error:String(error?.message||error).slice(0,500),contextDigest:await digest(context)});return{schema:'xavi-semantic-route-proposal/v1',capability:stage.capability,strategyId:null,ranked:[],semantic:{nextOperation:'route',targetHint:stage.observer,feasibility:0,authority:false},authority:false,unavailable:true,error:String(error?.message||error),witness:{id:receipt.id,digest:receipt.digest,sequence:receipt.sequence}};}
  }
  /** Cheap-first media inspection. Heavy stages are proposal-only unless explicitly handled by the caller. */
  async inspect(input,{taskHint='',retain=false,retainStructure=true,minOcrConfidence=45,minTextChars=2,validator=null}={}){
    const analysis=await this.analyze(input,{retain,taskHint,retainStructure});
    const cheapStage=this._cheapStage(analysis);
    if(!cheapStage){
      const escalationStage=this._nextEscalationStage(analysis,0),context=escalationStage?await this._contextForStage(input,analysis,escalationStage,taskHint):{taskHint,media:analysis.media,complexity:analysis.complexity};
      const escalation=await this._proposalForStage(escalationStage,context);
      const witness=await this.xavi.ledger.append('media-inspection',{complexityWitnessDigest:analysis.witness.digest,cheapStage:null,usable:false,reason:'no-cheap-executable-stage',escalationWitnessDigest:escalation?.witness?.digest||null,authority:false});
      return{schema:'xavi-media-inspection/v1',analysis,cheap:null,usable:false,escalation,witness:{id:witness.id,digest:witness.digest,sequence:witness.sequence},authority:false};
    }
    const context=await this._contextForStage(input,analysis,cheapStage,taskHint);
    const proposal=await this._proposalForStage(cheapStage,context);
    const allowedCosts=new Set(['tiny','very-low','low']);
    if(!proposal?.strategyId||!allowedCosts.has(String(proposal.semantic?.costClass||cheapStage.cost||''))){
      const escalationStage=this._nextEscalationStage(analysis,Number(cheapStage.tier)||1),escalation=await this._proposalForStage(escalationStage,escalationStage?await this._contextForStage(input,analysis,escalationStage,taskHint):context);
      const witness=await this.xavi.ledger.append('media-inspection',{complexityWitnessDigest:analysis.witness.digest,cheapStage,cheapProposalDigest:proposal?.witness?.digest||null,executed:false,usable:false,reason:'cheap-strategy-unavailable-or-cost-exceeded',escalationWitnessDigest:escalation?.witness?.digest||null,authority:false});
      return{schema:'xavi-media-inspection/v1',analysis,cheap:{stage:cheapStage,proposal,executed:false},usable:false,escalation,witness:{id:witness.id,digest:witness.digest,sequence:witness.sequence},authority:false};
    }
    const execution=await this.xavi.execute(cheapStage.capability,context,{explore:false});
    const sufficiency=this._usable(cheapStage,execution,{minOcrConfidence,minTextChars});
    let validation={validated:false,ok:execution.ok&&sufficiency.usable,reason:'media-inspection-not-externally-validated'};
    if(typeof validator==='function'){
      const verdict=await validator({analysis,stage:cheapStage,execution,sufficiency,context});
      validation=typeof verdict==='boolean'?{validated:true,ok:verdict,reason:'caller-validator'}:{validated:verdict?.validated!==false,ok:Boolean(verdict?.ok),reason:String(verdict?.reason||'caller-validator')};
    }
    const learning=await this.xavi.outcome(execution.receiptId,{ok:validation.ok,validated:validation.validated,latencyMs:execution.latencyMs,reason:validation.reason});
    let escalation=null;
    if(!sufficiency.usable){const escalationStage=this._nextEscalationStage(analysis,Number(cheapStage.tier)||1);if(escalationStage)escalation=await this._proposalForStage(escalationStage,await this._contextForStage(input,analysis,escalationStage,taskHint));}
    const evidence=execution.value?.witness||null;
    const inspectionWitness=await this.xavi.ledger.append('media-inspection',{complexityWitnessDigest:analysis.witness.digest,cheapStage,cheapProposalDigest:proposal.witness?.digest||null,routeWitnessDigest:execution.routeWitness?.digest||null,evidenceWitnessDigest:evidence?.digest||null,sufficiency,validation,promoted:Boolean(learning.promotion?.promoted),escalationWitnessDigest:escalation?.witness?.digest||null,authority:false});
    return{schema:'xavi-media-inspection/v1',analysis,cheap:{stage:cheapStage,proposal,execution:{ok:execution.ok,strategyId:execution.strategyId,latencyMs:execution.latencyMs,error:execution.error||null,evidence:execution.value},sufficiency,validation,learning:{promoted:Boolean(learning.promotion?.promoted),outcomeWitnessDigest:learning.outcomeWitness?.digest||null,predictionAssessmentDigest:learning.predictionAssessment?.digest||null}},usable:sufficiency.usable,escalation,witness:{id:inspectionWitness.id,digest:inspectionWitness.digest,sequence:inspectionWitness.sequence},authority:false};
  }
}
