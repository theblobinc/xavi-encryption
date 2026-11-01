import { access } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SPECIALIST_OBSERVER_CATALOG } from './catalog.js';

const PROJECT_ROOT=fileURLToPath(new URL('../../',import.meta.url));
const VENDORED_TRANSFORMERS='../../vendor/transformers.js/packages/transformers/dist/transformers.node.mjs';
const QWEN_MATH_ONNX_REVISION='29b745e87b28faa666ea598ee43b4db439144be6';
const MOONDREAM_ONNX_REVISION='2d577a7ec3b54cce81456f5358d7aa815d587079';

async function readable(path){try{await access(path,fsConstants.R_OK);return true;}catch{return false;}}
async function loadTransformers(){return import(VENDORED_TRANSFORMERS);}
function configureOffline(mod){mod.env.allowRemoteModels=false;mod.env.allowLocalModels=true;mod.env.localModelPath=PROJECT_ROOT;return mod;}
function generatedText(out){
  const value=out?.[0]?.generated_text ?? out?.generated_text ?? out;
  if(Array.isArray(value)) return String(value.at(-1)?.content ?? value.at(-1) ?? '');
  return String(value ?? '');
}

export class LocalTransformersTextGenerator {
  constructor({model='models/onnx/qwen2.5-math-1.5b-instruct',modelId='Qwen/Qwen2.5-Math-1.5B-Instruct',dtype='q8',device='cpu',task='text-generation'}={}){
    this.model=model;this.modelId=modelId;this.dtype=dtype;this.device=device;this.task=task;this.pipe=null;this.module=null;
  }
  async init(){
    const graph=resolve(PROJECT_ROOT,this.model,'onnx',this.dtype==='q8'?'model_quantized.onnx':`model_${this.dtype}.onnx`);
    if(!await readable(graph))throw new Error(`local ONNX model unavailable: ${graph}`);
    this.module=configureOffline(await loadTransformers());
    return this;
  }
  async _ensure(){
    if(!this.module)await this.init();
    if(!this.pipe)this.pipe=await this.module.pipeline(this.task,this.model,{dtype:this.dtype,device:this.device});
    return this.pipe;
  }
  async generate(context={}, {generation={}}={}){
    const pipe=await this._ensure();
    let input=context.prompt ?? null;
    if(input==null && context.expression!=null) input=`${String(context.expression).trim()} =`;
    if(input==null && Array.isArray(context.messages)) input=context.messages;
    if(input==null) input=String(context.text ?? context.query ?? '');
    if(!input || (Array.isArray(input)&&!input.length))throw new TypeError('local text observer requires prompt, expression, messages, text, or query');
    const stringInput=typeof input==='string';
    const maxNew=Number(generation.maxNewTokens ?? generation.max_new_tokens ?? (context.expression!=null?16:96));
    const options={...generation,max_new_tokens:Math.max(1,Math.min(512,Number.isFinite(maxNew)?Math.floor(maxNew):96)),do_sample:generation.do_sample??false};
    delete options.maxNewTokens;
    if(stringInput && options.return_full_text===undefined) options.return_full_text=false;
    const started=performance.now();
    const raw=await pipe(input,options);
    const text=generatedText(raw).trim();
    return {schema:'xavi-local-transformers-text/v1',modelId:this.modelId,modelPath:this.model,dtype:this.dtype,device:this.device,text,elapsedMs:Math.max(0,performance.now()-started)};
  }
  async dispose(){if(this.pipe?.dispose)await this.pipe.dispose();this.pipe=null;}
}

export class LocalMoondreamOnnxObserver {
  constructor({model='models/onnx/moondream2',modelId='vikhyatk/moondream2',device='cpu',dtype={decoder_model_merged:'q4',embed_tokens:'q8',vision_encoder:'q4'},imageTokenCount=729}={}){
    this.model=model;this.modelId=modelId;this.device=device;this.dtype=dtype;this.imageTokenCount=imageTokenCount;this.module=null;this.tokenizer=null;this.processor=null;this.modelRuntime=null;
  }
  async init(){
    const required=['onnx/decoder_model_merged_q4.onnx','onnx/embed_tokens_quantized.onnx','onnx/vision_encoder_q4.onnx','tokenizer.json','preprocessor_config.json'];
    for(const rel of required){const path=resolve(PROJECT_ROOT,this.model,rel);if(!await readable(path))throw new Error(`local Moondream artifact unavailable: ${path}`);}
    this.module=configureOffline(await loadTransformers());
    return this;
  }
  async _ensure(){
    if(!this.module)await this.init();
    if(!this.modelRuntime){
      const id=this.model;
      [this.tokenizer,this.processor,this.modelRuntime]=await Promise.all([
        this.module.AutoTokenizer.from_pretrained(id,{local_files_only:true}),
        this.module.AutoProcessor.from_pretrained(id,{local_files_only:true}),
        this.module.AutoModelForImageTextToText.from_pretrained(id,{local_files_only:true,dtype:this.dtype,device:this.device}),
      ]);
    }
    return this;
  }
  async observe(context={}, {generation={}}={}){
    await this._ensure();
    const imageInput=context.image ?? context.imagePath ?? context.path;
    if(!imageInput)throw new TypeError('Moondream observer requires image/imagePath/path');
    const question=String(context.question ?? context.query ?? (context.task==='caption'?'Describe this image in one concise sentence.':'Describe this image.'));
    const image=typeof imageInput==='string'?await this.module.RawImage.read(imageInput):imageInput;
    const vision=await this.processor(image);
    const prefix='<image>'.repeat(this.imageTokenCount);
    const prompt=`${prefix}\n\nQuestion: ${question}\n\nAnswer:`;
    const textInputs=this.tokenizer(prompt);
    const maxNew=Number(generation.maxNewTokens ?? generation.max_new_tokens ?? 24);
    const options={...generation,max_new_tokens:Math.max(1,Math.min(256,Number.isFinite(maxNew)?Math.floor(maxNew):24)),do_sample:generation.do_sample??false};
    delete options.maxNewTokens;
    const started=performance.now();
    const output=await this.modelRuntime.generate({...textInputs,...vision,...options});
    const decoded=this.tokenizer.batch_decode(output,{skip_special_tokens:true})[0] ?? '';
    const marker='Answer:';
    const answer=String(decoded).includes(marker)?String(decoded).split(marker).slice(1).join(marker).trim():String(decoded).trim();
    return {schema:'xavi-local-moondream-onnx/v1',modelId:this.modelId,modelPath:this.model,dtype:this.dtype,device:this.device,question,answer,elapsedMs:Math.max(0,performance.now()-started)};
  }
  async dispose(){if(this.modelRuntime?.dispose)await this.modelRuntime.dispose();this.modelRuntime=null;this.tokenizer=null;this.processor=null;}
}

export async function registerLocalTransformersMathObserver(xavi,{prior=0,retainOutput=false,timeoutMs=90000,model='models/onnx/qwen2.5-math-1.5b-instruct',dtype='q8',device='cpu',metadata={}}={}){
  if(!xavi?.observers)throw new TypeError('XaviBrowser observer registry required');
  const spec=SPECIALIST_OBSERVER_CATALOG['qwen2.5-math-1.5b-instruct'];
  const runtime=await new LocalTransformersTextGenerator({model,modelId:spec.modelId,dtype,device}).init();
  xavi.addDisposable?.(runtime);
  const descriptor=xavi.observers.register({
    id:'local-qwen2.5-math-1.5b-instruct-onnx',modelId:spec.modelId,revision:QWEN_MATH_ONNX_REVISION,license:spec.license,
    runtime:'transformers.js-onnx',capabilities:spec.capabilities,modalities:spec.modalities,prior,retainOutput,timeoutMs,
    metadata:{standalone:true,costClass:spec.costClass,modalities:spec.modalities,backend:'onnx',sourceRepository:'onnx-community/Qwen2.5-Math-1.5B-Instruct',sourceRevision:QWEN_MATH_ONNX_REVISION,dtype,device,...metadata},
    run:(context,options)=>runtime.generate(context,options),
  });
  return {descriptor,runtime};
}

export async function registerLocalMoondreamObserver(xavi,{prior=0,retainOutput=false,timeoutMs=120000,model='models/onnx/moondream2',device='cpu',metadata={}}={}){
  if(!xavi?.observers)throw new TypeError('XaviBrowser observer registry required');
  const spec=SPECIALIST_OBSERVER_CATALOG.moondream2;
  const runtime=await new LocalMoondreamOnnxObserver({model,modelId:spec.modelId,device}).init();
  xavi.addDisposable?.(runtime);
  const capabilities=['vision:caption','vision:query'];
  const descriptor=xavi.observers.register({
    id:'local-moondream2-onnx',modelId:spec.modelId,revision:MOONDREAM_ONNX_REVISION,license:spec.license,
    runtime:'transformers.js-onnx',capabilities,modalities:spec.modalities,prior,retainOutput,timeoutMs,
    metadata:{standalone:true,costClass:spec.costClass,modalities:spec.modalities,backend:'onnx',sourceRepository:'Xenova/moondream2',sourceRevision:MOONDREAM_ONNX_REVISION,dtype:runtime.dtype,device,imageTokenCount:runtime.imageTokenCount,...metadata},
    run:(context,options)=>runtime.observe(context,options),
  });
  return {descriptor,runtime};
}

export const LOCAL_TRANSFORMERS_REVISIONS=Object.freeze({qwenMath:QWEN_MATH_ONNX_REVISION,moondream:MOONDREAM_ONNX_REVISION});
