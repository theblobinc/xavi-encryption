import { XaviBrowser } from '../index.js';
import { NodeFileStore } from '../storage/node-file-store.js';
import { ShardedWitnessVectorStore } from '../vector/sharded-witness-store.js';
import { HashFeatureEmbedder } from '../vector/embeddings.js';
import { TransformersJsEmbedder } from '../vector/transformers-embedder.js';
import { LlamaCppEmbedder } from '../vector/llama-cpp-embedder.js';
import { semanticEmbeddingProfile, DEFAULT_SEMANTIC_EMBEDDING_PROFILE } from '../vector/embedding-profiles.js';
import { registerLocalCTranslate2Observer } from '../observers/local-ctranslate2.js';
import { registerLocalTransformersMathObserver, registerLocalMoondreamObserver } from '../observers/local-transformers.js';
import { registerCheerioObserver } from '../observers/local-cheerio.js';
import { registerTesseractObserver } from '../observers/local-tesseract.js';
import { MediaTriageService } from '../media/complexity.js';
import { access } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const PROJECT_ROOT=fileURLToPath(new URL('../../',import.meta.url));
const loadVendoredTransformers=()=>import('../../vendor/transformers.js/packages/transformers/dist/transformers.node.mjs');

export const STANDALONE_CT2_SPECIALISTS = Object.freeze([
  Object.freeze({
    catalogKey:'qwen2.5-coder-0.5b-instruct',
    modelDir:'models/ct2/qwen2.5-coder-0.5b-instruct',
    tokenizerDir:'models/qwen2.5-coder-0.5b-instruct',
    revision:'ct2-int8-local',
    defaultSystem:'You are a coding evidence observer. Report evidence concisely and do not claim authority.',
  }),
  Object.freeze({
    catalogKey:'qwen2.5-math-1.5b-instruct',
    modelDir:'models/ct2/qwen2.5-math-1.5b-instruct',
    tokenizerDir:'models/qwen2.5-math-1.5b-instruct',
    revision:'ct2-int8-local',
    defaultSystem:'You are a mathematical evidence observer. Show useful reasoning evidence but do not claim authority.',
  }),
]);

export const STANDALONE_DEFAULT_CT2_SPECIALISTS = Object.freeze([STANDALONE_CT2_SPECIALISTS[0]]);

async function readable(path) {
  try { await access(path, fsConstants.R_OK); return true; } catch { return false; }
}

export async function createStandaloneSemanticEmbedder({profile=DEFAULT_SEMANTIC_EMBEDDING_PROFILE,model=null,modelId=null,dimensions=null,dtype=null,device='cpu',license=null,nativeBinary=null,nativeThreads=null,nativeTimeoutMs=30000,nativeArgs=[]}={}){
  const spec=semanticEmbeddingProfile(profile);
  if(spec.optionalNative){
    const nativeModel=model||process.env.XAVI_GGUF_EMBEDDING_MODEL||null;
    if(!nativeModel) throw new Error(`embedding profile ${profile} requires a GGUF model path via model or XAVI_GGUF_EMBEDDING_MODEL`);
    const embedder=new LlamaCppEmbedder({binary:nativeBinary||process.env.XAVI_LLAMA_EMBEDDING_BIN||'llama-embedding',model:nativeModel,modelId:modelId||spec.modelId,dimensions:dimensions||spec.dimensions,threads:nativeThreads,timeoutMs:nativeTimeoutMs,license:license||spec.license,extraArgs:nativeArgs});
    await embedder.init();return embedder;
  }
  const embedder=new TransformersJsEmbedder({moduleLoader:loadVendoredTransformers,model:model||spec.model,modelId:modelId||spec.modelId,dimensions:dimensions||spec.dimensions,dtype:dtype||spec.dtype,device,localModelPath:PROJECT_ROOT,license:license||spec.license});
  await embedder.init();
  return embedder;
}


export async function registerStandaloneCheapObservers(xavi,{cheerio=true,tesseract=true,prior=0,retainOutput=false}={}){
  const registered=[];const skipped=[];
  if(cheerio){const row=registerCheerioObserver(xavi,{prior,retainOutput,metadata:{standalone:true,shortTerm:true}});registered.push(row.descriptor);}
  if(tesseract){
    const binary=resolve(PROJECT_ROOT,'runtime/local/tesseract/bin/tesseract');
    if(await readable(binary)){const row=registerTesseractObserver(xavi,{prior,retainOutput,metadata:{standalone:true,shortTerm:true}});registered.push(row.descriptor);}
    else skipped.push({catalogKey:'tesseract',reason:'local-binary-unavailable'});
  }
  const current=xavi.localObservers||{registered:[],skipped:[]};xavi.localObservers={registered:[...current.registered,...registered],skipped:[...current.skipped,...skipped]};return{registered,skipped};
}

export async function registerStandaloneLocalObservers(xavi,{specialists=STANDALONE_DEFAULT_CT2_SPECIALISTS,threads=4,prior=0,retainOutput=false,strict=false}={}){
  const registered=[];
  const skipped=[];
  for(const spec of specialists){
    const modelBin=resolve(PROJECT_ROOT,spec.modelDir,'model.bin');
    const tokenizer=resolve(PROJECT_ROOT,spec.tokenizerDir,'tokenizer.json');
    if(!await readable(modelBin)||!await readable(tokenizer)){
      const row={catalogKey:spec.catalogKey,reason:'local-artifacts-unavailable',modelDir:spec.modelDir,tokenizerDir:spec.tokenizerDir};
      if(strict) throw new Error(`standalone specialist unavailable: ${spec.catalogKey}`);
      skipped.push(row);
      continue;
    }
    const observer=await registerLocalCTranslate2Observer(xavi,{...spec,threads,prior,retainOutput,metadata:{standalone:true}});
    registered.push(observer.descriptor);
  }
  const current=xavi.localObservers || {registered:[],skipped:[]};
  xavi.localObservers={registered:[...current.registered,...registered],skipped:[...current.skipped,...skipped]};
  return {registered,skipped};
}

export async function registerStandaloneOnnxObservers(xavi,{math=true,vision=true,prior=0,retainOutput=false}={}){
  const registered=[];const skipped=[];
  if(math){
    const graph=resolve(PROJECT_ROOT,'models/onnx/qwen2.5-math-1.5b-instruct/onnx/model_quantized.onnx');
    if(await readable(graph)){const row=await registerLocalTransformersMathObserver(xavi,{prior,retainOutput});registered.push(row.descriptor);}else skipped.push({catalogKey:'qwen2.5-math-1.5b-instruct',reason:'local-onnx-artifacts-unavailable'});
  }
  if(vision){
    const graph=resolve(PROJECT_ROOT,'models/onnx/moondream2/onnx/decoder_model_merged_q4.onnx');
    if(await readable(graph)){const row=await registerLocalMoondreamObserver(xavi,{prior,retainOutput});registered.push(row.descriptor);}else skipped.push({catalogKey:'moondream2',reason:'local-onnx-artifacts-unavailable'});
  }
  const current=xavi.localObservers || {registered:[],skipped:[]};
  xavi.localObservers={registered:[...current.registered,...registered],skipped:[...current.skipped,...skipped]};
  return {registered,skipped};
}

export async function createStandaloneRuntime({root='runtime/data',namespace='standalone',stateDim=256,featureDim=32,vectorDim=384,vectorShards=8,embedder=null,semantic=true,allowHashFallback=true,defaultTimeoutMs=30000,cheapObservers='auto',cheapObserverPrior=0,localObservers='auto',localObserverThreads=4,localObserverPrior=0,onnxObservers='auto',onnxObserverPrior=0,retainObserverOutput=false,mediaRoots=[process.cwd()],...options}={}){
  const store=await new NodeFileStore({root}).init();
  let actualEmbedder=embedder;
  if(!actualEmbedder&&semantic){try{actualEmbedder=await createStandaloneSemanticEmbedder({dimensions:vectorDim});}catch(error){if(!allowHashFallback)throw error;actualEmbedder=new HashFeatureEmbedder({dimensions:vectorDim,id:'xavi-hash-fallback-v1'});actualEmbedder.fallbackReason=String(error?.message||error);}}
  if(!actualEmbedder)actualEmbedder=new HashFeatureEmbedder({dimensions:vectorDim,id:'xavi-hash-bootstrap-v1'});
  const xavi=await XaviBrowser.create({...options,namespace,stateDim,featureDim,vectorDim:actualEmbedder.dimensions||vectorDim,embedder:actualEmbedder,store,defaultTimeoutMs,vectorStoreFactory:({store,namespace,dimensions})=>new ShardedWitnessVectorStore({store,namespace,dimensions,shards:vectorShards})});
  xavi.localObservers={registered:[],skipped:[]};
  xavi.media=new MediaTriageService(xavi,{allowedRoots:mediaRoots});
  if(cheapObservers){
    const cfg=typeof cheapObservers==='object' && !Array.isArray(cheapObservers)?cheapObservers:{};
    await registerStandaloneCheapObservers(xavi,{cheerio:cfg.cheerio!==false,tesseract:cfg.tesseract!==false,prior:cheapObserverPrior,retainOutput:retainObserverOutput});
  }
  if(localObservers){
    const specialists=Array.isArray(localObservers)?localObservers:(localObservers==='all'?STANDALONE_CT2_SPECIALISTS:STANDALONE_DEFAULT_CT2_SPECIALISTS);
    await registerStandaloneLocalObservers(xavi,{specialists,threads:localObserverThreads,prior:localObserverPrior,retainOutput:retainObserverOutput,strict:localObservers==='strict'});
  }
  if(onnxObservers){
    const cfg=typeof onnxObservers==='object' && !Array.isArray(onnxObservers)?onnxObservers:{};
    await registerStandaloneOnnxObservers(xavi,{math:cfg.math!==false,vision:cfg.vision!==false,prior:onnxObserverPrior,retainOutput:retainObserverOutput});
  }
  return xavi;
}
