export const SMALL_MODEL_RUNTIME_SCHEMA='xavi-small-model-runtime/v1';

const uniq=values=>[...new Set((Array.isArray(values)?values:values==null?[]:[values]).map(String).map(x=>x.trim()).filter(Boolean))].slice(0,24);
const text=(value,max=256)=>value==null?null:String(value).slice(0,max);
const positive=value=>Number.isFinite(Number(value))&&Number(value)>0?Number(value):null;

function backendFrom(value='external'){
  const v=String(value||'external').toLowerCase();
  if(v.includes('llama.cpp')||v.includes('gguf'))return'llama.cpp/gguf';
  if(v.includes('ctranslate'))return'ctranslate2';
  if(v.includes('transformers')||v.includes('onnx'))return'transformers.js/onnx';
  if(v.includes('tesseract'))return'tesseract';
  if(v.includes('cheerio'))return'cheerio';
  return text(value||'external',96);
}
function environmentFor(backend,input={}){
  if(input.environment)return text(input.environment,32);
  if(['llama.cpp/gguf','ctranslate2','tesseract'].includes(backend))return'native';
  if(['transformers.js/onnx','cheerio'].includes(backend))return'portable';
  return input.local===true?'native':'external';
}
function executionFor(backend,input={}){
  if(input.execution)return text(input.execution,32);
  if(['llama.cpp/gguf','ctranslate2','tesseract'].includes(backend))return'native-process';
  if(['transformers.js/onnx','cheerio'].includes(backend))return'in-process';
  return'external';
}
function kindFor(input={}){
  if(input.kind)return text(input.kind,32);
  if(input.dimensions!=null||input.semantic===true&&!(input.capabilities||[]).length)return'embedding';
  if(input.deterministic===true)return'deterministic';
  const caps=uniq(input.capabilities).map(x=>x.toLowerCase()),mods=uniq(input.modalities).map(x=>x.toLowerCase());
  if(caps.some(x=>x.startsWith('math:')))return'math';
  if(caps.some(x=>x.startsWith('vision:'))||mods.includes('image'))return'vision';
  if(caps.some(x=>x.startsWith('code:')))return'generation';
  if(String(input.backend||input.runtime||'').toLowerCase().includes('ctranslate'))return'generation';
  return'observer';
}

export function normalizeSmallModelRuntimeDescriptor(input={},overrides={}){
  const x={...(input||{}),...(overrides||{})};
  const backend=backendFrom(x.backend||x.runtime);
  const capabilities=uniq(x.capabilities),modalities=uniq(x.modalities);
  const descriptor={
    schema:SMALL_MODEL_RUNTIME_SCHEMA,
    id:text(x.runtimeId||x.id||`${kindFor(x)}:${backend}:${x.modelId||x.model||'runtime'}`,192),
    kind:kindFor(x),backend,
    runtime:text(x.runtime||backend,96),modelId:text(x.modelId||x.model||x.id||'unknown',256),revision:text(x.revision||'',128),
    license:text(x.license||'unknown',64),role:text(x.role||x.evidenceClass||'',64),environment:environmentFor(backend,x),execution:executionFor(backend,x),
    modalities,capabilities,costClass:text(x.costClass||'',32),dimensions:positive(x.dimensions),dtype:text(x.dtype||'',32),device:text(x.device||'',32),
    offline:x.offline!=null?Boolean(x.offline):x.networkRequired!=null?!Boolean(x.networkRequired):(backend!=='external'&&environmentFor(backend,x)!=='external'),deterministic:Boolean(x.deterministic),optionalNative:Boolean(x.optionalNative),authority:false,
  };
  return Object.freeze(descriptor);
}

export function smallModelRuntimeFromEmbeddingProfile(profile={},overrides={}){
  return normalizeSmallModelRuntimeDescriptor(profile,{kind:'embedding',offline:true,modalities:['text'],capabilities:['embedding:text'],costClass:profile.costClass||'low',...overrides});
}

export function smallModelRuntimeFromObserver(observer={},overrides={}){
  const metadata=observer.metadata||{};
  return normalizeSmallModelRuntimeDescriptor(observer,{...metadata,modelId:observer.modelId,revision:observer.revision,license:observer.license,runtime:observer.runtime,capabilities:observer.capabilities,modalities:observer.modalities,costClass:metadata.costClass||observer.costClass,deterministic:metadata.deterministic,networkRequired:metadata.networkRequired,role:metadata.role||metadata.evidenceClass,...overrides});
}
