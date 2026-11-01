import { execFile } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { normalizeSmallModelRuntimeDescriptor } from '../runtime/small-model-runtime.js';

function finiteVector(value){return Array.isArray(value)&&value.length>0&&value.every(Number.isFinite);}
function parseEmbedding(stdout){
  const text=String(stdout??'').trim();
  if(!text) throw new Error('llama.cpp embedding runtime returned empty output');
  try{
    const parsed=JSON.parse(text);
    const vector=parsed?.data?.[0]?.embedding ?? (Array.isArray(parsed?.[0])?parsed[0]:null) ?? (Array.isArray(parsed)?parsed:null);
    if(finiteVector(vector)) return vector.map(Number);
  } catch {}
  const raw=text.split(/\s+/).map(Number).filter(Number.isFinite);
  if(finiteVector(raw)) return raw;
  throw new Error('unable to parse llama.cpp embedding output');
}
function run(binary,args,options){return new Promise((resolve,reject)=>{execFile(binary,args,options,(error,stdout,stderr)=>{if(error){error.stdout=stdout;error.stderr=stderr;reject(error);return;}resolve({stdout,stderr});});});}

export class LlamaCppEmbedder {
  constructor({binary='llama-embedding',model=null,modelId='gguf-embedding-model',dimensions=384,pooling='mean',normalize=2,threads=null,timeoutMs=30000,maxBuffer=4*1024*1024,license='MIT',extraArgs=[]}={}){
    this.binary=String(binary||'llama-embedding');this.model=model?String(model):null;this.modelId=String(modelId||'gguf-embedding-model');this.dimensions=Math.max(1,Number(dimensions)||384);this.pooling=String(pooling||'mean');this.normalize=Number(normalize);this.threads=threads==null?null:Math.max(1,Number(threads)||1);this.timeoutMs=Math.max(1000,Number(timeoutMs)||30000);this.maxBuffer=Math.max(1024*1024,Number(maxBuffer)||4*1024*1024);this.license=String(license||'MIT');this.extraArgs=Array.isArray(extraArgs)?extraArgs.map(String):[];this.runtime='llama.cpp/gguf';this.id=`llama-cpp:${this.modelId}`;
  }
  async init(){if(!this.model)throw new TypeError('GGUF model path required');await access(this.model,fsConstants.R_OK);if(this.binary.includes('/'))await access(this.binary,fsConstants.X_OK);return this;}
  async embed(text,metadata={}){
    if(!this.model)throw new TypeError('GGUF model path required');
    const args=['-m',this.model,'--pooling',this.pooling,'--embd-normalize',String(Number.isFinite(this.normalize)?this.normalize:2),'--embd-output-format','json','--log-disable'];
    if(this.threads)args.push('--threads',String(this.threads));
    args.push(...this.extraArgs,'-p',String(text??''));
    const {stdout}=await run(this.binary,args,{timeout:this.timeoutMs,maxBuffer:this.maxBuffer,signal:metadata?.signal,env:{...process.env,LC_NUMERIC:'C'}});
    const vector=parseEmbedding(stdout);if(vector.length!==this.dimensions)throw new Error(`llama.cpp embedding dimension mismatch: expected ${this.dimensions}, got ${vector.length}`);return vector;
  }
  describe(){const base={id:this.id,modelId:this.modelId,modelPath:this.model,dimensions:this.dimensions,runtime:this.runtime,license:this.license,semantic:true,offline:true,binary:this.binary,pooling:this.pooling,normalize:this.normalize,authority:false};return{...base,smallModelRuntime:normalizeSmallModelRuntimeDescriptor(base,{kind:'embedding',backend:'llama.cpp/gguf',modalities:['text'],capabilities:['embedding:text'],costClass:'low',optionalNative:true,environment:'native',execution:'native-process'})};}
  async dispose(){}
}

export { parseEmbedding as parseLlamaCppEmbeddingOutput };
