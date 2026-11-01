import { featurize } from '../core/utils.js';

function toFloat32(values, dimensions = null) {
  const arr = values instanceof Float32Array ? new Float32Array(values) : Float32Array.from(values || [], Number);
  if (dimensions != null && arr.length !== dimensions) throw new TypeError(`embedding dimension mismatch: expected ${dimensions}, got ${arr.length}`);
  for (const value of arr) if (!Number.isFinite(value)) throw new TypeError('embedding contains non-finite value');
  return arr;
}

export class HashFeatureEmbedder {
  constructor({dimensions=64,id='xavi-hash-feature-v1'}={}) {
    this.id=String(id); this.dimensions=Math.max(8,Number(dimensions)||64); this.runtime='pure-js'; this.license='MIT OR Apache-2.0';
  }
  async embed(text, context={}) { return toFloat32(featurize({text:String(text??''),...context},this.dimensions),this.dimensions); }
  describe(){return{id:this.id,dimensions:this.dimensions,runtime:this.runtime,license:this.license,semantic:false};}
}

export class FunctionEmbedder {
  constructor({id='external-embedder',dimensions,runtime='local',license='MIT OR Apache-2.0',embed,metadata={}}={}) {
    if(!Number.isInteger(dimensions)||dimensions<1)throw new TypeError('embedder dimensions required');
    if(typeof embed!=='function')throw new TypeError('embedder embed(text, context) required');
    this.id=String(id);this.dimensions=dimensions;this.runtime=String(runtime);this.license=String(license);this.fn=embed;this.metadata=Object.freeze({...metadata});
  }
  async embed(text,context={}){return toFloat32(await this.fn(String(text??''),context),this.dimensions);}
  describe(){return{id:this.id,dimensions:this.dimensions,runtime:this.runtime,license:this.license,semantic:true,metadata:{...this.metadata}};}
}

export { toFloat32 as normalizeEmbeddingInput };
