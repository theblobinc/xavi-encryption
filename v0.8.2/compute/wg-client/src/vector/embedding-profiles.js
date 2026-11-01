export const DEFAULT_SEMANTIC_EMBEDDING_PROFILE='minilm-l12-v2-q8';
export const FAST_SEMANTIC_EMBEDDING_PROFILE='bge-micro-v2-q8';

export const SEMANTIC_EMBEDDING_PROFILES=Object.freeze({
  'minilm-l12-v2-q8':Object.freeze({
    id:'minilm-l12-v2-q8',model:'models/all-minilm-l12-v2',modelId:'sentence-transformers/all-MiniLM-L12-v2',dimensions:384,dtype:'q8',license:'Apache-2.0',runtime:'transformers.js/onnx',recommendedMinScore:0.20,authority:false,
  }),
  'bge-micro-v2-q8':Object.freeze({
    id:'bge-micro-v2-q8',model:'models/bge-micro-v2',modelId:'SmartComponents/bge-micro-v2',dimensions:384,dtype:'q8',license:'MIT',runtime:'transformers.js/onnx',recommendedMinScore:0.55,weights:'onnx/model_quantized.onnx',sha256:'ed65e36025aa94cb74207dab863c85452919ec0ab7df3512092932aa22c9a33a',authority:false,
  }),
  'bge-micro-v2-q4-gguf':Object.freeze({
    id:'bge-micro-v2-q4-gguf',modelId:'mradermacher/bge-micro-v2-GGUF',dimensions:384,dtype:'Q4_K_M',license:'MIT',runtime:'llama.cpp/gguf',recommendedMinScore:0.55,optionalNative:true,authority:false,
  }),
});
export function semanticEmbeddingProfile(id=DEFAULT_SEMANTIC_EMBEDDING_PROFILE){
  const profile=SEMANTIC_EMBEDDING_PROFILES[String(id)];if(!profile)throw new Error(`unknown semantic embedding profile: ${id}`);return profile;
}
