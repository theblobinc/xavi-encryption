export { WitnessVectorStore, normalizeVector, cosineNormalized } from './witness-vector-store.js';
export { HashFeatureEmbedder, FunctionEmbedder, normalizeEmbeddingInput } from './embeddings.js';
export { HnswIndex } from './hnsw-index.js';
export { HnswWitnessVectorStore } from './hnsw-witness-store.js';
export { ShardedWitnessVectorStore } from './sharded-witness-store.js';
export { TransformersJsEmbedder } from './transformers-embedder.js';

export { DEFAULT_SEMANTIC_EMBEDDING_PROFILE, FAST_SEMANTIC_EMBEDDING_PROFILE, SEMANTIC_EMBEDDING_PROFILES, semanticEmbeddingProfile } from './embedding-profiles.js';
