export const SPECIALIST_OBSERVER_CATALOG = Object.freeze({
  'qwen2.5-math-1.5b-instruct': Object.freeze({
    modelId: 'Qwen/Qwen2.5-Math-1.5B-Instruct',
    license: 'Apache-2.0',
    role: 'math-evidence',
    modalities: Object.freeze(['text']),
    capabilities: Object.freeze(['math:reason', 'math:verify', 'math:tool-plan']),
    requirePinnedRevision: true,
    costClass: 'high',
  }),
  'qwen2.5-coder-0.5b-instruct': Object.freeze({
    modelId: 'Qwen/Qwen2.5-Coder-0.5B-Instruct',
    license: 'Apache-2.0',
    role: 'code-evidence',
    modalities: Object.freeze(['text', 'code']),
    capabilities: Object.freeze(['code:explain', 'code:review', 'code:generate', 'code:repair']),
    requirePinnedRevision: true,
    costClass: 'medium',
  }),
  'moondream2': Object.freeze({
    modelId: 'vikhyatk/moondream2',
    license: 'Apache-2.0',
    role: 'vision-evidence',
    modalities: Object.freeze(['image', 'text']),
    capabilities: Object.freeze(['vision:caption', 'vision:query', 'vision:detect', 'vision:point']),
    requirePinnedRevision: true,
    costClass: 'high',
  }),
});

export const OBSERVER_RUNTIME_CATALOG = Object.freeze({
  'transformers.js': Object.freeze({
    project: 'huggingface/transformers.js',
    license: 'Apache-2.0',
    environment: 'browser',
    backends: Object.freeze(['WASM', 'WebGPU']),
    role: 'browser-model-runtime',
  }),
  'ctranslate2': Object.freeze({
    project: 'OpenNMT/CTranslate2',
    license: 'MIT',
    environment: 'native',
    backends: Object.freeze(['CPU', 'CUDA']),
    role: 'efficient-server-model-runtime',
  }),
});

export const CURRICULUM_SOURCE_CATALOG = Object.freeze({
  'ossu-computer-science': Object.freeze({
    project: 'ossu/computer-science',
    license: 'MIT',
    role: 'curriculum-index',
    note: 'Repository metadata/curriculum is MIT; independently linked course and book content requires its own source-license check before ingestion.',
  }),
});


export const DETERMINISTIC_OBSERVER_CATALOG = Object.freeze({
  cheerio: Object.freeze({
    project: 'cheeriojs/cheerio',
    version: '1.2.0',
    license: 'MIT',
    role: 'html-dom-evidence',
    modalities: Object.freeze(['html', 'xml', 'text']),
    capabilities: Object.freeze(['html:extract', 'html:structure', 'html:metadata', 'html:links', 'html:query']),
    deterministic: true,
    costClass: 'very-low',
    networkRequired: false,
  }),
  tesseract: Object.freeze({
    project: 'tesseract-ocr/tesseract',
    version: '5.5.3',
    license: 'Apache-2.0',
    role: 'ocr-evidence',
    modalities: Object.freeze(['image', 'document', 'text']),
    capabilities: Object.freeze(['image:ocr', 'document:ocr', 'vision:text', 'vision:ocr']),
    deterministic: true,
    costClass: 'low',
    networkRequired: false,
    dependencyNote: 'Uses Leptonica (BSD-2-Clause) and Apache-2.0 tessdata language models.',
  }),
});
