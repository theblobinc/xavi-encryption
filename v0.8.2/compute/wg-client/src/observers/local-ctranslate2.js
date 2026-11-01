import { spawn } from 'node:child_process';
import { access, readFile, stat } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SPECIALIST_OBSERVER_CATALOG } from './catalog.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TRANSFORMERS_MODULE = '../../vendor/transformers.js/packages/transformers/dist/transformers.node.mjs';
const DEFAULT_BINARY = resolve(PROJECT_ROOT, 'runtime/local/ctranslate2/bin/xavi-ct2-generator');

function clampNumber(value, fallback, lo, hi) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : fallback;
}

function writeU32(value) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32LE(Number(value) >>> 0, 0);
  return b;
}
function writeF32(value) {
  const b = Buffer.allocUnsafe(4);
  b.writeFloatLE(Number(value), 0);
  return b;
}
function encodeString(value) {
  const s = Buffer.from(String(value), 'utf8');
  if (s.length > 16 * 1024 * 1024) throw new RangeError('generator token exceeds 16 MiB');
  return Buffer.concat([writeU32(s.length), s]);
}

export function encodeGeneratorRequest(tokens, { maxLength = 256, topK = 1, temperature = 1, topP = 1 } = {}) {
  if (!Array.isArray(tokens) || tokens.length < 1) throw new TypeError('generator requires prompt tokens');
  if (tokens.length > 262144) throw new RangeError('generator prompt token limit exceeded');
  return Buffer.concat([
    Buffer.from('XCT2'), writeU32(1), writeU32(tokens.length),
    ...tokens.map(encodeString),
    writeU32(Math.floor(clampNumber(maxLength, 256, 1, 8192))),
    writeU32(Math.floor(clampNumber(topK, 1, 1, 1000))),
    writeF32(clampNumber(temperature, 1, 0.01, 10)),
    writeF32(clampNumber(topP, 1, 0.01, 1)),
  ]);
}

export function decodeGeneratorResponse(buffer) {
  const b = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  let offset = 0;
  const need = n => { if (offset + n > b.length) throw new Error('truncated XCT2 response'); };
  need(12);
  if (b.subarray(0, 4).toString('ascii') !== 'XCT2') throw new Error('invalid XCT2 response magic');
  offset = 4;
  const version = b.readUInt32LE(offset); offset += 4;
  if (version !== 1) throw new Error(`unsupported XCT2 response version ${version}`);
  const count = b.readUInt32LE(offset); offset += 4;
  if (count > 262144) throw new Error('invalid XCT2 response token count');
  const tokens = [];
  for (let i = 0; i < count; i += 1) {
    need(4); const size = b.readUInt32LE(offset); offset += 4;
    if (size > 16 * 1024 * 1024) throw new Error('invalid XCT2 response token size');
    need(size); tokens.push(b.subarray(offset, offset + size).toString('utf8')); offset += size;
  }
  if (offset !== b.length) throw new Error('trailing bytes in XCT2 response');
  return tokens;
}

function normalizeMessages(context = {}, defaultSystem = '') {
  if (Array.isArray(context.messages) && context.messages.length) {
    return context.messages.map(m => ({ role: String(m.role || 'user'), content: String(m.content ?? '') }));
  }
  const prompt = context.prompt ?? context.text ?? context.code ?? context.question ?? context.input ?? '';
  const messages = [];
  const system = context.system ?? defaultSystem;
  if (system) messages.push({ role: 'system', content: String(system) });
  messages.push({ role: 'user', content: typeof prompt === 'string' ? prompt : JSON.stringify(prompt) });
  return messages;
}

async function defaultModuleLoader() { return import(TRANSFORMERS_MODULE); }

export class LocalCTranslate2Generator {
  constructor({
    modelDir,
    tokenizerDir = null,
    binary = DEFAULT_BINARY,
    modelId = '',
    threads = 4,
    defaultSystem = '',
    moduleLoader = defaultModuleLoader,
    projectRoot = PROJECT_ROOT,
    maxOutputBytes = 8 * 1024 * 1024,
  } = {}) {
    if (!modelDir) throw new TypeError('modelDir required');
    this.projectRoot = projectRoot;
    this.modelDir = resolve(projectRoot, modelDir);
    this.tokenizerDir = tokenizerDir ? resolve(projectRoot, tokenizerDir) : this.modelDir;
    this.binary = resolve(projectRoot, binary);
    this.modelId = String(modelId || '');
    this.threads = Math.max(1, Math.min(128, Number(threads) || 4));
    this.defaultSystem = String(defaultSystem || '');
    this.moduleLoader = moduleLoader;
    this.maxOutputBytes = Math.max(1024, Number(maxOutputBytes) || 8 * 1024 * 1024);
    this.tokenizer = null;
    this.idToToken = null;
  }

  async init() {
    await access(this.binary, fsConstants.X_OK);
    const modelStat = await stat(this.modelDir).catch(() => null);
    if (!modelStat?.isDirectory()) throw new Error(`CTranslate2 model directory missing: ${this.modelDir}`);
    const { env, AutoTokenizer } = await this.moduleLoader();
    env.allowRemoteModels = false;
    env.allowLocalModels = true;
    env.localModelPath = this.projectRoot.endsWith('/') ? this.projectRoot : `${this.projectRoot}/`;
    let tokenizerName = this.tokenizerDir;
    if (this.tokenizerDir.startsWith(this.projectRoot)) tokenizerName = this.tokenizerDir.slice(this.projectRoot.length).replace(/^\/+/, '');
    this.tokenizer = await AutoTokenizer.from_pretrained(tokenizerName, { local_files_only: true });
    this.idToToken = [];
    for (const [token, id] of this.tokenizer.get_vocab()) this.idToToken[Number(id)] = token;
    return this;
  }

  tokenize(context = {}) {
    if (!this.tokenizer || !this.idToToken) throw new Error('LocalCTranslate2Generator not initialized');
    const messages = normalizeMessages(context, this.defaultSystem);
    const encoded = this.tokenizer.apply_chat_template(messages, {
      tokenize: true,
      add_generation_prompt: true,
      return_tensor: false,
    });
    const ids = encoded?.input_ids;
    if (!Array.isArray(ids) || !ids.length) throw new Error('tokenizer returned no input_ids');
    const missing = ids.find(id => this.idToToken[Number(id)] === undefined);
    if (missing !== undefined) throw new Error(`tokenizer id ${missing} has no token-string mapping`);
    return { messages, ids: ids.map(Number), tokens: ids.map(id => this.idToToken[Number(id)]) };
  }

  decode(tokens) {
    if (!this.tokenizer) throw new Error('LocalCTranslate2Generator not initialized');
    const ids = this.tokenizer.convert_tokens_to_ids(tokens);
    if (!Array.isArray(ids) || ids.some(id => id === null || id === undefined || Number(id) < 0)) {
      throw new Error('generator returned token unknown to tokenizer');
    }
    return this.tokenizer.decode(ids.map(Number), { skip_special_tokens: true }).trim();
  }

  async _invoke(request, { signal = null } = {}) {
    return new Promise((resolvePromise, reject) => {
      const child = spawn(this.binary, [this.modelDir, String(this.threads)], { stdio: ['pipe', 'pipe', 'pipe'] });
      const out = []; const err = []; let outBytes = 0; let settled = false;
      const finish = (fn, value) => { if (settled) return; settled = true; signal?.removeEventListener?.('abort', onAbort); fn(value); };
      const onAbort = () => { child.kill('SIGTERM'); finish(reject, new Error('CTranslate2 generation aborted')); };
      if (signal?.aborted) return onAbort();
      signal?.addEventListener?.('abort', onAbort, { once: true });
      child.stdout.on('data', chunk => {
        outBytes += chunk.length;
        if (outBytes > this.maxOutputBytes) { child.kill('SIGTERM'); finish(reject, new Error('CTranslate2 output exceeded limit')); return; }
        out.push(chunk);
      });
      child.stderr.on('data', chunk => { if (err.reduce((n, x) => n + x.length, 0) < 65536) err.push(chunk); });
      child.on('error', error => finish(reject, error));
      child.on('close', code => {
        if (settled) return;
        if (code !== 0) return finish(reject, new Error(`CTranslate2 generator exited ${code}: ${Buffer.concat(err).toString('utf8').slice(0, 4000)}`));
        finish(resolvePromise, Buffer.concat(out));
      });
      child.stdin.on('error', error => finish(reject, error));
      child.stdin.end(request);
    });
  }

  async generate(context = {}, options = {}) {
    if (!this.tokenizer) await this.init();
    const prompt = this.tokenize(context);
    const generation = {
      maxLength: options.maxTokens ?? context.maxTokens ?? 256,
      topK: options.topK ?? context.topK ?? 1,
      temperature: options.temperature ?? context.temperature ?? 1,
      topP: options.topP ?? context.topP ?? 1,
    };
    const response = await this._invoke(encodeGeneratorRequest(prompt.tokens, generation), { signal: options.signal });
    const outputTokens = decodeGeneratorResponse(response);
    return {
      schema: 'xavi-local-ctranslate2-result/v1',
      modelId: this.modelId,
      runtime: 'ctranslate2-local',
      promptTokens: prompt.tokens.length,
      generatedTokens: outputTokens.length,
      text: this.decode(outputTokens),
    };
  }
}

export async function registerLocalCTranslate2Observer(xavi, {
  catalogKey,
  modelDir,
  tokenizerDir,
  binary = DEFAULT_BINARY,
  revision = '',
  threads = 4,
  prior = 0,
  retainOutput = false,
  defaultSystem = '',
  metadata = {},
} = {}) {
  const spec = SPECIALIST_OBSERVER_CATALOG[catalogKey];
  if (!spec) throw new Error(`unknown specialist catalog key: ${catalogKey}`);
  const runner = await new LocalCTranslate2Generator({
    modelDir, tokenizerDir, binary, modelId: spec.modelId, threads, defaultSystem,
  }).init();
  const descriptor = xavi.observers.register({
    id: `local-${catalogKey}`,
    modelId: spec.modelId,
    revision,
    license: spec.license,
    runtime: 'ctranslate2-local',
    capabilities: spec.capabilities,
    modalities: spec.modalities,
    prior,
    retainOutput,
    metadata: { local: true, catalogKey, modelDir, tokenizerDir, costClass: spec.costClass, modalities: spec.modalities, ...metadata },
    run: (context, runtimeOptions = {}) => runner.generate(context, runtimeOptions),
  });
  return { descriptor, runner };
}
