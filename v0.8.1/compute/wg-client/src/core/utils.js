import { shake256Hex } from './crypto.js';

function stableValue(value, seen = new WeakSet(), depth = 0) {
  if (value === null) return null;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return value;
  if (type === 'number') return Number.isFinite(value) ? value : `[${String(value)}]`;
  if (type === 'bigint') return `${value}n`;
  if (type === 'undefined') return '[undefined]';
  if (type === 'function') return `[function:${value.name || 'anonymous'}]`;
  if (type === 'symbol') return `[symbol:${String(value.description || '')}]`;
  if (depth >= 6) return '[max-depth]';
  if (value instanceof Date) return value.toISOString();
  if (typeof URL !== 'undefined' && value instanceof URL) return value.href;
  if (value instanceof Error) return {name:value.name,message:value.message};
  if (ArrayBuffer.isView(value)) return {type:value.constructor?.name || 'TypedArray', length:value.length ?? value.byteLength, sample:Array.from(value).slice(0,64)};
  if (value instanceof ArrayBuffer) return {type:'ArrayBuffer',byteLength:value.byteLength};
  if (type !== 'object') return String(value);
  if (seen.has(value)) return '[circular]';
  seen.add(value);
  try {
    if (typeof value.nodeType === 'number') {
      return {type:'DOMNode',nodeType:value.nodeType,nodeName:String(value.nodeName || ''),id:String(value.id || ''),className:typeof value.className==='string'?value.className:''};
    }
    if (Array.isArray(value)) return value.slice(0,64).map(v=>stableValue(v,seen,depth+1));
    const out={};
    for (const key of Object.keys(value).sort().slice(0,64)) {
      try { out[key]=stableValue(value[key],seen,depth+1); } catch { out[key]='[unreadable]'; }
    }
    return out;
  } finally { seen.delete(value); }
}

export function canonicalize(value) { return JSON.stringify(stableValue(value)); }

const SHA256_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
const rr=(x,n)=>(x>>>n)|(x<<(32-n));
function sha256Fallback(bytes) {
  const length=bytes.length; const bitHi=Math.floor((length*8)/0x100000000); const bitLo=(length*8)>>>0;
  const total=Math.ceil((length+9)/64)*64; const data=new Uint8Array(total); data.set(bytes); data[length]=0x80;
  const dv=new DataView(data.buffer); dv.setUint32(total-8,bitHi); dv.setUint32(total-4,bitLo);
  const h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const w=new Uint32Array(64);
  for(let off=0;off<total;off+=64){
    for(let i=0;i<16;i++) w[i]=dv.getUint32(off+i*4);
    for(let i=16;i<64;i++){ const a=w[i-15],b=w[i-2]; const s0=(rr(a,7)^rr(a,18)^(a>>>3))>>>0; const s1=(rr(b,17)^rr(b,19)^(b>>>10))>>>0; w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0; }
    let [a,b,c,d,e,f,g,hh]=h;
    for(let i=0;i<64;i++){ const S1=(rr(e,6)^rr(e,11)^rr(e,25))>>>0; const ch=((e&f)^((~e)&g))>>>0; const t1=(hh+S1+ch+SHA256_K[i]+w[i])>>>0; const S0=(rr(a,2)^rr(a,13)^rr(a,22))>>>0; const maj=((a&b)^(a&c)^(b&c))>>>0; const t2=(S0+maj)>>>0; hh=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0; }
    h[0]=(h[0]+a)>>>0;h[1]=(h[1]+b)>>>0;h[2]=(h[2]+c)>>>0;h[3]=(h[3]+d)>>>0;h[4]=(h[4]+e)>>>0;h[5]=(h[5]+f)>>>0;h[6]=(h[6]+g)>>>0;h[7]=(h[7]+hh)>>>0;
  }
  return [...h].map(x=>x.toString(16).padStart(8,'0')).join('');
}

export async function digest(value) {
  const text = typeof value === 'string' ? value : canonicalize(value);
  return `shake256-512:${shake256Hex(text, 64)}`;
}

export async function legacySha256Digest(value) {
  const bytes = new TextEncoder().encode(typeof value === 'string' ? value : canonicalize(value));
  if (globalThis.crypto?.subtle?.digest) {
    const out = await crypto.subtle.digest('SHA-256', bytes);
    return `sha256:${[...new Uint8Array(out)].map(b => b.toString(16).padStart(2, '0')).join('')}`;
  }
  return `sha256:${sha256Fallback(bytes)}`;
}

export function nowMs() { return Date.now(); }
export function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
export function sigmoid(x) { return 1 / (1 + Math.exp(-clamp(x, -30, 30))); }

export function finiteVector(input, expected = null) {
  if (!input || typeof input[Symbol.iterator] !== 'function') return null;
  const vector = Array.from(input, Number);
  if (!vector.length || vector.some(v => !Number.isFinite(v))) return null;
  if (expected !== null && vector.length !== expected) return null;
  return vector;
}

export function stateHealth(input, topK = 8) {
  const vector = Array.from(input || [], Number);
  const finite = vector.length > 0 && vector.every(Number.isFinite);
  if (!finite) return {dimension: vector.length, finite: false, l2: null, linf: null, rms: null, topKRatio: null, peakRmsRatio: null};
  const squares = vector.map(v => v * v); const energy = squares.reduce((a,b)=>a+b,0); const l2=Math.sqrt(energy);
  const linf=vector.reduce((m,v)=>Math.max(m,Math.abs(v)),0); const rms=Math.sqrt(energy/vector.length);
  const top=[...squares].sort((a,b)=>b-a).slice(0,Math.max(1,topK)).reduce((a,b)=>a+b,0);
  return {dimension:vector.length,finite:true,l2,linf,rms,topKRatio:energy>0?top/energy:0,peakRmsRatio:rms>0?linf/rms:0};
}

function fnv1a(text) { let h=0x811c9dc5; for(let i=0;i<text.length;i+=1){h^=text.charCodeAt(i);h=Math.imul(h,0x01000193)>>>0;} return h>>>0; }
function flatten(value,prefix='',out=[],seen=new WeakSet(),depth=0) {
  if(depth>5){out.push(`${prefix}=[max-depth]`);return out;}
  if(value===null||value===undefined){out.push(`${prefix}=null`);return out;}
  if(typeof value==='object'){
    if(seen.has(value)){out.push(`${prefix}=[circular]`);return out;} seen.add(value);
    try {
      if(typeof value.nodeType==='number'){out.push(`${prefix}.node=${value.nodeName||''}#${value.id||''}`);return out;}
      if(Array.isArray(value)||ArrayBuffer.isView(value)){Array.from(value).slice(0,32).forEach((v,i)=>flatten(v,`${prefix}[${i}]`,out,seen,depth+1));return out;}
      Object.keys(value).sort().slice(0,64).forEach(k=>{try{flatten(value[k],prefix?`${prefix}.${k}`:k,out,seen,depth+1);}catch{out.push(`${prefix}.${k}=[unreadable]`);}}); return out;
    } finally { seen.delete(value); }
  }
  out.push(`${prefix}=${String(value).slice(0,256)}`); return out;
}
export function featureTokens(value){ return flatten(value); }
export function hashFeatureTokens(tokens=[]){ const out=new Uint32Array(tokens.length); for(let i=0;i<tokens.length;i+=1)out[i]=fnv1a(tokens[i]); return out; }
export function featureResidues(hashes=[]){ let a=1,b=1; for(const raw of hashes){const h=Number(raw)>>>0;a=(a+(h%65521))%65521;b=(b+Math.imul(h&0xffff,(h>>>16)||1))%65519;} return [a,b,hashes.length]; }
export function featurizeFeatureHashes(hashes,dim=32){ const v=new Float64Array(dim); for(const raw of hashes){const h=Number(raw)>>>0;v[h%dim]+=(h&0x80000000)?-1:1;} const norm=Math.hypot(...v); if(norm>0)for(let i=0;i<v.length;i+=1)v[i]/=norm; return v; }
export function featurize(value,dim=32) { return featurizeFeatureHashes(hashFeatureTokens(featureTokens(value)),dim); }
export function dot(a,b){const n=Math.min(a.length,b.length);let x=0;for(let i=0;i<n;i+=1)x+=a[i]*b[i];return x;}
export function randomId(prefix='xavi'){const bytes=new Uint8Array(12);if(globalThis.crypto?.getRandomValues)crypto.getRandomValues(bytes);else for(let i=0;i<bytes.length;i+=1)bytes[i]=Math.floor(Math.random()*256);return `${prefix}:${[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('')}`;}
