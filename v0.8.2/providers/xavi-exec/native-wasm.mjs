function asBytes(source){
  if(source instanceof Uint8Array)return source;
  if(source instanceof ArrayBuffer)return new Uint8Array(source);
  if(ArrayBuffer.isView(source))return new Uint8Array(source.buffer,source.byteOffset,source.byteLength);
  throw new TypeError('native wasm source must be bytes');
}
function finiteArgs(args){if(!Array.isArray(args))throw new TypeError('wasm args must be an array');return args.map(v=>{if(typeof v==='bigint')return v;const n=Number(v);if(!Number.isFinite(n))throw new TypeError('wasm numeric args must be finite');return n;});}
export function createNativeWasmExecutor({bytes,exportName='run',allowedExports=[exportName],imports=null}={}){
  const source=asBytes(bytes),allow=new Set((allowedExports||[]).map(String));
  if(imports&&Object.keys(imports).length)throw new Error('native wasm imports are disabled; use Worker RPC capability bridge');
  let instancePromise=null;
  return async function run(context={}){
    const name=String(context.exportName||exportName);if(!allow.has(name))throw new Error(`wasm export not allowed: ${name}`);
    if(!instancePromise)instancePromise=WebAssembly.instantiate(source,{}).then(r=>r.instance||r);
    const instance=await instancePromise,fn=instance.exports?.[name];if(typeof fn!=='function')throw new Error(`wasm export unavailable: ${name}`);
    return Object.freeze({exportName:name,value:fn(...finiteArgs(context.args||[])),authority:false,hostImports:false});
  };
}
