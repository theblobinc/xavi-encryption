import { SandboxPolicy } from './policy.js';

function asBytes(source){
  if(source instanceof Uint8Array)return source;
  if(source instanceof ArrayBuffer)return new Uint8Array(source);
  if(ArrayBuffer.isView(source))return new Uint8Array(source.buffer,source.byteOffset,source.byteLength);
  throw new TypeError('native wasm source must be Uint8Array, ArrayBuffer, or ArrayBuffer view');
}
function finiteArgs(args){
  if(!Array.isArray(args))throw new TypeError('wasm args must be an array');
  return args.map(v=>{if(typeof v==='bigint')return v;const n=Number(v);if(!Number.isFinite(n))throw new TypeError('wasm numeric args must be finite');return n;});
}

/**
 * Execute a first-party WebAssembly module with zero host imports.
 * This is deliberately narrow: no DOM, network, filesystem, clock, randomness or JS callbacks.
 * Modules needing richer host facilities belong behind Worker RPC or the container2wasm bridge.
 */
export function createNativeWasmExecutor({bytes,exportName='run',allowedExports=[exportName],policy=new SandboxPolicy({network:'none',filesystem:'none'}),imports=null}={}){
  const source=asBytes(bytes);
  const fixed=policy instanceof SandboxPolicy?policy:new SandboxPolicy(policy);
  const allow=new Set((allowedExports||[]).map(String));
  if(imports && Object.keys(imports).length)throw new Error('native wasm imports are disabled; use a registered sandbox bridge for host capabilities');
  if(fixed.network!=='none'||fixed.filesystem!=='none'||fixed.allowStdin)throw new Error('native wasm executor only supports no-network/no-filesystem/no-stdin policy');
  let instancePromise=null;
  const instantiate=async()=>{
    if(!instancePromise)instancePromise=WebAssembly.instantiate(source,{}).then(result=>result.instance||result);
    return instancePromise;
  };
  return async function run(context={}){
    const name=String(context.exportName||exportName);
    if(!allow.has(name))throw new Error(`wasm export not allowed: ${name}`);
    const instance=await instantiate();
    const fn=instance.exports?.[name];
    if(typeof fn!=='function')throw new Error(`wasm export unavailable: ${name}`);
    const value=fn(...finiteArgs(context.args||[]));
    return {exportName:name,value};
  };
}
