import { SandboxPolicy } from './policy.js';

export function createWorkerRpcExecutor({workerUrl,workerOptions={type:'module'},policy=new SandboxPolicy(),messageType='xavi-sandbox-exec'}={}){
  if(!workerUrl)throw new TypeError('workerUrl required');
  const fixed=policy instanceof SandboxPolicy?policy:new SandboxPolicy(policy);
  return async function run(task,{signal}={}){
    const worker=new Worker(workerUrl,workerOptions);const id=`rpc:${Date.now()}:${Math.random().toString(16).slice(2)}`;
    return await new Promise((resolve,reject)=>{
      let bytes=0;let timer;
      const cleanup=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);worker.terminate();};
      const abort=()=>{cleanup();reject(new DOMException('Sandbox aborted','AbortError'));};
      worker.onmessage=e=>{const msg=e.data||{};if(msg.id!==id)return;if(msg.type==='stdout'||msg.type==='stderr'){bytes+=new TextEncoder().encode(String(msg.data||'')).length;if(bytes>fixed.maxOutputBytes){cleanup();reject(new Error('sandbox output limit exceeded'));}return;}if(msg.type==='result'){cleanup();msg.ok?resolve(msg.value):reject(new Error(String(msg.error||'sandbox execution failed')));}};
      worker.onerror=e=>{cleanup();reject(new Error(e.message||'sandbox worker error'));};
      signal?.addEventListener('abort',abort,{once:true});
      timer=setTimeout(()=>{cleanup();reject(new Error('sandbox runtime limit exceeded'));},fixed.maxRuntimeMs);
      worker.postMessage({type:messageType,id,task,policy:fixed.describe()});
    });
  };
}
