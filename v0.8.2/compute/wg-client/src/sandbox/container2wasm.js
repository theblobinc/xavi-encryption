import { SandboxPolicy } from './policy.js';

// Adapter boundary for container-to-WASM/browser runners. The application supplies the
// runner; xavi-browser-js does not bundle a converter, OS image, emulator, or foreign image.
// Image approval remains authoritative in FirstPartyImageRegistry + SandboxManager.
export function createContainer2WasmExecutor({runner,policy=new SandboxPolicy(),imageId=null,defaultCommand=[]}={}){
  if(typeof runner!=='function')throw new TypeError('container2wasm executor requires runner(task, options)');
  if(!imageId)throw new TypeError('container2wasm executor requires approved imageId');
  const fixed=policy instanceof SandboxPolicy?policy:new SandboxPolicy(policy);
  return async function run(context,{signal,imageVersion=null,sourceDigest=null,imageDigest=null,imageLicense=null}={}){
    const command=Array.isArray(context.command)?context.command:[...defaultCommand];
    const request={
      command,
      args:Array.isArray(context.args)?context.args:[],
      stdin:fixed.allowStdin?String(context.stdin??''):'',
      env:context.env&&typeof context.env==='object'?{...context.env}:{},
      imageId,
      imageVersion,
      sourceDigest,
      imageDigest,
      imageLicense,
    };
    return runner(request,{signal,policy:fixed.describe()});
  };
}

export const CONTAINER2WASM_NOTES=Object.freeze({
  adapterOnly:true,
  bundledRuntime:false,
  bundledImages:false,
  xaviGuestLicense:'MIT OR Apache-2.0',
  guestImagePolicy:'Only project-owned, approved Xavi guest images may back WASM executors.',
  browserNetworking:'Browser Fetch/WebSocket networking remains subject to browser origin/CORS restrictions.'
});
