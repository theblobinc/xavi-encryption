import {parentPort,workerData} from 'node:worker_threads';
import {WasmCapabilityHost} from './wasm-capability-host.mjs';
import {FheCapabilityDispatcher} from './fhe-capability-dispatcher.mjs';
const dispatcher=new FheCapabilityDispatcher(workerData?.dispatcher||{});
const host=new WasmCapabilityHost({allowedCapabilities:workerData?.allowedCapabilities||[],dispatch:r=>dispatcher.dispatch(r)});
parentPort.on('message',async msg=>{
  const {id,capability,request,close=false}=msg||{};
  if(close){try{await dispatcher.close();parentPort.postMessage({id,ok:true,value:{closed:true}});}catch(e){parentPort.postMessage({id,ok:false,error:String(e?.message||e)});}return;}
  try{const value=await host.call(capability,request);parentPort.postMessage({id,ok:true,value});}catch(e){parentPort.postMessage({id,ok:false,error:String(e?.message||e)});}
});
