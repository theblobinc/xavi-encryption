import {Worker} from 'node:worker_threads';
import {fileURLToPath} from 'node:url';
const workerUrl=new URL('./fhe-worker.mjs',import.meta.url);
export class FheWorkerRpc{
  constructor({allowedCapabilities=['fhe.boolean','fhe.word64','fhe.vector.approx'],dispatcher={}}={}){this.seq=0;this.pending=new Map();this.worker=new Worker(fileURLToPath(workerUrl),{workerData:{allowedCapabilities,dispatcher}});this.worker.on('message',m=>{const p=this.pending.get(m.id);if(!p)return;this.pending.delete(m.id);m.ok?p.resolve(m.value):p.reject(new Error(m.error));});this.worker.on('error',e=>{for(const p of this.pending.values())p.reject(e);this.pending.clear();});}
  call(capability,request){const id=`fhe-worker:${++this.seq}`;return new Promise((resolve,reject)=>{this.pending.set(id,{resolve,reject});this.worker.postMessage({id,capability,request});});}
  async close(){if(!this.worker)return;const id=`fhe-worker:${++this.seq}`;try{await new Promise((resolve,reject)=>{this.pending.set(id,{resolve,reject});this.worker.postMessage({id,close:true});});}finally{await this.worker.terminate();this.worker=null;}}
}
