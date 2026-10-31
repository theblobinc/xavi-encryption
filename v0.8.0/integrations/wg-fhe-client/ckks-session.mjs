import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'../..');
const CLIENT=path.join(root,'providers/openfhe-ckks-split/client.py');
const EVALUATOR=path.join(root,'providers/openfhe-ckks-split/evaluator.py');
const EVAL_FILES=['context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json'];

class JsonLineProcess {
  constructor(command,args,{label='sidecar'}={}){
    this.label=label;this.stderr='';this.pending=[];
    this.proc=spawn(command,args,{stdio:['pipe','pipe','pipe']});
    this.proc.stderr.setEncoding('utf8');this.proc.stderr.on('data',d=>{this.stderr=(this.stderr+d).slice(-16384);});
    this.rl=createInterface({input:this.proc.stdout});
    this.rl.on('line',line=>{const p=this.pending.shift();if(!p)return;try{const row=JSON.parse(line);if(!row.ok)p.reject(new Error(String(row.error||`${label} failed`)));else p.resolve(row.result);}catch(e){p.reject(e);}});
    this.proc.on('exit',(code,signal)=>{while(this.pending.length)this.pending.shift().reject(new Error(`${label} exited code=${code} signal=${signal}: ${this.stderr}`));});
  }
  call(obj){return new Promise((resolve,reject)=>{if(this.proc.exitCode!==null)return reject(new Error(`${this.label} is not running`));this.pending.push({resolve,reject});this.proc.stdin.write(JSON.stringify(obj)+'\n');});}
  async close(){if(this.proc.exitCode===null){try{await this.call({op:'close'});}catch{};this.proc.stdin.end();await new Promise(resolve=>{const t=setTimeout(()=>{try{this.proc.kill('SIGKILL');}catch{};resolve();},5000);this.proc.once('exit',()=>{clearTimeout(t);resolve();});});}this.rl.close();}
}

function podmanArgs(script,keyDir,mode,image){
  const uid=process.getuid?.()??1000,gid=process.getgid?.()??1000;
  return ['run','--rm','-i','--userns=keep-id','--user',`${uid}:${gid}`,'--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-e','PYTHONDONTWRITEBYTECODE=1','-v',`${script}:/app/sidecar.py:ro`,'-v',`${keyDir}:/keys:${mode}`,'--entrypoint','python3',image,'/app/sidecar.py'];
}

export class CKKSSplitSession {
  constructor({clientKeyDir,evaluatorKeyDir,image='localhost/xavi-void-openfhe:1.2-dev5',remote=false,evaluatorId='openfhe-ckks-evaluator'}={}){
    if(!clientKeyDir||!evaluatorKeyDir)throw new Error('clientKeyDir and evaluatorKeyDir are required');
    this.clientKeyDir=path.resolve(clientKeyDir);this.evaluatorKeyDir=path.resolve(evaluatorKeyDir);this.image=image;this.remote=Boolean(remote);this.evaluatorId=evaluatorId;this.initialized=false;this.lastWallMs=0;this.runs=0;
  }
  async init(){
    fs.mkdirSync(this.clientKeyDir,{recursive:true,mode:0o700});fs.chmodSync(this.clientKeyDir,0o700);
    fs.mkdirSync(this.evaluatorKeyDir,{recursive:true,mode:0o700});fs.chmodSync(this.evaluatorKeyDir,0o700);
    this.client=new JsonLineProcess('podman',podmanArgs(CLIENT,this.clientKeyDir,'rw',this.image),{label:'CKKS client'});
    this.clientCaps=await this.client.call({op:'capabilities'});this.manifest=await this.client.call({op:'bundle_manifest'});
    for(const name of EVAL_FILES)fs.copyFileSync(path.join(this.clientKeyDir,name),path.join(this.evaluatorKeyDir,name));
    try{fs.unlinkSync(path.join(this.evaluatorKeyDir,'private.bin'));}catch(e){if(e.code!=='ENOENT')throw e;}
    this.evaluator=new JsonLineProcess('podman',podmanArgs(EVALUATOR,this.evaluatorKeyDir,'ro',this.image),{label:'CKKS evaluator'});
    this.evaluatorCaps=await this.evaluator.call({op:'capabilities'});
    if(this.evaluatorCaps.has_client_secret||this.evaluatorCaps.role!=='evaluator')throw new Error('unsafe CKKS evaluator role');
    if(this.evaluatorCaps.key_id!==this.clientCaps.key_id)throw new Error('CKKS client/evaluator key mismatch');
    this.initialized=true;return this;
  }
  get keyId(){return this.clientCaps?.key_id??null;}
  get evaluationKeyBytes(){return Object.values(this.manifest?.files??{}).reduce((a,r)=>a+Number(r.bytes||0),0);}
  candidate(){return{id:this.evaluatorId,provider:'openfhe',device:this.evaluatorCaps?.device||'cpu',remote:this.remote,fhe:true,role:'evaluator',hasClientSecret:false,keyId:this.keyId,wallMs:this.lastWallMs,queue:0,cacheHitRate:this.runs?1:0,supportsResidentSessions:true,supportsBulkRegisters:true,ciphertextBytes:0};}
  async _importVector(v){const enc=await this.client.call({op:'encrypt_vector',value:v});return this.evaluator.call({op:'import_vector',data:enc.data,length:enc.length});}
  async _exportDecrypt(handle,length){const enc=await this.evaluator.call({op:'export_vector',handle});return (await this.client.call({op:'decrypt_vector',data:enc.data,length})).value;}
  _chunks(v){const n=this.clientCaps.batch_size;const out=[];for(let i=0;i<v.length;i+=n)out.push(v.slice(i,i+n));return out;}
  async dot(left,right){
    if(!this.initialized)throw new Error('CKKS session not initialized');if(left.length!==right.length||!left.length)throw new Error('equal non-empty vectors required');
    const batch=this.clientCaps.batch_size;if(left.length%batch!==0)throw new Error(`dot length must be a multiple of ${batch}`);
    const t0=performance.now(),scalars=[];
    for(let i=0;i<left.length;i+=batch){const a=await this._importVector(left.slice(i,i+batch)),b=await this._importVector(right.slice(i,i+batch));scalars.push((await this.evaluator.call({op:'dot',left:a.handle,right:b.handle})).handle);}
    const total=scalars.length===1?scalars[0]:(await this.evaluator.call({op:'sum_handles',handles:scalars})).handle;
    const value=(await this._exportDecrypt(total,1))[0],metrics=await this.evaluator.call({op:'metrics'});this.lastWallMs=performance.now()-t0;this.runs+=1;return{value,wallMs:this.lastWallMs,metrics,keyId:this.keyId};
  }
  async cosine(left,right){
    if(left.length!==right.length||!left.length)throw new Error('equal non-empty vectors required');const batch=this.clientCaps.batch_size;if(left.length%batch!==0)throw new Error(`cosine length must be a multiple of ${batch}`);
    // The WG stack is the trusted FHE client and already owns these plaintext vectors.
    // Fold deterministic norm work client-side; only the cross-dot needs homomorphic evaluation.
    const leftNorm2=left.reduce((sum,v)=>sum+Number(v)*Number(v),0),rightNorm2=right.reduce((sum,v)=>sum+Number(v)*Number(v),0);
    const t0=performance.now(),xy=[];
    for(let i=0;i<left.length;i+=batch){const a=await this._importVector(left.slice(i,i+batch)),b=await this._importVector(right.slice(i,i+batch));xy.push((await this.evaluator.call({op:'dot',left:a.handle,right:b.handle})).handle);}
    const hxy=xy.length===1?xy[0]:(await this.evaluator.call({op:'sum_handles',handles:xy})).handle;
    const dxy=await this._exportDecrypt(hxy,1),denom=Math.sqrt(Math.max(0,leftNorm2)*Math.max(0,rightNorm2));
    const value=denom?dxy[0]/denom:0,metrics=await this.evaluator.call({op:'metrics'});this.lastWallMs=performance.now()-t0;this.runs+=1;return{value,dot:dxy[0],leftNorm2,rightNorm2,clientSideNormalization:true,wallMs:this.lastWallMs,metrics,keyId:this.keyId};
  }
  async linearBlend(current,next,rate){
    if(current.length!==next.length||!current.length)throw new Error('equal non-empty vectors required');const batch=this.clientCaps.batch_size;if(current.length%batch!==0)throw new Error(`blend length must be a multiple of ${batch}`);const r=Math.max(0,Math.min(1,Number(rate))),out=[],t0=performance.now();
    for(let i=0;i<current.length;i+=batch){const a=await this._importVector(current.slice(i,i+batch)),b=await this._importVector(next.slice(i,i+batch));const sa=(await this.evaluator.call({op:'vector_scale',value:a.handle,scalar:1-r})).handle,sb=(await this.evaluator.call({op:'vector_scale',value:b.handle,scalar:r})).handle,h=(await this.evaluator.call({op:'vector_add',left:sa,right:sb})).handle;out.push(...await this._exportDecrypt(h,batch));}
    const metrics=await this.evaluator.call({op:'metrics'});this.lastWallMs=performance.now()-t0;this.runs+=1;return{value:out,wallMs:this.lastWallMs,metrics,keyId:this.keyId};
  }
  async close(){await this.evaluator?.close();await this.client?.close();this.initialized=false;}
}
