import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { WGTrustedFHEClient } from './index.mjs';
import { word64ToWire } from '../../providers/xavi-exec/word64.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));const root=path.resolve(here,'../..');const BRIDGE=path.join(root,'providers/wg-tfhe-client/bridge.py');
const digest=v=>'sha256:'+createHash('sha256').update(JSON.stringify(v)).digest('hex');
class Rpc {
  constructor(env){this.pending=[];this.stderr='';this.p=spawn('python3',[BRIDGE],{env:{...process.env,...env},stdio:['pipe','pipe','pipe']});this.p.stderr.setEncoding('utf8');this.p.stderr.on('data',d=>this.stderr=(this.stderr+d).slice(-16384));this.rl=createInterface({input:this.p.stdout});this.rl.on('line',line=>{const q=this.pending.shift();if(!q)return;try{const r=JSON.parse(line);r.ok?q.resolve(r.result):q.reject(new Error(r.error));}catch(e){q.reject(e);}});this.p.on('exit',(code,signal)=>{while(this.pending.length)this.pending.shift().reject(new Error(`TFHE bridge exited ${code}/${signal}: ${this.stderr}`));});}
  call(o){return new Promise((resolve,reject)=>{this.pending.push({resolve,reject});this.p.stdin.write(JSON.stringify(o)+'\n');});}
  async close(){if(this.p.exitCode===null){try{await this.call({op:'close'});}catch{};this.p.stdin.end();await new Promise(r=>{const t=setTimeout(()=>{try{this.p.kill('SIGKILL');}catch{};r();},5000);this.p.once('exit',()=>{clearTimeout(t);r();});});}this.rl.close();}
}
export class WGEncryptedGateRuntime {
  constructor({clientKeyDir,evaluatorKeyDir,wgClient=null,custodyRef=null,remote=false}={}){if(!clientKeyDir||!evaluatorKeyDir)throw new Error('TFHE key dirs required');this.clientKeyDir=path.resolve(clientKeyDir);this.evaluatorKeyDir=path.resolve(evaluatorKeyDir);this.wg=wgClient||new WGTrustedFHEClient();this.custodyRef=custodyRef;this.remote=Boolean(remote);this.lastWallMs=0;this.runs=0;}
  async init(){fs.mkdirSync(this.clientKeyDir,{recursive:true,mode:0o700});fs.mkdirSync(this.evaluatorKeyDir,{recursive:true,mode:0o700});fs.chmodSync(this.clientKeyDir,0o700);fs.chmodSync(this.evaluatorKeyDir,0o700);await this.wg.init();this.rpc=new Rpc({XAVI_TFHE_CLIENT_DIR:this.clientKeyDir,XAVI_TFHE_EVAL_DIR:this.evaluatorKeyDir});this.caps=await this.rpc.call({op:'capabilities'});if(this.caps.evaluator_has_client_secret||this.caps.evaluator_role!=='evaluator')throw new Error('unsafe TFHE evaluator');return this;}
  _input(component,operation,inputs){const program={id:`${component}:${operation}`,irCommitment:digest({component,operation}),booleanOps:Object.keys(inputs).length,wordOps:0,depth:3,bootstraps:0,ciphertextBytes:0,recursiveDepth:this.wg.history.length};const key={scheme:'TFHE',keyId:this.caps.key_id,parameterSet:'tfhe-rs-1.8',clientSecretPresent:true,custodyRef:this.custodyRef,evaluationKeyBytes:this.caps.server_key_bytes,ciphertextExpansion:0,deterministicClient:false};const candidate={id:'tfhe-cpu-evaluator',provider:'tfhe',device:this.caps.device||'cpu',remote:this.remote,fhe:true,role:'evaluator',hasClientSecret:false,keyId:this.caps.key_id,wallMs:this.lastWallMs,queue:0,cacheHitRate:this.runs?1:0,supportsResidentSessions:true,supportsBulkRegisters:true};return{program,key,candidates:[candidate],trustedPlaintextFeatures:{component,operation,inputs}};}
  async _run(component,operation,op,inputs){const planned=await this.wg.plan(this._input(component,operation,inputs));try{const result=await this.rpc.call({op,...inputs});this.lastWallMs=Number(result.wall_ns||0)/1e6;this.runs+=1;const settled=await this.wg.settle({planned,outcome:{ok:true,wallMs:this.lastWallMs,provider:'tfhe',device:this.caps.device||'cpu',cacheHit:this.runs>1,bootstrapCount:0}});return{schema:'XAVI-DUO/WG-TFHE-GATE-RESULT/v1',component,operation,value:result.value,wallMs:this.lastWallMs,plan:planned.plan,evaluatorView:planned.evaluatorView,settled,authority:false};}catch(error){await this.wg.settle({planned,outcome:{ok:false,provider:'tfhe',device:this.caps.device||'cpu'}});throw error;}}
  rnnRouteGate({routeEnabled,capacityOk}){return this._run('wg-rnn','discrete-route-gate','rnn_route_gate',{route_enabled:Boolean(routeEnabled),capacity_ok:Boolean(capacityOk)});}
  sfmWitnessGate({evidenceValid,authorityAllowed,override=false}){return this._run('wg-sfm','witness-gate','sfm_witness_gate',{evidence_valid:Boolean(evidenceValid),authority_allowed:Boolean(authorityAllowed),override:Boolean(override)});}
  srnnReleaseGate({candidateValid,noConflict,integrityOk}){return this._run('wg-srnn','release-gate','srnn_release_gate',{candidate_valid:Boolean(candidateValid),no_conflict:Boolean(noConflict),integrity_ok:Boolean(integrityOk)});}
  wordEq({left,right}){return this._run('portable','word-eq','word_eq',{left:word64ToWire(left,{name:'left'}),right:word64ToWire(right,{name:'right'})});}
  wordXor({left,right}){return this._run('portable','word-xor','word_xor',{left:word64ToWire(left,{name:'left'}),right:word64ToWire(right,{name:'right'})});}
  async close(){await this.rpc?.close();}
}
