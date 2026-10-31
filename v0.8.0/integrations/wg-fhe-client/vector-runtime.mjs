import { createHash } from 'node:crypto';
import { WGTrustedFHEClient } from './index.mjs';

const digest=v=>'sha256:'+createHash('sha256').update(JSON.stringify(v)).digest('hex');
export class WGEncryptedVectorRuntime {
  constructor({wgClient=null,ckksSession,custodyRef=null}={}){if(!ckksSession)throw new Error('ckksSession required');this.wg=wgClient||new WGTrustedFHEClient();this.ckks=ckksSession;this.custodyRef=custodyRef;}
  async init(){await this.wg.init();if(!this.ckks.initialized)await this.ckks.init();return this;}
  _planInput(operation,left,right=null){
    const dim=left.length,keyId=this.ckks.keyId,program={id:`wg-rnn:${operation}:${dim}`,irCommitment:digest({operation,dim}),booleanOps:0,wordOps:0,depth:operation==='cosine-similarity'?1:1,bootstraps:0,ciphertextBytes:0,recursiveDepth:this.wg.history.length};
    const key={scheme:'CKKS',keyId,parameterSet:`openfhe-ckks-batch${this.ckks.clientCaps.batch_size}-depth${this.ckks.manifest.multiplicative_depth}`,clientSecretPresent:true,custodyRef:this.custodyRef,evaluationKeyBytes:this.ckks.evaluationKeyBytes,ciphertextExpansion:0,deterministicClient:false};
    const trustedPlaintextFeatures={operation,dimension:dim,leftNorm2:left.reduce((s,x)=>s+x*x,0),rightNorm2:right?right.reduce((s,x)=>s+x*x,0):null,knownZeroCount:left.filter(x=>x===0).length+(right?right.filter(x=>x===0).length:0)};
    return{program,key,candidates:[this.ckks.candidate()],trustedPlaintextFeatures};
  }
  async cosine(left,right){const planned=await this.wg.plan(this._planInput('cosine-similarity',left,right));try{const result=await this.ckks.cosine(left,right);const settled=await this.wg.settle({planned,outcome:{ok:true,wallMs:result.wallMs,provider:'openfhe',device:'cpu',cacheHit:this.ckks.runs>1,bootstrapCount:0}});return{schema:'XAVI-DUO/WG-FHE-COSINE-RESULT/v1',value:result.value,fhe:result,plan:planned.plan,evaluatorView:planned.evaluatorView,settled,authority:false};}catch(error){await this.wg.settle({planned,outcome:{ok:false,wallMs:0,provider:'openfhe',device:'cpu'}});throw error;}}
  async linearBlend(current,next,rate=.1){const planned=await this.wg.plan(this._planInput('prediction-vector',current,next));try{const result=await this.ckks.linearBlend(current,next,rate);const settled=await this.wg.settle({planned,outcome:{ok:true,wallMs:result.wallMs,provider:'openfhe',device:'cpu',cacheHit:this.ckks.runs>1,bootstrapCount:0}});return{schema:'XAVI-DUO/WG-FHE-LINEAR-BLEND-RESULT/v1',value:result.value,fhe:result,plan:planned.plan,evaluatorView:planned.evaluatorView,settled,authority:false};}catch(error){await this.wg.settle({planned,outcome:{ok:false,provider:'openfhe',device:'cpu'}});throw error;}}
  async close(){await this.ckks.close();}
}
