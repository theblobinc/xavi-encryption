import { SandboxPolicy } from './policy.js';
import { digest } from '../core/utils.js';

export class SandboxManager{
  constructor(xavi){this.xavi=xavi;this.executors=new Map();}
  register({id,run,capabilities=['sandbox-exec'],policy=new SandboxPolicy(),prior=0,when=null,kind='wasm',imageId=null}={}){
    if(!id||typeof run!=='function')throw new TypeError('sandbox executor requires id and run()');
    const fixedPolicy=policy instanceof SandboxPolicy?policy:new SandboxPolicy(policy);
    const imageBacked=kind==='wasm'||kind==='container2wasm'||kind==='wasm-component';
    let image=null;
    if(imageId)image=this.xavi.images?.require(imageId);
    else if(imageBacked)throw new Error(`sandbox executor ${id} rejected: ${kind} executors require an approved first-party imageId`);
    if(image){
      for(const capability of capabilities){
        if(!image.capabilities.includes(capability))throw new Error(`sandbox executor ${id} rejected: image ${image.id} does not approve capability ${capability}`);
      }
    }
    const executor={
      id:String(id),
      run,
      capabilities:[...capabilities],
      policy:fixedPolicy,
      kind:String(kind),
      prior:Number(prior)||0,
      when,
      imageId:image?.id||null,
      imageVersion:image?.version||null,
      sourceDigest:image?.sourceDigest||null,
      imageDigest:image?.contentDigest||null,
      imageLicense:image?.license||null,
    };
    this.executors.set(executor.id,executor);
    this.xavi.router.register({
      id:`sandbox:${executor.id}`,
      capabilities:executor.capabilities,
      prior:executor.prior,
      when:context=>executor.when?executor.when(context)!==false:true,
      run:async(context,runtime)=>this._run(executor,context,runtime),
    });
    return executor;
  }
  async _run(executor,context,{signal}={}){
    const taskDigest=await digest(context);
    const imageEvidence={
      imageId:executor.imageId,
      imageVersion:executor.imageVersion,
      sourceDigest:executor.sourceDigest,
      imageDigest:executor.imageDigest,
      imageLicense:executor.imageLicense,
    };
    const startWitness=await this.xavi.ledger.append('sandbox-execution-start',{
      executorId:executor.id,
      kind:executor.kind,
      ...imageEvidence,
      policy:executor.policy.describe(),
      taskDigest,
    });
    const started=performance.now();
    try{
      const value=await executor.run(context,{signal,policy:executor.policy,...imageEvidence});
      const elapsed=performance.now()-started;
      const finish=await this.xavi.ledger.append('sandbox-execution-finish',{
        executorId:executor.id,
        parent:startWitness.digest,
        ...imageEvidence,
        ok:true,
        elapsedMs:elapsed,
        resultDigest:await digest(value),
      });
      return{executorId:executor.id,kind:executor.kind,...imageEvidence,value,elapsedMs:elapsed,witness:finish};
    }catch(error){
      const elapsed=performance.now()-started;
      await this.xavi.ledger.append('sandbox-execution-finish',{
        executorId:executor.id,
        parent:startWitness.digest,
        ...imageEvidence,
        ok:false,
        elapsedMs:elapsed,
        error:String(error?.message||error).slice(0,1000),
      });
      throw error;
    }
  }
  async execute(capability,context={},options={}){return this.xavi.execute(capability,context,options);}
}
