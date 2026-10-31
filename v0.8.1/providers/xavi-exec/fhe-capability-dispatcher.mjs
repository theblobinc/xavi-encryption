import {WGEncryptedGateRuntime} from '../../integrations/wg-fhe-client/tfhe-runtime.mjs';
import {CKKSSplitSession} from '../../integrations/wg-fhe-client/ckks-session.mjs';
import {WGEncryptedVectorRuntime} from '../../integrations/wg-fhe-client/vector-runtime.mjs';

export class FheCapabilityDispatcher{
  constructor({tfhe=null,ckks=null}={}){this.tfheOptions=tfhe;this.ckksOptions=ckks;this.tfhe=null;this.ckks=null;this.vector=null;}
  async _tfhe(){if(!this.tfheOptions)throw new Error('TFHE capability is not configured');if(!this.tfhe)this.tfhe=await new WGEncryptedGateRuntime(this.tfheOptions).init();return this.tfhe;}
  async _vector(){if(!this.ckksOptions)throw new Error('CKKS capability is not configured');if(!this.ckks){this.ckks=await new CKKSSplitSession(this.ckksOptions).init();this.vector=await new WGEncryptedVectorRuntime({ckksSession:this.ckks,custodyRef:this.ckksOptions.custodyRef??null}).init();}return this.vector;}
  async dispatch({capability,request}={}){
    if(!request||request.authority===true)throw new Error('capability request cannot grant authority');
    const op=String(request.op||'');
    if(capability==='fhe.boolean'){
      const r=await this._tfhe();
      if(op==='rnn-route-gate')return r.rnnRouteGate(request);
      if(op==='sfm-witness-gate')return r.sfmWitnessGate(request);
      if(op==='srnn-release-gate')return r.srnnReleaseGate(request);
      throw new Error(`unsupported fhe.boolean op: ${op}`);
    }
    if(capability==='fhe.word64'){
      const r=await this._tfhe();
      if(op==='eq')return r.wordEq(request);
      if(op==='xor')return r.wordXor(request);
      throw new Error(`unsupported fhe.word64 op: ${op}`);
    }
    if(capability==='fhe.vector.approx'){
      const r=await this._vector();
      if(op==='cosine')return r.cosine(request.left,request.right);
      if(op==='linear-blend')return r.linearBlend(request.current,request.next,request.rate);
      throw new Error(`unsupported fhe.vector.approx op: ${op}`);
    }
    throw new Error(`unsupported FHE capability: ${capability}`);
  }
  async close(){if(this.vector)await this.vector.close();else if(this.ckks)await this.ckks.close();if(this.tfhe)await this.tfhe.close();}
}
