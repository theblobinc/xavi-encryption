export class WasmCapabilityHost {
  constructor({allowedCapabilities,dispatch}){
    if(!Array.isArray(allowedCapabilities)||typeof dispatch!=='function')throw new TypeError('invalid capability host');
    this.allowed=Object.freeze([...new Set(allowedCapabilities)]);
    this.dispatch=dispatch;
    Object.freeze(this);
  }
  async call(capability,request){
    if(!this.allowed.includes(capability))throw new Error(`capability denied: ${capability}`);
    if(!request || request.authority===true)throw new Error('WASM request cannot grant authority');
    return this.dispatch(Object.freeze({capability,request:Object.freeze({...request,authority:false})}));
  }
}
export function frozenCapabilityPolicy(capabilities){return Object.freeze({schema:'XAVI-DUO/WASM-CAPABILITY-POLICY/v1',capabilities:Object.freeze([...new Set(capabilities)]),network:'none',filesystem:'none',raw_gpu:false,authority:false});}
