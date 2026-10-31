const NETWORK_MODES=new Set(['none','browser-fetch','delegate-websocket']);
export class SandboxPolicy{
  constructor({network='none',allowedOrigins=[],filesystem='none',maxRuntimeMs=10000,maxOutputBytes=1048576,maxMemoryPages=null,allowStdin=false,label='sandbox'}={}){
    if(!NETWORK_MODES.has(network))throw new TypeError(`unsupported sandbox network mode: ${network}`);
    if(filesystem!=='none'&&!Array.isArray(filesystem))throw new TypeError('filesystem must be none or an explicit mapping array');
    this.network=network;
    this.allowedOrigins=Object.freeze([...new Set((allowedOrigins||[]).map(String))]);
    this.filesystem=filesystem==='none'?'none':Object.freeze(filesystem.map(row=>Object.freeze({...row})));
    this.maxRuntimeMs=Math.max(1,Number(maxRuntimeMs)||10000);
    this.maxOutputBytes=Math.max(1024,Number(maxOutputBytes)||1048576);
    this.maxMemoryPages=maxMemoryPages==null?null:Math.max(1,Number(maxMemoryPages)||1);
    this.allowStdin=Boolean(allowStdin);
    this.label=String(label||'sandbox');
    Object.freeze(this);
  }
  describe(){return{network:this.network,allowedOrigins:[...this.allowedOrigins],filesystem:this.filesystem==='none'?'none':this.filesystem.map(x=>({...x})),maxRuntimeMs:this.maxRuntimeMs,maxOutputBytes:this.maxOutputBytes,maxMemoryPages:this.maxMemoryPages,allowStdin:this.allowStdin,label:this.label};}
}
