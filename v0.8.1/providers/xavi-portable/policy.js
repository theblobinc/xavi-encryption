export const DEFAULT_CRYPTO_POLICY=Object.freeze({
  network:'none',filesystem:'workdir-only',stdin:false,maxRuntimeMs:30000,maxOutputBytes:1048576,
  readOnlyRoot:true,capDrop:'all',noNewPrivileges:true,pidsLimit:64,memory:'256m',cpus:'1.0'
});
export function normalizePolicy(p={}){return Object.freeze({...DEFAULT_CRYPTO_POLICY,...p,network:'none',readOnlyRoot:true,capDrop:'all',noNewPrivileges:true});}
