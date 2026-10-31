import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
const here=path.dirname(fileURLToPath(import.meta.url));
const defaultRegistryPath=path.resolve(here,"../../ACCELERATOR_PROVIDERS.json");
export function acceleratorRegistryPath(){return process.env.XAVI_DUO_ACCELERATOR_REGISTRY?path.resolve(process.env.XAVI_DUO_ACCELERATOR_REGISTRY):defaultRegistryPath;}
export function loadAccelerators(){return JSON.parse(fs.readFileSync(acceleratorRegistryPath(),"utf8")).profiles;}
export function selectAccelerator({abi,vendor=null,remote=false,allowedIds=null}){
  const rows=loadAccelerators().filter(p=>{
    if(!p.abis?.includes(abi))return false;
    if(vendor && ![vendor,"any"].includes(p.vendor))return false;
    if(remote && !p.remote_safe)return false;
    if(allowedIds && !allowedIds.includes(p.id))return false;
    if(String(p.status||"").includes("disabled"))return false;
    return true;
  });
  if(!rows.length)throw new Error("no eligible accelerator profile");
  const rank=p=>String(p.status||"").startsWith("tested")?0:(String(p.status||"").startsWith("interface-ready")&&!String(p.status||"").includes("unvalidated")?1:2);
  rows.sort((a,b)=>rank(a)-rank(b)||(a.vendor==="any")-(b.vendor==="any")||a.id.localeCompare(b.id));
  return Object.freeze({...rows[0]});
}
export function acceleratorCompatible(provider,accelerator){
  const abi=provider?.accelerator_abi;
  return !abi || Boolean(accelerator?.abis?.includes(abi));
}
export function assertAcceleratorSandbox(profile){
  const sb=profile?.sandbox||{};
  if(sb.read_only_rootfs!==true)throw new Error("accelerator rootfs must be read-only");
  if(sb.cap_drop!=="all")throw new Error("accelerator capabilities must be dropped");
  if(sb.no_new_privileges!==true)throw new Error("accelerator must set no-new-privileges");
  for(const o of sb.writable_injection_overlays||[]){
    if(o.type!=="tmpfs"||o.persistent===true)throw new Error("accelerator writable overlays must be ephemeral tmpfs");
  }
  return true;
}
