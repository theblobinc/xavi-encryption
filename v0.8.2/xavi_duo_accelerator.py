#!/usr/bin/env python3
from __future__ import annotations
import glob, json, os, shutil, socket, subprocess
from pathlib import Path
REGISTRY=Path(__file__).resolve().with_name("ACCELERATOR_PROVIDERS.json")
def _registry_source(path=None):
    if path is not None: return Path(path)
    override=os.environ.get('XAVI_DUO_ACCELERATOR_REGISTRY','').strip()
    if override:
        p=Path(override).expanduser().resolve()
        if not p.is_file(): raise AcceleratorPolicyError('configured accelerator registry unavailable')
        return p
    if REGISTRY.is_file(): return REGISTRY
    from importlib.resources import files
    return files("xavi_duo_data").joinpath("ACCELERATOR_PROVIDERS.json")
class AcceleratorPolicyError(RuntimeError): pass

def registry(path=None): return json.loads(_registry_source(path).read_text())
def profiles(path=None): return registry(path)["profiles"]
def get_profile(profile_id:str,path=None):
    for p in profiles(path):
        if p["id"]==profile_id: return p
    raise AcceleratorPolicyError(f"unknown accelerator profile: {profile_id}")
def select_profile(abi:str,*,vendor:str|None=None,remote:bool=False,allowed_ids:list[str]|None=None,path=None):
    rows=[]
    for p in profiles(path):
        if abi not in p.get("abis",[]): continue
        if vendor and p.get("vendor") not in {vendor,"any"}: continue
        if remote and not p.get("remote_safe",False): continue
        if allowed_ids and p["id"] not in allowed_ids: continue
        if "disabled" in p.get("status",""): continue
        rows.append(p)
    if not rows: raise AcceleratorPolicyError("no eligible accelerator profile")
    rank={"tested":0,"interface-ready":1,"interface-ready-unvalidated":2}
    def key(p):
        st=p.get("status","")
        r=0 if st.startswith("tested") else 1 if st.startswith("interface-ready") and "unvalidated" not in st else 2
        return (r,0 if p.get("vendor")!='any' else 1,p["id"])
    return sorted(rows,key=key)[0]

def _tmpfs_arg(o:dict)->str:
    opts=["rw"]
    if o.get("exec"): opts.append("exec")
    else: opts.append("noexec")
    opts.append(f"mode={o.get('mode','0755').lstrip('0') or '0'}")
    opts.append("tmpcopyup" if o.get("copyup",True) else "notmpcopyup")
    return f"{o['path']}:{','.join(opts)}"

def oci_security_args(profile:dict,*,selector:str|None=None,runtime_user:str|None=None,existing_only:bool=True,runtime:str='podman')->list[str]:
    runtime=str(runtime or 'podman').lower()
    if runtime not in {'podman','docker'}: raise AcceleratorPolicyError('unsupported OCI runtime for accelerator sandbox')
    sb=profile.get("sandbox",{})
    if not sb.get("read_only_rootfs",False): raise AcceleratorPolicyError("production accelerator profile must keep rootfs read-only")
    args=["--read-only"]
    if sb.get("network")=="none": args += ["--network","none"]
    if sb.get("cap_drop")=="all": args += ["--cap-drop","all"]
    if sb.get("no_new_privileges"): args += ["--security-opt","no-new-privileges"]
    if sb.get("selinux_label")=="disable" and runtime=='podman': args += ["--security-opt","label=disable"]
    if sb.get("numeric_user_required"):
        if not runtime_user or not all(x.isdigit() for x in runtime_user.split(':')): raise AcceleratorPolicyError("numeric runtime user required by accelerator profile")
        args += ["--user",runtime_user]
    elif runtime_user:
        args += ["--user",runtime_user]
    for o in sb.get("writable_injection_overlays",[]):
        if o.get("type")!="tmpfs" or o.get("persistent",False): raise AcceleratorPolicyError("writable injection overlays must be ephemeral tmpfs")
        if runtime!='podman' and o.get('copyup',True): raise AcceleratorPolicyError('accelerator profile requires copy-up tmpfs semantics not validated for this OCI runtime')
        if runtime=='podman': args += ["--tmpfs",_tmpfs_arg(o)]
        else: args += ['--tmpfs',f"{o['path']}:rw,noexec" if not o.get('exec') else f"{o['path']}:rw,exec"]
    inj=profile.get("injection",{})
    t=inj.get("type")
    if t=="cdi":
        if runtime!='podman': raise AcceleratorPolicyError('CDI accelerator injection is not validated for this OCI runtime')
        sel=selector or inj.get("default_selector")
        if not sel: raise AcceleratorPolicyError("CDI selector required")
        args += ["--device",inj["device_template"].format(selector=sel)]
    elif t=="cdi-full-name":
        if runtime!='podman': raise AcceleratorPolicyError('CDI accelerator injection is not validated for this OCI runtime')
        if not selector: raise AcceleratorPolicyError("full CDI device name required")
        if "=" not in selector and "/" not in selector: raise AcceleratorPolicyError("invalid CDI device name")
        args += ["--device",selector]
    elif t=="device-glob":
        found=[]
        for pat in inj.get("device_globs",[]):
            found += glob.glob(pat)
        found=sorted(set(found))
        if existing_only and not found: raise AcceleratorPolicyError("no accelerator device nodes matched")
        if existing_only:
            denied=[d for d in found if not os.access(d,os.R_OK|os.W_OK)]
            if denied: raise AcceleratorPolicyError("accelerator device access denied for current worker identity: "+",".join(denied))
        for d in found: args += ["--device",d]
    elif t=="remote-rpc":
        pass
    else: raise AcceleratorPolicyError(f"unsupported accelerator injection: {t}")
    return args

# Backward-compatible name retained for v0.6 callers.
podman_security_args = oci_security_args

def discover_host()->dict:
    drm=[]
    vendors={"0x10de":"nvidia","0x1002":"amd","0x8086":"intel"}
    for card in sorted(Path('/sys/class/drm').glob('card[0-9]*')):
        vp=card/'device/vendor'
        if not vp.exists(): continue
        vid=vp.read_text().strip().lower(); drm.append({'card':card.name,'vendor_id':vid,'vendor':vendors.get(vid,'other')})
    render=sorted(glob.glob('/dev/dri/renderD*'))
    device_paths=sorted(set(render+(['/dev/kfd'] if Path('/dev/kfd').exists() else [])+glob.glob('/dev/nvidia*')))
    device_access=[]
    for d in device_paths:
        try:
            st=os.stat(d); device_access.append({'path':d,'read':os.access(d,os.R_OK),'write':os.access(d,os.W_OK),'mode':oct(st.st_mode & 0o777),'uid':st.st_uid,'gid':st.st_gid})
        except OSError: pass
    cdi=[]
    for root in [Path('/etc/cdi'),Path('/var/run/cdi'),Path.home()/'.config/cdi']:
        if not root.exists(): continue
        for f in sorted(root.glob('*')):
            if not f.is_file(): continue
            text=f.read_text(errors='ignore')
            kind=None
            for line in text.splitlines():
                st=line.strip()
                if st.startswith('kind:'): kind=st.split(':',1)[1].strip().strip('"')
                elif st.startswith('- name:') or st.startswith('name:'):
                    name=st.split(':',1)[1].strip().strip('"')
                    if kind and name: cdi.append(f"{kind}={name}")
    tools={x:bool(shutil.which(x)) for x in ['nvidia-smi','rocminfo','rocm-smi','sycl-ls','vulkaninfo','clinfo']}
    return {'schema':'XAVI-DUO/ACCELERATOR-DISCOVERY/v1','host':socket.gethostname(),'drm':drm,'render_nodes':render,'device_access':device_access,'kfd':Path('/dev/kfd').exists(),'nvidia_nodes':bool(glob.glob('/dev/nvidia*')),'cdi_devices':sorted(set(cdi)),'tools':tools}

def compatible(compute_provider:dict,accelerator_profile:dict)->bool:
    abi=compute_provider.get('accelerator_abi')
    return abi is None or abi in accelerator_profile.get('abis',[])
