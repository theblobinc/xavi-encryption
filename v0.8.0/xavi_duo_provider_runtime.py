#!/usr/bin/env python3
"""Standalone provider runtime abstraction.

No cluster, hostname, registry, or container engine is assumed. Providers may be
implemented by an allowlisted OCI image or by a hash-pinned native executable.
"""
from __future__ import annotations
import hashlib,json,os,platform,shutil,subprocess
from pathlib import Path

class ProviderRuntimeError(RuntimeError): pass

def _csv(name:str)->list[str]:
    return [x.strip().removeprefix('sha256:') for x in os.environ.get(name,'').split(',') if x.strip()]

def container_engine(preferred:str|None=None)->str|None:
    requested=(preferred or os.environ.get('XAVI_DUO_CONTAINER_RUNTIME','auto')).strip().lower()
    if requested in {'','auto'}:
        for name in ('podman','docker'):
            if shutil.which(name): return name
        return None
    if requested not in {'podman','docker'}: raise ProviderRuntimeError('container runtime must be podman, docker, or auto')
    exe=shutil.which(requested)
    if not exe: raise ProviderRuntimeError(f'configured container runtime unavailable: {requested}')
    return requested

def inspect_oci(image:str,*,allowed_image_ids:list[str]|tuple[str,...],engine:str|None=None)->dict:
    runtime=container_engine(engine)
    if not runtime: return {'available':False,'backend':'oci','image':image,'error':'no supported OCI runtime available'}
    try:
        image_id=subprocess.check_output([runtime,'image','inspect',image,'--format','{{.Id}}'],text=True,stderr=subprocess.STDOUT,timeout=30).strip().removeprefix('sha256:')
        allowed={str(x).removeprefix('sha256:') for x in allowed_image_ids if x}
        if not allowed: return {'available':False,'backend':'oci','runtime':runtime,'image':image,'image_id':image_id,'error':'provider has no allowlisted image identity'}
        if image_id not in allowed: return {'available':False,'backend':'oci','runtime':runtime,'image':image,'image_id':image_id,'allowed_image_ids':sorted(allowed),'error':'provider image ID is not allowlisted'}
        size=None
        try:size=int(subprocess.check_output([runtime,'image','inspect',image,'--format','{{.Size}}'],text=True,stderr=subprocess.STDOUT,timeout=30).strip())
        except Exception: pass
        return {'available':True,'backend':'oci','runtime':runtime,'image':image,'image_id':image_id,'run_ref':image_id,'size':size,'pinned':True,'platform':platform.machine()}
    except Exception as exc:
        return {'available':False,'backend':'oci','runtime':runtime,'image':image,'error':str(exc)}

def inspect_native(executable:str|Path,*,allowed_sha256:list[str]|tuple[str,...])->dict:
    p=Path(executable).expanduser()
    resolved=Path(shutil.which(str(p)) or p).resolve()
    if not resolved.is_file(): return {'available':False,'backend':'native','executable':str(p),'error':'native provider executable unavailable'}
    digest=hashlib.sha256(resolved.read_bytes()).hexdigest()
    allowed={str(x).removeprefix('sha256:') for x in allowed_sha256 if x}
    if not allowed: return {'available':False,'backend':'native','executable':str(resolved),'sha256':digest,'error':'native provider has no allowlisted executable hash'}
    if digest not in allowed: return {'available':False,'backend':'native','executable':str(resolved),'sha256':digest,'allowed_sha256':sorted(allowed),'error':'native provider executable hash is not allowlisted'}
    return {'available':True,'backend':'native','executable':str(resolved),'sha256':digest,'run_ref':str(resolved),'pinned':True,'platform':platform.machine()}

def provider_choice(*,image:str,default_image_ids:list[str],native_env:str,backend_env:str='XAVI_DUO_PROVIDER_BACKEND')->dict:
    mode=os.environ.get(backend_env,'auto').strip().lower()
    if mode not in {'auto','oci','native'}: raise ProviderRuntimeError('provider backend must be auto, oci, or native')
    native=os.environ.get(native_env,'').strip()
    native_hashes=_csv(native_env+'_SHA256')
    image_ids=_csv('XAVI_DUO_MLKEM_ALLOWED_IMAGE_IDS') or [x.removeprefix('sha256:') for x in default_image_ids]
    if mode in {'auto','native'} and native:
        n=inspect_native(native,allowed_sha256=native_hashes)
        if n.get('available') or mode=='native': return n
    if mode in {'auto','oci'}:
        o=inspect_oci(image,allowed_image_ids=image_ids)
        if o.get('available') or mode=='oci': return o
    return {'available':False,'backend':mode,'error':'no allowlisted provider backend available'}



def _provider_env_prefix(provider_id:str)->str:
    return 'XAVI_DUO_PROVIDER_'+''.join(c if c.isalnum() else '_' for c in str(provider_id).upper())

def resolve_provider(provider:dict)->dict:
    """Resolve one compute provider to an immutable local runtime implementation.

    Resolution is deployment-local. Registry records may supply OCI image IDs and/or
    native executable hashes; environment overrides choose a locally installed native
    implementation without changing the protocol or provider identity.
    """
    pid=str(provider.get('id') or '')
    if not pid: raise ProviderRuntimeError('provider id required')
    prefix=_provider_env_prefix(pid)
    mode=os.environ.get(prefix+'_BACKEND',os.environ.get('XAVI_DUO_PROVIDER_BACKEND','auto')).strip().lower()
    if mode not in {'auto','oci','native'}: raise ProviderRuntimeError('provider backend must be auto, oci, or native')
    native=os.environ.get(prefix+'_NATIVE',str(provider.get('native_executable') or '')).strip()
    native_hashes=_csv(prefix+'_NATIVE_SHA256')
    if not native_hashes:
        vals=provider.get('native_sha256s') or ([provider.get('native_sha256')] if provider.get('native_sha256') else [])
        native_hashes=[str(x).removeprefix('sha256:') for x in vals if x]
    image=str(provider.get('image') or '').strip()
    vals=provider.get('image_ids') or ([provider.get('image_id')] if provider.get('image_id') else [])
    image_ids=[str(x).removeprefix('sha256:') for x in vals if x]
    if mode in {'auto','native'} and native:
        row=inspect_native(native,allowed_sha256=native_hashes)
        row.update({'provider_id':pid})
        if row.get('available') or mode=='native': return row
    if mode in {'auto','oci'} and image:
        row=inspect_oci(image,allowed_image_ids=image_ids)
        row.update({'provider_id':pid})
        if row.get('available') or mode=='oci': return row
    return {'available':False,'provider_id':pid,'backend':mode,'error':'no allowlisted provider implementation available'}

def hardened_oci_args(runtime:str,work:Path,image_ref:str,*,cgroup_manager:str|None=None)->list[str]:
    prefix=[runtime]
    if runtime=='podman' and cgroup_manager: prefix += ['--cgroup-manager',cgroup_manager]
    return prefix+['run','--rm','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--cpus','1.0','-v',f'{work}:/work:rw',image_ref]

def run_provider(info:dict,work:Path,args:list[str],*,timeout:int,cgroup_manager:str|None=None)->subprocess.CompletedProcess:
    if not info.get('available'): raise ProviderRuntimeError('provider unavailable')
    if info['backend']=='native':
        return subprocess.run([info['run_ref'],*args],cwd=work,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env={'PATH':os.environ.get('PATH',''),'LANG':'C','LC_ALL':'C'})
    runtime=info['runtime']
    cp=subprocess.run(hardened_oci_args(runtime,work,info['run_ref'],cgroup_manager=cgroup_manager)+args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if cp.returncode!=0 and runtime=='podman' and not cgroup_manager and ('systemd unit' in cp.stderr or 'scope' in cp.stderr):
        cp=subprocess.run(hardened_oci_args(runtime,work,info['run_ref'],cgroup_manager='cgroupfs')+args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    return cp
