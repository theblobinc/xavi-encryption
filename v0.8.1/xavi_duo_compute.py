#!/usr/bin/env python3
from __future__ import annotations
import json,os,subprocess
from pathlib import Path
from xavi_duo_accelerator import select_profile as select_accelerator_profile, compatible as accelerator_compatible
from xavi_duo_provider_runtime import container_engine
REGISTRY=Path(__file__).resolve().with_name('COMPUTE_PROVIDERS.json')
def _registry_source():
 override=os.environ.get('XAVI_DUO_COMPUTE_REGISTRY','').strip()
 if override:
  p=Path(override).expanduser().resolve()
  if not p.is_file(): raise ComputePolicyError('configured compute registry unavailable')
  return p
 if REGISTRY.is_file(): return REGISTRY
 from importlib.resources import files
 return files('xavi_duo_data').joinpath('COMPUTE_PROVIDERS.json')
class ComputePolicyError(RuntimeError): pass
def providers(): return json.loads(_registry_source().read_text())['providers']
def get_provider(provider_id):
 for p in providers():
  if p.get('id')==provider_id: return p
 raise ComputePolicyError(f'unknown compute provider: {provider_id}')
def select_provider(capability,*,device=None,remote=False,require_no_client_secret=True,accelerator_abi=None):
 rows=[]
 for p in providers():
  if capability not in p.get('capabilities',[]): continue
  if accelerator_abi and p.get('accelerator_abi') != accelerator_abi: continue
  if device and p.get('device') not in {device,'portable'}: continue
  if remote and not p.get('remote_safe',False): continue
  if require_no_client_secret and p.get('contains_client_secret',False): continue
  if 'rebuild-required' in p.get('status',''): continue
  rows.append(p)
 if not rows: raise ComputePolicyError('no eligible compute provider')
 order={'wasm':0,'tfhe':1,'openfhe':2,'gpu-word':3}
 return sorted(rows,key=lambda p:(order.get(p.get('kind'),99),p['id']))[0]

def select_execution(capability,*,accelerator_abi=None,accelerator_vendor=None,device=None,remote=False,require_no_client_secret=True,allowed_accelerator_ids=None):
 p=select_provider(capability,device=device,remote=remote,require_no_client_secret=require_no_client_secret,accelerator_abi=accelerator_abi)
 abi=accelerator_abi or p.get('accelerator_abi')
 if not abi: return {'provider':p,'accelerator':None}
 a=select_accelerator_profile(abi,vendor=accelerator_vendor,remote=remote,allowed_ids=allowed_accelerator_ids)
 if not accelerator_compatible(p,a): raise ComputePolicyError('compute provider is incompatible with accelerator profile')
 return {'provider':p,'accelerator':a}

def tfhe_local_boolean_smoke(image='localhost/xavi-void-tfhe-sidecar:1.2-dev5-cpu'):
 runtime=container_engine()
 if not runtime: raise RuntimeError('no OCI runtime available for TFHE smoke')
 cmd=[runtime,'run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','512m','--cpus','2',image,'--device','cpu']
 p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 def q(o):
  p.stdin.write(json.dumps(o,separators=(',',':'))+'\n'); p.stdin.flush(); line=p.stdout.readline()
  if not line: raise RuntimeError(p.stderr.read())
  row=json.loads(line)
  if not row.get('ok'): raise RuntimeError(str(row))
  return row['result']
 try:
  a=q({'op':'encrypt_bit','value':True})['handle']; b=q({'op':'encrypt_bit','value':False})['handle']; x=q({'op':'bit_xor','left':a,'right':b})['handle']; y=q({'op':'bit_and','left':a,'right':b})['handle']; xv=q({'op':'decrypt_bit','handle':x})['value']; yv=q({'op':'decrypt_bit','handle':y})['value']; caps=q({'op':'capabilities'}); q({'op':'close'}); p.wait(timeout=20)
 finally:
  if p.poll() is None: p.kill()
 if xv is not True or yv is not False: raise RuntimeError('TFHE Boolean smoke mismatch')
 return {'status':'PASS','xor':xv,'and':yv,'provider':caps.get('provider'),'device':caps.get('device'),'tfhe_rs':caps.get('tfhe_rs'),'key_id':caps.get('key_id')}
