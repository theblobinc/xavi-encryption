#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, math, shutil, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IMAGE='localhost/xavi-void-openfhe:1.2-dev5'
CLIENT=ROOT/'providers/openfhe-ckks-split/client.py'
EVAL_FILES=('context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json')

def sha256(path:Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def start_client(keydir:Path):
 a=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','3g','--cpus','2','-e','PYTHONDONTWRITEBYTECODE=1','-e','XAVI_CKKS_DEPTH=10','-e','XAVI_CKKS_SCALE_BITS=40','-v',f'{CLIENT}:/app/sidecar.py:ro','-v',f'{keydir}:/keys:rw','--entrypoint','python3',IMAGE,'/app/sidecar.py']
 return subprocess.Popen(a,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)

def q(p,o):
 p.stdin.write(json.dumps(o,separators=(',',':'))+'\n');p.stdin.flush();line=p.stdout.readline()
 if not line:raise RuntimeError(p.stderr.read())
 r=json.loads(line)
 if not r.get('ok'):raise RuntimeError(r.get('error'))
 return r['result']

def close(p):
 if p.poll() is None:
  try:q(p,{'op':'close'})
  except Exception:pass
  try:p.wait(timeout=20)
  except subprocess.TimeoutExpired:p.kill()

def vectors():
 return {
  'input':[-.8,-.5,-.2,.1,.3,.5,.7,.9],
  'prev':[-.4,-.2,0,.2,.4,.1,-.1,.3],
  'neighbor':[.3,-.4,-.2,0,.2,.4,.1,-.1],
  'temporal':[.1,-.1,.05,-.05,.1,0,-.1,.05],
  'assoc':[.2,.1,-.1,.2,-.2,.1,.05,-.05],
 }

def truth(v,conf=.6):
 out=[]
 for i in range(len(v['input'])):
  x=v['input'][i];p=v['prev'][i];n=v['neighbor'][i];t=v['temporal'][i];a=v['assoc'][i]
  z=1/(1+math.exp(-(.78*x+.34*p-.08*n+.05*t)))
  r=1/(1+math.exp(-(.52*x+.21*n+.13*p+.04*a)))
  proposal=math.tanh(.91*x+.63*(r*p)+.07*n+.10*t+.12*conf*a)
  out.append((1-z)*p+z*proposal)
 return out

def prepare(shared:Path,state:Path):
 if shared.exists():shutil.rmtree(shared)
 if state.exists():shutil.rmtree(state)
 shared.mkdir(parents=True); state.mkdir(parents=True); (shared/'eval').mkdir(); (state/'client').mkdir(); (state/'client').chmod(0o777)
 c=start_client(state/'client')
 try:
  cap=q(c,{'op':'capabilities'}); assert cap['multiplicative_depth']==10
  for n in EVAL_FILES:shutil.copy2(state/'client'/n,shared/'eval'/n)
  assert not (shared/'eval'/'private.bin').exists()
  v=vectors(); encrypted={}
  for name,row in v.items():encrypted[name]=q(c,{'op':'encrypt_vector','value':row})
 finally:close(c)
 req=[{'op':'capabilities'}]
 handles={'input':'h1','prev':'h2','neighbor':'h3','temporal':'h4','assoc':'h5'}
 for name in ('input','prev','neighbor','temporal','assoc'):
  req.append({'op':'import_vector','data':encrypted[name]['data'],'length':encrypted[name]['length']})
 req.append({'op':'wg_rnn_recurrent_step',**handles,'assoc_confidence':.6})
 req.append({'op':'export_vector','handle':'h6'})
 req.append({'op':'metrics'})
 req.append({'op':'close'})
 (shared/'request.ndjson').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in req))
 manifest={'schema':'XAVI-DUO/REMOTE-CKKS-WG-RNN/v1','created_ns':time.time_ns(),'key_id':cap['key_id'],'client_node':'prod4','evaluator_node':'prod3','profile':'wg-rnn-recurrent-depth10','dimensions':8,'evaluator_contains_client_secret':False,'request_sha256':sha256(shared/'request.ndjson'),'eval_bundle':{n:sha256(shared/'eval'/n) for n in EVAL_FILES}}
 (shared/'TRANSFER_MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
 meta={**manifest,'truth':truth(v),'tolerance':.03}
 (state/'meta.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'status':'PREPARED','key_id':cap['key_id'],'shared':str(shared),'state':str(state),'request_sha256':manifest['request_sha256'],'private_key_shared':False},sort_keys=True))

def finish(shared:Path,state:Path,out:Path):
 meta=json.loads((state/'meta.json').read_text()); lines=[json.loads(x) for x in (shared/'response.ndjson').read_text().splitlines() if x.strip()]
 if len(lines)!=10:raise RuntimeError(f'expected 10 evaluator responses, got {len(lines)}')
 for i,row in enumerate(lines):
  if not row.get('ok'):raise RuntimeError(f'evaluator response {i} failed: {row.get("error")}')
 cap=lines[0]['result']; assert cap['role']=='evaluator' and cap['has_client_secret'] is False and cap['key_id']==meta['key_id']
 blob=lines[7]['result']; metrics=lines[8]['result']
 c=start_client(state/'client')
 try:
  ccap=q(c,{'op':'capabilities'}); assert ccap['key_id']==meta['key_id']
  vals=q(c,{'op':'decrypt_vector','data':blob['data'],'length':meta['dimensions']})['value']
 finally:close(c)
 err=max(abs(a-b) for a,b in zip(vals,meta['truth']))
 remote=json.loads((shared/'remote-evaluator.json').read_text())
 result={'schema':'XAVI-DUO/REMOTE-WG-RNN-FHE-VALIDATION/v1','status':'PASS' if err<meta['tolerance'] else 'FAIL','scheme':'CKKS','profile':meta['profile'],'client_node':'prod4','evaluator_node':'prod3','key_id':meta['key_id'],'dimensions':meta['dimensions'],'max_abs_error':err,'tolerance':meta['tolerance'],'values':vals,'truth':meta['truth'],'evaluator_has_client_secret':False,'client_secret_only_in_client':True,'remote_wall_ms':remote['wall_ms'],'evaluator_metrics':metrics,'response_sha256':sha256(shared/'response.ndjson'),'image_id':remote['image_id'],'authority':False}
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
 if result['status']!='PASS':raise SystemExit(1)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['prepare','finish']);ap.add_argument('--shared',required=True);ap.add_argument('--state',required=True);ap.add_argument('--out',default=str(ROOT/'validation/xavi-cluster/VALIDATION_REMOTE_WG_RNN_FHE_PROD3.json'));a=ap.parse_args()
 shared=Path(a.shared);state=Path(a.state)
 prepare(shared,state) if a.mode=='prepare' else finish(shared,state,Path(a.out))
if __name__=='__main__':main()
