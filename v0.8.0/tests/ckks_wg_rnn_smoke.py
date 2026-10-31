#!/usr/bin/env python3
import json,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]; script=root/'providers/openfhe-ckks-sidecar/sidecar.py'
cmd=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-v',f'{script}:/app/ckks.py:ro','--entrypoint','python3','localhost/xavi-void-openfhe:1.2-dev5','/app/ckks.py']
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
def q(o):
 p.stdin.write(json.dumps(o,separators=(',',':'))+'\n'); p.stdin.flush(); line=p.stdout.readline()
 if not line: raise RuntimeError(p.stderr.read())
 r=json.loads(line)
 if not r.get('ok'): raise RuntimeError(r)
 return r['result']
try:
 caps=q({'op':'capabilities'}); a=q({'op':'encrypt_vector','value':[1.0,2.0,3.0,4.0]})['handle']; b=q({'op':'encrypt_vector','value':[2.0,3.0,4.0,5.0]})['handle']; add=q({'op':'vector_add','left':a,'right':b})['handle']; mul=q({'op':'vector_mul','left':a,'right':b})['handle']; dot=q({'op':'dot','left':a,'right':b})['handle']; av=q({'op':'decrypt_vector','handle':add})['value']; mv=q({'op':'decrypt_vector','handle':mul})['value']; dv=q({'op':'decrypt_vector','handle':dot})['value'][0]; met=q({'op':'metrics'}); q({'op':'close'}); p.wait(timeout=30)
finally:
 if p.poll() is None: p.kill()
def close(a,b,t=1e-3): return abs(a-b)<=t
assert all(close(x,y) for x,y in zip(av,[3,5,7,9])),av
assert all(close(x,y,2e-3) for x,y in zip(mv,[2,6,12,20])),mv
assert close(dv,40.0,1e-2),(dv,met)
print(json.dumps({'status':'PASS','scheme':caps['scheme'],'role':caps['role'],'batch_size':caps['batch_size'],'add':av,'mul':mv,'dot':dv,'metrics':met['operations']},sort_keys=True))
