#!/usr/bin/env python3
from __future__ import annotations
import json,math,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];IMAGE='localhost/xavi-void-openfhe:1.2-dev5';CLIENT=ROOT/'providers/openfhe-ckks-split/client.py';EVAL=ROOT/'providers/openfhe-ckks-split/evaluator.py'
def start(script,keydir,role):
 a=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','3g','--cpus','2','-e','PYTHONDONTWRITEBYTECODE=1']
 if role=='client':a+=['-e','XAVI_CKKS_DEPTH=10','-e','XAVI_CKKS_SCALE_BITS=40']
 a+=['-v',f'{script}:/app/sidecar.py:ro','-v',f'{keydir}:/keys:{"rw" if role=="client" else "ro"}','--entrypoint','python3',IMAGE,'/app/sidecar.py']
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
def main():
 with tempfile.TemporaryDirectory(prefix='xde-wgrnn-') as td:
  td=Path(td);cd=td/'client';ed=td/'eval';cd.mkdir();ed.mkdir();cd.chmod(0o777);ed.chmod(0o777)
  c=start(CLIENT,cd,'client')
  try:
   cc=q(c,{'op':'capabilities'});assert cc['multiplicative_depth']==10
   for n in ['context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json']:shutil.copy2(cd/n,ed/n)
   assert not (ed/'private.bin').exists()
   e=start(EVAL,ed,'evaluator')
   try:
    ec=q(e,{'op':'capabilities'});assert ec['supports_wg_rnn_recurrent'] and not ec['has_client_secret']
    xi=[-.8,-.5,-.2,.1,.3,.5,.7,.9];prev=[-.4,-.2,0,.2,.4,.1,-.1,.3];neighbor=[.3,-.4,-.2,0,.2,.4,.1,-.1];temporal=[.1,-.1,.05,-.05,.1,0,-.1,.05];assoc=[.2,.1,-.1,.2,-.2,.1,.05,-.05];conf=.6
    handles={}
    for name,v in [('input',xi),('prev',prev),('neighbor',neighbor),('temporal',temporal),('assoc',assoc)]:
     enc=q(c,{'op':'encrypt_vector','value':v});handles[name]=q(e,{'op':'import_vector','data':enc['data'],'length':enc['length']})['handle']
    out=q(e,{'op':'wg_rnn_recurrent_step',**handles,'assoc_confidence':conf});blob=q(e,{'op':'export_vector','handle':out['handle']});vals=q(c,{'op':'decrypt_vector','data':blob['data'],'length':len(xi)})['value']
    truth=[]
    for i in range(len(xi)):
     z=1/(1+math.exp(-(.78*xi[i]+.34*prev[i]-.08*neighbor[i]+.05*temporal[i])))
     r=1/(1+math.exp(-(.52*xi[i]+.21*neighbor[i]+.13*prev[i]+.04*assoc[i])))
     proposal=math.tanh(.91*xi[i]+.63*(r*prev[i])+.07*neighbor[i]+.10*temporal[i]+.12*conf*assoc[i])
     truth.append((1-z)*prev[i]+z*proposal)
    err=max(abs(a-b) for a,b in zip(vals,truth));assert err<.03,(err,vals,truth)
    print(json.dumps({'status':'PASS','scheme':'CKKS','profile':'wg-rnn-recurrent-depth10','dimensions':len(xi),'max_abs_error':err,'client_secret_only_in_client':True,'evaluator_has_client_secret':False,'key_id':cc['key_id']},sort_keys=True))
   finally:close(e)
  finally:close(c)
if __name__=='__main__':main()
