#!/usr/bin/env python3
from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IMAGE='localhost/xavi-void-openfhe:1.2-dev5'
CLIENT=ROOT/'providers/openfhe-ckks-split/client.py'
EVAL=ROOT/'providers/openfhe-ckks-split/evaluator.py'

def start(script,keydir,role):
    args=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-e','PYTHONDONTWRITEBYTECODE=1','-v',f'{script}:/app/sidecar.py:ro','-v',f'{keydir}:/keys:{"rw" if role=="client" else "ro"}','--entrypoint','python3',IMAGE,'/app/sidecar.py']
    return subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)

def q(p,obj):
    p.stdin.write(json.dumps(obj,separators=(',',':'))+'\n'); p.stdin.flush(); line=p.stdout.readline()
    if not line: raise RuntimeError(p.stderr.read())
    row=json.loads(line)
    if not row.get('ok'): raise RuntimeError(row.get('error'))
    return row['result']

def close(p):
    if p.poll() is None:
        try:q(p,{'op':'close'})
        except Exception:pass
        try:p.wait(timeout=20)
        except subprocess.TimeoutExpired:p.kill()

def main():
    with tempfile.TemporaryDirectory(prefix='xde-ckks-split-') as td:
        td=Path(td); cdir=td/'client'; edir=td/'eval'; cdir.mkdir(); edir.mkdir(); cdir.chmod(0o777); edir.chmod(0o777)
        client=start(CLIENT,cdir,'client')
        try:
            cc=q(client,{'op':'capabilities'}); assert cc['role']=='client' and cc['has_client_secret'] is True
            for name in ['context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json']: shutil.copy2(cdir/name,edir/name)
            assert not (edir/'private.bin').exists()
            evaluator=start(EVAL,edir,'evaluator')
            try:
                ec=q(evaluator,{'op':'capabilities'}); assert ec['role']=='evaluator' and ec['has_client_secret'] is False and ec['key_id']==cc['key_id']
                a=[float(i) for i in range(1,33)]; b=[float(i+1) for i in range(1,33)]
                scalars=[]
                for off in (0,16):
                    ea=q(client,{'op':'encrypt_vector','value':a[off:off+16]}); eb=q(client,{'op':'encrypt_vector','value':b[off:off+16]})
                    ha=q(evaluator,{'op':'import_vector','data':ea['data'],'length':ea['length']})['handle']; hb=q(evaluator,{'op':'import_vector','data':eb['data'],'length':eb['length']})['handle']
                    scalars.append(q(evaluator,{'op':'dot','left':ha,'right':hb})['handle'])
                total=q(evaluator,{'op':'sum_handles','handles':scalars})['handle']; enc=q(evaluator,{'op':'export_vector','handle':total}); dec=q(client,{'op':'decrypt_vector','data':enc['data'],'length':1})['value'][0]
                expected=sum(x*y for x,y in zip(a,b)); assert abs(dec-expected)<0.1,(dec,expected)
                metrics=q(evaluator,{'op':'metrics'})
                print(json.dumps({'status':'PASS','scheme':'CKKS','key_id':cc['key_id'],'client_secret_only_in_client':True,'evaluator_has_client_secret':False,'dimensions':32,'dot':dec,'expected':expected,'eval_bundle_bytes':sum((edir/n).stat().st_size for n in ['context.bin','public.bin','eval-mult.bin','eval-auto.bin']),'ciphertext_chunks':4,'metrics':metrics['operations']},sort_keys=True))
            finally: close(evaluator)
        finally: close(client)
if __name__=='__main__':main()
