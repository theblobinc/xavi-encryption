#!/usr/bin/env python3
from __future__ import annotations
import json,math,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IMAGE='localhost/xavi-void-openfhe:1.2-dev5'
CLIENT=ROOT/'providers/openfhe-ckks-split/client.py'
EVAL=ROOT/'providers/openfhe-ckks-split/evaluator.py'

def start(script,keydir,role):
    args=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-e','PYTHONDONTWRITEBYTECODE=1']
    if role=='client': args += ['-e','XAVI_CKKS_DEPTH=4']
    args += ['-v',f'{script}:/app/sidecar.py:ro','-v',f'{keydir}:/keys:{"rw" if role=="client" else "ro"}','--entrypoint','python3',IMAGE,'/app/sidecar.py']
    return subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)

def q(p,obj):
    p.stdin.write(json.dumps(obj,separators=(',',':'))+'\n');p.stdin.flush();line=p.stdout.readline()
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
    with tempfile.TemporaryDirectory(prefix='xde-ckks-act-') as td:
        td=Path(td);cdir=td/'client';edir=td/'eval';cdir.mkdir();edir.mkdir();cdir.chmod(0o777);edir.chmod(0o777)
        c=start(CLIENT,cdir,'client')
        try:
            cc=q(c,{'op':'capabilities'});assert cc['multiplicative_depth']==4
            for n in ['context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json']:shutil.copy2(cdir/n,edir/n)
            assert not (edir/'private.bin').exists()
            e=start(EVAL,edir,'evaluator')
            try:
                ec=q(e,{'op':'capabilities'});assert ec['supports_activation'] is True and ec['has_client_secret'] is False
                xs=[-2,-1.5,-1,-.5,0,.5,1,1.5,2]
                enc=q(c,{'op':'encrypt_vector','value':xs});h=q(e,{'op':'import_vector','data':enc['data'],'length':enc['length']})['handle']
                out={}
                for kind in ['sigmoid','tanh']:
                    ah=q(e,{'op':'activation','kind':kind,'value':h})['handle']; blob=q(e,{'op':'export_vector','handle':ah}); vals=q(c,{'op':'decrypt_vector','data':blob['data'],'length':len(xs)})['value']
                    truth=[1/(1+math.exp(-x)) for x in xs] if kind=='sigmoid' else [math.tanh(x) for x in xs]
                    out[kind]={'max_abs_error':max(abs(a-b) for a,b in zip(vals,truth)),'values':vals}
                assert out['sigmoid']['max_abs_error']<0.005
                assert out['tanh']['max_abs_error']<0.08
                print(json.dumps({'status':'PASS','scheme':'CKKS','depth':4,'domain':[-2,2],'evaluator_has_client_secret':False,'client_secret_only_in_client':True,'sigmoid_max_abs_error':out['sigmoid']['max_abs_error'],'tanh_max_abs_error':out['tanh']['max_abs_error'],'key_id':cc['key_id']},sort_keys=True))
            finally:close(e)
        finally:close(c)
if __name__=='__main__':main()
