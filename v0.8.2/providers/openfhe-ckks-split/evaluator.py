#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, sys, time
from pathlib import Path
from openfhe import *

def b64e(v:bytes)->str:return base64.b64encode(v).decode('ascii')
def b64d(v:str)->bytes:return base64.b64decode(v,validate=True)
def sha(v:bytes)->str:return hashlib.sha256(v).hexdigest()

def main():
    keydir=Path(os.environ.get('XAVI_CKKS_EVAL_DIR','/keys'))
    if (keydir/'private.bin').exists(): raise RuntimeError('evaluator key directory contains forbidden client private key')
    manifest=json.loads((keydir/'manifest.json').read_text()); batch=int(manifest['batch_size'])
    for name,row in manifest['files'].items():
        data=(keydir/name).read_bytes()
        if len(data)!=row['bytes'] or sha(data)!=row['sha256']: raise RuntimeError('CKKS evaluator bundle integrity failure: '+name)
    cc=DeserializeCryptoContextString((keydir/'context.bin').read_bytes(),BINARY)
    DeserializePublicKeyString((keydir/'public.bin').read_bytes(),BINARY)
    DeserializeEvalMultKeyString((keydir/'eval-mult.bin').read_bytes(),BINARY)
    DeserializeEvalAutomorphismKeyString((keydir/'eval-auto.bin').read_bytes(),BINARY)
    objects={}; lengths={}; counter=0; metrics={}
    def put(ct,n):
        nonlocal counter; counter+=1; h=f'h{counter}'; objects[h]=ct; lengths[h]=int(n); return h
    def get(h):
        if h not in objects: raise ValueError('unknown ciphertext handle')
        return objects[h],lengths[h]
    def record(op,dt):
        row=metrics.setdefault(op,{'calls':0,'wall_ns':0}); row['calls']+=1; row['wall_ns']+=dt
    def execute(r):
        op=r.get('op')
        if op=='capabilities': return {'provider':'openfhe','scheme':'CKKS','role':'evaluator','cryptographic':True,'approximate':True,'has_client_secret':False,'remote_safe':True,'key_id':manifest['key_id'],'device':'cpu','batch_size':batch,'supports_packed_vector':True,'supports_vector_add':True,'supports_vector_mul':True,'supports_vector_scale':True,'supports_dot':True,'supports_sum_handles':True,'supports_activation':int(manifest.get('multiplicative_depth',0))>=4,'activation_domain':[-2.0,2.0],'supports_wg_rnn_recurrent':int(manifest.get('multiplicative_depth',0))>=10,'supports_metrics':True}
        if op=='import_vector':
            n=int(r.get('length',0));
            if n<1 or n>batch: raise ValueError('invalid vector length')
            return {'handle':put(DeserializeCiphertextString(b64d(r['data']),BINARY),n)}
        if op=='export_vector':
            ct,n=get(r['handle']); return {'data':b64e(Serialize(ct,BINARY)),'length':n,'key_id':manifest['key_id']}
        if op=='vector_add':
            a,na=get(r['left']); b,nb=get(r['right']);
            if na!=nb: raise ValueError('vector length mismatch')
            return {'handle':put(cc.EvalAdd(a,b),na)}
        if op=='vector_mul':
            a,na=get(r['left']); b,nb=get(r['right']);
            if na!=nb: raise ValueError('vector length mismatch')
            return {'handle':put(cc.EvalMult(a,b),na)}
        if op=='vector_scale':
            a,n=get(r['value']); return {'handle':put(cc.EvalMult(a,float(r['scalar'])),n)}
        if op=='dot':
            a,n=get(r['left']); b,nb=get(r['right']);
            if n!=nb or n<1 or n>batch or n&(n-1): raise ValueError('dot requires equal power-of-two vector length')
            acc=cc.EvalMult(a,b); step=1
            while step<n: acc=cc.EvalAdd(acc,cc.EvalRotate(acc,step)); step*=2
            return {'handle':put(acc,1)}
        if op=='activation':
            if int(manifest.get('multiplicative_depth',0))<4: raise ValueError('activation requires CKKS multiplicative depth >=4')
            x,n=get(r['value']); kind=str(r.get('kind','')).lower()
            x2=cc.EvalMult(x,x); x3=cc.EvalMult(x2,x)
            if kind=='sigmoid':
                # Least-squares cubic on [-2,2], max plaintext approximation error ~= 0.00434.
                y=cc.EvalAdd(cc.EvalMult(x,0.244914329),cc.EvalMult(x3,-0.0141710484))
                y=cc.EvalAdd(y,cc.MakeCKKSPackedPlaintext([0.5]*batch))
            elif kind=='tanh':
                # Cubic on [-2,2]; experimental because max approximation error ~= 0.0762.
                y=cc.EvalAdd(cc.EvalMult(x,0.866295932),cc.EvalMult(x3,-0.105591757))
            else: raise ValueError('activation kind must be sigmoid or tanh')
            return {'handle':put(y,n),'kind':kind,'domain':[-2.0,2.0]}
        if op=='wg_rnn_recurrent_step':
            if int(manifest.get('multiplicative_depth',0))<10: raise ValueError('WG-RNN recurrent step requires CKKS multiplicative depth >=10')
            names=('input','prev','neighbor','temporal','assoc')
            rows=[get(r[name]) for name in names]
            ns={n for _,n in rows}
            if len(ns)!=1: raise ValueError('WG-RNN recurrent vectors must have equal length')
            n=ns.pop(); X,P,N,T,A=[ct for ct,_ in rows]
            assoc_conf=max(0.0,min(1.0,float(r.get('assoc_confidence',0.0))))
            def add(a,b): return cc.EvalAdd(a,b)
            def scale(a,v): return cc.EvalMult(a,float(v))
            def mul(a,b): return cc.EvalMult(a,b)
            def lin(terms):
                out=None
                for ct,v in terms:
                    term=scale(ct,v); out=term if out is None else add(out,term)
                return out
            def sigmoid3(x):
                x2=mul(x,x); x3=mul(x2,x)
                y=add(scale(x,0.244914329),scale(x3,-0.0141710484))
                return add(y,cc.MakeCKKSPackedPlaintext([0.5]*batch))
            def tanh3(x):
                x2=mul(x,x); x3=mul(x2,x)
                return add(scale(x,0.866295932),scale(x3,-0.105591757))
            z=sigmoid3(lin(((X,.78),(P,.34),(N,-.08),(T,.05))))
            reset=sigmoid3(lin(((X,.52),(N,.21),(P,.13),(A,.04))))
            rp=mul(reset,P)
            proposal=tanh3(lin(((X,.91),(rp,.63),(N,.07),(T,.10),(A,.12*assoc_conf))))
            diff=add(proposal,scale(P,-1.0))
            nxt=add(P,mul(z,diff))
            return {'handle':put(nxt,n),'approximation':'cubic-sigmoid-tanh','activation_domain':[-2.0,2.0],'assoc_confidence':assoc_conf}
        if op=='sum_handles':
            hs=list(r.get('handles') or [])
            if not hs: raise ValueError('handles required')
            first,n=get(hs[0]);
            if n!=1: raise ValueError('sum_handles requires scalar ciphertexts')
            acc=first
            for h in hs[1:]:
                ct,ln=get(h)
                if ln!=1: raise ValueError('sum_handles requires scalar ciphertexts')
                acc=cc.EvalAdd(acc,ct)
            return {'handle':put(acc,1)}
        if op=='release_handles':
            c=0
            for h in r.get('handles',[]):
                if objects.pop(h,None) is not None: lengths.pop(h,None); c+=1
            return {'released':c,'resident_objects':len(objects)}
        if op=='metrics': return {'operations':metrics,'resident_objects':len(objects),'key_id':manifest['key_id'],'scheme':'CKKS','batch_size':batch}
        if op=='close': return {'closed':True}
        raise ValueError('unknown op')
    for line in sys.stdin:
        try:
            r=json.loads(line); t=time.perf_counter_ns(); out=execute(r); record(r.get('op','parse'),time.perf_counter_ns()-t); print(json.dumps({'ok':True,'result':out},separators=(',',':')),flush=True)
            if r.get('op')=='close': break
        except Exception as e: print(json.dumps({'ok':False,'error':f'{type(e).__name__}: {e}'},separators=(',',':')),flush=True)
if __name__=='__main__': main()
