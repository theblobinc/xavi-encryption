#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,secrets,sys,time
from openfhe import *
BATCH=256
params=CCParamsCKKSRNS(); params.SetMultiplicativeDepth(4); params.SetScalingModSize(50); params.SetBatchSize(BATCH)
cc=GenCryptoContext(params); cc.Enable(PKESchemeFeature.PKE); cc.Enable(PKESchemeFeature.KEYSWITCH); cc.Enable(PKESchemeFeature.LEVELEDSHE)
keys=cc.KeyGen(); cc.EvalMultKeyGen(keys.secretKey); cc.EvalRotateKeyGen(keys.secretKey,[1,2,4,8,16,32,64,128])
key_id='ckks-'+secrets.token_hex(16); objects={}; counter=1; metrics={}
def put(ct,n):
 global counter
 h=f'h{counter}'; counter+=1; objects[h]=(ct,int(n)); return h
def get(h):
 if h not in objects: raise ValueError('unknown ciphertext handle')
 return objects[h]
def vec(v):
 if not isinstance(v,list) or not v or len(v)>BATCH: raise ValueError('vector length must be 1..256')
 return [float(x) for x in v]
def enc(v):
 v=vec(v); pt=cc.MakeCKKSPackedPlaintext(v); return put(cc.Encrypt(keys.publicKey,pt),len(v))
def dec(h):
 ct,n=get(h); pt=cc.Decrypt(ct,keys.secretKey); pt.SetLength(n); return [float(x.real if hasattr(x,'real') else x) for x in pt.GetCKKSPackedValue()[:n]]
def record(op,dt):
 r=metrics.setdefault(op,{'calls':0,'wall_ns':0}); r['calls']+=1; r['wall_ns']+=dt
def execute(r):
 op=r['op']
 if op=='capabilities': return {'provider':'openfhe','scheme':'CKKS','cryptographic':True,'approximate':True,'role':'client','has_client_secret':True,'key_id':key_id,'device':'cpu','batch_size':BATCH,'supports_packed_vector':True,'supports_vector_add':True,'supports_vector_mul':True,'supports_vector_scale':True,'supports_dot':True,'supports_metrics':True,'remote_safe':False}
 if op=='encrypt_vector': return {'handle':enc(r['value'])}
 if op=='decrypt_vector': return {'value':dec(r['handle'])}
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
  if n!=nb or n<1 or n>256 or n&(n-1): raise ValueError('dot requires equal power-of-two vector length <=256')
  acc=cc.EvalMult(a,b); step=1
  while step<n:
   acc=cc.EvalAdd(acc,cc.EvalRotate(acc,step)); step*=2
  return {'handle':put(acc,1)}
 if op=='metrics': return {'operations':metrics,'resident_objects':len(objects),'key_id':key_id,'scheme':'CKKS','batch_size':BATCH}
 if op=='release_handles':
  c=0
  for h in r.get('handles',[]): c+=1 if objects.pop(h,None) is not None else 0
  return {'released':c,'resident_objects':len(objects)}
 if op=='close': return {'closed':True}
 raise ValueError('unknown op')
for line in sys.stdin:
 try:
  r=json.loads(line); op=r.get('op','parse'); t=time.perf_counter_ns(); out=execute(r); record(op,time.perf_counter_ns()-t); print(json.dumps({'ok':True,'result':out},separators=(',',':')),flush=True)
  if op=='close': break
 except Exception as e: print(json.dumps({'ok':False,'error':f'{type(e).__name__}: {e}'},separators=(',',':')),flush=True)
