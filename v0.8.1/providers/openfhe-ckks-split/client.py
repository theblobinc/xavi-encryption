#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, sys
from pathlib import Path
from openfhe import *

BATCH=int(os.environ.get('XAVI_CKKS_BATCH','16'))
DEPTH=int(os.environ.get('XAVI_CKKS_DEPTH','2'))
SCALE=int(os.environ.get('XAVI_CKKS_SCALE_BITS','45'))
ROTATIONS=[1,2,4,8]
EVAL_FILES=('context.bin','public.bin','eval-mult.bin','eval-auto.bin','manifest.json')
ALL_FILES=EVAL_FILES+('private.bin',)

def b64e(v:bytes)->str:return base64.b64encode(v).decode('ascii')
def b64d(v:str)->bytes:return base64.b64decode(v,validate=True)
def sha(v:bytes)->str:return hashlib.sha256(v).hexdigest()

def atomic(path:Path,data:bytes,mode:int):
    tmp=path.with_name(path.name+'.tmp-'+str(os.getpid()))
    with open(tmp,'wb') as f:
        os.fchmod(f.fileno(),mode); f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path)

def build_material(keydir:Path):
    p=CCParamsCKKSRNS(); p.SetMultiplicativeDepth(DEPTH); p.SetScalingModSize(SCALE); p.SetBatchSize(BATCH)
    cc=GenCryptoContext(p); cc.Enable(PKESchemeFeature.PKE); cc.Enable(PKESchemeFeature.KEYSWITCH); cc.Enable(PKESchemeFeature.LEVELEDSHE)
    keys=cc.KeyGen(); cc.EvalMultKeyGen(keys.secretKey); cc.EvalRotateKeyGen(keys.secretKey,ROTATIONS)
    tag=keys.publicKey.GetKeyTag()
    blobs={
      'context.bin':Serialize(cc,BINARY),
      'public.bin':Serialize(keys.publicKey,BINARY),
      'private.bin':Serialize(keys.secretKey,BINARY),
      'eval-mult.bin':SerializeEvalMultKeyString(BINARY,tag),
      'eval-auto.bin':SerializeEvalAutomorphismKeyString(BINARY,tag),
    }
    key_id='sha256:'+sha(blobs['context.bin']+blobs['public.bin']+blobs['eval-mult.bin']+blobs['eval-auto.bin'])
    manifest={'schema':'XAVI-DUO/CKKS-EVAL-BUNDLE/v1','scheme':'CKKS','provider':'openfhe','key_id':key_id,'batch_size':BATCH,'multiplicative_depth':DEPTH,'scale_bits':SCALE,'rotations':ROTATIONS,'files':{n:{'sha256':sha(b),'bytes':len(b)} for n,b in blobs.items() if n!='private.bin'},'contains_client_secret':False}
    for name,data in blobs.items(): atomic(keydir/name,data,0o600 if name=='private.bin' else 0o644)
    atomic(keydir/'manifest.json',(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode(),0o644)
    return cc,keys.publicKey,keys.secretKey,manifest

def load_material(keydir:Path):
    present=[(keydir/n).exists() for n in ALL_FILES]
    if any(present) and not all(present): raise RuntimeError('incomplete CKKS key directory')
    if not all(present): return build_material(keydir)
    manifest=json.loads((keydir/'manifest.json').read_text())
    for name,row in manifest['files'].items():
        data=(keydir/name).read_bytes()
        if len(data)!=row['bytes'] or sha(data)!=row['sha256']: raise RuntimeError('CKKS evaluator bundle integrity failure: '+name)
    cc=DeserializeCryptoContextString((keydir/'context.bin').read_bytes(),BINARY)
    pub=DeserializePublicKeyString((keydir/'public.bin').read_bytes(),BINARY)
    priv=DeserializePrivateKeyString((keydir/'private.bin').read_bytes(),BINARY)
    return cc,pub,priv,manifest

def validate_vec(v):
    if not isinstance(v,list) or not v or len(v)>BATCH: raise ValueError(f'vector length must be 1..{BATCH}')
    return [float(x) for x in v]

def main():
    keydir=Path(os.environ.get('XAVI_CKKS_KEY_DIR','/keys')); keydir.mkdir(parents=True,exist_ok=True)
    cc,pub,priv,manifest=load_material(keydir)
    metrics={}
    def execute(r):
        op=r.get('op')
        if op=='capabilities':
            return {'provider':'openfhe','scheme':'CKKS','role':'client','cryptographic':True,'approximate':True,'has_client_secret':True,'remote_safe':False,'key_id':manifest['key_id'],'batch_size':manifest['batch_size'],'multiplicative_depth':manifest['multiplicative_depth'],'supports_packed_vector':True,'supports_encrypt':True,'supports_decrypt':True,'supports_eval_bundle':True}
        if op=='bundle_manifest': return manifest
        if op=='encrypt_vector':
            v=validate_vec(r.get('value')); pt=cc.MakeCKKSPackedPlaintext(v); ct=cc.Encrypt(pub,pt); return {'data':b64e(Serialize(ct,BINARY)),'length':len(v),'key_id':manifest['key_id']}
        if op=='decrypt_vector':
            n=int(r.get('length',0));
            if n<1 or n>BATCH: raise ValueError('invalid vector length')
            ct=DeserializeCiphertextString(b64d(r['data']),BINARY); pt=cc.Decrypt(ct,priv); pt.SetLength(n)
            vals=pt.GetCKKSPackedValue()[:n]; return {'value':[float(x.real if hasattr(x,'real') else x) for x in vals],'key_id':manifest['key_id']}
        if op=='close': return {'closed':True}
        raise ValueError('unknown op')
    for line in sys.stdin:
        try:
            r=json.loads(line); out=execute(r); print(json.dumps({'ok':True,'result':out},separators=(',',':')),flush=True)
            if r.get('op')=='close': break
        except Exception as e: print(json.dumps({'ok':False,'error':f'{type(e).__name__}: {e}'},separators=(',',':')),flush=True)
if __name__=='__main__': main()
