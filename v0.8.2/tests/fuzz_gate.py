#!/usr/bin/env python3
import multiprocessing as mp, os, random, tempfile, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'vendor'))
import duo_core as duo
from xavi_duo_crypto import create_keyfile, claim_nonce, encrypt_bytes, decrypt_bytes

rng=random.Random(0xD00F00D)
# Rev009 direct/inverse codec gate over large coordinates.
for i in range(25000):
    M=rng.randint(2,65535); N=rng.randint(1,(1<<62)-1)
    t=duo.token_at(N,M)['token']; r=duo.invert_token(t,M)
    if r is None or r['count']!=N: raise AssertionError((i,M,N,t,r))
# Encryption randomized round trips with zero-free wire.
master=bytes(rng.randrange(256) for _ in range(32))
for i in range(500):
    n=rng.randrange(0,4097); pt=os.urandom(n); aad=os.urandom(rng.randrange(0,65)); nonce=i.to_bytes(12,'big'); pad=0 if i%3 else 256
    frame=encrypt_bytes(master,pt,aad=aad,nonce=nonce,pad_to=pad)
    if '0' in frame or decrypt_bytes(master,frame,aad=aad)!=pt: raise AssertionError(i)

def claim(path):
    _,_,m=claim_nonce(path); return m['counter_used']

with tempfile.TemporaryDirectory() as td:
    p=str(Path(td)/'parallel.xdek'); create_keyfile(p)
    with mp.Pool(8) as pool: vals=pool.map(claim,[p]*64)
    if sorted(vals)!=list(range(1,65)): raise AssertionError(vals)
print('XDE2_FUZZ_GATE PASS codec=25000 encryption=500 concurrent_nonce_claims=64')
