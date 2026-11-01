#!/usr/bin/env python3
from __future__ import annotations
import json, secrets, sys
from openfhe import BinFHEContext, STD128, GINX, XOR, AND, OR

MASK=(1<<64)-1
cc=BinFHEContext(); cc.GenerateBinFHEContext(STD128, GINX)
sk=cc.KeyGen(); cc.BTKeyGen(sk)
key_id='openfhe-'+secrets.token_hex(16)
objects={}; counter=1

def put(kind,value):
    global counter
    h=f'h{counter}'; counter+=1; objects[h]=(kind,value); return h

def get(h,kind=None):
    if h not in objects: raise ValueError('unknown ciphertext handle')
    k,v=objects[h]
    if kind is not None and k!=kind: raise ValueError(f'ciphertext kind mismatch: expected {kind}, got {k}')
    return v

def encbit(v): return cc.Encrypt(sk, 1 if v else 0)
def decbit(c): return bool(int(cc.Decrypt(sk,c)))
def bxor(a,b): return cc.EvalBinGate(XOR,a,b)
def band(a,b): return cc.EvalBinGate(AND,a,b)
def bor(a,b): return cc.EvalBinGate(OR,a,b)
def bnot(a): return cc.EvalNOT(a)
def bmux(sel,t,f): return bor(band(sel,t),band(bnot(sel),f))

def encword(v):
    v=int(v)&MASK
    return [encbit((v>>i)&1) for i in range(64)]
def decword(w):
    out=0
    for i,c in enumerate(w):
        if decbit(c): out|=(1<<i)
    return out&MASK

def map2(a,b,fn): return [fn(x,y) for x,y in zip(a,b)]
def map1(a,fn): return [fn(x) for x in a]
def rotl(w,n):
    n=int(n)&63
    if n==0: return list(w)
    return [w[(i-n)&63] for i in range(64)]
def eq_word_public(w,value,bits=64):
    value=int(value)
    terms=[]
    for i in range(bits):
        bit=w[i]
        terms.append(bit if ((value>>i)&1) else bnot(bit))
    while len(terms)>1:
        nxt=[]
        it=iter(terms)
        for a in it:
            b=next(it,None); nxt.append(a if b is None else band(a,b))
        terms=nxt
    return terms[0]
def eq_words(a,b):
    terms=[bnot(bxor(x,y)) for x,y in zip(a,b)]
    while len(terms)>1:
        nxt=[]; it=iter(terms)
        for x in it:
            y=next(it,None); nxt.append(x if y is None else band(x,y))
        terms=nxt
    return terms[0]
def mux_word(sel,t,f): return [bmux(sel,x,y) for x,y in zip(t,f)]
def rotl_secret(w,amount):
    out=rotl(w,0)
    for k in range(64):
        sel=eq_word_public(amount,k,bits=6)
        out=mux_word(sel,rotl(w,k),out)
    return out

def select_register(bank,index,kind):
    if not bank: raise ValueError('empty register bank')
    if kind=='bit':
        out=encbit(False)
        for ordinal,h in enumerate(bank,1): out=bmux(eq_word_public(index,ordinal),get(h,'bit'),out)
        return put('bit',out)
    out=encword(0)
    for ordinal,h in enumerate(bank,1): out=mux_word(eq_word_public(index,ordinal),get(h,'word64'),out)
    return put('word64',out)
def write_register(bank,index,value,kind):
    val=get(value,kind); result=[]
    for ordinal,h in enumerate(bank,1):
        sel=eq_word_public(index,ordinal)
        old=get(h,kind)
        new=bmux(sel,val,old) if kind=='bit' else mux_word(sel,val,old)
        result.append(put(kind,new))
    return result

def respond(result): print(json.dumps({'ok':True,'result':result},separators=(',',':')),flush=True)
def fail(exc): print(json.dumps({'ok':False,'error':f'{type(exc).__name__}: {exc}'},separators=(',',':')),flush=True)

for line in sys.stdin:
    try:
        r=json.loads(line); op=r['op']
        if op=='capabilities':
            respond({'provider':'openfhe','cryptographic':True,'role':'combined','has_client_secret':True,
                     'supports_boolean':True,'supports_word64':True,'supports_oblivious_select':True,
                     'supports_secret_rotation':True,'key_id':key_id,'device':'cpu','supports_bulk_registers':True,
                     'supports_keccak24':False,'supports_metrics':False,'supports_resident_sessions':False})
        elif op=='close': respond({}); break
        elif op in ('encrypt_bit','trivial_bit'): respond({'handle':put('bit',encbit(bool(r['value'])))})
        elif op in ('encrypt_word64','trivial_word64'): respond({'handle':put('word64',encword(r['value']))})
        elif op=='decrypt_bit': respond({'value':decbit(get(r['handle'],'bit'))})
        elif op=='decrypt_word64': respond({'value':decword(get(r['handle'],'word64'))})
        elif op=='bit_not': respond({'handle':put('bit',bnot(get(r['value'],'bit')))})
        elif op=='bit_xor': respond({'handle':put('bit',bxor(get(r['left'],'bit'),get(r['right'],'bit')))})
        elif op=='bit_and': respond({'handle':put('bit',band(get(r['left'],'bit'),get(r['right'],'bit')))})
        elif op=='bit_or': respond({'handle':put('bit',bor(get(r['left'],'bit'),get(r['right'],'bit')))})
        elif op=='bit_mux': respond({'handle':put('bit',bmux(get(r['selector'],'bit'),get(r['when_true'],'bit'),get(r['when_false'],'bit')))})
        elif op=='word_xor': respond({'handle':put('word64',map2(get(r['left'],'word64'),get(r['right'],'word64'),bxor))})
        elif op=='word_and': respond({'handle':put('word64',map2(get(r['left'],'word64'),get(r['right'],'word64'),band))})
        elif op=='word_not': respond({'handle':put('word64',map1(get(r['value'],'word64'),bnot))})
        elif op=='word_rotl_public': respond({'handle':put('word64',rotl(get(r['value'],'word64'),r['amount']))})
        elif op=='word_rotl_secret': respond({'handle':put('word64',rotl_secret(get(r['value'],'word64'),get(r['amount'],'word64')))})
        elif op=='word_eq': respond({'handle':put('bit',eq_words(get(r['left'],'word64'),get(r['right'],'word64')))})
        elif op=='word_mux': respond({'handle':put('word64',mux_word(get(r['selector'],'bit'),get(r['when_true'],'word64'),get(r['when_false'],'word64')))})
        elif op=='select_register': respond({'handle':select_register(r['bank'],get(r['index'],'word64'),r['kind'])})
        elif op=='write_register': respond({'handles':write_register(r['bank'],get(r['index'],'word64'),r['value'],r['kind'])})
        else: raise ValueError(f'unsupported operation {op}')
    except Exception as exc: fail(exc)
