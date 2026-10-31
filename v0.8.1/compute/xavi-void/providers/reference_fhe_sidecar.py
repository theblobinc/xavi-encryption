#!/usr/bin/env python3
"""NON-SECURE xavi-void FHE sidecar protocol fixture.

Rev 1.2-dev2 mirrors the production sidecar surface, including resident handles,
bulk oblivious register access, specialized Keccak-24, and operation timing.
All values remain plaintext.  ``cryptographic=false`` is deliberate and this
provider is only for protocol/conformance tests.
"""
from __future__ import annotations

import base64
from collections import defaultdict
import hashlib
import itertools
import json
import sys
import time

MASK=(1<<64)-1
objects={}
counter=itertools.count(1)
metrics=defaultdict(lambda:{"calls":0,"total_ns":0,"max_ns":0})
RHO=((0,36,3,41,18),(1,44,10,45,2),(62,6,43,15,61),(28,55,25,21,56),(27,20,39,8,14))
RC=(0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
    0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
    0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
    0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
    0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
    0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008)

def rotl(x,n):
    n&=63
    return x&MASK if n==0 else ((x<<n)|(x>>(64-n)))&MASK

def keccak24_words(s):
    a=list(s)
    for rc in RC:
        c=[a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
        d=[c[(x-1)%5]^rotl(c[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): a[x+5*y]^=d[x]
        b=[0]*25
        for x in range(5):
            for y in range(5): b[y+5*((2*x+3*y)%5)]=rotl(a[x+5*y],RHO[x][y])
        for x in range(5):
            for y in range(5): a[x+5*y]=(b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]))&MASK
        a[0]^=rc
    return [x&MASK for x in a]

def put(value):
    h=f"h{next(counter)}";objects[h]=value;return h

def get(h):
    if h not in objects: raise ValueError("unknown ciphertext handle")
    return objects[h]

def out(result): print(json.dumps({"ok":True,"result":result},separators=(",",":")),flush=True)
def err(e): print(json.dumps({"ok":False,"error":str(e)},separators=(",",":")),flush=True)

def record(op,start):
    dt=time.perf_counter_ns()-start;m=metrics[op];m["calls"]+=1;m["total_ns"]+=dt;m["max_ns"]=max(m["max_ns"],dt)

def select(bank,index,kind):
    idx=int(get(index))
    default=False if kind=="bit" else 0
    return get(bank[idx-1]) if 1<=idx<=len(bank) else default

def write(bank,index,value):
    idx=int(get(index)); vals=[get(h) for h in bank]
    if 1<=idx<=len(vals): vals[idx-1]=get(value)
    return [put(v) for v in vals]

for line in sys.stdin:
    start=time.perf_counter_ns(); op="parse"
    try:
        r=json.loads(line);op=r["op"]
        if op=="capabilities":
            out({"provider":"reference","cryptographic":False,"supports_boolean":True,"supports_word64":True,
                 "supports_oblivious_select":True,"supports_secret_rotation":True,"key_id":"reference-not-secure",
                 "device":"cpu","supports_bulk_registers":True,"supports_keccak24":True,"supports_metrics":True,"supports_resident_sessions":True});record(op,start);continue
        if op=="close": out({});record(op,start);break
        if op=="metrics": out({"operations":dict(metrics),"resident_objects":len(objects)});record(op,start);continue
        if op=="reset_metrics": metrics.clear();out({});record(op,start);continue
        if op=="resident_stats": out({"resident_objects":len(objects),"cached_selector_sets":0,"device":"cpu","key_id":"reference-not-secure"});record(op,start);continue
        if op=="release_handles":
            released=0
            for h in r["handles"]:
                if h in objects: del objects[h];released+=1
            out({"released":released,"resident_objects":len(objects)});record(op,start);continue
        if op=="clear_session":
            released=len(objects);objects.clear();out({"released":released,"resident_objects":0});record(op,start);continue
        if op in {"encrypt_bit","trivial_bit"}: out({"handle":put(bool(r["value"]))});record(op,start);continue
        if op in {"encrypt_word64","trivial_word64"}: out({"handle":put(int(r["value"])&MASK)});record(op,start);continue
        if op=="decrypt_bit": out({"value":bool(get(r["handle"]))});record(op,start);continue
        if op=="decrypt_word64": out({"value":int(get(r["handle"]))&MASK});record(op,start);continue
        if op=="bit_not": out({"handle":put(not bool(get(r["value"]))) });record(op,start);continue
        if op in {"bit_xor","bit_and","bit_or"}:
            a,b=bool(get(r["left"])),bool(get(r["right"]));v=(a^b if op=="bit_xor" else a and b if op=="bit_and" else a or b);out({"handle":put(v)});record(op,start);continue
        if op=="bit_mux": out({"handle":put(get(r["when_true"]) if get(r["selector"]) else get(r["when_false"]))});record(op,start);continue
        if op in {"word_xor","word_and"}:
            a,b=int(get(r["left"])),int(get(r["right"]));out({"handle":put((a^b if op=="word_xor" else a&b)&MASK)});record(op,start);continue
        if op=="word_not": out({"handle":put((~int(get(r["value"])))&MASK)});record(op,start);continue
        if op=="word_rotl_public": out({"handle":put(rotl(int(get(r["value"])),int(r["amount"])))});record(op,start);continue
        if op=="word_rotl_secret": out({"handle":put(rotl(int(get(r["value"])),int(get(r["amount"]))))});record(op,start);continue
        if op=="word_eq": out({"handle":put(int(get(r["left"]))==int(get(r["right"]))) });record(op,start);continue
        if op=="word_mux": out({"handle":put(get(r["when_true"]) if get(r["selector"]) else get(r["when_false"]))});record(op,start);continue
        if op=="select_register": out({"handle":put(select(r["bank"],r["index"],r["kind"]))});record(op,start);continue
        if op=="write_register": out({"handles":write(r["bank"],r["index"],r["value"])});record(op,start);continue
        if op=="keccak24":
            vals=[int(get(h))&MASK for h in r["state"]]
            if len(vals)!=25: raise ValueError("keccak24 requires 25 words")
            out({"handles":[put(v) for v in keccak24_words(vals)]});record(op,start);continue
        if op=="export_ciphertext":
            value=get(r["handle"]);raw=(b"\x01" if value is True else b"\x00") if r["kind"]=="bit" else int(value).to_bytes(8,"little")
            out({"data":base64.b64encode(raw).decode()});record(op,start);continue
        if op=="import_ciphertext":
            raw=base64.b64decode(r["data"],validate=True)
            if r["kind"]=="bit":
                if raw not in {b"\x00",b"\x01"}: raise ValueError("invalid bit ciphertext")
                value=raw==b"\x01"
            else:
                if len(raw)!=8: raise ValueError("invalid word64 ciphertext")
                value=int.from_bytes(raw,"little")
            out({"handle":put(value)});record(op,start);continue
        if op=="ciphertext_commitment":
            raw=repr(get(r["handle"])).encode();out({"commitment":"ref:"+hashlib.sha3_256(raw).hexdigest()});record(op,start);continue
        raise ValueError(f"unknown op {op}")
    except Exception as e:
        record(op,start);err(e)
