#!/usr/bin/env python3
from __future__ import annotations
import json, sys, time
import cupy as cp

SRC=r'''
extern "C" __device__ __forceinline__ unsigned long long rotl64(unsigned long long x, unsigned int n) {
    return n ? ((x << n) | (x >> (64u-n))) : x;
}
extern "C" __global__ void keccak24(unsigned long long* a) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const unsigned int rho[25] = {
        0,1,62,28,27, 36,44,6,55,20, 3,10,43,25,39, 41,45,15,21,8, 18,2,61,56,14
    };
    const unsigned long long rc[24] = {
        0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
        0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
        0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
        0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
        0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
        0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
    };
    unsigned long long c[5], d[5], b[25];
    for (int r=0;r<24;r++) {
        for (int x=0;x<5;x++) c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
        for (int x=0;x<5;x++) d[x]=c[(x+4)%5]^rotl64(c[(x+1)%5],1);
        for (int x=0;x<5;x++) for (int y=0;y<5;y++) a[x+5*y]^=d[x];
        for (int x=0;x<5;x++) for (int y=0;y<5;y++) {
            int dst=y+5*((2*x+3*y)%5);
            b[dst]=rotl64(a[x+5*y],rho[x+5*y]);
        }
        for (int x=0;x<5;x++) for (int y=0;y<5;y++) {
            a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
        }
        a[0]^=rc[r];
    }
}
'''

if cp.cuda.runtime.getDeviceCount() < 1:
    raise RuntimeError('no CUDA device visible')
DEVICE=int(cp.cuda.runtime.getDevice())
PROPS=cp.cuda.runtime.getDeviceProperties(DEVICE)
NAME=PROPS['name'].decode() if isinstance(PROPS['name'],bytes) else str(PROPS['name'])
KERNEL=cp.RawKernel(SRC,'keccak24',options=('--std=c++11',))
# Force NVRTC compilation and a real device launch before advertising acceleration.
_probe=cp.zeros(25,dtype=cp.uint64); KERNEL((1,),(1,),(_probe,)); cp.cuda.runtime.deviceSynchronize()

def respond(result): print(json.dumps({'ok':True,'result':result},separators=(',',':')),flush=True)
def fail(exc): print(json.dumps({'ok':False,'error':f'{type(exc).__name__}: {exc}'},separators=(',',':')),flush=True)

for line in sys.stdin:
    try:
        r=json.loads(line); op=r['op']
        if op=='capabilities':
            respond({'provider':'cupy-rawkernel','device':'cuda','accelerated':True,'supports_keccak_word_ir':True,
                     'gpu_name':NAME,'device_ordinal':DEVICE})
        elif op=='execute_keccak_word_program':
            state=r.get('state',[])
            if len(state)!=25: raise ValueError('Keccak state must contain 25 uint64 words')
            start=time.perf_counter_ns()
            arr=cp.asarray(state,dtype=cp.uint64)
            KERNEL((1,),(1,),(arr,)); cp.cuda.runtime.deviceSynchronize()
            elapsed=time.perf_counter_ns()-start
            respond({'state':[int(v) for v in cp.asnumpy(arr)],'elapsed_ns':elapsed,'device':'cuda','gpu_name':NAME})
        elif op=='close': respond({}); break
        else: raise ValueError(f'unsupported operation {op}')
    except Exception as exc: fail(exc)
