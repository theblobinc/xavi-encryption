#!/usr/bin/env python3
import hashlib,json,sys
def letters(n):
    out=[]
    while n:
        n,r=divmod(n-1,26); out.append(chr(97+r))
    return ''.join(reversed(out))
def token(count,modulus):
    if modulus==1:return '1'+letters(count)
    w=modulus-1; B=(w+8)//9
    cyc=(count-1)//w; phase=(count-1)%w+1
    d=(phase-1)%9+1; local=(phase-1)//9; beta=cyc*B+local
    return str(d)+('' if beta==0 else letters(beta))
req=json.loads(sys.stdin.read())
pairs=req['pairs']
out=[{'count':c,'modulus':m,'token':token(c,m)} for c,m in pairs]
body=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
print(json.dumps({'schema':'XAVI-DUO/POLYMORPHIC-RESULT/v1','implementation':'python-closed-form','rows':out,'result_sha256':hashlib.sha256(body).hexdigest(),'authority':False},sort_keys=True,separators=(',',':')))
