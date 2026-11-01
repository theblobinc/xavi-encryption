#!/usr/bin/env python3
"""DUO-Math Numerals canonical adjustable-mod core (Rev009).

One-origin, zero-free human notation with two typed ten-letter alphabets:
- uppercase A-J recursively encodes left realized-count continuation groups;
- lowercase a-j recursively encodes right modular rollover identity.

For modulus M>1, S=M-1 and every positive count N has the unique form
N = c*S + r, 1 <= r <= S, c >= 0. The canonical token is H(r)R(c).
For modulus 1 the canonical token is 1R(N).

Conventional integers used below are implementation coordinates only.
License: MIT OR Apache-2.0
"""
from __future__ import annotations
import argparse, json, re
from collections import defaultdict

REVISION = '009'
UPPER_ALPHABET = 'ABCDEFGHIJ'
LOWER_ALPHABET = 'abcdefghij'
TOKEN_RE = re.compile(r'^([1-9])([A-J]*)([a-j]*)$')
COUNT_RE = re.compile(r'^([1-9])([A-J]*)$')


def _encode_bijective10(n:int, alphabet:str)->str:
    if n < 1: raise ValueError('ordinal must be >= 1')
    if len(alphabet) != 10 or len(set(alphabet)) != 10: raise ValueError('alphabet must contain 10 unique symbols')
    out=[]
    while n:
        n,r=divmod(n-1,10)
        out.append(alphabet[r])
    return ''.join(reversed(out))


def _decode_bijective10(s:str, alphabet:str)->int:
    if not s: return 0
    pos={ch:i+1 for i,ch in enumerate(alphabet)}
    n=0
    for ch in s:
        if ch not in pos: raise ValueError('invalid bijective ten-letter suffix')
        n=n*10+pos[ch]
    return n


def bij_letters(n:int, *, upper:bool=False)->str:
    """Canonical ten-letter bijective identity encoder.

    Historical callers used this helper for suffixes, so lowercase remains the
    default. New left-count code passes upper=True explicitly.
    """
    return _encode_bijective10(n, UPPER_ALPHABET if upper else LOWER_ALPHABET)


def letters_value(s:str)->int:
    """Decode a canonical all-uppercase or all-lowercase A-J/a-j suffix."""
    if not s: return 0
    if all(ch in UPPER_ALPHABET for ch in s): return _decode_bijective10(s,UPPER_ALPHABET)
    if all(ch in LOWER_ALPHABET for ch in s): return _decode_bijective10(s,LOWER_ALPHABET)
    raise ValueError('suffix must use only A-J or only a-j')


def left_encode(r:int)->str:
    if r < 1: raise ValueError('left realized count must be >= 1')
    digit=((r-1)%9)+1
    group=(r-1)//9
    return str(digit) + ('' if group==0 else _encode_bijective10(group,UPPER_ALPHABET))


def left_decode(text:str)->int:
    s=str(text).strip()
    m=COUNT_RE.fullmatch(s)
    if not m: raise ValueError('left count must be digit 1-9 followed only by A-J')
    digit=int(m.group(1)); group=_decode_bijective10(m.group(2),UPPER_ALPHABET)
    value=9*group+digit
    if left_encode(value)!=s: raise ValueError('non-canonical left-count glyph')
    return value


def right_encode(c:int)->str:
    if c < 0: raise ValueError('right identity ordinal must be >= 0')
    return '' if c==0 else _encode_bijective10(c,LOWER_ALPHABET)


def right_decode(text:str)->int:
    s=str(text)
    if not s: return 0
    return _decode_bijective10(s,LOWER_ALPHABET)


def duo_count(n:int)->str:
    """Canonical one-origin realized count glyph (the left H() encoder)."""
    return left_encode(n)


def parse_duo_count(s:str)->int:
    return left_decode(s)


def left_groups_per_cycle(modulus:int)->int:
    if modulus < 1: raise ValueError('modulus must be >= 1')
    return 1 if modulus==1 else ((modulus-1)+8)//9


def bands_per_cycle(modulus:int)->int:
    """API alias retained for callers; now means left A-J groups per cycle."""
    return left_groups_per_cycle(modulus)


def parse_token(token:str)->dict:
    s=str(token).strip()
    m=TOKEN_RE.fullmatch(s)
    if not m: raise ValueError('token must be [1-9][A-J]*[a-j]*')
    digit=int(m.group(1)); upper=m.group(2); lower=m.group(3)
    left_group=_decode_bijective10(upper,UPPER_ALPHABET)
    r=9*left_group+digit
    c=_decode_bijective10(lower,LOWER_ALPHABET)
    return dict(token=s,digit=digit,left_group=left_group,left_suffix=upper,
                phase=r,right_index=c,right_suffix=lower)


def token_at(count:int, modulus:int)->dict:
    if count < 1 or modulus < 1: raise ValueError('count/modulus must be >= 1')
    if modulus == 1:
        c=count; r=1; width=0
    else:
        width=modulus-1
        c=(count-1)//width
        r=((count-1)%width)+1
    left=left_encode(r); right=right_encode(c); token=left+right
    p=parse_token(token)
    return dict(token=token,count=count,duo_count=duo_count(count),modulus=modulus,
                duo_modulus=duo_count(modulus),width=width,
                left_groups_per_cycle=left_groups_per_cycle(modulus),
                bands_per_cycle=left_groups_per_cycle(modulus),
                cycle=(c+1 if modulus>1 else c),cycle_zero_based=c,
                phase=r,digit=p['digit'],left_group=p['left_group'],
                left_suffix=p['left_suffix'],right_index=c,right_suffix=right,
                rollover=(modulus==1 or (r==1 and count>1)))


def numeral_context(count:int, modulus:int)->dict:
    """Return the canonical typed DUO numeral identity.

    A glyph alone is not a numeric identity.  For M>1 this object binds
    N, M, S=M-1, c, r, H(r), R(c), and the reconstructed symbol, with
    N=c*S+r.  Mod 1 is the explicit degenerate absolute-count transport.
    """
    state=token_at(count,modulus)
    if modulus==1:
        c=count; r=1; span=0
    else:
        span=modulus-1; c=(count-1)//span; r=((count-1)%span)+1
        if count != c*span+r: raise AssertionError((count,modulus,c,r))
    left=left_encode(r); right=right_encode(c); symbol=left+right
    if symbol!=state['token']: raise AssertionError((count,modulus,symbol,state['token']))
    return {
        'schema':'DUO-MATH/NUMERAL-CONTEXT/v1',
        'revision':'009',
        'external_count':count,
        'modulus':modulus,
        'span':span,
        'cycle':c,
        'remainder':r,
        'left':left,
        'right':right,
        'symbol':symbol,
        'mod1_absolute_transport': bool(modulus==1),
        'authority':False,
    }

def validate_numeral_context(ctx:dict)->dict:
    required={'schema','revision','external_count','modulus','span','cycle','remainder','left','right','symbol','mod1_absolute_transport','authority'}
    if not isinstance(ctx,dict) or set(ctx)!=required: raise ValueError('noncanonical DUO numeral context')
    if ctx['schema']!='DUO-MATH/NUMERAL-CONTEXT/v1' or ctx['revision']!='009' or ctx['authority'] is not False:
        raise ValueError('invalid DUO numeral context metadata')
    count=int(ctx['external_count']); modulus=int(ctx['modulus'])
    expect=numeral_context(count,modulus)
    if ctx!=expect: raise ValueError('DUO numeral context recomputation mismatch')
    return expect

def invert_token(token:str, modulus:int)->dict|None:
    if modulus < 1: raise ValueError('modulus must be >= 1')
    p=parse_token(token)
    r=p['phase']; c=p['right_index']
    if modulus == 1:
        if r != 1 or p['left_suffix'] or c < 1: return None
        count=c
    else:
        width=modulus-1
        if r > width: return None
        count=c*width+r
    got=token_at(count,modulus)
    if got['token'] != p['token']: raise AssertionError((token,modulus,count,got))
    return got


def token_recurrence(token:str,max_modulus:int)->list[dict]:
    return [r for M in range(1,max_modulus+1) if (r:=invert_token(token,M)) is not None]


def compare_moduli(m1:int,m2:int,max_count:int)->list[dict]:
    a={token_at(c,m1)['token']:c for c in range(1,max_count+1)}
    b={token_at(c,m2)['token']:c for c in range(1,max_count+1)}
    out=[]
    for tok in sorted(set(a)&set(b), key=lambda t:(parse_token(t)['right_index'],parse_token(t)['phase'])):
        c1,c2=a[tok],b[tok]
        out.append(dict(token=tok,count_m1=c1,duo_count_m1=duo_count(c1),
                        count_m2=c2,duo_count_m2=duo_count(c2),delta=c2-c1,
                        same_value=(c1==c2)))
    return out


def ambiguity_scan(max_modulus:int,max_count:int)->list[dict]:
    seen=defaultdict(list)
    for M in range(1,max_modulus+1):
        for c in range(1,max_count+1):
            r=token_at(c,M); seen[r['token']].append((M,c))
    rows=[]
    for tok,occ in seen.items():
        mods={m for m,_ in occ}; vals={c for _,c in occ}
        if len(mods)<2: continue
        rows.append(dict(token=tok,modulus_count=len(mods),occurrence_count=len(occ),
                         distinct_values=len(vals),min_count=min(vals),max_count=max(vals),
                         value_spread=max(vals)-min(vals)))
    rows.sort(key=lambda r:(r['distinct_values'],r['modulus_count'],r['value_spread']),reverse=True)
    return rows


def native_walk(modulus:int,count_limit:int):
    """Yield canonical states by one-origin successor transitions."""
    if modulus < 1 or count_limit < 1: raise ValueError('modulus/count_limit must be >= 1')
    if modulus==1:
        for count in range(1,count_limit+1):
            yield token_at(count,1)
        return
    width=modulus-1; r=1; c=0
    for count in range(1,count_limit+1):
        token=left_encode(r)+right_encode(c)
        state=token_at(count,modulus)
        if state['token']!=token: raise AssertionError((modulus,count,token,state))
        yield state
        if r==width: r=1; c+=1
        else: r+=1


def verify_native_equivalence(max_modulus:int=100,count_limit:int=1000):
    for M in range(1,max_modulus+1):
        for state in native_walk(M,count_limit):
            analytic=token_at(state['count'],M)
            if analytic['token']!=state['token']: raise AssertionError((M,state,analytic))
            inv=invert_token(state['token'],M)
            if not inv or inv['count']!=state['count']: raise AssertionError((M,state,inv))
    return True


def main():
    ap=argparse.ArgumentParser(description='DUO-Math Rev009 adjustable-mod analyzer')
    sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('token'); p.add_argument('token'); p.add_argument('--max-mod',type=int,default=50)
    p=sub.add_parser('compare'); p.add_argument('m1'); p.add_argument('m2'); p.add_argument('--max-count',type=int,default=200)
    p=sub.add_parser('scan'); p.add_argument('--max-mod',type=int,default=50); p.add_argument('--max-count',type=int,default=200); p.add_argument('--top',type=int,default=50)
    args=ap.parse_args()
    if args.cmd=='token': data=token_recurrence(args.token,args.max_mod)
    elif args.cmd=='compare': data=compare_moduli(parse_duo_count(args.m1),parse_duo_count(args.m2),args.max_count)
    else: data=ambiguity_scan(args.max_mod,args.max_count)[:args.top]
    print(json.dumps(data,indent=2))

if __name__=='__main__': main()
