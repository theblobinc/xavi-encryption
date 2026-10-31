#!/usr/bin/env python3
"""DUO-Math theorem/research layer derived from Rev007.

This module distinguishes proved finite recurrence laws, representation-level
ambiguity metrics, and a direct-limit infinite-modulus finite-prefix semantics.
Conventional Python integers are implementation/meta-math addresses only.
License: MIT OR Apache-2.0
"""
from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Iterable
import duo_core as core


def token_parameters(token:str)->dict:
    m=core.TOKEN_RE.fullmatch(token.strip().lower())
    if not m: raise ValueError('token must look like 1, 9, 1a, 7c, 3aa, ...')
    return {'token':token.strip().lower(),'digit':int(m.group(1)),'beta':core.letters_value(m.group(2)),'suffix':m.group(2)}


def band_width(modulus:int)->int:
    """Exact Rev007 band count B(M)=ceil((M-1)/9)=floor((M+7)/9), M>=2."""
    if modulus < 2: raise ValueError('finite band-width theorem is for modulus >= 2')
    return (modulus+7)//9


def recurrence_law(token:str, modulus:int)->dict:
    """Exact finite inverse recurrence theorem for positive-hand DUO token d L(beta)."""
    p=token_parameters(token)
    M=int(modulus)
    if M < 2: raise ValueError('exact recurrence theorem here is stated for M>=2')
    w=M-1; B=band_width(M); q,lam=divmod(p['beta'],B); phase=9*lam+p['digit']
    present=phase<=w
    count=q*w+phase if present else None
    return {
        **p,'modulus':M,'duo_modulus':core.duo_count(M),'width':w,'B':B,
        'band_block_min_modulus':9*B-8,'band_block_max_modulus':9*B+1,
        'q':q,'lambda':lam,'phase':phase,'present':present,
        'count':count,'duo_count':core.duo_count(count) if count else None,
        'affine_slope':q,'affine_intercept':phase-q,
    }


def eventual_plateau(token:str)->dict:
    p=token_parameters(token)
    c=9*p['beta']+p['digit']
    return {**p,'plateau_count':c,'duo_plateau_count':core.duo_count(c),
            'stable_from_modulus':c+1,'duo_stable_from_modulus':core.duo_count(c+1)}


def is_band_transition_modulus(modulus:int)->bool:
    """True iff B(M)>B(M-1); valid M>=3."""
    M=int(modulus)
    if M<3:return False
    return band_width(M)>band_width(M-1)


def structural_band_point(n:int,family:str)->dict:
    n=int(n)
    if n<1: raise ValueError('n>=1')
    if family=='square': M=n*n
    elif family=='pronic': M=n*(n+1)
    else: raise ValueError('family must be square or pronic')
    B=1 if M==1 else band_width(M)
    return {'n':n,'family':family,'modulus':M,'duo_modulus':core.duo_count(M),'B':B,
            'mod9':M%9,'is_band_transition':is_band_transition_modulus(M),
            'transition_theorem_expected':(family=='pronic' and n%3==1 and M>=3)}


def structural_transition_theorem(n_max:int=300)->dict:
    rows=[]
    for n in range(1,n_max+1):
        rows.extend([structural_band_point(n,'square'),structural_band_point(n,'pronic')])
    bad=[r for r in rows if r['is_band_transition']!=r['transition_theorem_expected']]
    return {'n_max':n_max,'checked_points':len(rows),'mismatches':bad,
            'statement':'square terms never equal a DUO band-transition modulus; for n>=2, pronic n(n+1) is a transition iff n ≡ 1 (mod 3); n=1 is the Mod1/Mod2 base exception'}


def ambiguity_metrics(token:str, moduli:Iterable[int])->dict:
    """Combinatorial ambiguity over an explicit finite modulus candidate set.

    `uniform_*_bits` become Shannon entropy only under the explicit assumption
    that compatible candidates (or distinct meanings) are equiprobable after
    observing the token. They are NOT a cryptographic security level.
    """
    rows=[]
    for M in moduli:
        r=core.invert_token(token,int(M))
        if r is not None: rows.append(r)
    mods=sorted({r['modulus'] for r in rows}); values=sorted({r['count'] for r in rows})
    mc=len(mods); vc=len(values)
    return {
        'token':token.lower(),'candidate_moduli':mc,'distinct_realized_values':vc,
        'uniform_modulus_ambiguity_bits':math.log2(mc) if mc else 0.0,
        'uniform_value_ambiguity_bits':math.log2(vc) if vc else 0.0,
        'min_count':min(values) if values else None,'max_count':max(values) if values else None,
        'moduli':mods,'values':values,
        'security_claim':False,
        'note':'Combinatorial/posterior-uniform ambiguity only; not key entropy, perfect secrecy, or PQ security.'
    }


def phase_token(position:int)->str:
    """No-rollover phase renderer P(c): 1..9,1a..9a,1b..."""
    c=int(position)
    if c<1:raise ValueError('position>=1')
    digit=((c-1)%9)+1; beta=(c-1)//9
    return f"{digit}{'' if beta==0 else core.bij_letters(beta)}"


def infinite_modulus_prefix(count:int,hand:str='+')->dict:
    """Direct-limit Mod ∞ semantics for a finite realized count.

    For every finite c, all finite M>=c+1 produce this same first-cycle phase.
    This establishes the finite prefix of an infinite modulus without pretending
    that a finite lowercase glyph encodes transfinite cycle ordinals.
    """
    c=int(count)
    if c<1:raise ValueError('count>=1')
    if hand not in ('+','-'):raise ValueError("hand must be + or -")
    tok=phase_token(c)
    if hand=='-' and c!=1:tok='-'+tok
    return {'schema':'duo-infinite-modulus-finite-prefix/v1','modulus':'omega/infinite-limit',
            'count':c,'duo_count':core.duo_count(c),'hand':hand,'cycle':1,'phase':c,
            'token':tok,'stable_for_all_finite_moduli_from':c+1,
            'duo_stable_from':core.duo_count(c+1),'authority':False}


def abstract_typed_state(modulus,cycle,phase,hand='+')->dict:
    """Representation-independent DUO semantic tuple.

    For finite integer M>=2: 1<=phase<M. For symbolic/transfinite modulus the
    caller supplies a typed symbol and this function records the one-origin
    cycle/phase structure; ordinal validation belongs to a future ordinal type.
    """
    if hand not in ('+','-'):raise ValueError('hand')
    if int(cycle)<1:raise ValueError('cycle>=1')
    if isinstance(modulus,int):
        if modulus<2 or not isinstance(phase,int) or phase<1 or phase>=modulus:raise ValueError('finite state requires M>=2 and 1<=phase<M')
    return {'schema':'duo-typed-state/v1','hand':hand,'modulus':modulus,'cycle':cycle,'phase':phase,'authority':False}


def tuple_notation(state:dict)->str:
    """An alternate reversible diagnostic notation, proving current glyphs are not unique."""
    return f"DUO<{state['hand']}|M={state['modulus']}|C={state['cycle']}|P={state['phase']}>"


def validate(max_modulus:int=1000,beta_max:int=120,n_max:int=1000,count_max:int=1000)->dict:
    checks=0
    for beta in range(beta_max+1):
        suf='' if beta==0 else core.bij_letters(beta)
        for d in range(1,10):
            tok=f'{d}{suf}'
            ep=eventual_plateau(tok)
            for M in range(2,max_modulus+1):
                law=recurrence_law(tok,M); got=core.invert_token(tok,M)
                assert (got is not None)==law['present'],(tok,M,law,got)
                if got: assert got['count']==law['count'],(tok,M,law,got)
                checks+=1
            # Exact eventual plateau at and after threshold.
            for M in (ep['stable_from_modulus'],ep['stable_from_modulus']+1,ep['stable_from_modulus']+97):
                got=core.invert_token(tok,M); assert got and got['count']==ep['plateau_count']
    st=structural_transition_theorem(n_max); assert not st['mismatches']
    for c in range(1,count_max+1):
        lim=infinite_modulus_prefix(c)
        for M in (c+1,c+2,c+101):
            assert core.token_at(c,M)['token']==lim['token'],(c,M,lim,core.token_at(c,M))
    return {'recurrence_checks':checks,'structural_points':st['checked_points'],
            'infinite_prefix_counts':count_max,'status':'PASS'}

if __name__=='__main__':
    import json
    print(json.dumps(validate(),indent=2))
