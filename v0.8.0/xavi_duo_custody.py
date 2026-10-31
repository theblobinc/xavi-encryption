#!/usr/bin/env python3
from dataclasses import dataclass
from urllib.parse import urlparse
STRENGTH={'file':1,'authority':2,'xavi-authority':2,'remote':3,'tpm2':4,'pkcs11':4}
@dataclass(frozen=True)
class CustodyRef:
    scheme:str; host:str; name:str; raw:str
    @property
    def strength(self): return STRENGTH[self.scheme]
class CustodyError(RuntimeError): pass
def parse_custody_ref(value):
    p=urlparse(str(value))
    if p.scheme not in STRENGTH: raise CustodyError('unsupported custody scheme')
    if p.scheme=='file':
        if not p.path: raise CustodyError('file custody path required')
        return CustodyRef('file','local',p.path,value)
    scheme='authority' if p.scheme=='xavi-authority' else p.scheme
    host=p.netloc.strip(); name=p.path.strip('/')
    if not host or not name: raise CustodyError(f'{scheme} custody requires host/name')
    raw=f'{scheme}://{host}/{name}'
    return CustodyRef(scheme,host,name,raw)
def portable_projection(ref):
    return {'schema':'XAVI-DUO/CUSTODY-REFERENCE/v1','scheme':ref.scheme,'host':ref.host,'name':ref.name,'reference':ref.raw,'strength':ref.strength,'private_key_bytes':False,'authority':False}
def require_node(ref,node_id):
    if ref.scheme in {'tpm2','authority','remote'} and ref.host!=node_id: raise CustodyError(f'private operation pinned to custody node {ref.host}')
    return True
def select_custody(references,minimum_strength=1):
    order={'tpm2':0,'pkcs11':1,'remote':2,'authority':3,'file':4}
    rows=[parse_custody_ref(x) for x in references]; rows=[r for r in rows if r.strength>=minimum_strength]
    if not rows: raise CustodyError('no custody backend satisfies minimum security policy')
    return sorted(rows,key=lambda r:(order.get(r.scheme,99),-r.strength,r.raw))[0]
