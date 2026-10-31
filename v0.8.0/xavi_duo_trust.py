#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path
from xavi_duo_custody import parse_custody_ref,CustodyRef,CustodyError

SCHEMA='XAVI-DUO/TRUST-POLICY/v2'
MAX_POLICY_BYTES=256*1024
class TrustPolicyError(RuntimeError): pass

def _no_dupes(pairs):
    d={}
    for k,v in pairs:
        if k in d: raise TrustPolicyError(f'duplicate trust-policy field: {k}')
        d[k]=v
    return d

def _canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def policy_digest(policy): return 'sha256:'+hashlib.sha256(_canonical(policy)).hexdigest()
def key_id(path): return 'sha256:'+hashlib.sha256(Path(path).read_bytes()).hexdigest()

def _secure_file(path:Path,*,private=False,base:Path|None=None):
    path=Path(path)
    if not path.is_absolute() and base is not None: path=base/path
    path=path.resolve()
    st=path.stat()
    if not stat.S_ISREG(st.st_mode): raise TrustPolicyError(f'not a regular file: {path}')
    if os.name=='posix':
        if not hasattr(os,'getuid'): raise TrustPolicyError('POSIX ownership attestation unavailable')
        if st.st_uid!=os.getuid(): raise TrustPolicyError(f'file is not owned by worker uid: {path}')
        if st.st_mode & 0o022: raise TrustPolicyError(f'file is group/world writable: {path}')
        if private and st.st_mode & 0o077: raise TrustPolicyError(f'private key permissions are not private: {path}')
    elif private:
        raise TrustPolicyError('private-key filesystem attestation unsupported on this platform; configure a custody backend')
    return path

def _read_policy(path):
    p=_secure_file(Path(path))
    if p.stat().st_size>MAX_POLICY_BYTES: raise TrustPolicyError('trust policy exceeds size limit')
    data=p.read_bytes()
    try: obj=json.loads(data.decode('utf-8','strict'),object_pairs_hook=_no_dupes)
    except TrustPolicyError: raise
    except Exception as exc: raise TrustPolicyError('invalid trust policy JSON') from exc
    return p,obj

def load_policy(path):
    p,obj=_read_policy(path)
    required={'schema','project_id','policy_id','senders','authorities','workers'}
    if set(obj)!=required: raise TrustPolicyError('noncanonical trust policy fields')
    if obj['schema']!=SCHEMA: raise TrustPolicyError('unsupported trust policy schema')
    if not isinstance(obj['project_id'],str) or not obj['project_id'] or len(obj['project_id'])>128: raise TrustPolicyError('invalid project_id')
    if not isinstance(obj['policy_id'],str) or not obj['policy_id'] or len(obj['policy_id'])>128: raise TrustPolicyError('invalid policy_id')
    for role in ('senders','authorities','workers'):
        if not isinstance(obj[role],dict): raise TrustPolicyError(f'{role} must be an object')
    obj['_meta']={'path':str(p),'base_dir':str(p.parent),'digest':policy_digest(obj)}
    return obj

def _entry(policy,role,name):
    row=policy.get(role,{}).get(name)
    if not isinstance(row,dict) or row.get('enabled') is not True: raise TrustPolicyError(f'untrusted or disabled {role[:-1]}: {name}')
    return row

def _public_entry(policy,role,kid):
    row=_entry(policy,role,kid)
    allowed={'enabled','public_key','capabilities','operations','providers','workers'} if role=='authorities' else {'enabled','public_key','capabilities','operations','providers'}
    if not set(row).issubset(allowed): raise TrustPolicyError(f'noncanonical {role[:-1]} trust entry')
    pub=_secure_file(Path(row.get('public_key','')),base=Path(policy['_meta']['base_dir']))
    if key_id(pub)!=kid: raise TrustPolicyError(f'{role[:-1]} key-id mismatch')
    return row,pub

def resolve_sender(policy,kid): return _public_entry(policy,'senders',kid)
def resolve_authority(policy,kid): return _public_entry(policy,'authorities',kid)

def authorize(row,*,capability,operation,provider_id,worker_id=None,role='principal'):
    if capability not in row.get('capabilities',[]): raise TrustPolicyError(f'{role} capability not allowed')
    if operation not in row.get('operations',[]): raise TrustPolicyError(f'{role} operation not allowed')
    if provider_id not in row.get('providers',[]): raise TrustPolicyError(f'{role} provider not allowed')
    if worker_id is not None:
        workers=row.get('workers',['any'])
        if 'any' not in workers and worker_id not in workers: raise TrustPolicyError(f'{role} worker not allowed')
    return True

def _private_ref(value,*,base):
    try: ref=parse_custody_ref(value)
    except CustodyError as exc: raise TrustPolicyError('invalid worker custody reference') from exc
    if ref.scheme=='file':
        p=Path(ref.name)
        if not p.is_absolute(): p=Path(base)/p
        p=_secure_file(p,private=True)
        ref=CustodyRef('file','local',str(p),'file://'+str(p))
    return ref

def resolve_worker(policy,worker_id,provider_id):
    row=_entry(policy,'workers',worker_id)
    allowed={'enabled','public_key','signing_private_ref','transport_public_key','transport_private_ref','providers'}
    if not set(row).issubset(allowed): raise TrustPolicyError('noncanonical worker trust entry')
    if provider_id not in row.get('providers',[]): raise TrustPolicyError('worker provider not allowed')
    base=Path(policy['_meta']['base_dir'])
    pub=_secure_file(Path(row.get('public_key','')),base=base)
    transport_pub=_secure_file(Path(row.get('transport_public_key','')),base=base)
    signing_ref=_private_ref(row.get('signing_private_ref',''),base=base)
    transport_ref=_private_ref(row.get('transport_private_ref',''),base=base)
    return row,pub,signing_ref,transport_pub,transport_ref

def assert_project(policy,project_id):
    if project_id!=policy.get('project_id'): raise TrustPolicyError('cross-project admission rejected')
    return True
