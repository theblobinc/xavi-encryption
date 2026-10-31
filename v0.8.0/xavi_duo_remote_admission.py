#!/usr/bin/env python3
from __future__ import annotations
import base64,hashlib,json,time
from pathlib import Path
from xavi_duo_identity import HIGH_ASSURANCE_ALGORITHM, public_key_id, sign, verify
from xavi_duo_private_ops import custody_sign

ADMISSION_SCHEMA='XAVI-DUO/REMOTE-ADMISSION/v2'
APPROVAL_SCHEMA='XAVI-DUO/AUTHORITY-APPROVAL/v2'
MAX_CLOCK_SKEW=60
MAX_TTL=900

class AdmissionError(RuntimeError): pass

def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha256(data:bytes): return 'sha256:'+hashlib.sha256(data).hexdigest()
def _e(b): return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')
def _d(s): return base64.urlsafe_b64decode(str(s)+'='*(-len(str(s))%4))

def create_admission(sender_private,sender_public,task_envelope:bytes,*,project_id,session_id,sequence,message_id,aad:bytes,issued_at=None,expires_at=None):
    now=int(time.time()) if issued_at is None else int(issued_at); exp=now+300 if expires_at is None else int(expires_at)
    body={'schema':ADMISSION_SCHEMA,'signature_algorithm':HIGH_ASSURANCE_ALGORITHM,'project_id':str(project_id),'sender_key_id':public_key_id(sender_public),'session_id':str(session_id),'sequence':int(sequence),'message_id':str(message_id),'issued_at':now,'expires_at':exp,'task_envelope_sha256':sha256(task_envelope),'task_envelope_bytes':len(task_envelope),'aad_sha256':sha256(aad),'authority':False}
    sig,_=sign(sender_private,canonical(body),algorithm=HIGH_ASSURANCE_ALGORITHM)
    return {**body,'signature':_e(sig)}

def verify_admission(obj,sender_public,task_envelope:bytes,aad:bytes,*,now=None):
    now=int(time.time()) if now is None else int(now)
    expected={'schema','signature_algorithm','project_id','sender_key_id','session_id','sequence','message_id','issued_at','expires_at','task_envelope_sha256','task_envelope_bytes','aad_sha256','authority','signature'}
    if set(obj)!=expected: raise AdmissionError('noncanonical admission fields')
    if obj['schema']!=ADMISSION_SCHEMA or obj['signature_algorithm']!=HIGH_ASSURANCE_ALGORITHM or obj['authority'] is not False or not obj['project_id']: raise AdmissionError('invalid admission policy')
    if obj['sender_key_id']!=public_key_id(sender_public): raise AdmissionError('sender identity mismatch')
    issued,exp=int(obj['issued_at']),int(obj['expires_at'])
    if issued>now+MAX_CLOCK_SKEW or exp<now or exp-issued>MAX_TTL or exp<=issued: raise AdmissionError('invalid admission validity window')
    if int(obj['sequence'])<1 or not obj['session_id'] or not obj['message_id']: raise AdmissionError('invalid replay identity')
    if obj['task_envelope_sha256']!=sha256(task_envelope) or int(obj['task_envelope_bytes'])!=len(task_envelope) or obj['aad_sha256']!=sha256(aad): raise AdmissionError('admission transport binding mismatch')
    body={k:v for k,v in obj.items() if k!='signature'}
    if not verify(sender_public,canonical(body),_d(obj['signature']),algorithm=HIGH_ASSURANCE_ALGORITHM): raise AdmissionError('sender signature verification failed')
    return body

def create_authority_approval(authority_private,authority_public,admission,*,capability,operation,provider_id,worker_id='any',issued_at=None,expires_at=None):
    now=int(time.time()) if issued_at is None else int(issued_at); exp=min(int(admission['expires_at']),now+300) if expires_at is None else int(expires_at)
    body={'schema':APPROVAL_SCHEMA,'signature_algorithm':HIGH_ASSURANCE_ALGORITHM,'project_id':admission['project_id'],'authority_key_id':public_key_id(authority_public),'admission_sha256':sha256(canonical({k:v for k,v in admission.items() if k!='signature'})),'sender_key_id':admission['sender_key_id'],'session_id':admission['session_id'],'message_id':admission['message_id'],'task_envelope_sha256':admission['task_envelope_sha256'],'capability':str(capability),'operation':str(operation),'provider_id':str(provider_id),'worker_id':str(worker_id),'issued_at':now,'expires_at':exp,'authority':True}
    sig,_=sign(authority_private,canonical(body),algorithm=HIGH_ASSURANCE_ALGORITHM)
    return {**body,'signature':_e(sig)}

def verify_authority_approval(obj,authority_public,admission,*,capability,operation,provider_id,worker_id,now=None):
    now=int(time.time()) if now is None else int(now)
    required={'schema','signature_algorithm','project_id','authority_key_id','admission_sha256','sender_key_id','session_id','message_id','task_envelope_sha256','capability','operation','provider_id','worker_id','issued_at','expires_at','authority','signature'}
    if set(obj)!=required: raise AdmissionError('noncanonical authority approval fields')
    if obj['schema']!=APPROVAL_SCHEMA or obj['signature_algorithm']!=HIGH_ASSURANCE_ALGORITHM or obj['authority'] is not True or obj['project_id']!=admission['project_id']: raise AdmissionError('invalid authority approval policy')
    if obj['authority_key_id']!=public_key_id(authority_public): raise AdmissionError('authority identity mismatch')
    adm_digest=sha256(canonical({k:v for k,v in admission.items() if k!='signature'}))
    for k,v in [('admission_sha256',adm_digest),('sender_key_id',admission['sender_key_id']),('session_id',admission['session_id']),('message_id',admission['message_id']),('task_envelope_sha256',admission['task_envelope_sha256']),('capability',capability),('operation',operation),('provider_id',provider_id)]:
        if obj[k]!=v: raise AdmissionError(f'authority binding mismatch: {k}')
    if obj['worker_id'] not in {'any',worker_id}: raise AdmissionError('authority worker binding mismatch')
    issued,exp=int(obj['issued_at']),int(obj['expires_at'])
    if issued>now+MAX_CLOCK_SKEW or exp<now or exp-issued>MAX_TTL or exp>int(admission['expires_at']): raise AdmissionError('invalid authority validity window')
    body={k:v for k,v in obj.items() if k!='signature'}
    if not verify(authority_public,canonical(body),_d(obj['signature']),algorithm=HIGH_ASSURANCE_ALGORITHM): raise AdmissionError('authority signature verification failed')
    return body


def create_admission_custody(sender_ref,sender_public,task_envelope:bytes,*,project_id,session_id,sequence,message_id,aad:bytes,registry,issued_at=None,expires_at=None,high_assurance=True):
    now=int(time.time()) if issued_at is None else int(issued_at); exp=now+300 if expires_at is None else int(expires_at)
    body={'schema':ADMISSION_SCHEMA,'signature_algorithm':HIGH_ASSURANCE_ALGORITHM,'project_id':str(project_id),'sender_key_id':public_key_id(sender_public),'session_id':str(session_id),'sequence':int(sequence),'message_id':str(message_id),'issued_at':now,'expires_at':exp,'task_envelope_sha256':sha256(task_envelope),'task_envelope_bytes':len(task_envelope),'aad_sha256':sha256(aad),'authority':False}
    sig,_=custody_sign(sender_ref,canonical(body),algorithm=HIGH_ASSURANCE_ALGORITHM,registry=registry,high_assurance=high_assurance)
    return {**body,'signature':_e(sig)}

def create_authority_approval_custody(authority_ref,authority_public,admission,*,capability,operation,provider_id,registry,worker_id='any',issued_at=None,expires_at=None,high_assurance=True):
    now=int(time.time()) if issued_at is None else int(issued_at); exp=min(int(admission['expires_at']),now+300) if expires_at is None else int(expires_at)
    body={'schema':APPROVAL_SCHEMA,'signature_algorithm':HIGH_ASSURANCE_ALGORITHM,'project_id':admission['project_id'],'authority_key_id':public_key_id(authority_public),'admission_sha256':sha256(canonical({k:v for k,v in admission.items() if k!='signature'})),'sender_key_id':admission['sender_key_id'],'session_id':admission['session_id'],'message_id':admission['message_id'],'task_envelope_sha256':admission['task_envelope_sha256'],'capability':str(capability),'operation':str(operation),'provider_id':str(provider_id),'worker_id':str(worker_id),'issued_at':now,'expires_at':exp,'authority':True}
    sig,_=custody_sign(authority_ref,canonical(body),algorithm=HIGH_ASSURANCE_ALGORITHM,registry=registry,high_assurance=high_assurance)
    return {**body,'signature':_e(sig)}
