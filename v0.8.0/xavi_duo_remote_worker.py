#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,json,socket,subprocess,time
from pathlib import Path
from xavi_duo_pq import decrypt_for_custody,encrypt_for,MAX_ENVELOPE_BYTES
from xavi_duo_remote_admission import verify_admission,verify_authority_approval,canonical as admission_canonical,sha256 as tagged_sha256
from xavi_duo_replay import ReplayGuard
from xavi_duo_replay_anchor import HTTPSNonceAnchor
from xavi_duo_compute import get_provider
from xavi_duo_accelerator import get_profile,oci_security_args
podman_security_args=oci_security_args  # v0.6 compatibility hook
from xavi_duo_identity import HIGH_ASSURANCE_ALGORITHM,public_key_id as identity_key_id
from xavi_duo_private_ops import PrivateOpsRegistry,FilePrivateOperator,HTTPSPrivateOperator,PrivateOpsError
from xavi_duo_fs import atomic_write
from xavi_duo_trust import load_policy,assert_project,resolve_sender,resolve_authority,authorize,resolve_worker
from xavi_duo_provider_runtime import container_engine,resolve_provider as resolve_provider_runtime

TASK_SCHEMA='XAVI-DUO/REMOTE-FHE-TASK/v1'
RESULT_SCHEMA='XAVI-DUO/REMOTE-FHE-RESULT/v3'
PORTABLE_SCHEMA='xavi-encrypted-polymorphic-task/v1'
ALLOWED_CAPS={'fhe.boolean'}
ALLOWED_OPS={'sfm-witness-gate'}
MAX_ADMISSION_BYTES=64*1024
MAX_APPROVAL_BYTES=64*1024
MAX_DECRYPTED_TASK_BYTES=2*1024*1024
MAX_CIPHERTEXT_BYTES=1024*1024
MAX_TOTAL_INLINE_CIPHERTEXT_BYTES=2*1024*1024
MAX_CIPHERTEXT_B64_CHARS=((MAX_CIPHERTEXT_BYTES+2)//3)*4
MAX_REMOTE_ENVELOPE_BYTES=8*1024*1024
MAX_JSON_DEPTH=24
MAX_JSON_NODES=8192

class RemoteWorkerError(ValueError): pass

def _no_dupes(pairs):
    d={}
    for k,v in pairs:
        if k in d: raise RemoteWorkerError(f'duplicate JSON field: {k}')
        d[k]=v
    return d

def _read_bytes(path,limit,label):
    p=Path(path); st=p.stat()
    if st.st_size>limit: raise RemoteWorkerError(f'{label} exceeds {limit} bytes')
    with p.open('rb') as f:data=f.read(limit+1)
    if len(data)>limit: raise RemoteWorkerError(f'{label} exceeds {limit} bytes')
    return data

def _validate_json_shape(root,label):
    stack=[(root,0)]; nodes=0
    while stack:
        value,depth=stack.pop(); nodes+=1
        if nodes>MAX_JSON_NODES: raise RemoteWorkerError(f'{label} JSON node limit exceeded')
        if depth>MAX_JSON_DEPTH: raise RemoteWorkerError(f'{label} JSON nesting limit exceeded')
        if isinstance(value,dict):
            if len(value)>512: raise RemoteWorkerError(f'{label} JSON object too wide')
            for k,v in value.items():
                if not isinstance(k,str) or len(k)>256: raise RemoteWorkerError(f'{label} JSON key invalid')
                stack.append((v,depth+1))
        elif isinstance(value,list):
            if len(value)>4096: raise RemoteWorkerError(f'{label} JSON array too large')
            stack.extend((v,depth+1) for v in value)
        elif isinstance(value,str):
            if len(value)>MAX_CIPHERTEXT_B64_CHARS+4096: raise RemoteWorkerError(f'{label} JSON string exceeds control-plane bound')
        elif value is None or isinstance(value,(bool,int,float)):
            pass
        else: raise RemoteWorkerError(f'{label} JSON value type unsupported')
    return root

def _json_bytes(data,label):
    try: obj=json.loads(data.decode('utf-8','strict'),object_pairs_hook=_no_dupes)
    except RemoteWorkerError:raise
    except Exception as exc:raise RemoteWorkerError(f'invalid {label} JSON') from exc
    return _validate_json_shape(obj,label)

def _json_file(path,limit,label):return _json_bytes(_read_bytes(path,limit,label),label)

def canonical(v):
    if isinstance(v,list):return [canonical(x) for x in v]
    if isinstance(v,dict):return {k:canonical(v[k]) for k in sorted(v)}
    return v

def digest(v):return hashlib.sha256(json.dumps(canonical(v),separators=(',',':')).encode()).hexdigest()
def public_key_id(path:Path):return 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()

def validate_task(task:dict,*,return_key_id:str|None=None,image_id:str|None=None)->tuple[dict,dict]:
    if task.get('schema')!=TASK_SCHEMA:raise RemoteWorkerError('invalid remote FHE task schema')
    if task.get('authority') is not False:raise RemoteWorkerError('remote FHE task cannot grant authority')
    if task.get('capability') not in ALLOWED_CAPS:raise RemoteWorkerError('FHE capability not allowed')
    if task.get('operation') not in ALLOWED_OPS:raise RemoteWorkerError('FHE operation not allowed')
    operands=task.get('ciphertexts') or {}; portable=task.get('portable_task') or {}
    if portable.get('schema')!=PORTABLE_SCHEMA or portable.get('authority') is not False:raise RemoteWorkerError('invalid portable task')
    body={k:v for k,v in portable.items() if k!='digest'}
    if digest(body)!=portable.get('digest'):raise RemoteWorkerError('portable task digest mismatch')
    if portable.get('requestId')!=task.get('request_id') or portable.get('kind')!='worker' or portable.get('capability')!=task.get('capability') or portable.get('entrypoint')!=task.get('operation'):raise RemoteWorkerError('portable task binding mismatch')
    required=('evidence_valid','authority_allowed','override')
    if tuple(sorted(operands))!=tuple(sorted(required)):raise RemoteWorkerError('unexpected FHE operands')
    total_inline=0
    for k in required:
        encoded=operands[k]
        if not isinstance(encoded,str): raise RemoteWorkerError('FHE ciphertext must use base64 text')
        if len(encoded)>MAX_CIPHERTEXT_B64_CHARS: raise RemoteWorkerError('inline FHE ciphertext encoding exceeds bound')
        try:raw=base64.b64decode(encoded,validate=True)
        except Exception as exc:raise RemoteWorkerError('invalid FHE ciphertext encoding') from exc
        if len(raw)>MAX_CIPHERTEXT_BYTES:raise RemoteWorkerError('FHE ciphertext exceeds bound')
        total_inline += len(raw)
        if total_inline>MAX_TOTAL_INLINE_CIPHERTEXT_BYTES: raise RemoteWorkerError('total inline FHE ciphertexts exceed control-plane bound')
    inputs_digest='sha256:'+hashlib.sha256(json.dumps(canonical(operands),separators=(',',':')).encode()).hexdigest()
    if portable.get('inputDigest')!=inputs_digest:raise RemoteWorkerError('portable input commitment mismatch')
    if return_key_id is not None and portable.get('returnKeyId')!=return_key_id:raise RemoteWorkerError('portable return-key binding mismatch')
    if image_id is not None and portable.get('imageDigest')!='sha256:'+image_id:raise RemoteWorkerError('portable image digest mismatch')
    return operands,portable

def _resolve_provider(provider_id:str):
    provider=get_provider(provider_id)
    if not provider.get('remote_safe') or provider.get('contains_client_secret'):raise RemoteWorkerError('provider is not remote-secret-blind')
    resolved=resolve_provider_runtime(provider)
    if not resolved.get('available'):raise RemoteWorkerError('no allowlisted provider implementation available: '+str(resolved.get('error') or 'unavailable'))
    # This worker exposes the validated FHE sidecar protocol. Native remote execution
    # requires a separately validated OS sandbox profile and is intentionally fail-closed.
    if resolved.get('backend')!='oci':raise RemoteWorkerError('native remote evaluator backend is not yet approved for this worker')
    image_id=str(resolved.get('image_id') or '').removeprefix('sha256:')
    if not image_id or resolved.get('run_ref')!=image_id:raise RemoteWorkerError('provider runtime is not pinned to immutable OCI identity')
    profile_id=provider.get('accelerator_profile')
    if not profile_id:raise RemoteWorkerError('provider lacks accelerator profile')
    profile=get_profile(profile_id)
    provider=dict(provider);provider['_runtime_info']=resolved
    return provider,profile,image_id

def run_eval(task:dict,server_key:Path,provider_id:str)->dict:
    provider,profile,image_id=_resolve_provider(provider_id)
    operands,portable=validate_task(task,image_id=image_id)
    if not server_key.is_file() or server_key.stat().st_size<=0:raise RemoteWorkerError('server key unavailable')
    required=('evidence_valid','authority_allowed','override')
    req=[{'op':'capabilities'}]
    for k in required:req.append({'op':'import_ciphertext','kind':'bit','data':operands[k]})
    req += [{'op':'bit_and','left':'h1','right':'h2'},{'op':'bit_or','left':'h4','right':'h3'},{'op':'export_ciphertext','handle':'h5','kind':'bit'},{'op':'metrics'},{'op':'close'}]
    info=provider.get('_runtime_info') or {'backend':'oci','runtime':container_engine(),'run_ref':image_id}
    runtime=info.get('runtime')
    if not runtime:raise RemoteWorkerError('no OCI runtime available for FHE evaluator')
    security=oci_security_args(profile,selector='all',runtime_user=str(provider.get('runtime_user') or ''),existing_only=True,runtime=runtime)
    cmd=[runtime,'run','--rm','-i']+security+['--pids-limit','64','--memory','3g','--cpus','2','-v',f'{server_key.resolve()}:/keys/server-key.bin:ro',str(info.get('run_ref') or image_id)]
    started=time.perf_counter_ns()
    cp=subprocess.run(cmd,input=''.join(json.dumps(x,separators=(',',':'))+'\n' for x in req),text=True,capture_output=True,timeout=180)
    wall_ms=(time.perf_counter_ns()-started)/1e6
    if cp.returncode:raise RemoteWorkerError('FHE evaluator failed: '+cp.stderr[-2000:])
    try:rows=[json.loads(x) for x in cp.stdout.splitlines() if x.strip()]
    except Exception as exc:raise RemoteWorkerError('invalid evaluator response JSON') from exc
    if len(rows)!=9 or not all(r.get('ok') for r in rows):raise RemoteWorkerError('non-canonical evaluator response')
    caps=rows[0]['result']
    if caps.get('role')!='evaluator' or caps.get('has_client_secret') is not False or caps.get('key_id')!=task.get('fhe_key_id'):raise RemoteWorkerError('evaluator trust boundary mismatch')
    exported=rows[6]['result']['data']
    try:base64.b64decode(exported,validate=True)
    except Exception as exc:raise RemoteWorkerError('invalid evaluator ciphertext result') from exc
    return {'ciphertext':exported,'metrics':rows[7]['result'],'evaluator_wall_ms':wall_ms,'evaluator_image_id':image_id,'evaluator_has_client_secret':False,'device':provider.get('device'),'provider_id':provider_id,'accelerator_profile':profile['id']}

def main():
    ap=argparse.ArgumentParser(prog='xavi-duo-worker',description='Standalone XAVI-DUO authenticated remote FHE evaluator')
    for name in ('return-public','task-envelope','admission','authority-approval','trust-policy','replay-state','server-key','out'):
        ap.add_argument('--'+name,required=True)
    ap.add_argument('--witness');ap.add_argument('--aad',required=True);ap.add_argument('--provider-id',default='tfhe-cuda-evaluator');ap.add_argument('--worker-id',default=socket.gethostname())
    ap.add_argument('--replay-anchor-url')
    ap.add_argument('--replay-anchor-ca')
    ap.add_argument('--replay-anchor-cert')
    ap.add_argument('--replay-anchor-key')
    ap.add_argument('--allow-local-replay-only',action='store_true',help='standard/development mode only; disables independent replay rollback protection')
    ap.add_argument('--private-ops-url')
    ap.add_argument('--private-ops-ca')
    ap.add_argument('--private-ops-cert')
    ap.add_argument('--private-ops-key')
    ap.add_argument('--allow-file-private-ops',action='store_true',help='standard/development mode only; allows exporting file:// private keys to local provider processes')
    x=ap.parse_args();aad=x.aad.encode()
    policy=load_policy(x.trust_policy)
    env_bytes=_read_bytes(x.task_envelope,min(MAX_ENVELOPE_BYTES,MAX_REMOTE_ENVELOPE_BYTES),'task envelope')
    admission=_json_file(x.admission,MAX_ADMISSION_BYTES,'admission')
    assert_project(policy,admission.get('project_id'))
    sender_row,sender_public=resolve_sender(policy,admission.get('sender_key_id'))
    verify_admission(admission,sender_public,env_bytes,aad)
    approval=_json_file(x.authority_approval,MAX_APPROVAL_BYTES,'authority approval')
    if approval.get('capability') not in ALLOWED_CAPS or approval.get('operation') not in ALLOWED_OPS:raise RemoteWorkerError('authority approval requests unsupported capability/operation')
    authority_row,authority_public=resolve_authority(policy,approval.get('authority_key_id'))
    authorize(sender_row,capability=approval['capability'],operation=approval['operation'],provider_id=x.provider_id,role='sender')
    authorize(authority_row,capability=approval['capability'],operation=approval['operation'],provider_id=x.provider_id,worker_id=x.worker_id,role='authority')
    worker_row,worker_public,worker_signing_ref,worker_transport_public,worker_transport_ref=resolve_worker(policy,x.worker_id,x.provider_id)
    verify_authority_approval(approval,authority_public,admission,capability=approval['capability'],operation=approval['operation'],provider_id=x.provider_id,worker_id=x.worker_id)
    private_ops=PrivateOpsRegistry()
    if x.allow_file_private_ops: private_ops.register(FilePrivateOperator())
    if x.private_ops_url:
        private_ops.register(HTTPSPrivateOperator.mtls(x.private_ops_url,ca_file=x.private_ops_ca,cert_file=x.private_ops_cert,key_file=x.private_ops_key))
    high_assurance=not x.allow_file_private_ops
    if high_assurance and not x.private_ops_url:
        raise RemoteWorkerError('high-assurance remote execution requires a non-exporting private-operation provider')
    replay_anchor=None
    if x.replay_anchor_url:
        replay_anchor=HTTPSNonceAnchor.mtls(x.replay_anchor_url,ca_file=x.replay_anchor_ca,cert_file=x.replay_anchor_cert,key_file=x.replay_anchor_key)
    elif not x.allow_local_replay_only:
        raise RemoteWorkerError('high-assurance remote execution requires an independent replay anchor; use --allow-local-replay-only only for standard/development deployments')
    replay=ReplayGuard(x.replay_state).init().claim(
        admission['session_id'],admission['sequence'],admission['message_id'],admission['expires_at'],
        project_id=policy['project_id'],anchor=replay_anchor,require_anchor=not x.allow_local_replay_only)
    env=_json_bytes(env_bytes,'task envelope');payload,dec_witness=decrypt_for_custody(worker_transport_ref,worker_transport_public,env,aad=aad,registry=private_ops,high_assurance=high_assurance)
    if len(payload)>MAX_DECRYPTED_TASK_BYTES:raise RemoteWorkerError('decrypted remote task exceeds bound')
    task=_json_bytes(payload,'remote task')
    if task.get('capability')!=approval['capability'] or task.get('operation')!=approval['operation']:raise RemoteWorkerError('decrypted task exceeds authority approval')
    operands,portable=validate_task(task,return_key_id=public_key_id(Path(x.return_public)))
    result=run_eval(task,Path(x.server_key),x.provider_id)
    body={'schema':RESULT_SCHEMA,'project_id':policy['project_id'],'policy_id':policy['policy_id'],'trust_policy_digest':policy['_meta']['digest'],'request_id':task['request_id'],'capability':task['capability'],'operation':task['operation'],'fhe_key_id':task['fhe_key_id'],'result_ciphertext':result['ciphertext'],'metrics':result['metrics'],'evaluator_wall_ms':result['evaluator_wall_ms'],'evaluator_image_id':result['evaluator_image_id'],'provider_id':result['provider_id'],'accelerator_profile':result['accelerator_profile'],'evaluator_has_client_secret':False,'transport_recipient_key_id':env['recipient_key_id'],'portable_task_digest':portable.get('digest'),'sender_key_id':admission['sender_key_id'],'authority_key_id':approval['authority_key_id'],'admission_sha256':tagged_sha256(admission_canonical({k:v for k,v in admission.items() if k!='signature'})),'replay_claim':replay,'worker_id':x.worker_id,'worker_key_id':identity_key_id(worker_public),'worker_signature_algorithm':HIGH_ASSURANCE_ALGORITHM,'authority':False}
    try: sig,sig_ev=private_ops.sign(worker_signing_ref,admission_canonical(body),algorithm=HIGH_ASSURANCE_ALGORITHM,high_assurance=high_assurance)
    except PrivateOpsError as exc: raise RemoteWorkerError('worker result signing custody operation failed') from exc
    body['worker_signature']=base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')
    out_env,enc_witness=encrypt_for(x.return_public,(json.dumps(body,sort_keys=True,separators=(',',':'))+'\n').encode(),aad=aad,pad_to=4096)
    atomic_write(Path(x.out),(json.dumps(out_env,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
    witness={'schema':'XAVI-DUO/REMOTE-FHE-WORKER-WITNESS/v3','project_id':policy['project_id'],'policy_id':policy['policy_id'],'trust_policy_digest':policy['_meta']['digest'],'request_id':task['request_id'],'task_envelope_sha256':hashlib.sha256(env_bytes).hexdigest(),'result_envelope_sha256':hashlib.sha256((json.dumps(out_env,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),'transport_decrypt':dec_witness,'transport_encrypt':enc_witness,'sender_admission':{k:v for k,v in admission.items() if k!='signature'},'authority_approval':{k:v for k,v in approval.items() if k!='signature'},'replay_claim':replay,'worker_signature_evidence':sig_ev,'worker_key_id':body['worker_key_id'],'evaluator_image_id':result['evaluator_image_id'],'provider_id':result['provider_id'],'accelerator_profile':result['accelerator_profile'],'evaluator_has_client_secret':False,'portable_task_digest':portable.get('digest'),'authority':False}
    if x.witness:atomic_write(Path(x.witness),(json.dumps(witness,indent=2,sort_keys=True)+'\n').encode(),0o600)
    print(json.dumps({'status':'PASS','project_id':policy['project_id'],'request_id':task['request_id'],'out':x.out,'provider_id':result['provider_id'],'evaluator_image_id':result['evaluator_image_id'],'worker_key_id':body['worker_key_id'],'authority':False},sort_keys=True))

if __name__=='__main__':main()
