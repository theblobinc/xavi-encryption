#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,json,os,shutil,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'compute/xavi-void/src'));sys.path.insert(0,str(ROOT))
from xavi_void.runtime.tfhe_split import TFHEClientCryptoSidecar
from mlkem_provider import keygen as mlkem_keygen
from xavi_duo_pq import encrypt_for,decrypt_for
from xavi_duo_identity import keygen as identity_keygen,public_key_id as identity_key_id,verify,HIGH_ASSURANCE_ALGORITHM
from xavi_duo_remote_admission import create_admission,create_authority_approval,canonical as admission_canonical

TASK_SCHEMA='XAVI-DUO/REMOTE-FHE-TASK/v1'
RESULT_SCHEMA='XAVI-DUO/REMOTE-FHE-RESULT/v3'
PORTABLE_SCHEMA='xavi-encrypted-polymorphic-task/v1'
IMAGE='localhost/xavi-void-tfhe-split:1.2-dev5'
EVALUATOR_IMAGE_ID='2ea9e686f6c3a8df005791247ab64115087a606efbaf046af6f9e0f05fe6152e'

def canonical(v):
 if isinstance(v,list):return [canonical(x) for x in v]
 if isinstance(v,dict):return {k:canonical(v[k]) for k in sorted(v)}
 return v
def digest(v):return hashlib.sha256(json.dumps(canonical(v),separators=(',',':')).encode()).hexdigest()
def public_key_id(path:Path):return 'sha256:'+hashlib.sha256(path.read_bytes()).hexdigest()
def b64d(s):return base64.urlsafe_b64decode(str(s)+'='*(-len(str(s))%4))

def client(keydir:Path):
 uid=os.getuid();gid=os.getgid();keydir.mkdir(parents=True,exist_ok=True);keydir.chmod(0o700)
 cmd=['podman','run','--rm','-i','--userns=keep-id','--user',f'{uid}:{gid}','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','128','--memory','1g','--cpus','2','-v',f'{keydir}:/keys:rw','--entrypoint','/usr/local/bin/xvoid-tfhe-client',IMAGE,'--key-dir','/keys']
 return TFHEClientCryptoSidecar(cmd)

def ensure_identity(root:Path,name:str):
 root.mkdir(parents=True,exist_ok=True);root.chmod(0o700);priv=root/(name+'.pem');pub=root/(name+'.pub')
 if not priv.exists(): identity_keygen(priv,pub,algorithm=HIGH_ASSURANCE_ALGORITHM)
 return priv,pub

def prepare(shared:Path,state:Path,recipient_public:Path,worker_public:Path,aad:str,project_id:str,policy_id:str,worker_id:str,provider_id:str):
 shared.mkdir(parents=True,exist_ok=True);state.mkdir(parents=True,exist_ok=True);state.chmod(0o700)
 tfdir=state/'tfhe-client';ret=state/'return-mlkem';ret.mkdir(exist_ok=True);ret.chmod(0o700)
 if not (ret/'private.pem').exists(): mlkem_keygen(ret/'private.pem',ret/'public.pem')
 sender_priv,sender_pub=ensure_identity(state/'identity','sender'); authority_priv,authority_pub=ensure_identity(state/'identity','authority')
 c=client(tfdir)
 try:
  caps=c.capabilities;server=c.export_server_key();vals={'evidence_valid':True,'authority_allowed':False,'override':True};cts={k:base64.b64encode(c.encrypt_bit(v)).decode() for k,v in vals.items()}
 finally:c.close()
 server_path=shared/'server-key.bin';server_path.write_bytes(server);os.chmod(server_path,0o644)
 for src,name in [(ret/'public.pem','return-public.pem'),(sender_pub,'sender.pub'),(authority_pub,'authority.pub'),(worker_public,'worker.pub')]: shutil.copy2(src,shared/name);os.chmod(shared/name,0o644)
 request_id=f'pq-fhe-v07-{time.time_ns()}'
 inputs_digest='sha256:'+hashlib.sha256(json.dumps(canonical(cts),separators=(',',':')).encode()).hexdigest()
 portable_body={'schema':PORTABLE_SCHEMA,'requestId':request_id,'kind':'worker','capability':'fhe.boolean','imageDigest':'sha256:'+EVALUATOR_IMAGE_ID,'modelDigest':None,'entrypoint':'sfm-witness-gate','inputDigest':inputs_digest,'resourceClass':'fhe-gpu-bounded','returnKeyId':public_key_id(ret/'public.pem'),'authority':False}
 portable={**portable_body,'digest':digest(portable_body)}
 task={'schema':TASK_SCHEMA,'request_id':request_id,'capability':'fhe.boolean','operation':'sfm-witness-gate','fhe_key_id':caps.key_id,'ciphertexts':cts,'expected':True,'portable_task':portable,'authority':False}
 env,witness=encrypt_for(recipient_public,(json.dumps(task,sort_keys=True,separators=(',',':'))+'\n').encode(),aad=aad.encode(),pad_to=4096)
 env_bytes=(json.dumps(env,sort_keys=True,separators=(',',':'))+'\n').encode();(shared/'task.pq2').write_bytes(env_bytes);os.chmod(shared/'task.pq2',0o600)
 admission=create_admission(sender_priv,sender_pub,env_bytes,project_id=project_id,session_id='remote-fhe-v07',sequence=1,message_id=request_id,aad=aad.encode(),expires_at=int(time.time())+600)
 approval=create_authority_approval(authority_priv,authority_pub,admission,capability='fhe.boolean',operation='sfm-witness-gate',provider_id=provider_id,worker_id=worker_id,expires_at=min(admission['expires_at'],int(time.time())+540))
 (shared/'task.admission.json').write_text(json.dumps(admission,sort_keys=True,separators=(',',':'))+'\n');(shared/'task.authority.json').write_text(json.dumps(approval,sort_keys=True,separators=(',',':'))+'\n')
 (shared/'task.transport.witness.json').write_text(json.dumps(witness,indent=2,sort_keys=True)+'\n')
 meta={'schema':'XAVI-DUO/PQ-FHE-REMOTE-CLIENT/v2','project_id':project_id,'policy_id':policy_id,'worker_id':worker_id,'provider_id':provider_id,'worker_key_id':identity_key_id(worker_public),'sender_key_id':identity_key_id(sender_pub),'authority_key_id':identity_key_id(authority_pub),'request_id':request_id,'fhe_key_id':caps.key_id,'expected':True,'aad':aad,'task_envelope_sha256':hashlib.sha256(env_bytes).hexdigest(),'portable_task_digest':portable['digest'],'portable_input_digest':inputs_digest,'server_key_sha256':hashlib.sha256(server).hexdigest(),'server_key_bytes':len(server),'tfhe_client_secret_shared':False,'transport_private_key_shared':False,'authority':False}
 (state/'meta.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n');print(json.dumps({'status':'PREPARED',**meta},sort_keys=True))

def finish(shared:Path,state:Path,out:Path):
 meta=json.loads((state/'meta.json').read_text());env=json.loads((shared/'result.pq2').read_text());body,witness=decrypt_for(state/'return-mlkem/private.pem',env,aad=meta['aad'].encode());result=json.loads(body)
 if result.get('schema')!=RESULT_SCHEMA or result.get('request_id')!=meta['request_id'] or result.get('authority') is not False:raise RuntimeError('result binding failure')
 if result.get('project_id')!=meta['project_id'] or result.get('policy_id')!=meta['policy_id'] or result.get('provider_id')!=meta['provider_id'] or result.get('worker_id')!=meta['worker_id']:raise RuntimeError('result project/policy/provider binding failure')
 if result.get('worker_key_id')!=meta['worker_key_id'] or result.get('worker_signature_algorithm')!=HIGH_ASSURANCE_ALGORITHM:raise RuntimeError('worker identity binding failure')
 sig=b64d(result['worker_signature']);unsigned={k:v for k,v in result.items() if k!='worker_signature'}
 if not verify(shared/'worker.pub',admission_canonical(unsigned),sig,algorithm=HIGH_ASSURANCE_ALGORITHM):raise RuntimeError('worker result signature verification failed')
 c=client(state/'tfhe-client')
 try:value=c.decrypt_bit(base64.b64decode(result['result_ciphertext'],validate=True));caps=c.capabilities
 finally:c.close()
 status='PASS' if value is meta['expected'] and caps.key_id==meta['fhe_key_id'] and result.get('evaluator_has_client_secret') is False else 'FAIL'
 row={'schema':'XAVI-DUO/PQ-FHE-REMOTE-TRANSPORT-VALIDATION/v2','status':status,'project_id':meta['project_id'],'policy_id':meta['policy_id'],'request_id':meta['request_id'],'transport':'XDE2-PQ2/ML-KEM-1024','admission_identity':'ML-DSA-87','authority_identity':'ML-DSA-87','worker_result_identity':'ML-DSA-87','fhe':'TFHE CUDA','client_node':'prod4','evaluator_node':'prod3','fhe_result':value,'expected':meta['expected'],'fhe_key_id':meta['fhe_key_id'],'worker_key_id':result.get('worker_key_id'),'sender_key_id':result.get('sender_key_id'),'authority_key_id':result.get('authority_key_id'),'trust_policy_digest':result.get('trust_policy_digest'),'provider_id':result.get('provider_id'),'accelerator_profile':result.get('accelerator_profile'),'evaluator_image_id':result.get('evaluator_image_id'),'evaluator_wall_ms':result.get('evaluator_wall_ms'),'tfhe_client_secret_only_in_client':True,'transport_private_keys_node_local':True,'server_key_bytes':meta['server_key_bytes'],'task_envelope_sha256':meta['task_envelope_sha256'],'portable_task_digest':meta['portable_task_digest'],'portable_input_digest':meta['portable_input_digest'],'result_envelope_sha256':hashlib.sha256((shared/'result.pq2').read_bytes()).hexdigest(),'return_transport_witness':witness,'authority':False}
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(row,indent=2,sort_keys=True)+'\n');print(json.dumps(row,sort_keys=True))
 if status!='PASS':raise SystemExit(1)

def main():
 a=argparse.ArgumentParser();a.add_argument('mode',choices=['prepare','finish']);a.add_argument('--shared',required=True);a.add_argument('--state',required=True);a.add_argument('--recipient-public');a.add_argument('--worker-public');a.add_argument('--project-id',default='xavi-duo-v07-security-validation');a.add_argument('--policy-id',default='v07-high-assurance-test');a.add_argument('--worker-id',default='prod3');a.add_argument('--provider-id',default='tfhe-cuda-evaluator');a.add_argument('--aad',default='xavi-duo:remote-fhe-task:v2');a.add_argument('--out',default='validation/PQ_FHE_REMOTE_TRANSPORT_v0.7.json');x=a.parse_args()
 if x.mode=='prepare':
  if not x.recipient_public or not x.worker_public:raise SystemExit('--recipient-public and --worker-public required')
  prepare(Path(x.shared),Path(x.state),Path(x.recipient_public),Path(x.worker_public),x.aad,x.project_id,x.policy_id,x.worker_id,x.provider_id)
 else:finish(Path(x.shared),Path(x.state),Path(x.out))
if __name__=='__main__':main()
