#!/usr/bin/env python3
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'compute/xavi-void/src'))
from xavi_void.runtime.tfhe_split import TFHEClientCryptoSidecar, TFHEEvaluatorSidecarBackend, SplitTFHEBackend, assert_remote_safe_evaluator

IMAGE=os.environ.get('XAVI_TFHE_IMAGE','localhost/xavi-void-tfhe-split:1.2-dev5')
CLIENT_DIR=Path(os.environ['XAVI_TFHE_CLIENT_DIR']).resolve(); EVAL_DIR=Path(os.environ['XAVI_TFHE_EVAL_DIR']).resolve()
CLIENT_DIR.mkdir(parents=True,exist_ok=True);EVAL_DIR.mkdir(parents=True,exist_ok=True);CLIENT_DIR.chmod(0o700);EVAL_DIR.chmod(0o700)
uid=os.getuid();gid=os.getgid()
base=['podman','run','--rm','-i','--userns=keep-id','--user',f'{uid}:{gid}','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','128','--memory','1g','--cpus','2']
client_cmd=base+['-v',f'{CLIENT_DIR}:/keys:rw','--entrypoint','/usr/local/bin/xvoid-tfhe-client',IMAGE,'--key-dir','/keys']
client=TFHEClientCryptoSidecar(client_cmd)
server=client.export_server_key(); server_path=EVAL_DIR/'server-key.bin'; server_path.write_bytes(server); os.chmod(server_path,0o644)
eval_cmd=base+['-v',f'{EVAL_DIR}:/keys:ro','--entrypoint','/usr/local/bin/xvoid-tfhe-evaluator',IMAGE,'--server-key','/keys/server-key.bin','--device','cpu']
evaluator=TFHEEvaluatorSidecarBackend(eval_cmd);assert_remote_safe_evaluator(evaluator)
bridge=SplitTFHEBackend(client,evaluator)

def gate_and(*vals):
    c=[bridge.encrypt_bit(bool(v)) for v in vals]; out=c[0]
    for v in c[1:]:out=bridge.bit_and(out,v)
    return bridge.decrypt_bit(out)

def execute(r):
    op=r.get('op')
    if op=='capabilities':
        ec=evaluator.capabilities
        return {'provider':'tfhe','role':'trusted-client-orchestrator','cryptographic':True,'client_has_secret':True,'evaluator_role':ec.role,'evaluator_has_client_secret':ec.has_client_secret,'key_id':ec.key_id,'device':ec.device,'server_key_bytes':len(server),'supports_boolean':ec.supports_boolean,'supports_word64':ec.supports_word64,'supports_oblivious_select':ec.supports_oblivious_select,'supports_keccak24':ec.supports_keccak24,'supports_metrics':ec.supports_metrics}
    if op=='rnn_route_gate': return {'value':gate_and(r['route_enabled'],r['capacity_ok'])}
    if op=='sfm_witness_gate':
        evidence=bridge.encrypt_bit(bool(r['evidence_valid'])); authority=bridge.encrypt_bit(bool(r['authority_allowed'])); override=bridge.encrypt_bit(bool(r.get('override',False)))
        return {'value':bridge.decrypt_bit(bridge.bit_or(bridge.bit_and(evidence,authority),override))}
    if op=='srnn_release_gate': return {'value':gate_and(r['candidate_valid'],r['no_conflict'],r['integrity_ok'])}
    if op=='word_eq':
        a=bridge.encrypt_word64(int(r['left']));b=bridge.encrypt_word64(int(r['right']));return {'value':bridge.decrypt_bit(bridge.word_eq(a,b))}
    if op=='word_xor':
        a=bridge.encrypt_word64(int(r['left']));b=bridge.encrypt_word64(int(r['right']));return {'value':str(bridge.decrypt_word64(bridge.word_xor(a,b)))}
    if op=='metrics': return bridge.metrics()
    if op=='close': return {'closed':True}
    raise ValueError('unknown op')

try:
    for line in sys.stdin:
        try:
            r=json.loads(line);t=time.perf_counter_ns();out=execute(r);elapsed=time.perf_counter_ns()-t
            if isinstance(out,dict) and r.get('op') not in {'capabilities','metrics','close'}:out={**out,'wall_ns':elapsed}
            print(json.dumps({'ok':True,'result':out},separators=(',',':')),flush=True)
            if r.get('op')=='close':break
        except Exception as e:print(json.dumps({'ok':False,'error':f'{type(e).__name__}: {e}'},separators=(',',':')),flush=True)
finally:
    try:bridge.close()
    except Exception:pass
