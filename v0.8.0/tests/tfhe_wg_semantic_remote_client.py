#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, subprocess, time
from pathlib import Path

IMAGE='localhost/xavi-void-tfhe-split:1.2-dev5'

def sha(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def start_client(keydir:Path):
    a=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-v',f'{keydir}:/keys:rw','--entrypoint','/usr/local/bin/xvoid-tfhe-client',IMAGE,'--key-dir','/keys']
    return subprocess.Popen(a,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)

def q(p,o):
    p.stdin.write(json.dumps(o,separators=(',',':'))+'\n'); p.stdin.flush(); line=p.stdout.readline()
    if not line: raise RuntimeError(p.stderr.read())
    r=json.loads(line)
    if not r.get('ok'): raise RuntimeError(r.get('error'))
    return r['result']

def close(p):
    if p.poll() is None:
        try:q(p,{'op':'close'})
        except Exception:pass
        try:p.wait(timeout=20)
        except subprocess.TimeoutExpired:p.kill()

def prepare(shared:Path,keydir:Path):
    shared.mkdir(parents=True,exist_ok=True)
    for n in ('request.ndjson','response.ndjson','remote-evaluator.json','TRANSFER_MANIFEST.json'):
        try:(shared/n).unlink()
        except FileNotFoundError:pass
    (shared/'keys').mkdir(exist_ok=True)
    # Representative trusted WG client values. Remote evaluator must never see plaintext.
    bits={
      'evidence_valid':True,
      'authority_allowed':False,
      'override':True,
      'candidate_valid':True,
      'no_conflict':True,
      'integrity_ok':False,
      'reflection_select':True,
    }
    words={
      'type_left':0xA5A5A5A5A5A5A5A5,
      'type_right':0xA5A5A5A5A5A5A5A5,
      'typed_good':0x1122334455667788,
      'typed_bad':0xDEADBEEFCAFEBABE,
    }
    c=start_client(keydir)
    try:
        cap=q(c,{'op':'capabilities'}); assert cap['has_client_secret'] is True
        enc_bits={k:q(c,{'op':'encrypt_bit','value':v}) for k,v in bits.items()}
        enc_words={k:q(c,{'op':'encrypt_word64','value':v}) for k,v in words.items()}
    finally: close(c)
    server=keydir/'server-key.bin'
    if not server.exists(): raise RuntimeError('missing server-key.bin')
    # Copy evaluation key only. Never copy client-key.bin.
    import shutil
    shutil.copy2(server,shared/'keys'/'server-key.bin')
    assert not (shared/'keys'/'client-key.bin').exists()
    req=[{'op':'capabilities'}]
    # Handles h1..h7 bits, h8..h11 words.
    for k in ('evidence_valid','authority_allowed','override','candidate_valid','no_conflict','integrity_ok','reflection_select'):
        req.append({'op':'import_ciphertext','kind':'bit','data':enc_bits[k]['data']})
    for k in ('type_left','type_right','typed_good','typed_bad'):
        req.append({'op':'import_ciphertext','kind':'word64','data':enc_words[k]['data']})
    req += [
      # WG-SFM witness gate: (evidence_valid AND authority_allowed) OR override
      {'op':'bit_and','left':'h1','right':'h2'},                    # h12
      {'op':'bit_or','left':'h12','right':'h3'},                   # h13
      # WG-SFM typed selection: equal types choose typed_good, else typed_bad
      {'op':'word_eq','left':'h8','right':'h9'},                   # h14
      {'op':'word_mux','selector':'h14','when_true':'h10','when_false':'h11'}, # h15
      # WG-SRNN release gate: candidate_valid AND no_conflict AND integrity_ok
      {'op':'bit_and','left':'h4','right':'h5'},                   # h16
      {'op':'bit_and','left':'h16','right':'h6'},                  # h17
      # Reconsideration signal and encrypted arbitration/reflection selection.
      {'op':'bit_not','value':'h17'},                              # h18
      {'op':'bit_mux','selector':'h7','when_true':'h13','when_false':'h18'},   # h19
      {'op':'word_mux','selector':'h7','when_true':'h15','when_false':'h11'},  # h20
      {'op':'export_ciphertext','handle':'h13','kind':'bit'},
      {'op':'export_ciphertext','handle':'h14','kind':'bit'},
      {'op':'export_ciphertext','handle':'h15','kind':'word64'},
      {'op':'export_ciphertext','handle':'h17','kind':'bit'},
      {'op':'export_ciphertext','handle':'h18','kind':'bit'},
      {'op':'export_ciphertext','handle':'h19','kind':'bit'},
      {'op':'export_ciphertext','handle':'h20','kind':'word64'},
      {'op':'metrics'},
      {'op':'close'},
    ]
    (shared/'request.ndjson').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in req))
    expected={
      'sfm_witness_gate':(bits['evidence_valid'] and bits['authority_allowed']) or bits['override'],
      'sfm_type_equal':words['type_left']==words['type_right'],
      'sfm_typed_selection':str(words['typed_good']),
      'srnn_release_gate':bits['candidate_valid'] and bits['no_conflict'] and bits['integrity_ok'],
      'srnn_reconsideration':not (bits['candidate_valid'] and bits['no_conflict'] and bits['integrity_ok']),
      'srnn_arbitration':True,
      'srnn_reflection_selection':str(words['typed_good']),
    }
    meta={'schema':'XAVI-DUO/REMOTE-TFHE-WG-SEMANTICS/v1','created_ns':time.time_ns(),'client_node':'prod4','evaluator_node':'prod3','key_id':cap['key_id'],'expected':expected,'request_sha256':sha(shared/'request.ndjson'),'server_key_sha256':sha(shared/'keys'/'server-key.bin'),'server_key_bytes':(shared/'keys'/'server-key.bin').stat().st_size,'client_secret_shared':False}
    (shared/'TRANSFER_MANIFEST.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'PREPARED',**meta},sort_keys=True))

def finish(shared:Path,keydir:Path,out:Path):
    meta=json.loads((shared/'TRANSFER_MANIFEST.json').read_text())
    expected=dict(meta['expected']); expected['sfm_typed_selection']=str(expected['sfm_typed_selection']); expected['srnn_reflection_selection']=str(expected['srnn_reflection_selection'])
    rows=[json.loads(x) for x in (shared/'response.ndjson').read_text().splitlines() if x.strip()]
    if len(rows)!=30: raise RuntimeError(f'expected 30 responses got {len(rows)}')
    for i,r in enumerate(rows):
        if not r.get('ok'): raise RuntimeError(f"response {i}: {r.get('error')}")
    cap=rows[0]['result']; assert cap['role']=='evaluator' and cap['has_client_secret'] is False and cap['key_id']==meta['key_id']
    # Exports are rows 21..27 (0-based after 1 cap + 11 imports + 9 semantic ops).
    blobs=[rows[i]['result']['data'] for i in range(21,28)]
    metrics=rows[28]['result']
    c=start_client(keydir)
    try:
        cc=q(c,{'op':'capabilities'}); assert cc['key_id']==meta['key_id']
        vals={
          'sfm_witness_gate':q(c,{'op':'decrypt_bit','data':blobs[0]})['value'],
          'sfm_type_equal':q(c,{'op':'decrypt_bit','data':blobs[1]})['value'],
          'sfm_typed_selection':str(q(c,{'op':'decrypt_word64','data':blobs[2]})['value']),
          'srnn_release_gate':q(c,{'op':'decrypt_bit','data':blobs[3]})['value'],
          'srnn_reconsideration':q(c,{'op':'decrypt_bit','data':blobs[4]})['value'],
          'srnn_arbitration':q(c,{'op':'decrypt_bit','data':blobs[5]})['value'],
          'srnn_reflection_selection':str(q(c,{'op':'decrypt_word64','data':blobs[6]})['value']),
        }
    finally: close(c)
    remote=json.loads((shared/'remote-evaluator.json').read_text())
    status='PASS' if vals==expected else 'FAIL'
    result={'schema':'XAVI-DUO/REMOTE-TFHE-WG-SEMANTICS-VALIDATION/v1','status':status,'client_node':'prod4','evaluator_node':'prod3','device':'cuda','key_id':meta['key_id'],'results':vals,'expected':expected,'client_secret_only_in_client':True,'evaluator_has_client_secret':False,'server_key_bytes':meta['server_key_bytes'],'remote_wall_ms':remote['wall_ms'],'image_id':remote['image_id'],'metrics':metrics,'authority':False}
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n'); print(json.dumps(result,sort_keys=True))
    if status!='PASS': raise SystemExit(1)

def main():
    a=argparse.ArgumentParser(); a.add_argument('mode',choices=['prepare','finish']); a.add_argument('--shared',required=True); a.add_argument('--client-key-dir',required=True); a.add_argument('--out',default='validation/xavi-cluster/REMOTE_TFHE_WG_SEMANTICS_PROD3_v0.5.json'); x=a.parse_args()
    prepare(Path(x.shared),Path(x.client_key_dir)) if x.mode=='prepare' else finish(Path(x.shared),Path(x.client_key_dir),Path(x.out))
if __name__=='__main__': main()
