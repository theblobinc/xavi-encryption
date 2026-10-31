#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,shutil,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IMAGE='localhost/xavi-void-tfhe-split:1.2-dev5'

def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()

def start_client(keydir):
 a=['podman','run','--rm','-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','2g','--cpus','2','-v',f'{keydir}:/keys:rw','--entrypoint','/usr/local/bin/xvoid-tfhe-client',IMAGE,'--key-dir','/keys']
 return subprocess.Popen(a,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
def q(p,o):
 p.stdin.write(json.dumps(o,separators=(',',':'))+'\n');p.stdin.flush();line=p.stdout.readline()
 if not line:raise RuntimeError(p.stderr.read())
 r=json.loads(line)
 if not r.get('ok'):raise RuntimeError(r.get('error'))
 return r['result']
def close(p):
 if p.poll() is None:
  try:q(p,{'op':'close'})
  except Exception:pass
  try:p.wait(timeout=20)
  except subprocess.TimeoutExpired:p.kill()
def rol64(v,n):
 n&=63;return ((v<<n)|(v>>(64-n if n else 64)))&((1<<64)-1) if n else v&((1<<64)-1)
def prepare(shared,state):
 shared=Path(shared);state=Path(state)
 for p in (shared,state):
  if p.exists():shutil.rmtree(p)
 shared.mkdir(parents=True);state.mkdir(parents=True);(state/'client').mkdir();(state/'client').chmod(0o777);(shared/'keys').mkdir()
 a=0x123456789ABCDEF0;b=0x0F0F0F0F0F0F0F0F;selector=True;secret_amount=7
 c=start_client(state/'client')
 try:
  cap=q(c,{'op':'capabilities'});assert cap['has_client_secret'] is True
  enc_a=q(c,{'op':'encrypt_word64','value':a});enc_b=q(c,{'op':'encrypt_word64','value':b});enc_s=q(c,{'op':'encrypt_bit','value':selector});enc_amt=q(c,{'op':'encrypt_word64','value':secret_amount})
 finally:close(c)
 shutil.copy2(state/'client'/'server-key.bin',shared/'keys'/'server-key.bin');assert not (shared/'keys'/'client-key.bin').exists()
 req=[
  {'op':'capabilities'},
  {'op':'import_ciphertext','kind':'word64','data':enc_a['data']},
  {'op':'import_ciphertext','kind':'word64','data':enc_b['data']},
  {'op':'import_ciphertext','kind':'bit','data':enc_s['data']},
  {'op':'import_ciphertext','kind':'word64','data':enc_amt['data']},
  {'op':'word_xor','left':'h1','right':'h2'},
  {'op':'word_and','left':'h1','right':'h2'},
  {'op':'word_rotl_public','value':'h5','amount':13},
  {'op':'word_rotl_secret','value':'h6','amount':'h4'},
  {'op':'word_mux','selector':'h3','when_true':'h7','when_false':'h8'},
  {'op':'bit_not','value':'h3'},
  {'op':'export_ciphertext','handle':'h9','kind':'word64'},
  {'op':'export_ciphertext','handle':'h10','kind':'bit'},
  {'op':'metrics'},
  {'op':'close'},
 ]
 (shared/'request.ndjson').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in req))
 expected_word=rol64(a^b,13) if selector else rol64(a&b,secret_amount)
 meta={'schema':'XAVI-DUO/REMOTE-TFHE-GPU/v1','created_ns':time.time_ns(),'client_node':'prod4','evaluator_node':'prod3','key_id':cap['key_id'],'expected_word':expected_word,'expected_bit':not selector,'request_sha256':sha(shared/'request.ndjson'),'server_key_sha256':sha(shared/'keys'/'server-key.bin'),'server_key_bytes':(shared/'keys'/'server-key.bin').stat().st_size,'client_secret_shared':False}
 (shared/'TRANSFER_MANIFEST.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n');(state/'meta.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'status':'PREPARED',**meta},sort_keys=True))
def finish(shared,state,out):
 shared=Path(shared);state=Path(state);meta=json.loads((state/'meta.json').read_text());rows=[json.loads(x) for x in (shared/'response.ndjson').read_text().splitlines() if x.strip()]
 if len(rows)!=15:raise RuntimeError(f'expected 15 responses got {len(rows)}')
 for i,r in enumerate(rows):
  if not r.get('ok'):raise RuntimeError(f'response {i}: {r.get("error")}')
 cap=rows[0]['result'];assert cap['role']=='evaluator' and cap['has_client_secret'] is False and cap['device']=='cuda' and cap['key_id']==meta['key_id']
 word_blob=rows[11]['result']['data'];bit_blob=rows[12]['result']['data'];metrics=rows[13]['result']
 c=start_client(state/'client')
 try:
  cc=q(c,{'op':'capabilities'});assert cc['key_id']==meta['key_id']
  word=q(c,{'op':'decrypt_word64','data':word_blob})['value'];bit=q(c,{'op':'decrypt_bit','data':bit_blob})['value']
 finally:close(c)
 remote=json.loads((shared/'remote-evaluator.json').read_text())
 status='PASS' if word==meta['expected_word'] and bit==meta['expected_bit'] else 'FAIL'
 result={'schema':'XAVI-DUO/REMOTE-TFHE-GPU-VALIDATION/v1','status':status,'client_node':'prod4','evaluator_node':'prod3','device':'cuda','key_id':meta['key_id'],'word_value':word,'expected_word':meta['expected_word'],'bit_value':bit,'expected_bit':meta['expected_bit'],'client_secret_only_in_client':True,'evaluator_has_client_secret':False,'server_key_bytes':meta['server_key_bytes'],'remote_wall_ms':remote['wall_ms'],'image_id':remote['image_id'],'metrics':metrics,'authority':False}
 Path(out).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True))
 if status!='PASS':raise SystemExit(1)
def main():
 a=argparse.ArgumentParser();a.add_argument('mode',choices=['prepare','finish']);a.add_argument('--shared',required=True);a.add_argument('--state',required=True);a.add_argument('--out',default='VALIDATION_REMOTE_TFHE_GPU_PROD3.json');x=a.parse_args();
 prepare(x.shared,x.state) if x.mode=='prepare' else finish(x.shared,x.state,x.out)
if __name__=='__main__':main()
