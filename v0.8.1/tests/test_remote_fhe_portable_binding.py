import base64,copy,hashlib,importlib.util,json,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'xavi_duo_remote_worker.py'
spec=importlib.util.spec_from_file_location('remote_fhe_worker',P);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class PortableBindingTests(unittest.TestCase):
 def task(self):
  c={k:base64.b64encode(bytes([i])).decode() for i,k in enumerate(('evidence_valid','authority_allowed','override'),1)}
  inp='sha256:'+hashlib.sha256(json.dumps(m.canonical(c),separators=(',',':')).encode()).hexdigest()
  b={'schema':m.PORTABLE_SCHEMA,'requestId':'r1','kind':'worker','capability':'fhe.boolean','imageDigest':'sha256:image1','modelDigest':None,'entrypoint':'sfm-witness-gate','inputDigest':inp,'resourceClass':'fhe-gpu-bounded','returnKeyId':'sha256:return1','authority':False}
  p={**b,'digest':m.digest(b)}
  return {'schema':m.TASK_SCHEMA,'request_id':'r1','capability':'fhe.boolean','operation':'sfm-witness-gate','fhe_key_id':'key1','ciphertexts':c,'portable_task':p,'authority':False}
 def test_binding_passes(self):
  operands,p=m.validate_task(self.task(),return_key_id='sha256:return1',image_id='image1');self.assertEqual(set(operands),{'evidence_valid','authority_allowed','override'});self.assertEqual(p['kind'],'worker')
 def test_digest_tamper_fails(self):
  t=self.task();t['portable_task']['entrypoint']='other';self.assertRaisesRegex(ValueError,'digest mismatch',m.validate_task,t)
 def test_input_tamper_fails(self):
  t=self.task();t['ciphertexts']['override']=base64.b64encode(b'x').decode();self.assertRaisesRegex(ValueError,'input commitment',m.validate_task,t)
 def test_image_and_return_key_fail_closed(self):
  t=self.task();self.assertRaisesRegex(ValueError,'image digest',m.validate_task,t,image_id='other');self.assertRaisesRegex(ValueError,'return-key',m.validate_task,t,return_key_id='sha256:other')
 def test_authority_escalation_fails(self):
  t=self.task();t['authority']=True;self.assertRaisesRegex(ValueError,'cannot grant authority',m.validate_task,t)

 def test_inline_ciphertext_bounds_fail_before_bulk_path(self):
  t=self.task(); t['ciphertexts']['evidence_valid']='A'*(m.MAX_CIPHERTEXT_B64_CHARS+4)
  with self.assertRaises(m.RemoteWorkerError): m.validate_task(t)

 def test_oversized_inline_ciphertext_rejected_before_decode(self):
  t=self.task(); t['ciphertexts']['evidence_valid']='A'*(m.MAX_CIPHERTEXT_B64_CHARS+4)
  with self.assertRaisesRegex(ValueError,'inline FHE ciphertext encoding exceeds bound'): m.validate_task(t)

 def test_total_inline_ciphertext_budget_rejected(self):
  # Use valid-size base64 strings that individually fit but together exceed the control-plane budget.
  raw=b'x'*(768*1024); enc=base64.b64encode(raw).decode()
  t=self.task(); t['ciphertexts']={k:enc for k in ('evidence_valid','authority_allowed','override')}
  # Refresh the portable input digest so the size fence, not commitment mismatch, is what fires.
  t['portable_task']['inputDigest']='sha256:'+hashlib.sha256(json.dumps(m.canonical(t['ciphertexts']),separators=(',',':')).encode()).hexdigest()
  body={k:v for k,v in t['portable_task'].items() if k!='digest'}; t['portable_task']['digest']=m.digest(body)
  with self.assertRaisesRegex(ValueError,'total inline FHE ciphertexts exceed control-plane bound'): m.validate_task(t)

 def test_image_mismatch_stops_before_evaluator_launch(self):
  t=self.task()
  with tempfile.TemporaryDirectory() as td:
   key=Path(td)/'server-key.bin';key.write_bytes(b'k')
   provider={'id':'tfhe-cuda-evaluator','image':'tag','image_id':'image1','remote_safe':True,'contains_client_secret':False,'accelerator_profile':'p','runtime_user':'10001:999','device':'cuda'}
   with patch.object(m,'get_provider',return_value=provider), patch.object(m,'resolve_provider_runtime',return_value={'available':False,'backend':'oci','error':'provider image ID is not allowlisted'}), patch.object(m.subprocess,'run') as run:
    self.assertRaisesRegex(ValueError,'no allowlisted provider implementation',m._resolve_provider,'tfhe-cuda-evaluator')
    run.assert_not_called()
 def test_valid_run_eval_builds_canonical_request(self):
  t=self.task()
  exported=base64.b64encode(b'cipher-result').decode()
  rows=[
   {'ok':True,'result':{'role':'evaluator','has_client_secret':False,'key_id':'key1'}},
   {'ok':True,'result':{'handle':'h1'}},{'ok':True,'result':{'handle':'h2'}},{'ok':True,'result':{'handle':'h3'}},
   {'ok':True,'result':{'handle':'h4'}},{'ok':True,'result':{'handle':'h5'}},
   {'ok':True,'result':{'data':exported}},{'ok':True,'result':{'operations':{}}},{'ok':True,'result':{'closed':True}},
  ]
  proc=SimpleNamespace(returncode=0,stdout=''.join(json.dumps(r)+'\n' for r in rows),stderr='')
  with tempfile.TemporaryDirectory() as td:
   key=Path(td)/'server-key.bin';key.write_bytes(b'k')
   provider={'id':'tfhe-cuda-evaluator','image':'tag','image_id':'image1','remote_safe':True,'contains_client_secret':False,'accelerator_profile':'p','runtime_user':'10001:999','device':'cuda'}
   profile={'id':'p'}
   with patch.object(m,'_resolve_provider',return_value=(provider,profile,'image1')), patch.object(m,'oci_security_args',return_value=['--read-only','--network','none']), patch.object(m.subprocess,'run',return_value=proc) as run:
    out=m.run_eval(t,key,'tfhe-cuda-evaluator')
    self.assertEqual(out['ciphertext'],exported);self.assertFalse(out['evaluator_has_client_secret']);self.assertEqual(out['evaluator_image_id'],'image1')
    sent=run.call_args.kwargs['input'].splitlines();req=[json.loads(x) for x in sent]
    self.assertEqual([r['op'] for r in req],['capabilities','import_ciphertext','import_ciphertext','import_ciphertext','bit_and','bit_or','export_ciphertext','metrics','close'])
if __name__=='__main__':unittest.main()
