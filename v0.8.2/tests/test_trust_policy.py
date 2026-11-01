import json,os,tempfile,unittest
from pathlib import Path
from xavi_duo_identity import public_key_id
from xavi_duo_trust import load_policy,resolve_sender,resolve_authority,resolve_worker,authorize,assert_project,TrustPolicyError

class TrustPolicyTests(unittest.TestCase):
 def make(self,p):
  # Trust-policy tests exercise file identity, permissions, scoping, and key-ID binding.
  # Real ML-DSA key generation/sign/verify is covered by dedicated identity/admission tests.
  for i,n in enumerate(('sender','authority','worker','transport'),1):
   priv=p/(n+'.pem'); pub=p/(n+'.pub')
   priv.write_bytes((f'test-private-{n}-{i}\n').encode()); priv.chmod(0o600)
   pub.write_bytes((f'test-public-{n}-{i}\n').encode()); pub.chmod(0o644)
  sid=public_key_id(p/'sender.pub'); aid=public_key_id(p/'authority.pub')
  pol={'schema':'XAVI-DUO/TRUST-POLICY/v2','project_id':'project-a','policy_id':'policy-1',
       'senders':{sid:{'enabled':True,'public_key':str((p/'sender.pub').resolve()),'capabilities':['fhe.boolean'],'operations':['sfm-witness-gate'],'providers':['tfhe-cuda-evaluator']}},
       'authorities':{aid:{'enabled':True,'public_key':str((p/'authority.pub').resolve()),'capabilities':['fhe.boolean'],'operations':['sfm-witness-gate'],'providers':['tfhe-cuda-evaluator'],'workers':['prod3']}},
       'workers':{'prod3':{'enabled':True,'public_key':str((p/'worker.pub').resolve()),'signing_private_ref':(p/'worker.pem').resolve().as_uri(),'transport_public_key':str((p/'transport.pub').resolve()),'transport_private_ref':(p/'transport.pem').resolve().as_uri(),'providers':['tfhe-cuda-evaluator']}}}
  pp=p/'trust.json'; pp.write_text(json.dumps(pol,sort_keys=True,separators=(',',':'))+'\n'); pp.chmod(0o600)
  return pp,sid,aid
 def test_scoped_resolution(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); pp,sid,aid=self.make(p); pol=load_policy(pp)
   assert_project(pol,'project-a')
   sr,sp=resolve_sender(pol,sid); ar,ap=resolve_authority(pol,aid); wr,wp,wref,tp,tref=resolve_worker(pol,'prod3','tfhe-cuda-evaluator')
   self.assertEqual(sp,p/'sender.pub'); self.assertEqual(ap,p/'authority.pub'); self.assertEqual(wp,p/'worker.pub'); self.assertEqual(wref.scheme,'file'); self.assertEqual(Path(wref.name),p/'worker.pem'); self.assertEqual(tp,p/'transport.pub'); self.assertEqual(Path(tref.name),p/'transport.pem')
   self.assertTrue(authorize(sr,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',role='sender'))
   self.assertTrue(authorize(ar,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='prod3',role='authority'))
 def test_cross_project_and_scope_fail(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); pp,sid,aid=self.make(p); pol=load_policy(pp); sr,_=resolve_sender(pol,sid); ar,_=resolve_authority(pol,aid)
   with self.assertRaises(TrustPolicyError): assert_project(pol,'project-b')
   with self.assertRaises(TrustPolicyError): authorize(sr,capability='fhe.vector.approx',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',role='sender')
   with self.assertRaises(TrustPolicyError): authorize(ar,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='other',worker_id='prod3',role='authority')
   with self.assertRaises(TrustPolicyError): authorize(ar,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='prod4',role='authority')
 def test_key_substitution_and_policy_permissions_fail(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); pp,sid,aid=self.make(p); pol=json.loads(pp.read_text()); pol['senders'][sid]['public_key']=pol['authorities'][aid]['public_key']; pp.write_text(json.dumps(pol)); pp.chmod(0o600)
   loaded=load_policy(pp)
   with self.assertRaises(TrustPolicyError): resolve_sender(loaded,sid)
   pp.chmod(0o666)
   with self.assertRaises(TrustPolicyError): load_policy(pp)
if __name__=='__main__': unittest.main()
