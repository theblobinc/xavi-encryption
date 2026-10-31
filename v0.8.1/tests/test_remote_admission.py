import tempfile,time,unittest
from pathlib import Path
from xavi_duo_identity import keygen,HIGH_ASSURANCE_ALGORITHM
from xavi_duo_remote_admission import create_admission,verify_admission,create_authority_approval,verify_authority_approval,AdmissionError
from xavi_duo_replay import ReplayGuard,ReplayError
class RemoteAdmissionTests(unittest.TestCase):
 def test_signed_authority_replay_chain(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); keygen(p/'s.pem',p/'s.pub',algorithm=HIGH_ASSURANCE_ALGORITHM); keygen(p/'a.pem',p/'a.pub',algorithm=HIGH_ASSURANCE_ALGORITHM)
   task=b'{"sealed":true}'; now=int(time.time())
   adm=create_admission(p/'s.pem',p/'s.pub',task,project_id='project-a',session_id='sess',sequence=1,message_id='m1',aad=b'ctx',issued_at=now,expires_at=now+300)
   verify_admission(adm,p/'s.pub',task,b'ctx',now=now)
   app=create_authority_approval(p/'a.pem',p/'a.pub',adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='prod3',issued_at=now,expires_at=now+240)
   verify_authority_approval(app,p/'a.pub',adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='prod3',now=now)
   rg=ReplayGuard(p/'replay.json').init(); rg.claim('sess',1,'m1',now+300)
   with self.assertRaises(ReplayError): rg.claim('sess',1,'m1',now+300)
   bad=dict(adm); bad['task_envelope_bytes']+=1
   with self.assertRaises(AdmissionError): verify_admission(bad,p/'s.pub',task,b'ctx',now=now)
 def test_authority_cannot_expand_provider_or_operation(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); keygen(p/'s.pem',p/'s.pub',algorithm=HIGH_ASSURANCE_ALGORITHM); keygen(p/'a.pem',p/'a.pub',algorithm=HIGH_ASSURANCE_ALGORITHM)
   task=b'abc'; now=int(time.time()); adm=create_admission(p/'s.pem',p/'s.pub',task,project_id='project-a',session_id='s',sequence=1,message_id='m',aad=b'',issued_at=now,expires_at=now+300)
   app=create_authority_approval(p/'a.pem',p/'a.pub',adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='prod3',issued_at=now,expires_at=now+200)
   with self.assertRaises(AdmissionError): verify_authority_approval(app,p/'a.pub',adm,capability='fhe.boolean',operation='other',provider_id='tfhe-cuda-evaluator',worker_id='prod3',now=now)
   with self.assertRaises(AdmissionError): verify_authority_approval(app,p/'a.pub',adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='other',worker_id='prod3',now=now)
if __name__=='__main__': unittest.main()
