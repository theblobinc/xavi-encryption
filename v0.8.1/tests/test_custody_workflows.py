import base64,json,tempfile,time,unittest
from pathlib import Path
from xavi_duo_identity import keygen,sign,verify,HIGH_ASSURANCE_ALGORITHM
from xavi_duo_private_ops import PrivateOpsRegistry,CallbackPrivateOperator
from xavi_duo_remote_admission import create_admission_custody,verify_admission,create_authority_approval_custody,verify_authority_approval
from xavi_duo_release import sign_manifest_custody,verify_manifest

class CustodyWorkflowTests(unittest.TestCase):
    def make_operator(self,priv,scheme='authority'):
        def cb(op,ref,payload,algorithm):
            if op!='sign': raise RuntimeError('unexpected op')
            sig,_=sign(priv,payload,algorithm=algorithm)
            return {'status':'PASS','algorithm':algorithm,'reference':ref.raw,'signature':base64.b64encode(sig).decode()}
        return PrivateOpsRegistry().register(CallbackPrivateOperator(cb,schemes=frozenset({scheme}),external_authority=True))
    def test_admission_and_authority_can_sign_without_private_path_api(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); sp=p/'s.pem'; su=p/'s.pub'; ap=p/'a.pem'; au=p/'a.pub'
            keygen(sp,su,algorithm=HIGH_ASSURANCE_ALGORITHM);keygen(ap,au,algorithm=HIGH_ASSURANCE_ALGORITHM)
            task=b'ciphertext-envelope';aad=b'aad';now=int(time.time())
            adm=create_admission_custody('authority://sender/key',su,task,project_id='p',session_id='s',sequence=1,message_id='m',aad=aad,registry=self.make_operator(sp),issued_at=now,expires_at=now+120)
            verify_admission(adm,su,task,aad,now=now+1)
            appr=create_authority_approval_custody('authority://approver/key',au,adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='w',registry=self.make_operator(ap),issued_at=now,expires_at=now+120)
            verify_authority_approval(appr,au,adm,capability='fhe.boolean',operation='sfm-witness-gate',provider_id='tfhe-cuda-evaluator',worker_id='w',now=now+1)
    def test_release_signing_uses_custody_operator(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);priv=p/'r.pem';pub=p/'r.pub';manifest=p/'manifest.json';out=p/'sig.json'
            keygen(priv,pub,algorithm=HIGH_ASSURANCE_ALGORITHM);manifest.write_text(json.dumps({'version':'0.8.0','artifact':'x'}))
            sign_manifest_custody('authority://release/key',pub,manifest,out,registry=self.make_operator(priv))
            self.assertEqual(verify_manifest(pub,manifest,out)['status'],'PASS')
if __name__=='__main__':unittest.main()
