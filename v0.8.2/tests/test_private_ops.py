import base64,tempfile,unittest
from pathlib import Path
from xavi_duo_custody import parse_custody_ref
from xavi_duo_private_ops import PrivateOpsRegistry,FilePrivateOperator,CallbackPrivateOperator,PrivateOpsError
from xavi_duo_identity import keygen,verify

class PrivateOpsTests(unittest.TestCase):
    def test_file_operator_standard_only_and_real_signature(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);priv=root/'private.pem';pub=root/'public.pem';keygen(priv,pub,algorithm='ML-DSA-87')
            reg=PrivateOpsRegistry().register(FilePrivateOperator());ref=parse_custody_ref('file://'+str(priv))
            sig,ev=reg.sign(ref,b'msg',algorithm='ML-DSA-87',high_assurance=False)
            self.assertTrue(verify(pub,b'msg',sig,algorithm='ML-DSA-87'))
            self.assertFalse(ev['hardware_bound'])
            with self.assertRaisesRegex(PrivateOpsError,'high-assurance'):
                reg.sign(ref,b'msg',algorithm='ML-DSA-87',high_assurance=True)
    def test_nonexporting_callback_can_satisfy_high_assurance(self):
        def cb(op,ref,payload,algorithm):
            self.assertEqual(op,'sign');self.assertEqual(algorithm,'ML-DSA-87')
            return {'status':'PASS','algorithm':algorithm,'reference':ref.raw,'signature':base64.b64encode(b'sig').decode()}
        op=CallbackPrivateOperator(cb,schemes=frozenset({'authority'}),external_authority=True)
        reg=PrivateOpsRegistry().register(op);ref=parse_custody_ref('authority://signer/key1')
        sig,ev=reg.sign(ref,b'msg',algorithm='ML-DSA-87',high_assurance=True)
        self.assertEqual(sig,b'sig');self.assertTrue(ev['non_exporting_private_key'])
    def test_unconfigured_hardware_uri_fails_closed(self):
        reg=PrivateOpsRegistry().register(FilePrivateOperator())
        with self.assertRaisesRegex(PrivateOpsError,'no private-operation provider'):
            reg.sign(parse_custody_ref('tpm2://node/key'),b'x',algorithm='ML-DSA-87',high_assurance=True)
if __name__=='__main__':unittest.main()
