import tempfile, unittest
from pathlib import Path
from xavi_duo_identity import keygen, sign, verify, actual_key_algorithm, IdentityError

class IdentityAlgorithmBindingTests(unittest.TestCase):
    def test_actual_parameter_set_and_downgrade_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); msg=b'parameter-set binding'
            pairs={}
            for alg in ('ML-DSA-44','ML-DSA-65','ML-DSA-87'):
                d=root/alg; d.mkdir(); priv=d/'private.pem'; pub=d/'public.pem'
                keygen(priv,pub,algorithm=alg)
                self.assertEqual(actual_key_algorithm(priv),alg)
                self.assertEqual(actual_key_algorithm(pub,public=True),alg)
                pairs[alg]=(priv,pub)
            priv87,pub87=pairs['ML-DSA-87']
            sig,_=sign(priv87,msg,algorithm='ML-DSA-87')
            self.assertTrue(verify(pub87,msg,sig,algorithm='ML-DSA-87'))
            for weak in ('ML-DSA-44','ML-DSA-65'):
                priv,pub=pairs[weak]
                with self.assertRaises(IdentityError): sign(priv,msg,algorithm='ML-DSA-87')
                weak_sig,_=sign(priv,msg,algorithm=weak)
                self.assertFalse(verify(pub,msg,weak_sig,algorithm='ML-DSA-87'))

if __name__=='__main__': unittest.main()
