import json, os, tempfile, unittest
from pathlib import Path
from mlkem_provider import keygen, self_test
from xavi_duo_pq import encrypt_for, decrypt_for, duo_bytes_encode, duo_bytes_decode
from xavi_duo_crypto import AuthenticationError

class PQ2Tests(unittest.TestCase):
    def test_provider_self_test(self):
        self.assertEqual(self_test()['status'],'PASS')
    def test_duo_public_byte_codec(self):
        b=bytes(range(256)); s=duo_bytes_encode(b); self.assertNotIn('0',s); self.assertEqual(duo_bytes_decode(s),b)
    def test_pq_roundtrip_and_aad(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); priv=d/'private.pem'; pub=d/'public.pem'; keygen(priv,pub)
            plain=os.urandom(333); env,w1=encrypt_for(pub,plain,aad=b'ctx',pad_to=512)
            self.assertNotIn('0',env['kem_ciphertext_duo'])
            got,w2=decrypt_for(priv,env,aad=b'ctx'); self.assertEqual(got,plain)
            with self.assertRaises(AuthenticationError): decrypt_for(priv,env,aad=b'wrong')
            self.assertFalse(w1['authority']); self.assertFalse(w2['authority'])

if __name__=='__main__':unittest.main()
