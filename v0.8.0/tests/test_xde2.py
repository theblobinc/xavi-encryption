import json, os, stat, tempfile, unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from xavi_duo_crypto import AuthenticationError, XDEError, claim_nonce, create_keyfile, decrypt_bytes, derive_receipt_key, duo_context_commitment, hidden_duo_context, encrypt_bytes, frame_info, read_master_key
from xavi_duo_evidence import authenticate_receipt, receipt_body, verify_receipt
from pqc_provider import provider_status

class XDE2Tests(unittest.TestCase):
    def setUp(self): self.master=bytes(range(32)); self.nonce=bytes.fromhex('000102030405060708090a0b')
    def test_roundtrip_and_zero_free(self):
        for n in (0,1,2,31,255,256,4096):
            pt=os.urandom(n); f=encrypt_bytes(self.master,pt,aad=b'ctx',nonce=self.nonce)
            self.assertNotIn('0',f); self.assertEqual(decrypt_bytes(self.master,f,aad=b'ctx'),pt)
            self.assertTrue(frame_info(f)['duo_cell_grammar_ok'])
    def test_padding_roundtrip_and_bucket(self):
        pt=b'length secret'; f=encrypt_bytes(self.master,pt,aad=b'p',nonce=self.nonce,pad_to=1024)
        info=frame_info(f); self.assertEqual(info['encrypted_payload_bytes'],1024)
        self.assertEqual(decrypt_bytes(self.master,f,aad=b'p'),pt)
    def test_wrong_aad_and_key_fail(self):
        f=encrypt_bytes(self.master,b'secret',aad=b'A',nonce=self.nonce)
        with self.assertRaises(AuthenticationError): decrypt_bytes(self.master,f,aad=b'B')
        with self.assertRaises(AuthenticationError): decrypt_bytes(bytes(reversed(self.master)),f,aad=b'A')
    def test_valid_grammar_tamper_rejected(self):
        f=encrypt_bytes(self.master,b'tamper me',nonce=self.nonce); a,b,c=f.split('|'); cells=c.split('.')
        cells[-1]=('2' if cells[-1][0]!='2' else '3')+cells[-1][1:]
        bad='|'.join([a,b,'.'.join(cells)])
        with self.assertRaises((AuthenticationError,XDEError)): decrypt_bytes(self.master,bad)
    def test_receipt(self):
        f=encrypt_bytes(self.master,b'evidence',aad=b'C',nonce=self.nonce)
        cc=duo_context_commitment(self.master,f)
        body=receipt_body(frame=f,aad=b'C',key_id='test-key',counter=1,pad_to=0,duo_context_commitment=cc)
        r=authenticate_receipt(body,derive_receipt_key(self.master))
        self.assertTrue(verify_receipt(r,derive_receipt_key(self.master),frame=f,aad=b'C',duo_context_commitment=cc))
        self.assertFalse(verify_receipt(r,derive_receipt_key(self.master),frame=f,aad=b'D',duo_context_commitment=cc))
    def test_hidden_rotating_mod_context_is_bound_but_not_serialized(self):
        f=encrypt_bytes(self.master,b'context witness',aad=b'ctx',nonce=self.nonce)
        c0=hidden_duo_context(self.master,f,0)
        self.assertEqual(c0['duo']['external_count'],c0['duo']['cycle']*c0['duo']['span']+c0['duo']['remainder'])
        self.assertEqual(c0['duo']['symbol'],f.split('|',2)[2].split('.')[0])
        self.assertNotIn(str(c0['duo']['modulus']),f)
        a=duo_context_commitment(self.master,f)
        self.assertTrue(a.startswith('hmac-sha256:'))
        bad=bytes(reversed(self.master))
        with self.assertRaises((XDEError,AuthenticationError,ValueError)):
            hidden_duo_context(bad,f,0)

    def test_keyfile_and_append_only_nonce_chronology(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'k.xdek'; meta=create_keyfile(p)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600); jp=Path(str(p)+'.nonce'); self.assertEqual(stat.S_IMODE(jp.stat().st_mode),0o600)
            k1,n1,m1=claim_nonce(p); k2,n2,m2=claim_nonce(p)
            self.assertEqual(k1,k2); self.assertNotEqual(n1,n2); self.assertEqual((m1['counter_used'],m2['counter_used']),(1,2))
            self.assertEqual(jp.read_text().splitlines(),['XDE-NONCE/v1','1','2','3'])
    def test_malformed_nonce_journal_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'k.xdek'; create_keyfile(p); Path(str(p)+'.nonce').write_text('XDE-NONCE/v1\n1\nBROKEN')
            with self.assertRaises(XDEError): claim_nonce(p)
    def test_nonce_head_recovers_append_ahead_without_reuse(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'k.xdek'; create_keyfile(p); _,n1,_=claim_nonce(p)
            jp=Path(str(p)+'.nonce'); hp=Path(str(p)+'.nonce.head')
            # Simulate crash after durable journal append but before head replacement.
            with jp.open('a') as f: f.write('3\n'); f.flush(); os.fsync(f.fileno())
            _,n3,m3=claim_nonce(p)
            self.assertEqual(m3['counter_used'],3); self.assertNotEqual(n1,n3)
            self.assertEqual(json.loads(hp.read_text())['next_counter'],4)
    def test_nonce_head_rejects_journal_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'k.xdek'; create_keyfile(p); claim_nonce(p); claim_nonce(p)
            jp=Path(str(p)+'.nonce'); lines=jp.read_text().splitlines(); jp.write_text('\n'.join(lines[:-1])+'\n')
            with self.assertRaisesRegex(XDEError,'rollback'): claim_nonce(p)
    def test_pq_provider_never_reports_dev_fallback(self): self.assertFalse(provider_status()['development_fallback'])

if __name__=='__main__': unittest.main()
