import tempfile,unittest
from pathlib import Path
from xavi_duo_crypto import create_keyfile,claim_nonce,XDEError
from xavi_duo_nonce_anchor import CallbackNonceAnchor,NonceRollbackDetected,NonceAnchorError,RECEIPT_SCHEMA

def receipt(k,c,high=None):
 return {'schema':RECEIPT_SCHEMA,'status':'accepted','anchor_id':'test-independent','rollback_domain':'independent-test-domain','key_id':k,'counter':c,'high_water':c if high is None else high,'authority':False}

class NonceAnchorTests(unittest.TestCase):
 def test_high_assurance_requires_external_anchor_before_mutation(self):
  with tempfile.TemporaryDirectory() as td:
   k=Path(td)/'k';create_keyfile(k)
   with self.assertRaises(XDEError):claim_nonce(k,require_external_anchor=True)
   _,_,m=claim_nonce(k);self.assertEqual(m['counter_used'],1)

 def test_full_snapshot_rollback_is_detected_and_quarantined(self):
  with tempfile.TemporaryDirectory() as td:
   k=Path(td)/'k';create_keyfile(k)
   snap={p.name:p.read_bytes() for p in [k,Path(str(k)+'.nonce'),Path(str(k)+'.nonce.head')]}
   state={'high':0}
   def cb(key_id,counter):
    if counter<=state['high']: raise NonceRollbackDetected('reused')
    state['high']=counter;return receipt(key_id,counter,state['high'])
   a=CallbackNonceAnchor(cb,anchor_id='test',rollback_domain='external-test')
   _,_,m=claim_nonce(k,anchor=a,require_external_anchor=True);self.assertEqual(m['counter_used'],1)
   for name,data in snap.items(): (Path(td)/name).write_bytes(data)
   with self.assertRaises(XDEError):claim_nonce(k,anchor=a,require_external_anchor=True)
   self.assertTrue(Path(str(k)+'.nonce.rollback').is_file())
   with self.assertRaises(XDEError):claim_nonce(k)

 def test_transient_anchor_failure_consumes_nonce_without_quarantine(self):
  with tempfile.TemporaryDirectory() as td:
   k=Path(td)/'k';create_keyfile(k)
   def down(kid,c): raise NonceAnchorError('down')
   bad=CallbackNonceAnchor(down,rollback_domain='external-test')
   with self.assertRaises(XDEError):claim_nonce(k,anchor=bad,require_external_anchor=True)
   self.assertFalse(Path(str(k)+'.nonce.rollback').exists())
   good=CallbackNonceAnchor(lambda kid,c:receipt(kid,c),rollback_domain='external-test')
   _,_,m=claim_nonce(k,anchor=good,require_external_anchor=True);self.assertEqual(m['counter_used'],2)

if __name__=='__main__':unittest.main()
