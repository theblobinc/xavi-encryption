import tempfile,time,unittest
from pathlib import Path
from xavi_duo_custody import select_custody,require_node
from xavi_duo_software_custody import SoftwareCustody
from xavi_duo_authority_custody import AuthorityCustody
from xavi_duo_replay import ReplayGuard,ReplayError
from xavi_duo_witness_bridge import WitnessBridge
from xavi_duo_identity import self_test as identity_self_test
class V030Tests(unittest.TestCase):
 def test_custody_selection(self):
  from xavi_duo_custody import parse_custody_ref
  self.assertEqual(parse_custody_ref('authority://legacy/key').scheme,'authority')
  r=select_custody(['file:///tmp/a','authority://prod4/a','tpm2://prod3/a'],2); self.assertEqual(r.scheme,'tpm2'); self.assertRaises(Exception,require_node,r,'prod4')
 def test_software_custody(self):
  with tempfile.TemporaryDirectory() as td:
   c=SoftwareCustody(td,'prod4').init(); row=c.seal('a',b'secret'); self.assertTrue(row['reference'].startswith('file://')); self.assertEqual(c.unseal('a'),b'secret'); self.assertNotIn(b'secret',(Path(td)/'objects/a.json').read_bytes())

 def test_authority_custody(self):
  with tempfile.TemporaryDirectory() as td:
   secret=Path(td)/'authority.secret'; secret.write_bytes(b'x'*32); secret.chmod(0o600); root=Path(td)/'objects-root'; verifier=lambda approval,request: approval=={'allow':True} and request['node']=='prod4' and request['name']=='a'; c=AuthorityCustody(root,'prod4',secret,approval_verifier=verifier).init(); row=c.seal('a',b'secret'); self.assertTrue(row['reference'].startswith('authority://prod4/')); self.assertRaises(Exception,c.unseal,'a'); self.assertEqual(c.unseal('a',approval={'allow':True}),b'secret'); self.assertFalse((root/'wrapping.key').exists())
 def test_replay(self):
  with tempfile.TemporaryDirectory() as td:
   r=ReplayGuard(Path(td)/'r.json').init(); exp=time.time()+60; r.claim('s',1,'m1',exp); self.assertRaises(ReplayError,r.claim,'s',1,'m1',exp); r.claim('s',2,'m2',exp)
 def test_witness(self):
  with tempfile.TemporaryDirectory() as td:
   w=WitnessBridge(td).init(); a=w.append('a',{'v':1}); b=w.append('b',{'v':2}); self.assertEqual(b['parentDigest'],a['digest']); self.assertEqual(b['sequence'],2); self.assertEqual(b['duo_sequence']['symbol'],'1b')
 def test_identity(self): self.assertEqual(identity_self_test()['status'],'PASS')

 def test_witness_duo_context_recomputed(self):
  with tempfile.TemporaryDirectory() as td:
   w=WitnessBridge(td).init(); row=w.append_duo('ctx',{'v':3},external_count=20,modulus=11)
   self.assertEqual(row['body']['duo_numeral']['symbol'],'1Aa')
   bad=dict(row['body']['duo_numeral']); bad['symbol']='9j'
   with self.assertRaises(ValueError): w.append('bad',{'duo_numeral':bad})

if __name__=='__main__': unittest.main()
