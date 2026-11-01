import json,tempfile,unittest
from pathlib import Path
from xavi_duo_identity import HIGH_ASSURANCE_ALGORITHM,keygen
from xavi_duo_release import sign_manifest,verify_manifest,ReleaseSignatureError
class ReleaseSignatureTests(unittest.TestCase):
 def test_mldsa87_release_signature_and_tamper_rejection(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); keygen(p/'release.pem',p/'release.pub',algorithm=HIGH_ASSURANCE_ALGORITHM)
   manifest=p/'manifest.json';manifest.write_text(json.dumps({'schema':'XAVI-DUO/RELEASE-MANIFEST/v1','version':'0.7.0','artifacts':{'a':'sha256:'+'1'*64}},indent=2)+'\n')
   row=sign_manifest(p/'release.pem',p/'release.pub',manifest,p/'manifest.sig.json')
   self.assertEqual(row['algorithm'],'ML-DSA-87'); self.assertFalse(row['authority'])
   ok=verify_manifest(p/'release.pub',manifest,p/'manifest.sig.json'); self.assertEqual(ok['status'],'PASS')
   manifest.write_text(json.dumps({'schema':'XAVI-DUO/RELEASE-MANIFEST/v1','version':'0.7.1','artifacts':{'a':'sha256:'+'1'*64}})+'\n')
   with self.assertRaises(ReleaseSignatureError): verify_manifest(p/'release.pub',manifest,p/'manifest.sig.json')
 def test_signature_metadata_tamper_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td); keygen(p/'release.pem',p/'release.pub',algorithm=HIGH_ASSURANCE_ALGORITHM)
   m=p/'m.json';m.write_text('{"version":"0.7.0"}\n'); sign_manifest(p/'release.pem',p/'release.pub',m,p/'s.json')
   o=json.loads((p/'s.json').read_text());o['algorithm']='ML-DSA-65';(p/'s.json').write_text(json.dumps(o))
   with self.assertRaises(ReleaseSignatureError): verify_manifest(p/'release.pub',m,p/'s.json')
if __name__=='__main__':unittest.main()
