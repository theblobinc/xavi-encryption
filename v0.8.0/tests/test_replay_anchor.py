import json,tempfile,time,unittest
from pathlib import Path
from xavi_duo_replay import ReplayGuard,ReplayError
from xavi_duo_replay_anchor import CallbackNonceAnchor,replay_anchor_key
from xavi_duo_nonce_anchor import NonceRollbackDetected

class MemoryAnchor:
    def __init__(self): self.high={}
    def callback(self,key,counter):
        high=self.high.get(key,0)
        if counter<=high: raise NonceRollbackDetected('rollback/reuse')
        self.high[key]=counter
        return {'schema':'XAVI-DUO/NONCE-ANCHOR-RECEIPT/v1','status':'accepted','anchor_id':'test-anchor','rollback_domain':'independent-test-domain','key_id':key,'counter':counter,'high_water':counter,'authority':False}

class ReplayAnchorTests(unittest.TestCase):
    def test_high_assurance_requires_anchor(self):
        with tempfile.TemporaryDirectory() as td:
            g=ReplayGuard(Path(td)/'replay.json').init()
            with self.assertRaises(ReplayError):
                g.claim('s',1,'m1',int(time.time())+60,project_id='p',require_anchor=True)

    def test_external_anchor_detects_full_local_snapshot_rollback_and_quarantines(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'replay.json'; mem=MemoryAnchor(); anchor=CallbackNonceAnchor(mem.callback,anchor_id='test',rollback_domain='independent-test-domain')
            g=ReplayGuard(p).init(); expiry=int(time.time())+120
            c1=g.claim('s',1,'m1',expiry,project_id='p',anchor=anchor,require_anchor=True)
            snapshot=p.read_bytes()
            c2=g.claim('s',2,'m2',expiry,project_id='p',anchor=anchor,require_anchor=True)
            self.assertEqual(c2['external_anchor']['high_water'],2)
            # Simulate full local state rollback to the snapshot after sequence 1.
            p.write_bytes(snapshot)
            with self.assertRaisesRegex(ReplayError,'rollback detected'):
                g.claim('s',2,'m2-again',expiry,project_id='p',anchor=anchor,require_anchor=True)
            self.assertTrue(g.quarantine.exists())
            with self.assertRaisesRegex(ReplayError,'quarantined'):
                g.claim('s',3,'m3',expiry,project_id='p',anchor=anchor,require_anchor=True)

    def test_anchor_key_is_project_session_domain_separated(self):
        self.assertNotEqual(replay_anchor_key('p1','s'),replay_anchor_key('p2','s'))
        self.assertNotEqual(replay_anchor_key('p','s1'),replay_anchor_key('p','s2'))

if __name__=='__main__': unittest.main()
