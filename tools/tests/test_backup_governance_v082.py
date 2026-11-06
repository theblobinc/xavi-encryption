"""Immutable-scope checks for the on-prem v0.8.2 backup governance proposal."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
POLICY=ROOT/"backup-policy/v0.8.2-local-governance.PROPOSED.json"
SYSTEMD=ROOT/"deploy/systemd/v082"

class BackupGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy=json.loads(POLICY.read_text())

    def test_no_cloud_or_automatic_deletion(self):
        p=self.policy
        self.assertEqual(p["schema"],"XAVI-ENCRYPT/LOCAL-BACKUP-GOVERNANCE/v1")
        self.assertEqual(p["release_version"],"0.8.2")
        self.assertFalse(p["aws_allowed"])
        self.assertEqual(p["cloud_dependencies"],[])
        for key in ("automatic_deletion","automatic_pruning","automatic_overwrite","emergency_auto_repair"):
            self.assertFalse(p["retention"][key],key)
        self.assertFalse(p["authoritative_for_runtime_trust"])
        self.assertFalse(p["runtime_authority"])

    def test_recipient_key_rotation_remains_explicit(self):
        p=self.policy
        self.assertFalse(p["recipient_rotation"]["automatic_rotation"])
        self.assertTrue(p["recipient_rotation"]["dual_envelope_overlap_required"])
        self.assertTrue(p["recipient_rotation"]["fresh_return_to_original_tpm_signing_drill_required"])
        self.assertTrue(p["recipient_rotation"]["retire_old_recipient_only_after_owner_approval"])
        self.assertFalse(p["tpm"]["different_tpm_unseal_supported"])
        self.assertEqual(p["audits"]["certificate_rotation_warning_seconds"],60*24*60*60)

    def test_schedules_cover_expected_profiles(self):
        self.assertEqual(set(self.policy["audits"]["daily"]),
                         {"prod3-root","prod3-seaweed","prod4-root","prod4-user","vm1-root"})
        self.assertEqual(set(self.policy["audits"]["weekly_authenticated"]),
                         {"prod3-root","prod4-root","vm1-root"})
        self.assertFalse(self.policy["failure_domains"]["offsite"])
        self.assertEqual(self.policy["failure_domains"]["nfs_backing_host"],"prod3")
        self.assertEqual(self.policy["failure_domains"]["seaweedfs_backing_host"],"prod3")

    def test_units_are_only_read_only_audits(self):
        for typ in ("root","user","deep"):
            service=(SYSTEMD/f"xavi-encrypt-v082-{typ}@.service").read_text()
            timer=(SYSTEMD/f"xavi-encrypt-v082-{typ}@.timer").read_text()
            self.assertIn("ExecStart=/usr/bin/python3 -I /usr/local/libexec/xavi-encrypt-v082-audit.py",service)
            self.assertIn("--profile %i",service)
            self.assertIn("Persistent=true",timer)
            self.assertIn("WantedBy=timers.target",timer)
            for keyword in ("ExecStopPost","rm -rf","prune","rotate-key","aws "):
                self.assertNotIn(keyword,service)
                self.assertNotIn(keyword,timer)
        special=(SYSTEMD/"xavi-encrypt-v082-deep-prod3.service").read_text()
        self.assertIn("--profile prod3-root --deep",special)
        self.assertIn("ProtectSystem=full",special)
        self.assertNotIn("ExecStart=/bin/sh",special)

if __name__=="__main__":
    unittest.main()
