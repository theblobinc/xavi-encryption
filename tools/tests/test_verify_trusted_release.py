"""Scope and tamper regression for the proposed v0.8.2 release-root policy."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODPATH = ROOT / "tools" / "verify_trusted_release.py"
SPEC = importlib.util.spec_from_file_location("xavi_release_trust_verifier_test", MODPATH)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
PUBLIC = ROOT / "attestations/v0.8.2/release-root-mldsa87.pub.pem"
MANIFEST = ROOT / "v0.8.2/release/XAVI_DUO_Encryption_v0.8.2_2026-11-02.RELEASE.json"
SIGNATURE = ROOT / "attestations/v0.8.2/XAVI_DUO_Encryption_v0.8.2_2026-11-02.RELEASE-SIGNATURE.json"
PROPOSAL = ROOT / "trust-policy/v0.8.2-root-policy.PROPOSED.json"


class TrustPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(PROPOSAL.read_text())

    def verify(self, **kwargs):
        return MOD.verify_with_policy(kwargs.pop("policy", self.policy),
            public_key=kwargs.pop("public_key", PUBLIC),
            manifest=kwargs.pop("manifest", MANIFEST),
            signature=kwargs.pop("signature", SIGNATURE))

    def test_valid_signature_and_explicit_scope(self):
        row = self.verify()
        self.assertEqual(row["status"], "TRUSTED_RELEASE_PASS")
        self.assertEqual(row["release_version"], "0.8.2")
        self.assertIs(row["runtime_authority"], False)

    def test_inactive_trust_denied(self):
        row = copy.deepcopy(self.policy)
        row["status"] = "revoked"
        with self.assertRaises(MOD.TrustError):
            self.verify(policy=row)

    def test_key_substitution_denied(self):
        row = copy.deepcopy(self.policy)
        row["signer"]["key_id"] = "sha256:" + "0" * 64
        with self.assertRaises(MOD.TrustError):
            self.verify(policy=row)

    def test_unapproved_release_digest_denied(self):
        row = copy.deepcopy(self.policy)
        row["allowed_manifests"]["0.8.2"] = "sha256:" + "1" * 64
        with self.assertRaises(MOD.TrustError):
            self.verify(policy=row)

    def test_unapproved_version_denied(self):
        row = copy.deepcopy(self.policy)
        row["allowed_manifests"] = {"0.8.3": row["allowed_manifests"]["0.8.2"]}
        with self.assertRaises(MOD.TrustError):
            self.verify(policy=row)

    def test_runtime_authority_denied(self):
        row = copy.deepcopy(self.policy)
        row["runtime_authority"] = True
        with self.assertRaises(MOD.TrustError):
            self.verify(policy=row)

    def test_manifest_byte_change_denied(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "RELEASE.json"
            m = json.loads(MANIFEST.read_text())
            m["release_date"] = "1999-01-01"
            p.write_text(json.dumps(m))
            with self.assertRaises(MOD.TrustError):
                self.verify(manifest=p)

    def test_signature_change_denied(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "SIGNATURE.json"
            row = json.loads(SIGNATURE.read_text())
            row["signature_sha256"] = "sha256:" + "a" * 64
            p.write_text(json.dumps(row))
            with self.assertRaises(Exception):
                self.verify(signature=p)

    def test_untrusted_file_location_denied(self):
        with self.assertRaises(MOD.TrustError):
            MOD.read_owner_policy(PROPOSAL)


if __name__ == "__main__":
    unittest.main()
