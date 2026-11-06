"""Safety and fail-closed unit tests for the bounded frozen-backup auditor."""
import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT=Path(__file__).resolve().parents[1]/"audit_backup_replicas_v082.py"
spec=importlib.util.spec_from_file_location("xavi_backup_audit_v082",SCRIPT)
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class BackupAuditTests(unittest.TestCase):
    def test_profiles_are_strict(self):
        self.assertEqual(set(audit.PROFILES),set(audit.PROFILE_IDS))
        self.assertEqual(len(audit.PROFILE_IDS),5)
        self.assertNotIn("other",audit.PROFILES)

    def test_digest_is_exact(self):
        self.assertEqual(audit.digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_exact_regular_file_and_modes_pass(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"cipher.cms.der"
            path.write_bytes(b"ciphertext")
            path.chmod(0o600)
            self.assertEqual(audit.file_hash(path,audit.digest(b"ciphertext"),os.getuid()),10)

    def test_tampered_digest_fails(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"cipher.cms.der"
            path.write_bytes(b"ciphertext-tampered");path.chmod(0o600)
            with self.assertRaisesRegex(audit.AuditFailure,"SHA-256 mismatch"):
                audit.file_hash(path,audit.digest(b"ciphertext"),os.getuid())

    def test_wrong_file_permissions_fail(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"cipher.cms.der"
            path.write_bytes(b"x");path.chmod(0o644)
            with self.assertRaisesRegex(audit.AuditFailure,"file permissions"):
                audit.file_hash(path,audit.digest(b"x"),os.getuid())

    def test_symlink_fails(self):
        with tempfile.TemporaryDirectory() as td:
            actual=Path(td)/"a";link=Path(td)/"link"
            actual.write_bytes(b"x");actual.chmod(0o600);link.symlink_to(actual)
            with self.assertRaisesRegex(audit.AuditFailure,"regular file"):
                audit.file_hash(link,audit.digest(b"x"),os.getuid())

    def test_directory_requires_private_mode(self):
        with tempfile.TemporaryDirectory() as td:
            dir=Path(td);dir.chmod(0o755)
            with self.assertRaisesRegex(audit.AuditFailure,"directory permissions"):
                audit.directory_mode(dir,os.getuid())

    def test_oversize_decrypted_archive_fails(self):
        with self.assertRaisesRegex(audit.AuditFailure,"over size limit"):
            audit.validate_custody_tar(b"x"*131073)

    def test_tar_wrong_members_fail(self):
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode="w:") as tf:
            data=b"x"
            m=tarfile.TarInfo("custody/wrong")
            m.size=1;m.mode=0o600;m.uid=0;m.gid=0
            tf.addfile(m,io.BytesIO(data))
        with self.assertRaisesRegex(audit.AuditFailure,"membership mismatch"):
            audit.validate_custody_tar(out.getvalue())

    def test_deep_decrypt_failure_is_closed(self):
        with mock.patch.object(audit.subprocess,"run",return_value=mock.Mock(returncode=1,stdout=b"",stderr=b"no recipient")):
            with self.assertRaisesRegex(audit.AuditFailure,"decryption failed"):
                audit.deep_cms_check(Path("/does-not-exist"),Path("/cert"),Path("/key"))

    def test_profile_deep_disallowed_for_nfs_user(self):
        with self.assertRaisesRegex(audit.AuditFailure,"unprivileged profile"):
            audit.check_prod4_user(True,[])

    def test_profile_deep_disallowed_for_seaweed_user(self):
        with self.assertRaisesRegex(audit.AuditFailure,"ciphertext-only"):
            audit.check_prod3_seaweed(True,[])

    def test_recipient_expiry_window_passes_when_certificate_is_current(self):
        with mock.patch.object(audit.subprocess,"run",return_value=mock.Mock(returncode=0)) as run:
            audit.check_recipient_certificate_window(Path("/public-certificate.pem"))
        argv=run.call_args.args[0]
        self.assertEqual(argv[:3],["/usr/bin/openssl","x509","-in"])
        self.assertIn("-checkend",argv)
        self.assertEqual(argv[argv.index("-checkend")+1],str(60*24*60*60))

    def test_recipient_expiry_window_fails_closed(self):
        with mock.patch.object(audit.subprocess,"run",return_value=mock.Mock(returncode=1)):
            with self.assertRaisesRegex(audit.AuditFailure,"expires within 60 days"):
                audit.check_recipient_certificate_window(Path("/public-certificate.pem"))

    def test_cli_disallows_unknown_profile(self):
        # argparse's expected error is tested, not printed as a test failure.
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                audit.main(["--profile","some-other-backup"])
        self.assertEqual(ctx.exception.code,2)

if __name__=="__main__":
    unittest.main()
