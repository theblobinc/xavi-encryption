import os
import tempfile
import unittest
from pathlib import Path

from xavi_duo_crypto import XDEError, claim_nonce, create_keyfile, read_key_data


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX O_NOFOLLOW")
class SecureStateTests(unittest.TestCase):
    def test_key_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real.xdek"
            link = root / "link.xdek"
            create_keyfile(real)
            os.symlink(real.name, link)
            with self.assertRaises(XDEError):
                read_key_data(link)

    def test_nonce_journal_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = root / "key.xdek"
            create_keyfile(key)
            journal = Path(str(key) + ".nonce")
            real = root / "nonce.real"
            journal.rename(real)
            os.symlink(real.name, journal)
            with self.assertRaises(XDEError):
                claim_nonce(key)

    def test_nonce_head_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = root / "key.xdek"
            create_keyfile(key)
            claim_nonce(key)
            head = Path(str(key) + ".nonce.head")
            real = root / "head.real"
            head.rename(real)
            os.symlink(real.name, head)
            with self.assertRaises(XDEError):
                claim_nonce(key)


if __name__ == "__main__":
    unittest.main()
