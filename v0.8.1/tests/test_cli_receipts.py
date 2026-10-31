import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "xavi_duo.py"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(CLI), *map(str, args)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class CLIReceiptTests(unittest.TestCase):
    def test_receipt_round_trip_and_verification(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            key = root / "alice.xdek"
            plain = root / "plain.bin"
            frame = root / "cipher.xde"
            receipt = root / "cipher.receipt.json"
            recovered = root / "recovered.bin"
            payload = b"XAVI-DUO v0.8.1 CLI receipt regression\x00\xff"
            plain.write_bytes(payload)

            r = run_cli("keygen", "--out", key)
            self.assertEqual(r.returncode, 0, r.stderr)

            r = run_cli(
                "encrypt", "--key", key, "--in", plain, "--out", frame,
                "--aad", "cli:test:v081", "--receipt", receipt,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(receipt.is_file())

            r = run_cli(
                "verify-receipt", "--key", key, "--frame", frame,
                "--receipt", receipt, "--aad", "cli:test:v081",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(json.loads(r.stdout)["verified"])

            r = run_cli(
                "decrypt", "--key", key, "--in", frame, "--out", recovered,
                "--aad", "cli:test:v081", "--receipt", receipt,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(recovered.read_bytes(), payload)

            tampered = json.loads(receipt.read_text())
            tampered["body"]["payload_cells"] += 1
            receipt.write_text(json.dumps(tampered), encoding="utf-8")
            r = run_cli(
                "verify-receipt", "--key", key, "--frame", frame,
                "--receipt", receipt, "--aad", "cli:test:v081",
            )
            self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
