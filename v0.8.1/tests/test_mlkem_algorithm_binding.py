import tempfile
import unittest
from pathlib import Path

from mlkem_provider import (
    MLKEMProviderError, actual_key_algorithm, decapsulate, encapsulate, keygen,
    require_key_algorithm,
)


class MLKEMAlgorithmBindingTests(unittest.TestCase):
    def test_actual_parameter_set_is_bound_to_operations(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            private = root / "kem512.pem"
            public = root / "kem512.pub.pem"
            keygen(private, public, algorithm="ML-KEM-512")
            self.assertEqual(actual_key_algorithm(private), "ML-KEM-512")
            self.assertEqual(actual_key_algorithm(public, public=True), "ML-KEM-512")
            with self.assertRaises(MLKEMProviderError):
                require_key_algorithm(private, "ML-KEM-1024")
            with self.assertRaises(MLKEMProviderError):
                encapsulate(public, algorithm="ML-KEM-1024")
            with self.assertRaises(MLKEMProviderError):
                decapsulate(private, b"\x00" * 1568, algorithm="ML-KEM-1024")


if __name__ == "__main__":
    unittest.main()
