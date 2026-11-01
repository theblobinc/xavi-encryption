#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xavi_duo_custody import parse_custody_ref
from xavi_duo_private_ops import CallbackPrivateOperator, PrivateOpsError, PrivateOpsRegistry
from xavi_duo_tpm2_custody import (
    TPM2Custody,
    TPM2CustodyError,
    TPM2PrivateOperator,
    TPM_TOOLS,
    provision_mldsa_identity,
)


class FakeTPM:
    def __init__(self):
        self.calls = []
        self.sealed_kek = None

    @staticmethod
    def _value(argv, flag):
        return argv[argv.index(flag) + 1]

    def __call__(self, argv, *, cwd, env, timeout):
        cwd = Path(cwd)
        tool = Path(argv[0]).name
        self.calls.append((tool, tuple(argv[1:]), dict(env)))
        if tool == 'tpm2_createprimary':
            (cwd / self._value(argv, '-c')).write_bytes(b'PRIMARY-CONTEXT')
        elif tool == 'tpm2_startauthsession':
            (cwd / self._value(argv, '-S')).write_bytes(b'POLICY-SESSION')
        elif tool == 'tpm2_policypcr':
            if '-L' in argv:
                (cwd / self._value(argv, '-L')).write_bytes(b'POLICY:' + self._value(argv, '-l').encode())
        elif tool == 'tpm2_create':
            self.sealed_kek = (cwd / self._value(argv, '-i')).read_bytes()
            (cwd / self._value(argv, '-u')).write_bytes(b'SEALED-PUBLIC')
            (cwd / self._value(argv, '-r')).write_bytes(b'SEALED-PRIVATE')
        elif tool == 'tpm2_load':
            (cwd / self._value(argv, '-c')).write_bytes(b'SEALED-CONTEXT')
        elif tool == 'tpm2_unseal':
            if self.sealed_kek is None:
                return subprocess.CompletedProcess(argv, 1, b'', b'no sealed KEK')
            (cwd / self._value(argv, '-o')).write_bytes(self.sealed_kek)
        elif tool == 'tpm2_flushcontext':
            pass
        else:
            return subprocess.CompletedProcess(argv, 1, b'', b'unexpected fake TPM tool')
        return subprocess.CompletedProcess(argv, 0, b'', b'')


class TPM2CustodyV082Tests(unittest.TestCase):
    def make(self, root, *, node='prod3'):
        fake = FakeTPM()
        tools = {name: name for name in TPM_TOOLS}
        counter = {'n': 0}

        def rnd(n):
            counter['n'] += 1
            return bytes(((i + counter['n']) & 0xFF) for i in range(n))

        custody = TPM2Custody(root, node, pcr_policy='sha256:7', runner=fake, tool_paths=tools, random_bytes=rnd)
        return custody, fake

    def test_kek_is_pcr_bound_and_plaintext_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as td:
            custody, fake = self.make(Path(td) / 'custody')
            row = custody.provision_kek()
            self.assertEqual(row['reference'], 'tpm2://prod3/default-kek')
            self.assertEqual(row['pcr_policy'], 'sha256:7')
            self.assertTrue(row['hardware_bound_wrapping'])
            self.assertFalse(row['native_pq_operation'])
            self.assertTrue(custody.kek_status()['configured'])
            calls = fake.calls
            self.assertTrue(any(t == 'tpm2_policypcr' and '-l' in a and 'sha256:7' in a for t, a, _ in calls))
            self.assertTrue(any(t == 'tpm2_create' and '-L' in a and 'policy.digest' in a for t, a, _ in calls))
            self.assertEqual(len(fake.sealed_kek), 32)
            persisted = b''.join(p.read_bytes() for p in custody.root.rglob('*') if p.is_file())
            self.assertNotIn(fake.sealed_kek, persisted)

    def test_private_object_roundtrip_and_ciphertext_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            custody, _ = self.make(Path(td) / 'custody')
            custody.provision_kek()
            secret = b'PRIVATE-ML-DSA-87-PEM-MATERIAL'
            row = custody.seal('release-root', secret, purpose='mldsa-private-key', algorithm='ML-DSA-87')
            self.assertEqual(row['reference'], 'tpm2://prod3/release-root')
            object_path = custody.objects / 'release-root.json'
            self.assertNotIn(secret, object_path.read_bytes())
            self.assertEqual(
                custody.unseal('release-root', expected_purpose='mldsa-private-key', expected_algorithm='ML-DSA-87'),
                secret,
            )
            data = json.loads(object_path.read_text())
            c = bytearray(base64.b64decode(data['ciphertext']))
            c[-1] ^= 1
            data['ciphertext'] = base64.b64encode(bytes(c)).decode()
            object_path.write_text(json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n')
            os.chmod(object_path, 0o600)
            with self.assertRaises(TPM2CustodyError):
                custody.unseal('release-root', expected_algorithm='ML-DSA-87')

    def test_unseal_uses_policy_session_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            custody, fake = self.make(Path(td) / 'custody')
            custody.provision_kek()
            custody.seal('a', b'secret', purpose='private-key', algorithm='test')
            custody.unseal('a', expected_algorithm='test')
            unseals = [a for t, a, _ in fake.calls if t == 'tpm2_unseal']
            self.assertTrue(unseals)
            self.assertIn('session:policy.session', unseals[-1])

    def test_high_assurance_tpm_operator_signs_without_returning_private_key(self):
        with tempfile.TemporaryDirectory() as td:
            custody, _ = self.make(Path(td) / 'custody')
            custody.provision_kek()
            private = b'FAKE-PRIVATE-PEM'
            custody.seal('release-root', private, purpose='mldsa-private-key', algorithm='ML-DSA-87')

            def signer(path, data, *, algorithm):
                self.assertEqual(Path(path).read_bytes(), private)
                self.assertEqual(algorithm, 'ML-DSA-87')
                sig = hashlib.sha256(data + private).digest()
                return sig, {'provider': 'fake-openssl-3.5', 'authority': False}

            op = TPM2PrivateOperator(custody, signer=signer)
            reg = PrivateOpsRegistry().register(op)
            ref = parse_custody_ref('tpm2://prod3/release-root')
            signature, evidence = reg.sign(ref, b'release-message', algorithm='ML-DSA-87', high_assurance=True)
            self.assertEqual(signature, hashlib.sha256(b'release-message' + private).digest())
            self.assertTrue(evidence['non_exporting_private_key'])
            self.assertTrue(evidence['hardware_bound'])
            self.assertTrue(evidence['private_key_ephemeral_process_exposure'])
            self.assertFalse(evidence['native_pq_operation'])
            self.assertFalse(evidence['private_key_exported_to_caller'])

    def test_tpm_high_assurance_rejects_non_hardware_callback(self):
        callback = CallbackPrivateOperator(
            lambda operation, ref, payload, algorithm: {
                'status': 'PASS', 'algorithm': algorithm, 'reference': ref.raw, 'signature': base64.b64encode(b'x').decode()
            },
            schemes=frozenset({'tpm2'}),
            hardware_bound=False,
        )
        reg = PrivateOpsRegistry().register(callback)
        ref = parse_custody_ref('tpm2://prod3/release-root')
        with self.assertRaises(PrivateOpsError):
            reg.sign(ref, b'x', algorithm='ML-DSA-87', high_assurance=True)

    def test_tpm_operator_is_node_pinned(self):
        with tempfile.TemporaryDirectory() as td:
            custody, _ = self.make(Path(td) / 'custody')
            custody.provision_kek()
            custody.seal('release-root', b'k', purpose='mldsa-private-key', algorithm='ML-DSA-87')
            reg = PrivateOpsRegistry().register(TPM2PrivateOperator(custody, signer=lambda *a, **k: (b's', {})))
            with self.assertRaises(Exception):
                reg.sign(parse_custody_ref('tpm2://prod4/release-root'), b'x', algorithm='ML-DSA-87', high_assurance=True)

    def test_provision_mldsa_wraps_private_and_exports_only_public(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            custody, _ = self.make(base / 'custody')
            custody.provision_kek()
            public_out = base / 'release-root.pub.pem'

            def fake_keygen(private_path, public_path, *, algorithm):
                Path(private_path).write_bytes(b'PRIVATE-' + algorithm.encode())
                os.chmod(private_path, 0o600)
                Path(public_path).write_bytes(b'PUBLIC-' + algorithm.encode())
                os.chmod(public_path, 0o644)
                return {'algorithm': algorithm, 'provider': 'fake'}

            row = provision_mldsa_identity(custody, 'release-root', public_out, algorithm='ML-DSA-87', keygen_func=fake_keygen)
            self.assertEqual(row['reference'], 'tpm2://prod3/release-root')
            self.assertEqual(public_out.read_bytes(), b'PUBLIC-ML-DSA-87')
            self.assertNotIn(b'PRIVATE-ML-DSA-87', (custody.objects / 'release-root.json').read_bytes())
            self.assertEqual(
                custody.unseal('release-root', expected_purpose='mldsa-private-key', expected_algorithm='ML-DSA-87'),
                b'PRIVATE-ML-DSA-87',
            )


if __name__ == '__main__':
    unittest.main()
