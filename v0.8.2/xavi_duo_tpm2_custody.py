#!/usr/bin/env python3
"""TPM2-sealed KEK custody for XAVI-DUO.

The TPM does not execute ML-DSA or ML-KEM.  It seals a 256-bit wrapping key
(Kek) to a PCR policy.  PQ private PEM objects are authenticated ciphertext on
disk.  A private operation unseals the KEK, decrypts the PEM only inside the
custody process, performs the provider operation from a secure temporary
location, and then destroys the temporary material.

"non_exporting_private_key" therefore means the private-key API does not return
private bytes to the requesting caller.  It does *not* mean that ML-DSA is
performed natively inside TPM hardware; the private PEM is present ephemerally
in signer-process memory for the OpenSSL provider operation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from xavi_duo_custody import CustodyRef, require_node
from xavi_duo_fs import atomic_create, atomic_write, fsync_dir, read_regular_file, secure_tempdir
from xavi_duo_private_ops import PrivateOperator, PrivateOpsRegistry

KEK_SCHEMA = 'XAVI-DUO/TPM2-KEK/v1'
OBJECT_SCHEMA = 'XAVI-DUO/TPM2-WRAPPED-OBJECT/v1'
EVIDENCE_SCHEMA = 'XAVI-DUO/TPM2-PRIVATE-OP-EVIDENCE/v1'
MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_OBJECT_FILE_BYTES = 8 * 1024 * 1024
TPM_TOOLS = (
    'tpm2_createprimary', 'tpm2_startauthsession', 'tpm2_policypcr',
    'tpm2_create', 'tpm2_load', 'tpm2_unseal', 'tpm2_flushcontext',
)


class TPM2CustodyError(RuntimeError):
    pass


def _canonical(row: dict) -> bytes:
    return json.dumps(row, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode('ascii'), validate=True)
    except Exception as exc:
        raise TPM2CustodyError('invalid base64 in custody object') from exc


def _wipe(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _validate_name(name: str) -> str:
    value = str(name)
    if not value or value in {'.', '..'} or '/' in value or '\\' in value or len(value) > 128:
        raise ValueError('invalid custody object name')
    return value


class TPM2Custody:
    def __init__(
        self,
        root: Path | str,
        node_id: str,
        *,
        pcr_policy: str = 'sha256:7',
        tcti: str | None = None,
        runner: Callable | None = None,
        tool_paths: dict[str, str] | None = None,
        random_bytes: Callable[[int], bytes] = os.urandom,
        timeout: float = 30.0,
    ):
        self.root = Path(root).resolve()
        self.node_id = str(node_id)
        self.pcr_policy = str(pcr_policy)
        self.tcti = str(tcti) if tcti else None
        self.runner = runner
        self.tool_paths = dict(tool_paths) if tool_paths is not None else None
        self.random_bytes = random_bytes
        self.timeout = float(timeout)
        self.kek_dir = self.root / 'default-kek'
        self.objects = self.root / 'objects'
        if ':' not in self.pcr_policy:
            raise ValueError('PCR policy must be in bank:index form')

    @property
    def kek_reference(self) -> str:
        return f'tpm2://{self.node_id}/default-kek'

    def init_layout(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.objects, 0o700)
        return self

    def _tool(self, name: str) -> str:
        if name not in TPM_TOOLS:
            raise TPM2CustodyError('unapproved TPM tool')
        if self.tool_paths is not None:
            path = self.tool_paths.get(name)
            if not path:
                raise TPM2CustodyError(f'TPM tool path not configured: {name}')
            return path
        if self.runner is not None:
            return name
        path = shutil.which(name)
        if not path:
            raise TPM2CustodyError(f'TPM tool not installed: {name}')
        return path

    def _run(self, name: str, args: list[str], work: Path, *, check: bool = True):
        argv = [self._tool(name), *map(str, args)]
        env = os.environ.copy()
        if self.tcti:
            env['TPM2TOOLS_TCTI'] = self.tcti
        try:
            if self.runner is not None:
                result = self.runner(argv, cwd=work, env=env, timeout=self.timeout)
            else:
                result = subprocess.run(
                    argv,
                    cwd=work,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout,
                    check=False,
                )
        except Exception as exc:
            raise TPM2CustodyError(f'TPM command failed to execute: {name}') from exc
        rc = int(getattr(result, 'returncode', 1))
        if check and rc != 0:
            raw = getattr(result, 'stderr', b'') or b''
            if isinstance(raw, bytes):
                detail = raw.decode('utf-8', 'replace')
            else:
                detail = str(raw)
            detail = detail.strip().replace('\n', ' ')[:600]
            raise TPM2CustodyError(f'TPM command failed: {name}: {detail or "nonzero exit"}')
        return result

    def _flush(self, context: str, work: Path) -> None:
        try:
            self._run('tpm2_flushcontext', [context], work, check=False)
        except Exception:
            pass

    def _create_primary(self, work: Path) -> None:
        self._run('tpm2_createprimary', ['-C', 'o', '-G', 'rsa', '-g', 'sha256', '-c', 'primary.ctx'], work)

    def _start_policy(self, work: Path, *, write_digest: bool) -> None:
        self._run('tpm2_startauthsession', ['--policy-session', '-g', 'sha256', '-S', 'policy.session'], work)
        args = ['-S', 'policy.session', '-l', self.pcr_policy]
        if write_digest:
            args += ['-L', 'policy.digest']
        self._run('tpm2_policypcr', args, work)

    def provision_kek(self) -> dict:
        self.init_layout()
        if self.kek_dir.exists():
            raise FileExistsError(self.kek_dir)
        kek = bytearray(self.random_bytes(32))
        if len(kek) != 32:
            raise TPM2CustodyError('KEK generator did not return 32 bytes')
        stage = Path(tempfile.mkdtemp(prefix='.default-kek.new-', dir=self.root))
        os.chmod(stage, 0o700)
        try:
            with secure_tempdir(prefix='xavi-tpm2-provision-') as work:
                atomic_write(work / 'kek.bin', bytes(kek), 0o600)
                self._create_primary(work)
                policy_started = False
                try:
                    self._start_policy(work, write_digest=True)
                    policy_started = True
                finally:
                    if policy_started:
                        self._flush('policy.session', work)
                self._run(
                    'tpm2_create',
                    ['-C', 'primary.ctx', '-g', 'sha256', '-u', 'seal.pub', '-r', 'seal.priv', '-i', 'kek.bin', '-L', 'policy.digest'],
                    work,
                )
                self._flush('primary.ctx', work)
                for name in ('seal.pub', 'seal.priv', 'policy.digest'):
                    atomic_write(stage / name, read_regular_file(work / name, max_bytes=128 * 1024), 0o600)
            meta = {
                'schema': KEK_SCHEMA,
                'node': self.node_id,
                'reference': self.kek_reference,
                'pcr_policy': self.pcr_policy,
                'kek_bytes': 32,
                'native_pq_operation': False,
                'hardware_bound_wrapping': True,
                'created_unix': int(time.time()),
                'artifacts': {
                    name: 'sha256:' + hashlib.sha256(read_regular_file(stage / name, max_bytes=128 * 1024, private=True)).hexdigest()
                    for name in ('seal.pub', 'seal.priv', 'policy.digest')
                },
                'authority': False,
            }
            atomic_write(stage / 'metadata.json', _canonical(meta) + b'\n', 0o600)
            fsync_dir(stage)
            os.rename(stage, self.kek_dir)
            fsync_dir(self.root)
            return meta
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        finally:
            _wipe(kek)

    def kek_status(self) -> dict:
        if not self.kek_dir.is_dir():
            return {'configured': False, 'reference': self.kek_reference, 'node': self.node_id, 'authority': False}
        try:
            raw = read_regular_file(self.kek_dir / 'metadata.json', max_bytes=64 * 1024, private=True)
            meta = json.loads(raw.decode('utf-8', 'strict'))
        except Exception as exc:
            raise TPM2CustodyError('invalid TPM KEK metadata') from exc
        if meta.get('schema') != KEK_SCHEMA or meta.get('node') != self.node_id or meta.get('reference') != self.kek_reference:
            raise TPM2CustodyError('TPM KEK metadata binding mismatch')
        if meta.get('pcr_policy') != self.pcr_policy:
            raise TPM2CustodyError('TPM KEK PCR policy mismatch')
        for name in ('seal.pub', 'seal.priv', 'policy.digest'):
            data = read_regular_file(self.kek_dir / name, max_bytes=128 * 1024, private=True)
            expected = meta.get('artifacts', {}).get(name)
            if expected != 'sha256:' + hashlib.sha256(data).hexdigest():
                raise TPM2CustodyError(f'TPM KEK artifact digest mismatch: {name}')
        return {**meta, 'configured': True}

    def _unseal_kek(self) -> bytearray:
        self.kek_status()
        with secure_tempdir(prefix='xavi-tpm2-unseal-') as work:
            for name in ('seal.pub', 'seal.priv', 'policy.digest'):
                atomic_write(work / name, read_regular_file(self.kek_dir / name, max_bytes=128 * 1024, private=True), 0o600)
            self._create_primary(work)
            loaded = False
            policy_started = False
            try:
                self._run('tpm2_load', ['-C', 'primary.ctx', '-u', 'seal.pub', '-r', 'seal.priv', '-c', 'seal.ctx'], work)
                loaded = True
                self._start_policy(work, write_digest=False)
                policy_started = True
                self._run('tpm2_unseal', ['-c', 'seal.ctx', '-p', 'session:policy.session', '-o', 'kek.bin'], work)
                os.chmod(work / 'kek.bin', 0o600)
                kek = bytearray(read_regular_file(work / 'kek.bin', max_bytes=32, private=True))
                if len(kek) != 32:
                    _wipe(kek)
                    raise TPM2CustodyError('TPM returned invalid KEK length')
                return kek
            finally:
                if policy_started:
                    self._flush('policy.session', work)
                if loaded:
                    self._flush('seal.ctx', work)
                self._flush('primary.ctx', work)

    def _object_path(self, name: str) -> Path:
        return self.objects / (_validate_name(name) + '.json')

    def seal(self, name: str, plaintext: bytes, *, purpose: str = 'private-key', algorithm: str | None = None) -> dict:
        self.init_layout()
        name = _validate_name(name)
        data = bytes(plaintext)
        if not data or len(data) > MAX_OBJECT_BYTES:
            raise TPM2CustodyError('custody plaintext size outside allowed bound')
        dest = self._object_path(name)
        if dest.exists():
            raise FileExistsError(dest)
        kek = self._unseal_kek()
        try:
            nonce = self.random_bytes(12)
            if len(nonce) != 12:
                raise TPM2CustodyError('nonce generator did not return 12 bytes')
            meta = {
                'schema': OBJECT_SCHEMA,
                'node': self.node_id,
                'name': name,
                'purpose': str(purpose),
                'algorithm': str(algorithm) if algorithm else None,
                'kek_reference': self.kek_reference,
                'pcr_policy': self.pcr_policy,
                'hardware_bound_wrapping': True,
                'native_pq_operation': False,
                'authority': False,
            }
            aad = _canonical(meta)
            ciphertext = ChaCha20Poly1305(bytes(kek)).encrypt(nonce, data, aad)
            row = {
                **meta,
                'nonce': _b64e(nonce),
                'ciphertext': _b64e(ciphertext),
                'ciphertext_sha256': 'sha256:' + hashlib.sha256(ciphertext).hexdigest(),
            }
            atomic_create(dest, _canonical(row) + b'\n', 0o600)
            return {
                'schema': OBJECT_SCHEMA,
                'reference': f'tpm2://{self.node_id}/{name}',
                'node': self.node_id,
                'name': name,
                'purpose': str(purpose),
                'algorithm': str(algorithm) if algorithm else None,
                'kek_reference': self.kek_reference,
                'pcr_policy': self.pcr_policy,
                'hardware_bound_wrapping': True,
                'native_pq_operation': False,
                'authority': False,
            }
        finally:
            _wipe(kek)

    def unseal(self, name: str, *, expected_purpose: str | None = None, expected_algorithm: str | None = None) -> bytes:
        name = _validate_name(name)
        try:
            raw = read_regular_file(self._object_path(name), max_bytes=MAX_OBJECT_FILE_BYTES, private=True)
            row = json.loads(raw.decode('utf-8', 'strict'))
        except Exception as exc:
            raise TPM2CustodyError('invalid TPM custody object') from exc
        required = {
            'schema': OBJECT_SCHEMA,
            'node': self.node_id,
            'name': name,
            'kek_reference': self.kek_reference,
            'pcr_policy': self.pcr_policy,
            'hardware_bound_wrapping': True,
            'native_pq_operation': False,
            'authority': False,
        }
        for key, value in required.items():
            if row.get(key) != value:
                raise TPM2CustodyError(f'TPM custody object binding mismatch: {key}')
        if expected_purpose is not None and row.get('purpose') != expected_purpose:
            raise TPM2CustodyError('TPM custody purpose mismatch')
        if expected_algorithm is not None and row.get('algorithm') != expected_algorithm:
            raise TPM2CustodyError('TPM custody algorithm mismatch')
        nonce = _b64d(row.get('nonce', ''))
        ciphertext = _b64d(row.get('ciphertext', ''))
        if len(nonce) != 12:
            raise TPM2CustodyError('invalid custody nonce length')
        if row.get('ciphertext_sha256') != 'sha256:' + hashlib.sha256(ciphertext).hexdigest():
            raise TPM2CustodyError('custody ciphertext digest mismatch')
        meta = {k: row[k] for k in (
            'schema', 'node', 'name', 'purpose', 'algorithm', 'kek_reference',
            'pcr_policy', 'hardware_bound_wrapping', 'native_pq_operation', 'authority',
        )}
        kek = self._unseal_kek()
        try:
            try:
                return ChaCha20Poly1305(bytes(kek)).decrypt(nonce, ciphertext, _canonical(meta))
            except Exception as exc:
                raise TPM2CustodyError('TPM custody authentication failed') from exc
        finally:
            _wipe(kek)


@dataclass
class TPM2PrivateOperator(PrivateOperator):
    custody: TPM2Custody
    signer: Callable | None = None
    decapsulator: Callable | None = None
    schemes: frozenset = field(default_factory=lambda: frozenset({'tpm2'}))
    non_exporting_private_key: bool = True
    hardware_bound: bool = True
    external_authority: bool = False

    def _evidence(self, operation: str, ref: CustodyRef, algorithm: str, inner: dict | None = None) -> dict:
        return {
            'schema': EVIDENCE_SCHEMA,
            'operation': operation,
            'algorithm': algorithm,
            'custody_ref': ref.raw,
            'operator': 'tpm2-sealed-kek',
            'non_exporting_private_key': True,
            'private_key_exported_to_caller': False,
            'private_key_ephemeral_process_exposure': True,
            'hardware_bound': True,
            'hardware_binding': 'TPM2-sealed-KEK',
            'native_pq_operation': False,
            'pcr_policy': self.custody.pcr_policy,
            'external_authority': False,
            'provider_evidence': inner or {},
            'authority': False,
        }

    def sign(self, ref: CustodyRef, data: bytes, *, algorithm: str):
        require_node(ref, self.custody.node_id)
        private = bytearray(self.custody.unseal(ref.name, expected_purpose='mldsa-private-key', expected_algorithm=algorithm))
        try:
            with secure_tempdir(prefix='xavi-tpm2-mldsa-sign-') as work:
                path = work / 'identity.pem'
                atomic_write(path, bytes(private), 0o600)
                if self.signer is None:
                    from xavi_duo_identity import sign as signer
                    signature, ev = signer(path, bytes(data), algorithm=algorithm)
                else:
                    signature, ev = self.signer(path, bytes(data), algorithm=algorithm)
            return bytes(signature), self._evidence('sign', ref, algorithm, ev)
        finally:
            _wipe(private)

    def decapsulate(self, ref: CustodyRef, ciphertext: bytes, *, algorithm: str):
        require_node(ref, self.custody.node_id)
        private = bytearray(self.custody.unseal(ref.name, expected_purpose='mlkem-private-key', expected_algorithm=algorithm))
        try:
            with secure_tempdir(prefix='xavi-tpm2-mlkem-decap-') as work:
                path = work / 'private.pem'
                atomic_write(path, bytes(private), 0o600)
                if self.decapsulator is None:
                    from mlkem_provider import decapsulate as decapsulator
                    secret, ev = decapsulator(path, bytes(ciphertext), algorithm=algorithm)
                else:
                    secret, ev = self.decapsulator(path, bytes(ciphertext), algorithm=algorithm)
            return bytes(secret), self._evidence('decapsulate', ref, algorithm, ev)
        finally:
            _wipe(private)


def provision_mldsa_identity(
    custody: TPM2Custody,
    name: str,
    public_out: Path | str,
    *,
    algorithm: str = 'ML-DSA-87',
    keygen_func: Callable | None = None,
) -> dict:
    name = _validate_name(name)
    public_out = Path(public_out).resolve()
    if public_out.exists():
        raise FileExistsError(public_out)
    if custody._object_path(name).exists():
        raise FileExistsError(custody._object_path(name))
    with secure_tempdir(prefix='xavi-tpm2-mldsa-keygen-') as work:
        private_path = work / 'identity.pem'
        public_path = work / 'identity.pub.pem'
        if keygen_func is None:
            from xavi_duo_identity import keygen as keygen_func
        ev = keygen_func(private_path, public_path, algorithm=algorithm)
        private = bytearray(read_regular_file(private_path, max_bytes=MAX_OBJECT_BYTES, private=True))
        public = read_regular_file(public_path, max_bytes=MAX_OBJECT_BYTES)
        try:
            sealed = custody.seal(name, bytes(private), purpose='mldsa-private-key', algorithm=algorithm)
            atomic_create(public_out, public, 0o644)
        finally:
            _wipe(private)
    return {
        'schema': 'XAVI-DUO/TPM2-MLDSA-PROVISION/v1',
        'reference': sealed['reference'],
        'algorithm': algorithm,
        'public_key': str(public_out),
        'public_key_id': 'sha256:' + hashlib.sha256(public).hexdigest(),
        'kek_reference': custody.kek_reference,
        'pcr_policy': custody.pcr_policy,
        'hardware_bound_wrapping': True,
        'native_mldsa': False,
        'provider_evidence': ev,
        'authority': False,
    }


def _custody_from_args(args) -> TPM2Custody:
    return TPM2Custody(args.root, args.node, pcr_policy=args.pcr, tcti=args.tcti)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='TPM2-sealed KEK custody for XAVI-DUO')
    p.add_argument('--root', required=True)
    p.add_argument('--node', required=True)
    p.add_argument('--pcr', default='sha256:7')
    p.add_argument('--tcti')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    sub.add_parser('provision-kek')
    km = sub.add_parser('provision-mldsa')
    km.add_argument('--name', required=True)
    km.add_argument('--algorithm', default='ML-DSA-87', choices=['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'])
    km.add_argument('--public-out', required=True)
    rs = sub.add_parser('release-sign')
    rs.add_argument('--name', required=True)
    rs.add_argument('--public-key', required=True)
    rs.add_argument('--manifest', required=True)
    rs.add_argument('--output', required=True)
    rv = sub.add_parser('release-verify')
    rv.add_argument('--public-key', required=True)
    rv.add_argument('--manifest', required=True)
    rv.add_argument('--signature', required=True)
    args = p.parse_args(argv)
    custody = _custody_from_args(args)
    if args.command == 'status':
        row = custody.kek_status()
    elif args.command == 'provision-kek':
        row = custody.provision_kek()
    elif args.command == 'provision-mldsa':
        row = provision_mldsa_identity(custody, args.name, args.public_out, algorithm=args.algorithm)
    elif args.command == 'release-sign':
        from xavi_duo_release import sign_manifest_custody
        registry = PrivateOpsRegistry().register(TPM2PrivateOperator(custody))
        row = sign_manifest_custody(
            f'tpm2://{args.node}/{_validate_name(args.name)}',
            args.public_key,
            args.manifest,
            args.output,
            registry=registry,
            high_assurance=True,
        )
    elif args.command == 'release-verify':
        from xavi_duo_release import verify_manifest
        row = verify_manifest(args.public_key, args.manifest, args.signature)
    else:
        raise AssertionError(args.command)
    print(json.dumps(row, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
