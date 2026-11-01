"""Rev 1.2-dev4 split TFHE trust boundary.

The production remote evaluator must never possess a TFHE client/decryption key.
This module therefore separates the client-crypto process from the evaluator
process.  The client sidecar only key-generates/encrypts/decrypts and exports
server/evaluation material.  The evaluator sidecar only receives that public
server material and performs homomorphic operations over opaque ciphertexts.

``SplitTFHEBackend`` is a trusted-client convenience bridge for local acceptance
runs: it transfers serialized ciphertexts between the two isolated processes.
It must not be embedded inside the remote evaluator service; production worker
construction accepts ``TFHEEvaluatorSidecarBackend`` directly and rejects any
backend advertising client-secret custody.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import json
import subprocess
from typing import Sequence

from .encrypted import (
    BackendUnavailable,
    CipherBit,
    CipherWord64,
    FHEBackend,
    FHECapabilities,
    SidecarFHEBackend,
)


class ClientCryptoUnavailable(RuntimeError):
    pass


class EvaluatorPolicyError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TFHEClientCapabilities:
    provider: str
    role: str
    cryptographic: bool
    has_client_secret: bool
    key_id: str
    supports_server_key_export: bool
    device: str = "client"


class _JsonLineProcess:
    def __init__(self, command: Sequence[str], *, label: str) -> None:
        if not command:
            raise ValueError(f"{label} sidecar command is required")
        self.label = label
        try:
            self._proc = subprocess.Popen(
                list(command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise ClientCryptoUnavailable(f"unable to launch {label} sidecar: {exc}") from exc

    def call(self, op: str, **kwargs):
        if self._proc.poll() is not None:
            raise ClientCryptoUnavailable(f"{self.label} sidecar terminated")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        request = {"op": op, **kwargs}
        self._proc.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            detail = ""
            if self._proc.stderr is not None:
                try:
                    detail = self._proc.stderr.read().strip()
                except Exception:
                    detail = ""
            suffix = f": {detail}" if detail else ""
            raise ClientCryptoUnavailable(f"{self.label} sidecar returned no response{suffix}")
        response = json.loads(line)
        if not response.get("ok", False):
            raise RuntimeError(str(response.get("error", f"{self.label} sidecar operation failed")))
        return response.get("result", {})

    def close(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is not None and proc.poll() is None:
            try:
                self.call("close")
            except Exception:
                pass
            proc.terminate()


class TFHEClientCryptoSidecar:
    """Client-secret process. It is never handed to the remote worker."""

    def __init__(self, command: Sequence[str]) -> None:
        self._rpc = _JsonLineProcess(command, label="TFHE client-crypto")
        hello = self._rpc.call("capabilities")
        self.capabilities = TFHEClientCapabilities(
            provider=str(hello.get("provider", "")),
            role=str(hello.get("role", "")),
            cryptographic=bool(hello.get("cryptographic")),
            has_client_secret=bool(hello.get("has_client_secret")),
            key_id=str(hello.get("key_id", "")),
            supports_server_key_export=bool(hello.get("supports_server_key_export")),
            device=str(hello.get("device", "client")),
        )
        caps = self.capabilities
        if (
            caps.provider != "tfhe"
            or caps.role != "client"
            or not caps.cryptographic
            or not caps.has_client_secret
            or not caps.key_id
            or not caps.supports_server_key_export
        ):
            self.close()
            raise ClientCryptoUnavailable("TFHE client sidecar does not expose the required client-only contract")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value, validate=True)

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    def export_server_key(self) -> bytes:
        return self._decode(self._rpc.call("export_server_key")["data"])

    def encrypt_bit(self, value: bool) -> bytes:
        return self._decode(self._rpc.call("encrypt_bit", value=bool(value))["data"])

    def decrypt_bit(self, ciphertext: bytes) -> bool:
        return bool(self._rpc.call("decrypt_bit", data=self._encode(ciphertext))["value"])

    def encrypt_word64(self, value: int) -> bytes:
        if not isinstance(value, int) or not 0 <= value < 2**64:
            raise ValueError("word must be uint64")
        return self._decode(self._rpc.call("encrypt_word64", value=value)["data"])

    def decrypt_word64(self, ciphertext: bytes) -> int:
        return int(self._rpc.call("decrypt_word64", data=self._encode(ciphertext))["value"])

    def close(self) -> None:
        self._rpc.close()


class TFHEPortableClientBackend(FHEBackend):
    """Client-only backend whose ciphertext payloads are serialized TFHE blobs.

    It exists so the client can compile/encrypt a complete program without any
    evaluator process being present.  Evaluation methods all fail closed.
    """

    def __init__(self, client: TFHEClientCryptoSidecar) -> None:
        self.client = client
        self.backend_id = f"xavi-void-tfhe-portable-client:{client.capabilities.key_id}"
        self.capabilities = FHECapabilities(
            provider="tfhe", cryptographic=True, role="client", has_client_secret=True,
            supports_boolean=False, supports_word64=False, supports_oblivious_select=False,
            supports_secret_rotation=False, key_id=client.capabilities.key_id, device="client",
        )

    @staticmethod
    def _eval_forbidden():
        raise EvaluatorPolicyError("client-only TFHE backend cannot perform evaluator operations")

    def encrypt_bit(self, value: bool) -> CipherBit:
        return CipherBit(self.backend_id, self.client.encrypt_bit(value))
    def decrypt_bit(self, value: CipherBit) -> bool:
        self._check_bit(value); return self.client.decrypt_bit(bytes(value.payload))
    def encrypt_word64(self, value: int) -> CipherWord64:
        return CipherWord64(self.backend_id, self.client.encrypt_word64(value))
    def decrypt_word64(self, value: CipherWord64) -> int:
        self._check_word(value); return self.client.decrypt_word64(bytes(value.payload))
    def export_bit(self, value: CipherBit) -> bytes:
        self._check_bit(value); return bytes(value.payload)
    def import_bit(self, data: bytes) -> CipherBit:
        return CipherBit(self.backend_id, bytes(data))
    def export_word64(self, value: CipherWord64) -> bytes:
        self._check_word(value); return bytes(value.payload)
    def import_word64(self, data: bytes) -> CipherWord64:
        return CipherWord64(self.backend_id, bytes(data))

    def trivial_bit(self, value: bool) -> CipherBit: self._eval_forbidden()
    def trivial_word64(self, value: int) -> CipherWord64: self._eval_forbidden()
    def bit_not(self, value: CipherBit) -> CipherBit: self._eval_forbidden()
    def bit_xor(self, left: CipherBit, right: CipherBit) -> CipherBit: self._eval_forbidden()
    def bit_and(self, left: CipherBit, right: CipherBit) -> CipherBit: self._eval_forbidden()
    def bit_or(self, left: CipherBit, right: CipherBit) -> CipherBit: self._eval_forbidden()
    def bit_mux(self, selector: CipherBit, when_true: CipherBit, when_false: CipherBit) -> CipherBit: self._eval_forbidden()
    def word_xor(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: self._eval_forbidden()
    def word_and(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: self._eval_forbidden()
    def word_not(self, value: CipherWord64) -> CipherWord64: self._eval_forbidden()
    def word_rotl_public(self, value: CipherWord64, amount: int) -> CipherWord64: self._eval_forbidden()
    def word_rotl_secret(self, value: CipherWord64, amount: CipherWord64) -> CipherWord64: self._eval_forbidden()
    def word_eq(self, left: CipherWord64, right: CipherWord64) -> CipherBit: self._eval_forbidden()
    def word_mux(self, selector: CipherBit, when_true: CipherWord64, when_false: CipherWord64) -> CipherWord64: self._eval_forbidden()


class TFHEEvaluatorSidecarBackend(SidecarFHEBackend):
    """Evaluation-only TFHE backend.

    Construction fails if the sidecar says it has client-secret custody.  The
    encryption/decryption methods intentionally raise even though ``FHEBackend``
    includes them for compatibility with the local combined provider interface.
    """

    def __init__(self, command: Sequence[str]) -> None:
        super().__init__(command, expected_provider="tfhe")
        caps = self.capabilities
        if caps.role != "evaluator" or caps.has_client_secret:
            self.close()
            raise EvaluatorPolicyError("remote TFHE evaluator must be role=evaluator and has_client_secret=false")
        if not caps.key_id:
            self.close()
            raise EvaluatorPolicyError("remote TFHE evaluator must report a stable evaluation-key id")

    @staticmethod
    def _forbidden() -> None:
        raise EvaluatorPolicyError("evaluation-only TFHE backend has no client encryption/decryption key")

    def encrypt_bit(self, value: bool) -> CipherBit:
        self._forbidden()

    def decrypt_bit(self, value: CipherBit) -> bool:
        self._forbidden()

    def encrypt_word64(self, value: int) -> CipherWord64:
        self._forbidden()

    def decrypt_word64(self, value: CipherWord64) -> int:
        self._forbidden()


class SplitTFHEBackend(FHEBackend):
    """Trusted-client bridge between isolated client and evaluator processes.

    This adapter is suitable for local end-to-end acceptance tests and for a
    client process that talks to an evaluator transport.  It is deliberately
    rejected by ``ProductionTFHEWorker`` because its process owns client-secret
    access through ``client``.
    """

    def __init__(self, client: TFHEClientCryptoSidecar, evaluator: TFHEEvaluatorSidecarBackend) -> None:
        if client.capabilities.key_id != evaluator.capabilities.key_id:
            raise EvaluatorPolicyError("TFHE client/evaluator key ids do not match")
        self.client = client
        self.evaluator = evaluator
        self.backend_id = evaluator.backend_id
        self.capabilities = replace(
            evaluator.capabilities,
            role="split-client-orchestrator",
            has_client_secret=True,
        )

    def close(self) -> None:
        self.evaluator.close()
        self.client.close()

    def encrypt_bit(self, value: bool) -> CipherBit:
        return self.evaluator.import_bit(self.client.encrypt_bit(value))

    def decrypt_bit(self, value: CipherBit) -> bool:
        return self.client.decrypt_bit(self.evaluator.export_bit(value))

    def encrypt_word64(self, value: int) -> CipherWord64:
        return self.evaluator.import_word64(self.client.encrypt_word64(value))

    def decrypt_word64(self, value: CipherWord64) -> int:
        return self.client.decrypt_word64(self.evaluator.export_word64(value))

    def trivial_bit(self, value: bool) -> CipherBit:
        return self.evaluator.trivial_bit(value)

    def trivial_word64(self, value: int) -> CipherWord64:
        return self.evaluator.trivial_word64(value)

    def bit_not(self, value: CipherBit) -> CipherBit:
        return self.evaluator.bit_not(value)

    def bit_xor(self, left: CipherBit, right: CipherBit) -> CipherBit:
        return self.evaluator.bit_xor(left, right)

    def bit_and(self, left: CipherBit, right: CipherBit) -> CipherBit:
        return self.evaluator.bit_and(left, right)

    def bit_or(self, left: CipherBit, right: CipherBit) -> CipherBit:
        return self.evaluator.bit_or(left, right)

    def bit_mux(self, selector: CipherBit, when_true: CipherBit, when_false: CipherBit) -> CipherBit:
        return self.evaluator.bit_mux(selector, when_true, when_false)

    def word_xor(self, left: CipherWord64, right: CipherWord64) -> CipherWord64:
        return self.evaluator.word_xor(left, right)

    def word_and(self, left: CipherWord64, right: CipherWord64) -> CipherWord64:
        return self.evaluator.word_and(left, right)

    def word_not(self, value: CipherWord64) -> CipherWord64:
        return self.evaluator.word_not(value)

    def word_rotl_public(self, value: CipherWord64, amount: int) -> CipherWord64:
        return self.evaluator.word_rotl_public(value, amount)

    def word_rotl_secret(self, value: CipherWord64, amount: CipherWord64) -> CipherWord64:
        return self.evaluator.word_rotl_secret(value, amount)

    def word_eq(self, left: CipherWord64, right: CipherWord64) -> CipherBit:
        return self.evaluator.word_eq(left, right)

    def word_mux(self, selector: CipherBit, when_true: CipherWord64, when_false: CipherWord64) -> CipherWord64:
        return self.evaluator.word_mux(selector, when_true, when_false)

    def export_bit(self, value: CipherBit) -> bytes:
        return self.evaluator.export_bit(value)

    def import_bit(self, data: bytes) -> CipherBit:
        return self.evaluator.import_bit(data)

    def export_word64(self, value: CipherWord64) -> bytes:
        return self.evaluator.export_word64(value)

    def import_word64(self, data: bytes) -> CipherWord64:
        return self.evaluator.import_word64(data)

    def select_bit(self, bank, encrypted_register):
        return self.evaluator.select_bit(bank, encrypted_register)

    def select_word(self, bank, encrypted_register):
        return self.evaluator.select_word(bank, encrypted_register)

    def write_bit(self, bank, encrypted_register, value):
        return self.evaluator.write_bit(bank, encrypted_register, value)

    def write_word(self, bank, encrypted_register, value):
        return self.evaluator.write_word(bank, encrypted_register, value)

    def ciphertext_bit_commitment(self, value: CipherBit) -> str:
        return self.evaluator.ciphertext_bit_commitment(value)

    def ciphertext_word_commitment(self, value: CipherWord64) -> str:
        return self.evaluator.ciphertext_word_commitment(value)

    def metrics(self) -> dict[str, object]:
        return self.evaluator.metrics()

    def reset_metrics(self) -> None:
        self.evaluator.reset_metrics()

    def resident_stats(self) -> dict[str, object]:
        return self.evaluator.resident_stats()

    def release_ciphertexts(self, values) -> int:
        return self.evaluator.release_ciphertexts(values)

    def keccak24_words(self, state):
        return self.evaluator.keccak24_words(state)


def assert_remote_safe_evaluator(backend: FHEBackend) -> None:
    caps = backend.capabilities
    if not caps.cryptographic:
        raise EvaluatorPolicyError("production remote evaluator requires a cryptographic backend")
    if caps.role != "evaluator":
        raise EvaluatorPolicyError("production remote evaluator requires role=evaluator")
    if caps.has_client_secret:
        raise EvaluatorPolicyError("production remote evaluator cannot possess client-secret material")
    if not caps.key_id:
        raise EvaluatorPolicyError("production remote evaluator requires a stable evaluation-key id")
