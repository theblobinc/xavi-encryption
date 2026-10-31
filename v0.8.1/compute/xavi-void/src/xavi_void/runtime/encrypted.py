"""Provider-neutral homomorphic execution for xavi-void Rev 1.2.

The evaluator code in this module never decrypts encrypted program fields or
encrypted data.  Provider implementations supply homomorphic Boolean/word
operations.  A non-secure reference provider exists solely for deterministic
conformance tests; production providers are attached through the sidecar
adapter and must advertise a cryptographic FHE capability.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import base64
import json
import secrets
import subprocess
from typing import Mapping, Sequence

from xavi_void.crypto.shake import ID_PREFIX, canonical_bytes, content_id
from xavi_void.math.types import InstructionId, Ordinal, PositiveExtent, RegisterId
from .ir import ExecutionIR, Op
from .semantic import semantic_from_execution
from .word_ir import MASK64, WordOp, WordProgram


class BackendUnavailable(RuntimeError):
    """Raised when a requested cryptographic/GPU provider is not installed."""


@dataclass(frozen=True, slots=True)
class FHECapabilities:
    provider: str
    cryptographic: bool
    role: str = "combined"
    has_client_secret: bool = True
    supports_boolean: bool = True
    supports_word64: bool = True
    supports_oblivious_select: bool = True
    supports_secret_rotation: bool = True
    key_id: str = ""
    device: str = "cpu"
    supports_bulk_registers: bool = False
    supports_keccak24: bool = False
    supports_metrics: bool = False
    supports_resident_sessions: bool = False


@dataclass(frozen=True, slots=True)
class CipherBit:
    backend_id: str
    payload: object


@dataclass(frozen=True, slots=True)
class CipherWord64:
    backend_id: str
    payload: object


@dataclass(frozen=True, slots=True)
class EncryptedRegisterBank:
    backend_id: str
    registers: tuple[CipherBit, ...]


@dataclass(frozen=True, slots=True)
class EncryptedWordRegisterBank:
    backend_id: str
    registers: tuple[CipherWord64, ...]


@dataclass(frozen=True, slots=True)
class EncryptedInstruction:
    instruction_id: InstructionId
    opcode_tag: CipherWord64
    destination: CipherWord64
    source_a: CipherWord64
    source_b: CipherWord64
    input_slot: CipherWord64


@dataclass(frozen=True, slots=True)
class EncryptedProgram:
    backend_id: str
    encrypted_semantic_id: tuple[CipherWord64, ...]
    encrypted_representation_id: tuple[CipherWord64, ...]
    register_count: PositiveExtent
    instructions: tuple[EncryptedInstruction, ...]
    outputs: tuple[CipherWord64, ...]
    padded_instruction_count: PositiveExtent


@dataclass(frozen=True, slots=True)
class EncryptedWordInstruction:
    instruction_id: InstructionId
    opcode_tag: CipherWord64
    destination: CipherWord64
    source_a: CipherWord64
    source_b: CipherWord64
    source_c: CipherWord64
    source_d: CipherWord64
    source_e: CipherWord64
    rotate: CipherWord64
    immediate: CipherWord64


@dataclass(frozen=True, slots=True)
class EncryptedWordProgram:
    backend_id: str
    encrypted_semantic_id: tuple[CipherWord64, ...]
    encrypted_representation_id: tuple[CipherWord64, ...]
    register_count: PositiveExtent
    instructions: tuple[EncryptedWordInstruction, ...]
    padded_instruction_count: PositiveExtent


class FHEBackend(ABC):
    """Strict FHE provider interface used by the evaluator.

    ``trivial_*`` creates a ciphertext/encoded public constant without a client
    secret.  Production implementations normally use the provider's trivial or
    server-side constant encoding.
    """

    backend_id: str
    capabilities: FHECapabilities

    @abstractmethod
    def encrypt_bit(self, value: bool) -> CipherBit: ...

    @abstractmethod
    def decrypt_bit(self, value: CipherBit) -> bool: ...

    @abstractmethod
    def encrypt_word64(self, value: int) -> CipherWord64: ...

    @abstractmethod
    def decrypt_word64(self, value: CipherWord64) -> int: ...

    @abstractmethod
    def trivial_bit(self, value: bool) -> CipherBit: ...

    @abstractmethod
    def trivial_word64(self, value: int) -> CipherWord64: ...

    @abstractmethod
    def bit_not(self, value: CipherBit) -> CipherBit: ...

    @abstractmethod
    def bit_xor(self, left: CipherBit, right: CipherBit) -> CipherBit: ...

    @abstractmethod
    def bit_and(self, left: CipherBit, right: CipherBit) -> CipherBit: ...

    @abstractmethod
    def bit_or(self, left: CipherBit, right: CipherBit) -> CipherBit: ...

    @abstractmethod
    def bit_mux(self, selector: CipherBit, when_true: CipherBit, when_false: CipherBit) -> CipherBit: ...

    @abstractmethod
    def word_xor(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: ...

    @abstractmethod
    def word_and(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: ...

    @abstractmethod
    def word_not(self, value: CipherWord64) -> CipherWord64: ...

    @abstractmethod
    def word_rotl_public(self, value: CipherWord64, amount: int) -> CipherWord64: ...

    @abstractmethod
    def word_rotl_secret(self, value: CipherWord64, amount: CipherWord64) -> CipherWord64: ...

    @abstractmethod
    def word_eq(self, left: CipherWord64, right: CipherWord64) -> CipherBit: ...

    @abstractmethod
    def word_mux(self, selector: CipherBit, when_true: CipherWord64, when_false: CipherWord64) -> CipherWord64: ...

    @abstractmethod
    def export_bit(self, value: CipherBit) -> bytes:
        """Serialize one ciphertext for transport/storage without decrypting it."""
        ...

    @abstractmethod
    def import_bit(self, data: bytes) -> CipherBit: ...

    @abstractmethod
    def export_word64(self, value: CipherWord64) -> bytes: ...

    @abstractmethod
    def import_word64(self, data: bytes) -> CipherWord64: ...

    def _check_bit(self, value: CipherBit) -> None:
        if value.backend_id != self.backend_id:
            raise ValueError("ciphertext belongs to a different backend")

    def _check_word(self, value: CipherWord64) -> None:
        if value.backend_id != self.backend_id:
            raise ValueError("ciphertext belongs to a different backend")

    def select_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64) -> CipherBit:
        """Obliviously select one one-origin register. Default implementation is FHE-safe."""
        self._check_word(encrypted_register)
        result = self.trivial_bit(False)
        for ordinal, candidate in enumerate(bank, start=1):
            self._check_bit(candidate)
            match = self.word_eq(encrypted_register, self.trivial_word64(ordinal))
            result = self.bit_mux(match, candidate, result)
        return result

    def select_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64) -> CipherWord64:
        self._check_word(encrypted_register)
        result = self.trivial_word64(0)
        for ordinal, candidate in enumerate(bank, start=1):
            self._check_word(candidate)
            match = self.word_eq(encrypted_register, self.trivial_word64(ordinal))
            result = self.word_mux(match, candidate, result)
        return result

    def write_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64, value: CipherBit) -> tuple[CipherBit, ...]:
        self._check_word(encrypted_register); self._check_bit(value)
        updated: list[CipherBit] = []
        for ordinal, current in enumerate(bank, start=1):
            match = self.word_eq(encrypted_register, self.trivial_word64(ordinal))
            updated.append(self.bit_mux(match, value, current))
        return tuple(updated)

    def write_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64, value: CipherWord64) -> tuple[CipherWord64, ...]:
        self._check_word(encrypted_register); self._check_word(value)
        updated: list[CipherWord64] = []
        for ordinal, current in enumerate(bank, start=1):
            match = self.word_eq(encrypted_register, self.trivial_word64(ordinal))
            updated.append(self.word_mux(match, value, current))
        return tuple(updated)

    def ciphertext_bit_commitment(self, value: CipherBit) -> str:
        self._check_bit(value)
        return content_id("XAVI-VOID/CIPHERTEXT-BIT/v1", repr(value.payload).encode("utf-8"))

    def ciphertext_word_commitment(self, value: CipherWord64) -> str:
        self._check_word(value)
        return content_id("XAVI-VOID/CIPHERTEXT-WORD64/v1", repr(value.payload).encode("utf-8"))

    def metrics(self) -> dict[str, object]:
        return {}

    def reset_metrics(self) -> None:
        return None

    def resident_stats(self) -> dict[str, object]:
        return {}

    def release_ciphertexts(self, values: Sequence[CipherBit | CipherWord64]) -> int:
        return 0

    def keccak24_words(self, state: Sequence[CipherWord64]) -> tuple[CipherWord64, ...]:
        raise BackendUnavailable("provider does not expose a specialized Keccak-f[1600] kernel")


class FHEClientView:
    """Trusted-client capability view: encryption/decryption and ciphertext I/O only."""
    __slots__=("__backend",)
    def __init__(self,backend:FHEBackend)->None:self.__backend=backend
    @property
    def backend_id(self)->str:return self.__backend.backend_id
    @property
    def capabilities(self)->FHECapabilities:return self.__backend.capabilities
    def encrypt_bit(self,value:bool)->CipherBit:return self.__backend.encrypt_bit(value)
    def decrypt_bit(self,value:CipherBit)->bool:return self.__backend.decrypt_bit(value)
    def encrypt_word64(self,value:int)->CipherWord64:return self.__backend.encrypt_word64(value)
    def decrypt_word64(self,value:CipherWord64)->int:return self.__backend.decrypt_word64(value)
    def export_bit(self,value:CipherBit)->bytes:return self.__backend.export_bit(value)
    def import_bit(self,data:bytes)->CipherBit:return self.__backend.import_bit(data)
    def export_word64(self,value:CipherWord64)->bytes:return self.__backend.export_word64(value)
    def import_word64(self,data:bytes)->CipherWord64:return self.__backend.import_word64(data)
    def ciphertext_bit_commitment(self,value:CipherBit)->str:return self.__backend.ciphertext_bit_commitment(value)
    def ciphertext_word_commitment(self,value:CipherWord64)->str:return self.__backend.ciphertext_word_commitment(value)

class FHEEvaluatorView:
    """Evaluator-only capability view. There is deliberately no decrypt method."""
    __slots__=("__backend",)
    def __init__(self,backend:FHEBackend)->None:self.__backend=backend
    @property
    def backend_id(self)->str:return self.__backend.backend_id
    @property
    def capabilities(self)->FHECapabilities:return self.__backend.capabilities
    def trivial_bit(self,value:bool)->CipherBit:return self.__backend.trivial_bit(value)
    def trivial_word64(self,value:int)->CipherWord64:return self.__backend.trivial_word64(value)
    def bit_not(self,v:CipherBit)->CipherBit:return self.__backend.bit_not(v)
    def bit_xor(self,a:CipherBit,b:CipherBit)->CipherBit:return self.__backend.bit_xor(a,b)
    def bit_and(self,a:CipherBit,b:CipherBit)->CipherBit:return self.__backend.bit_and(a,b)
    def bit_or(self,a:CipherBit,b:CipherBit)->CipherBit:return self.__backend.bit_or(a,b)
    def bit_mux(self,s:CipherBit,t:CipherBit,f:CipherBit)->CipherBit:return self.__backend.bit_mux(s,t,f)
    def word_xor(self,a:CipherWord64,b:CipherWord64)->CipherWord64:return self.__backend.word_xor(a,b)
    def word_and(self,a:CipherWord64,b:CipherWord64)->CipherWord64:return self.__backend.word_and(a,b)
    def word_not(self,v:CipherWord64)->CipherWord64:return self.__backend.word_not(v)
    def word_rotl_public(self,v:CipherWord64,amount:int)->CipherWord64:return self.__backend.word_rotl_public(v,amount)
    def word_rotl_secret(self,v:CipherWord64,amount:CipherWord64)->CipherWord64:return self.__backend.word_rotl_secret(v,amount)
    def word_eq(self,a:CipherWord64,b:CipherWord64)->CipherBit:return self.__backend.word_eq(a,b)
    def word_mux(self,s:CipherBit,t:CipherWord64,f:CipherWord64)->CipherWord64:return self.__backend.word_mux(s,t,f)
    def select_bit(self,bank:Sequence[CipherBit],idx:CipherWord64)->CipherBit:return self.__backend.select_bit(bank,idx)
    def select_word(self,bank:Sequence[CipherWord64],idx:CipherWord64)->CipherWord64:return self.__backend.select_word(bank,idx)
    def write_bit(self,bank:Sequence[CipherBit],idx:CipherWord64,v:CipherBit)->tuple[CipherBit,...]:return self.__backend.write_bit(bank,idx,v)
    def write_word(self,bank:Sequence[CipherWord64],idx:CipherWord64,v:CipherWord64)->tuple[CipherWord64,...]:return self.__backend.write_word(bank,idx,v)
    def export_bit(self,value:CipherBit)->bytes:return self.__backend.export_bit(value)
    def import_bit(self,data:bytes)->CipherBit:return self.__backend.import_bit(data)
    def export_word64(self,value:CipherWord64)->bytes:return self.__backend.export_word64(value)
    def import_word64(self,data:bytes)->CipherWord64:return self.__backend.import_word64(data)
    def ciphertext_bit_commitment(self,value:CipherBit)->str:return self.__backend.ciphertext_bit_commitment(value)
    def ciphertext_word_commitment(self,value:CipherWord64)->str:return self.__backend.ciphertext_word_commitment(value)
    def metrics(self)->dict[str,object]:return self.__backend.metrics()
    def reset_metrics(self)->None:self.__backend.reset_metrics()
    def resident_stats(self)->dict[str,object]:return self.__backend.resident_stats()
    def release_ciphertexts(self,values:Sequence[CipherBit | CipherWord64])->int:return self.__backend.release_ciphertexts(values)
    def keccak24_words(self,state:Sequence[CipherWord64])->tuple[CipherWord64,...]:return self.__backend.keccak24_words(state)

class ReferenceFHEBackend(FHEBackend):
    """Deterministic **non-secure** backend for conformance/CI only.

    Each instance is key-domain distinct so tests catch cross-evaluator ciphertext
    reuse instead of accidentally accepting an object from another provider.
    """

    capabilities = FHECapabilities("reference-NOT-SECURE", cryptographic=False)

    def __init__(self) -> None:
        self.backend_id = f"xavi-void-reference-fhe-NOT-SECURE:{secrets.token_hex(16)}"

    def _bit(self, value: CipherBit) -> bool:
        self._check_bit(value); return bool(value.payload)

    def _word(self, value: CipherWord64) -> int:
        self._check_word(value); return int(value.payload) & MASK64

    def encrypt_bit(self, value: bool) -> CipherBit:
        if type(value) is not bool: raise TypeError("bit encryption requires bool")
        return CipherBit(self.backend_id, value)

    def decrypt_bit(self, value: CipherBit) -> bool: return self._bit(value)

    def encrypt_word64(self, value: int) -> CipherWord64:
        if not isinstance(value, int) or not 0 <= value <= MASK64: raise ValueError("word must be uint64")
        return CipherWord64(self.backend_id, value)

    def decrypt_word64(self, value: CipherWord64) -> int: return self._word(value)
    def trivial_bit(self, value: bool) -> CipherBit: return self.encrypt_bit(value)
    def trivial_word64(self, value: int) -> CipherWord64: return self.encrypt_word64(value)
    def bit_not(self, value: CipherBit) -> CipherBit: return CipherBit(self.backend_id, not self._bit(value))
    def bit_xor(self, left: CipherBit, right: CipherBit) -> CipherBit: return CipherBit(self.backend_id, self._bit(left) ^ self._bit(right))
    def bit_and(self, left: CipherBit, right: CipherBit) -> CipherBit: return CipherBit(self.backend_id, self._bit(left) and self._bit(right))
    def bit_or(self, left: CipherBit, right: CipherBit) -> CipherBit: return CipherBit(self.backend_id, self._bit(left) or self._bit(right))
    def bit_mux(self, selector: CipherBit, when_true: CipherBit, when_false: CipherBit) -> CipherBit:
        return CipherBit(self.backend_id, self._bit(when_true) if self._bit(selector) else self._bit(when_false))
    def word_xor(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: return CipherWord64(self.backend_id, self._word(left) ^ self._word(right))
    def word_and(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: return CipherWord64(self.backend_id, self._word(left) & self._word(right))
    def word_not(self, value: CipherWord64) -> CipherWord64: return CipherWord64(self.backend_id, (~self._word(value)) & MASK64)
    def word_rotl_public(self, value: CipherWord64, amount: int) -> CipherWord64:
        if not isinstance(amount, int) or not 0 <= amount < 64: raise ValueError("rotation must be in 0..63")
        x = self._word(value); r = amount
        return CipherWord64(self.backend_id, x if r == 0 else ((x << r) | (x >> (64-r))) & MASK64)
    def word_rotl_secret(self, value: CipherWord64, amount: CipherWord64) -> CipherWord64:
        return self.word_rotl_public(value, self._word(amount) & 63)
    def word_eq(self, left: CipherWord64, right: CipherWord64) -> CipherBit: return CipherBit(self.backend_id, self._word(left) == self._word(right))
    def word_mux(self, selector: CipherBit, when_true: CipherWord64, when_false: CipherWord64) -> CipherWord64:
        return CipherWord64(self.backend_id, self._word(when_true) if self._bit(selector) else self._word(when_false))
    def export_bit(self, value: CipherBit) -> bytes: return b"\x01" if self._bit(value) else b"\x00"
    def import_bit(self, data: bytes) -> CipherBit:
        if data not in {b"\x00",b"\x01"}: raise ValueError("invalid reference bit ciphertext")
        return CipherBit(self.backend_id,data==b"\x01")
    def export_word64(self, value: CipherWord64) -> bytes: return self._word(value).to_bytes(8,"little")
    def import_word64(self, data: bytes) -> CipherWord64:
        if len(data)!=8: raise ValueError("invalid reference word ciphertext")
        return CipherWord64(self.backend_id,int.from_bytes(data,"little"))

    # Reference-only accelerators preserve the evaluator API while avoiding an
    # O(register_count) Python object loop in every conformance step.
    def select_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64) -> CipherBit:
        idx = self._word(encrypted_register)
        if not 1 <= idx <= len(bank): return self.trivial_bit(False)
        return bank[idx-1]
    def select_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64) -> CipherWord64:
        idx = self._word(encrypted_register)
        if not 1 <= idx <= len(bank): return self.trivial_word64(0)
        return bank[idx-1]
    def write_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64, value: CipherBit) -> tuple[CipherBit, ...]:
        idx = self._word(encrypted_register); out = list(bank)
        if 1 <= idx <= len(out): out[idx-1] = value
        return tuple(out)
    def write_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64, value: CipherWord64) -> tuple[CipherWord64, ...]:
        idx = self._word(encrypted_register); out = list(bank)
        if 1 <= idx <= len(out): out[idx-1] = value
        return tuple(out)


class SidecarFHEBackend(FHEBackend):
    """Real-provider adapter over a strict line-delimited JSON sidecar protocol.

    The sidecar owns provider-specific TFHE/OpenFHE keys and ciphertext objects;
    Python sees opaque ciphertext handles only.  Construction fails unless the
    sidecar reports ``cryptographic=true`` and all required capabilities.
    """

    def __init__(self, command: Sequence[str], *, expected_provider: str | None = None, require_cryptographic: bool = True) -> None:
        if not command: raise ValueError("sidecar command is required")
        try:
            self._proc = subprocess.Popen(list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        except OSError as error:
            raise BackendUnavailable(f"unable to launch FHE sidecar: {error}") from error
        hello = self._call("capabilities")
        provider = str(hello.get("provider", ""))
        if expected_provider is not None and provider != expected_provider:
            self.close(); raise BackendUnavailable(f"expected provider {expected_provider!r}; sidecar reported {provider!r}")
        caps = FHECapabilities(
            provider=provider,
            cryptographic=bool(hello.get("cryptographic")),
            role=str(hello.get("role", "combined")),
            has_client_secret=bool(hello.get("has_client_secret", True)),
            supports_boolean=bool(hello.get("supports_boolean")),
            supports_word64=bool(hello.get("supports_word64")),
            supports_oblivious_select=bool(hello.get("supports_oblivious_select")),
            supports_secret_rotation=bool(hello.get("supports_secret_rotation")),
            key_id=str(hello.get("key_id", "")),
            device=str(hello.get("device", "cpu")),
            supports_bulk_registers=bool(hello.get("supports_bulk_registers", False)),
            supports_keccak24=bool(hello.get("supports_keccak24", False)),
            supports_metrics=bool(hello.get("supports_metrics", False)),
            supports_resident_sessions=bool(hello.get("supports_resident_sessions", False)),
        )
        required_ok = caps.supports_boolean and caps.supports_word64 and caps.supports_oblivious_select and caps.supports_secret_rotation
        if not required_ok or (require_cryptographic and not caps.cryptographic):
            self.close(); raise BackendUnavailable("FHE sidecar lacks required cryptographic capabilities")
        self.capabilities = caps
        identity = caps.key_id or "ephemeral"
        self.backend_id = f"xavi-void-fhe-sidecar:{provider}:{identity}"

    def close(self) -> None:
        proc = getattr(self, "_proc", None)
        if proc is not None and proc.poll() is None:
            try: self._call("close")
            except Exception: pass
            proc.terminate()

    def _call(self, op: str, **args):
        if self._proc.poll() is not None: raise BackendUnavailable("FHE sidecar terminated")
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(json.dumps({"op": op, **args}, separators=(",", ":")) + "\n"); self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line: raise BackendUnavailable("FHE sidecar returned no response")
        response = json.loads(line)
        if not response.get("ok", False): raise RuntimeError(str(response.get("error", "FHE sidecar operation failed")))
        return response.get("result", {})

    def _bh(self, c: CipherBit) -> str: self._check_bit(c); return str(c.payload)
    def _wh(self, c: CipherWord64) -> str: self._check_word(c); return str(c.payload)
    def _bit_result(self, op: str, **kwargs) -> CipherBit: return CipherBit(self.backend_id, self._call(op, **kwargs)["handle"])
    def _word_result(self, op: str, **kwargs) -> CipherWord64: return CipherWord64(self.backend_id, self._call(op, **kwargs)["handle"])

    def encrypt_bit(self, value: bool) -> CipherBit: return self._bit_result("encrypt_bit", value=bool(value))
    def decrypt_bit(self, value: CipherBit) -> bool: return bool(self._call("decrypt_bit", handle=self._bh(value))["value"])
    def encrypt_word64(self, value: int) -> CipherWord64: return self._word_result("encrypt_word64", value=int(value))
    def decrypt_word64(self, value: CipherWord64) -> int: return int(self._call("decrypt_word64", handle=self._wh(value))["value"])
    def trivial_bit(self, value: bool) -> CipherBit: return self._bit_result("trivial_bit", value=bool(value))
    def trivial_word64(self, value: int) -> CipherWord64: return self._word_result("trivial_word64", value=int(value))
    def bit_not(self, value: CipherBit) -> CipherBit: return self._bit_result("bit_not", value=self._bh(value))
    def bit_xor(self, left: CipherBit, right: CipherBit) -> CipherBit: return self._bit_result("bit_xor", left=self._bh(left), right=self._bh(right))
    def bit_and(self, left: CipherBit, right: CipherBit) -> CipherBit: return self._bit_result("bit_and", left=self._bh(left), right=self._bh(right))
    def bit_or(self, left: CipherBit, right: CipherBit) -> CipherBit: return self._bit_result("bit_or", left=self._bh(left), right=self._bh(right))
    def bit_mux(self, selector: CipherBit, when_true: CipherBit, when_false: CipherBit) -> CipherBit: return self._bit_result("bit_mux", selector=self._bh(selector), when_true=self._bh(when_true), when_false=self._bh(when_false))
    def word_xor(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: return self._word_result("word_xor", left=self._wh(left), right=self._wh(right))
    def word_and(self, left: CipherWord64, right: CipherWord64) -> CipherWord64: return self._word_result("word_and", left=self._wh(left), right=self._wh(right))
    def word_not(self, value: CipherWord64) -> CipherWord64: return self._word_result("word_not", value=self._wh(value))
    def word_rotl_public(self, value: CipherWord64, amount: int) -> CipherWord64: return self._word_result("word_rotl_public", value=self._wh(value), amount=int(amount))
    def word_rotl_secret(self, value: CipherWord64, amount: CipherWord64) -> CipherWord64: return self._word_result("word_rotl_secret", value=self._wh(value), amount=self._wh(amount))
    def word_eq(self, left: CipherWord64, right: CipherWord64) -> CipherBit: return self._bit_result("word_eq", left=self._wh(left), right=self._wh(right))
    def word_mux(self, selector: CipherBit, when_true: CipherWord64, when_false: CipherWord64) -> CipherWord64: return self._word_result("word_mux", selector=self._bh(selector), when_true=self._wh(when_true), when_false=self._wh(when_false))
    def export_bit(self, value: CipherBit) -> bytes:
        raw=self._call("export_ciphertext",kind="bit",handle=self._bh(value))["data"]
        return base64.b64decode(raw)
    def import_bit(self, data: bytes) -> CipherBit:
        return CipherBit(self.backend_id,self._call("import_ciphertext",kind="bit",data=base64.b64encode(data).decode("ascii"))["handle"])
    def export_word64(self, value: CipherWord64) -> bytes:
        raw=self._call("export_ciphertext",kind="word64",handle=self._wh(value))["data"]
        return base64.b64decode(raw)
    def import_word64(self, data: bytes) -> CipherWord64:
        return CipherWord64(self.backend_id,self._call("import_ciphertext",kind="word64",data=base64.b64encode(data).decode("ascii"))["handle"])
    def ciphertext_bit_commitment(self, value: CipherBit) -> str: return str(self._call("ciphertext_commitment", kind="bit", handle=self._bh(value))["commitment"])
    def ciphertext_word_commitment(self, value: CipherWord64) -> str: return str(self._call("ciphertext_commitment", kind="word64", handle=self._wh(value))["commitment"])

    def select_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64) -> CipherBit:
        if not self.capabilities.supports_bulk_registers:
            return super().select_bit(bank, encrypted_register)
        result=self._call("select_register",kind="bit",bank=[self._bh(v) for v in bank],index=self._wh(encrypted_register))
        return CipherBit(self.backend_id,result["handle"])

    def select_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64) -> CipherWord64:
        if not self.capabilities.supports_bulk_registers:
            return super().select_word(bank, encrypted_register)
        result=self._call("select_register",kind="word64",bank=[self._wh(v) for v in bank],index=self._wh(encrypted_register))
        return CipherWord64(self.backend_id,result["handle"])

    def write_bit(self, bank: Sequence[CipherBit], encrypted_register: CipherWord64, value: CipherBit) -> tuple[CipherBit, ...]:
        if not self.capabilities.supports_bulk_registers:
            return super().write_bit(bank, encrypted_register, value)
        result=self._call("write_register",kind="bit",bank=[self._bh(v) for v in bank],index=self._wh(encrypted_register),value=self._bh(value))
        return tuple(CipherBit(self.backend_id,h) for h in result["handles"])

    def write_word(self, bank: Sequence[CipherWord64], encrypted_register: CipherWord64, value: CipherWord64) -> tuple[CipherWord64, ...]:
        if not self.capabilities.supports_bulk_registers:
            return super().write_word(bank, encrypted_register, value)
        result=self._call("write_register",kind="word64",bank=[self._wh(v) for v in bank],index=self._wh(encrypted_register),value=self._wh(value))
        return tuple(CipherWord64(self.backend_id,h) for h in result["handles"])

    def metrics(self) -> dict[str, object]:
        if not self.capabilities.supports_metrics: return {}
        return dict(self._call("metrics"))

    def reset_metrics(self) -> None:
        if self.capabilities.supports_metrics: self._call("reset_metrics")

    def resident_stats(self) -> dict[str, object]:
        if not self.capabilities.supports_resident_sessions: return {}
        return dict(self._call("resident_stats"))

    def release_ciphertexts(self, values: Sequence[CipherBit | CipherWord64]) -> int:
        if not self.capabilities.supports_resident_sessions: return 0
        handles=[]
        for value in values:
            if isinstance(value,CipherBit): handles.append(self._bh(value))
            elif isinstance(value,CipherWord64): handles.append(self._wh(value))
            else: raise TypeError("release expects ciphertext values")
        return int(self._call("release_handles",handles=handles).get("released",0))

    def keccak24_words(self, state: Sequence[CipherWord64]) -> tuple[CipherWord64, ...]:
        if not self.capabilities.supports_keccak24:
            return super().keccak24_words(state)
        if len(state)!=25: raise ValueError("Keccak state requires exactly 25 encrypted words")
        result=self._call("keccak24",state=[self._wh(v) for v in state])
        handles=result.get("handles",[])
        if len(handles)!=25: raise RuntimeError("FHE sidecar returned invalid Keccak state")
        return tuple(CipherWord64(self.backend_id,h) for h in handles)


class TFHESidecarBackend(SidecarFHEBackend):
    def __init__(self, command: Sequence[str]) -> None: super().__init__(command, expected_provider="tfhe")


class OpenFHESidecarBackend(SidecarFHEBackend):
    def __init__(self, command: Sequence[str]) -> None: super().__init__(command, expected_provider="openfhe")


_BOOL_OP_TAG = {Op.INPUT:1, Op.CONST_FALSE:2, Op.CONST_TRUE:3, Op.XOR:4, Op.AND:5, Op.OR:6, Op.NOT:7, Op.COPY:8}
_WORD_OP_TAG = {WordOp.XOR5:1, WordOp.XOR_ROT1:2, WordOp.XOR2:3, WordOp.ROT_COPY:4, WordOp.CHI:5, WordOp.XOR_CONST:6}
_NOP_TAG = 255


def _id_words(identifier: str) -> tuple[int, ...]:
    if not identifier.startswith(ID_PREFIX): raise ValueError("identifier is not xavi-void SHAKE256-512")
    token = identifier[len(ID_PREFIX):]
    raw = base64.urlsafe_b64decode(token + "=" * ((4 - len(token) % 4) % 4))
    if len(raw) != 64: raise ValueError("identifier digest must be 64 bytes")
    return tuple(int.from_bytes(raw[i:i+8], "little") for i in range(0,64,8))



def decrypt_encrypted_id(words: Sequence[CipherWord64], backend: FHEBackend) -> str:
    """Trusted-client helper used only after evaluation, never by evaluator code."""
    raw=b"".join(backend.decrypt_word64(word).to_bytes(8,"little") for word in words)
    if len(raw)!=64: raise ValueError("encrypted identifier must contain eight words")
    token=base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return ID_PREFIX+token

def _encrypt_id(identifier: str, backend: FHEBackend) -> tuple[CipherWord64, ...]:
    return tuple(backend.encrypt_word64(word) for word in _id_words(identifier))


def encrypt_program_representation(program: ExecutionIR, backend: FHEBackend, *, padded_instruction_count: int | None = None, padded_register_count: int | None = None) -> EncryptedProgram:
    program.validate()
    target = len(program.instructions) if padded_instruction_count is None else padded_instruction_count
    registers = program.register_count.value if padded_register_count is None else padded_register_count
    if target < len(program.instructions) or target < 1: raise ValueError("padded instruction count cannot truncate the program")
    if registers < program.register_count.value: raise ValueError("padded register count cannot truncate the register bank")
    encrypted: list[EncryptedInstruction] = []
    for ins in program.instructions:
        sources = [s.value for s in ins.sources]
        encrypted.append(EncryptedInstruction(
            ins.instruction_id,
            backend.encrypt_word64(_BOOL_OP_TAG[ins.op]),
            backend.encrypt_word64(ins.destination.value),
            backend.encrypt_word64(sources[0] if sources else 1),
            backend.encrypt_word64(sources[1] if len(sources)>1 else 1),
            backend.encrypt_word64(ins.input_slot.value if ins.input_slot is not None else 1),
        ))
    # Encrypted NOP padding writes register 1 back to itself.
    for i in range(len(encrypted)+1, target+1):
        encrypted.append(EncryptedInstruction(InstructionId(i), backend.encrypt_word64(_NOP_TAG), backend.encrypt_word64(1), backend.encrypt_word64(1), backend.encrypt_word64(1), backend.encrypt_word64(1)))
    semantic_id = semantic_from_execution(program).semantic_id()
    representation_id = program.representation_id()
    return EncryptedProgram(
        backend.backend_id, _encrypt_id(semantic_id, backend), _encrypt_id(representation_id, backend),
        PositiveExtent(registers), tuple(encrypted), tuple(backend.encrypt_word64(o.value) for o in program.outputs), PositiveExtent(target)
    )


def encrypt_word_program(program: WordProgram, backend: FHEBackend, *, semantic_id: str, padded_instruction_count: int | None = None, padded_register_count: int | None = None) -> EncryptedWordProgram:
    program.validate(); target = len(program.instructions) if padded_instruction_count is None else padded_instruction_count
    registers = program.register_count.value if padded_register_count is None else padded_register_count
    if target < len(program.instructions) or target < 1: raise ValueError("padded instruction count cannot truncate word program")
    if registers < program.register_count.value: raise ValueError("padded register count cannot truncate word register bank")
    out: list[EncryptedWordInstruction] = []
    for ins in program.instructions:
        sources = [s.value for s in ins.sources] + [1]*5
        out.append(EncryptedWordInstruction(
            ins.instruction_id, backend.encrypt_word64(_WORD_OP_TAG[ins.op]), backend.encrypt_word64(ins.destination.value),
            *(backend.encrypt_word64(sources[i]) for i in range(5)),
            backend.encrypt_word64(ins.rotate if ins.rotate is not None else 0),
            backend.encrypt_word64(ins.immediate if ins.immediate is not None else 0),
        ))
    for i in range(len(out)+1,target+1):
        out.append(EncryptedWordInstruction(InstructionId(i), backend.encrypt_word64(_NOP_TAG), backend.encrypt_word64(1), *(backend.encrypt_word64(1) for _ in range(5)), backend.encrypt_word64(0), backend.encrypt_word64(0)))
    return EncryptedWordProgram(backend.backend_id, _encrypt_id(semantic_id, backend), _encrypt_id(program.representation_id(), backend), PositiveExtent(registers), tuple(out), PositiveExtent(target))


def _select_encrypted_input(inputs: Sequence[CipherBit], input_slot: CipherWord64, backend: FHEBackend) -> CipherBit:
    result = backend.trivial_bit(False)
    for ordinal, value in enumerate(inputs, start=1):
        match = backend.word_eq(input_slot, backend.trivial_word64(ordinal))
        result = backend.bit_mux(match, value, result)
    return result


def _select_bit_candidate(opcode: CipherWord64, tag: int, candidate: CipherBit, current: CipherBit, backend: FHEBackend) -> CipherBit:
    return backend.bit_mux(backend.word_eq(opcode, backend.trivial_word64(tag)), candidate, current)


def oblivious_boolean_step(
    bank: Sequence[CipherBit],
    ins: EncryptedInstruction,
    encrypted_inputs: Sequence[CipherBit],
    backend: FHEBackend,
) -> tuple[CipherBit, ...]:
    """Execute one encrypted Boolean instruction without plaintext dispatch."""
    a = backend.select_bit(bank, ins.source_a); b = backend.select_bit(bank, ins.source_b)
    input_value = _select_encrypted_input(encrypted_inputs, ins.input_slot, backend)
    candidates = {
        1: input_value,
        2: backend.trivial_bit(False),
        3: backend.trivial_bit(True),
        4: backend.bit_xor(a,b),
        5: backend.bit_and(a,b),
        6: backend.bit_or(a,b),
        7: backend.bit_not(a),
        8: a,
        _NOP_TAG: backend.select_bit(bank, ins.destination),
    }
    selected = backend.trivial_bit(False)
    for tag, candidate in candidates.items():
        selected = _select_bit_candidate(ins.opcode_tag, tag, candidate, selected, backend)
    return backend.write_bit(bank, ins.destination, selected)


def execute_oblivious_encrypted_program(program: EncryptedProgram, encrypted_inputs: Mapping[Ordinal, CipherBit], backend: FHEBackend) -> tuple[CipherBit, ...]:
    """Evaluate encrypted code + encrypted data without plaintext dispatch."""
    if program.backend_id != backend.backend_id: raise ValueError("encrypted program belongs to another backend")
    slots = tuple(sorted(encrypted_inputs, key=lambda s:s.value))
    if slots and [s.value for s in slots] != list(range(1,len(slots)+1)): raise ValueError("encrypted inputs must be contiguous one-origin slots")
    inputs = tuple(encrypted_inputs[s] for s in slots)
    bank: tuple[CipherBit, ...] = tuple(backend.trivial_bit(False) for _ in range(program.register_count.value))
    for ins in program.instructions:
        bank = oblivious_boolean_step(bank, ins, inputs, backend)
    return tuple(backend.select_bit(bank, out) for out in program.outputs)


def execute_encrypted_data(program: ExecutionIR, encrypted_inputs: Mapping[Ordinal, CipherBit], backend: FHEBackend) -> tuple[CipherBit, ...]:
    """Public-code / encrypted-data compatibility path."""
    encrypted_program = encrypt_program_representation(program, backend)
    return execute_oblivious_encrypted_program(encrypted_program, encrypted_inputs, backend)


def _select_word_candidate(opcode: CipherWord64, tag: int, candidate: CipherWord64, current: CipherWord64, backend: FHEBackend) -> CipherWord64:
    return backend.word_mux(backend.word_eq(opcode, backend.trivial_word64(tag)), candidate, current)


def oblivious_word_step(
    bank: Sequence[CipherWord64],
    ins: EncryptedWordInstruction,
    backend: FHEBackend,
) -> tuple[CipherWord64, ...]:
    """Execute one encrypted word instruction without inspecting its fields."""
    a=backend.select_word(bank,ins.source_a); b=backend.select_word(bank,ins.source_b); c=backend.select_word(bank,ins.source_c); d=backend.select_word(bank,ins.source_d); e=backend.select_word(bank,ins.source_e)
    xor5 = backend.word_xor(backend.word_xor(backend.word_xor(backend.word_xor(a,b),c),d),e)
    xor_rot1 = backend.word_xor(a,backend.word_rotl_public(b,1))
    xor2 = backend.word_xor(a,b)
    rot_copy = backend.word_rotl_secret(a,ins.rotate)
    chi = backend.word_xor(a,backend.word_and(backend.word_not(b),c))
    xor_const = backend.word_xor(a,ins.immediate)
    nop = backend.select_word(bank,ins.destination)
    selected = backend.trivial_word64(0)
    for tag,candidate in ((1,xor5),(2,xor_rot1),(3,xor2),(4,rot_copy),(5,chi),(6,xor_const),(_NOP_TAG,nop)):
        selected = _select_word_candidate(ins.opcode_tag,tag,candidate,selected,backend)
    return backend.write_word(bank,ins.destination,selected)


def execute_oblivious_word_program(program: EncryptedWordProgram, encrypted_state: Sequence[CipherWord64], backend: FHEBackend) -> tuple[CipherWord64, ...]:
    if program.backend_id != backend.backend_id: raise ValueError("encrypted word program belongs to another backend")
    if len(encrypted_state) != 25: raise ValueError("Keccak encrypted state requires 25 words")
    bank: tuple[CipherWord64, ...] = tuple(encrypted_state) + tuple(backend.trivial_word64(0) for _ in range(program.register_count.value-25))
    for ins in program.instructions:
        bank = oblivious_word_step(bank, ins, backend)
    return tuple(bank[:25])


def execute_keccak24_execution_class(encrypted_state: Sequence[CipherWord64], backend: FHEBackend) -> tuple[CipherWord64, ...]:
    """Execute the public fixed Keccak-24 execution class in one provider call.

    This is an optimization lane, not a replacement for encrypted ExecutionIR
    conformance.  The caller chooses the public execution class; no encrypted
    opcode/register field is decrypted or used in a plaintext branch.
    """
    if not backend.capabilities.supports_keccak24:
        raise BackendUnavailable("provider does not support the Keccak-24 execution class")
    if len(encrypted_state)!=25: raise ValueError("Keccak encrypted state requires 25 words")
    return backend.keccak24_words(tuple(encrypted_state))


def encrypted_program_commitment(program: EncryptedProgram, backend: FHEBackend) -> str:
    """Commit to ciphertext objects and public execution-class shape without decrypting them."""
    if program.backend_id != backend.backend_id: raise ValueError("encrypted program belongs to another backend")
    fields: list[bytes] = []
    for word in program.encrypted_semantic_id + program.encrypted_representation_id:
        fields.append(backend.ciphertext_word_commitment(word).encode("ascii"))
    for ins in program.instructions:
        for word in (ins.opcode_tag, ins.destination, ins.source_a, ins.source_b, ins.input_slot):
            fields.append(backend.ciphertext_word_commitment(word).encode("ascii"))
    for out in program.outputs: fields.append(backend.ciphertext_word_commitment(out).encode("ascii"))
    return content_id("XAVI-VOID/ENCRYPTED-PROGRAM/v1", str(program.register_count.value).encode(), str(program.padded_instruction_count.value).encode(), *fields)

def encrypted_word_program_commitment(program: EncryptedWordProgram, backend: FHEBackend) -> str:
    if program.backend_id != backend.backend_id: raise ValueError("encrypted word program belongs to another backend")
    fields: list[bytes] = []
    for word in program.encrypted_semantic_id + program.encrypted_representation_id:
        fields.append(backend.ciphertext_word_commitment(word).encode("ascii"))
    for ins in program.instructions:
        for word in (ins.opcode_tag,ins.destination,ins.source_a,ins.source_b,ins.source_c,ins.source_d,ins.source_e,ins.rotate,ins.immediate):
            fields.append(backend.ciphertext_word_commitment(word).encode("ascii"))
    return content_id("XAVI-VOID/ENCRYPTED-WORD-PROGRAM/v1",str(program.register_count.value).encode(),str(program.padded_instruction_count.value).encode(),*fields)
