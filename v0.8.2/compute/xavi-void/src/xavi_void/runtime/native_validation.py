"""Rev 1.2-dev4 native encrypted-runtime validation.

This module is deliberately provider-neutral.  It drives the exact same SHAKE
workload through the standard library, SemanticIR, plaintext ExecutionIR, and a
cryptographic FHE provider, records provider timing/residency evidence, and
performs a conservative static audit for evaluator-side secret-dependent
branching.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ast
import hashlib
import inspect
import json
import os
import random
import shlex
import textwrap
from typing import Iterable, Sequence

from xavi_void.crypto.keccak import SHAKE256_512_OUTPUT_BYTES
from .encrypted import FHEBackend, FHEClientView, FHEEvaluatorView, TFHESidecarBackend
from .shake_encrypted import (
    compile_encrypted_shake_program,
    decrypt_encrypted_shake_result,
    execute_encrypted_shake256_512,
    prepare_encrypted_shake_input,
)
from .shake_workload import compile_shake256_512, execute_shake_plan, execute_shake_semantic


@dataclass(frozen=True, slots=True)
class ShakeVector:
    name: str
    message: bytes


@dataclass(frozen=True, slots=True)
class VectorResult:
    name: str
    input_bytes: int
    absorb_blocks: int
    standard_hex: str
    semantic_match: bool
    plaintext_execution_match: bool
    encrypted_execution_match: bool | None
    specialized_execution_match: bool | None
    encrypted_ns: int
    specialized_ns: int | None
    provider_metrics: dict[str, object]
    specialized_metrics: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class SecrecyAudit:
    passed: bool
    forbidden_decrypt_references: tuple[str, ...]
    secret_branch_references: tuple[str, ...]
    audited_functions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeValidationReport:
    schema: str
    provider: str
    device: str
    key_id: str
    cryptographic: bool
    secrecy_audit: SecrecyAudit
    required_oblivious_execution_ir: bool
    required_specialized_keccak: bool
    vectors: tuple[VectorResult, ...]

    @property
    def passed(self) -> bool:
        return bool(
            self.cryptographic
            and self.secrecy_audit.passed
            and self.vectors
            and all(v.semantic_match and v.plaintext_execution_match
                    and ((v.encrypted_execution_match is True) if self.required_oblivious_execution_ir else True)
                    and ((v.specialized_execution_match is True) if self.required_specialized_keccak else True)
                    for v in self.vectors)
        )

    def canonical(self) -> dict[str, object]:
        value=asdict(self)
        value['passed']=self.passed
        return value


_BOUNDARY_LENGTHS=(135,136,137,271,272,273,544)


def _pattern(length:int)->bytes:
    if length < 0: raise ValueError('length cannot be negative')
    seed=hashlib.shake_256(f'xavi-void/dev3/vector/{length}'.encode()).digest(length)
    return seed


def shake_validation_vectors(*, random_cases:int=4, random_seed:int=0x58415649)->tuple[ShakeVector,...]:
    """Canonical boundary corpus plus deterministic multiblock/random cases."""
    vectors=[ShakeVector('empty',b''),ShakeVector('abc',b'abc')]
    vectors.extend(ShakeVector(f'boundary-{n}',_pattern(n)) for n in _BOUNDARY_LENGTHS)
    rng=random.Random(random_seed)
    for ordinal in range(1,random_cases+1):
        n=rng.randint(1,1024)
        vectors.append(ShakeVector(f'random-{ordinal}-{n}',_pattern(n)))
    return tuple(vectors)


_SECRET_TOKENS={
    'opcode_tag','destination','source_a','source_b','source_c','source_d','source_e',
    'rotate','immediate','encrypted_register','encrypted_inputs',
}
_FORBIDDEN_DECRYPT={'decrypt_bit','decrypt_word64','decrypt_encrypted_id'}


class _BranchVisitor(ast.NodeVisitor):
    def __init__(self, source:str, label:str):
        self.source=source; self.label=label; self.decrypt=[]; self.branches=[]
    def visit_Call(self,node:ast.Call):
        name=None
        if isinstance(node.func,ast.Attribute): name=node.func.attr
        elif isinstance(node.func,ast.Name): name=node.func.id
        if name in _FORBIDDEN_DECRYPT:
            self.decrypt.append(f'{self.label}:{getattr(node,"lineno",1)}:{name}')
        self.generic_visit(node)
    def _test(self,node):
        text=ast.get_source_segment(self.source,node) or ''
        hits=sorted(t for t in _SECRET_TOKENS if t in text)
        if hits:self.branches.append(f'{self.label}:{getattr(node,"lineno",1)}:{",".join(hits)}')
    def visit_If(self,node:ast.If): self._test(node.test); self.generic_visit(node)
    def visit_IfExp(self,node:ast.IfExp): self._test(node.test); self.generic_visit(node)
    def visit_While(self,node:ast.While): self._test(node.test); self.generic_visit(node)


def audit_evaluator_secrecy() -> SecrecyAudit:
    """Fail conservatively if evaluator functions decrypt or branch on encrypted fields."""
    from . import encrypted as encrypted_mod
    from . import shake_encrypted as shake_mod
    from . import remote_tfhe as remote_tfhe_mod
    targets=(
        encrypted_mod.oblivious_word_step,
        encrypted_mod.execute_oblivious_word_program,
        encrypted_mod.execute_keccak24_execution_class,
        shake_mod.execute_encrypted_shake256_512,
        remote_tfhe_mod.ProductionTFHEWorker.execute_shake,
    )
    decrypt=[]; branches=[]; names=[]
    for fn in targets:
        src=textwrap.dedent(inspect.getsource(fn)); label=f'{fn.__module__}.{fn.__name__}'; names.append(label)
        tree=ast.parse(src); visitor=_BranchVisitor(src,label); visitor.visit(tree)
        decrypt.extend(visitor.decrypt);branches.extend(visitor.branches)
    return SecrecyAudit(not decrypt and not branches,tuple(decrypt),tuple(branches),tuple(names))


def _run_encrypted(message:bytes, backend:FHEBackend, *, specialized:bool):
    client=FHEClientView(backend); evaluator=FHEEvaluatorView(backend)
    encrypted_input=prepare_encrypted_shake_input(message,client)
    encrypted_program=None if specialized else compile_encrypted_shake_program(client)
    result=execute_encrypted_shake256_512(encrypted_input,encrypted_program,evaluator,specialized_keccak=specialized)
    return decrypt_encrypted_shake_result(result,client), result


def validate_native_provider(
    backend:FHEBackend,
    *,
    vectors:Sequence[ShakeVector]|None=None,
    run_oblivious_execution_ir:bool=True,
    run_specialized_keccak:bool=True,
) -> NativeValidationReport:
    if not backend.capabilities.cryptographic:
        raise ValueError('native validation requires a cryptographic FHE provider')
    chosen=tuple(vectors or shake_validation_vectors())
    if not chosen: raise ValueError('at least one validation vector is required')
    rows=[]
    for vector in chosen:
        message=vector.message
        standard=hashlib.shake_256(message).digest(SHAKE256_512_OUTPUT_BYTES)
        semantic=execute_shake_semantic(message)
        plan=compile_shake256_512(message)
        plaintext=execute_shake_plan(message,plan)
        encrypted_match=None; encrypted_ns=0; metrics={}
        if run_oblivious_execution_ir:
            encrypted, er=_run_encrypted(message,backend,specialized=False)
            encrypted_match=encrypted==standard
            encrypted_ns=er.timing.full_evaluation_ns if er.timing else 0
            metrics=er.timing.provider_metrics if er.timing else {}
        specialized_match=None; specialized_ns=None; specialized_metrics=None
        if run_specialized_keccak and backend.capabilities.supports_keccak24:
            specialized, sr=_run_encrypted(message,backend,specialized=True)
            specialized_match=specialized==standard
            specialized_ns=sr.timing.full_evaluation_ns if sr.timing else 0
            specialized_metrics=sr.timing.provider_metrics if sr.timing else {}
        rows.append(VectorResult(
            vector.name,len(message),len(plan.absorb_schedule),standard.hex(),semantic==standard,
            plaintext==standard,encrypted_match,specialized_match,encrypted_ns,specialized_ns,
            dict(metrics),None if specialized_metrics is None else dict(specialized_metrics),
        ))
    caps=backend.capabilities
    required_specialized=bool(run_specialized_keccak and backend.capabilities.supports_keccak24)
    return NativeValidationReport('xavi-void-native-tfhe-validation-v1',caps.provider,caps.device,caps.key_id,caps.cryptographic,audit_evaluator_secrecy(),run_oblivious_execution_ir,required_specialized,tuple(rows))


def configured_tfhe_backend(env_var:str='XAVI_VOID_TFHE_SIDECAR')->TFHESidecarBackend:
    command=os.environ.get(env_var)
    if not command: raise RuntimeError(f'{env_var} is not configured')
    return TFHESidecarBackend(shlex.split(command))


def report_json(report:NativeValidationReport)->str:
    return json.dumps(report.canonical(),indent=2,sort_keys=True)
