"""Layered Boolean equivalence verification.

Proof order:
1. exhaustive truth table for small public input domains;
2. exact algebraic-normal-form (ANF) normalization under a monomial budget;
3. bounded Tseitin-CNF SAT search using a deterministic DPLL solver;
4. explicit UNKNOWN when proof resources are exhausted.

UNKNOWN is never accepted as equivalence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import product
from typing import Iterable

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import semantic_bit_label
from xavi_void.math.types import Ordinal

from .ir import ExecutionIR, Op, evaluate
from .semantic import semantic_from_execution

DEFAULT_MAX_EXACT_INPUTS = 12
DEFAULT_ANF_MONOMIAL_BUDGET = 50_000
DEFAULT_SAT_DECISION_BUDGET = 100_000


class EquivalenceStatus(str, Enum):
    PROVED = "PROVED"
    DISPROVED = "DISPROVED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class BehaviorCommitment:
    behavior_id: str
    input_slots: tuple[int, ...]
    output_arity: int
    vector_count: int
    truth_table_commitment: str

    def canonical(self) -> dict:
        return {
            "behavior_id": self.behavior_id,
            "input_slots": list(self.input_slots),
            "output_arity": self.output_arity,
            "vector_count": self.vector_count,
            "truth_table_commitment": self.truth_table_commitment,
        }


@dataclass(frozen=True, slots=True)
class EquivalenceWitness:
    left_representation_id: str
    right_representation_id: str
    behavior_id: str
    proof_kind: str
    input_slots: tuple[int, ...]
    vector_count: int
    proof_commitment: str

    def witness_id(self) -> str:
        return content_id(
            "XAVI-VOID/PROGRAM-EQUIVALENCE-WITNESS/v1",
            canonical_bytes(
                {
                    "left_representation_id": self.left_representation_id,
                    "right_representation_id": self.right_representation_id,
                    "behavior_id": self.behavior_id,
                    "proof_kind": self.proof_kind,
                    "input_slots": list(self.input_slots),
                    "vector_count": self.vector_count,
                    "proof_commitment": self.proof_commitment,
                }
            ),
        )


@dataclass(frozen=True, slots=True)
class EquivalenceResult:
    status: EquivalenceStatus
    proof_kind: str
    behavior_id: str | None
    witness: EquivalenceWitness | None
    counterexample: tuple[tuple[int, bool], ...] | None = None
    reason: str | None = None


def _bit_token(value: bool) -> str:
    return semantic_bit_label(value)


def exact_behavior(program: ExecutionIR, *, max_inputs: int = DEFAULT_MAX_EXACT_INPUTS) -> BehaviorCommitment:
    program.validate()
    input_slots = program.input_slots()
    if len(input_slots) > max_inputs:
        raise ValueError(
            f"exact behavior proof supports at most {max_inputs} inputs; got {len(input_slots)}"
        )
    rows: list[dict] = []
    for vector_ordinal, bits in enumerate(product((False, True), repeat=len(input_slots)), start=1):
        inputs = {slot: bit for slot, bit in zip(input_slots, bits, strict=True)}
        outputs = evaluate(program, inputs).outputs
        rows.append(
            {
                "vector": vector_ordinal,
                "inputs": [_bit_token(bit) for bit in bits],
                "outputs": [_bit_token(bit) for bit in outputs],
            }
        )
    truth_table_commitment = content_id(
        "XAVI-VOID/BOOLEAN-TRUTH-TABLE/v1",
        canonical_bytes(
            {
                "input_slots": [slot.value for slot in input_slots],
                "output_arity": len(program.outputs),
                "rows": rows,
            }
        ),
    )
    behavior_id = content_id(
        "XAVI-VOID/BOOLEAN-BEHAVIOR/v1",
        canonical_bytes(
            {
                "input_slots": [slot.value for slot in input_slots],
                "output_arity": len(program.outputs),
                "truth_table_commitment": truth_table_commitment,
            }
        ),
    )
    return BehaviorCommitment(
        behavior_id,
        tuple(slot.value for slot in input_slots),
        len(program.outputs),
        len(rows),
        truth_table_commitment,
    )


# A polynomial is a GF(2) set of monomials; a monomial is a frozenset of input ordinals.
Polynomial = frozenset[frozenset[int]]
_ZERO: Polynomial = frozenset()
_ONE: Polynomial = frozenset({frozenset()})


def _pxor(left: Polynomial, right: Polynomial) -> Polynomial:
    return frozenset(set(left) ^ set(right))


def _pmul(left: Polynomial, right: Polynomial, budget: int) -> Polynomial:
    if not left or not right:
        return _ZERO
    out: set[frozenset[int]] = set()
    for a in left:
        for b in right:
            term = frozenset(set(a) | set(b))
            if term in out:
                out.remove(term)
            else:
                out.add(term)
            if len(out) > budget:
                raise OverflowError("ANF monomial budget exceeded")
    return frozenset(out)


def _anf(program: ExecutionIR, budget: int) -> tuple[Polynomial, ...]:
    program.validate()
    regs: dict[int, Polynomial] = {}
    for instruction in program.instructions:
        if instruction.op == Op.INPUT:
            assert instruction.input_slot is not None
            value = frozenset({frozenset({instruction.input_slot.value})})
        elif instruction.op == Op.CONST_FALSE:
            value = _ZERO
        elif instruction.op == Op.CONST_TRUE:
            value = _ONE
        elif instruction.op == Op.COPY:
            value = regs[instruction.sources[0].value]
        elif instruction.op == Op.NOT:
            value = _pxor(_ONE, regs[instruction.sources[0].value])
        elif instruction.op == Op.XOR:
            value = _pxor(regs[instruction.sources[0].value], regs[instruction.sources[1].value])
        elif instruction.op == Op.AND:
            value = _pmul(
                regs[instruction.sources[0].value], regs[instruction.sources[1].value], budget
            )
        elif instruction.op == Op.OR:
            left = regs[instruction.sources[0].value]
            right = regs[instruction.sources[1].value]
            value = _pxor(_pxor(left, right), _pmul(left, right, budget))
        else:  # pragma: no cover
            raise AssertionError("unknown op")
        if len(value) > budget:
            raise OverflowError("ANF monomial budget exceeded")
        regs[instruction.destination.value] = value
    return tuple(regs[output.value] for output in program.outputs)


def _anf_canonical(outputs: tuple[Polynomial, ...], input_slots: tuple[Ordinal, ...]) -> dict:
    def poly_obj(poly: Polynomial) -> list[list[int]]:
        return [list(term) for term in sorted((tuple(sorted(m)) for m in poly), key=lambda x: (len(x), x))]
    return {
        "input_slots": [slot.value for slot in input_slots],
        "outputs": [poly_obj(poly) for poly in outputs],
    }


class _SatBudgetExceeded(RuntimeError):
    pass


class _CNFBuilder:
    def __init__(self, input_count: int) -> None:
        self.next_var = input_count + 1
        self.clauses: list[tuple[int, ...]] = []
        self.shared_inputs = {slot: slot for slot in range(1, input_count + 1)}

    def new_var(self) -> int:
        value = self.next_var
        self.next_var += 1
        return value

    def add(self, *lits: int) -> None:
        self.clauses.append(tuple(lits))

    def encode_program(self, program: ExecutionIR) -> list[int]:
        regs: dict[int, int] = {}
        for instruction in program.instructions:
            if instruction.op == Op.INPUT:
                assert instruction.input_slot is not None
                regs[instruction.destination.value] = self.shared_inputs[instruction.input_slot.value]
                continue
            z = self.new_var()
            regs[instruction.destination.value] = z
            if instruction.op == Op.CONST_FALSE:
                self.add(-z)
            elif instruction.op == Op.CONST_TRUE:
                self.add(z)
            elif instruction.op == Op.COPY:
                x = regs[instruction.sources[0].value]
                self.add(-z, x); self.add(z, -x)
            elif instruction.op == Op.NOT:
                x = regs[instruction.sources[0].value]
                self.add(z, x); self.add(-z, -x)
            elif instruction.op == Op.AND:
                x, y = (regs[s.value] for s in instruction.sources)
                self.add(-z, x); self.add(-z, y); self.add(z, -x, -y)
            elif instruction.op == Op.OR:
                x, y = (regs[s.value] for s in instruction.sources)
                self.add(z, -x); self.add(z, -y); self.add(-z, x, y)
            elif instruction.op == Op.XOR:
                x, y = (regs[s.value] for s in instruction.sources)
                self.add(x, y, -z); self.add(-x, -y, -z)
                self.add(x, -y, z); self.add(-x, y, z)
            else:  # pragma: no cover
                raise AssertionError("unknown op")
        return [regs[output.value] for output in program.outputs]

    def xor_var(self, x: int, y: int) -> int:
        z = self.new_var()
        self.add(x, y, -z); self.add(-x, -y, -z)
        self.add(x, -y, z); self.add(-x, y, z)
        return z


def _simplify_clauses(
    clauses: tuple[tuple[int, ...], ...], assignment: dict[int, bool]
) -> tuple[tuple[int, ...], ...] | None:
    simplified: list[tuple[int, ...]] = []
    for clause in clauses:
        keep: list[int] = []
        satisfied = False
        for lit in clause:
            var = abs(lit)
            if var in assignment:
                if assignment[var] == (lit > 0):
                    satisfied = True
                    break
            else:
                keep.append(lit)
        if satisfied:
            continue
        if not keep:
            return None
        simplified.append(tuple(keep))
    return tuple(simplified)


def _dpll(
    clauses: tuple[tuple[int, ...], ...], assignment: dict[int, bool], budget: list[int]
) -> dict[int, bool] | None:
    if budget[0] <= 0:
        raise _SatBudgetExceeded
    budget[0] -= 1
    clauses = _simplify_clauses(clauses, assignment)
    if clauses is None:
        return None
    if not clauses:
        return assignment

    changed = True
    while changed:
        changed = False
        units = [clause[0] for clause in clauses if len(clause) == 1]
        if units:
            for lit in units:
                var, val = abs(lit), lit > 0
                if var in assignment and assignment[var] != val:
                    return None
                assignment[var] = val
            clauses = _simplify_clauses(clauses, assignment)
            if clauses is None:
                return None
            if not clauses:
                return assignment
            changed = True

    # Deterministic shortest-clause / smallest-variable branching.
    clause = min(clauses, key=lambda c: (len(c), tuple(abs(v) for v in c)))
    var = min(abs(lit) for lit in clause if abs(lit) not in assignment)
    for val in (False, True):
        trial = dict(assignment)
        trial[var] = val
        result = _dpll(clauses, trial, budget)
        if result is not None:
            return result
    return None


def _sat_difference(
    left: ExecutionIR, right: ExecutionIR, decision_budget: int
) -> tuple[bool | None, dict[int, bool] | None, str]:
    input_slots = left.input_slots()
    builder = _CNFBuilder(len(input_slots))
    lout = builder.encode_program(left)
    rout = builder.encode_program(right)
    diffs = [builder.xor_var(a, b) for a, b in zip(lout, rout, strict=True)]
    builder.add(*diffs)  # At least one public output differs.
    proof_commitment = content_id(
        "XAVI-VOID/SAT-EQUIVALENCE-CNF/v1",
        canonical_bytes({"var_count": builder.next_var - 1, "clauses": [list(c) for c in builder.clauses]}),
    )
    try:
        model = _dpll(tuple(builder.clauses), {}, [decision_budget])
    except _SatBudgetExceeded:
        return None, None, proof_commitment
    return model is not None, model, proof_commitment


def _interface_error(left: ExecutionIR, right: ExecutionIR) -> str | None:
    if tuple(slot.value for slot in left.input_slots()) != tuple(slot.value for slot in right.input_slots()):
        return "program input interfaces differ"
    if len(left.outputs) != len(right.outputs):
        return "program output arity differs"
    return None


def verify_equivalence(
    left: ExecutionIR,
    right: ExecutionIR,
    *,
    exhaustive_max_inputs: int = DEFAULT_MAX_EXACT_INPUTS,
    anf_monomial_budget: int = DEFAULT_ANF_MONOMIAL_BUDGET,
    sat_decision_budget: int = DEFAULT_SAT_DECISION_BUDGET,
) -> EquivalenceResult:
    left.validate(); right.validate()
    interface_error = _interface_error(left, right)
    if interface_error:
        return EquivalenceResult(EquivalenceStatus.DISPROVED, "interface", None, None, reason=interface_error)
    slots = left.input_slots()

    if len(slots) <= exhaustive_max_inputs:
        lb = exact_behavior(left, max_inputs=exhaustive_max_inputs)
        rb = exact_behavior(right, max_inputs=exhaustive_max_inputs)
        if lb.behavior_id != rb.behavior_id:
            # Produce first concrete counterexample.
            for bits in product((False, True), repeat=len(slots)):
                inp = {slot: bit for slot, bit in zip(slots, bits, strict=True)}
                if evaluate(left, inp).outputs != evaluate(right, inp).outputs:
                    ce = tuple((slot.value, inp[slot]) for slot in slots)
                    return EquivalenceResult(
                        EquivalenceStatus.DISPROVED, "exhaustive", None, None, ce,
                        "truth tables differ",
                    )
        proof_commitment = lb.truth_table_commitment
        witness = EquivalenceWitness(
            left.representation_id(), right.representation_id(), lb.behavior_id,
            "exhaustive-boolean-truth-table", tuple(slot.value for slot in slots),
            lb.vector_count, proof_commitment,
        )
        return EquivalenceResult(EquivalenceStatus.PROVED, "exhaustive", lb.behavior_id, witness)

    try:
        la = _anf(left, anf_monomial_budget)
        ra = _anf(right, anf_monomial_budget)
        if la != ra:
            return EquivalenceResult(
                EquivalenceStatus.DISPROVED, "algebraic-normal-form", None, None,
                reason="exact ANF outputs differ",
            )
        anf_object = _anf_canonical(la, slots)
        behavior_id = content_id("XAVI-VOID/BOOLEAN-ANF-BEHAVIOR/v1", canonical_bytes(anf_object))
        proof_commitment = content_id("XAVI-VOID/BOOLEAN-ANF-PROOF/v1", canonical_bytes(anf_object))
        witness = EquivalenceWitness(
            left.representation_id(), right.representation_id(), behavior_id,
            "exact-algebraic-normal-form", tuple(slot.value for slot in slots), 0,
            proof_commitment,
        )
        return EquivalenceResult(EquivalenceStatus.PROVED, "algebraic-normal-form", behavior_id, witness)
    except OverflowError:
        pass

    satisfiable, model, proof_commitment = _sat_difference(left, right, sat_decision_budget)
    if satisfiable is None:
        return EquivalenceResult(
            EquivalenceStatus.UNKNOWN,
            "bounded-sat",
            None,
            None,
            reason="SAT decision budget exhausted",
        )
    if satisfiable:
        assert model is not None
        ce = tuple((slot.value, bool(model.get(slot.value, False))) for slot in slots)
        return EquivalenceResult(
            EquivalenceStatus.DISPROVED, "bounded-sat", None, None, ce,
            "SAT found an input assignment with different outputs",
        )

    # UNSAT proves equivalence. Anchor the behavior class to the canonical source semantic object.
    behavior_id = content_id(
        "XAVI-VOID/SAT-PROVED-BEHAVIOR/v1",
        semantic_from_execution(left).semantic_id().encode("ascii"),
        proof_commitment.encode("ascii"),
    )
    witness = EquivalenceWitness(
        left.representation_id(), right.representation_id(), behavior_id,
        "tseitin-cnf-unsat", tuple(slot.value for slot in slots), 0, proof_commitment,
    )
    return EquivalenceResult(EquivalenceStatus.PROVED, "bounded-sat", behavior_id, witness)


def prove_equivalent(
    left: ExecutionIR,
    right: ExecutionIR,
    *,
    max_inputs: int = DEFAULT_MAX_EXACT_INPUTS,
    anf_monomial_budget: int = DEFAULT_ANF_MONOMIAL_BUDGET,
    sat_decision_budget: int = DEFAULT_SAT_DECISION_BUDGET,
) -> EquivalenceWitness:
    result = verify_equivalence(
        left,
        right,
        exhaustive_max_inputs=max_inputs,
        anf_monomial_budget=anf_monomial_budget,
        sat_decision_budget=sat_decision_budget,
    )
    if result.status == EquivalenceStatus.UNKNOWN:
        raise ValueError(f"equivalence UNKNOWN: {result.reason}")
    if result.status == EquivalenceStatus.DISPROVED:
        raise ValueError(f"programs are not observationally equivalent: {result.reason}")
    assert result.witness is not None
    return result.witness
