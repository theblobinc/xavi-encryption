"""Proof-carrying ExecutionIR rewrite engine.

Every accepted rewrite is re-verified through the layered equivalence engine.
A syntactic transform is never returned as trusted merely because its rule name
claims an identity.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.boundary import to_host_offset
from xavi_void.math.types import InstructionId, PositiveExtent, RegisterId

from .behavior import EquivalenceStatus, EquivalenceWitness, verify_equivalence
from .ir import ExecutionIR, Instruction, Op
from .polymorph import derive_register_permutation, permute_registers
from .semantic import semantic_from_execution


class RewriteRule(str, Enum):
    XOR_COMMUTATIVITY = "xor-commutativity"
    XOR_ASSOCIATIVITY = "xor-associativity"
    XOR_CANCELLATION = "xor-cancellation"
    DOUBLE_NEGATION = "double-negation"
    DE_MORGAN = "de-morgan"
    AND_DISTRIBUTION = "and-distribution-over-xor"
    CONSTANT_PROPAGATION = "constant-propagation"
    INSTRUCTION_SPLIT = "instruction-splitting"
    INSTRUCTION_FUSION = "instruction-fusion"
    DEAD_REGISTER_INTRODUCTION = "dead-register-introduction"
    DEAD_REGISTER_REMOVAL = "dead-register-removal"
    TEMPORARY_LAYOUT = "equivalent-temporary-layout"


@dataclass(frozen=True, slots=True)
class RewriteWitness:
    rule: str
    site: int
    source_representation_id: str
    target_representation_id: str
    source_semantic_id: str
    target_semantic_id: str
    shared_behavior_commitment: str
    equivalence_witness_id: str

    def witness_id(self) -> str:
        return content_id(
            "XAVI-VOID/REWRITE-WITNESS/v1",
            canonical_bytes(
                {
                    "rule": self.rule,
                    "site": self.site,
                    "source_representation_id": self.source_representation_id,
                    "target_representation_id": self.target_representation_id,
                    "source_semantic_id": self.source_semantic_id,
                    "target_semantic_id": self.target_semantic_id,
                    "shared_behavior_commitment": self.shared_behavior_commitment,
                    "equivalence_witness_id": self.equivalence_witness_id,
                }
            ),
        )


def _renumber(instructions: list[Instruction]) -> tuple[Instruction, ...]:
    return tuple(
        replace(instruction, instruction_id=InstructionId(i))
        for i, instruction in enumerate(instructions, start=1)
    )


def _producer_map(program: ExecutionIR) -> dict[int, Instruction]:
    return {instruction.destination.value: instruction for instruction in program.instructions}


def _instruction_position(program: ExecutionIR) -> dict[int, int]:
    return {instruction.destination.value: i for i, instruction in enumerate(program.instructions, start=1)}


def _replace_at(program: ExecutionIR, site: InstructionId, replacements: list[Instruction], *, register_count: int | None = None) -> ExecutionIR:
    if site.value > len(program.instructions):
        raise ValueError("rewrite site is outside instruction domain")
    items = list(program.instructions)
    items[to_host_offset(site):to_host_offset(site) + 1] = replacements
    target = ExecutionIR(
        PositiveExtent(register_count or program.register_count.value),
        _renumber(items),
        program.outputs,
    )
    target.validate()
    return target


def _constant_values(program: ExecutionIR) -> dict[int, bool | None]:
    values: dict[int, bool | None] = {}
    for ins in program.instructions:
        if ins.op == Op.CONST_FALSE:
            value: bool | None = False
        elif ins.op == Op.CONST_TRUE:
            value = True
        elif ins.op == Op.COPY:
            value = values.get(ins.sources[0].value)
        elif ins.op == Op.NOT:
            child = values.get(ins.sources[0].value)
            value = None if child is None else not child
        elif ins.op in {Op.XOR, Op.AND, Op.OR}:
            a, b = (values.get(source.value) for source in ins.sources)
            if a is not None and b is not None:
                value = a ^ b if ins.op == Op.XOR else (a and b if ins.op == Op.AND else a or b)
            else:
                value = None
        else:
            value = None
        values[ins.destination.value] = value
    return values


def _apply_rule(
    program: ExecutionIR,
    rule: RewriteRule,
    site: InstructionId | None,
    *,
    seed: bytes | None,
) -> tuple[ExecutionIR, int]:
    program.validate()
    if rule == RewriteRule.DEAD_REGISTER_INTRODUCTION:
        new_reg = RegisterId(program.register_count.value + 1)
        items = list(program.instructions)
        items.append(Instruction(InstructionId(len(items) + 1), new_reg, Op.CONST_FALSE))
        target = ExecutionIR(PositiveExtent(new_reg.value), tuple(items), program.outputs)
        target.validate()
        return target, len(items)
    if rule == RewriteRule.TEMPORARY_LAYOUT:
        if not seed:
            raise ValueError("temporary-layout rewrite requires a nonempty seed")
        permutation = derive_register_permutation(program, seed)
        target = permute_registers(program, permutation)
        return target, 1 if site is None else site.value
    if site is None:
        raise ValueError(f"rewrite rule {rule.value} requires an InstructionId site")
    if not isinstance(site, InstructionId):
        raise TypeError("rewrite site must be InstructionId")
    if site.value > len(program.instructions):
        raise ValueError("rewrite site outside instruction domain")

    ins = program.instructions[to_host_offset(site)]
    producers = _producer_map(program)
    positions = _instruction_position(program)

    if rule == RewriteRule.XOR_COMMUTATIVITY:
        if ins.op != Op.XOR:
            raise ValueError("xor-commutativity requires XOR site")
        return _replace_at(program, site, [replace(ins, sources=(ins.sources[1], ins.sources[0]))]), site.value

    if rule == RewriteRule.XOR_CANCELLATION:
        if ins.op != Op.XOR or ins.sources[0] != ins.sources[1]:
            raise ValueError("xor-cancellation requires XOR(x,x)")
        return _replace_at(program, site, [replace(ins, op=Op.CONST_FALSE, sources=())]), site.value

    if rule == RewriteRule.DOUBLE_NEGATION:
        if ins.op != Op.NOT:
            raise ValueError("double-negation requires outer NOT")
        inner = producers.get(ins.sources[0].value)
        if inner is None or inner.op != Op.NOT:
            raise ValueError("double-negation pattern not found")
        return _replace_at(program, site, [replace(ins, op=Op.COPY, sources=(inner.sources[0],))]), site.value

    if rule == RewriteRule.XOR_ASSOCIATIVITY:
        if ins.op != Op.XOR:
            raise ValueError("xor-associativity requires outer XOR")
        for inner_pos in (0, 1):
            inner = producers.get(ins.sources[inner_pos].value)
            if inner is None or inner.op != Op.XOR:
                continue
            other = ins.sources[1 - inner_pos]
            # Reusing the inner destination requires the new source to exist before inner executes.
            if positions[other.value] >= inner.instruction_id.value:
                continue
            a, b = inner.sources
            new_inner = replace(inner, sources=(b, other))
            new_outer = replace(ins, sources=(a, inner.destination))
            items = list(program.instructions)
            items[to_host_offset(inner.instruction_id)] = new_inner
            items[to_host_offset(site)] = new_outer
            target = ExecutionIR(program.register_count, tuple(items), program.outputs)
            target.validate()
            return target, site.value
        raise ValueError("safe xor-associativity pattern not found")

    if rule == RewriteRule.DE_MORGAN:
        if ins.op != Op.NOT:
            raise ValueError("de-morgan requires NOT(AND/OR(...))")
        inner = producers.get(ins.sources[0].value)
        if inner is None or inner.op not in {Op.AND, Op.OR}:
            raise ValueError("de-morgan pattern not found")
        r1 = RegisterId(program.register_count.value + 1)
        r2 = RegisterId(program.register_count.value + 2)
        complement = Op.OR if inner.op == Op.AND else Op.AND
        replacements = [
            Instruction(InstructionId(1), r1, Op.NOT, sources=(inner.sources[0],)),
            Instruction(InstructionId(1), r2, Op.NOT, sources=(inner.sources[1],)),
            replace(ins, op=complement, sources=(r1, r2)),
        ]
        return _replace_at(program, site, replacements, register_count=r2.value), site.value

    if rule == RewriteRule.AND_DISTRIBUTION:
        if ins.op != Op.AND:
            raise ValueError("and-distribution requires outer AND")
        pair: tuple[RegisterId, Instruction] | None = None
        for pos in (0, 1):
            inner = producers.get(ins.sources[pos].value)
            if inner is not None and inner.op == Op.XOR:
                pair = (ins.sources[1 - pos], inner)
                break
        if pair is None:
            raise ValueError("AND(a, XOR(b,c)) pattern not found")
        a, inner = pair
        r1 = RegisterId(program.register_count.value + 1)
        r2 = RegisterId(program.register_count.value + 2)
        replacements = [
            Instruction(InstructionId(1), r1, Op.AND, sources=(a, inner.sources[0])),
            Instruction(InstructionId(1), r2, Op.AND, sources=(a, inner.sources[1])),
            replace(ins, op=Op.XOR, sources=(r1, r2)),
        ]
        return _replace_at(program, site, replacements, register_count=r2.value), site.value

    if rule == RewriteRule.CONSTANT_PROPAGATION:
        values = _constant_values(program)
        source_values = [values.get(source.value) for source in ins.sources]
        replacement: Instruction | None = None
        if ins.op in {Op.COPY, Op.NOT, Op.XOR, Op.AND, Op.OR} and ins.sources:
            if all(value is not None for value in source_values):
                bools = [bool(v) for v in source_values]
                if ins.op == Op.COPY:
                    result = bools[0]
                elif ins.op == Op.NOT:
                    result = not bools[0]
                elif ins.op == Op.XOR:
                    result = bools[0] ^ bools[1]
                elif ins.op == Op.AND:
                    result = bools[0] and bools[1]
                else:
                    result = bools[0] or bools[1]
                replacement = replace(ins, op=Op.CONST_TRUE if result else Op.CONST_FALSE, sources=())
            elif len(ins.sources) == 2:
                a, b = source_values
                sa, sb = ins.sources
                if ins.op == Op.XOR:
                    if a is False: replacement = replace(ins, op=Op.COPY, sources=(sb,))
                    elif b is False: replacement = replace(ins, op=Op.COPY, sources=(sa,))
                    elif a is True: replacement = replace(ins, op=Op.NOT, sources=(sb,))
                    elif b is True: replacement = replace(ins, op=Op.NOT, sources=(sa,))
                elif ins.op == Op.AND:
                    if a is False or b is False: replacement = replace(ins, op=Op.CONST_FALSE, sources=())
                    elif a is True: replacement = replace(ins, op=Op.COPY, sources=(sb,))
                    elif b is True: replacement = replace(ins, op=Op.COPY, sources=(sa,))
                elif ins.op == Op.OR:
                    if a is True or b is True: replacement = replace(ins, op=Op.CONST_TRUE, sources=())
                    elif a is False: replacement = replace(ins, op=Op.COPY, sources=(sb,))
                    elif b is False: replacement = replace(ins, op=Op.COPY, sources=(sa,))
        if replacement is None:
            raise ValueError("constant propagation has no applicable simplification at site")
        return _replace_at(program, site, [replacement]), site.value

    if rule == RewriteRule.INSTRUCTION_SPLIT:
        if not ins.sources:
            raise ValueError("instruction-splitting requires an instruction with a source")
        temp = RegisterId(program.register_count.value + 1)
        copy = Instruction(InstructionId(1), temp, Op.COPY, sources=(ins.sources[0],))
        new_sources = (temp,) + ins.sources[1:]
        return _replace_at(
            program,
            site,
            [copy, replace(ins, sources=new_sources)],
            register_count=temp.value,
        ), site.value

    if rule == RewriteRule.INSTRUCTION_FUSION:
        if ins.op != Op.COPY:
            raise ValueError("instruction-fusion site must be COPY")
        if ins.destination in program.outputs:
            raise ValueError("cannot fuse away an output register")
        uses = [
            later
            for later in program.instructions[site.value:]
            if ins.destination in later.sources
        ]
        if len(uses) != 1:
            raise ValueError("fusion requires COPY destination to have exactly one use")
        items: list[Instruction] = []
        for current in program.instructions:
            if current.instruction_id == ins.instruction_id:
                continue
            if current.instruction_id == uses[0].instruction_id:
                sources = tuple(ins.sources[0] if s == ins.destination else s for s in current.sources)
                current = replace(current, sources=sources)
            items.append(current)
        target = ExecutionIR(program.register_count, _renumber(items), program.outputs)
        target.validate()
        return target, site.value

    if rule == RewriteRule.DEAD_REGISTER_REMOVAL:
        if ins.destination in program.outputs:
            raise ValueError("cannot remove output-producing instruction")
        if any(ins.destination in later.sources for later in program.instructions[site.value:]):
            raise ValueError("register is live and cannot be removed")
        items = [i for i in program.instructions if i.instruction_id != ins.instruction_id]
        target = ExecutionIR(program.register_count, _renumber(items), program.outputs)
        target.validate()
        return target, site.value

    raise ValueError(f"unsupported rewrite rule: {rule.value}")


def apply_rewrite(
    program: ExecutionIR,
    rule: RewriteRule,
    site: InstructionId | None = None,
    *,
    seed: bytes | None = None,
    exhaustive_max_inputs: int = 12,
    anf_monomial_budget: int = 50_000,
    sat_decision_budget: int = 100_000,
) -> tuple[ExecutionIR, RewriteWitness, EquivalenceWitness]:
    """Apply one rule, prove it, and return only if equivalence is PROVED."""
    target, site_value = _apply_rule(program, rule, site, seed=seed)
    if target.representation_id() == program.representation_id():
        raise ValueError("rewrite produced no representation change")
    result = verify_equivalence(
        program,
        target,
        exhaustive_max_inputs=exhaustive_max_inputs,
        anf_monomial_budget=anf_monomial_budget,
        sat_decision_budget=sat_decision_budget,
    )
    if result.status != EquivalenceStatus.PROVED or result.witness is None or result.behavior_id is None:
        raise ValueError(f"rewrite rejected because equivalence is {result.status.value}: {result.reason}")
    source_semantic = semantic_from_execution(program).semantic_id()
    target_semantic = semantic_from_execution(target).semantic_id()
    witness = RewriteWitness(
        rule=rule.value,
        site=site_value,
        source_representation_id=program.representation_id(),
        target_representation_id=target.representation_id(),
        source_semantic_id=source_semantic,
        target_semantic_id=target_semantic,
        shared_behavior_commitment=result.behavior_id,
        equivalence_witness_id=result.witness.witness_id(),
    )
    return target, witness, result.witness
