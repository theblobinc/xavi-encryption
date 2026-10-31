"""Canonical Boolean SemanticIR and compilation to typed ExecutionIR.

SemanticIR captures meaning, not register layout. Commutative inputs are sorted,
associative operators are flattened, and simple Boolean identities are normalized.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from xavi_void.crypto.shake import canonical_bytes, content_id
from xavi_void.math.types import InstructionId, Ordinal, PositiveExtent, RegisterId

from .ir import ExecutionIR, Instruction, Op


class SemanticOp(str, Enum):
    INPUT = "INPUT"
    CONST_FALSE = "CONST_FALSE"
    CONST_TRUE = "CONST_TRUE"
    XOR = "XOR"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


@dataclass(frozen=True, slots=True)
class SemanticExpr:
    op: SemanticOp
    args: tuple["SemanticExpr", ...] = ()
    input_slot: Ordinal | None = None

    @staticmethod
    def input(slot: Ordinal) -> "SemanticExpr":
        if not isinstance(slot, Ordinal):
            raise TypeError("semantic input slot must be Ordinal")
        return SemanticExpr(SemanticOp.INPUT, input_slot=slot)

    @staticmethod
    def false() -> "SemanticExpr":
        return SemanticExpr(SemanticOp.CONST_FALSE)

    @staticmethod
    def true() -> "SemanticExpr":
        return SemanticExpr(SemanticOp.CONST_TRUE)

    def canonical(self) -> dict:
        if self.op == SemanticOp.INPUT:
            assert self.input_slot is not None
            return {"op": self.op.value, "input_slot": self.input_slot.value}
        return {"op": self.op.value, "args": [arg.canonical() for arg in self.args]}

    def key(self) -> bytes:
        return canonical_bytes(self.canonical())


def _xor_many(args: tuple[SemanticExpr, ...]) -> SemanticExpr:
    flat: list[SemanticExpr] = []
    invert = False
    for arg in args:
        arg = normalize(arg)
        if arg.op == SemanticOp.CONST_FALSE:
            continue
        if arg.op == SemanticOp.CONST_TRUE:
            invert = not invert
            continue
        if arg.op == SemanticOp.XOR:
            flat.extend(arg.args)
        else:
            flat.append(arg)
    parity: dict[bytes, SemanticExpr] = {}
    for arg in flat:
        key = arg.key()
        if key in parity:
            del parity[key]
        else:
            parity[key] = arg
    remaining = [parity[key] for key in sorted(parity)]
    if not remaining:
        result = SemanticExpr.true() if invert else SemanticExpr.false()
    elif len(remaining) == 1:
        result = remaining[0]
    else:
        result = SemanticExpr(SemanticOp.XOR, tuple(remaining))
    return normalize(SemanticExpr(SemanticOp.NOT, (result,))) if invert else result


def _commutative_many(op: SemanticOp, args: tuple[SemanticExpr, ...]) -> SemanticExpr:
    flat: list[SemanticExpr] = []
    for arg in args:
        arg = normalize(arg)
        if arg.op == op:
            flat.extend(arg.args)
        else:
            flat.append(arg)
    if op == SemanticOp.AND:
        if any(arg.op == SemanticOp.CONST_FALSE for arg in flat):
            return SemanticExpr.false()
        flat = [arg for arg in flat if arg.op != SemanticOp.CONST_TRUE]
    elif op == SemanticOp.OR:
        if any(arg.op == SemanticOp.CONST_TRUE for arg in flat):
            return SemanticExpr.true()
        flat = [arg for arg in flat if arg.op != SemanticOp.CONST_FALSE]
    unique = {arg.key(): arg for arg in flat}
    ordered = [unique[key] for key in sorted(unique)]
    if not ordered:
        return SemanticExpr.true() if op == SemanticOp.AND else SemanticExpr.false()
    if len(ordered) == 1:
        return ordered[0]
    return SemanticExpr(op, tuple(ordered))


def normalize(expr: SemanticExpr) -> SemanticExpr:
    op = expr.op
    if op == SemanticOp.INPUT:
        if expr.input_slot is None or expr.args:
            raise ValueError("INPUT requires exactly an input slot")
        return expr
    if op in {SemanticOp.CONST_FALSE, SemanticOp.CONST_TRUE}:
        if expr.args or expr.input_slot is not None:
            raise ValueError("constant semantic expressions have no arguments")
        return expr
    if expr.input_slot is not None:
        raise ValueError("only INPUT may carry input_slot")
    if op == SemanticOp.NOT:
        if len(expr.args) != 1:
            raise ValueError("NOT requires one argument")
        child = normalize(expr.args[0])
        if child.op == SemanticOp.CONST_FALSE:
            return SemanticExpr.true()
        if child.op == SemanticOp.CONST_TRUE:
            return SemanticExpr.false()
        if child.op == SemanticOp.NOT:
            return normalize(child.args[0])
        return SemanticExpr(SemanticOp.NOT, (child,))
    if op == SemanticOp.XOR:
        return _xor_many(expr.args)
    if op in {SemanticOp.AND, SemanticOp.OR}:
        return _commutative_many(op, expr.args)
    raise ValueError("unknown semantic operator")


@dataclass(frozen=True, slots=True)
class SemanticIR:
    input_count: PositiveExtent | None
    outputs: tuple[SemanticExpr, ...]

    def __post_init__(self) -> None:
        if self.input_count is not None and not isinstance(self.input_count, PositiveExtent):
            raise TypeError("input_count must be PositiveExtent or None for an empty input domain")
        if not self.outputs:
            raise ValueError("SemanticIR requires at least one output")
        for output in self.outputs:
            self._validate_expr(normalize(output))

    def _validate_expr(self, expr: SemanticExpr) -> None:
        if expr.op == SemanticOp.INPUT:
            assert expr.input_slot is not None
            if self.input_count is None or expr.input_slot.value > self.input_count.value:
                raise ValueError("semantic input outside declared input domain")
        for arg in expr.args:
            self._validate_expr(arg)

    def canonical_outputs(self) -> tuple[SemanticExpr, ...]:
        return tuple(normalize(output) for output in self.outputs)

    def canonical(self) -> dict:
        return {
            "input_count": None if self.input_count is None else self.input_count.value,
            "outputs": [output.canonical() for output in self.canonical_outputs()],
        }

    def semantic_id(self) -> str:
        return content_id("XAVI-VOID/BOOLEAN-SEMANTIC-IR/v1", canonical_bytes(self.canonical()))


def semantic_from_execution(program: ExecutionIR) -> SemanticIR:
    program.validate()
    expressions: dict[int, SemanticExpr] = {}
    for instruction in program.instructions:
        if instruction.op == Op.INPUT:
            assert instruction.input_slot is not None
            expr = SemanticExpr.input(instruction.input_slot)
        elif instruction.op == Op.CONST_FALSE:
            expr = SemanticExpr.false()
        elif instruction.op == Op.CONST_TRUE:
            expr = SemanticExpr.true()
        elif instruction.op == Op.COPY:
            expr = expressions[instruction.sources[0].value]
        elif instruction.op == Op.NOT:
            expr = SemanticExpr(SemanticOp.NOT, (expressions[instruction.sources[0].value],))
        elif instruction.op in {Op.XOR, Op.AND, Op.OR}:
            sem_op = {
                Op.XOR: SemanticOp.XOR,
                Op.AND: SemanticOp.AND,
                Op.OR: SemanticOp.OR,
            }[instruction.op]
            expr = SemanticExpr(
                sem_op,
                tuple(expressions[source.value] for source in instruction.sources),
            )
        else:  # pragma: no cover
            raise AssertionError("unsupported ExecutionIR opcode")
        expressions[instruction.destination.value] = normalize(expr)
    slots = program.input_slots()
    return SemanticIR(
        input_count=None if not slots else PositiveExtent(len(slots)),
        outputs=tuple(expressions[output.value] for output in program.outputs),
    )


def compile_semantic(semantic: SemanticIR) -> ExecutionIR:
    """Compile canonical SemanticIR to deterministic SSA ExecutionIR with CSE."""
    instructions: list[Instruction] = []
    cache: dict[bytes, RegisterId] = {}

    def emit(op: Op, *, sources: tuple[RegisterId, ...] = (), input_slot: Ordinal | None = None) -> RegisterId:
        destination = RegisterId(len(instructions) + 1)
        instructions.append(
            Instruction(
                InstructionId(len(instructions) + 1),
                destination,
                op,
                sources=sources,
                input_slot=input_slot,
            )
        )
        return destination

    # Materialize inputs first so the public interface is stable.
    input_count = 0 if semantic.input_count is None else semantic.input_count.value
    for value in range(1, input_count + 1):
        slot = Ordinal(value)
        expr = SemanticExpr.input(slot)
        cache[expr.key()] = emit(Op.INPUT, input_slot=slot)

    def compile_expr(raw: SemanticExpr) -> RegisterId:
        expr = normalize(raw)
        key = expr.key()
        if key in cache:
            return cache[key]
        if expr.op == SemanticOp.CONST_FALSE:
            reg = emit(Op.CONST_FALSE)
        elif expr.op == SemanticOp.CONST_TRUE:
            reg = emit(Op.CONST_TRUE)
        elif expr.op == SemanticOp.NOT:
            reg = emit(Op.NOT, sources=(compile_expr(expr.args[0]),))
        elif expr.op in {SemanticOp.XOR, SemanticOp.AND, SemanticOp.OR}:
            op = {SemanticOp.XOR: Op.XOR, SemanticOp.AND: Op.AND, SemanticOp.OR: Op.OR}[expr.op]
            args = list(expr.args)
            left = compile_expr(args[0])
            for arg in args[1:]:
                right = compile_expr(arg)
                left = emit(op, sources=(left, right))
            reg = left
        elif expr.op == SemanticOp.INPUT:
            assert expr.input_slot is not None
            reg = cache[expr.key()]
        else:  # pragma: no cover
            raise AssertionError("unknown semantic op")
        cache[key] = reg
        return reg

    outputs = tuple(compile_expr(expr) for expr in semantic.canonical_outputs())
    program = ExecutionIR(
        register_count=PositiveExtent(len(instructions)),
        instructions=tuple(instructions),
        outputs=outputs,
    )
    program.validate()
    return program
