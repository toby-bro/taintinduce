from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from taintinduce.isa.register import Register
from taintinduce.serialization import SerializableMixin
from taintinduce.types import Architecture


class Op(str, Enum):
    # Binary operations
    AND = 'AND'
    OR = 'OR'
    XOR = 'XOR'
    # Unary operations
    NOT = 'NOT'


@dataclass
class Expr(SerializableMixin):
    """Base class for AST expressions."""

    def evaluate(self, input_taint: dict[str, int], input_values: dict[str, int]) -> int:
        raise NotImplementedError


@dataclass
class TaintOperand(Expr):
    """Represents a taint value operand (e.g. the taint status of EAX) or a concrete value operand."""

    name: str
    bit_start: int
    bit_end: int
    is_taint: bool = True  # True if T_x, False if V_x

    def __str__(self) -> str:
        prefix = 'T' if self.is_taint else 'V'
        if self.bit_start == self.bit_end:
            return f'{prefix}_{self.name}[{self.bit_start}]'
        return f'{prefix}_{self.name}[{self.bit_end}:{self.bit_start}]'

    def evaluate(self, input_taint: dict[str, int], input_values: dict[str, int]) -> int:
        state = input_taint if self.is_taint else input_values
        val = state.get(self.name, 0)
        # Extract the bit slice
        mask = (1 << (self.bit_end - self.bit_start + 1)) - 1
        return (val >> self.bit_start) & mask


@dataclass
class Constant(Expr):
    """A constant boolean or integer value."""

    value: int
    size: int  # size in bits

    def __str__(self) -> str:
        return hex(self.value)

    def evaluate(self, input_taint: dict[str, int], input_values: dict[str, int]) -> int:  # noqa: ARG002
        return self.value


@dataclass
class UnaryExpr(Expr):
    """A unary operator application."""

    op: Op
    expr: Expr

    def __str__(self) -> str:
        return f'{self.op.value}({self.expr})'

    def evaluate(self, input_taint: dict[str, int], input_values: dict[str, int]) -> int:
        val = self.expr.evaluate(input_taint, input_values)
        if self.op == Op.NOT:
            return ~val
        raise NotImplementedError(f'Unsupported unary op {self.op}')


@dataclass
class BinaryExpr(Expr):
    """A binary operator application."""

    op: Op
    lhs: Expr
    rhs: Expr

    def __str__(self) -> str:
        return f'({self.lhs} {self.op.value} {self.rhs})'

    def evaluate(self, input_taint: dict[str, int], input_values: dict[str, int]) -> int:
        left = self.lhs.evaluate(input_taint, input_values)
        right = self.rhs.evaluate(input_taint, input_values)
        if self.op == Op.AND:
            return left & right
        if self.op == Op.OR:
            return left | right
        if self.op == Op.XOR:
            return left ^ right
        raise NotImplementedError(f'Unsupported binary op {self.op}')


@dataclass
class TaintAssignment(SerializableMixin):
    """Represents assigning a logic block of taint variables to a target"""

    target: TaintOperand
    dependencies: list[TaintOperand]
    expression: Optional[Expr] = None
    expression_str: str = ''

    def __str__(self) -> str:
        if self.expression:
            expr = str(self.expression)
        elif self.expression_str:
            expr = self.expression_str
        else:
            expr = ' | '.join(str(d) for d in self.dependencies)
        return f'{self.target} = {expr}'


@dataclass
class LogicCircuit(SerializableMixin):
    """Represents the final circuit computing the taint output for an instruction."""

    assignments: list[TaintAssignment]
    architecture: Architecture
    instruction: str
    state_format: list[Register]

    def __str__(self) -> str:
        return '\n'.join(str(a) for a in self.assignments)

    def evaluate(self, input_taint: dict[str, int], input_values: Optional[dict[str, int]] = None) -> dict[str, int]:
        if input_values is None:
            input_values = {}
        output_taint = {}
        for assignment in self.assignments:
            if assignment.expression is not None:
                val = assignment.expression.evaluate(input_taint, input_values)
            elif assignment.expression_str:
                raise NotImplementedError('Arbitrary string expressions not supported for evaluation right now.')
            else:
                # For purely mapped operations, it's just an OR of dependencies
                val = 0
                for dep in assignment.dependencies:
                    val |= dep.evaluate(input_taint, input_values)

            output_taint[assignment.target.name] = val
        return output_taint
