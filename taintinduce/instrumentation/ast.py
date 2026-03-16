from dataclasses import dataclass

from taintinduce.isa.register import Register
from taintinduce.serialization import SerializableMixin
from taintinduce.types import Architecture


@dataclass
class TaintOperand(SerializableMixin):
    """Represents a taint value operand (e.g. the taint status of EAX)"""

    name: str
    bit_start: int
    bit_end: int

    def __str__(self):
        return f'T_{self.name}[{self.bit_end}:{self.bit_start}]'


@dataclass
class TaintAssignment(SerializableMixin):
    """Represents assigning a logic block of taint variables to a target"""

    target: TaintOperand
    dependencies: list[TaintOperand]
    expression_str: str = ''

    def __str__(self):
        if self.expression_str:
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

    def __str__(self):
        return '\n'.join(str(a) for a in self.assignments)

    def evaluate(self, input_taint: dict[str, int]) -> dict[str, int]:
        output_taint = {}
        for assignment in self.assignments:
            if assignment.expression_str:
                raise NotImplementedError('Arbitrary string expressions not supported for evaluation right now.')
            # For purely mapped operations, it's just an OR of dependencies
            val = 0
            for dep in assignment.dependencies:
                val |= input_taint.get(dep.name, 0)
            output_taint[assignment.target.name] = val
        return output_taint
