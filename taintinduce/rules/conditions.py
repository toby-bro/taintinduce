from enum import Enum
from typing import Any, Optional

from taintinduce.serialization import SerializableMixin
from taintinduce.state.state import State, check_ones
from taintinduce.types import BitPosition


class LogicType(Enum):
    DNF = 0
    LOGIC = 1
    CMP = 2


class OutputBitRef(SerializableMixin):
    """Reference to an output bit position in a condition.

    When a condition references an output bit, it means the condition
    depends on the computed value of that output bit from another dataflow.
    """

    output_bit: BitPosition

    def __init__(self, output_bit: BitPosition) -> None:
        self.output_bit = output_bit

    def __repr__(self) -> str:
        return f'OutputBitRef({self.output_bit})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OutputBitRef):
            return False
        return self.output_bit == other.output_bit

    def __hash__(self) -> int:
        return hash(self.output_bit)


class TaintCondition(SerializableMixin):
    """Condition that represents a partition bisection for conditional dataflow.

    Attributes:
        OPS_FN_MAP (dict{String: String}): A mapping that maps the operation string to its function name.

    The condition is represented as a tuple containing the operator in string and
    a list of the arguments to be performed based on the operator. (String, [])
    For example, a DNF can be represented as [('DNF', [(1024, 0),(64,1),...]), ...]

    Now supports output bit references:
    - Input bit conditions: (mask, value) tuples where bits are input state bits
    - Output bit refs: OutputBitRef objects that reference output bits from other flows
    """

    condition_type: LogicType
    condition_ops: frozenset[tuple[int, int]]
    output_bit_refs: frozenset[OutputBitRef]

    def __repr__(self) -> str:
        return f"""TaintCondition({self.condition_type}, {
            {bin(mask): bin(value)  for mask, value in self.condition_ops} if self.condition_ops else None
        }, {self.output_bit_refs})"""

    def __str__(self) -> str:
        return self.__repr__()

    def __init__(
        self,
        condition_type: LogicType,
        conditions: Optional[frozenset[tuple[int, int]]] = None,
        output_bit_refs: Optional[frozenset[OutputBitRef]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.condition_type = condition_type
            self.condition_ops = conditions if conditions is not None else frozenset()
            self.output_bit_refs = output_bit_refs if output_bit_refs is not None else frozenset()

    def __hash__(self) -> int:
        return hash((self.condition_type, self.condition_ops, self.output_bit_refs))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintCondition):
            return False
        return (
            self.condition_type == other.condition_type
            and self.condition_ops == other.condition_ops
            and self.output_bit_refs == other.output_bit_refs
        )

    def eval(self, state: State, output_state: Optional[State] = None) -> bool:
        """The eval() method takes in a State object and checks if the condition evaluates to True or False.

        Args:
            state (State): The State object to which the condition is being evaluated on (input state).
            output_state (Optional[State]): Output state for evaluating output bit references.
        Returns:
            True if the condition evaluates is satisfied else False.
        Raises:
            None
        """
        result = True
        if len(self.condition_ops) == 0 and (not hasattr(self, 'output_bit_refs') or len(self.output_bit_refs) == 0):
            return result

        match self.condition_type:
            case LogicType.DNF:
                return self._dnf_eval(state, output_state)
            case LogicType.CMP:
                return self._cmp_eval(state, self.condition_ops)
            case LogicType.LOGIC:
                return self._logic_eval(state, self.condition_ops)
            case _:
                raise ValueError(f'Condition type {self.condition_type} is not defined')

    def get_cond_bits(self) -> frozenset[BitPosition]:
        cond_bits: set[BitPosition] = set()
        if self.condition_type == LogicType.DNF:
            for mask, _ in self.condition_ops:
                cond_bits |= check_ones(mask)
        return frozenset(cond_bits)

    def _dnf_eval(self, state: State, output_state: Optional[State] = None) -> bool:
        """Evaluate DNF condition with support for output bit references.

        Args:
            state: Input state
            output_state: Output state for evaluating output bit refs

        Returns:
            True if condition is satisfied
        """
        if state.state_value is None:
            raise Exception('State value not initialized!')

        # First evaluate input bit conditions
        input_satisfied = True
        if self.condition_ops:
            # I have a doubt that it should rather be all ?
            input_satisfied = any((state.state_value & bitmask == value) for bitmask, value in self.condition_ops)

        # Then evaluate output bit references
        output_satisfied = True
        if hasattr(self, 'output_bit_refs') and self.output_bit_refs:
            if output_state is None or output_state.state_value is None:
                # Cannot evaluate output bit refs without output state
                # For backward compatibility, treat as satisfied if no output state provided
                pass
            else:
                # Check if all referenced output bits are set in the output state
                for output_ref in self.output_bit_refs:
                    bit_pos = output_ref.output_bit
                    if not (output_state.state_value & (1 << bit_pos)):
                        output_satisfied = False
                        break

        return input_satisfied and output_satisfied

    def _logic_eval(self, state: State, logic_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')

    def _cmp_eval(self, state: State, cmp_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')
