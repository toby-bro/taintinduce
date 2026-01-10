from enum import Enum
from typing import Any, Optional

from taintinduce.serialization import SerializableMixin
from taintinduce.state.state import State, check_ones
from taintinduce.types import BitPosition


class LogicType(Enum):
    DNF = 0
    LOGIC = 1
    CMP = 2


class TaintCondition(SerializableMixin):
    """Condition that represents a partition bisection for conditional dataflow.

    Attributes:
        OPS_FN_MAP (dict{String: String}): A mapping that maps the operation string to its function name.

    The condition is represented as a tuple containing the operator in string and
    a list of the arguments to be performed based on the operator. (String, [])
    For example, a DNF can be represented as [('DNF', [(1024, 0),(64,1),...]), ...]
    """

    condition_type: LogicType
    condition_ops: Optional[frozenset[tuple[int, int]]]

    def __repr__(self) -> str:
        if self.condition_ops is None:
            return 'TaintCondition()'
        return f'TaintCondition({self.condition_type}, {self.condition_ops})'

    def __str__(self) -> str:
        return self.__repr__()

    def __init__(
        self,
        condition_type: LogicType,
        conditions: Optional[frozenset[tuple[int, int]]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.condition_type = condition_type
            self.condition_ops = conditions

    def __hash__(self) -> int:
        return hash((self.condition_type, self.condition_ops))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintCondition):
            return False
        return self.condition_type == other.condition_type and self.condition_ops == other.condition_ops

    def eval(self, state: State) -> bool:
        """The eval() method takes in a State object and checks if the condition evaluates to True or False.

        Args:
            state (State): The State object to which the condition is being evaluated on.
        Returns:
            True if the condition evaluates is satisfied else False.
        Raises:
            None
        """
        result = True
        if self.condition_ops is None:
            return result

        match self.condition_type:
            case LogicType.DNF:
                return self._dnf_eval(state, self.condition_ops)
            case LogicType.CMP:
                return self._cmp_eval(state, self.condition_ops)
            case LogicType.LOGIC:
                return self._logic_eval(state, self.condition_ops)
            case _:
                raise ValueError(f'Condition type {self.condition_type} is not defined')

    def get_cond_bits(self) -> frozenset[BitPosition]:
        if self.condition_ops is None:
            return frozenset()
        cond_bits: set[BitPosition] = set()
        if self.condition_type == LogicType.DNF:
            for mask, _ in self.condition_ops:
                cond_bits |= check_ones(mask)
        return frozenset(cond_bits)

    def _dnf_eval(self, state: State, dnf_args: frozenset[tuple[int, int]]) -> bool:
        if state.state_value is None:
            raise Exception('State value not initialized!')
        return any((state.state_value & bitmask == value) for bitmask, value in dnf_args)

    def _logic_eval(self, state: State, logic_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')

    def _cmp_eval(self, state: State, cmp_args: Any) -> bool:  # noqa: ARG002
        raise Exception('Not yet implemented')
