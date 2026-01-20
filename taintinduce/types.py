"""Type aliases for TaintInduce.

This module contains all type aliases used throughout the codebase
to make complex type signatures more readable.
"""

from typing import TYPE_CHECKING, NamedTuple, NewType

from taintinduce.isa.register import Register

# Forward declarations for circular type hints
if TYPE_CHECKING:
    from taintinduce.state.state import State


# CPU state representation as register-value mapping
class CpuRegisterMap(dict[Register, int]):
    """Maps CPU registers to their integer values."""


# Unitary flow: single input bit -> single output bit
class UnitaryFlow(NamedTuple):
    """Represents a single input bit affecting a single output bit."""

    input_bit: 'BitPosition'
    output_bit: 'BitPosition'


# Taint dataflow types

BitPosition = NewType('BitPosition', int)


class Dataflow(
    dict[
        BitPosition,
        frozenset[BitPosition],
    ],
):
    """Maps input bit position -> output bit positions"""

    def inputs(self) -> set[BitPosition]:
        """Get all input bit positions in the dataflow."""
        return set(self.keys())

    def get_modified_outputs(self, input_bit: BitPosition) -> frozenset[BitPosition]:
        """Get all output bits tainted by the given input bit."""
        return self.get(input_bit, frozenset())

    def __getitem__(
        self,
        key: BitPosition,
    ) -> frozenset[BitPosition]:  # I just added it but I think I should delete it...
        if key not in self:
            self[key] = frozenset()
        return super().__getitem__(key)


BehaviorPattern = NewType('BehaviorPattern', set[BitPosition])


class MutatedInputStates(
    dict[
        BitPosition,
        'State',
    ],
):
    """Maps input bit position -> mutated input State."""

    def mutated_bits(self) -> set[BitPosition]:
        """Get all mutated input bit positions."""
        return set(self.keys())

    def get_input_state(self, bitpos: BitPosition) -> 'State':
        """Get the mutated input State for a given bit position."""
        return self[bitpos]


class ObservationDependency:
    """Holds dataflow and mutated inputs for a single observation."""

    dataflow: Dataflow
    mutated_inputs: MutatedInputStates
    original_output: 'State'

    def __init__(
        self,
        dataflow: Dataflow,
        mutated_inputs: MutatedInputStates,
        original_output: 'State',
    ) -> None:
        self.dataflow = dataflow
        self.mutated_inputs = mutated_inputs
        self.original_output = original_output


class DataflowSet(dict[BitPosition, set[frozenset[BitPosition]]]):
    """Set of (bit_pos, behaviors)."""


StateValue = NewType('StateValue', int)
