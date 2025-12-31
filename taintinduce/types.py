"""Type aliases for TaintInduce.

This module contains all type aliases used throughout the codebase
to make complex type signatures more readable.
"""

from typing import TYPE_CHECKING, TypeAlias

from taintinduce.isa.register import Register

# Forward declarations for circular type hints
if TYPE_CHECKING:
    from taintinduce.rules import TaintCondition
    from taintinduce.state import State

# CPU state representation as register-value mapping
CpuRegisterMap: TypeAlias = dict[Register, int]

# Taint dataflow types
BitPosition: TypeAlias = int
OutputBits: TypeAlias = set[int]
Dataflow: TypeAlias = dict[BitPosition, OutputBits]  # Maps input bit position → output bit positions
BehaviorPattern: TypeAlias = tuple[int, ...]  # Tuple of output bit positions (sorted)
MutatedInputStates: TypeAlias = dict[BitPosition, 'State']  # Maps flipped bit → mutated input state
ObservationDependency: TypeAlias = tuple[Dataflow, MutatedInputStates, 'State']  # (dependencies, mutated_states, seed)
ConditionKey: TypeAlias = tuple['TaintCondition', ...]  # Tuple of conditions
DataflowSet: TypeAlias = set[tuple[BitPosition, tuple[BehaviorPattern, ...]]]  # Set of (bit_pos, behaviors)
