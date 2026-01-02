"""State representation for instruction inputs/outputs."""

from typing import Optional

from taintinduce.isa.register import Register
from taintinduce.serialization import SerializableMixin
from taintinduce.types import BitPosition, StateValue


def check_ones(value: int) -> set[BitPosition]:
    """Obtains the position of bits that are set."""
    result_set: set[BitPosition] = set()
    pos = BitPosition(0)
    while value:
        if value & 1:
            result_set.add(pos)
        value >>= 1
        pos.inc()
    return result_set


class State(SerializableMixin):
    """Representation of the input/output of an instruction as a bitvector.

    Attributes:
        num_bits (int): Size of state in number of bits.
        state_value (StateValue): Bitvector to represent the state stored as an integer.
    """

    state_value: StateValue
    num_bits: int

    def __init__(
        self,
        num_bits: Optional[int] = None,
        state_value: Optional[StateValue] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        """Initializes the State object to length num_bits.

        Args:
            num_bits (int): Size of State in bits.
            state_value (int): Integer value representing the bit array.
        Returns:
            None
        Raises:
            None
        """
        if repr_str:
            self.deserialize(repr_str)
        elif num_bits is not None and state_value is not None:
            self.num_bits = num_bits
            self.state_value = state_value
        else:
            raise Exception('Invalid arguments to State constructor!')

    def __str__(self) -> str:
        """Produces the corresponding bit string for the given state.

        Args:
            None
        Returns:
            A bitstring representing the state. For example, for the argument (8, 2),
            the corresponding string returned is "00000010"
        """
        return '{{:<0{}b}}'.format(self.num_bits).format(self.state_value)

    def diff(self, other_state: 'State') -> set[BitPosition]:
        """Obtains the difference between two States.

        Args:
            other_state (State): The other state which we will be comparing against.

        Returns:
            A set of integers which identifies which position are different between the two States.
        """
        if self.state_value is None or other_state.state_value is None:
            raise Exception('State values not initialized!')

        value_changed = self.state_value ^ other_state.state_value
        return check_ones(value_changed)


class Observation(SerializableMixin):
    """Collection of states that represents a single observation.

    Made up of an initial input seed state, followed by a set of mutated states
    obtained by performing a single bit-flip. For each state, an 'output' state
    is included forming a tuple (input_state, output_state) called IOPair.

    Attributes:
        seed_io (IOPair): A tuple representing the seed state. (input_state, output_state).
        mutated_ios (list of IOPair): A list containing all IOPairs of mutated states.
    """

    seed_io: tuple[State, State]
    mutated_ios: list[tuple[State, State]]
    bytestring: str
    archstring: str
    state_format: list[Register]

    def __init__(
        self,
        iopair: Optional[tuple[State, State]] = None,
        mutated_iopairs: Optional[list[tuple[State, State]]] = None,
        bytestring: Optional[str] = None,
        archstring: Optional[str] = None,
        state_format: Optional[list[Register]] = None,
        repr_str: Optional[str] = None,
    ) -> None:
        """Initializes the Observation object.

        Args:
            iopair ((State, State)): seed_state of the form (input_state, output_state)
            mutated_iopairs (list of (State, State)): list of tuple of mutated States
        Returns:
            None
        Raises:
            None
        """
        if repr_str:
            self.deserialize(repr_str)
            if (
                self.seed_io is None
                or self.mutated_ios is None
                or self.bytestring is None
                or self.archstring is None
                or self.state_format is None
            ):
                raise Exception('Invalid serialized Observation!')
        else:
            if (
                iopair is None
                or mutated_iopairs is None
                or bytestring is None
                or archstring is None
                or state_format is None
            ):
                raise Exception('Invalid arguments to Observation constructor!')
            self.seed_io = iopair
            self.mutated_ios = mutated_iopairs
            self.bytestring = bytestring
            self.archstring = archstring
            self.state_format = state_format
