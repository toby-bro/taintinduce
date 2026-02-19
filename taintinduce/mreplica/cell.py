from taintinduce.cpu.cpu import CPU, CPUFactory
from taintinduce.isa.register import Register
from taintinduce.observation_engine.observation import simple_state_executor
from taintinduce.state.state import State
from taintinduce.types import Architecture, StateValue


class Cell:
    mask: int
    value: int
    hex_instruction: str
    architecture: Architecture
    state_format: list[Register]
    cpu: CPU

    def __init__(
        self,
        value: int,
        mask: int,
        hex_instruction: str,
        architecture: Architecture,
        state_format: list[Register],
    ):
        self.value = value
        self.mask = mask
        self.hex_instruction = hex_instruction
        self.architecture = architecture
        self.state_format = state_format
        self.cpu = CPUFactory.create_cpu(architecture)

    def __repr__(self) -> str:
        return f'Cell({self.value}, {self.mask}, {self.hex_instruction}, {self.architecture}, {self.state_format})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Cell):
            return NotImplemented
        return (
            self.value == other.value
            and self.mask == other.mask
            and self.hex_instruction == other.hex_instruction
            and self.architecture == other.architecture
            and self.state_format == other.state_format
        )

    def __hash__(self) -> int:
        return hash((self.value, self.mask, self.hex_instruction, self.architecture, tuple(self.state_format)))

    def get_output(self, state: State) -> State:
        return simple_state_executor(
            self.apply_mask(state),
            self.architecture,
            self.hex_instruction,
            self.state_format,
            self.cpu,
        )

    def apply_mask(self, input_value: State) -> State:
        """Apply the cell's mask and replace by the cell's value to the input value."""
        new_state_value = (input_value.state_value & ~self.mask) | (self.value & self.mask)
        return State(input_value.num_bits, StateValue(new_state_value))
