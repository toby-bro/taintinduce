from itertools import combinations

from taintinduce.isa.register import Register
from taintinduce.mreplica.cell import Cell
from taintinduce.state.state import State
from taintinduce.types import Architecture, StateValue


class MReplica:
    cells: set[Cell]
    hex_instruction: str
    architecture: Architecture
    state_format: list[Register]

    def __init__(self, hex_instruction: str, architecture: Architecture, state_format: list[Register]):
        self.hex_instruction = hex_instruction
        self.architecture = architecture
        self.state_format = state_format
        self.cells = set()

    def add_cell(self, cell: Cell) -> None:
        self.cells.add(cell)

    def add_cells(self, cells: set[Cell]) -> None:
        self.cells.update(cells)

    def new_cell(self, mask: int, value: int) -> Cell:
        cell = Cell(
            value=value,
            mask=mask,
            hex_instruction=self.hex_instruction,
            architecture=self.architecture,
            state_format=self.state_format,
        )
        self.add_cell(cell)
        return cell

    def simulate(self, input_state: State) -> State:
        """Simulate the instruction on the given input state and return the set of possible output states."""
        output_states = set()
        for cell in list(self.cells):
            output_state = cell.get_output(input_state)
            output_states.add(output_state.state_value)
        # XOR bitwise two by two all output states and OR them together to get the final output state
        output_taint = 0
        for output_1, output_2 in combinations(output_states, 2):
            output_taint |= output_1 ^ output_2

        return State(input_state.num_bits, StateValue(output_taint))

    def __repr__(self) -> str:
        return f'MReplica({self.hex_instruction}, {self.architecture}, {self.state_format}, {len(self.cells)} cells)'

    def __str__(self) -> str:
        return f'MReplica({self.hex_instruction}, {self.architecture}, {self.state_format}, \n{tuple(self.cells)})'

    def make_full_m_replica(self, bits_to_use: State, reset: bool = True) -> None:
        """
        Generate a full M-replica for the instruction by creating cells for all possible combinations of input bits.
        """
        if reset:
            self.cells.clear()
        mask = bits_to_use.state_value
        active_bit_positions = [i for i in range(bits_to_use.num_bits) if mask & (1 << i)]
        for r in range(len(active_bit_positions) + 1):
            for combo in combinations(active_bit_positions, r):
                value = sum(1 << bit for bit in combo)
                self.new_cell(mask, value)
