"""JN (Just Nibbles) ISA Executor.

Executes JN instructions and tracks state changes.
"""

from taintinduce.isa.jn_isa import JNInstruction
from taintinduce.isa.jn_registers import get_jn_state_format
from taintinduce.state.state import State
from taintinduce.types import StateValue


class JNExecutor:
    """Executes JN instructions and manages register state."""

    def __init__(self):
        self.state_format = get_jn_state_format()

    def execute(self, instruction: JNInstruction, input_state: State) -> State:
        """Execute an instruction on the given state.

        Args:
            instruction: The JN instruction to execute
            input_state: Input state with R1 (bits 0-3), R2 (bits 4-7), NZVC (bits 8-11)

        Returns:
            Output state after execution
        """
        # Extract R1, R2, and NZVC from state
        r1 = (input_state.state_value >> 0) & 0xF
        r2 = (input_state.state_value >> 4) & 0xF
        nzvc = (input_state.state_value >> 8) & 0xF

        # Execute instruction (only modifies R1, R2 unchanged)
        new_r1, new_r2 = instruction.execute(r1, r2)

        # TODO: Update NZVC flags based on result
        # For now, NZVC remains unchanged
        new_nzvc = nzvc

        # Build new state (12 bits)
        new_state_value = (new_r1 & 0xF) | ((new_r2 & 0xF) << 4) | ((new_nzvc & 0xF) << 8)

        return State(num_bits=12, state_value=StateValue(new_state_value))

    def create_state(self, r1: int, r2: int, nzvc: int = 0) -> State:
        """Create a state from R1, R2, and NZVC values.

        Args:
            r1: R1 value (0-15)
            r2: R2 value (0-15)
            nzvc: NZVC flags value (0-15), default 0

        Returns:
            State object
        """
        state_value = (r1 & 0xF) | ((r2 & 0xF) << 4) | ((nzvc & 0xF) << 8)
        return State(num_bits=12, state_value=StateValue(state_value))

    def extract_registers(self, state: State) -> tuple[int, int, int]:
        """Extract R1, R2, and NZVC from a state.

        Args:
            state: State object

        Returns:
            Tuple of (r1, r2, nzvc)
        """
        r1 = (state.state_value >> 0) & 0xF
        r2 = (state.state_value >> 4) & 0xF
        nzvc = (state.state_value >> 8) & 0xF
        return r1, r2, nzvc
