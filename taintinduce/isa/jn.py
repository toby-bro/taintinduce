"""JN (Just Nibbles) ISA - A simplified 4-bit architecture for testing.

This is a minimal ISA with:
- 2 registers: R1, R2 (4 bits each)
- 8 instructions: ADD/OR/AND/XOR with register or immediate variants
- No condition flags (for simplicity)
- Direct execution (no emulation needed)
"""

from . import jn_registers
from .isa import ISA
from .register import Register


class JN(ISA):
    """JN (Just Nibbles) ISA - Simplified 4-bit architecture."""

    def __init__(self) -> None:
        # Only two registers
        self.cpu_regs = [
            jn_registers.JN_REG_R1(),
            jn_registers.JN_REG_R2(),
        ]

        # Full register list (same as cpu_regs for JN)
        self.full_cpu_regs = [
            jn_registers.JN_REG_R1(),
            jn_registers.JN_REG_R2(),
        ]

        # No memory operations in JN
        self.cpu_read_emu_regs = []
        self.cpu_write_emu_regs = []

        # No PC register (instructions execute directly)
        self.pc_reg = None  # type: ignore[assignment]
        self.flag_reg = []
        self.state_reg = []

        # No register aliasing in JN
        self.register_map: dict[str, list[str]] = {}
        self.register_alias = {
            'R1': 'R1',
            'R2': 'R2',
        }

        # No emulator constants needed for JN
        self.uc_arch = None  # type: ignore[assignment]
        self.ks_arch = None  # type: ignore[assignment]
        self.cs_arch = None  # type: ignore[assignment]
        self.code_mem = 0
        self.code_addr = 0
        self.addr_space = 12  # Total state is 12 bits (R1=4, R2=4, NZCV=4)

        # Condition flags register
        self.cond_reg = jn_registers.JN_REG_NZCV()

    def name2mem(self, name: str) -> tuple[Register, Register]:
        """JN has no memory operations."""
        raise NotImplementedError('JN ISA does not support memory operations')

    def name2reg(self, name: str) -> Register:
        """Convert register name to register object."""
        name = name.upper()
        if name == 'R1':
            return jn_registers.JN_REG_R1()
        if name == 'R2':
            return jn_registers.JN_REG_R2()
        raise ValueError(f'Unknown JN register: {name}')

    def create_full_reg(self, name: str, bits: int = 0, structure: list[int] | None = None) -> Register:
        """Create a full register. JN has no sub-registers."""
        _ = bits, structure  # Unused but required by interface
        return self.name2reg(name)
