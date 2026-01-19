"""JN CPU emulator compatible with UnicornCPU interface.

This provides a CPU interface for JN ISA that matches UnicornCPU's API,
allowing JN to work with the standard observation generation code.
"""

from typing import Sequence

from taintinduce.isa.jn_isa import decode_hex_string as decode_jn_hex
from taintinduce.isa.jn_registers import JN_REG_NZVC, JN_REG_R1, JN_REG_R2
from taintinduce.isa.register import Register
from taintinduce.types import CpuRegisterMap

from .cpu import CPU


class JNCpu(CPU):
    """JN CPU that implements UnicornCPU-like interface."""

    def __init__(self) -> None:
        """Initialize JN CPU."""
        self.current_state: CpuRegisterMap = CpuRegisterMap(
            {
                JN_REG_R1(): 0,
                JN_REG_R2(): 0,
                JN_REG_NZVC(): 0,
            },
        )

    def randomize_regs(self, _: list[Register] | None = None) -> None:
        """Randomize register values (not needed for JN - we test exhaustively)."""
        import random  # noqa: PLC0415

        self.current_state[JN_REG_R1()] = random.randint(0, 0xF)
        self.current_state[JN_REG_R2()] = random.randint(0, 0xF)
        self.current_state[JN_REG_NZVC()] = random.randint(0, 0xF)

    def set_cpu_state(self, regs: CpuRegisterMap) -> None:
        """Set CPU state from register map.

        Args:
            regs: Dictionary mapping registers to values
        """
        self.current_state = CpuRegisterMap(regs)

    def write_reg(self, reg: Register, value: int) -> None:
        """Write a value to a register.

        Args:
            reg: Register to write
            value: Value to write
        """
        self.current_state[reg] = value & 0xF

    def write_regs(self, regs: Sequence[Register], values: Sequence[int] | int) -> None:
        """Write values to multiple registers.

        Args:
            regs: List of registers to write
            values: List of values to write
        """
        seq_values: Sequence[int]
        if isinstance(values, int):
            seq_values = tuple([values for _ in regs])
        else:
            seq_values = values
        for reg, val in zip(regs, seq_values, strict=True):
            self.write_reg(reg, val)

    def execute(self, bytecode: bytes) -> tuple[CpuRegisterMap, CpuRegisterMap]:
        """Execute instruction and return before/after state.

        Args:
            bytecode: Instruction bytes (as hex string for JN)

        Returns:
            Tuple of (state_before, state_after)
        """
        # Decode instruction
        instruction = decode_jn_hex(bytecode.hex())

        # Save state before
        state_before = CpuRegisterMap(self.current_state)

        # Extract register values
        r1 = self.current_state.get(JN_REG_R1(), 0)
        r2 = self.current_state.get(JN_REG_R2(), 0)

        # Execute instruction directly
        out_r1, out_r2 = instruction.execute(r1, r2)

        # Update current state (NZVC remains unchanged for now - TODO: update flags)
        self.current_state[JN_REG_R1()] = out_r1 & 0xF
        self.current_state[JN_REG_R2()] = out_r2 & 0xF

        # Return before/after
        state_after = CpuRegisterMap(self.current_state)
        return state_before, state_after

    def set_memregs(self, mem_regs: set[Register]) -> None:
        """Set memory registers (not used for JN).

        Args:
            mem_regs: Set of memory registers (ignored for JN)
        """
        if mem_regs:
            raise NotImplementedError('JN CPU does not support memory registers.')

    def read_reg(self, reg: Register) -> int:
        return self.current_state.get(reg, 0)

    def get_cpu_state(self) -> CpuRegisterMap:
        return self.current_state
