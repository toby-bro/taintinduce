from abc import ABC, abstractmethod
from typing import Optional, Sequence

from taintinduce.isa.register import Register
from taintinduce.types import CpuRegisterMap


class CPU(ABC):
    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def set_memregs(self, mem_regs: set[Register]) -> None:
        """Set memory registers in the CPU.

        Args:
            memregs: Dictionary mapping memory addresses to values
        """

    @abstractmethod
    def write_reg(self, reg: Register, value: int) -> None:
        """Write value to register.

        Args:
            reg: Register to write to
            value: Value to write
        """

    @abstractmethod
    def write_regs(self, regs: Sequence[Register], values: Sequence[int] | int) -> None:
        """Write values to multiple registers.

        Args:
            regs: List of registers to write to
            values: List of values to write, or single value to write to all registers
        """

    @abstractmethod
    def read_reg(self, reg: Register) -> int:
        """Read value from register.

        Args:
            reg: Register to read from

        Returns:
            Value read from the register
        """

    @abstractmethod
    def get_cpu_state(self) -> CpuRegisterMap:
        """Get current CPU register state.

        Returns:
            Dictionary mapping registers to their current values
        """

    def set_cpu_state(self, cpu_state: CpuRegisterMap) -> None:
        for reg, value in cpu_state.items():
            self.write_reg(reg, value)

    @abstractmethod
    def randomize_regs(self, reg_list: Optional[list[Register]] = None) -> None:
        """Randomize values of registers.

        Args:
            reg_list: List of registers to randomize. If None, randomize all registers.
        """

    @abstractmethod
    def execute(
        self,
        code: bytes,
    ) -> tuple[CpuRegisterMap, CpuRegisterMap]:
        """Execute code on the CPU.

        Args:
            code: Bytes of code to execute

        Returns:
            Tuple of (initial CPU state, final CPU state)
        """

    def identify_memops_jump(self, _: bytes) -> tuple[set[Register], Optional[Register]]:
        """Identify memory operation registers and jump register in the code.

        Args:
            code: Bytes of code to analyze

        Returns:
            Tuple of (set of memory operation registers, jump register or None)
        """
        return set(), None


class CPUFactory:
    @staticmethod
    def create_cpu(arch: str) -> CPU:
        if arch == 'JN':
            from taintinduce.cpu.jn_cpu import JNCpu  # noqa: PLC0415

            return JNCpu()

        from taintinduce.cpu.unicorn_cpu import UnicornCPU  # noqa: PLC0415

        return UnicornCPU(arch)
