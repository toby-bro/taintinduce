from abc import ABC, abstractmethod
from typing import Optional

from taintinduce.serialization import SerializableMixin

from .register import CondRegister, Register


class ISA(ABC, SerializableMixin):
    """Abstract base class for ISA implementations (X86, AMD64, ARM64, etc.)."""

    name: str
    cpu_regs: list[Register]
    full_cpu_regs: list[Register]
    cpu_read_emu_regs: list[Register]
    cpu_write_emu_regs: list[Register]
    pc_reg: Register
    flag_reg: list[Register]
    state_reg: list[Register]
    cond_reg: CondRegister
    uc_arch: tuple[int, int]
    ks_arch: tuple[int, int]
    cs_arch: tuple[int, int]
    code_mem: int
    code_addr: int
    addr_space: int

    def __init__(self) -> None:
        pass

    @abstractmethod
    def name2reg(self, name: str) -> Register:
        """Convert register name to register object. Must be implemented by subclasses."""

    @abstractmethod
    def name2mem(self, name: str) -> tuple[Register, Register]:
        """Convert memory register name to (memory_register, address_register) tuple.
        Must be implemented by subclasses."""

    @abstractmethod
    def create_full_reg(self, name: str, bits: int = 0, structure: Optional[list[int]] = None) -> Register:
        """Create a full register with given parameters. Must be implemented by subclasses."""
