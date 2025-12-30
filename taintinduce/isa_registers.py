"""
Register definitions to replace squirrel.isa.registers.
Simple implementation for ISA register handling.
"""

from typing import Any

from taintinduce.serialization import MemorySlot as _MemorySlot
from taintinduce.serialization import get_register_arch as _get_register_arch
from taintinduce.serialization import register_arch

# Re-export for compatibility
MemorySlot = _MemorySlot
get_register_arch = _get_register_arch


class SimpleReg:
    """Simple register object with just a name."""

    def __init__(self, reg_name: str) -> None:
        self.name: str = reg_name

    def __repr__(self) -> str:
        return f'SimpleReg({self.name})'


class RegisterBase:
    """
    Base class for architecture-specific registers.
    Each architecture should subclass this and define get_reg method.
    """

    # Class-level Capstone instance for register name mapping
    _capstone_instance: Any = None

    @classmethod
    def set_capstone_instance(cls, md: Any) -> None:
        """Set the Capstone instance for register name resolution."""
        cls._capstone_instance = md

    @classmethod
    def get_reg_name(cls, reg_id: int) -> str:
        """Get register name from Capstone register ID."""
        if cls._capstone_instance:
            name = cls._capstone_instance.reg_name(reg_id)
            return name.upper() if name else str(reg_id)
        return str(reg_id)

    @classmethod
    def get_reg(cls, name: str) -> Any:
        """Get a register by name. Should be implemented by subclasses."""
        return SimpleReg(name)


@register_arch('X86')
class X86Registers(RegisterBase):
    """X86 register accessor."""



@register_arch('AMD64')
class AMD64Registers(RegisterBase):
    """AMD64 register accessor."""



@register_arch('ARM64')
class ARM64Registers(RegisterBase):
    """ARM64 register accessor."""

