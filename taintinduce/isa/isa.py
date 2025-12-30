from abc import ABC, abstractmethod
from typing import Optional

from taintinduce.serialization import SerializableMixin


class Register(ABC, SerializableMixin):
    """Abstract base class for CPU registers and memory locations. Only subclasses should be instantiated."""

    name: str
    uc_const: int
    bits: int
    structure: list[int]
    value: Optional[int]
    address: Optional[int]

    @abstractmethod
    def __init__(self, repr_str: Optional[str] = None) -> None:
        pass

    def __hash__(self) -> int:
        return hash(self.uc_const)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Register):
            return NotImplemented
        return self.uc_const == other.uc_const

    def __ne__(self, other: object) -> bool:
        return not (self == other)


class ISA(ABC, SerializableMixin):
    """Abstract base class for ISA implementations (X86, AMD64, ARM64, etc.)."""

    name: Optional[str]
    cpu_regs: Optional[list[Register]]

    def __init__(self) -> None:
        pass

    @abstractmethod
    def name2reg(self, name: str) -> Register | tuple[Register, Register]:
        """Convert register name to register objects. Must be implemented by subclasses."""

    @abstractmethod
    def create_full_reg(self, name: str, bits: int = 0, structure: list[int] = []) -> Register:  # noqa: B006
        """Create a full register with given parameters. Must be implemented by subclasses."""
