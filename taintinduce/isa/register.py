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


class CondRegister(Register):
    """Abstract base class for condition flag registers."""

    @abstractmethod
    def __init__(self, repr_str: Optional[str] = None) -> None:
        pass
