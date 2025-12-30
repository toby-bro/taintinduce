"""
Simple JSON serialization to replace squirrel-framework.
Uses dataclasses + custom JSON encoder/decoder for object serialization.
"""

import importlib
import json
from typing import TYPE_CHECKING, Any, Callable, Optional, Self, TypeVar

if TYPE_CHECKING:
    from taintinduce.isa_registers import RegisterBase

T = TypeVar('T')


class TaintInduceEncoder(json.JSONEncoder):
    """Custom JSON encoder for TaintInduce objects."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, set):
            # Convert sets to lists for JSON serialization
            return {'_set': True, 'values': list(obj)}
        if hasattr(obj, '__dict__'):
            # Serialize objects with their class name and attributes
            return {'_class': obj.__class__.__name__, '_module': obj.__class__.__module__, **obj.__dict__}
        return super().default(obj)


class TaintInduceDecoder(json.JSONDecoder):
    """Custom JSON decoder for TaintInduce objects."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(object_hook=self.object_hook, *args, **kwargs)  # noqa: B026

    def object_hook(self, dct: dict[str, Any]) -> Any:
        # Handle sets
        if '_set' in dct and dct.get('_set'):
            return set(dct['values'])

        if '_class' not in dct:
            return dct

        # Import the module and get the class

        class_name = dct.pop('_class')
        module_name = dct.pop('_module')

        try:
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)

            # Create instance without calling __init__
            obj = cls.__new__(cls)
            obj.__dict__.update(dct)
            return obj
        except (ImportError, AttributeError) as e:
            # Fall back to dict if class not found
            print(f'Warning: Could not deserialize {module_name}.{class_name}: {e}')
            return dct


class SerializableMixin:
    """Mixin to add serialize/deserialize methods to any class."""

    def serialize(self) -> str:
        """Serialize object to JSON string."""
        return json.dumps(self, cls=TaintInduceEncoder)

    @classmethod
    def deserialize(cls, data: str) -> Self:
        """Deserialize object from JSON string."""
        return json.loads(data, cls=TaintInduceDecoder)

    def to_dict(self) -> dict[str, Any]:
        """Convert object to dictionary."""
        return {'_class': self.__class__.__name__, '_module': self.__class__.__module__, **self.__dict__}


class TaintRule:
    """
    Simplified TaintRule to replace squirrel.acorn.acorn.TaintRule.
    Represents taint propagation rules.
    """

    def __init__(self, state_format: Optional[Any] = None, conditions: Optional[list[Any]] = None) -> None:
        self.state_format: Any = state_format or []
        self.conditions: list[Any] = conditions or []
        self.dataflows: list[dict[Any, Any]] = [{}]  # List of dataflow dicts

    def serialize(self) -> str:
        return json.dumps(self, cls=TaintInduceEncoder)

    @classmethod
    def deserialize(cls: type['TaintRule'], data: str) -> 'TaintRule':
        return json.loads(data, cls=TaintInduceDecoder)

    def __str__(self) -> str:
        # Handle both list and StateFormat objects
        if isinstance(self.state_format, StateFormat):
            num_regs = len(self.state_format.registers) + len(self.state_format.mem_slots)
        else:
            num_regs = len(self.state_format) if hasattr(self.state_format, '__len__') else 0

        return (
            f'TaintRule(state_format={num_regs} regs, '
            f'conditions={len(self.conditions)}, dataflows={len(self.dataflows)})'
        )

    def __repr__(self) -> str:
        return self.__str__()


class StateFormat:
    """Simplified StateFormat to replace squirrel's version."""

    def __init__(self, arch: str, registers: Optional[list[Any]] = None, mem_slots: Optional[list[Any]] = None) -> None:
        self.arch: str = arch
        self.registers: list[Any] = registers or []
        self.mem_slots: list[Any] = mem_slots or []

    def serialize(self) -> str:
        return json.dumps(self, cls=TaintInduceEncoder)


class MemorySlot:
    """Simplified MemorySlot for memory access tracking."""

    READ: str = 'READ'
    WRITE: str = 'WRITE'
    ADDR: str = 'ADDR'
    VALUE: str = 'VALUE'

    def __init__(self, slot_id: int, access_type: str, size: int, mem_type: str) -> None:
        self.slot_id: int = slot_id
        self.access_type: str = access_type
        self.size: int = size
        self.mem_type: str = mem_type

    @staticmethod
    def get_mem(slot_id: int, access_type: str, size: int, mem_type: str) -> 'MemorySlot':
        return MemorySlot(slot_id, access_type, size, mem_type)


# Registry for architecture-specific register implementations
_register_archs: dict[str, type['RegisterBase']] = {}


def register_arch(arch_name: str) -> Callable[[type['RegisterBase']], type['RegisterBase']]:
    """Decorator to register architecture implementations."""

    def decorator(cls: type['RegisterBase']) -> type['RegisterBase']:
        _register_archs[arch_name] = cls
        return cls

    return decorator


def get_register_arch(arch_name: str) -> Optional[type['RegisterBase']]:
    """Get the register class for a specific architecture."""
    return _register_archs.get(arch_name)
