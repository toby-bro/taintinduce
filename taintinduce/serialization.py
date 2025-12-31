"""JSON serialization for TaintInduce objects.

This module provides custom JSON encoding/decoding for TaintInduce classes.
"""

import importlib
import json
from typing import Any, Self, TypeVar

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
        return json.loads(data, cls=TaintInduceDecoder)  # type: ignore[no-any-return]

    def to_dict(self) -> dict[str, Any]:
        """Convert object to dictionary."""
        return {'_class': self.__class__.__name__, '_module': self.__class__.__module__, **self.__dict__}
