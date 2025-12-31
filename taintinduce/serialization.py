"""JSON serialization for TaintInduce objects.

This module provides custom JSON encoding/decoding for TaintInduce classes.
"""

import importlib
import json
from typing import Any, Self, TypeVar

T = TypeVar('T')


class TaintInduceEncoder(json.JSONEncoder):
    """Custom JSON encoder for TaintInduce objects."""

    def encode(self, obj: Any) -> str:
        """Override encode to add type markers before encoding."""
        marked_obj = self._add_type_markers(obj)
        return super().encode(marked_obj)

    def default(self, obj: Any) -> Any:
        """Handle objects that can't be serialized by default JSON encoder."""
        return self._add_type_markers(obj)

    def _get_common_type(self, items: list[Any]) -> str | None:
        """Get the common type name if all items are the same type."""
        if not items:
            return None
        types = {type(item).__name__ for item in items}
        if len(types) == 1:
            return types.pop()
        return None

    def _add_type_markers(self, obj: Any) -> Any:  # noqa: C901
        """Add type markers only at the collection level, indicating element types."""
        if isinstance(obj, set):
            values_list = list(obj)
            result: dict[str, Any] = {'_set': True, 'values': values_list}
            common_type = self._get_common_type(values_list)
            if common_type:
                result['_type'] = common_type
            return result
        if isinstance(obj, list):
            # Recursively process list items
            processed_list = [self._add_type_markers(item) for item in obj]
            result = {'_list': processed_list}
            common_type = self._get_common_type(obj)
            if common_type:
                result['_type'] = common_type
            return result
        if isinstance(obj, dict):
            # Check if this is already a type marker dict to avoid double-wrapping
            if len(obj) == 1:
                key = next(iter(obj.keys()))
                if key in ('_int', '_str', '_list', '_dict', '_set', '_class'):
                    return obj
            # Mark dict and recursively process only values (keys stay as-is)
            processed_dict = {k: self._add_type_markers(v) for k, v in obj.items()}
            result = {'_dict': processed_dict}

            # Add key type if all keys are the same type
            key_type = self._get_common_type(list(obj.keys()))
            if key_type:
                result['_key_type'] = key_type

            # Add value type if all values are the same type
            value_type = self._get_common_type(list(obj.values()))
            if value_type:
                result['_value_type'] = value_type

            return result
        if hasattr(obj, '__dict__'):
            # Serialize objects with their class name and attributes, processing attributes recursively
            result = {'_class': obj.__class__.__name__, '_module': obj.__class__.__module__}
            for k, v in obj.__dict__.items():
                result[k] = self._add_type_markers(v)
            return result
        # For anything else (int, str, bool, None, etc) - no markers
        return obj


class TaintInduceDecoder(json.JSONDecoder):
    """Custom JSON decoder for TaintInduce objects."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(object_hook=self.object_hook, *args, **kwargs)  # noqa: B026

    def object_hook(self, dct: dict[str, Any]) -> Any:
        # Handle list (may have _type field)
        if '_list' in dct:
            return dct['_list']

        # Handle dict (may have _key_type and _value_type fields)
        if '_dict' in dct:
            inner_dict = dct['_dict']
            # If keys were originally ints, convert them back
            if dct.get('_key_type') == 'int':
                inner_dict = {int(k): v for k, v in inner_dict.items()}
            return inner_dict

        # Handle sets (may have _type field)
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
