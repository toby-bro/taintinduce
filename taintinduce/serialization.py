"""JSON serialization for TaintInduce objects.

This module provides custom JSON encoding/decoding for TaintInduce classes.
"""

import importlib
import json
from typing import Any, Iterable, Self, TypeVar

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

    def _get_common_type(self, items: Iterable[Any]) -> str | None:
        """Get the common type name if all items are the same type."""
        if not items:
            return None
        types = {type(item).__name__ for item in items}
        if len(types) == 1:
            return types.pop()
        return None

    def _add_type_markers(self, obj: Any) -> Any:  # noqa: C901
        """Add type markers only at the collection level, indicating element types."""
        if isinstance(obj, set) or isinstance(obj, frozenset):
            values_list = list(obj)
            result: dict[str, Any] = {'_set': True, '_frozen': isinstance(obj, frozenset), 'values': values_list}
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
        if isinstance(obj, tuple):
            # Recursively process tuple items
            processed_list = [self._add_type_markers(item) for item in obj]
            result = {'_tuple': processed_list}
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

        if hasattr(obj, '__dict__') and len(obj.__dict__) > 0:
            # Serialize objects with their class name and attributes, processing attributes recursively
            result = {'_class': obj.__class__.__name__, '_module': obj.__class__.__module__}
            for k, v in obj.__dict__.items():
                result[k] = self._add_type_markers(v)
            return result
        # if isinstance(obj, int):
        #     return {'_int': obj}
        # if isinstance(obj, str):
        #     return {'_str': obj}
        # if isinstance(obj, bool):
        #     return {'_bool': obj}
        # if obj is None:
        #     return {'_none': True}
        # For anything else (int, str, bool, None, etc) - no markers
        return obj


class TaintInduceDecoder(json.JSONDecoder):
    """Custom JSON decoder for TaintInduce objects."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(object_hook=self.object_hook, *args, **kwargs)  # noqa: B026

    def convert_to_type(self, value: Any, type_name: str | None) -> Any:
        """Convert value to the specified type."""
        if type_name is None:
            return value
        if value.__class__.__name__ == type_name:
            return value
        if type_name == 'int':
            return int(value)
        if type_name == 'str':
            return str(value)
        if type_name == 'bool':
            return bool(value)
        if type_name == 'float':
            return float(value)
        if type_name == 'bytes':
            return bytes(value)
        if type_name == 'tuple':
            return tuple(value)
        if type_name == 'list':
            return list(value)
        raise ValueError(f'Unsupported type for conversion: {type_name}')

    def object_hook(self, dct: dict[str, Any]) -> Any:
        # Handle list (may have _type field)
        if '_list' in dct:
            if dct.get('_type'):
                return [self.convert_to_type(item, dct['_type']) for item in dct['_list']]
            return dct['_list']

        if '_tuple' in dct:
            return tuple(dct['_tuple'])

        # Handle dict (may have _key_type and _value_type fields)
        if '_dict' in dct:
            inner_dict = dct['_dict']
            # If keys were originally ints, convert them back
            inner_dict = {
                self.convert_to_type(k, dct.get('_key_type')): self.convert_to_type(v, dct.get('_value_type'))
                for k, v in inner_dict.items()
            }
            return inner_dict  # noqa: RET504

        # Handle sets (may have _type field)
        if '_set' in dct and dct.get('_set'):
            inner = (
                [self.convert_to_type(item, dct['_type']) for item in dct['values']]
                if dct.get('_type')
                else dct['values']
            )
            if dct.get('_frozen'):
                return frozenset(inner)
            return set(inner)

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
