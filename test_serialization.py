#!/usr/bin/env python3
"""Test the updated serialization with type markers."""

import json

from taintinduce.serialization import TaintInduceDecoder, TaintInduceEncoder

# Test data with various types
test_data = {
    'conditions': [],
    'dataflows': [
        {
            '34': {2, 6, 34},  # set of ints
            '35': {2, 35, 6},  # set of ints
            '18': {18},  # set of single int
            '4': set(),  # empty set
        },
        {
            '99': {99, 100},
        },
    ],
    'metadata': {
        1: 100,  # int keys, int values
        2: 200,
        3: 300,
    },
    'mixed': {
        'a': 'hello',  # str keys, str values
        'b': 'world',
    },
    'registers': ['eax', 'ebx', 'ecx'],  # list of strings
    'bits': [1, 0, 1, 1, 0],  # list of ints
    'nested': [{'x': 1}, {'y': 2}],  # list of dicts
}

print('Original data:')
print(test_data)
print()

# Serialize
serialized = json.dumps(test_data, cls=TaintInduceEncoder, indent=2)
print('Serialized JSON:')
print(serialized)
print()

# Deserialize
deserialized = json.loads(serialized, cls=TaintInduceDecoder)
print('Deserialized data:')
print(deserialized)
print()

# Verify round-trip
if test_data == deserialized:
    print('✓ Round-trip successful!')
else:
    print('✗ Round-trip failed!')
    print(f'Original: {test_data}')
    print(f'Deserialized: {deserialized}')
