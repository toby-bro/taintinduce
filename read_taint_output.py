#!/usr/bin/env python3
"""
Helper script to read and analyze TaintInduce output files.

Usage:
    python read_taint_output.py <rule_file.json>
    python read_taint_output.py <obs_file.json> --observations
"""

import json
import sys
from pathlib import Path

from taintinduce.rules import TaintRule
from taintinduce.serialization import TaintInduceDecoder
from taintinduce.state import Observation


def _print_dataflow_propagations(dataflow: dict[int, set[int]]) -> None:
    """Print sample taint propagations for a dataflow."""
    if not dataflow:
        return

    print('\n   Sample taint propagations (input bit → output bits):')
    for _, (src_bit, dest_bits) in enumerate(list(dataflow.items())[:5]):
        # Handle sets that were serialized
        dest_list = sorted(dest_bits)

        # Convert src_bit to int if it's a string
        src_bit_val = src_bit

        if len(dest_list) > 10:
            print(
                f"     Bit {src_bit_val:3d} → [{', '.join(map(str, dest_list[:5]))}... +{len(dest_list)-5} more]",
            )
        else:
            print(f'     Bit {src_bit_val:3d} → {dest_list}')

    if len(dataflow) > 5:
        print(f'     ... and {len(dataflow) - 5} more input bits')


def read_rule(rule_file: str) -> None:
    """Read and display a taint rule file."""
    print('=' * 70)
    print(f'TAINT RULE: {rule_file}')
    print('=' * 70)

    with open(rule_file, 'r') as f:
        rule = json.load(f, cls=TaintInduceDecoder)
    if not isinstance(rule, TaintRule):
        print('❌ Error: Loaded object is not a TaintRule.')
        return

    print(f'\n📊 Rule: {rule}')
    print('\n🏗️  State Format:')
    print(f'   Architecture: {rule.format.arch}')
    print(f'   Registers ({len(rule.format.registers)}):')
    for i, reg in enumerate(rule.format.registers, 1):
        reg_name = reg.name if hasattr(reg, 'name') else str(reg)
        print(f'     {i}. {reg_name}')

    print(f'\n   Memory Slots ({len(rule.format.mem_slots)}):')
    for i, mem in enumerate(rule.format.mem_slots, 1):
        access = mem.access_type if hasattr(mem, 'access_type') else '?'
        mem_type = mem.mem_type if hasattr(mem, 'mem_type') else '?'
        size = mem.size if hasattr(mem, 'size') else '?'
        print(f'     {i}. {access} {mem_type} (size: {size})')

    print(f'\n🔀 Dataflows ({len(rule.dataflows)} dataflow sets):')
    for df_id, dataflow in enumerate(rule.dataflows):
        print(f'   Dataflow {df_id}: {len(dataflow)} input bits tracked')
        _print_dataflow_propagations(dataflow)

    print(f'\n🎯 Conditions: {len(rule.conditions)}')
    if rule.conditions:
        for i, cond in enumerate(rule.conditions):
            print(f'   Condition {i}: {cond}')
    else:
        print('   No conditions (unconditional dataflow)')

    print()


def read_observations(obs_file: str, limit: int = 5) -> None:
    """Read and display observations file."""
    print('=' * 70)
    print(f'OBSERVATIONS: {obs_file}')
    print('=' * 70)

    with open(obs_file, 'r') as f:
        obs_list = json.load(f, cls=TaintInduceDecoder)
    if not isinstance(obs_list, list):
        print('❌ Error: Expected a list of observations in the file.')
        return

    print(f'\n📝 Total observations: {len(obs_list)}')

    if obs_list:
        first_obs = obs_list[0]
        if not isinstance(first_obs, Observation):
            print('❌ Error: Invalid observation structure.')
            return
        print('\n📊 Observation structure:')
        print(f'   Instruction: {first_obs.bytestring} ({first_obs.archstring})')
        print(f'   State format: {len(first_obs.state_format)} elements')
        print('   Seed I/O pair: 1')
        print(f'   Mutated I/O pairs: {len(first_obs.mutated_ios)}')

        print(f'\n🔍 Showing first {min(limit, len(obs_list))} observations:')
        for i, obs in enumerate(obs_list[:limit]):
            assert isinstance(obs, Observation)
            seed_in, seed_out = obs.seed_io
            print(f'\n   Observation {i+1}:')
            print(f'     Seed input state:  {seed_in.num_bits} bits, value={hex(seed_in.state_value)[:20]}...')
            print(f'     Seed output state: {seed_out.num_bits} bits, value={hex(seed_out.state_value)[:20]}...')
            print(f'     Mutations tested: {len(obs.mutated_ios)}')

    print()


def main():
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python read_taint_output.py <rule_file.json>')
        print('  python read_taint_output.py <obs_file.json> --observations')
        print('\nExamples:')
        print('  python read_taint_output.py output/c3_X86_rule.json')
        print('  python read_taint_output.py output/c3_X86_obs.json --observations')
        sys.exit(1)

    file_path = sys.argv[1]

    if not Path(file_path).exists():
        print(f'❌ Error: File not found: {file_path}')
        sys.exit(1)

    if '--observations' in sys.argv or 'obs' in file_path:
        limit = int(sys.argv[sys.argv.index('--limit') + 1]) if '--limit' in sys.argv else 5
        read_observations(file_path, limit)
    else:
        read_rule(file_path)


if __name__ == '__main__':
    main()
