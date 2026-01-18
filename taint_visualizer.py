#!/usr/bin/env python3
"""
TaintInduce Visualizer - Interactive web-based tool for visualizing and testing taint rules.

Features:
1. Graph visualization of taint flows
2. Condition-dataflow explorer
3. Interactive simulator with concrete test cases
4. Rule validation and debugging

Usage:
    python taint_visualizer.py <rule_file.json>

Then open http://localhost:5000 in your browser
"""

import json
import sys
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

from taintinduce.isa.register import Register
from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import TaintRule
from taintinduce.serialization import TaintInduceDecoder
from taintinduce.state.state import check_ones

# Import visualizer helper modules
from visualizer.taint_simulator import (
    build_state_from_bits,
    extract_bits_from_state,
    get_flag_info,
    simulate_taint_propagation,
)

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent

app = Flask(__name__, static_folder=str(SCRIPT_DIR / 'static'))

# Global rule storage
current_rule: TaintRule | None = None
rule_file_path: str = ''


def evaluate_condition(condition: TaintCondition | None, state_value: int) -> bool:
    """Evaluate a condition against a specific state value."""
    if condition is None:
        return True  # Unconditional always matches

    if condition.condition_ops is None or len(condition.condition_ops) == 0:
        return True

    if condition.condition_type == LogicType.DNF:
        # DNF: OR of ANDs - any clause can be true
        for bitmask, value in condition.condition_ops:
            # Ensure integers for bitwise operations
            if (state_value & int(bitmask)) == int(value):
                return True
        return False

    return False


def get_matching_pairs(rule: TaintRule, input_state_value: int) -> list[dict['str', Any]]:
    """Find which condition-dataflow pairs match the given input state."""
    matching_pairs = []
    for idx, pair in enumerate(rule.pairs):
        if evaluate_condition(pair.condition, input_state_value):
            matching_pairs.append(
                {
                    'pair_index': idx,
                    'condition': pair.condition,
                    'dataflow': pair.output_bits,
                    'is_unconditional': pair.condition is None,
                },
            )
    return matching_pairs


def format_condition_human_readable(condition: TaintCondition | None) -> str:
    """Format condition as human-readable text."""
    if condition is None:
        return 'UNCONDITIONAL (always applies)'

    if condition.condition_ops is None or len(condition.condition_ops) == 0:
        return 'UNCONDITIONAL (no conditions)'

    if condition.condition_type == LogicType.DNF:
        clauses = []
        for bitmask, value in condition.condition_ops:
            # Ensure bitmask and value are integers (may be floats from JSON)
            bitmask_int = int(bitmask)
            value_int = int(value)
            bit_positions = sorted(check_ones(bitmask_int))
            value_bits = check_ones(value_int)

            bit_desc = []
            for bit_pos in bit_positions:  # Show all bits
                if bit_pos in value_bits:
                    bit_desc.append(f'bit[{bit_pos}]=1')
                else:
                    bit_desc.append(f'bit[{bit_pos}]=0')

            clause = '(' + ' AND '.join(bit_desc) + ')'
            clauses.append(clause)

        # Show all clauses
        return 'DNF: ' + ' OR '.join(clauses)

    return f'{condition.condition_type.name}: {len(condition.condition_ops)} conditions'


def generate_test_cases(rule: TaintRule) -> list[dict[str, Any]]:
    """Generate concrete test cases for each condition-dataflow pair."""
    test_cases = []

    for idx, pair in enumerate(rule.pairs):
        if pair.condition is None:
            # Unconditional - use zero state
            test_case = {
                'pair_index': idx,
                'description': 'Unconditional case',
                'input_state': 0,
                'input_state_hex': '0x0',
                'condition_matches': True,
            }
            test_cases.append(test_case)
        else:
            # Generate a state that satisfies this condition
            if pair.condition.condition_ops:
                # Take first clause of DNF
                bitmask, value = next(iter(pair.condition.condition_ops))
                test_input = int(value)  # Set bits according to value

                test_case = {
                    'pair_index': idx,
                    'description': f'Satisfies condition {idx}',
                    'input_state': test_input,
                    'input_state_hex': hex(test_input),
                    'input_state_bin': bin(test_input),
                    'condition_matches': True,
                    'bitmask': hex(int(bitmask)),
                    'expected_value': hex(int(value)),
                }
                test_cases.append(test_case)

    return test_cases


@app.route('/')
def index():
    """Serve the main HTML page."""
    return send_file(SCRIPT_DIR / 'static' / 'index.html')


def bitpos_to_reg_bit(bitpos: int, registers: list[Register]) -> dict['str', object]:
    """Convert integer bit position to {type: 'reg', name: 'EFLAGS', bit: 0}."""
    remaining_pos = bitpos
    for reg in registers:
        if remaining_pos < reg.bits:
            return {'type': 'reg', 'name': reg.name, 'bit': remaining_pos}
        remaining_pos -= reg.bits
    # If we got here, it's out of bounds - return unknown
    return {'type': 'unknown', 'bitpos': bitpos}


@app.route('/api/rule')
def get_rule_data():
    """API endpoint to get rule data."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    # Build pairs data
    pairs_data = []
    for idx, pair in enumerate(current_rule.pairs):
        # Get ALL flows (no truncation)
        sample_flows = []
        dataflow_list = []

        if isinstance(pair.output_bits, dict):
            for input_bit, output_bits in pair.output_bits.items():
                # Convert input bit position to register name
                in_info = bitpos_to_reg_bit(input_bit, current_rule.format.registers)
                input_label = (
                    f"{in_info['name']}[{in_info['bit']}]" if in_info['type'] == 'reg' else f'bit[{input_bit}]'
                )

                # Convert output bit positions to register names
                output_labels = []
                for out_bit in sorted(output_bits):
                    out_info = bitpos_to_reg_bit(out_bit, current_rule.format.registers)
                    out_label = (
                        f"{out_info['name']}[{out_info['bit']}]" if out_info['type'] == 'reg' else f'bit[{out_bit}]'
                    )
                    output_labels.append(out_label)

                outputs_str = ', '.join(output_labels)
                sample_flows.append(
                    {
                        'input': input_label,
                        'outputs': outputs_str,
                    },
                )

            # Also prepare structured dataflow for graph
            # BitPosition is just an integer offset - need to map to register+bit
            for input_bit_pos, output_bits in pair.output_bits.items():
                for out_bit_pos in output_bits:
                    # Convert integer BitPosition to (register, bit) using format
                    out_info = bitpos_to_reg_bit(out_bit_pos, current_rule.format.registers)
                    in_info = bitpos_to_reg_bit(input_bit_pos, current_rule.format.registers)

                    dataflow_list.append(
                        {
                            'output_bit': out_info,
                            'input_bits': [in_info],
                            'condition': format_condition_human_readable(pair.condition),
                            'is_unconditional': pair.condition is None,
                            'pair_index': idx,
                        },
                    )

            num_dataflows = len(pair.output_bits)
            total_propagations = sum(len(outputs) for outputs in pair.output_bits.values())
        else:
            num_dataflows = 0
            total_propagations = 0

        pairs_data.append(
            {
                'index': idx,
                'condition_text': format_condition_human_readable(pair.condition),
                'condition_readable': format_condition_human_readable(pair.condition),
                'is_unconditional': pair.condition is None,
                'num_dataflows': num_dataflows,
                'total_propagations': total_propagations,
                'sample_flows': sample_flows,
                'dataflow': dataflow_list,
            },
        )

    return jsonify(
        {
            'filename': rule_file_path,
            'format': {
                'arch': current_rule.format.arch,
                'registers': [{'name': reg.name, 'bits': reg.bits} for reg in current_rule.format.registers],
                'mem_slots': len(current_rule.format.mem_slots),
            },
            'num_pairs': len(current_rule.pairs),
            'pairs': pairs_data,
        },
    )


@app.route('/api/simulate', methods=['POST'])
def simulate():
    """API endpoint to simulate taint propagation for a given input state."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    try:
        data = request.json
        input_str = data.get('input_state', '0')

        # Parse input (support hex or decimal)
        if input_str.startswith('0x') or input_str.startswith('0X'):
            input_state = int(input_str, 16)
        else:
            input_state = int(input_str)

        # Find matching pairs
        matching_pairs = get_matching_pairs(current_rule, input_state)

        # Format results
        results = []
        for match in matching_pairs:
            pair = current_rule.pairs[match['pair_index']]

            # Get sample flows
            sample_flows = []
            if isinstance(pair.output_bits, dict):
                for input_bit, output_bits in list(pair.output_bits.items())[:5]:
                    outputs_str = ', '.join(map(str, sorted(output_bits)[:10]))
                    if len(output_bits) > 10:
                        outputs_str += f', ... +{len(output_bits) - 10} more'
                    sample_flows.append(
                        {
                            'input': input_bit,
                            'outputs': outputs_str,
                        },
                    )
                num_flows = len(pair.output_bits)
            else:
                num_flows = 0

            results.append(
                {
                    'pair_index': match['pair_index'],
                    'condition_text': format_condition_human_readable(match['condition']),
                    'is_unconditional': match['is_unconditional'],
                    'sample_flows': sample_flows,
                    'num_flows': num_flows,
                },
            )

        return jsonify(
            {
                'input_state': input_state,
                'input_state_hex': hex(input_state),
                'input_state_bin': bin(input_state),
                'matching_pairs': results,
            },
        )

    except ValueError as e:
        return jsonify({'error': f'Invalid input: {e}'}), 400


@app.route('/api/test-cases')
def get_test_cases():
    """API endpoint to get generated test cases."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    test_cases = generate_test_cases(current_rule)
    return jsonify({'test_cases': test_cases})


@app.route('/api/upload-rule', methods=['POST'])
def upload_rule():
    """API endpoint to upload and deserialize a rule JSON file."""
    global current_rule, rule_file_path

    try:
        # Get the JSON data from the request
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        # Deserialize using TaintInduceDecoder
        rule = json.loads(json.dumps(data), cls=TaintInduceDecoder)

        if not isinstance(rule, TaintRule):
            return jsonify({'error': 'Uploaded data is not a valid TaintRule'}), 400

        # Update global rule
        current_rule = rule
        rule_file_path = '<uploaded>'

        # Return success - frontend will call /api/rule to get formatted data
        return jsonify(
            {
                'success': True,
                'message': 'Rule uploaded successfully',
                'num_pairs': len(rule.pairs),
                'arch': rule.format.arch,
            },
        )

    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e!s}'}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to deserialize rule: {e!s}'}), 400


@app.route('/api/simulate-detailed', methods=['POST'])
def simulate_detailed():
    """API endpoint for detailed bit-level taint simulation.

    Request body:
    {
        "register_values": {"EFLAGS": {"0": 1, "6": 0}, "EAX": {"0": 1}},
        "tainted_bits": [["EFLAGS", 0], ["EAX", 15]],
        "hex_value": "0x1234" (optional - alternative to register_values)
    }

    Returns detailed taint propagation results showing which output bits are tainted.
    """
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    try:
        data = request.json

        # Build input state
        if data.get('hex_value'):
            # Parse hex value
            hex_val = data['hex_value']
            if isinstance(hex_val, str):
                if hex_val.startswith(('0x', '0X')):
                    input_state = int(hex_val, 16)
                else:
                    input_state = int(hex_val)
            else:
                input_state = int(hex_val)

            # Extract register values from state
            register_values = extract_bits_from_state(input_state, current_rule.format)
        else:
            # Build from register_values
            register_values = data.get('register_values', {})
            # Convert string keys to ints where needed
            cleaned_reg_vals = {}
            for reg_name, bit_dict in register_values.items():
                cleaned_reg_vals[reg_name] = {int(k) if isinstance(k, str) else k: int(v) for k, v in bit_dict.items()}
            register_values = cleaned_reg_vals
            input_state = build_state_from_bits(register_values, current_rule.format)

        # Parse tainted bits
        tainted_bits_list = data.get('tainted_bits', [])
        tainted_bits = {(reg, int(bit)) for reg, bit in tainted_bits_list}

        # Run simulation
        result = simulate_taint_propagation(current_rule, input_state, tainted_bits)

        # Add formatted register values to response
        result['register_values'] = register_values
        result['input_state_hex'] = hex(input_state)
        result['input_state_bin'] = bin(input_state)

        # Add flag information for tainted bits
        tainted_with_flags = []
        for reg_name, bit_idx in result['tainted_outputs']:
            flag_info = get_flag_info(reg_name, bit_idx)
            entry = {
                'register': reg_name,
                'bit': bit_idx,
                'flag_name': flag_info['name'] if flag_info else None,
                'flag_desc': flag_info['desc'] if flag_info else None,
            }
            tainted_with_flags.append(entry)

        result['tainted_outputs_detailed'] = tainted_with_flags

        return jsonify(result)

    except ValueError as e:
        return jsonify({'error': f'Invalid input: {e!s}'}), 400
    except Exception as e:
        return jsonify({'error': f'Simulation failed: {e!s}'}), 500


def main():
    global current_rule, rule_file_path

    if len(sys.argv) < 2:
        print('Usage: python taint_visualizer.py <rule_file.json>')
        print('\nExample:')
        print('  python taint_visualizer.py output/0402_X86_rule.json')
        sys.exit(1)

    rule_file = sys.argv[1]
    if not Path(rule_file).exists():
        print(f'Error: File not found: {rule_file}')
        sys.exit(1)

    # Load the rule
    print(f'Loading rule from {rule_file}...')
    with open(rule_file) as f:
        rule = json.load(f, cls=TaintInduceDecoder)

    if not isinstance(rule, TaintRule):
        print('Error: Loaded object is not a TaintRule')
        sys.exit(1)

    current_rule = rule
    rule_file_path = rule_file

    print(f'✅ Loaded rule: {rule}')
    print(f'   Architecture: {rule.format.arch}')
    print(f'   Pairs: {len(rule.pairs)}')
    print()
    print('🚀 Starting Flask server...')
    print('📊 Open http://localhost:5000 in your browser')
    print()

    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()
