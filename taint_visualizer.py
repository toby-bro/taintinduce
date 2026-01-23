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

from taintinduce.cpu.cpu import CPUFactory
from taintinduce.disassembler.compat import SquirrelDisassemblerZydis
from taintinduce.isa.register import Register
from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.rules.rules import TaintRule
from taintinduce.serialization import TaintInduceDecoder
from taintinduce.state.state import check_ones
from taintinduce.types import CpuRegisterMap

# Import visualizer helper modules
from taintinduce.visualizer.taint_simulator import (
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
                    'dataflow': pair.output_bit,
                    'is_unconditional': pair.condition is None,
                },
            )
    return matching_pairs


def _format_dnf_clauses(condition_ops: frozenset[tuple[int, int]]) -> str:
    """Format DNF clauses as human-readable text."""
    clauses = []
    for bitmask, value in condition_ops:
        bitmask_int = int(bitmask)
        value_int = int(value)
        bit_positions = sorted(check_ones(bitmask_int))

        bits_str = ', '.join(
            [f'bit[{pos}]={(value_int >> pos) & 1}' for pos in bit_positions],
        )
        if len(bit_positions) == 1:
            clauses.append(bits_str)
        else:
            clauses.append(f'({bits_str})')
    return ' OR '.join(clauses)


def _format_output_bit_refs(output_bit_refs: frozenset[OutputBitRef]) -> str:
    """Format output bit references as human-readable text."""
    output_refs = [f'output[{ref.output_bit}]' for ref in output_bit_refs]
    return ' AND '.join(output_refs)


def format_condition_human_readable(condition: TaintCondition | None) -> str:
    """Format condition as human-readable text."""
    if condition is None:
        return 'UNCONDITIONAL (always applies)'

    if condition.condition_ops is None or len(condition.condition_ops) == 0:
        if not hasattr(condition, 'output_bit_refs') or condition.output_bit_refs is None:
            return 'UNCONDITIONAL (no conditions)'

    parts = []

    # Add DNF clauses if present
    if condition.condition_type == LogicType.DNF and condition.condition_ops:
        parts.append(_format_dnf_clauses(condition.condition_ops))

    # Add output bit references if present
    if hasattr(condition, 'output_bit_refs') and condition.output_bit_refs:
        output_str = _format_output_bit_refs(condition.output_bit_refs)
        if parts:
            parts.append(f' AND ({output_str})')
        else:
            parts.append(output_str)

    return ''.join(parts) if parts else 'UNCONDITIONAL'


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


def get_instruction_text(arch: str, bytestring: str) -> str:
    """Disassemble instruction bytes to human-readable assembly."""
    try:
        dis = SquirrelDisassemblerZydis(arch)
        insn = dis.disassemble(bytestring)
        return f'{insn.mnemonic} {insn.op_str}'
    except Exception as e:
        return f'<disassembly failed: {e!s}>'


@app.route('/api/rule')
def get_rule_data():
    """API endpoint to get rule data."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    # print(f'📤 Backend: Building response for {current_rule.format.arch} with {len(current_rule.pairs)} pairs')

    ## Debug: Check if any pair has the problematic EAX[1]->EAX[1] flow
    # for idx, pair in enumerate(current_rule.pairs):
    #    if isinstance(pair.output_bits, dict):
    #        for input_bit, output_bits in pair.output_bits.items():
    #            in_info = bitpos_to_reg_bit(input_bit, current_rule.format.registers)
    #            for out_bit in output_bits:
    #                out_info = bitpos_to_reg_bit(out_bit, current_rule.format.registers)
    #                # Check for EAX[1] -> EAX[1]
    #                if (in_info.get('name') == 'EAX' and in_info.get('bit') == 1 and
    #                    out_info.get('name') == 'EAX' and out_info.get('bit') == 1):
    #                    print(f'   🔍 Found EAX[1]->EAX[1] in pair {idx}:')
    #                    print(f'      Condition object: {pair.condition}')
    #                    print(f'      Condition type: {type(pair.condition)}')
    #                    if pair.condition:
    #                        print(f'      Condition ops: {pair.condition.condition_ops}')
    #                        print(f'      Formatted: {format_condition_human_readable(pair.condition)[:200]}')

    # Build pairs data
    pairs_data = []
    for idx, pair in enumerate(current_rule.pairs):
        # Get ALL flows (no truncation)
        sample_flows: list[dict[str, str]] = []
        dataflow_list: list[dict[str, object]] = []

        # Convert input bit position to register name
        in_info = bitpos_to_reg_bit(pair.input_bit, current_rule.format.registers)
        input_label = f"{in_info['name']}[{in_info['bit']}]" if in_info['type'] == 'reg' else f'bit[{pair.input_bit}]'

        # Convert output bit position to register name (single output now)
        out_info = bitpos_to_reg_bit(pair.output_bit, current_rule.format.registers)
        out_label = f"{out_info['name']}[{out_info['bit']}]" if out_info['type'] == 'reg' else f'bit[{pair.output_bit}]'

        sample_flows.append(
            {
                'input': input_label,
                'outputs': out_label,
            },
        )

        # Also prepare structured dataflow for graph
        # BitPosition is just an integer offset - need to map to register+bit
        # Convert integer BitPosition to (register, bit) using format
        out_info = bitpos_to_reg_bit(pair.output_bit, current_rule.format.registers)
        in_info = bitpos_to_reg_bit(pair.input_bit, current_rule.format.registers)

        dataflow_list.append(
            {
                'output_bit': out_info,
                'input_bits': [in_info],
                'condition': format_condition_human_readable(pair.condition),
                'is_unconditional': pair.condition is None,
                'pair_index': idx,
            },
        )

        num_dataflows = 1  # Single output bit per pair now

        pairs_data.append(
            {
                'index': idx,
                'condition_text': format_condition_human_readable(pair.condition),
                'condition_readable': format_condition_human_readable(pair.condition),
                'is_unconditional': pair.condition is None,
                'num_dataflows': num_dataflows,
                'sample_flows': sample_flows,
                'dataflow': dataflow_list,
            },
        )

    return jsonify(
        {
            'filename': rule_file_path,
            'instruction': {
                'bytestring': current_rule.bytestring,
                'asm': get_instruction_text(current_rule.format.arch, current_rule.bytestring),
                'arch': current_rule.format.arch,
            },
            'format': {
                'arch': current_rule.format.arch,
                'registers': [{'name': reg.name, 'bits': reg.bits} for reg in current_rule.format.registers],
                'mem_slots': len(current_rule.format.mem_slots),
            },
            'num_pairs': len(current_rule.pairs),
            'pairs': pairs_data,
        },
    )


@app.route('/api/taint', methods=['POST'])
def taint():
    """API endpoint to simulate taint propagation for a given input state."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    try:
        data = request.json
        input_str = data.get('input_state', '0')

        # Parse input (support hex or decimal)
        if input_str.startswith(('0x', '0X')):
            input_state = int(input_str, 16)
        else:
            input_state = int(input_str)

        # Find matching pairs
        matching_pairs = get_matching_pairs(current_rule, input_state)

        # Format results
        results = []
        for match in matching_pairs:
            results.append(
                {
                    'pair_index': match['pair_index'],
                    'condition_text': format_condition_human_readable(match['condition']),
                    'is_unconditional': match['is_unconditional'],
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
    global current_rule, rule_file_path  # noqa: PLW0603

    try:
        # Get the raw JSON text from the request (not parsed by JavaScript)
        # This preserves large integer precision
        json_text = request.get_data(as_text=True)

        if not json_text:
            return jsonify({'error': 'No JSON data provided'}), 400

        # Deserialize using TaintInduceDecoder directly from JSON string
        decoder = TaintInduceDecoder()
        rule = decoder.decode(json_text)

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


def _parse_input_state(data: dict[str, Any], rule: TaintRule) -> tuple[int, dict[str, dict[int, int]]]:
    """Parse input state from request data.

    Returns:
        Tuple of (input_state, register_values)
    """
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
        register_values = extract_bits_from_state(input_state, rule.format)
    else:
        # Build from register_values
        register_values = data.get('register_values', {})
        # Convert string keys to ints where needed
        cleaned_reg_vals = {}
        for reg_name, bit_dict in register_values.items():
            cleaned_reg_vals[reg_name] = {int(k) if isinstance(k, str) else k: int(v) for k, v in bit_dict.items()}
        register_values = cleaned_reg_vals
        input_state = build_state_from_bits(register_values, rule.format)

    return input_state, register_values


def _build_cpu_state(register_values: dict[str, dict[int, int]], rule: TaintRule) -> CpuRegisterMap:
    """Build CPU state from register values."""
    input_cpu_state = CpuRegisterMap()
    for reg in rule.format.registers:
        reg_value = 0
        reg_bits = register_values.get(reg.name, {})
        for bit_idx in range(reg.bits):
            if reg_bits.get(bit_idx, 0) == 1:
                reg_value |= 1 << bit_idx
        input_cpu_state[reg] = reg_value
    return input_cpu_state


def _extract_output_register_values(output_cpu_state: CpuRegisterMap) -> dict[str, dict[int, int]]:
    """Extract output register values as bit dict."""
    output_register_values: dict[str, dict[int, int]] = {}
    # Extract all registers from the CPU state (not just those in rule.format)
    # This ensures we return values for all registers the CPU tracks
    for reg, reg_value in output_cpu_state.items():
        output_register_values[reg.name] = {}
        for bit_idx in range(reg.bits):
            output_register_values[reg.name][bit_idx] = (reg_value >> bit_idx) & 1
    return output_register_values


def _execute_instruction(
    register_values: dict[str, dict[int, int]],
    bytecode: bytes,
    rule: TaintRule,
) -> dict[str, dict[int, int]]:
    """Execute instruction and return output register values."""
    input_cpu_state = _build_cpu_state(register_values, rule)
    cpu = CPUFactory.create_cpu(rule.format.arch)
    cpu.set_cpu_state(input_cpu_state)
    _, output_cpu_state = cpu.execute(bytecode)
    return _extract_output_register_values(output_cpu_state)


def _get_output_register_values(
    register_values: dict[str, dict[int, int]],
    rule: TaintRule,
    rule_path: str,
) -> dict[str, dict[int, int]]:
    """Get output register values by executing instruction."""
    output_register_values = register_values  # Default: output = input

    if rule.bytestring:
        try:
            # Pad hex string to even length (e.g., "6" -> "60")
            hex_str = rule.bytestring
            if len(hex_str) % 2 == 1:
                hex_str = hex_str + '0'
            bytecode = bytes.fromhex(hex_str)
            output_register_values = _execute_instruction(register_values, bytecode, rule)
        except Exception:
            # If execution fails, try extracting from filename as fallback
            if rule_path and rule_path != '<uploaded>':
                try:
                    filename = Path(rule_path).stem
                    bytestring = filename.split('_')[0]
                    # Pad hex string to even length (e.g., "6" -> "60")
                    if len(bytestring) % 2 == 1:
                        bytestring = bytestring + '0'  # Append 0, not prepend
                    bytecode = bytes.fromhex(bytestring)
                    output_register_values = _execute_instruction(register_values, bytecode, rule)
                except Exception as e:
                    print(f'Warning: Failed to extract register values: {e}')

    return output_register_values


def _add_flag_information(result: dict[str, Any]) -> None:
    """Add flag information to tainted output bits in the result."""
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

        # Parse input state and register values
        input_state, register_values = _parse_input_state(data, current_rule)

        # Parse tainted bits
        tainted_bits_list = data.get('tainted_bits', [])
        tainted_bits = {(reg, int(bit)) for reg, bit in tainted_bits_list}

        # Execute the instruction to get output state
        output_register_values = _get_output_register_values(register_values, current_rule, rule_file_path)

        # Run taint simulation
        result = simulate_taint_propagation(current_rule, input_state, tainted_bits)

        # Add formatted register values to response
        result['register_values'] = register_values
        result['output_register_values'] = output_register_values
        result['input_state_hex'] = hex(input_state)
        result['input_state_bin'] = bin(input_state)

        # Add flag information for tainted bits
        _add_flag_information(result)

        return jsonify(result)

    except ValueError as e:
        return jsonify({'error': f'Invalid input: {e!s}'}), 400
    except Exception as e:
        return jsonify({'error': f'Simulation failed: {e!s}'}), 500


def main():
    global current_rule, rule_file_path  # noqa: PLW0603

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
    app.run(debug=True, host='0.0.0.0', port=5000)  # noqa: S104, S201


if __name__ == '__main__':
    main()
