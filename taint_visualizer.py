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

from flask import Flask, Response, jsonify, request, send_file

from taintinduce.cpu.cpu import CPUFactory
from taintinduce.disassembler.compat import SquirrelDisassemblerZydis
from taintinduce.instrumentation.ast import LogicCircuit
from taintinduce.isa.register import Register
from taintinduce.mreplica.cell import Cell as MReplicaCell
from taintinduce.mreplica.mrepica import MReplica
from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.rules.rules import TaintRule
from taintinduce.serialization import TaintInduceDecoder
from taintinduce.state.state import State, check_ones
from taintinduce.types import CpuRegisterMap, StateValue

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
current_rule: TaintRule | LogicCircuit | None = None
rule_file_path: str = ''

# Global M-Replica storage
current_mreplica: MReplica | None = None


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


def get_matching_pairs(rule: TaintRule | LogicCircuit, input_state_value: int) -> list[dict['str', Any]]:
    """Find which condition-dataflow pairs match the given input state."""
    if isinstance(rule, LogicCircuit):
        # All logic circuit assignments are unconditionally applied
        return [
            {
                'pair_index': idx,
                'condition': None,
                'dataflow': assignment.target.name + ':' + str(assignment.target.bit_start),
                'is_unconditional': True,
            }
            for idx, assignment in enumerate(rule.assignments)
        ]

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


def generate_test_cases(rule: TaintRule | LogicCircuit) -> list[dict[str, Any]]:
    """Generate concrete test cases for each condition-dataflow pair."""
    test_cases: list[dict[str, Any]] = []

    if isinstance(rule, LogicCircuit):
        return test_cases

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
def index() -> Response:
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
def get_rule_data() -> Response | tuple[Response, int]:
    """API endpoint to get rule data."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    # print( for {_get_rule_format(current_rule).arch} with {len(current_rule.pairs)} pairs')

    ## Debug: Check if any pair has the problematic EAX[1]->EAX[1] flow
    # for idx, pair in enumerate(current_rule.pairs):
    #    if isinstance(pair.output_bits, dict):
    #        for input_bit, output_bits in pair.output_bits.items():
    #            in_info = bitpos_to_reg_bit(input_bit, _get_rule_format(current_rule).registers)
    #            for out_bit in output_bits:
    #                out_info = bitpos_to_reg_bit(out_bit, _get_rule_format(current_rule).registers)
    #                # Check for EAX[1] -> EAX[1]
    #                if (in_info.get('name') == 'EAX' and in_info.get('bit') == 1 and
    #                    out_info.get('name') == 'EAX' and out_info.get('bit') == 1):
    #                    print(f'   🔍 Found EAX[1]->EAX[1] in pair {idx}:')
    #                    print(f'      Condition object: {pair.condition}')
    #                    print(f'      Condition type: {type(pair.condition)}')
    #                    if pair.condition:
    #                        print(f'      Condition ops: {pair.condition.condition_ops}')
    #                        print(f'      Formatted: {format_condition_human_readable(pair.condition)[:200]}')

    if isinstance(current_rule, LogicCircuit):
        fmt = {
            'arch': _get_rule_format(current_rule).arch,
            'registers': [{'name': r.name, 'bits': r.bits} for r in _get_rule_format(current_rule).registers],
            'mem_slots': 0,
        }

        pairs_data_circuit = []
        for idx, assignment in enumerate(current_rule.assignments):
            target = assignment.target.name
            target_start = assignment.target.bit_start
            target_end = assignment.target.bit_end

            sample_flows_circuit = []
            dataflow_list_circuit = []

            out_info_circuit = {'type': 'reg', 'name': target, 'bit': f'{target_end}:{target_start}'}

            input_bits_circuit = []
            input_labels_circuit = []
            for dep in assignment.dependencies:
                input_bits_circuit.append({'type': 'reg', 'name': dep.name, 'bit': f'{dep.bit_end}:{dep.bit_start}'})
                input_labels_circuit.append(str(dep))

            if assignment.expression:
                input_label_circuit = str(assignment.expression)
            elif not input_labels_circuit:
                input_label_circuit = '0'
            else:
                input_label_circuit = ' | '.join(input_labels_circuit)

            sample_flows_circuit.append(
                {
                    'input': input_label_circuit,
                    'outputs': str(assignment.target),
                },
            )

            # Create bit-level mapping for graph
            target_size = target_end - target_start + 1
            for out_idx in range(target_size):
                out_bit = target_start + out_idx
                out_info = {'type': 'reg', 'name': target, 'bit': out_bit}
                in_bits = []
                for dep in assignment.dependencies:
                    dep_size = dep.bit_end - dep.bit_start + 1
                    if dep_size == target_size:
                        # bitwise mapping
                        in_bits.append({'type': 'reg', 'name': dep.name, 'bit': dep.bit_start + out_idx})
                    else:
                        # broadcast
                        for in_bit in range(dep.bit_start, dep.bit_end + 1):
                            in_bits.append({'type': 'reg', 'name': dep.name, 'bit': in_bit})

                dataflow_list_circuit.append(
                    {
                        'output_bit': out_info,
                        'input_bits': in_bits,
                        'condition': 'UNCONDITIONAL',
                        'is_unconditional': True,
                        'pair_index': idx,
                    },
                )

            pairs_data_circuit.append(
                {
                    'index': idx,
                    'condition_text': 'UNCONDITIONAL',
                    'condition_readable': str(assignment),
                    'is_unconditional': True,
                    'num_dataflows': 1,
                    'sample_flows': sample_flows_circuit,
                    'dataflow': dataflow_list_circuit,
                },
            )

        return jsonify(
            {
                'filename': rule_file_path,
                'is_logic_circuit': True,
                'instruction': {
                    'bytestring': getattr(current_rule, 'instruction', '') or getattr(current_rule, 'bytestring', ''),
                    'asm': get_instruction_text(
                        _get_rule_format(current_rule).arch,
                        getattr(current_rule, 'instruction', '') or getattr(current_rule, 'bytestring', ''),
                    ),
                    'arch': _get_rule_format(current_rule).arch,
                },
                'format': fmt,
                'num_pairs': len(current_rule.assignments),
                'pairs': pairs_data_circuit,
            },
        )

    # Build pairs data
    pairs_data = []
    for idx, pair in enumerate(current_rule.pairs):
        # Get ALL flows (no truncation)
        sample_flows: list[dict[str, str]] = []
        dataflow_list: list[dict[str, object]] = []

        # Convert input bit position to register name
        in_info = bitpos_to_reg_bit(pair.input_bit, _get_rule_format(current_rule).registers)
        input_label = f'{in_info["name"]}[{in_info["bit"]}]' if in_info['type'] == 'reg' else f'bit[{pair.input_bit}]'

        # Convert output bit position to register name (single output now)
        out_info = bitpos_to_reg_bit(pair.output_bit, _get_rule_format(current_rule).registers)
        out_label = f'{out_info["name"]}[{out_info["bit"]}]' if out_info['type'] == 'reg' else f'bit[{pair.output_bit}]'

        sample_flows.append(
            {
                'input': input_label,
                'outputs': out_label,
            },
        )

        # Also prepare structured dataflow for graph
        # BitPosition is just an integer offset - need to map to register+bit
        # Convert integer BitPosition to (register, bit) using format
        out_info = bitpos_to_reg_bit(pair.output_bit, _get_rule_format(current_rule).registers)
        in_info = bitpos_to_reg_bit(pair.input_bit, _get_rule_format(current_rule).registers)

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
                'bytestring': getattr(current_rule, 'bytestring', getattr(current_rule, 'instruction', '')),
                'asm': get_instruction_text(
                    _get_rule_format(current_rule).arch,
                    getattr(current_rule, 'bytestring', getattr(current_rule, 'instruction', '')),
                ),
                'arch': _get_rule_format(current_rule).arch,
            },
            'format': {
                'arch': _get_rule_format(current_rule).arch,
                'registers': [{'name': reg.name, 'bits': reg.bits} for reg in _get_rule_format(current_rule).registers],
                'mem_slots': len(_get_rule_format(current_rule).mem_slots),
            },
            'num_pairs': len(current_rule.pairs),
            'pairs': pairs_data,
        },
    )


@app.route('/api/taint', methods=['POST'])
def taint() -> Response | tuple[Response, int]:
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
def get_test_cases() -> Response | tuple[Response, int]:
    """API endpoint to get generated test cases."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400

    test_cases = generate_test_cases(current_rule)
    return jsonify({'test_cases': test_cases})


@app.route('/api/upload-rule', methods=['POST'])
def upload_rule() -> Response | tuple[Response, int]:
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

        if not isinstance(rule, (TaintRule, LogicCircuit)):
            return jsonify({'error': 'Uploaded data is not a valid TaintRule'}), 400

        # Update global rule
        current_rule = rule
        rule_file_path = '<uploaded>'

        # Return success - frontend will call /api/rule to get formatted data
        return jsonify(
            {
                'success': True,
                'message': 'Rule uploaded successfully',
                'num_pairs': len(rule.pairs) if isinstance(rule, TaintRule) else len(rule.assignments),
                'arch': _get_rule_format(rule).arch,
            },
        )

    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e!s}'}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to deserialize rule: {e!s}'}), 400


def _parse_input_state(data: dict[str, Any], rule: TaintRule | LogicCircuit) -> tuple[int, dict[str, dict[int, int]]]:
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
        register_values = extract_bits_from_state(input_state, _get_rule_format(rule))
    else:
        # Build from register_values
        register_values = data.get('register_values', {})
        # Convert string keys to ints where needed
        cleaned_reg_vals = {}
        for reg_name, bit_dict in register_values.items():
            cleaned_reg_vals[reg_name] = {int(k) if isinstance(k, str) else k: int(v) for k, v in bit_dict.items()}
        register_values = cleaned_reg_vals
        input_state = build_state_from_bits(register_values, _get_rule_format(rule))

    return input_state, register_values


def _build_cpu_state(register_values: dict[str, dict[int, int]], rule: TaintRule | LogicCircuit) -> CpuRegisterMap:
    """Build CPU state from register values."""
    input_cpu_state = CpuRegisterMap()
    for reg in _get_rule_format(rule).registers:
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
    # Extract all registers from the CPU state (not just those in _get_rule_format(rule))
    # This ensures we return values for all registers the CPU tracks
    for reg, reg_value in output_cpu_state.items():
        output_register_values[reg.name] = {}
        for bit_idx in range(reg.bits):
            output_register_values[reg.name][bit_idx] = (reg_value >> bit_idx) & 1
    return output_register_values


def _execute_instruction(
    register_values: dict[str, dict[int, int]],
    bytecode: bytes,
    rule: TaintRule | LogicCircuit,
) -> dict[str, dict[int, int]]:
    """Execute instruction and return output register values."""
    input_cpu_state = _build_cpu_state(register_values, rule)
    cpu = CPUFactory.create_cpu(_get_rule_format(rule).arch)
    cpu.set_cpu_state(input_cpu_state)
    _, output_cpu_state = cpu.execute(bytecode)
    return _extract_output_register_values(output_cpu_state)


def _get_output_register_values(
    register_values: dict[str, dict[int, int]],
    rule: TaintRule | LogicCircuit,
) -> dict[str, dict[int, int]]:
    """Get output register values by executing instruction."""
    output_register_values = register_values  # Default: output = input

    if getattr(rule, 'bytestring', getattr(rule, 'instruction', '')):
        try:
            # Pad hex string to even length (e.g., "6" -> "60")
            hex_str = getattr(rule, 'bytestring', getattr(rule, 'instruction', ''))
            if len(hex_str) % 2 == 1:
                hex_str = hex_str + '0'
            bytecode = bytes.fromhex(hex_str)
            output_register_values = _execute_instruction(register_values, bytecode, rule)
        except Exception as e:
            print(f'Warning: Failed to execute instruction: {e}')

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
def simulate_detailed() -> Response | tuple[Response, int]:
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
        output_register_values = _get_output_register_values(register_values, current_rule)

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


# ──────────────────────────────────────────────────────────────
# M-Replica API helpers
# ──────────────────────────────────────────────────────────────


class PseudoFormat:
    def __init__(self, obj: Any) -> None:
        self.arch = getattr(obj, 'architecture', '')

        self.registers = getattr(obj, 'state_format', None)
        if not self.registers:

            class DummyReg:
                def __init__(self, name: str, bits: int) -> None:
                    self.name = name
                    self.bits = bits

            regs = {}
            if hasattr(obj, 'assignments'):
                for a in obj.assignments:
                    for op in [a.target, *a.dependencies]:
                        if op.name not in regs:
                            regs[op.name] = DummyReg(op.name, 256)
            self.registers = list(regs.values())

        self.mem_slots: list[Any] = []


def _get_rule_format(rule_obj: Any) -> Any:
    if hasattr(rule_obj, 'format'):
        return rule_obj.format
    return PseudoFormat(rule_obj)


def _make_mreplica_if_needed() -> MReplica:
    """Return the current M-Replica, creating one from the loaded rule if needed."""
    global current_mreplica  # noqa: PLW0603
    if current_mreplica is None:
        if current_rule is None:
            raise ValueError('No rule loaded')
        current_mreplica = MReplica(
            hex_instruction=getattr(current_rule, 'bytestring', getattr(current_rule, 'instruction', '')),
            architecture=_get_rule_format(current_rule).arch,
            state_format=_get_rule_format(current_rule).registers,
        )
    return current_mreplica


def _total_bits() -> int:
    """Total number of state bits from the loaded rule."""
    if current_rule is None:
        raise ValueError('No rule loaded')
    return sum(reg.bits for reg in _get_rule_format(current_rule).registers)


def _reg_values_from_int(state_val: int) -> dict[str, dict[int, int]]:
    """Convert flat integer state value to per-register bit dicts."""
    if current_rule is None:
        raise ValueError('No rule loaded')
    return extract_bits_from_state(state_val, _get_rule_format(current_rule))


def _cells_as_json(replica: MReplica) -> list[dict[str, int]]:
    """Serialize cells to JSON-friendly list sorted by (mask, value)."""
    return sorted(
        [{'mask': c.mask, 'value': c.value} for c in replica.cells],
        key=lambda c: (c['mask'], c['value']),
    )


@app.route('/api/mreplica', methods=['GET'])
def get_mreplica_state() -> Response | tuple[Response, int]:
    """Return the current M-Replica cells and basic metadata."""
    if current_mreplica is None or not current_mreplica.cells:
        return jsonify({'cells': [], 'num_cells': 0})
    return jsonify(
        {
            'cells': _cells_as_json(current_mreplica),
            'num_cells': len(current_mreplica.cells),
            'hex_instruction': current_mreplica.hex_instruction,
            'architecture': str(current_mreplica.architecture),
        },
    )


@app.route('/api/mreplica/reset', methods=['POST'])
def reset_mreplica() -> Response | tuple[Response, int]:
    """Clear all cells from the M-Replica."""
    global current_mreplica  # noqa: PLW0603
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400
    current_mreplica = MReplica(
        hex_instruction=getattr(current_rule, 'bytestring', getattr(current_rule, 'instruction', '')),
        architecture=_get_rule_format(current_rule).arch,
        state_format=_get_rule_format(current_rule).registers,
    )
    return jsonify({'success': True, 'num_cells': 0})


@app.route('/api/mreplica/add-cell', methods=['POST'])
def add_mreplica_cell() -> Response | tuple[Response, int]:
    """Add a single cell (mask, value) to the M-Replica."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400
    data = request.json
    mask = int(data['mask'])
    value = int(data['value'])
    replica = _make_mreplica_if_needed()
    replica.new_cell(mask=mask, value=value)
    return jsonify({'success': True, 'num_cells': len(replica.cells)})


@app.route('/api/mreplica/delete-cell', methods=['POST'])
def delete_mreplica_cell() -> Response | tuple[Response, int]:
    """Remove a cell identified by (mask, value) from the M-Replica."""
    if current_mreplica is None:
        return jsonify({'error': 'No M-Replica'}), 400
    data = request.json
    mask = int(data['mask'])
    value = int(data['value'])
    cell_to_remove = MReplicaCell(
        value=value,
        mask=mask,
        hex_instruction=current_mreplica.hex_instruction,
        architecture=current_mreplica.architecture,
        state_format=current_mreplica.state_format,
    )
    current_mreplica.cells.discard(cell_to_remove)
    return jsonify({'success': True, 'num_cells': len(current_mreplica.cells)})


@app.route('/api/mreplica/make-full', methods=['POST'])
def make_full_mreplica_endpoint() -> Response | tuple[Response, int]:
    """Replace all cells with the full M-Replica for given bits_mask."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400
    data = request.json
    bits_mask = int(data['bits_mask'])
    try:
        n_bits = _total_bits()
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    bits_state = State(num_bits=n_bits, state_value=StateValue(bits_mask))
    replica = _make_mreplica_if_needed()
    replica.make_full_m_replica(bits_state)
    return jsonify({'success': True, 'num_cells': len(replica.cells)})


@app.route('/api/mreplica/simulate', methods=['POST'])
def simulate_mreplica_endpoint() -> Response | tuple[Response, int]:
    """Run M-Replica simulation + real instruction execution on an input state."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400
    replica = _make_mreplica_if_needed()
    data = request.json
    input_val = int(data.get('input_state', 0))
    try:
        n_bits = _total_bits()
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    input_state = State(num_bits=n_bits, state_value=StateValue(input_val))

    # Collect per-cell outputs
    cell_results: list[dict[str, Any]] = []
    all_output_vals: list[int] = []
    for cell in replica.cells:
        out = cell.get_output(input_state)
        all_output_vals.append(out.state_value)
        cell_results.append({'mask': cell.mask, 'value': cell.value, 'output': out.state_value})
    cell_results.sort(key=lambda c: (c['mask'], c['value']))

    # Mark cells whose output differs from at least one other cell
    for cr in cell_results:
        cr['contributes_to_taint'] = any(o != cr['output'] for o in all_output_vals)

    # Taint output via MReplica.simulate
    taint_state = replica.simulate(input_state)

    # Real instruction output
    register_values = _reg_values_from_int(input_val)
    real_output = _get_output_register_values(register_values, current_rule)

    return jsonify(
        {
            'taint_output': taint_state.state_value,
            'taint_output_hex': hex(taint_state.state_value),
            'cell_results': cell_results,
            'real_output': real_output,
            'num_bits': n_bits,
            'register_format': [
                {'name': reg.name, 'bits': reg.bits} for reg in _get_rule_format(current_rule).registers
            ],
        },
    )


@app.route('/api/mreplica/adapt', methods=['POST'])
def adapt_mreplica() -> Response | tuple[Response, int]:
    """Build full M-Replica from tainted bits (one active bit per tainted bit position)."""
    if current_rule is None:
        return jsonify({'error': 'No rule loaded'}), 400
    data = request.json
    # tainted_bits: list of [register_name, bit_index]
    tainted_bits_list: list[list[Any]] = data.get('tainted_bits', [])

    # Convert (reg, bit) pairs to a flat integer mask
    bits_mask = 0
    bit_offset = 0
    for reg in _get_rule_format(current_rule).registers:
        for bit_idx in range(reg.bits):
            if [reg.name, bit_idx] in tainted_bits_list or [reg.name, str(bit_idx)] in tainted_bits_list:
                bits_mask |= 1 << (bit_offset + bit_idx)
        bit_offset += reg.bits

    try:
        n_bits = _total_bits()
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    bits_state = State(num_bits=n_bits, state_value=StateValue(bits_mask))
    replica = _make_mreplica_if_needed()
    replica.make_full_m_replica(bits_state)
    return jsonify({'success': True, 'num_cells': len(replica.cells), 'bits_mask': bits_mask})


# ──────────────────────────────────────────────────────────────


def main() -> None:
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

    if not isinstance(rule, (TaintRule, LogicCircuit)):
        print('Error: Loaded object is not a TaintRule or LogicCircuit')
        sys.exit(1)

    current_rule = rule
    rule_file_path = rule_file

    print(f'✅ Loaded rule: {rule}')
    print(f'   Architecture: {_get_rule_format(rule).arch}')
    print(f'   Pairs: {len(getattr(rule, "pairs", getattr(rule, "assignments", [])))}')
    print()
    print('🚀 Starting Flask server...')
    print('📊 Open http://localhost:5000 in your browser')
    print()

    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)  # noqa: S104, S201


if __name__ == '__main__':
    main()
