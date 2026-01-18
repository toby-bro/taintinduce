"""Taint simulation engine for interactive visualizer.

This module provides detailed taint propagation simulation with bit-level granularity.
Reuses core TaintInduce logic for condition evaluation and dataflow application.
"""

from typing import Any

from taintinduce.rules.conditions import LogicType, TaintCondition
from taintinduce.rules.rules import TaintRule, TaintRuleFormat


def evaluate_condition(condition: TaintCondition | None, state_value: int) -> bool:
    """Evaluate a condition against a specific state value.

    Args:
        condition: TaintCondition to evaluate (None means unconditional)
        state_value: Integer representing the input state

    Returns:
        True if condition matches, False otherwise
    """
    if condition is None:
        return True  # Unconditional always matches

    if condition.condition_ops is None or len(condition.condition_ops) == 0:
        return True

    if condition.condition_type == LogicType.DNF:
        # DNF: OR of ANDs - any clause can be true
        for bitmask, value in condition.condition_ops:
            bitmask_int = int(bitmask)
            value_int = int(value)
            if (state_value & bitmask_int) == value_int:
                return True
        return False

    return False


def build_state_from_bits(
    register_values: dict[str, dict[int, int]],
    format: TaintRuleFormat,
) -> int:
    """Build integer state value from register bit values.

    Args:
        register_values: Dict mapping register name to dict of bit_index: value (0 or 1)
        format: TaintRuleFormat describing register layout

    Returns:
        Integer state value
    """
    state = 0
    bit_offset = 0

    for reg in format.registers:
        reg_bits = register_values.get(reg.name, {})
        for bit_idx in range(reg.bits):
            if reg_bits.get(bit_idx, 0) == 1:
                state |= 1 << (bit_offset + bit_idx)
        bit_offset += reg.bits

    # Handle memory slots if present
    for mem_idx, mem_slot in enumerate(format.mem_slots):
        mem_key = f'MEM{mem_idx}'
        mem_bits = register_values.get(mem_key, {})
        for bit_idx in range(mem_slot.size):
            if mem_bits.get(bit_idx, 0) == 1:
                state |= 1 << (bit_offset + bit_idx)
        bit_offset += mem_slot.size

    return state


def extract_bits_from_state(
    state: int,
    format: TaintRuleFormat,
) -> dict[str, dict[int, int]]:
    """Extract bit values from integer state.

    Args:
        state: Integer state value
        format: TaintRuleFormat describing register layout

    Returns:
        Dict mapping register name to dict of bit_index: value (0 or 1)
    """
    result = {}
    bit_offset = 0

    for reg in format.registers:
        reg_bits = {}
        for bit_idx in range(reg.bits):
            bit_value = (state >> (bit_offset + bit_idx)) & 1
            reg_bits[bit_idx] = bit_value
        result[reg.name] = reg_bits
        bit_offset += reg.bits

    # Handle memory slots
    for mem_idx, mem_slot in enumerate(format.mem_slots):
        mem_bits = {}
        for bit_idx in range(mem_slot.size):
            bit_value = (state >> (bit_offset + bit_idx)) & 1
            mem_bits[bit_idx] = bit_value
        result[f'MEM{mem_idx}'] = mem_bits
        bit_offset += mem_slot.size

    return result


def simulate_taint_propagation(
    rule: TaintRule,
    input_state: int,
    tainted_bits: set[tuple[str, int]],  # Set of (register_name, bit_index) tuples
) -> dict[str, Any]:
    """Simulate taint propagation for given input state and tainted input bits.

    Args:
        rule: TaintRule to apply
        input_state: Integer representing input state
        tainted_bits: Set of (register_name, bit_index) tuples marking which input bits are tainted

    Returns:
        Dict containing:
            - matching_pairs: List of matching condition-dataflow pairs
            - tainted_outputs: Set of (register_name, bit_index) tuples for tainted output bits
            - dataflows: List of all active dataflows showing taint propagation paths
    """
    # Find matching pairs
    matching_pairs = []
    all_dataflows = []
    tainted_outputs = set()

    # Convert tainted_bits to global bit positions
    tainted_positions = set()
    bit_offset = 0
    for reg in rule.format.registers:
        for bit_idx in range(reg.bits):
            if (reg.name, bit_idx) in tainted_bits:
                tainted_positions.add(bit_offset + bit_idx)
        bit_offset += reg.bits

    # Handle memory slots
    for mem_idx, mem_slot in enumerate(rule.format.mem_slots):
        for bit_idx in range(mem_slot.size):
            if (f'MEM{mem_idx}', bit_idx) in tainted_bits:
                tainted_positions.add(bit_offset + bit_idx)
        bit_offset += mem_slot.size

    # Evaluate each pair
    for pair_idx, pair in enumerate(rule.pairs):
        if evaluate_condition(pair.condition, input_state):
            matching_pairs.append(pair_idx)

            # Apply dataflow for this pair
            if isinstance(pair.output_bits, dict):
                for input_bit_pos, output_bit_positions in pair.output_bits.items():
                    # Check if this input bit is tainted
                    if input_bit_pos in tainted_positions:
                        # Taint propagates to all output bits
                        for output_bit_pos in output_bit_positions:
                            # Convert output bit position to (register, bit) tuple
                            reg_name, bit_idx = _global_bit_to_reg_bit(
                                output_bit_pos,
                                rule.format,
                            )
                            tainted_outputs.add((reg_name, bit_idx))

                            # Record dataflow
                            input_reg, input_bit = _global_bit_to_reg_bit(
                                input_bit_pos,
                                rule.format,
                            )
                            all_dataflows.append(
                                {
                                    'input_register': input_reg,
                                    'input_bit': input_bit,
                                    'output_register': reg_name,
                                    'output_bit': bit_idx,
                                    'pair_index': pair_idx,
                                },
                            )

    return {
        'matching_pairs': matching_pairs,
        'tainted_outputs': list(tainted_outputs),
        'dataflows': all_dataflows,
        'num_tainted_inputs': len(tainted_bits),
        'num_tainted_outputs': len(tainted_outputs),
    }


def _global_bit_to_reg_bit(
    bit_pos: int,
    format: TaintRuleFormat,
) -> tuple[str, int]:
    """Convert global bit position to (register_name, bit_index) tuple.

    Args:
        bit_pos: Global bit position
        format: TaintRuleFormat describing layout

    Returns:
        Tuple of (register_name, bit_index)
    """
    offset = 0

    # Check registers
    for reg in format.registers:
        if bit_pos < offset + reg.bits:
            return (reg.name, bit_pos - offset)
        offset += reg.bits

    # Check memory slots
    for mem_idx, mem_slot in enumerate(format.mem_slots):
        if bit_pos < offset + mem_slot.size:
            return (f'MEM{mem_idx}', bit_pos - offset)
        offset += mem_slot.size

    # Fallback
    return ('UNKNOWN', bit_pos)


def get_flag_info(register_name: str, bit_index: int) -> dict[str, str] | None:
    """Get flag information for a specific bit in a register.

    Args:
        register_name: Name of the register (e.g., 'EFLAGS')
        bit_index: Bit index within the register

    Returns:
        Dict with 'name' and 'description' if this is a known flag, None otherwise
    """
    flag_defs = {
        'EFLAGS': {
            0: {'name': 'CF', 'desc': 'Carry Flag'},
            2: {'name': 'PF', 'desc': 'Parity Flag'},
            4: {'name': 'AF', 'desc': 'Auxiliary Carry Flag'},
            6: {'name': 'ZF', 'desc': 'Zero Flag'},
            7: {'name': 'SF', 'desc': 'Sign Flag'},
            8: {'name': 'TF', 'desc': 'Trap Flag'},
            9: {'name': 'IF', 'desc': 'Interrupt Enable Flag'},
            10: {'name': 'DF', 'desc': 'Direction Flag'},
            11: {'name': 'OF', 'desc': 'Overflow Flag'},
        },
        'RFLAGS': {
            0: {'name': 'CF', 'desc': 'Carry Flag'},
            2: {'name': 'PF', 'desc': 'Parity Flag'},
            4: {'name': 'AF', 'desc': 'Auxiliary Carry Flag'},
            6: {'name': 'ZF', 'desc': 'Zero Flag'},
            7: {'name': 'SF', 'desc': 'Sign Flag'},
            8: {'name': 'TF', 'desc': 'Trap Flag'},
            9: {'name': 'IF', 'desc': 'Interrupt Enable Flag'},
            10: {'name': 'DF', 'desc': 'Direction Flag'},
            11: {'name': 'OF', 'desc': 'Overflow Flag'},
        },
        'CPSR': {
            31: {'name': 'N', 'desc': 'Negative'},
            30: {'name': 'Z', 'desc': 'Zero'},
            29: {'name': 'C', 'desc': 'Carry'},
            28: {'name': 'V', 'desc': 'Overflow'},
            27: {'name': 'Q', 'desc': 'Saturation'},
        },
        'APSR': {
            31: {'name': 'N', 'desc': 'Negative'},
            30: {'name': 'Z', 'desc': 'Zero'},
            29: {'name': 'C', 'desc': 'Carry'},
            28: {'name': 'V', 'desc': 'Overflow'},
            27: {'name': 'Q', 'desc': 'Saturation'},
        },
        'NZCV': {
            31: {'name': 'N', 'desc': 'Negative'},
            30: {'name': 'Z', 'desc': 'Zero'},
            29: {'name': 'C', 'desc': 'Carry'},
            28: {'name': 'V', 'desc': 'Overflow'},
        },
    }

    if register_name in flag_defs and bit_index in flag_defs[register_name]:
        return flag_defs[register_name][bit_index]

    return None
