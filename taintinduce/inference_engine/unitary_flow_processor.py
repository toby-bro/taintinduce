"""Processing functions for unitary dataflows (single input bit -> single output bit).

This module handles the splitting and grouping of dataflows into unitary flows
to enable per-output-bit condition generation without cross-contamination.
"""

from collections import defaultdict

from taintinduce.state.state import State
from taintinduce.types import BitPosition, Dataflow, ObservationDependency, StateValue, UnitaryFlow


def extract_unitary_flows(dataflow: Dataflow) -> set[UnitaryFlow]:
    """Split a dataflow into individual UnitaryFlow objects.

    Args:
        dataflow: A Dataflow mapping input bits to sets of output bits

    Returns:
        Set of UnitaryFlow objects, each representing one input bit -> one output bit
    """
    unitary_flows: set[UnitaryFlow] = set()
    for input_bit, output_bits in dataflow.items():
        for output_bit in output_bits:
            unitary_flows.add(UnitaryFlow(input_bit=input_bit, output_bit=output_bit))
    return unitary_flows


def group_unitary_flows_by_output(
    observation_dependencies: list[ObservationDependency],
) -> dict[BitPosition, frozenset[BitPosition]]:
    """Group all input bits that affect each output bit across all observations.

    Args:
        observation_dependencies: List of observation dependencies

    Returns:
        Dictionary mapping output_bit -> set of input bits that affect it
    """
    output_to_inputs: defaultdict[BitPosition, set[BitPosition]] = defaultdict(set)

    for obs_dep in observation_dependencies:
        unitary_flows = extract_unitary_flows(obs_dep.dataflow)
        for flow in unitary_flows:
            output_to_inputs[flow.output_bit].add(flow.input_bit)

    return {k: frozenset(v) for k, v in output_to_inputs.items()}


def collect_states_for_unitary_flow(
    observation_dependencies: list[ObservationDependency],
    input_bit: BitPosition,
    output_bit: BitPosition,
) -> tuple[set[tuple[State, State]], set[tuple[State, State]]]:
    """Collect states that trigger/don't trigger propagation for a unitary flow.

    This function analyzes observations to determine which input states cause propagation:
    - For each observation where input_bit was flipped
    - If output_bit changed as a result → propagating state
    - If output_bit did NOT change → non-propagating state

    Args:
        observation_dependencies: List of observation dependencies
        input_bit: The input bit position
        output_bit: The output bit position

    Returns:
        Tuple of (propagating_states, non_propagating_states)
        - propagating_states: Set of (input_state, output_state) tuples where mutating input_bit affects output_bit
        - non_propagating_states: Set of (input_state, output_state) tuples where mutating input_bit doesn't affect output_bit
    """  # noqa: E501
    propagating_states: set[tuple[State, State]] = set()
    non_propagating_states: set[tuple[State, State]] = set()

    for obs_dep in observation_dependencies:
        # Check if this observation has data for the input bit
        if input_bit not in obs_dep.dataflow.inputs():
            continue

        # Get the mutated input state for this input bit
        if input_bit not in obs_dep.mutated_states.mutated_bits():
            continue

        mutated_input_state = obs_dep.mutated_states.get_input_state(input_bit)
        mutated_output_state = obs_dep.mutated_states.get_output_state(input_bit)

        # Check if this input bit affects the output bit in this observation
        # obs_dep.dataflow[input_bit] contains the set of output bits that CHANGED
        # when we flipped input_bit in the state mutated_input_state
        affected_outputs = obs_dep.dataflow[input_bit]

        if output_bit in affected_outputs:
            # Flipping input_bit caused output_bit to change → propagating
            propagating_states.add((mutated_input_state, mutated_output_state))
        else:
            # Flipping input_bit did NOT cause output_bit to change → non-propagating
            non_propagating_states.add((mutated_input_state, mutated_output_state))

    return propagating_states, non_propagating_states


def extract_relevant_bits_from_state(
    state: State,
    relevant_bit_positions: frozenset[BitPosition],
) -> StateValue:
    """Extract only the relevant bits from a state and pack them densely.

    Args:
        state: The full state
        relevant_bit_positions: Set of bit positions to extract (in full state coordinates)

    Returns:
        A StateValue with only the relevant bits, packed from position 0
    """
    # Sort positions to ensure consistent ordering
    sorted_positions = sorted(relevant_bit_positions)

    # Extract and pack bits
    result = 0
    for new_position, old_position in enumerate(sorted_positions):
        if state.state_value & (1 << old_position):
            result |= 1 << new_position

    return StateValue(result)


def _transpose_input_bits(
    mask: int,
    value: int,
    sorted_input_positions: list[BitPosition],
) -> tuple[int, int]:
    """Transpose input bits from simplified to original positions."""
    new_mask = 0
    new_value = 0
    for simplified_pos in range(len(sorted_input_positions)):
        if not (mask & (1 << simplified_pos)):
            continue
        original_pos = sorted_input_positions[simplified_pos]
        new_mask |= 1 << original_pos
        if value & (1 << simplified_pos):
            new_value |= 1 << original_pos
    return new_mask, new_value


def _preserve_output_bits(
    mask: int,
    value: int,
    start_pos: int,
    num_bits: int,
) -> tuple[int, int]:
    """Preserve output bits in their simplified positions."""
    new_mask = 0
    new_value = 0
    for i in range(num_bits):
        simplified_pos = start_pos + i
        if not (mask & (1 << simplified_pos)):
            continue
        new_mask |= 1 << simplified_pos
        if value & (1 << simplified_pos):
            new_value |= 1 << simplified_pos
    return new_mask, new_value


def transpose_condition_bits(
    condition_ops: frozenset[tuple[int, int]],
    input_bit_positions: frozenset[BitPosition],
    sorted_output_positions: list[BitPosition],
) -> frozenset[tuple[int, int]]:
    """Transpose condition from simplified bit positions back to original positions.

    This function maps conditions from a simplified coordinate space back to the
    original bit positions. It handles:
    - Input bits: mapped back to original positions
    - Output taint bits: preserved in simplified positions for taint-by-induction
    - Output value bits: preserved in simplified positions for value-based conditions

    The simplified bit space is organized as:
    [input_bits | output_taint_bits | output_value_bits]

    Args:
        condition_ops: Condition in simplified coordinates as (mask, value) tuples
        input_bit_positions: The original input bit positions
        sorted_output_positions: The output bit positions for taint-by-induction and values.
                                These are in the higher bit range of the simplified space.

    Returns:
        Condition transposed to original bit positions as (mask, value) tuples.
        Output taint and value bit positions are preserved in their higher bit range.
    """
    sorted_input_positions = sorted(input_bit_positions)
    num_input_bits = len(sorted_input_positions)
    num_output_bits = len(sorted_output_positions)

    transposed_clauses: set[tuple[int, int]] = set()

    for mask, value in condition_ops:
        # Map input bits [0..num_input_bits-1] back to original positions
        new_mask, new_value = _transpose_input_bits(mask, value, sorted_input_positions)

        # Preserve output taint bits [num_input_bits..num_input_bits+num_output_bits-1]
        taint_mask, taint_value = _preserve_output_bits(mask, value, num_input_bits, num_output_bits)
        new_mask |= taint_mask
        new_value |= taint_value

        # Preserve output value bits [num_input_bits+num_output_bits..num_input_bits+2*num_output_bits-1]
        value_mask, value_value = _preserve_output_bits(mask, value, num_input_bits + num_output_bits, num_output_bits)
        new_mask |= value_mask
        new_value |= value_value

        transposed_clauses.add((new_mask, new_value))

    return frozenset(transposed_clauses)
