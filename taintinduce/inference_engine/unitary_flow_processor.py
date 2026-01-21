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
) -> tuple[set[State], set[State]]:
    """Collect states that trigger/don't trigger propagation for a unitary flow.

    Args:
        observation_dependencies: List of observation dependencies
        input_bit: The input bit position
        output_bit: The output bit position

    Returns:
        Tuple of (propagating_states, non_propagating_states)
        - propagating_states: States where mutating input_bit affects output_bit
        - non_propagating_states: States where mutating input_bit doesn't affect output_bit
    """
    propagating_states: set[State] = set()
    non_propagating_states: set[State] = set()

    for obs_dep in observation_dependencies:
        # Check if this observation has data for the input bit
        if input_bit not in obs_dep.dataflow:
            continue

        # Get the mutated input state for this input bit
        if input_bit not in obs_dep.mutated_inputs:
            continue

        mutated_input_state = obs_dep.mutated_inputs[input_bit]

        # Check if this input bit affects the output bit in this observation
        affected_outputs = obs_dep.dataflow[input_bit]

        if output_bit in affected_outputs:
            # This state causes propagation
            propagating_states.add(mutated_input_state)
        else:
            # This state blocks propagation
            non_propagating_states.add(mutated_input_state)

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


def transpose_condition_bits(
    condition_ops: frozenset[tuple[int, int]],
    input_bit_positions: frozenset[BitPosition],
    output_bit_positions: list[BitPosition] | None = None,
) -> frozenset[tuple[int, int]]:
    """Transpose condition from simplified bit positions back to original positions.

    This function maps conditions from a simplified coordinate space back to the
    original bit positions. It handles both input bits (which stay as regular
    bit positions) and output bits (which remain as-is since they're used for
    taint-by-induction evaluation).

    Args:
        condition_ops: Condition in simplified coordinates as (mask, value) tuples
        input_bit_positions: The original input bit positions
        output_bit_positions: The output bit positions (if any) for taint-by-induction.
                             These are in the higher bit range of the simplified space.

    Returns:
        Condition transposed to original bit positions as (mask, value) tuples.
        Output bit positions are preserved in their higher bit range.
    """
    # Sort input positions to get the mapping from simplified -> original
    sorted_input_positions = sorted(input_bit_positions)
    num_input_bits = len(sorted_input_positions)

    # Build output position mapping if provided
    sorted_output_positions = output_bit_positions if output_bit_positions else []

    transposed_clauses: set[tuple[int, int]] = set()

    for mask, value in condition_ops:
        # Build mask and value in original coordinates
        new_mask = 0
        new_value = 0

        # Map input bits [0..num_input_bits-1] back to original positions
        for simplified_pos in range(num_input_bits):
            if mask & (1 << simplified_pos):
                original_pos = sorted_input_positions[simplified_pos]
                new_mask |= 1 << original_pos
                if value & (1 << simplified_pos):
                    new_value |= 1 << original_pos

        # Map output bits [num_input_bits..num_input_bits+num_output_bits-1]
        # Keep them in the same relative positions (they're used for evaluation)
        for i, _output_pos in enumerate(sorted_output_positions):
            simplified_pos = num_input_bits + i
            if mask & (1 << simplified_pos):
                # Output bits stay in their simplified positions since they're
                # evaluated differently (via OutputBitRef in TaintCondition)
                new_mask |= 1 << simplified_pos
                if value & (1 << simplified_pos):
                    new_value |= 1 << simplified_pos

        transposed_clauses.add((new_mask, new_value))

    return frozenset(transposed_clauses)
