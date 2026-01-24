"""Partition handling functions for dataflow inference."""

import logging

from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair
from taintinduce.state.state import State
from taintinduce.types import (
    BitPosition,
    ObservationDependency,
    StateValue,
)

from . import condition_generator, unitary_flow_processor

logger = logging.getLogger(__name__)
INCLUSION_THRESHOLD = 2  # Minimum count to exclude input bits covered by output refs


def _evaluate_dependencies(
    output_bit: BitPosition,
    state: State,
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    inputs_to_flows: dict[BitPosition, list[ConditionDataflowPair]],
    taint_cache: dict[BitPosition, int],
    visiting: set[BitPosition],
) -> None:
    """Recursively evaluate all output bit dependencies.

    Args:
        output_bit: The output bit whose dependencies to evaluate
        state: The input state
        output_to_inputs: Mapping from output bits to their input bits
        inputs_to_flows: Mapping from input bits to their flows
        taint_cache: Memoization cache
        visiting: Set for cycle detection
    """
    influencing_inputs = output_to_inputs.get(output_bit, frozenset())
    for input_bit in influencing_inputs:
        if input_bit not in inputs_to_flows:
            continue
        for pair in inputs_to_flows[input_bit]:
            if pair.output_bit != output_bit:
                continue
            if not (pair.condition and hasattr(pair.condition, 'output_bit_refs')):
                continue
            for ref in pair.condition.output_bit_refs:
                # Recursively evaluate dependency
                _evaluate_output_bit_recursive(
                    ref.output_bit,
                    state,
                    output_to_inputs,
                    inputs_to_flows,
                    taint_cache,
                    visiting,
                )


def _evaluate_output_bit_recursive(
    output_bit: BitPosition,
    state: State,
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    inputs_to_flows: dict[BitPosition, list[ConditionDataflowPair]],
    taint_cache: dict[BitPosition, int],
    visiting: set[BitPosition],
) -> int:
    """Recursively evaluate if an output bit is tainted, with memoization.

    Uses depth-first search to evaluate dependencies before evaluating the current bit.
    Detects circular dependencies via the visiting set.

    Args:
        output_bit: The output bit to evaluate
        state: The input state
        output_to_inputs: Mapping from output bits to their input bits
        inputs_to_flows: Mapping from input bits to their flows
        taint_cache: Memoization cache for already-evaluated bits
        visiting: Set of bits currently being evaluated (for cycle detection)

    Returns:
        1 if tainted, 0 if not tainted

    Raises:
        RuntimeError: If circular dependency is detected
    """
    # Check cache first
    if output_bit in taint_cache:
        return taint_cache[output_bit]

    # Detect circular dependency
    if output_bit in visiting:
        raise RuntimeError(f'Circular dependency detected involving output bit {output_bit}')

    visiting.add(output_bit)

    try:
        # First, recursively evaluate any output bits that this bit's conditions depend on
        _evaluate_dependencies(output_bit, state, output_to_inputs, inputs_to_flows, taint_cache, visiting)

        # Now build current output state from cache
        output_state_value = StateValue(0)
        for cached_bit, taint_value in taint_cache.items():
            if taint_value:
                output_state_value = StateValue(output_state_value | (1 << cached_bit))

        output_state = State(
            num_bits=max(output_bit + 1, state.num_bits),
            state_value=output_state_value,
        )

        # Evaluate this bit's taint state
        influencing_inputs = output_to_inputs.get(output_bit, frozenset())
        found_condition = is_output_tainted(
            state,
            output_state,
            inputs_to_flows,
            influencing_inputs,
            output_bit,
        )
        taint_value = 1 if found_condition else 0

        # Cache and return
        taint_cache[output_bit] = taint_value
        return taint_value

    finally:
        visiting.remove(output_bit)


def evaluate_output_bit_taint_states(
    state: State,
    output_bit_refs: frozenset[OutputBitRef],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    all_conditions: list[ConditionDataflowPair],
) -> dict[BitPosition, int]:
    """Evaluate output bit taint states for a given input state.

    For each output bit in output_bit_refs, determine if it would be tainted
    by evaluating its condition against the current input state. This implements
    "taint by induction" where previous output taint states become inputs to
    later conditions.

    Uses recursive DFS with memoization to efficiently evaluate only the needed
    output bits and their dependencies. The cache is per-state, so different
    input states get independent evaluations.

    Args:
        state: The current input state
        output_bit_refs: Output bits to evaluate
        output_to_inputs: Mapping from output bits to their input bits
        all_conditions: List of ConditionDataflowPair objects

    Returns:
        Dict mapping output bit position to taint state (1=tainted, 0=untainted)
    """
    if len(output_bit_refs) == 0:
        return {}

    # Build mapping from input bits to their flows
    inputs_to_flows: dict[BitPosition, list[ConditionDataflowPair]] = {}
    for pair in all_conditions:
        if pair.input_bit not in inputs_to_flows.keys():
            inputs_to_flows[pair.input_bit] = []
        inputs_to_flows[pair.input_bit].append(pair)

    # Use recursive DFS with memoization to evaluate each output bit
    # IMPORTANT: Cache is per-state - create fresh cache for each call
    taint_cache: dict[BitPosition, int] = {}
    visiting: set[BitPosition] = set()

    for output_ref in output_bit_refs:
        _evaluate_output_bit_recursive(
            output_ref.output_bit,
            state,
            output_to_inputs,
            inputs_to_flows,
            taint_cache,
            visiting,
        )

    # Return only the bits we were asked to evaluate
    return {ref.output_bit: taint_cache[ref.output_bit] for ref in output_bit_refs}


def is_output_tainted(
    state: State,
    output_state: State,
    inputs_to_flows: dict[BitPosition, list[ConditionDataflowPair]],
    influencing_inputs: frozenset[BitPosition],
    target_output_bit: BitPosition,
) -> bool:
    """Check if a target output bit is tainted given input and output states.

    Args:
        state: The input state
        output_state: The accumulated output state (for evaluating output_bit_refs)
        inputs_to_flows: Mapping from input bits to their condition-dataflow pairs
        influencing_inputs: Input bits that influence the target output bit
        target_output_bit: The output bit we're checking

    Returns:
        True if the target output bit should be tainted, False otherwise
    """
    for input_bit in influencing_inputs:
        if input_bit not in inputs_to_flows:
            continue

        for pair in inputs_to_flows[input_bit]:
            # Only consider flows that target our output bit
            if pair.output_bit != target_output_bit:
                continue

            condition = pair.condition

            if condition is None:
                # Unconditional flow - always tainted
                return True

            # Evaluate condition against current state and output state
            is_tainted = condition.eval(state, output_state)
            if is_tainted:
                return True

    return False


def augment_states_with_output_bit_taints(
    propagating_states: set[State],
    non_propagating_states: set[State],
    relevant_input_bits: frozenset[BitPosition],
    output_bit_refs: frozenset[OutputBitRef],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    all_conditions: list[ConditionDataflowPair],
) -> tuple[set[StateValue], set[StateValue], list[BitPosition]]:
    """Augment simplified states with output bit taint values.

    For taint by induction, we evaluate the taint state of referenced output bits
    and append them as additional bits to the state representation before
    condition generation.

    Args:
        propagating_states: States where input bit affects output bit
        non_propagating_states: States where input bit doesn't affect output bit
        relevant_input_bits: Input bit positions for the current flow
        output_bit_refs: Output bits to include in condition
        all_conditions: List of ConditionDataflowPair objects

    Returns:
        Tuple of (augmented_propagating, augmented_non_propagating, output_bit_list)
    """
    # Sort output bits for consistent ordering
    output_bit_list = sorted([ref.output_bit for ref in output_bit_refs])

    augmented_propagating: set[StateValue] = set()
    augmented_propagating = _augment_states(
        propagating_states,
        output_bit_refs,
        output_to_inputs,
        all_conditions,
        output_bit_list,
        relevant_input_bits,
    )

    augmented_non_propagating = _augment_states(
        non_propagating_states,
        output_bit_refs,
        output_to_inputs,
        all_conditions,
        output_bit_list,
        relevant_input_bits,
    )

    return augmented_propagating, augmented_non_propagating, output_bit_list


def _augment_states(
    states: set[State],
    output_bit_refs: frozenset[OutputBitRef],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    all_conditions: list[ConditionDataflowPair],
    output_bit_list: list[BitPosition],
    relevant_input_bits: frozenset[BitPosition],
) -> set[StateValue]:
    augmented_statevalues: set[StateValue] = set()
    for state in states:
        # Evaluate output bit taint states
        augmented_state = augment_state_with_taint(
            output_bit_refs,
            output_to_inputs,
            all_conditions,
            output_bit_list,
            relevant_input_bits,
            state,
        )
        augmented_statevalues.add(augmented_state)
    return augmented_statevalues


def augment_state_with_taint(
    output_bit_refs: frozenset[OutputBitRef],
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    all_conditions: list[ConditionDataflowPair],
    output_bit_list: list[BitPosition],
    relevant_input_bits: frozenset[BitPosition],
    state: State,
) -> StateValue:
    taint_states = evaluate_output_bit_taint_states(
        state,
        output_bit_refs,
        output_to_inputs,
        all_conditions,
    )
    # Extract simplified states and append taint values to state (higher bits)
    augmented_state = unitary_flow_processor.extract_relevant_bits_from_state(state, relevant_input_bits)

    for i, output_bit_pos in enumerate(output_bit_list):
        taint_value = taint_states[output_bit_pos]
        augmented_state = StateValue(augmented_state | (taint_value << (len(relevant_input_bits) + i)))
    return augmented_state


def get_non_redundant_inputs_and_relevant_output_refs(
    studied_output_bit: BitPosition,
    completed_outputs: frozenset[BitPosition],
    outputs_to_inputs: dict[BitPosition, frozenset[BitPosition]],
) -> tuple[frozenset[BitPosition], frozenset[OutputBitRef]]:
    """Filter input bits that are covered by output bit references.

    This function identifies input bits that are already covered by output bits
    from subset flows and returns a filtered set of input bits along with the
    corresponding output bit references.

    Args:
        studied_output_bit: The output bit currently being processed
        completed_outputs: Set of completed output bits
        outputs_to_inputs: Map from output bits to their input bits

    Returns:
        Tuple of (filtered_input_bits, output_bit_refs)
    """
    relevant_input_bits = outputs_to_inputs[studied_output_bit]
    _output_bit_refs: set[OutputBitRef] = set()

    for completed_output in completed_outputs:
        if outputs_to_inputs[completed_output] < relevant_input_bits and len(outputs_to_inputs[completed_output]) > 1:
            logger.debug(
                f'Output bit {completed_output} covers input bits {sorted(outputs_to_inputs[completed_output])} '
                f'which are a subset of those for studied output bit {studied_output_bit}',
            )
            _output_bit_refs.add(OutputBitRef(completed_output))

    output_bit_refs = frozenset(_output_bit_refs)

    relevant_inputs_counter: dict[BitPosition, int] = {}
    for output_ref in output_bit_refs:
        for input_bit in outputs_to_inputs[output_ref.output_bit]:
            relevant_inputs_counter[input_bit] = relevant_inputs_counter.get(input_bit, 0) + 1

    filtered_input_bits = frozenset(
        bit
        for bit in relevant_input_bits
        if bit not in relevant_inputs_counter or relevant_inputs_counter[bit] < INCLUSION_THRESHOLD
    )

    return filtered_input_bits, output_bit_refs


def handle_multiple_partitions_output_centric(
    mutated_input_bit: BitPosition,
    output_bit: BitPosition,
    output_to_inputs: dict[BitPosition, frozenset[BitPosition]],
    completed_outputs: frozenset[BitPosition],
    observation_dependencies: list[ObservationDependency],
    all_conditions: list[ConditionDataflowPair],
) -> ConditionDataflowPair:
    """Handle multiple partitions using output-bit-centric approach.

    This function generates conditions for each output bit independently,
    considering only the relevant input bits for that specific output bit.
    This prevents conditions on secondary effects (like flags) from contaminating
    primary effects (like R2 -> R1 propagation).

    Args:
        mutated_input_bit: The input bit we're analyzing
        observation_dependencies: All observation dependencies
        completed_flows: Maps input bit sets to their output bits for
            previously processed flows (both conditional and unconditional)
        all_conditions: Maps input bit sets to their TaintCondition for evaluating
            output bit taint states (taint by induction)
        process_only_output: If provided, only process this specific output bit

    Returns:
        List of ConditionDataflowPair objects
    """

    relevant_input_bits, output_bit_refs = get_non_redundant_inputs_and_relevant_output_refs(
        output_bit,
        completed_outputs,
        output_to_inputs,
    )

    relevant_input_bits -= frozenset([mutated_input_bit])
    if len(relevant_input_bits) == 0 and len(output_bit_refs) == 0:
        # No relevant bits left - unconditional flow
        logger.debug(
            f'Output bit {output_bit}: no relevant input bits or output refs left after exclusion; '
            f'treating as unconditional flow',
        )
        return ConditionDataflowPair(None, mutated_input_bit, output_bit)

    logger.debug(
        f'Output bit {output_bit}: relevant input bits after exclusion: '
        f'{sorted(relevant_input_bits)}, output refs: {output_bit_refs}',
    )

    propagating_states, non_propagating_states = unitary_flow_processor.collect_states_for_unitary_flow(
        observation_dependencies,
        mutated_input_bit,
        output_bit,
    )

    logger.debug(
        f'  Counts: propagating={len(propagating_states)}, non_propagating={len(non_propagating_states)}',
    )

    # If no variation in behavior, it's unconditional
    if len(propagating_states) == 0 or len(non_propagating_states) == 0:
        # Unconditional flow from mutated_input_bit to output_bit
        logger.debug(
            f'  Output bit {output_bit}: unconditional flow (propagating={len(propagating_states)}, '
            f'non_propagating={len(non_propagating_states)})',
        )
        return ConditionDataflowPair(None, mutated_input_bit, output_bit)

    # Create simplified states with FILTERED relevant input bits (after exclusion)
    # Use the filtered bits to prevent DNF explosion and incorrect conditions

    # Add output bit taint values for taint by induction
    # If we have output bit refs, augment states with their taint values
    num_output_bits = 0
    ordered_interesting_outputs: list[BitPosition] = []
    augmented_prop, augmented_non_prop, ordered_interesting_outputs = augment_states_with_output_bit_taints(
        propagating_states,
        non_propagating_states,
        relevant_input_bits,
        output_bit_refs,
        output_to_inputs,
        all_conditions,
    )
    simplified_propagating = augmented_prop
    simplified_non_propagating = augmented_non_prop
    num_output_bits = len(ordered_interesting_outputs)

    logger.debug(
        f'  Augmented states with {num_output_bits} output bit taint values: {ordered_interesting_outputs}',
    )

    # Generate condition on simplified bits (including output bit taint values)
    condition_gen = condition_generator.ConditionGenerator()

    try:
        # Use espresso on augmented bit space (input bits + output bit taint values)
        total_num_bits = len(relevant_input_bits) + len(ordered_interesting_outputs)
        partitions = {1: simplified_propagating, 0: simplified_non_propagating}
        dnf_condition = condition_gen.espresso.minimize(total_num_bits, 1, 'fr', partitions)

        # Step 7: Transpose condition back to original bit positions
        # Separate input bit conditions from output bit conditions
        # We need to map back:
        # - bits [0..num_relevant_bits-1] -> relevant_input_bits
        # - bits [num_relevant_bits..total_num_bits-1] -> output_bit_list
        transposed_ops = unitary_flow_processor.transpose_condition_bits(
            dnf_condition,
            relevant_input_bits,
            ordered_interesting_outputs,
        )

        logger.debug(
            f'  Condition: simplified={dnf_condition}, '
            f'relevant_bits={sorted(relevant_input_bits)}, '
            f'transposed={transposed_ops}',
        )

        # Create condition object with output bit references
        cond = TaintCondition(LogicType.DNF, transposed_ops, output_bit_refs)
        return ConditionDataflowPair(cond, mutated_input_bit, output_bit)

    except Exception as e:
        # If condition generation fails, treat as unconditional
        logger.debug(
            f'Failed to generate condition for input bit {mutated_input_bit} -> output bit {output_bit}: {e}',
        )

        return ConditionDataflowPair(None, mutated_input_bit, output_bit)
