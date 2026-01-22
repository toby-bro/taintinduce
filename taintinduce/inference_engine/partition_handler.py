"""Partition handling functions for dataflow inference."""

import logging
from collections import defaultdict
from typing import Optional

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


def evaluate_output_bit_taint_states(
    state: StateValue,
    output_bit_refs: frozenset[OutputBitRef],
    completed_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> dict[BitPosition, int]:
    """Evaluate output bit taint states for a given input state.

    For each output bit in output_bit_refs, determine if it would be tainted
    by evaluating its condition against the current input state. This implements
    "taint by induction" where previous output taint states become inputs to
    later conditions.

    Args:
        state: The current input state value
        output_bit_refs: Output bits to evaluate
        completed_conditional_flows: Maps input bit sets to output bits
        all_conditions: Maps input bit sets to their TaintCondition

    Returns:
        Dict mapping output bit position to taint state (1=tainted, 0=untainted)
    """
    taint_states: dict[BitPosition, int] = {}

    for output_ref in output_bit_refs:
        output_bit = output_ref.output_bit

        # Find which condition generates this output bit
        found_condition = False
        for input_bits, output_bits in completed_conditional_flows.items():
            if output_bit in output_bits:
                # Get the condition for these input bits
                condition = all_conditions.get(input_bits)

                if condition is None:
                    # Unconditional flow - always tainted
                    taint_states[output_bit] = 1
                else:
                    # Evaluate condition against current state
                    # Count bits in state to create State object
                    num_bits = max(input_bits) + 1 if input_bits else 64
                    input_state = State(num_bits=num_bits, state_value=state)
                    is_tainted = condition.eval(input_state, output_state=None)
                    taint_states[output_bit] = 1 if is_tainted else 0

                found_condition = True
                break

        if not found_condition:
            # Output bit not found in completed flows - treat as untainted
            logger.warning(f'Output bit {output_bit} not found in completed flows')
            taint_states[output_bit] = 0

    return taint_states


def augment_states_with_output_bit_taints(
    propagating_states: set[State],
    non_propagating_states: set[State],
    relevant_bit_positions: frozenset[BitPosition],
    output_bit_refs: frozenset[OutputBitRef],
    completed_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> tuple[set[StateValue], set[StateValue], list[BitPosition]]:
    """Augment simplified states with output bit taint values.

    For taint by induction, we evaluate the taint state of referenced output bits
    and append them as additional bits to the state representation before
    condition generation.

    Args:
        propagating_states: States where input bit affects output bit
        non_propagating_states: States where input bit doesn't affect output bit
        relevant_bit_positions: Input bit positions for the current flow
        output_bit_refs: Output bits to include in condition
        completed_conditional_flows: Maps input bits to output bits
        all_conditions: Maps input bits to their conditions

    Returns:
        Tuple of (augmented_propagating, augmented_non_propagating, output_bit_list)
    """
    # Sort output bits for consistent ordering
    output_bit_list = sorted([ref.output_bit for ref in output_bit_refs])
    num_relevant_bits = len(relevant_bit_positions)

    # Augment propagating states
    augmented_propagating: set[StateValue] = set()
    for state in propagating_states:
        # Get original simplified state
        simplified_state = unitary_flow_processor.extract_relevant_bits_from_state(
            state,
            relevant_bit_positions,
        )
        # Evaluate output bit taint states
        if state.state_value is None:
            raise RuntimeError('State value is None')
        taint_states = evaluate_output_bit_taint_states(
            state.state_value,
            output_bit_refs,
            completed_conditional_flows,
            all_conditions,
        )
        # Append taint values to state (higher bits)
        augmented_state: StateValue = simplified_state
        for i, output_bit_pos in enumerate(output_bit_list):
            taint_value = taint_states.get(output_bit_pos, 0)
            augmented_state = StateValue(augmented_state | (taint_value << (num_relevant_bits + i)))
        augmented_propagating.add(augmented_state)

    # Augment non-propagating states
    augmented_non_propagating: set[StateValue] = set()
    for state in non_propagating_states:
        # Get original simplified state
        simplified_state = unitary_flow_processor.extract_relevant_bits_from_state(
            state,
            relevant_bit_positions,
        )
        # Evaluate output bit taint states
        if state.state_value is None:
            raise RuntimeError('State value is None')
        taint_states = evaluate_output_bit_taint_states(
            state.state_value,
            output_bit_refs,
            completed_conditional_flows,
            all_conditions,
        )
        # Append taint values to state (higher bits)
        augmented_state_np: StateValue = simplified_state
        for i, output_bit_pos in enumerate(output_bit_list):
            taint_value = taint_states.get(output_bit_pos, 0)
            augmented_state_np = StateValue(augmented_state_np | (taint_value << (num_relevant_bits + i)))
        augmented_non_propagating.add(augmented_state_np)

    return augmented_propagating, augmented_non_propagating, output_bit_list


def find_output_bit_refs_from_subsets(
    current_input_bits: frozenset[BitPosition],
    all_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
) -> Optional[frozenset[OutputBitRef]]:
    """Find output bits from smaller conditional flows whose inputs are a subset.

    When a dataflow uses input bits that are a superset of another conditional flow's
    inputs, we should include the output bits from that smaller flow in our condition.
    This helps with operations like ADD where carry propagation causes many inputs
    to affect an output bit.

    Args:
        current_input_bits: Input bits for the current flow being processed
        all_conditional_flows: Map from input bit sets to their output bits
                              (only conditional flows with actual conditions)

    Returns:
        Frozenset of OutputBitRef objects if subsets found, None otherwise
    """
    output_refs: set[OutputBitRef] = set()

    for other_input_bits, other_output_bits in all_conditional_flows.items():
        # Skip self
        if other_input_bits == current_input_bits:
            continue

        # Check if current inputs are a superset of other inputs
        if current_input_bits >= other_input_bits and len(current_input_bits) > len(other_input_bits):
            logger.debug(
                f'Found subset flow: {sorted(other_input_bits)} ⊂ {sorted(current_input_bits)}',
            )
            # Include all output bits from the smaller flow
            for output_bit in other_output_bits:
                output_refs.add(OutputBitRef(output_bit))

    if output_refs:
        logger.info(
            f'Including {len(output_refs)} output bit refs from subset flows: '
            f'{sorted([ref.output_bit for ref in output_refs])}',
        )
        return frozenset(output_refs)

    return None


def exclude_input_bits_covered_by_output_refs(
    relevant_input_bits: frozenset[BitPosition],
    output_bit_refs: Optional[frozenset[OutputBitRef]],
    completed_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
) -> frozenset[BitPosition]:
    """Exclude input bits that are already covered by output bit references.

    To prevent DNF explosion, when output bits from subset flows are included as
    output_bit_refs, we can exclude the input bits that generate those output bits.
    However, we only exclude input bits that appear in MULTIPLE subset flows (2 or more).
    This is because a bit appearing in only one subset flow might still be needed
    for the condition.

    For example, if we have:
    - Flow A: input bits {0, 1} -> output bit 32
    - Flow B: input bits {1, 2} -> output bit 33
    - Flow C: input bits {0, 1, 2, 3} -> output bit 34

    When processing Flow C, we add output bits 32 and 33 as output_bit_refs.
    - Bit 0 appears in 1 subset flow (A) -> keep it
    - Bit 1 appears in 2 subset flows (A, B) -> exclude it
    - Bit 2 appears in 1 subset flow (B) -> keep it
    - Bit 3 appears in 0 subset flows -> keep it

    Args:
        relevant_input_bits: All input bits that affect the current output bit
        output_bit_refs: Output bit references from subset flows (if any)
        completed_conditional_flows: Maps input bit sets to their output bits

    Returns:
        Filtered set of input bits with multiply-covered bits excluded
    """
    if not output_bit_refs:
        return relevant_input_bits

    # Count how many times each input bit appears in subset flows
    input_bit_counts: dict[BitPosition, int] = {}

    # For each output bit ref, find which input bits generate it
    for other_input_bits, other_output_bits in completed_conditional_flows.items():
        # Check if any of our output_bit_refs come from this flow
        for output_ref in output_bit_refs:
            if output_ref.output_bit in other_output_bits:
                # Count these input bits
                for input_bit in other_input_bits:
                    if input_bit in relevant_input_bits:
                        input_bit_counts[input_bit] = input_bit_counts.get(input_bit, 0) + 1
                break  # Only count each flow once

    # Only exclude bits that appear in 2+ subset flows
    excluded_input_bits = {bit for bit, count in input_bit_counts.items() if count >= INCLUSION_THRESHOLD}

    # Filter relevant_input_bits to exclude multiply-covered bits
    filtered_bits = frozenset(bit for bit in relevant_input_bits if bit not in excluded_input_bits)

    logger.debug(
        f'Excluding input bits covered by multiple output refs: '
        f'original={sorted(relevant_input_bits)}, '
        f'counts={dict(sorted(input_bit_counts.items()))}, '
        f'excluded={sorted(excluded_input_bits)}, '
        f'filtered={sorted(filtered_bits)}',
    )

    return filtered_bits


def handle_single_partition(
    mutated_input_bit: BitPosition,
    possible_flows: dict[BitPosition, set[frozenset[BitPosition]]],
) -> list[ConditionDataflowPair]:
    """Handle case with single partition (no conditional dataflow)."""
    no_cond_dataflow_set_flat: set[BitPosition] = set()
    for output_set in possible_flows[mutated_input_bit]:
        no_cond_dataflow_set_flat |= set(output_set)
    output_bits = frozenset(no_cond_dataflow_set_flat)
    if len(output_bits) > 1:
        logger.info(
            f'No condition for input bit {mutated_input_bit} -> {len(output_bits)} output bits',
        )
    return [ConditionDataflowPair(condition=None, output_bits=output_bits)]


def handle_multiple_partitions_output_centric(  # noqa: C901
    mutated_input_bit: BitPosition,
    observation_dependencies: list[ObservationDependency],
    completed_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> list[ConditionDataflowPair]:
    """Handle multiple partitions using output-bit-centric approach.

    This function generates conditions for each output bit independently,
    considering only the relevant input bits for that specific output bit.
    This prevents conditions on secondary effects (like flags) from contaminating
    primary effects (like R2 -> R1 propagation).

    Args:
        mutated_input_bit: The input bit we're analyzing
        observation_dependencies: All observation dependencies
        completed_conditional_flows: Maps input bit sets to their output bits for
            previously processed conditional flows (used for superset detection)
        all_conditions: Maps input bit sets to their TaintCondition for evaluating
            output bit taint states (taint by induction)

    Returns:
        List of ConditionDataflowPair objects
    """
    # Step 1: Get all output bits affected by this input bit
    affected_output_bits: set[BitPosition] = set()
    for obs_dep in observation_dependencies:
        if mutated_input_bit in obs_dep.dataflow:
            affected_output_bits.update(obs_dep.dataflow[mutated_input_bit])

    if not affected_output_bits:
        return [ConditionDataflowPair(condition=None, output_bits=frozenset())]

    # Step 2: For each output bit, determine all input bits that affect it
    output_to_all_inputs = unitary_flow_processor.group_unitary_flows_by_output(observation_dependencies)

    # Step 3: Generate conditions for each output bit independently
    # We'll group results by condition to merge later
    condition_to_outputs: dict[
        tuple[Optional[object], Optional[object], Optional[object]],
        set[BitPosition],
    ] = defaultdict(set)

    for output_bit in affected_output_bits:
        # Get all input bits that can affect this output bit (not just mutated_input_bit)
        relevant_input_bits = output_to_all_inputs.get(output_bit, frozenset())

        if not relevant_input_bits:
            # No input affects this output? Skip
            raise RuntimeError(
                f'No input bits found affecting output bit {output_bit} for mutated input bit {mutated_input_bit}',
            )

        # Find output bit references from subset flows
        output_bit_refs = find_output_bit_refs_from_subsets(
            frozenset(relevant_input_bits),
            completed_conditional_flows,
        )

        # OPTIMIZATION: Exclude input bits that are covered by output_bit_refs to prevent DNF explosion
        relevant_input_bits_filtered = exclude_input_bits_covered_by_output_refs(
            frozenset(relevant_input_bits),
            output_bit_refs,
            completed_conditional_flows,
        )

        logger.debug(
            f'Processing output bit {output_bit}: mutated_input_bit={mutated_input_bit}, '
            f'relevant_input_bits={sorted(relevant_input_bits)}, '
            f'filtered_input_bits={sorted(relevant_input_bits_filtered)}, '
            f'output_bit_refs={output_bit_refs}',
        )

        # Step 4: Collect states that do/don't trigger propagation from mutated_input_bit to output_bit
        propagating_states, non_propagating_states = unitary_flow_processor.collect_states_for_unitary_flow(
            observation_dependencies,
            mutated_input_bit,
            output_bit,
        )

        logger.debug(
            f'  Counts: propagating={len(propagating_states)}, non_propagating={len(non_propagating_states)}',
        )

        # If no variation in behavior, it's unconditional
        if not non_propagating_states or not propagating_states:
            # Unconditional flow from mutated_input_bit to output_bit
            logger.debug(
                f'  Output bit {output_bit}: unconditional flow (propagating={len(propagating_states)}, '
                f'non_propagating={len(non_propagating_states)})',
            )
            condition_key: tuple[Optional[object], Optional[object], Optional[object]] = (None, None, None)
            condition_to_outputs[condition_key].add(output_bit)
            continue

        # Step 5: Create simplified states with only relevant input bits
        # The relevant bits are ALL input bits that affect this output bit
        relevant_bit_positions = frozenset(relevant_input_bits)
        num_relevant_bits = len(relevant_bit_positions)

        # Extract simplified states
        simplified_propagating: set[StateValue] = {
            unitary_flow_processor.extract_relevant_bits_from_state(state, relevant_bit_positions)
            for state in propagating_states
        }
        simplified_non_propagating: set[StateValue] = {
            unitary_flow_processor.extract_relevant_bits_from_state(state, relevant_bit_positions)
            for state in non_propagating_states
        }

        # Step 5bis: Add output bit taint values for taint by induction
        # If we have output bit refs, augment states with their taint values
        num_output_bits = 0
        output_bit_list: list[BitPosition] = []
        if output_bit_refs:
            augmented_prop, augmented_non_prop, output_bit_list = augment_states_with_output_bit_taints(
                propagating_states,
                non_propagating_states,
                relevant_bit_positions,
                output_bit_refs,
                completed_conditional_flows,
                all_conditions,
            )
            simplified_propagating = augmented_prop
            simplified_non_propagating = augmented_non_prop
            num_output_bits = len(output_bit_list)

            logger.debug(
                f'  Augmented states with {num_output_bits} output bit taint values: {output_bit_list}',
            )

        # Step 6: Generate condition on simplified bits (including output bit taint values)
        condition_gen = condition_generator.ConditionGenerator()

        try:
            # Use espresso on augmented bit space (input bits + output bit taint values)
            total_num_bits = num_relevant_bits + num_output_bits
            partitions = {1: simplified_propagating, 0: simplified_non_propagating}
            dnf_condition = condition_gen.espresso.minimize(total_num_bits, 1, 'fr', partitions)

            # Step 7: Transpose condition back to original bit positions
            # Separate input bit conditions from output bit conditions
            # We need to map back:
            # - bits [0..num_relevant_bits-1] -> relevant_input_bits
            # - bits [num_relevant_bits..total_num_bits-1] -> output_bit_list
            transposed_ops = unitary_flow_processor.transpose_condition_bits(
                dnf_condition,
                relevant_bit_positions,
                output_bit_list,
            )

            logger.debug(
                f'  Condition: simplified={dnf_condition}, '
                f'relevant_bits={sorted(relevant_bit_positions)}, '
                f'transposed={transposed_ops}',
            )

            # Create condition object with output bit references
            cond = TaintCondition(LogicType.DNF, transposed_ops, output_bit_refs)
            condition_key = (cond.condition_type, cond.condition_ops, cond.output_bit_refs)
            condition_to_outputs[condition_key].add(output_bit)

        except Exception as e:
            # If condition generation fails, treat as unconditional
            logger.debug(
                f'Failed to generate condition for input bit {mutated_input_bit} -> output bit {output_bit}: {e}',
            )
            condition_key = (None, None, None)
            condition_to_outputs[condition_key].add(output_bit)

    # Step 8: Build ConditionDataflowPair list from grouped results
    condition_dataflow_pairs: list[ConditionDataflowPair] = []

    for condition_key, output_bits_set in condition_to_outputs.items():
        cond_type, cond_ops, output_refs = condition_key

        condition: Optional[TaintCondition]
        if cond_type is None:
            condition = None
        else:
            # cond_type and cond_ops are not None here
            condition = TaintCondition(cond_type, cond_ops, output_refs)  # type: ignore[arg-type]

        output_bits = frozenset(output_bits_set)
        condition_dataflow_pairs.append(ConditionDataflowPair(condition=condition, output_bits=output_bits))

    return condition_dataflow_pairs
