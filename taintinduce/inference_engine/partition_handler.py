"""Partition handling functions for dataflow inference."""

import logging
from collections import defaultdict
from typing import Optional

from taintinduce.rules.conditions import LogicType, OutputBitRef, TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair
from taintinduce.types import (
    BitPosition,
    ObservationDependency,
    StateValue,
)

from . import condition_generator, unitary_flow_processor

logger = logging.getLogger(__name__)


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


def handle_multiple_partitions_output_centric(
    mutated_input_bit: BitPosition,
    observation_dependencies: list[ObservationDependency],
    completed_conditional_flows: dict[frozenset[BitPosition], set[BitPosition]],
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
        relevant_input_bits = output_to_all_inputs.get(output_bit, set())

        if not relevant_input_bits:
            # No input affects this output? Skip
            continue

        # Find output bit references from subset flows
        output_bit_refs = find_output_bit_refs_from_subsets(
            frozenset(relevant_input_bits),
            completed_conditional_flows,
        )

        logger.debug(
            f'Processing output bit {output_bit}: mutated_input_bit={mutated_input_bit}, '
            f'relevant_input_bits={sorted(relevant_input_bits)}, '
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

        # Step 6: Generate condition on simplified bits
        condition_gen = condition_generator.ConditionGenerator()

        try:
            # Use espresso directly on simplified bit space
            partitions = {1: simplified_propagating, 0: simplified_non_propagating}
            dnf_condition = condition_gen.espresso.minimize(num_relevant_bits, 1, 'fr', partitions)

            # Step 7: Transpose condition back to original bit positions
            transposed_ops = unitary_flow_processor.transpose_condition_bits(
                dnf_condition,
                relevant_bit_positions,
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
