"""Partition handling functions for dataflow inference."""

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.register import CondRegister, Register
from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair
from taintinduce.state.state import Observation, State
from taintinduce.types import (
    BitPosition,
    ObservationDependency,
)

from . import condition_generator, observation_processor

logger = logging.getLogger(__name__)


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


def process_output_partition(
    output_set: frozenset[BitPosition],
    partitions: dict[frozenset[BitPosition], set[State]],
    state_format: list[Register],
    cond_reg: CondRegister,
    mutated_input_bit: BitPosition,
    enable_refinement: bool,
    observation_engine: Optional['ObservationEngine'],
    all_observations: Optional[list[Observation]],
) -> tuple[Optional[TaintCondition], frozenset[BitPosition]]:
    """Process a single output partition and infer its condition."""
    agreeing_partition: set[State] = set()
    disagreeing_partition: set[State] = set()
    for alternative_modified_output_set, input_states in partitions.items():
        if output_set != alternative_modified_output_set:
            disagreeing_partition.update(input_states)
        else:
            agreeing_partition.update(input_states)

    condition_gen = condition_generator.ConditionGenerator()

    # use_full_state=True: generates conditions on all input registers (data-dependent)
    # This captures conditions like "if ebx=0, no taint in AND eax,ebx"
    # For arithmetic operations, this may overfit if observations are sparse
    mycond = condition_gen.generate_condition(
        agreeing_partition,
        disagreeing_partition,
        state_format,
        cond_reg,
        use_full_state=True,
    )

    # Debug: Log partition sizes to help identify overfitting
    logger.debug(
        f'  Partition sizes: agreeing={len(agreeing_partition)}, disagreeing={len(disagreeing_partition)}',
    )
    if mycond:
        logger.debug(f'  Found condition for output set {output_set}: {mycond}')

        # Refinement pass: validate this specific condition
        if enable_refinement and observation_engine is not None and all_observations is not None:
            refined_cond = condition_gen.refine_condition(
                mycond,
                mutated_input_bit,
                output_set,
                observation_engine,
                all_observations,
                state_format,
                cond_reg,
            )
            if refined_cond != mycond:
                logger.info(f'  REFINED: {mycond} -> {refined_cond}')
                mycond = refined_cond
            else:
                logger.info(f'  UNCHANGED: {mycond}')

    return mycond, output_set


def handle_multiple_partitions(
    mutated_input_bit: BitPosition,
    observation_dependencies: list[ObservationDependency],
    state_format: list[Register],
    cond_reg: CondRegister,
    enable_refinement: bool,
    observation_engine: Optional['ObservationEngine'],
    all_observations: Optional[list[Observation]],
) -> list[ConditionDataflowPair]:
    """Handle case with multiple partitions (conditional dataflow)."""
    condition_dataflow_pairs: list[ConditionDataflowPair] = []
    no_cond_dataflow_set: set[frozenset[BitPosition]] = set()

    # Generate the two sets...
    # Iterate across all observations and extract the behavior for the partitions...
    partitions = observation_processor.link_affected_outputs_to_their_input_states(
        observation_dependencies,
        mutated_input_bit,
    )

    # ZL: The current heuristic is to always select the smaller partition first since
    # it lowers the chances of the DNF exploding.
    ordered_output_sets = sorted(partitions.keys(), key=lambda x: len(partitions[x]), reverse=True)

    for output_set in ordered_output_sets:
        mycond, output_bits = process_output_partition(
            output_set,
            partitions,
            state_format,
            cond_reg,
            mutated_input_bit,
            enable_refinement,
            observation_engine,
            all_observations,
        )

        if mycond:
            condition_dataflow_pairs.append(
                ConditionDataflowPair(condition=mycond, output_bits=output_bits),
            )
        else:
            if len(output_set) > 1:
                logger.info(
                    f'No condition for input bit {mutated_input_bit} -> {len(output_set)} output bits (partition)',
                )
            no_cond_dataflow_set.add(output_set)

    # Default/fallthrough case: remaining behavior with no condition
    remaining_behavior: frozenset[BitPosition] = frozenset()
    if len(no_cond_dataflow_set) > 0:
        for behavior in no_cond_dataflow_set:
            remaining_behavior = remaining_behavior.union(behavior)
        logger.info(
            f'No condition for input bit {mutated_input_bit} -> '
            f'{len(remaining_behavior)} output bits (fallthrough)',
        )
        condition_dataflow_pairs.append(
            ConditionDataflowPair(condition=None, output_bits=remaining_behavior),
        )

    return condition_dataflow_pairs
