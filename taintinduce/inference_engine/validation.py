"""Validation and checking utilities for taint inference rules.

This module provides functions to validate that inferred taint rules correctly
explain the observations used to generate them.
"""

import logging
from typing import Optional

from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, Rule
from taintinduce.state.state import State
from taintinduce.types import BitPosition, ObservationDependency

logger = logging.getLogger(__name__)


def check_condition_satisfied(
    condition: Optional[TaintCondition],
    input_state: State,
) -> bool:
    """Check if a condition is satisfied by an input state.

    Args:
        condition: The condition to check (None means unconditional/always True)
        input_state: The input state to evaluate

    Returns:
        True if the condition is satisfied, False otherwise
    """
    if condition is None or condition.condition_ops is None or len(condition.condition_ops) == 0:
        return True
    # Check if any DNF clause matches the input state
    for mask, value in condition.condition_ops:
        if (input_state.state_value & mask) == value:
            return True
    return False


def check_dataflow_matches(
    pair: ConditionDataflowPair,
    input_bit: BitPosition,
    output_bits: frozenset[BitPosition],
) -> bool:
    """Check if a pair's dataflow matches the observed behavior.

    Args:
        pair: The condition-dataflow pair to check
        input_bit: The input bit that was flipped
        output_bits: The observed output bits that changed

    Returns:
        True if the dataflow matches, False otherwise
    """
    if isinstance(pair.output_bits, dict):
        # pair.output_bits is a Dataflow dict: {input_bit: output_bits_set}
        if input_bit not in pair.output_bits:
            return False
        return output_bits == pair.output_bits[input_bit]

    # Fallback: pair.output_bits is a frozenset (shouldn't happen with new implementation)
    return output_bits == pair.output_bits


def validate_condition(
    condition: TaintCondition,
    agreeing_partition: set[State],
    disagreeing_partition: set[State],
) -> bool:
    """Validate that a condition correctly separates the two partitions.

    Args:
        condition: The condition to validate
        agreeing_partition: States where condition should be True
        disagreeing_partition: States where condition should be False

    Returns:
        True if condition correctly separates partitions, False otherwise
    """
    if condition.condition_ops is None:
        return True

    # Check that all agreeing states satisfy at least one clause in DNF
    for state in agreeing_partition:
        satisfies = False
        for mask, value in condition.condition_ops:
            if (state.state_value & mask) == value:
                satisfies = True
                break
        if not satisfies:
            logger.debug(f'  Validation failed: agreeing state {state.state_value:x} does not satisfy condition')
            return False

    # Check that no disagreeing states satisfy any clause
    for state in disagreeing_partition:
        for mask, value in condition.condition_ops:
            if (state.state_value & mask) == value:
                logger.debug(f'  Validation failed: disagreeing state {state.state_value:x} satisfies condition')
                return False

    return True


def validate_rule_explains_observations(  # noqa: C901
    rule: Rule,
    observation_dependencies: list[ObservationDependency],
) -> tuple[int, int]:
    """Validate that the generated rule explains all observations.

    Args:
        rule: The generated taint rule
        observation_dependencies: The extracted observation dependencies

    Returns:
        Tuple of (explained_count, total_count)
    """
    total_behaviors = 0
    explained_behaviors = 0
    unexplained: list[str] = []

    for obs_dep in observation_dependencies:
        for input_bit, output_bits in obs_dep.dataflow.items():
            total_behaviors += 1
            input_state = obs_dep.mutated_inputs.get_input_state(input_bit)

            # Collect all outputs from pairs that match this input_bit and satisfy the condition
            explained_outputs: set[BitPosition] = set()
            for pair in rule.pairs:
                if not check_condition_satisfied(pair.condition, input_state):
                    continue

                # Check if this pair has outputs for this input_bit
                if isinstance(pair.output_bits, dict) and input_bit in pair.output_bits:
                    explained_outputs.update(pair.output_bits[input_bit])
                elif not isinstance(pair.output_bits, dict):
                    # Fallback for old format
                    explained_outputs.update(pair.output_bits)

            # Check if the union of all explained outputs matches the observed outputs
            if frozenset(explained_outputs) == output_bits:
                explained_behaviors += 1
            else:
                unexplained.append(
                    f'Input bit {input_bit} -> {output_bits} (state=0x{input_state.state_value:x}), '
                    f'explained: {frozenset(explained_outputs)}',
                )

    # Log results
    coverage = (explained_behaviors / total_behaviors * 100) if total_behaviors > 0 else 0
    logger.info(
        f'Rule validation: {explained_behaviors}/{total_behaviors} behaviors explained ({coverage:.1f}%)',
    )

    if unexplained:
        logger.warning(f'Found {len(unexplained)} unexplained observation behaviors:')
        for i, desc in enumerate(unexplained[:10]):  # Show first 10
            logger.warning(f'  {i+1}. {desc}')
        if len(unexplained) > 10:
            logger.warning(f'  ... and {len(unexplained) - 10} more')

    return explained_behaviors, total_behaviors
