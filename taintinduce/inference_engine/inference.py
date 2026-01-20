# Replaced squirrel import with our own
import logging
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Optional

from tqdm import tqdm

if TYPE_CHECKING:
    from taintinduce.observation_engine.observation import ObservationEngine

from taintinduce.isa.register import CondRegister, Register
from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, Rule
from taintinduce.state.state import Observation
from taintinduce.types import (
    BitPosition,
    Dataflow,
    ObservationDependency,
)

from . import observation_processor, partition_handler, validation

"""Inference engine for data-dependent taint propagation rules.

This module infers taint propagation rules with conditions from observations.
It supports two types of conditions:

1. Control-flow dependent (legacy mode, use_full_state=False):
   - Conditions based only on FLAGS/NZCV register
   - Example: CMOV propagates taint only if ZF=0

2. Data-dependent (generalized mode, use_full_state=True):
   - Conditions based on any input register values
   - Example: AND eax,ebx propagates no taint if ebx=0
   - Example: SHL eax,cl propagates no taint if cl=0
   - Example: IMUL with small operands may not affect high bits

The algorithm uses ESPRESSO logic minimizer to find boolean formulas that
separate different taint propagation behaviors based on input state.
"""

logging.basicConfig(format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _log_unconditional_warnings(condition: TaintCondition | None, dataflow: Dataflow) -> None:
    """Log warnings for unconditional 1-to-many flows."""
    is_empty = condition is None or (condition.condition_ops is not None and len(condition.condition_ops) == 0)
    if not is_empty:
        return

    for input_bit, output_bits in dataflow.items():
        if len(output_bits) > 1:
            logger.warning(
                f'No condition for input bit {input_bit} -> {len(output_bits)} output bits (full dataflow)',
            )


def _build_dataflows_from_unitary_conditions(
    per_bit_conditions: dict[BitPosition, list[ConditionDataflowPair]],
) -> list[ConditionDataflowPair]:
    """Build list of ConditionDataflowPair objects from per-input-bit conditions.

    Each input bit's condition-dataflow pairs are converted to proper Dataflow objects.
    No grouping across input bits - each condition applies only to the specific
    input bits it was generated for.

    Args:
        per_bit_conditions: Maps each input bit to its condition-dataflow pairs

    Returns:
        List of ConditionDataflowPair objects with Dataflow dicts
    """
    result: list[ConditionDataflowPair] = []

    # Process each input bit's conditions
    for input_bit, pairs in per_bit_conditions.items():
        for pair in pairs:
            # Convert frozenset output_bits to Dataflow for this input bit
            if isinstance(pair.output_bits, frozenset):
                dataflow = Dataflow()
                dataflow[input_bit] = pair.output_bits

                # Log warnings for unconditional 1-to-many flows
                _log_unconditional_warnings(pair.condition, dataflow)

                result.append(
                    ConditionDataflowPair(condition=pair.condition, output_bits=dataflow),
                )
            elif isinstance(pair.output_bits, dict):
                # Already a Dataflow
                _log_unconditional_warnings(pair.condition, pair.output_bits)
                result.append(pair)

    return result


def infer(
    observations: list[Observation],
    cond_reg: CondRegister,
    observation_engine: Optional['ObservationEngine'] = None,
    enable_refinement: bool = False,
) -> Rule:
    """Infers the dataflow of the instruction using the obesrvations.

    Args:
        observations ([Observation]): List of observations to infer on.
        cond_reg: Condition register (EFLAGS for X86/AMD64, NZCV for ARM64/JN)
        observation_engine: Optional ObservationEngine for refinement pass
        enable_refinement: Whether to perform refinement pass with targeted observations
    Returns:
        A Rule object with inferred dataflows and conditions
    Raises:
        None
    """

    if len(observations) == 0:
        raise Exception('No observations to infer from!')

    # zl: we have the state_format in observation, assert that all observations in obs_list have the same state_format  # noqa: E501
    state_format = observations[0].state_format
    if state_format is None:
        raise Exception('State format is None!')
    assert all(obs.state_format == state_format for obs in observations)

    per_bit_conditions = infer_flow_conditions(
        observations,
        cond_reg,
        state_format,
        enable_refinement=enable_refinement,
        observation_engine=observation_engine,
    )

    if len(per_bit_conditions) == 0:
        raise Exception('No conditions inferred!')

    # Build list of ConditionDataflowPair objects from unitary flow conditions
    # Each condition applies only to the specific input bits it was generated for
    condition_dataflow_pairs = _build_dataflows_from_unitary_conditions(per_bit_conditions)

    rule = Rule(state_format, pairs=condition_dataflow_pairs)

    # Validate that the generated rule explains all observations
    observation_dependencies = observation_processor.extract_observation_dependencies(observations)
    explained, total = validation.validate_rule_explains_observations(rule, observation_dependencies)

    if explained < total:
        logger.warning(
            f'Rule validation incomplete: {explained}/{total} behaviors explained '
            f'({explained/total*100:.1f}%). Some observations may not be fully captured by conditions.',
        )
    else:
        logger.info(f'Rule validation successful: all {total} observation behaviors explained.')

    return rule


def infer_flow_conditions(
    observations: list[Observation],
    cond_reg: CondRegister,
    state_format: list[Register],
    enable_refinement: bool = False,
    observation_engine: Optional['ObservationEngine'] = None,
) -> dict[BitPosition, list[ConditionDataflowPair]]:
    """Infer conditions for dataflows for each input bit independently.

    Returns:
        Dictionary mapping each input bit to its list of ConditionDataflowPair objects.
        Each input bit's conditions are kept separate to avoid incorrectly applying
        conditions from one bit to another.
    """

    observation_dependencies = observation_processor.extract_observation_dependencies(observations)

    # iterate through all the dependencies from the observations and identify what are the possible flows
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]] = defaultdict(set)
    for observation in observation_dependencies:
        for mutated_input_bit, modified_output_bits in observation.dataflow.items():
            possible_flows[mutated_input_bit].add(modified_output_bits)

    # Store conditions per input bit - no grouping to avoid condition misattribution
    per_bit_conditions: dict[BitPosition, list[ConditionDataflowPair]] = {}

    # Parallelize condition inference across input bits
    max_workers = os.cpu_count() or 1
    logger.debug(f'Using {max_workers} workers for parallel condition inference')

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_bit = {
            executor.submit(
                infer_conditions_for_dataflows,
                cond_reg,
                state_format,
                observation_dependencies,
                possible_flows,
                mutated_input_bit,
                enable_refinement,
                observation_engine,
                observations,
            ): mutated_input_bit
            for mutated_input_bit in possible_flows
        }

        # Collect results as they complete with progress bar
        with tqdm(total=len(future_to_bit), desc='Inferring conditions', unit='bit') as pbar:
            for future in as_completed(future_to_bit):
                mutated_input_bit = future_to_bit[future]
                try:
                    condition_dataflow_pairs = future.result()
                    # Store this input bit's conditions directly - no grouping
                    per_bit_conditions[mutated_input_bit] = condition_dataflow_pairs
                    pbar.update(1)
                except Exception as e:
                    logger.error(f'Failed to infer conditions for bit {mutated_input_bit}: {e}')
                    raise

    return per_bit_conditions


def infer_conditions_for_dataflows(
    cond_reg: CondRegister,
    state_format: list[Register],
    observation_dependencies: list[ObservationDependency],
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
    mutated_input_bit: BitPosition,
    enable_refinement: bool = False,
    observation_engine: Optional['ObservationEngine'] = None,
    all_observations: Optional[list[Observation]] = None,
) -> list[ConditionDataflowPair]:
    """Infer conditions and their associated dataflows for a mutated input bit.

    Returns:
        List of ConditionDataflowPair objects, each pairing a condition with its output bits.
        condition=None represents the default/fallthrough case.
    """
    num_partitions = len(possible_flows[mutated_input_bit])
    if num_partitions == 0:
        raise Exception(f'No possible flows for mutated input bit {mutated_input_bit}')

    # ZL: TODO: Hack for cond_reg, do a check if state_format contains the cond_reg, if no, then skip condition inference  # noqa: E501
    if num_partitions == 1:
        # no conditional dataflow - single behavior for all inputs
        return partition_handler.handle_single_partition(mutated_input_bit, possible_flows)

    return partition_handler.handle_multiple_partitions(
        mutated_input_bit,
        observation_dependencies,
        state_format,
        cond_reg,
        enable_refinement,
        observation_engine,
        all_observations,
    )
