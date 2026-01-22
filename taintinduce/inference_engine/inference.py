# Replaced squirrel import with our own
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from taintinduce.rules.conditions import TaintCondition
from taintinduce.rules.rules import ConditionDataflowPair, GlobalRule
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

logger = logging.getLogger(__name__)


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
) -> GlobalRule:
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

    # zl: we have the state_format in observation, assert that all observations in obs_list have the same state_format
    state_format = observations[0].state_format
    if state_format is None:
        raise Exception('State format is None!')
    assert all(obs.state_format == state_format for obs in observations)

    per_bit_conditions = infer_flow_conditions(
        observations,
    )

    if len(per_bit_conditions) == 0:
        raise Exception('No conditions inferred!')

    # Build list of ConditionDataflowPair objects from unitary flow conditions
    # Each condition applies only to the specific input bits it was generated for
    condition_dataflow_pairs = _build_dataflows_from_unitary_conditions(per_bit_conditions)

    rule = GlobalRule(state_format, pairs=condition_dataflow_pairs)

    # Validate that the generated rule explains all observations
    observation_dependencies = observation_processor.extract_observation_dependencies(observations)
    explained, total = validation.validate_rule_explains_observations(rule, observation_dependencies)

    if explained < total:
        print(
            f'Rule validation incomplete: {explained}/{total} behaviors explained '
            f'({explained/total*100:.1f}%). Some observations may not be fully captured by conditions.',
        )
    else:
        print(f'Rule validation successful: all {total} observation behaviors explained.')

    return rule


def infer_flow_conditions(
    observations: list[Observation],
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

    # Sort input bits by their dataflow complexity (smallest first)
    # This ensures we process simpler flows before complex ones
    sorted_input_bits = sorted(
        possible_flows.keys(),
        key=lambda bit: min(len(flow) for flow in possible_flows[bit]),
    )
    logger.debug(f'Processing {len(sorted_input_bits)} input bits in order of dataflow complexity')

    # Track completed flows: maps input bits to their output bits
    # This includes both conditional and unconditional flows
    # This will be passed to handle_multiple_partitions for superset detection
    completed_flows: dict[frozenset[BitPosition], set[BitPosition]] = {}
    # Also track the actual conditions for evaluating output bit taint states
    all_conditions: dict[frozenset[BitPosition], TaintCondition] = {}

    # Process input bits in WAVES based on dependencies (parallel within each wave)
    logger.debug(f'Processing {len(sorted_input_bits)} input bits in dependency-aware waves')

    remaining_bits = set(sorted_input_bits)
    wave_number = 0

    while remaining_bits:
        wave_number += 1

        # Identify bits ready for this wave (all subset dependencies satisfied)
        ready_bits = _identify_ready_bits_by_subset_dependency(
            remaining_bits,
            possible_flows,
        )

        if not ready_bits:
            logger.error(f'Deadlock: {len(remaining_bits)} bits remain but none are ready')
            logger.error(f'Remaining bits: {remaining_bits}')
            raise Exception('Circular dependency detected in output_bit_refs')

        logger.debug(f'Wave {wave_number}: processing {len(ready_bits)} bits in parallel')

        # Process this wave in parallel, collect results WITHOUT modifying shared state
        wave_results = _process_wave_parallel(
            ready_bits,
            wave_number,
            observation_dependencies,
            possible_flows,
            completed_flows,
            all_conditions,
        )

        # NOW update shared state with all results from this wave (thread-safe)
        _update_state_from_wave_results(
            wave_results,
            per_bit_conditions,
            observation_dependencies,
            completed_flows,
            all_conditions,
        )

        remaining_bits -= ready_bits

    logger.debug(f'Completed processing in {wave_number} waves')

    return per_bit_conditions


def _update_state_from_wave_results(
    wave_results: dict[BitPosition, list[ConditionDataflowPair]],
    per_bit_conditions: dict[BitPosition, list[ConditionDataflowPair]],
    observation_dependencies: list[ObservationDependency],
    completed_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> None:
    """Update shared state with results from a completed wave."""
    for mutated_input_bit, condition_dataflow_pairs in wave_results.items():
        per_bit_conditions[mutated_input_bit] = condition_dataflow_pairs

        # Track completed flows (both conditional and unconditional) for superset detection
        for pair in condition_dataflow_pairs:
            if pair.output_bits:
                input_bits: set[BitPosition] = {mutated_input_bit}
                for obs_dep in observation_dependencies:
                    for input_bit, output_bits in obs_dep.dataflow.items():
                        if any(ob in pair.output_bits for ob in output_bits):
                            input_bits.add(input_bit)
                input_bits_frozen = frozenset(input_bits)
                completed_flows[input_bits_frozen] = set(pair.output_bits)
                if pair.condition is not None:
                    all_conditions[input_bits_frozen] = pair.condition


def _identify_ready_bits_by_subset_dependency(
    remaining_bits: set[BitPosition],
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
) -> set[BitPosition]:
    """Identify bits ready for processing based on subset dependencies.

    A bit is ready when all flows that produce SUBSETS of its outputs are completed.
    This ensures output_bit_refs can be properly detected.
    """
    ready: set[BitPosition] = set()

    for input_bit in remaining_bits:
        if _bit_is_ready(input_bit, remaining_bits, possible_flows):
            ready.add(input_bit)

    # If nothing is ready, return bits with minimal output sizes to bootstrap
    if not ready and remaining_bits:
        min_size = min(min(len(output_set) for output_set in possible_flows[bit]) for bit in remaining_bits)
        ready = {
            bit for bit in remaining_bits if min(len(output_set) for output_set in possible_flows[bit]) == min_size
        }

    return ready


def _bit_is_ready(
    input_bit: BitPosition,
    remaining_bits: set[BitPosition],
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
) -> bool:
    """Check if a bit is ready by verifying all subset dependencies are satisfied."""
    output_sets = possible_flows[input_bit]

    for output_set in output_sets:
        # Check other remaining bits for subset dependencies
        for other_bit in remaining_bits:
            if other_bit == input_bit:
                continue
            other_output_sets = possible_flows[other_bit]
            for other_output_set in other_output_sets:
                # If other produces a proper subset of our output, we must wait
                if other_output_set and output_set and other_output_set < output_set:
                    return False

    return True


def _process_wave_parallel(
    ready_bits: set[BitPosition],
    wave_number: int,
    observation_dependencies: list[ObservationDependency],
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
    completed_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> dict[BitPosition, list[ConditionDataflowPair]]:
    """Process a wave of bits in parallel, return results without modifying shared state."""
    wave_results: dict[BitPosition, list[ConditionDataflowPair]] = {}

    with ThreadPoolExecutor() as executor:
        futures = {}
        for mutated_input_bit in ready_bits:
            future = executor.submit(
                infer_conditions_for_dataflows,
                observation_dependencies,
                possible_flows,
                mutated_input_bit,
                completed_flows,
                all_conditions,
            )
            futures[future] = mutated_input_bit

        # Collect results
        for future in tqdm(
            as_completed(futures),
            total=len(futures),
            desc=f'Wave {wave_number}',
            unit='bit',
        ):
            mutated_input_bit = futures[future]
            try:
                condition_dataflow_pairs = future.result()
                wave_results[mutated_input_bit] = condition_dataflow_pairs
            except Exception as e:
                logger.error(f'Failed to infer conditions for bit {mutated_input_bit}: {e}')
                raise

    return wave_results


def infer_conditions_for_dataflows(
    observation_dependencies: list[ObservationDependency],
    possible_flows: defaultdict[BitPosition, set[frozenset[BitPosition]]],
    mutated_input_bit: BitPosition,
    completed_flows: dict[frozenset[BitPosition], set[BitPosition]],
    all_conditions: dict[frozenset[BitPosition], TaintCondition],
) -> list[ConditionDataflowPair]:
    """Infer conditions and their associated dataflows for a mutated input bit.

    Returns:
        List of ConditionDataflowPair objects, each pairing a condition with its output bits.
        condition=None represents the default/fallthrough case.
    """
    num_partitions = len(possible_flows[mutated_input_bit])
    if num_partitions == 0:
        raise Exception(f'No possible flows for mutated input bit {mutated_input_bit}')

    if num_partitions == 1:
        # no conditional dataflow - single behavior for all inputs
        return partition_handler.handle_single_partition(mutated_input_bit, possible_flows)

    return partition_handler.handle_multiple_partitions_output_centric(
        mutated_input_bit,
        observation_dependencies,
        completed_flows,
        all_conditions,
    )
